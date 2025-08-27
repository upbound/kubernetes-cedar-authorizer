use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    sync::Arc,
};

use cedar_policy_core::{
    ast::{self, Expr, ExprKind},
    tpe::{entities::PartialEntities, request::PartialRequest, residual::Residual},
};

use super::{
    err::{EarlyEvaluationError, SchemaError},
    residual::PartialResponseNew,
};

use itertools::Itertools;

/// PolicySet is a newtype wrapping Cedar's ast::PolicySet, but adding three important invariants:
/// 1. Deny policies must never error, i.e. arithmetic and extension function calls cannot be used.
/// 2. Using "is k8s::Resource" in a policy is disallowed, as it would fail to match typed resources like "core::pods".
/// 3. Only static policies are allowed for now, i.e. policies that do not contain any slots.
///
/// In addition, this policy set rewrites policies to be compatible with Typed Partial Evaluation, for use-cases where
/// some attributes are unknown, but some are known, using the rewrite documented in:
/// https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md#contingent-authorization-with-entity-based-unknown-values
// TODO: Consider if it's worth taking the schema as a reference here, or just owning it.
#[derive(Clone)]
pub struct PolicySet {
    pub(super) policies: ast::PolicySet,
    schema: Arc<super::Schema>,
}

impl PolicySet {
    pub fn new(policies: &ast::PolicySet, schema: Arc<super::Schema>) -> Result<Self, SchemaError> {
        for p in policies.policies() {
            // INVARIANT: Make sure that no deny policies could error.
            if p.effect() == ast::Effect::Forbid && Self::expr_could_error(&p.condition()) {
                // TODO: Instead of returning an error, we should just remove the policy, and return warnings about what policies were skipped.
                // The caller can then decide on how serious it is if some policy errored.
                return Err(SchemaError::PolicyCouldError(p.id().clone()));
            }

            // INVARIANT: Make sure that no policies (regardless of effect) contain "is k8s::Resource".
            if Self::expr_has_in_k8s_resource(&p.condition()) {
                return Err(SchemaError::IsK8sResourceDisallowed(p.id().clone()));
            }

            // INVARIANT: Make sure that no policies contain slots.
            if !p.is_static() {
                return Err(SchemaError::PolicyIsNotStatic(p.id().clone()));
            }

            // INVARIANT: Make sure that there are no 'resource.<attr> like "*"' expressions.
            // Also make sure that when like is used, it can only match prefix or suffixes.
            // TODO: This is not yet implemented.
        }

        // Rewrite the policies to be compatible with Typed Partial Evaluation, according to rewrites in the schema.
        let substituted_policies = ast::PolicySet::try_from_iter(policies.policies().map(|p| {
            ast::Policy::from_when_clause(
                p.effect(),
                schema.rewrite_expr(&p.condition()),
                p.id().clone(),
                p.loc().cloned(),
            )
        }))?;

        Ok(Self {
            policies: substituted_policies,
            schema,
        })
    }

    pub fn from_str(s: &str, schema: Arc<super::Schema>) -> Result<Self, anyhow::Error> {
        let policies: cedar_policy::PolicySet = s.parse()?;
        Ok(Self::new(policies.as_ref(), schema)?)
    }

    pub fn schema(&self) -> Arc<super::Schema> {
        self.schema.clone()
    }

    pub fn schema_ref(&self) -> &super::Schema {
        self.schema.as_ref()
    }

    /// expr_could_error checks if an expression could error, i.e. if it contains an arithmetic or extension function call.
    /// This is used to ensure that all deny policies are always true, i.e. they do not error.
    fn expr_could_error(expr: &Expr) -> bool {
        match expr.expr_kind() {
            ExprKind::And { left, right } => {
                Self::expr_could_error(left) || Self::expr_could_error(right)
            }
            ExprKind::BinaryApp { op, arg1, arg2 } => match op {
                // Arithmetic operations could error
                ast::BinaryOp::Add => true,
                ast::BinaryOp::Mul => true,
                ast::BinaryOp::Sub => true,

                // These operations only error if their sub-expr does
                ast::BinaryOp::Contains => {
                    Self::expr_could_error(arg1) || Self::expr_could_error(arg2)
                }
                ast::BinaryOp::ContainsAll => {
                    Self::expr_could_error(arg1) || Self::expr_could_error(arg2)
                }
                ast::BinaryOp::ContainsAny => {
                    Self::expr_could_error(arg1) || Self::expr_could_error(arg2)
                }
                ast::BinaryOp::Eq => Self::expr_could_error(arg1) || Self::expr_could_error(arg2),
                ast::BinaryOp::GetTag => {
                    Self::expr_could_error(arg1) || Self::expr_could_error(arg2)
                }
                ast::BinaryOp::HasTag => {
                    Self::expr_could_error(arg1) || Self::expr_could_error(arg2)
                }
                ast::BinaryOp::In => Self::expr_could_error(arg1) || Self::expr_could_error(arg2),
                ast::BinaryOp::Less => Self::expr_could_error(arg1) || Self::expr_could_error(arg2),
                ast::BinaryOp::LessEq => {
                    Self::expr_could_error(arg1) || Self::expr_could_error(arg2)
                }
            },
            // Extension functions could error
            ExprKind::ExtensionFunctionApp { .. } => true,

            ExprKind::GetAttr { expr, .. } => Self::expr_could_error(expr),
            ExprKind::HasAttr { expr, .. } => Self::expr_could_error(expr),

            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                Self::expr_could_error(test_expr)
                    || Self::expr_could_error(then_expr)
                    || Self::expr_could_error(else_expr)
            }
            ExprKind::Is { expr, .. } => Self::expr_could_error(expr),
            ExprKind::Like { expr, .. } => Self::expr_could_error(expr),
            ExprKind::Or { left, right } => {
                Self::expr_could_error(left) || Self::expr_could_error(right)
            }
            ExprKind::Record(attrs) => attrs.iter().any(|(_, e)| Self::expr_could_error(e)),

            ExprKind::Set(items) => items.iter().any(Self::expr_could_error),
            ExprKind::UnaryApp { op, arg } => match op {
                ast::UnaryOp::IsEmpty => Self::expr_could_error(arg),
                ast::UnaryOp::Neg => true, // TODO: Could this error?
                ast::UnaryOp::Not => Self::expr_could_error(arg),
            },
            ExprKind::Var(_) => false,
            ExprKind::Lit(_) => false,
            ExprKind::Slot(_) => false,
            ExprKind::Unknown(_) => false,
        }
    }

    fn expr_has_in_k8s_resource(expr: &Expr) -> bool {
        match expr.expr_kind() {
            ExprKind::And { left, right } => {
                Self::expr_has_in_k8s_resource(left) || Self::expr_has_in_k8s_resource(right)
            }
            ExprKind::BinaryApp { arg1, arg2, .. } => {
                Self::expr_has_in_k8s_resource(arg1) || Self::expr_has_in_k8s_resource(arg2)
            }
            ExprKind::ExtensionFunctionApp { args, .. } => {
                args.iter().any(Self::expr_has_in_k8s_resource)
            }
            ExprKind::GetAttr { expr, .. } => Self::expr_has_in_k8s_resource(expr),
            ExprKind::HasAttr { expr, .. } => Self::expr_has_in_k8s_resource(expr),

            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                Self::expr_has_in_k8s_resource(test_expr)
                    || Self::expr_has_in_k8s_resource(then_expr)
                    || Self::expr_has_in_k8s_resource(else_expr)
            }
            ExprKind::Is { expr, entity_type } => {
                Self::expr_has_in_k8s_resource(expr)
                    || match entity_type {
                        ast::EntityType::EntityType(name) => name.to_string() == "k8s::Resource",
                    }
            }
            ExprKind::Like { expr, .. } => Self::expr_has_in_k8s_resource(expr),
            ExprKind::Or { left, right } => {
                Self::expr_has_in_k8s_resource(left) || Self::expr_has_in_k8s_resource(right)
            }
            ExprKind::Record(attrs) => attrs.iter().any(|(_, e)| Self::expr_has_in_k8s_resource(e)),

            ExprKind::Set(items) => items.iter().any(Self::expr_has_in_k8s_resource),
            ExprKind::UnaryApp { arg, .. } => Self::expr_has_in_k8s_resource(arg),
            ExprKind::Var(_) => false,
            ExprKind::Lit(_) => false,
            ExprKind::Slot(_) => false,
            ExprKind::Unknown(_) => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Merges this `PolicySet` with another `PolicySet`.
    /// This `PolicySet` is modified while the other `PolicySet`
    /// remains unchanged.
    ///
    /// The flag `rename_duplicates` controls the expected behavior
    /// when a `PolicyID` in this and the other `PolicySet` conflict.
    ///
    /// When `rename_duplicates` is false, conflicting `PolicyID`s result
    /// in a occupied `PolicySetError`.
    ///
    /// Otherwise, when `rename_duplicates` is true, conflicting `PolicyID`s from
    /// the other `PolicySet` are automatically renamed to avoid conflict.
    /// This renaming is returned as a Hashmap from the old `PolicyID` to the
    /// renamed `PolicyID`.
    pub fn merge_policyset(
        &mut self,
        other: &PolicySet,
        rename_duplicates: bool,
    ) -> Result<HashMap<ast::PolicyID, ast::PolicyID>, ast::PolicySetError> {
        self.policies
            .merge_policyset(other.as_ref(), rename_duplicates)
    }

    pub fn tpe<'a>(
        &'a self,
        request: &'a PartialRequest,
        entities: &'a PartialEntities,
    ) -> Result<PartialResponseNew<'a>, EarlyEvaluationError> {
        use cedar_policy_core::tpe::is_authorized;
        let res: cedar_policy_core::tpe::response::Response<'a> = is_authorized(
            &self.policies,
            request,
            entities,
            self.schema.as_ref().as_ref(),
        )?;

        // TODO: Add res.is_error() instead of this matches!()
        let erroring_forbids = res
            .non_trival_forbids()
            .filter(|id| matches!(res.get_residual(id).unwrap(), Residual::Error(_)))
            .cloned()
            .collect::<Vec<_>>();
        if !erroring_forbids.is_empty() {
            return Err(EarlyEvaluationError::PolicyCouldError(erroring_forbids));
        }

        // TODO: Surface erroring allow policies better.
        Ok(PartialResponseNew {
            schema: self.schema.clone(),
            tpe_response: res,
        })
    }
}

impl AsRef<ast::PolicySet> for PolicySet {
    fn as_ref(&self) -> &ast::PolicySet {
        &self.policies
    }
}

impl TryFrom<PolicySet> for cedar_policy::PolicySet {
    type Error = cedar_policy::PolicySetError;
    fn try_from(ps: PolicySet) -> Result<Self, Self::Error> {
        ps.policies.try_into()
    }
}

impl Display for PolicySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            write!(f, "<empty policyset>")
        } else {
            write!(f, "{}", self.policies.static_policies().join("\n"),)
        }
    }
}

impl Debug for PolicySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

// TODO: This needs better thought, as it's not really a good idea to compare policies by string equality.
impl PartialEq for PolicySet {
    fn eq(&self, other: &Self) -> bool {
        self.policies.to_string() == other.policies.to_string()
            && self.schema.get_fragment() == other.schema.get_fragment()
    }
}

/*#[derive(Serialize, Deserialize)]
struct PartialEntityWithDebug {
    uid: ast::EntityUID,
    attrs: BTreeMap<SmolStr, ast::Value>,
    ancestors: Option<HashSet<ast::EntityUID>>,
    tags: Option<BTreeMap<SmolStr, ast::Value>>,
}*/

mod test {
    #[test]
    fn test_expr_has_in_k8s_resource() {
        use super::PolicySet;
        use cedar_policy_core::ast::Expr;

        // Walk the AST regardless of the actual values, in a nested way.
        let expr: Expr<()> = r#"false && (true || resource is k8s::Resource)"#.parse().unwrap();
        assert!(PolicySet::expr_has_in_k8s_resource(&expr));

        let expr: Expr<()> = r#"(resource is k8s::Resource || true) && false"#.parse().unwrap();
        assert!(PolicySet::expr_has_in_k8s_resource(&expr));

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert!(!PolicySet::expr_has_in_k8s_resource(&expr));

        let expr: Expr<()> = r#"resource is k8s::nonresource::NonResourceURL"#.parse().unwrap();
        assert!(!PolicySet::expr_has_in_k8s_resource(&expr));

        let expr: Expr<()> = r#"(if resource is k8s::Resource then resource else resource) is k8s::nonresource::NonResourceURL"#.parse().unwrap();
        assert!(PolicySet::expr_has_in_k8s_resource(&expr));
    }
}
