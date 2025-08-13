use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    sync::Arc,
};

use cedar_policy_core::{
    ast::{self, Expr, ExprKind, Var},
    tpe::{
        entities::{PartialEntities, PartialEntity},
        request::PartialRequest,
        residual::Residual,
    },
    validator::RawName,
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
pub struct PolicySet {
    pub(super) policies: ast::PolicySet,
    schema: Arc<super::Schema>,
}

impl PolicySet {
    pub fn new(policies: &ast::PolicySet, schema: Arc<super::Schema>) -> Result<Self, SchemaError> {
        for p in policies.policies() {
            // INVARIANT: Make sure that no deny policies could error.
            if p.effect() == ast::Effect::Forbid && Self::expr_could_error(&p.condition()) {
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
        }

        // Rewrite the policies to be compatible with Typed Partial Evaluation, according to rewrites in the schema.
        let substituted_policies = ast::PolicySet::try_from_iter(policies.policies().map(|p| {
            ast::Policy::from_when_clause(
                p.effect(),
                Self::rewrite_expr(&p.condition(), schema.rewritten_resource_attributes()),
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
                args.iter().any(|a| Self::expr_has_in_k8s_resource(a))
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

    /// rewrite_expr rewrites an expression to be compatible with Typed Partial Evaluation, for use-cases where
    /// some attributes are unknown, but some are known, using the rewrite documented in:
    /// https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md#contingent-authorization-with-entity-based-unknown-values
    ///
    /// However, the rewrite is only applied to the special case expression "resource.foo" is rewritten to "resource.foo.value", when
    /// "foo" is in the substitutions set.
    fn rewrite_expr(expr: &Expr, rewritten_resource_attributes: &HashMap<String, RawName>) -> Expr {
        match expr.expr_kind() {
            ExprKind::And { left, right } => Expr::and(
                Self::rewrite_expr(left, rewritten_resource_attributes),
                Self::rewrite_expr(right, rewritten_resource_attributes),
            ),
            ExprKind::BinaryApp { op, arg1, arg2 } => Expr::binary_app(
                *op,
                Self::rewrite_expr(arg1, rewritten_resource_attributes),
                Self::rewrite_expr(arg2, rewritten_resource_attributes),
            ),
            ExprKind::ExtensionFunctionApp { fn_name, args } => Expr::call_extension_fn(
                fn_name.clone(),
                args.iter()
                    .map(|a| Self::rewrite_expr(a, rewritten_resource_attributes))
                    .collect(),
            ),
            // TODO: This could become quite a lot more generic, now it's only for resource attributes.
            ExprKind::GetAttr {
                expr: get_expr,
                attr,
            } => {
                let is_resource = matches!(get_expr.expr_kind(), ExprKind::Var(Var::Resource));
                if is_resource && rewritten_resource_attributes.contains_key(attr.as_str()) {
                    return Expr::get_attr(expr.clone(), "value".into());
                } else {
                    Expr::get_attr(
                        Self::rewrite_expr(get_expr, rewritten_resource_attributes),
                        attr.clone(),
                    )
                }
            }
            ExprKind::HasAttr { expr, attr } => Expr::has_attr(
                Self::rewrite_expr(expr, rewritten_resource_attributes),
                attr.clone(),
            ),

            ExprKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => Expr::ite(
                Self::rewrite_expr(test_expr, rewritten_resource_attributes),
                Self::rewrite_expr(then_expr, rewritten_resource_attributes),
                Self::rewrite_expr(else_expr, rewritten_resource_attributes),
            ),
            ExprKind::Is { expr, entity_type } => Expr::is_entity_type(
                Self::rewrite_expr(expr, rewritten_resource_attributes),
                entity_type.clone(),
            ),
            ExprKind::Like { expr, pattern } => Expr::like(
                Self::rewrite_expr(expr, rewritten_resource_attributes),
                pattern.clone(),
            ),
            ExprKind::Or { left, right } => Expr::or(
                Self::rewrite_expr(left, rewritten_resource_attributes),
                Self::rewrite_expr(right, rewritten_resource_attributes),
            ),
            ExprKind::Record(attrs) => Expr::record(attrs.iter().map(|(k, v)| {
                (
                    k.clone(),
                    Self::rewrite_expr(v, rewritten_resource_attributes),
                )
            }))
            .unwrap(),
            ExprKind::Set(items) => Expr::set(
                items
                    .iter()
                    .map(|e| Self::rewrite_expr(e, rewritten_resource_attributes)),
            ),
            ExprKind::UnaryApp { op, arg } => {
                Expr::unary_app(*op, Self::rewrite_expr(arg, rewritten_resource_attributes))
            }
            ExprKind::Var(var) => Expr::var(*var),
            ExprKind::Lit(lit) => Expr::val(lit.clone()),
            ExprKind::Slot(slot_id) => Expr::slot(*slot_id),
            ExprKind::Unknown(unknown) => Expr::unknown(unknown.clone()),
        }
        .with_maybe_source_loc(expr.source_loc().cloned())
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
        if erroring_forbids.len() > 0 {
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

fn debug_entity(entity: PartialEntity) {
    match cedar_policy_core::ast::Entity::new(
        entity.uid,
        entity
            .attrs
            .unwrap_or_default()
            .iter()
            .map(|(k, v)| (k.clone().into(), v.clone().into())),
        HashSet::new(),
        entity
            .ancestors
            .unwrap_or_default()
            .iter()
            .map(|uid| uid.clone().into())
            .collect(),
        entity
            .tags
            .unwrap_or_default()
            .iter()
            .map(|(k, v)| (k.clone().into(), v.clone().into())),
        &cedar_policy_core::extensions::Extensions::all_available(),
    ) {
        Ok(entity) => match entity.to_json_value() {
            Ok(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap()),
            Err(e) => println!("Error: {e:?}"),
        },
        Err(e) => println!("Error: {e:?}"),
    }
}

mod test {
    #[test]
    fn test_has_resource_attribute() {
        use super::PolicySet;
        use cedar_policy_core::ast::Expr;
        use std::collections::HashMap;

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert_eq!(
            PolicySet::rewrite_expr(&expr, &HashMap::new()).to_string(),
            r#"(resource["apiGroup"]) == "foo""#
        );

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert_eq!(
            PolicySet::rewrite_expr(
                &expr,
                &HashMap::from([(
                    "apiGroup".to_string(),
                    "meta::UnknownString".parse().unwrap()
                )])
            )
            .to_string(),
            r#"((resource["apiGroup"])["value"]) == "foo""#
        );

        let expr: Expr<()> = r#"resource.apiGroup == "foo" && [resource.name].contains("bar")"#
            .parse()
            .unwrap();
        assert_eq!(
            PolicySet::rewrite_expr(
                &expr,
                &HashMap::from([
                    (
                        "apiGroup".to_string(),
                        "meta::UnknownString".parse().unwrap()
                    ),
                    ("name".to_string(), "meta::UnknownString".parse().unwrap())
                ])
            )
            .to_string(),
            r#"(((resource["apiGroup"])["value"]) == "foo") && ([(resource["name"])["value"]].contains("bar"))"#
        );

        /*let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert!(!has_resource_attribute(&expr, &HashSet::from([])));

        let expr: Expr<()> = r#"principal.apiGroup == "foo""#.parse().unwrap();
        assert!(!has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"resource has apiGroup"#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"resource.apiGroup.foobar"#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"principal.name == "foo" && resource.apiGroup == "foo""#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));*/
    }

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
