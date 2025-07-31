use std::{collections::HashMap, sync::Arc};

use cedar_policy::PolicySet;
use cedar_policy_core::ast;
use cedar_policy_core::tpe::err::TPEError;
use cedar_policy_core::validator::types;
use cedar_policy_core::{
    ast::Annotations,
    tpe::{
        entities::PartialEntities,
        request::PartialRequest,
        residual::{Residual, ResidualKind},
    },
    validator::ValidatorSchema,
};

#[derive(Debug, Clone)]
pub struct Residuals<'a> {
    pub(super) ps: PolicySet,
    pub(super) res: HashMap<ast::PolicyID, Arc<Residual>>,
    pub(super) request: &'a PartialRequest,
    pub(super) entities: &'a PartialEntities,
    pub(super) schema: &'a ValidatorSchema,
}

#[derive(Debug, Clone)]
pub struct PartialResponseNew {
    // TODO: Add Annotations here to be able to re-construct the policies?
    /// All of the [`Effect::Permit`] policies that were satisfied
    pub true_permits: Vec<ast::PolicyID>,
    /// All of the [`Effect::Permit`] policies that were not satisfied
    pub false_permits: Vec<ast::PolicyID>,
    /// All of the [`Effect::Permit`] policies that evaluated to a residual
    pub residual_permits: HashMap<ast::PolicyID, FoldedResidual>,
    /// All of the [`Effect::Forbid`] policies that were satisfied
    pub true_forbids: Vec<ast::PolicyID>,
    /// All of the [`Effect::Forbid`] policies that were not satisfied
    pub false_forbids: Vec<ast::PolicyID>,
    /// All of the [`Effect::Forbid`] policies that evaluated to a residual
    pub residual_forbids: HashMap<ast::PolicyID, FoldedResidual>,
    // All of the policy errors encountered during evaluation
    pub errors: HashMap<ast::PolicyID, types::Type>,
}

pub enum DetailedDecision {
    // If the request is denied with this non-empty enum, then at least one deny rule matched
    Deny(Vec<ast::PolicyID>),
    // If we got to conditional, then either we got a conditional deny policy and at least some true or conditional allow policies.
    Conditional(Vec<ast::Policy>),
    // If we are allowed, then we know that there were no deny policies that were either true or residual that did not fold to false,
    // AND we had at least one allow policy that was always true.
    Allow(Vec<ast::PolicyID>),
    // No allow rule matched
    NoOpinion,
}

enum AllowDecision {
    Allow(Vec<ast::PolicyID>),
    Conditional(Vec<ast::Policy>),
    NoMatch,
}

impl PartialResponseNew {
    // - If there are any true denies, deny.
    // (- If there are any folded true denies, deny.)
    // We can add this optimization later.
    // - If there are any residual denies (that do not fold to false), conditional
    // TODO: Should we give full context here; i.e. including foldable residual forbid policies?
    // In the beginning, we do not do this, but keep things simple.
    // The permit policies could potentially just be folded into "true", if there is at least one true.
    // - If there are any true allows, allow.
    // - NOTE: Do not fold allows to true, only to false.
    // - If there are any residual allows (that do not fold to false), conditional
    //   At this point, it is known that there are no residual denies.
    // - Otherwise (only false denies and allows, or none), no opinion.
    pub fn decision(&self) -> DetailedDecision {
        if !self.true_forbids.is_empty() {
            return DetailedDecision::Deny(self.true_forbids.clone());
        }

        let non_false_folded_forbid_residuals = self.non_false_folded_forbid_residuals();
        if !non_false_folded_forbid_residuals.is_empty() {
            return match self.allow_decision() {
                AllowDecision::Allow(ids) => {
                    let mut residual_policies = non_false_folded_forbid_residuals;
                    residual_policies.extend(ids.into_iter().map(|id| {
                        ast::Policy::from_when_clause_annos(
                            ast::Effect::Permit,
                            ast::Expr::val(true).into(),
                            id,
                            None,
                            Annotations::new().into(),
                        )
                    }));
                    DetailedDecision::Conditional(residual_policies)
                }
                AllowDecision::Conditional(mut allow_residuals) => {
                    let mut residual_policies = non_false_folded_forbid_residuals;
                    residual_policies.append(&mut allow_residuals);
                    DetailedDecision::Conditional(residual_policies)
                }
                AllowDecision::NoMatch => DetailedDecision::NoOpinion,
            };
        }

        // At this point, we know that all deny policies that existed, were false, or did fold to false, so we're good to go
        // for the allow part instead.
        match self.allow_decision() {
            AllowDecision::Allow(ids) => DetailedDecision::Allow(ids),
            // TODO: Should we include here the forbid or permit policies that did fold to false? I guess not, and that is a "feature" for clarity.
            AllowDecision::Conditional(allow_residuals) => {
                DetailedDecision::Conditional(allow_residuals)
            }
            AllowDecision::NoMatch => DetailedDecision::NoOpinion,
        }
    }

    // - If there are any true allows, allow.
    // - NOTE: Do not fold allows to true, only to false.
    // - If there are any residual allows (that do not fold to false), conditional
    //   At this point, it is known that there are no residual denies.
    // - Otherwise (only false denies and allows, or none), no opinion.
    fn allow_decision(&self) -> AllowDecision {
        if !self.true_permits.is_empty() {
            return AllowDecision::Allow(self.true_forbids.clone());
        }

        let non_false_folded_allow_residuals = self.non_false_folded_allow_residuals();
        if !non_false_folded_allow_residuals.is_empty() {
            return AllowDecision::Conditional(non_false_folded_allow_residuals);
        }

        AllowDecision::NoMatch
    }

    fn non_false_folded_allow_residuals(&self) -> Vec<ast::Policy> {
        self.residual_permits
            .iter()
            .filter(|(_, r)| !matches!(r.error_free_value, Some(false)))
            .map(|(id, r)| {
                r.residual
                    .clone()
                    .to_policy(id.clone(), ast::Effect::Permit, Annotations::new())
            })
            .collect()
    }

    fn non_false_folded_forbid_residuals(&self) -> Vec<ast::Policy> {
        self.residual_forbids
            .iter()
            .filter(|(_, r)| !matches!(r.error_free_value, Some(false)))
            .map(|(id, r)| {
                r.residual
                    .clone()
                    .to_policy(id.clone(), ast::Effect::Forbid, Annotations::new())
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct FoldedResidual {
    pub(crate) residual: Residual,
    // In case there are no errors, and error_free_value is Some, that is the value the residual is known to evaluate to,
    // when all data is available.
    pub(crate) error_free_value: Option<bool>,
}

impl Residuals<'_> {
    pub fn is_authorized_new(&self) -> Result<PartialResponseNew, EarlyEvaluationError> {
        let mut true_permits = vec![];
        let mut true_forbids = vec![];
        let mut false_permits = vec![];
        let mut false_forbids = vec![];
        let mut residual_permits = HashMap::new();
        let mut residual_forbids = HashMap::new();
        let mut errors = HashMap::new();

        for p in self.ps.policies() {
            let id = p.as_ref().id().clone();
            let residual = self.res.get(&id).unwrap();

            match (p.effect(), residual.as_ref()) {
                (
                    ast::Effect::Permit,
                    Residual::Concrete {
                        value:
                            ast::Value {
                                value: ast::ValueKind::Lit(ast::Literal::Bool(true)),
                                ..
                            },
                        ..
                    },
                ) => {
                    true_permits.push(id);
                }
                (
                    ast::Effect::Permit,
                    Residual::Concrete {
                        value:
                            ast::Value {
                                value: ast::ValueKind::Lit(ast::Literal::Bool(false)),
                                ..
                            },
                        ..
                    },
                ) => {
                    false_permits.push(id);
                }

                (ast::Effect::Permit, Residual::Partial { kind, .. }) => {
                    residual_permits.insert(
                        id,
                        FoldedResidual {
                            residual: residual.as_ref().clone(), // TODO: Is clone really needed here?
                            error_free_value: match residual_bool_value_ignoring_potential_errors(
                                residual,
                            )? {
                                BoolResidualValue::True => Some(true),
                                BoolResidualValue::Unknown => None,
                                BoolResidualValue::False => Some(false),
                            },
                        },
                    );
                }
                (
                    ast::Effect::Forbid,
                    Residual::Concrete {
                        value:
                            ast::Value {
                                value: ast::ValueKind::Lit(ast::Literal::Bool(true)),
                                ..
                            },
                        ..
                    },
                ) => {
                    true_forbids.push(id);
                }
                (
                    ast::Effect::Forbid,
                    Residual::Concrete {
                        value:
                            ast::Value {
                                value: ast::ValueKind::Lit(ast::Literal::Bool(false)),
                                ..
                            },
                        ..
                    },
                ) => {
                    false_forbids.push(id);
                }
                (ast::Effect::Forbid, Residual::Partial { kind, .. }) => {
                    // Cedar policies (both permit and forbid) are skipped if they error, so we make sure
                    // that forbid errors are impossible, so we can fold e.g. <residual> || true into true.
                    // For our use-case, we should enforce this already at policy submission stage, but here
                    // is a late check just in case for the general case.
                    if residual_could_error(residual) {
                        return Err(EarlyEvaluationError::PolicyCouldError);
                    }

                    residual_forbids.insert(
                        id,
                        FoldedResidual {
                            residual: residual.as_ref().clone(), // TODO: Is clone really needed here?
                            error_free_value: match residual_bool_value_ignoring_potential_errors(
                                residual,
                            )? {
                                BoolResidualValue::True => Some(true),
                                BoolResidualValue::Unknown => None,
                                BoolResidualValue::False => Some(false),
                            },
                        },
                    );
                }
                // We expect only concrete values that are either true or false, regardless of effect
                (_, Residual::Concrete { .. }) => {
                    return Err(EarlyEvaluationError::UnexpectedResidualForm); // TODO: Add a better error message here
                }
                // INVARIANT: We should validate the forbid policy to not be able to error, so this shouldn't happen.
                (ast::Effect::Forbid, Residual::Error(_)) => {
                    return Err(EarlyEvaluationError::PolicyCouldError); // TODO: Add a better error message here
                }
                // For now, ignore permit errors (e.g. from arithmetic overflows)
                // TODO: We'd want a better error type here, e.g. https://docs.rs/cedar-policy/latest/cedar_policy/enum.EvaluationError.html
                (ast::Effect::Permit, Residual::Error(ty)) => {
                    errors.insert(id, ty.clone());
                }
            }
        }

        Ok(PartialResponseNew {
            true_permits,
            false_permits,
            residual_permits,
            true_forbids,
            false_forbids,
            residual_forbids,
            errors,
        })
    }
}

pub(super) fn tpe<'a>(
    policies: &PolicySet,
    request: &'a PartialRequest,
    entities: &'a PartialEntities,
    schema: &'a ValidatorSchema,
) -> Result<Residuals<'a>, TPEError> {
    use cedar_policy_core::tpe::tpe_policies;
    let ps = policies.as_ref();
    let res = tpe_policies(ps, request, entities, schema)?;
    // PANIC SAFETY: `res` should have the same policy ids with `ps`
    #[allow(clippy::unwrap_used)]
    Ok(Residuals {
        res: res
            .clone()
            .into_iter()
            .map(|(id, r)| (id, Arc::new(r)))
            .collect(),
        ps: PolicySet::from_policies(res.into_iter().map(|(id, r)| {
            let p = ps.get(&id).unwrap();
            r.to_policy(id, p.effect(), p.annotations_arc().as_ref().clone())
                .into()
        }))
        .unwrap(),
        request,
        entities,
        schema,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum EarlyEvaluationError {
    #[error("Policy could error")]
    PolicyCouldError,

    #[error("Unexpected residual form")]
    UnexpectedResidualForm,
}

#[derive(Debug, PartialEq)]
pub(crate) enum BoolResidualValue {
    True,
    False,
    Unknown,
}

// TODO: Use Option<Bool> instead of BoolResidualValue
fn residual_bool_value_ignoring_potential_errors(
    r: &Arc<Residual>,
) -> Result<BoolResidualValue, EarlyEvaluationError> {
    Ok(match r.as_ref() {
        Residual::Partial { kind, .. } => match kind {
            // Always boolean return-value expressions
            ResidualKind::And { left, right } => match (
                residual_bool_value_ignoring_potential_errors(left)?,
                residual_bool_value_ignoring_potential_errors(right)?,
            ) {
                (BoolResidualValue::True, BoolResidualValue::True) => BoolResidualValue::True,
                (BoolResidualValue::False, _) | (_, BoolResidualValue::False) => {
                    BoolResidualValue::False
                }
                (BoolResidualValue::Unknown, _) | (_, BoolResidualValue::Unknown) => {
                    BoolResidualValue::Unknown
                }
            },
            ResidualKind::Or { left, right } => match (
                residual_bool_value_ignoring_potential_errors(left)?,
                residual_bool_value_ignoring_potential_errors(right)?,
            ) {
                (BoolResidualValue::True, _) | (_, BoolResidualValue::True) => {
                    BoolResidualValue::True
                }
                (BoolResidualValue::False, BoolResidualValue::False) => BoolResidualValue::False,
                (BoolResidualValue::Unknown, _) | (_, BoolResidualValue::Unknown) => {
                    BoolResidualValue::Unknown
                }
            },

            ResidualKind::HasAttr { .. } => BoolResidualValue::Unknown,
            ResidualKind::Is { .. } => BoolResidualValue::Unknown,
            ResidualKind::Like { .. } => BoolResidualValue::Unknown,

            // Potentially boolean return-value expressions
            ResidualKind::If {
                then_expr,
                else_expr,
                ..
            } => match (is_bool_residual(then_expr), is_bool_residual(else_expr)) {
                (true, true) => match (
                    residual_bool_value_ignoring_potential_errors(then_expr)?,
                    residual_bool_value_ignoring_potential_errors(else_expr)?,
                ) {
                    (BoolResidualValue::True, BoolResidualValue::True) => BoolResidualValue::True,
                    (BoolResidualValue::False, BoolResidualValue::False) => {
                        BoolResidualValue::False
                    }
                    _ => BoolResidualValue::Unknown,
                },
                // Non-boolean return values error; this function should only be called on boolean-typed residuals
                _ => return Err(EarlyEvaluationError::UnexpectedResidualForm),
            },
            ResidualKind::BinaryApp { op, .. } => match op {
                ast::BinaryOp::Contains => BoolResidualValue::Unknown,
                ast::BinaryOp::ContainsAll => BoolResidualValue::Unknown,
                ast::BinaryOp::ContainsAny => BoolResidualValue::Unknown,
                ast::BinaryOp::Eq => BoolResidualValue::Unknown,
                ast::BinaryOp::HasTag => BoolResidualValue::Unknown,
                ast::BinaryOp::In => BoolResidualValue::Unknown,
                ast::BinaryOp::Less => BoolResidualValue::Unknown,
                ast::BinaryOp::LessEq => BoolResidualValue::Unknown,

                // Non-boolean return values error; this function should only be called on boolean-typed residuals
                ast::BinaryOp::Add => return Err(EarlyEvaluationError::UnexpectedResidualForm),
                ast::BinaryOp::Mul => return Err(EarlyEvaluationError::UnexpectedResidualForm),
                ast::BinaryOp::Sub => return Err(EarlyEvaluationError::UnexpectedResidualForm),
                ast::BinaryOp::GetTag => return Err(EarlyEvaluationError::UnexpectedResidualForm),
            },
            ResidualKind::UnaryApp { op, arg } => match op {
                ast::UnaryOp::Not => match residual_bool_value_ignoring_potential_errors(arg)? {
                    BoolResidualValue::True => BoolResidualValue::False,
                    BoolResidualValue::False => BoolResidualValue::True,
                    BoolResidualValue::Unknown => BoolResidualValue::Unknown,
                },
                ast::UnaryOp::IsEmpty => BoolResidualValue::Unknown,
                // Non-boolean return values error; this function should only be called on boolean-typed residuals
                ast::UnaryOp::Neg => return Err(EarlyEvaluationError::UnexpectedResidualForm),
            },

            // Non-boolean return values error; this function should only be called on boolean-typed residuals
            ResidualKind::GetAttr { .. } => {
                return Err(EarlyEvaluationError::UnexpectedResidualForm)
            }
            ResidualKind::ExtensionFunctionApp { .. } => {
                return Err(EarlyEvaluationError::UnexpectedResidualForm)
            }
            ResidualKind::Var(_) => return Err(EarlyEvaluationError::UnexpectedResidualForm),
            ResidualKind::Record(_) => return Err(EarlyEvaluationError::UnexpectedResidualForm),
            ResidualKind::Set(_) => return Err(EarlyEvaluationError::UnexpectedResidualForm),
        },
        Residual::Concrete { value, .. } => match value.value_kind() {
            ast::ValueKind::Lit(ast::Literal::Bool(true)) => BoolResidualValue::True,
            ast::ValueKind::Lit(ast::Literal::Bool(false)) => BoolResidualValue::False,
            _ => return Err(EarlyEvaluationError::UnexpectedResidualForm),
        },
        Residual::Error(_) => return Err(EarlyEvaluationError::UnexpectedResidualForm),
    })
}

fn is_bool_residual(r: &Residual) -> bool {
    match r {
        Residual::Partial { ty, .. } => is_bool_type(ty),
        Residual::Concrete { ty, .. } => is_bool_type(ty),
        Residual::Error(_) => false,
    }
}

fn is_bool_type(ty: &types::Type) -> bool {
    match ty {
        types::Type::Primitive { primitive_type } => *primitive_type == types::Primitive::Bool,
        _ => false,
    }
}

fn residual_could_error(r: &Residual) -> bool {
    match r {
        Residual::Partial { kind, .. } => match kind {
            ResidualKind::And { left, right } => {
                residual_could_error(left) || residual_could_error(right)
            }
            ResidualKind::BinaryApp { op, arg1, arg2 } => match op {
                // Arithmetic operations could error
                ast::BinaryOp::Add => true,
                ast::BinaryOp::Mul => true,
                ast::BinaryOp::Sub => true,

                // These operations only error if their sub-expr does
                ast::BinaryOp::Contains => residual_could_error(arg1) || residual_could_error(arg2),
                ast::BinaryOp::ContainsAll => {
                    residual_could_error(arg1) || residual_could_error(arg2)
                }
                ast::BinaryOp::ContainsAny => {
                    residual_could_error(arg1) || residual_could_error(arg2)
                }
                ast::BinaryOp::Eq => residual_could_error(arg1) || residual_could_error(arg2),
                ast::BinaryOp::GetTag => residual_could_error(arg1) || residual_could_error(arg2),
                ast::BinaryOp::HasTag => residual_could_error(arg1) || residual_could_error(arg2),
                ast::BinaryOp::In => residual_could_error(arg1) || residual_could_error(arg2),
                ast::BinaryOp::Less => residual_could_error(arg1) || residual_could_error(arg2),
                ast::BinaryOp::LessEq => residual_could_error(arg1) || residual_could_error(arg2),
            },
            // Extension functions could error
            ResidualKind::ExtensionFunctionApp { .. } => true,

            ResidualKind::GetAttr { expr, .. } => residual_could_error(expr),
            ResidualKind::HasAttr { expr, .. } => residual_could_error(expr),

            ResidualKind::If {
                test_expr,
                then_expr,
                else_expr,
            } => {
                residual_could_error(test_expr)
                    || residual_could_error(then_expr)
                    || residual_could_error(else_expr)
            }
            ResidualKind::Is { expr, .. } => residual_could_error(expr),
            ResidualKind::Like { expr, .. } => residual_could_error(expr),
            ResidualKind::Or { left, right } => {
                residual_could_error(left) || residual_could_error(right)
            }
            ResidualKind::Record(attrs) => attrs.iter().any(|(_, e)| residual_could_error(e)),

            ResidualKind::Set(items) => items.iter().any(residual_could_error),
            ResidualKind::UnaryApp { op, arg } => match op {
                ast::UnaryOp::IsEmpty => residual_could_error(arg),
                ast::UnaryOp::Neg => true, // TODO: Could this error?
                ast::UnaryOp::Not => residual_could_error(arg),
            },
            ResidualKind::Var(_) => false,
        },
        Residual::Concrete { .. } => false, // TODO: Can ExtensionFunctionApp error?
        Residual::Error(_) => true,
    }
}
