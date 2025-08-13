use std::sync::Arc;

use cedar_policy_core::ast;
use cedar_policy_core::{
    ast::Annotations,
    tpe,
    tpe::residual::{Residual, ResidualKind},
};

use super::EarlyEvaluationError;

#[derive(Clone)]
pub struct PartialResponseNew<'a> {
    pub(super) schema: Arc<super::Schema>,
    pub tpe_response: tpe::response::Response<'a>,
}

pub enum DetailedDecision {
    // If the request is denied with this non-empty enum, then at least one deny rule matched
    Deny(Vec<ast::PolicyID>),
    // If we got to conditional, then either we got a conditional deny policy and at least some true or conditional allow policies.
    Conditional(super::PolicySet),
    // If we are allowed, then we know that there were no deny policies that were either true or residual that did not fold to false,
    // AND we had at least one allow policy that was always true.
    Allow(Vec<ast::PolicyID>),
    // No allow rule matched
    NoOpinion,
}

enum AllowDecision {
    Allow(Vec<ast::PolicyID>),
    Conditional(super::PolicySet),
    NoMatch,
}

impl<'a> PartialResponseNew<'a> {
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
    pub fn decision(&self) -> Result<DetailedDecision, super::SchemaError> {
        if self.tpe_response.satisfied_forbids().count() > 0 {
            return Ok(DetailedDecision::Deny(
                self.tpe_response.satisfied_forbids().cloned().collect(),
            ));
        }

        let non_false_folded_forbid_residuals = self.non_false_folded_forbid_residuals()?;
        if !non_false_folded_forbid_residuals.is_empty() {
            return match self.allow_decision()? {
                AllowDecision::Allow(ids) => {
                    let allowed_residuals =
                        ast::PolicySet::try_from_iter(ids.into_iter().map(|id| {
                            ast::Policy::from_when_clause_annos(
                                ast::Effect::Permit,
                                ast::Expr::val(true).into(),
                                id,
                                None,
                                Annotations::new().into(),
                            )
                        }))?;
                    let allowed_residuals =
                        super::PolicySet::new(&allowed_residuals, self.schema.clone())?;
                    let mut residual_policies = non_false_folded_forbid_residuals;
                    residual_policies.merge_policyset(&allowed_residuals, false)?; // TODO: Figure out how to handle policy IDs
                    Ok(DetailedDecision::Conditional(residual_policies))
                }
                AllowDecision::Conditional(allow_residuals) => {
                    let mut residual_policies = non_false_folded_forbid_residuals;
                    residual_policies.merge_policyset(&allow_residuals, false)?;
                    Ok(DetailedDecision::Conditional(residual_policies))
                }
                AllowDecision::NoMatch => Ok(DetailedDecision::NoOpinion),
            };
        }

        // At this point, we know that all deny policies that existed, were false, or did fold to false, so we're good to go
        // for the allow part instead.
        match self.allow_decision()? {
            AllowDecision::Allow(ids) => Ok(DetailedDecision::Allow(ids)),
            // TODO: Should we include here the forbid or permit policies that did fold to false? I guess not, and that is a "feature" for clarity.
            AllowDecision::Conditional(allow_residuals) => {
                Ok(DetailedDecision::Conditional(allow_residuals))
            }
            AllowDecision::NoMatch => Ok(DetailedDecision::NoOpinion),
        }
    }

    // - If there are any true allows, allow.
    // - NOTE: Do not fold allows to true, only to false.
    // - If there are any residual allows (that do not fold to false), conditional
    //   At this point, it is known that there are no residual denies.
    // - Otherwise (only false denies and allows, or none), no opinion.
    fn allow_decision(&self) -> Result<AllowDecision, super::SchemaError> {
        if self.tpe_response.satisfied_permits().count() > 0 {
            return Ok(AllowDecision::Allow(
                self.tpe_response.satisfied_permits().cloned().collect(),
            ));
        }

        let non_false_folded_allow_residuals = self.non_false_folded_allow_residuals()?;
        if !non_false_folded_allow_residuals.is_empty() {
            return Ok(AllowDecision::Conditional(non_false_folded_allow_residuals));
        }

        Ok(AllowDecision::NoMatch)
    }

    fn non_false_folded_allow_residuals(&self) -> Result<super::PolicySet, super::SchemaError> {
        // TODO: Improve the ergonomics of the upstream library API, this is unnecessarily complicated.
        let ps = ast::PolicySet::try_from_iter(
            self.tpe_response
                .non_trival_permits()
                .map(|id| (id, self.tpe_response.get_residual(id).unwrap()))
                .flat_map(
                    |(id, r)| match residual_bool_value_ignoring_potential_errors(r) {
                        Ok(Some(false)) => None,
                        Ok(Some(true)) | Ok(None) => Some(Ok(self
                            .tpe_response
                            .residual_policies()
                            .into_iter()
                            .find(|p| p.id() == id)
                            .unwrap())),
                        Err(e) => Some(Err(e)),
                    },
                )
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        super::PolicySet::new(&ps, self.schema.clone())
    }

    fn non_false_folded_forbid_residuals(&self) -> Result<super::PolicySet, super::SchemaError> {
        // TODO: Improve the ergonomics of the upstream library API, this is unnecessarily complicated.
        let ps = ast::PolicySet::try_from_iter(
            self.tpe_response
                .non_trival_forbids()
                .map(|id| (id, self.tpe_response.get_residual(id).unwrap()))
                .flat_map(
                    |(id, r)| match residual_bool_value_ignoring_potential_errors(r) {
                        Ok(Some(false)) => None,
                        Ok(Some(true)) | Ok(None) => Some(Ok(self
                            .tpe_response
                            .residual_policies()
                            .into_iter()
                            .find(|p| p.id() == id)
                            .unwrap())),
                        Err(e) => Some(Err(e)),
                    },
                )
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        super::PolicySet::new(&ps, self.schema.clone())
    }
}

// TODO: We could probably already rely on the TPE to have validated all of this correctly,
// and just return None if the residual form is unexpected, it "shouldn't" happen.
fn residual_bool_value_ignoring_potential_errors(
    r: &Residual,
) -> Result<Option<bool>, super::EarlyEvaluationError> {
    Ok(match r {
        Residual::Partial { kind, .. } => match kind {
            // Always boolean return-value expressions
            ResidualKind::And { left, right } => match (
                residual_bool_value_ignoring_potential_errors(left)?,
                residual_bool_value_ignoring_potential_errors(right)?,
            ) {
                (Some(true), Some(true)) => Some(true),
                (Some(false), _) | (_, Some(false)) => Some(false),
                (None, _) | (_, None) => None,
            },
            ResidualKind::Or { left, right } => match (
                residual_bool_value_ignoring_potential_errors(left)?,
                residual_bool_value_ignoring_potential_errors(right)?,
            ) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                (None, _) | (_, None) => None,
            },

            ResidualKind::HasAttr { .. } => None,
            ResidualKind::Is { .. } => None,
            ResidualKind::Like { .. } => None,

            // Potentially boolean return-value expressions
            ResidualKind::If {
                then_expr,
                else_expr,
                ..
            } => match (
                residual_bool_value_ignoring_potential_errors(then_expr)?,
                residual_bool_value_ignoring_potential_errors(else_expr)?,
            ) {
                (Some(true), Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            ResidualKind::BinaryApp { op, .. } => match op {
                ast::BinaryOp::Contains => None,
                ast::BinaryOp::ContainsAll => None,
                ast::BinaryOp::ContainsAny => None,
                ast::BinaryOp::Eq => None,
                ast::BinaryOp::HasTag => None,
                ast::BinaryOp::In => None,
                ast::BinaryOp::Less => None,
                ast::BinaryOp::LessEq => None,

                // Non-boolean return values error; this function should only be called on boolean-typed residuals
                ast::BinaryOp::Add => return Err(EarlyEvaluationError::UnexpectedResidualForm),
                ast::BinaryOp::Mul => return Err(EarlyEvaluationError::UnexpectedResidualForm),
                ast::BinaryOp::Sub => return Err(EarlyEvaluationError::UnexpectedResidualForm),
                ast::BinaryOp::GetTag => return Err(EarlyEvaluationError::UnexpectedResidualForm),
            },
            ResidualKind::UnaryApp { op, arg } => match op {
                ast::UnaryOp::Not => match residual_bool_value_ignoring_potential_errors(arg)? {
                    Some(true) => Some(false),
                    Some(false) => Some(true),
                    None => None,
                },
                ast::UnaryOp::IsEmpty => None,
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
            ast::ValueKind::Lit(ast::Literal::Bool(true)) => Some(true),
            ast::ValueKind::Lit(ast::Literal::Bool(false)) => Some(false),
            _ => return Err(EarlyEvaluationError::UnexpectedResidualForm),
        },
        Residual::Error(_) => return Err(EarlyEvaluationError::UnexpectedResidualForm),
    })
}
