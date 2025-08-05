use cedar_policy_core::ast;
use cedar_policy_core::tpe::err::TPEError;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error(transparent)]
    SchemaError(#[from] cedar_policy_core::validator::SchemaError),
    #[error(transparent)]
    PolicySetError(#[from] cedar_policy_core::ast::PolicySetError),
    #[error("Schema rewrite error: {0}")]
    SchemaRewriteError(String),
    #[error("Resource type {0} not found in schema")]
    MissingResourceType(String),
    #[error("Policy could error, although not allowed to: {0}")]
    PolicyCouldError(ast::PolicyID),
    #[error("Expression 'is k8s::Resource' is disallowed in policies")]
    IsK8sResourceDisallowed,
}

#[derive(Debug, thiserror::Error)]
pub enum EarlyEvaluationError {
    #[error("Unexpected residual form")]
    UnexpectedResidualForm,
    #[error("Policy could error, although not allowed to: {0}")]
    PolicyCouldError(ast::PolicyID),
    #[error("TPE error: {0}")]
    TPEError(#[from] TPEError),
}
