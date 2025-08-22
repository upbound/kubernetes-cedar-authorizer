use cedar_policy_core::ast;
use cedar_policy_core::tpe::err::TPEError;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error(transparent)]
    SchemaError(Box<cedar_policy_core::validator::SchemaError>),
    #[error(transparent)]
    PolicySetError(#[from] cedar_policy_core::ast::PolicySetError),
    #[error("Schema rewrite error: {0}")]
    SchemaRewriteError(String),
    #[error("Resource type {0} not found in schema")]
    MissingResourceType(String),
    #[error("Policy {0} could error, although not allowed to")]
    PolicyCouldError(ast::PolicyID),
    #[error("Policy {0} contains the disallowed expression 'is k8s::Resource'")]
    IsK8sResourceDisallowed(ast::PolicyID),
    #[error("Policy {0} is not static, only static policies are allowed for now")]
    PolicyIsNotStatic(ast::PolicyID),
    #[error(transparent)]
    EarlyEvaluationError(#[from] EarlyEvaluationError),
    #[error(transparent)]
    SolverFactoryError(#[from] crate::cedar_authorizer::symcc::SolverFactoryError),
}

#[derive(Debug, thiserror::Error)]
pub enum EarlyEvaluationError {
    #[error("Unexpected residual form")]
    UnexpectedResidualForm,
    #[error("Policies could error, although not allowed to: {0:?}")]
    PolicyCouldError(Vec<ast::PolicyID>),
    #[error("TPE error: {0}")]
    TPEError(#[from] TPEError),
}

impl From<cedar_policy_core::validator::SchemaError> for SchemaError {
    fn from(errors: cedar_policy_core::validator::SchemaError) -> Self {
        SchemaError::SchemaError(Box::new(errors))
    }
}
