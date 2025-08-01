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
}
