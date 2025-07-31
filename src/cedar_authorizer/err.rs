#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error(transparent)]
    SchemaError(#[from] cedar_policy_core::validator::SchemaError),
}