use thiserror::Error;

use cedar_policy_core::parser::err::ParseErrors;
use cedar_policy_core::validator::json_schema::ReservedCommonTypeBasenameError;

use super::types::ActionUID;

#[derive(Debug, Error)]
pub enum SchemaProcessingError {
    #[error("Action {0} is not defined")]
    ActionNotDefined(ActionUID),

    #[error("OpenAPI error: {0}")]
    OpenAPI(String),

    #[error("Unknown error: {0}")]
    Unknown(String),

    #[error("Cedar schema error: {0}")]
    CedarSchema(Box<ParseErrors>),

    #[error("Reserved common type base name error: {0}")]
    ReservedCommonTypeBaseName(#[from] ReservedCommonTypeBasenameError),
}

pub type Result<T> = std::result::Result<T, SchemaProcessingError>;

impl From<ParseErrors> for SchemaProcessingError {
    fn from(errors: ParseErrors) -> Self {
        SchemaProcessingError::CedarSchema(Box::new(errors))
    }
}
