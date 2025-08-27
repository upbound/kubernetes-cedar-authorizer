#[derive(Debug, thiserror::Error)]
pub enum SymbolicEvaluationError {
    #[error(transparent)]
    SymccError(Box<cedar_policy_symcc::err::Error>),
    #[error(transparent)]
    PolicySetError(Box<cedar_policy::PolicySetError>),
    #[error(transparent)]
    SolverFactoryError(#[from] crate::cedar_authorizer::symcc::SolverFactoryError),
}

impl From<cedar_policy_symcc::err::Error> for SymbolicEvaluationError {
    fn from(error: cedar_policy_symcc::err::Error) -> Self {
        SymbolicEvaluationError::SymccError(Box::new(error))
    }
}

impl From<cedar_policy::PolicySetError> for SymbolicEvaluationError {
    fn from(error: cedar_policy::PolicySetError) -> Self {
        SymbolicEvaluationError::PolicySetError(Box::new(error))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizerError {
    #[error("verb {0} is not supported")]
    UnsupportedVerb(String),
    #[error("invalid principal '{0}': {1}")]
    InvalidPrincipal(String, String),

    #[error(transparent)]
    ParseErrors(Box<cedar_policy_core::parser::err::ParseErrors>),
    #[error(transparent)]
    RequestValidationError(Box<cedar_policy_core::validator::RequestValidationError>),
    #[error(transparent)]
    TPEError(#[from] cedar_policy_core::tpe::err::TPEError),
    #[error(transparent)]
    EntitiesError(Box<cedar_policy_core::tpe::err::EntitiesError>),
    #[error(transparent)]
    EarlyEvaluationError(#[from] crate::cedar_authorizer::kube_invariants::EarlyEvaluationError),

    #[error(transparent)]
    SchemaError(#[from] crate::cedar_authorizer::kube_invariants::SchemaError),
    #[error(transparent)]
    AuthorizerParseError(#[from] ParseError),
    #[error("Unexpected schema shape: {0}")]
    UnexpectedSchemaShape(String),
    #[error(transparent)]
    CedarToCelError(#[from] crate::cedar_authorizer::cel::CedarToCelError),
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error(transparent)]
    SymbolicEvaluationError(#[from] SymbolicEvaluationError),
    #[error(transparent)]
    EntityAttrEvaluationError(Box<cedar_policy_core::ast::EntityAttrEvaluationError>),
}

impl From<cedar_policy_core::parser::err::ParseErrors> for AuthorizerError {
    fn from(errors: cedar_policy_core::parser::err::ParseErrors) -> Self {
        AuthorizerError::ParseErrors(Box::new(errors))
    }
}

impl From<cedar_policy_core::validator::RequestValidationError> for AuthorizerError {
    fn from(errors: cedar_policy_core::validator::RequestValidationError) -> Self {
        AuthorizerError::RequestValidationError(Box::new(errors))
    }
}

impl From<cedar_policy_core::tpe::err::EntitiesError> for AuthorizerError {
    fn from(errors: cedar_policy_core::tpe::err::EntitiesError) -> Self {
        AuthorizerError::EntitiesError(Box::new(errors))
    }
}

impl From<cedar_policy_core::ast::EntityAttrEvaluationError> for AuthorizerError {
    fn from(error: cedar_policy_core::ast::EntityAttrEvaluationError) -> Self {
        AuthorizerError::EntityAttrEvaluationError(Box::new(error))
    }
}

impl axum::response::IntoResponse for AuthorizerError {
    fn into_response(self) -> axum::response::Response {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from(self.to_string()))
            .unwrap()
    }
}

// pub type Result<T> = std::result::Result<T, AuthorizerError>;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid verb '{0}': {1}")]
    InvalidVerb(String, String),
    #[error("invalid value selector (where wildcard is denoted by *) '{0}': {1}")]
    InvalidStarWildcardSelector(String, String),
    #[error("invalid resource '{0}': {1}")]
    InvalidResource(String, String),
    #[error("invalid subresource '{0}': {1}")]
    InvalidSubresource(String, String),
    #[error("invalid username '{0}': {1}")]
    InvalidUsername(String, String),
    #[error("invalid subject access review: {0}")]
    InvalidSubjectAccessReview(String),
    #[error("invalid field selector requirement: {0}")]
    InvalidFieldSelectorRequirement(String),
    #[error("invalid label selector requirement: {0}")]
    InvalidLabelSelectorRequirement(String),
}
