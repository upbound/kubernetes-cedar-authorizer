#[derive(Debug, thiserror::Error)]
pub enum AuthorizerError {
    #[error("verb {0} is not supported")]
    UnsupportedVerb(String),
    #[error("invalid principal '{0}': {1}")]
    InvalidServiceAccount(String, String),

    #[error(transparent)]
    ParseErrors(#[from] cedar_policy_core::parser::err::ParseErrors),
    #[error(transparent)]
    RequestValidationError(#[from] cedar_policy_core::validator::RequestValidationError),
    #[error(transparent)]
    TPEError(#[from] cedar_policy_core::tpe::err::TPEError),
    #[error(transparent)]
    EntitiesError(#[from] cedar_policy_core::tpe::err::EntitiesError),
    #[error("No Kubernetes namespace found in schema")]
    NoKubernetesNamespace,
    #[error(transparent)]
    EarlyEvaluationError(#[from] crate::cedar_authorizer::residuals::EarlyEvaluationError),

    #[error(transparent)]
    PolicySetError(#[from] cedar_policy::PolicySetError)
}


// pub type Result<T> = std::result::Result<T, AuthorizerError>;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid verb '{0}': {1}")]
    InvalidVerb(String, String),
    #[error("invalid value selector (where wildcard is donated by *) '{0}': {1}")]
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