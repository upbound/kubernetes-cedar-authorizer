#[derive(Debug, thiserror::Error)]
pub enum AuthorizerError {
    #[error("invalid attributes: {0}")]
    InvalidAttributes(String),
    #[error("invalid selector: {0}")]
    InvalidSelector(String),
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("invalid policy set: {0}")]
    InvalidPolicySet(String),
    #[error("verb {0} is not supported")]
    UnsupportedVerb(String),
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