use super::err::ParseError;
use super::selectors::Selector;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;

// TODO: Encode as Attributes<T> where T is the type of the attributes, and then use a trait to implement the methods for the different types?
pub struct Attributes {
    // user returns the user.Info object to authorize
    // if impersonation has taken place, this represents the impersonated user
    pub user: UserInfo,

    // verb returns the kube verb associated with API requests (this includes get, list, watch, create, update, patch, delete, deletecollection, and proxy),
    // or the lowercased HTTP verb associated with non-API requests (this includes get, put, post, patch, and delete)
    // "*" means all.
    pub verb: Verb,

    pub request_type: RequestType,
}

pub enum RequestType {
    Resource(ResourceAttributes),
    NonResource(NonResourceAttributes),
}

pub struct NonResourceAttributes {
    pub path: StarWildcardStringSelector,
}

// TODO: Add the "post", "put", etc. nonresource verbs
// Should these be split between resource and non-resource verbs?
#[derive(Clone, PartialEq)]
pub enum Verb {
    Any,
    Get,
    List,
    Watch,
    Create,
    Update,
    Patch,
    Delete,
    DeleteCollection,
    Connect,
    Impersonate,
    ConstrainedImpersonate,
    Custom(String),
}

impl Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Verb::Any => "*",
            Verb::Get => "get",
            Verb::List => "list",
            Verb::Watch => "watch",
            Verb::Create => "create",
            Verb::Update => "update",
            Verb::Patch => "patch",
            Verb::Delete => "delete",
            Verb::DeleteCollection => "deletecollection",
            Verb::Connect => "connect",
            Verb::Impersonate => "impersonate",
            Verb::ConstrainedImpersonate => "constrainedimpersonate",
            Verb::Custom(v) => v,
        })
    }
}

fn str_is_lowercase_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_lowercase())
}

impl FromStr for Verb {
    type Err = ParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() > 64 {
            return Err(ParseError::InvalidVerb(
                s.to_string(),
                "must be at most 64 characters".to_string(),
            ));
        }
        if s == "*" {
            return Ok(Verb::Any);
        }
        if !str_is_lowercase_ascii(s) {
            return Err(ParseError::InvalidVerb(
                s.to_string(),
                "must only consist of ASCII lowercase letters".to_string(),
            ));
        }
        Ok(match s {
            "get" => Verb::Get,
            "list" => Verb::List,
            "watch" => Verb::Watch,
            "create" => Verb::Create,
            "update" => Verb::Update,
            "patch" => Verb::Patch,
            "delete" => Verb::Delete,
            "deletecollection" => Verb::DeleteCollection,
            "connect" => Verb::Connect,
            "impersonate" => Verb::Impersonate,
            "constrainedimpersonate" => Verb::ConstrainedImpersonate,
            _ => Verb::Custom(s.to_ascii_lowercase()),
        })
    }
}

impl Verb {
    // When is_read_only == true, the request has no side effects, other than
    // caching, logging, and other incidentals.
    /*pub fn is_read_only(&self) -> bool {
        // As per Kubernetes upstream impl.
        matches!(self, Verb::Get | Verb::List | Verb::Watch)
    }*/
}

#[derive(PartialEq)]
pub enum OneOrAll<T> {
    // TODO: Rename to Any?
    All,
    One(T),
}

/// A value that when string-encoded is either "*" (matching anything) or a string (matching exactly).
#[derive(Debug)]
pub enum StarWildcardStringSelector {
    Any,
    Exact(String),
}

impl FromStr for StarWildcardStringSelector {
    type Err = ParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "*" => Ok(StarWildcardStringSelector::Any),
            // TODO: Require that the string is lowercase ascii, does not have spaces, and is at most 255 characters, or something similar.
            _ => Ok(StarWildcardStringSelector::Exact(s.to_string())),
        }
    }
}
impl Display for StarWildcardStringSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Exact(s) => f.write_str(s),
        }
    }
}

impl StarWildcardStringSelector {
    pub fn is_exact(&self) -> bool {
        matches!(self, StarWildcardStringSelector::Exact(_))
    }
}

/// A value that when string-encoded is either "" (matching anything) or a string (matching exactly).
#[derive(Debug)]
pub enum EmptyWildcardStringSelector {
    Any,
    Exact(String),
}

impl FromStr for EmptyWildcardStringSelector {
    type Err = ParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "" => Ok(Self::Any),
            // TODO: Fold "*" literal into Any, even though it's not technically valid by k8s, or throw an error or warning?
            // TODO: Require that the string is lowercase ascii, does not have spaces, and is at most 255 characters, or something similar.
            _ => Ok(Self::Exact(s.to_string())),
        }
    }
}
impl Display for EmptyWildcardStringSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => f.write_str(""),
            Self::Exact(s) => f.write_str(s),
        }
    }
}

#[derive(Debug)]
pub enum CombinedResource {
    Any,

    AnyResourceSpecificSubresource {
        subresource: String,
    },

    // TODO: Kubernetes RBAC didn't implement this one, should we allow it?
    // What happens for a SAR that is like this? I guess it is matched only
    // for a rule that was *. Don't enable for now
    // SpecificResourceAnySubresource { resource: String },
    ResourceOnly {
        resource: String,
    },

    ResourceSubresource {
        resource: String,
        subresource: String,
    },
}

impl CombinedResource {
    fn new(resource: &str, subresource: &str) -> Result<Self, ParseError> {
        if !(str_is_lowercase_ascii(resource) || resource == "*") {
            return Err(ParseError::InvalidResource(
                resource.to_string(),
                "must be lowercase ascii".to_string(),
            ));
        }
        if !(str_is_lowercase_ascii(subresource)) {
            return Err(ParseError::InvalidSubresource(
                subresource.to_string(),
                "must be lowercase ascii".to_string(),
            ));
        }

        let resource = resource.to_string();
        let subresource = subresource.to_string();

        match (resource.as_str(), subresource.as_str()) {
            ("", _) => Err(ParseError::InvalidResource(
                resource.to_string(),
                "cannot be empty".to_string(),
            )),

            ("*", "") => Ok(CombinedResource::Any),
            ("*", _) => Ok(CombinedResource::AnyResourceSpecificSubresource { subresource }),

            (_, "") => Ok(CombinedResource::ResourceOnly { resource }),
            (_, _) => Ok(CombinedResource::ResourceSubresource {
                resource,
                subresource,
            }),
        }
    }

    pub fn wildcard(&self) -> bool {
        match self {
            CombinedResource::Any => true,
            CombinedResource::AnyResourceSpecificSubresource { .. } => true,
            //CombinedResource::SpecificResourceAnySubresource { .. } => true,
            _ => false,
        }
    }

    pub fn concrete(&self) -> bool {
        matches!(
            self,
            CombinedResource::ResourceOnly { .. } | CombinedResource::ResourceSubresource { .. }
        )
    }
}

impl FromStr for CombinedResource {
    type Err = ParseError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '/');
        CombinedResource::new(
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        )
    }
}

impl Display for CombinedResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CombinedResource::Any => f.write_str("*"),
            CombinedResource::AnyResourceSpecificSubresource { subresource } => {
                write!(f, "*/{subresource}")
            }
            //CombinedResource::SpecificResourceAnySubresource { resource } => write!(f, "{resource}/*"),
            CombinedResource::ResourceOnly { resource } => f.write_str(resource),
            CombinedResource::ResourceSubresource {
                resource,
                subresource,
            } => write!(f, "{resource}/{subresource}"),
        }
    }
}

#[derive(Debug)]
pub struct ResourceAttributes {
    // The namespace of the object, if a request is for a REST object.
    // Currently, there is no distinction between no namespace and all namespaces
    // "" (empty) is empty for cluster-scoped resources
    // "" (empty) means "all" for namespace scoped resources from a SubjectAccessReview or SelfSubjectAccessReview
    // TODO: Actually use a multi-state enum here, which can be Any, In(Vec<String>), or NotIn(Vec<String>)
    // TODO: Would it be possible (or even make sense) for SAR senders to distinguish between "unset" and "any" namespace?
    pub namespace: EmptyWildcardStringSelector,

    pub resource: CombinedResource,

    // name returns the name of the object as parsed off the request.  This will not be present for all request types, but
    // will be present for: get, update, delete
    // "" (empty) means all.
    // TODO: Actually use a multi-state enum here, which can be Any, In(Vec<String>), or NotIn(Vec<String>)
    pub name: EmptyWildcardStringSelector,

    // The group of the resource, if a request is for a REST object.
    // "*" means all.
    pub api_group: StarWildcardStringSelector,

    // api_version returns the version of the group requested, if a request is for a REST object.
    // "*" means all.
    // TODO: We could use this to determine which API version is available, in case we do not want to type-check against
    // all versions of the resource, or only the storage one.
    pub api_version: StarWildcardStringSelector,

    // ParseFieldSelector is lazy, thread-safe, and stores the parsed result and error.
    // It returns an error if the field selector cannot be parsed.
    // The returned requirements must be treated as readonly and not modified.
    // TODO: Use field selectors to authorize impersonation requests in a fine-grained way with only one SAR
    // The username is either both or either encoded as the resource name, and .user.username In (lucas),
    // .user.groups In (admin, dev),
    // .user.uid In (1234567890)
    // .user.extra[example.org/foo] In (bar, baz), and
    // .request.verb In (get, list, watch, create, update, patch, delete, deletecollection, connect)
    // .request.resource In (pods, nodes, namespaces, secrets, configmaps, etc.)
    // .request.apiGroup    In (core, apps, etc.)
    // etc. To be consistent with VAP, maybe refer to the user as .request.user instead of top-level
    pub field_selector: Option<Vec<Selector>>,

    // ParseLabelSelector is lazy, thread-safe, and stores the parsed result and error.
    // It returns an error if the label selector cannot be parsed.
    // The returned requirements must be treated as readonly and not modified.
    pub label_selector: Option<Vec<Selector>>,
}

impl ResourceAttributes {
    pub fn is_typed_resource(&self) -> bool {
        match (&self.api_group, &self.resource) {
            (
                StarWildcardStringSelector::Exact(_),
                CombinedResource::ResourceOnly { .. }
                | CombinedResource::ResourceSubresource { .. },
            ) => true,
            _ => false,
        }
    }

    // TODO: Should we validate to only allow only field selectors for specific verbs?
    // TODO: The more generic solution here is to allow multiple values for a field selector,
    // get a residual, and use the SAT/SMT/symbolic compiler method to make sure that all possible values
    // are authorized.
    pub fn default_from_selectors(&mut self) -> Result<(), ParseError> {
        if let Some(field_selectors) = &self.field_selector {
            for field_selector in field_selectors {
                match field_selector.key.as_str() {
                    // Populate the name field from the field selector, if present, like Kubernetes does.
                    "metadata.name" => {
                        match (&self.name, field_selector.exact_match()) {
                            // Fold the field selector value into the spec requirement, just like Kubernetes RequestInfo code does.
                            (EmptyWildcardStringSelector::Any, Some(fieldselector_name)) => {
                                self.name = EmptyWildcardStringSelector::Exact(fieldselector_name);
                            }
                            // No requirements, nothing to do.
                            (EmptyWildcardStringSelector::Any, None) => (),
                            // If name is specified both in the SAR spec and in the field selector, they must match.
                            (
                                EmptyWildcardStringSelector::Exact(spec_name),
                                Some(fieldselector_name),
                            ) => {
                                if spec_name.as_str() != fieldselector_name {
                                    return Err(ParseError::InvalidFieldSelectorRequirement(format!("if metadata.name is specified both on the SubjectAccessReview spec ({spec_name}) and in the field selector ({fieldselector_name}), they must match")));
                                }
                            }
                            // This is the usual case, name is specified in the SAR spec, but no field selector is present.
                            (EmptyWildcardStringSelector::Exact(_), None) => (),
                        }
                    }
                    // Populate the namespace field from the field selector in the similar manner, however, UNLIKE Kubernetes.
                    // We here choose to be consistent with the way we populate the name field, and not Kubernetes.
                    "metadata.namespace" => {
                        match (&self.namespace, field_selector.exact_match()) {
                            // Fold the field selector value into the spec requirement.
                            (EmptyWildcardStringSelector::Any, Some(fieldselector_namespace)) => {
                                self.namespace =
                                    EmptyWildcardStringSelector::Exact(fieldselector_namespace);
                            }
                            // No requirements, nothing to do.
                            (EmptyWildcardStringSelector::Any, None) => (),
                            // If namespace is specified both in the SAR spec and in the field selector, they must match.
                            (
                                EmptyWildcardStringSelector::Exact(spec_namespace),
                                Some(fieldselector_namespace),
                            ) => {
                                if spec_namespace.as_str() != fieldselector_namespace {
                                    return Err(ParseError::InvalidFieldSelectorRequirement(format!("if metadata.namespace is specified both on the SubjectAccessReview spec ({spec_namespace}) and in the field selector ({fieldselector_namespace}), they must match")));
                                }
                            }
                            // This is the usual case, namespace is specified in the SAR spec, but no field selector is present.
                            (EmptyWildcardStringSelector::Exact(_), None) => (),
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(())
    }
}

pub struct UserInfo {
    // name returns the name that uniquely identifies this user among all
    // other active users.
    pub name: String,

    // uid returns a unique value for a particular user that will change
    // if the user is removed from the system and another user is added with
    // the same name.
    pub uid: Option<String>,

    // groups returns the names of the groups the user is a member of
    // TODO: Warning if duplicate groups are present?
    pub groups: HashSet<String>,

    // extra can contain any additional information that the authenticator
    // thought was interesting.  One example would be scopes on a token.
    // Keys in this map should be namespaced to the authenticator or
    // authenticator/authorizer pair making use of them.
    // For instance: "example.org/foo" instead of "foo"
    // This is a map[string][]string because it needs to be serializeable into
    // a SubjectAccessReviewSpec.authorization.k8s.io for proper authorization
    // delegation flows
    // In order to faithfully round-trip through an impersonation flow, these keys
    // MUST be lowercase.
    pub extra: BTreeMap<String, Vec<String>>,
}

impl UserInfo {
    // TODO: Also check for system:unauthenticated group?
    /*pub fn is_any_principal(&self) -> bool {
        Self::is_any_username(&self.name)
    }*/

    pub fn is_any_username(username: &str) -> bool {
        username == "system:anonymous"
    }
}
