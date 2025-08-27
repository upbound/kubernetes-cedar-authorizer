#[cfg(test)]
use super::{
    Attributes, CombinedResource, EmptyWildcardStringSelector, ResourceAttributes,
    StarWildcardStringSelector, UserInfo, Verb,
};
#[cfg(test)]
use crate::k8s_authorizer::{NonResourceAttributes, RequestType, Selector};
#[cfg(test)]
use std::collections::{BTreeMap, HashSet};

#[cfg(test)]
pub struct AttributesBuilder {
    attrs: Attributes,
}

#[cfg(test)]
impl AttributesBuilder {
    pub fn nonresource(username: &str, verb: Verb, path: StarWildcardStringSelector) -> Self {
        Self {
            attrs: Attributes {
                user: UserInfo {
                    name: username.to_string(),
                    uid: None,
                    groups: HashSet::new(),
                    extra: BTreeMap::new(),
                },
                verb,
                request_type: RequestType::NonResource(NonResourceAttributes { path }),
            },
        }
    }

    pub fn resource(
        username: &str,
        verb: Verb,
        api_group: StarWildcardStringSelector,
        api_version: StarWildcardStringSelector,
        resource: CombinedResource,
        namespace: EmptyWildcardStringSelector,
        name: EmptyWildcardStringSelector,
    ) -> Self {
        Self::resource_and_selectors(
            username,
            verb,
            api_group,
            api_version,
            resource,
            namespace,
            name,
            None,
            None,
        )
    }

    #[warn(clippy::too_many_arguments)]
    pub fn resource_and_selectors(
        username: &str,
        verb: Verb,
        api_group: StarWildcardStringSelector,
        api_version: StarWildcardStringSelector,
        resource: CombinedResource,
        namespace: EmptyWildcardStringSelector,
        name: EmptyWildcardStringSelector,
        label_selector: Option<Vec<Selector>>,
        field_selector: Option<Vec<Selector>>,
    ) -> Self {
        Self {
            attrs: Attributes {
                user: UserInfo {
                    name: username.to_string(),
                    uid: None,
                    groups: HashSet::new(),
                    extra: BTreeMap::new(),
                },
                verb,
                request_type: RequestType::Resource(ResourceAttributes {
                    namespace,
                    resource,
                    name,
                    api_group,
                    api_version,
                    field_selector,
                    label_selector,
                }),
            },
        }
    }

    pub fn with_group(mut self, group: &str) -> Self {
        self.attrs.user.groups.insert(group.to_string());
        self
    }

    pub fn build(self) -> Attributes {
        self.attrs
    }
}
