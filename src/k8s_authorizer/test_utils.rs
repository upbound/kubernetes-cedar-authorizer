use std::collections::{BTreeMap, HashSet};

use crate::k8s_authorizer::{NonResourceAttributes, RequestType, Selector};

use super::{
    Attributes, CombinedResource, EmptyWildcardStringSelector, ResourceAttributes,
    StarWildcardStringSelector, UserInfo, Verb,
};

pub struct AttributesBuilder {
    attrs: Attributes,
}

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
                request_type: RequestType::NonResource(NonResourceAttributes {
                    path,
                }),
            },
        }
    }

    pub fn resource(username: &str, verb: Verb, api_group: StarWildcardStringSelector,
        resource: CombinedResource,
        namespace: EmptyWildcardStringSelector,
        name: EmptyWildcardStringSelector,) -> Self {
        Self::resource_and_selectors(username, verb, api_group, resource, namespace, name, None, None)
    }

    pub fn resource_and_selectors(username: &str, verb: Verb, api_group: StarWildcardStringSelector,
        resource: CombinedResource,
        namespace: EmptyWildcardStringSelector,
        name: EmptyWildcardStringSelector,
        label_selector: Option<Vec<Selector>>,
        field_selector: Option<Vec<Selector>>,) -> Self {
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
