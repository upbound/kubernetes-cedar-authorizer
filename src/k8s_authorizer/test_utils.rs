use std::collections::{BTreeMap, HashSet};

use super::{
    Attributes, CombinedResource, EmptyWildcardStringSelector, ResourceAttributes,
    StarWildcardStringSelector, UserInfo, Verb,
};

pub struct AttributesBuilder {
    attrs: Attributes,
}

impl AttributesBuilder {
    pub fn new(username: &str, verb: Verb) -> Self {
        Self {
            attrs: Attributes {
                user: UserInfo {
                    name: username.to_string(),
                    uid: None,
                    groups: HashSet::new(),
                    extra: BTreeMap::new(),
                },
                verb,
                path: None,
                resource_attrs: None,
            },
        }
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.attrs.path = Some(path.to_string());
        self
    }

    pub fn with_group(mut self, group: &str) -> Self {
        self.attrs.user.groups.insert(group.to_string());
        self
    }

    pub fn with_resource(
        mut self,
        api_group: StarWildcardStringSelector,
        resource: CombinedResource,
        namespace: EmptyWildcardStringSelector,
        name: EmptyWildcardStringSelector,
    ) -> Self {
        match self.attrs.resource_attrs {
            Some(ref mut resource_attrs) => {
                resource_attrs.namespace = namespace;
                resource_attrs.resource = resource;
                resource_attrs.name = name;
                resource_attrs.api_group = api_group;
            }
            None => {
                self.attrs.resource_attrs = Some(ResourceAttributes {
                    namespace,
                    resource,
                    name,
                    api_group,
                    field_selector: None,
                    label_selector: None,
                });
            }
        }
        self
    }
    pub fn build(self) -> Attributes {
        self.attrs
    }
}
