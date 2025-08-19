use std::{collections::{BTreeMap, HashMap}, sync::Arc};
#[cfg(test)]
use std::sync::{LazyLock, Mutex};

use cedar_policy_core::{
    ast::{Eid, EntityType, EntityUID, InternalName, Name, Value, Literal},
    tpe::entities::PartialEntity,
};
use smol_str::{SmolStr, ToSmolStr};
use uuid::Uuid;
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;

use crate::schema::core::{MAP_STRINGSTRING, MAP_STRINGSTRINGSET, ENTITY_OBJECTMETA};

#[cfg(test)]
static TEST_RNG: LazyLock<Mutex<rand::rngs::StdRng>> = LazyLock::new(|| {
    use rand::SeedableRng;
    Mutex::new(rand::rngs::StdRng::seed_from_u64(42))
});

// This function automatically uses a fixed seed in tests
pub fn new_uuid() -> Uuid {
    #[cfg(test)]
    {
        use rand::Rng;
        uuid::Builder::from_random_bytes(TEST_RNG.lock().unwrap().random()).into_uuid()
        // Fixed seed for tests
    }

    #[cfg(not(test))]
    {
        Uuid::new_v4() // Random UUID in production
    }
}

pub(super) struct EntityBuilder {
    entity_eid: Option<Eid>,
    entity_tags: Option<BTreeMap<SmolStr, Value>>,
    record_builder: RecordBuilderImpl,
}

impl EntityBuilder {
    pub(super) fn new() -> Self {
        Self {
            entity_eid: None,
            record_builder: RecordBuilderImpl::new(),
            entity_tags: None,
        }
    }

    pub(super) fn unknown_string(optional_value: Option<String>) -> BuiltEntity {
        let entity_type = "meta::UnknownString".parse().unwrap();
        match optional_value {
            Some(value) => EntityBuilder::new()
                .with_attr("value", Some(value.as_str()))
                .build(entity_type),
            None => Self::build_unknown(entity_type),
        }
    }

    #[must_use]
    pub(super) fn with_tags(mut self, tags: BTreeMap<SmolStr, Value>) -> Self {
        self.entity_tags = Some(tags);
        self
    }

    pub(super) fn build_unknown(entity_type_name: Name) -> BuiltEntity {
        let uid = EntityUID::from_components(
            EntityType::EntityType(entity_type_name),
            Eid::new(new_uuid().to_smolstr()),
            None,
        );
        BuiltEntity {
            uid: uid.clone(),
            entities: HashMap::new(),
            unknown_jsonpaths_to_uid: HashMap::from([(String::new(), uid)]),
        }
    }

    // TODO: Make this cleaner?
    pub(super) fn build_unknown_internal_name(entity_type_name: InternalName) -> BuiltEntity {
        Self::build_unknown(entity_type_name.to_string().parse().unwrap())
    }

    pub(super) fn build(mut self, entity_type_name: Name) -> BuiltEntity {
        let eid = match self.entity_eid {
            Some(eid) => eid,
            None => Eid::new(new_uuid().to_smolstr()),
        };
        let uid = EntityUID::from_components(EntityType::EntityType(entity_type_name), eid, None);

        self.record_builder.entities.insert(
            uid.clone(),
            PartialEntity {
                uid: uid.clone(),
                attrs: self.record_builder.entity_attrs,
                ancestors: None,
                tags: self.entity_tags,
            },
        );

        BuiltEntity {
            uid,
            entities: self.record_builder.entities,
            unknown_jsonpaths_to_uid: self.record_builder.unknown_jsonpaths_to_uid,
        }
    }
}
impl RecordBuilder for EntityBuilder {
    fn add_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(
        &mut self,
        key: K,
        optional_value: Option<V>,
    ) {
        self.record_builder.add_attr(key, optional_value);
    }
}

pub trait IntoValueWithEntities {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>);
}


// Instead of a blanket impl of impl<T: Into<Value>> IntoValueWithEntities for T, we have these specific impls for the types that are used in the authorizer.
// The reason for this is to make sure that arbitrary values do not implement IntoValueWithEntities, as values could contain e.g.
// EntityUIDs, that would mess things up with tracking the relation between jsonpaths and uids.
impl IntoValueWithEntities for &str {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>) {
        (self.into(), std::iter::empty(), std::iter::empty())
    }
}

impl IntoValueWithEntities for SmolStr {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>) {
        (Literal::String(self).into(), std::iter::empty(), std::iter::empty())
    }
}

impl IntoValueWithEntities for bool {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>) {
        (self.into(), std::iter::empty(), std::iter::empty())
    }
}

impl IntoValueWithEntities for Vec<&str> {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>) {
        (Value::set_of_lits(self.into_iter().map(|s| s.into()), None), std::iter::empty(), std::iter::empty())
    }
}

pub trait RecordBuilder: Sized {
    /// Adds an attribute to the record being built, if Some(value).
    /// Any entities associated with the value are added to the record builder.
    fn add_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(
        &mut self,
        key: K,
        optional_value: Option<V>,
    );

    fn add_string_to_string_map<K: Into<SmolStr>>(
        &mut self,
        key: K,
        map_option: Option<&BTreeMap<String, String>>,
    ) {
        // Note: Maps are usually required in the schema, but can be empty, so fold None into an empty map.
        let map = match map_option {
            Some(map) => map.clone(),
            None => BTreeMap::new(),
        };
        self.add_attr(
            key,
            Some(
                EntityBuilder::new()
                    .with_string_set("keys", Some(map.keys().map(|s| s.as_str())))
                    .with_tags(map.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
                    .build(MAP_STRINGSTRING.0.name()),
            ),
        );
    }

    fn add_string_to_stringset_map<K: Into<SmolStr>>(
        &mut self,
        key: K,
        map_option: Option<&BTreeMap<String, Vec<String>>>,
    ) {
        // Note: Maps are usually required in the schema, but can be empty, so fold None into an empty map.
        let map = match map_option {
            Some(map) => map.clone(),
            None => BTreeMap::new(),
        };
        self.add_attr(
            key,
            Some(
                EntityBuilder::new()
                    .with_string_set("keys", Some(map.keys().map(|s| s.as_str())))
                    .with_tags( // TODO: If only one value, add a "first" attribute to the entity.
                        map.into_iter()
                            .map(|(k, v)| {
                                (
                                    k.into(),
                                    Value::set_of_lits(v.into_iter().map(|s| s.into()), None),
                                )
                            })
                            .collect(),
                    )
                    .build(MAP_STRINGSTRINGSET.0.name()),
            ),
        );
    }

    fn add_string_set<'a, K: Into<SmolStr>, V: IntoIterator<Item = &'a str>>(
        &mut self,
        key: K,
        set_option: Option<V>,
    ) {
        // Note: Sets are usually required in the schema, but can be empty, so fold None into an empty set.
        let set_vec: Vec<&str> = match set_option {
            Some(set) => set.into_iter().collect(),
            None => Vec::new(),
        };
        self.add_attr(key, Some(set_vec));
    }

    fn add_metadata(&mut self, metadata_option: Option<&metav1::ObjectMeta>) {
        self.add_attr(
            "metadata",
            match metadata_option {
                Some(metadata) => 
                    Some(EntityBuilder::new()
                        .with_string_to_string_map("labels", metadata.labels.as_ref())
                        .with_string_to_string_map("annotations", metadata.annotations.as_ref())
                        .with_string_set("finalizers", metadata.finalizers.as_ref().map(|s| s.iter().map(|s| s.as_str())))
                        .with_attr("uid", metadata.uid.as_ref().map(|uid| uid.as_str()))
                        .with_attr("deleted", Some(metadata.deletion_timestamp.is_some()))
                        .build(ENTITY_OBJECTMETA.name.name())),
                None => Some(EntityBuilder::build_unknown_internal_name(ENTITY_OBJECTMETA.name.name().into())),
            },
        );
    }

    #[must_use]
    fn with_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(
        mut self,
        key: K,
        optional_value: Option<V>,
    ) -> Self {
        self.add_attr(key, optional_value);
        self
    }

    #[must_use]
    fn with_string_to_string_map<K: Into<SmolStr>>(
        mut self,
        key: K,
        map: Option<&BTreeMap<String, String>>,
    ) -> Self {
        self.add_string_to_string_map(key, map);
        self
    }

    #[must_use]
    fn with_string_to_stringset_map<K: Into<SmolStr>>(
        mut self,
        key: K,
        map: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Self {
        self.add_string_to_stringset_map(key, map);
        self
    }

    #[must_use]
    fn with_string_set<'a, K: Into<SmolStr>>(
        mut self,
        key: K,
        set: Option<impl IntoIterator<Item = &'a str>>,
    ) -> Self {
        self.add_string_set(key, set);
        self
    }

    #[must_use]
    fn with_metadata(mut self, metadata_option: Option<&metav1::ObjectMeta>) -> Self {
        self.add_metadata(metadata_option);
        self
    }
}

pub(super) struct RecordBuilderImpl {
    entity_attrs: Option<BTreeMap<SmolStr, Value>>,
    entities: HashMap<EntityUID, PartialEntity>,
    unknown_jsonpaths_to_uid: HashMap<String, EntityUID>,
}

impl RecordBuilder for RecordBuilderImpl {
    fn add_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(
        &mut self,
        key: K,
        optional_value: Option<V>,
    ) {
        if let Some(v) = optional_value {
            let (value, entities, unknown_jsonpaths_to_uid) = v.into_value_with_entities();
            let key_smolstr = key.into();
            self.unknown_jsonpaths_to_uid.extend(add_level_to_unknown_jsonpaths(key_smolstr.as_str(), unknown_jsonpaths_to_uid));
            // Note: There must be no duplicate UIDs in the entities, as we do not deduplicate them.
            self.entities.extend(entities);
            self.entity_attrs
                .get_or_insert(BTreeMap::new())
                .insert(key_smolstr, value.into());
        }
    }
}

impl IntoValueWithEntities for RecordBuilderImpl {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>) {
        (Value::record(self.entity_attrs.unwrap_or_default(), None), self.entities.into_iter(), self.unknown_jsonpaths_to_uid.into_iter())
    }
}

impl RecordBuilderImpl {
    pub(super) fn new() -> Self {
        Self {
            entity_attrs: None,
            entities: HashMap::new(),
            unknown_jsonpaths_to_uid: HashMap::new(),
        }
    }
}

pub(super) struct BuiltEntity {
    uid: EntityUID,
    entities: HashMap<EntityUID, PartialEntity>,
    unknown_jsonpaths_to_uid: HashMap<String, EntityUID>,
}

impl IntoValueWithEntities for BuiltEntity {
    fn into_value_with_entities(self) -> (Value, impl IntoIterator<Item = (EntityUID, PartialEntity)>, impl IntoIterator<Item = (String, EntityUID)>) {
        (self.uid.into(), self.entities.into_iter(), self.unknown_jsonpaths_to_uid.into_iter())
    }
}

impl BuiltEntity {
    pub(super) fn uid(&self) -> &EntityUID {
        &self.uid
    }
    pub(super) fn into_parts(self, toplevel_name: &str) -> (HashMap<EntityUID, PartialEntity>, HashMap<String, EntityUID>) {
        (self.entities, add_level_to_unknown_jsonpaths(toplevel_name, self.unknown_jsonpaths_to_uid.clone()))
    }
}
fn add_level_to_unknown_jsonpaths(level_name: &str, unknown_jsonpaths_to_uid: impl IntoIterator<Item = (String, EntityUID)>) -> HashMap<String, EntityUID> {
    unknown_jsonpaths_to_uid.into_iter().map(|(jsonpath, uid)| (format!("{}{}{}", level_name, if jsonpath.is_empty() { "" } else { "." }, jsonpath), uid)).collect()
}