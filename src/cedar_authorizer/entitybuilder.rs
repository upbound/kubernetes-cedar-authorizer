use std::collections::{BTreeMap, HashMap, HashSet};

use cedar_policy_core::{
    ast::{Eid, EntityType, EntityUID, Value},
    tpe::entities::PartialEntity,
};
use smol_str::{SmolStr, ToSmolStr};
use uuid::Uuid;

use crate::schema::core::{MAP_STRINGSTRING, MAP_STRINGSTRINGSET};

pub(super) struct EntityBuilder {
    entity_eid: Option<Eid>,
    entity_tags: Option<BTreeMap<SmolStr, Value>>,
    record_builder: RecordBuilder,
}

impl EntityBuilder {
    pub(super) fn new() -> Self {
        Self {
            entity_eid: None,
            record_builder: RecordBuilder::new(),
            entity_tags: None,
        }
    }

    #[must_use]
    pub(super) fn with_eid(mut self, eid: impl Into<SmolStr>) -> Self {
        self.entity_eid = Some(Eid::new(eid));
        self
    }

    #[must_use]
    pub(super) fn with_tags(mut self, tags: BTreeMap<SmolStr, Value>) -> Self {
        self.entity_tags = Some(tags);
        self
    }

    #[must_use]
    pub(super) fn with_attr<K: Into<SmolStr>, V: Into<Value>>(
        mut self,
        key: K,
        optional_value: Option<V>,
    ) -> Self {
        self.add_attr(key, optional_value);
        self
    }

    #[must_use]
    pub(super) fn with_entity_attr<K: Into<SmolStr>>(
        mut self,
        key: K,
        optional_built: Option<BuiltEntity>,
    ) -> Self {
        self.add_entity_attr(key, optional_built);
        self
    }

    #[must_use]
    pub(super) fn with_string_to_string_map<K: Into<SmolStr>>(
        mut self,
        key: K,
        map: Option<&BTreeMap<String, String>>,
    ) -> Self {
        self.add_string_to_string_map(key, map);
        self
    }

    #[must_use]
    pub(super) fn with_string_to_stringset_map<K: Into<SmolStr>>(
        mut self,
        key: K,
        map: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Self {
        self.add_string_to_stringset_map(key, map);
        self
    }

    #[must_use]
    pub(super) fn with_string_set<K: Into<SmolStr>>(
        mut self,
        key: K,
        set: Option<impl IntoIterator<Item = String>>,
    ) -> Self {
        self.add_string_set(key, set);
        self
    }

    #[must_use]
    pub(super) fn with_record_attr<K: Into<SmolStr>>(
        mut self,
        key: K,
        record: Option<RecordBuilder>,
    ) -> Self {
        self.add_record_attr(key, record);
        self
    }


    pub(super) fn add_attr<K: Into<SmolStr>, V: Into<Value>>(
        &mut self,
        key: K,
        optional_value: Option<V>,
    ) {
        self.record_builder.add_attr(key, optional_value);
    }

    pub(super) fn add_entity_attr<K: Into<SmolStr>>(
        &mut self,
        key: K,
        optional_built: Option<BuiltEntity>,
    ) {
        self.record_builder.add_entity_attr(key, optional_built);
    }

    pub(super) fn add_string_to_string_map<K: Into<SmolStr>>(
        &mut self,
        key: K,
        map: Option<&BTreeMap<String, String>>,
    ) {
        self.record_builder.add_string_to_string_map(key, map);
    }

    pub(super) fn add_string_to_stringset_map<K: Into<SmolStr>>(
        &mut self,
        key: K,
        map: Option<&BTreeMap<String, Vec<String>>>,
    ) {
        self.record_builder.add_string_to_stringset_map(key, map);
    }

    pub(super) fn add_string_set<K: Into<SmolStr>>(
        &mut self,
        key: K,
        set: Option<impl IntoIterator<Item = String>>,
    ) {
        self.record_builder.add_string_set(key, set);
    }

    pub(super) fn add_record_attr<K: Into<SmolStr>>(
        &mut self,
        key: K,
        record: Option<RecordBuilder>,
    ) {
        self.record_builder.add_record_attr(key, record);
    }



    pub(super) fn build(mut self, entity_type: EntityType) -> BuiltEntity {
        let eid = match self.entity_eid {
            Some(eid) => eid,
            None => Eid::new(Uuid::new_v4().to_smolstr()),
        };
        let uid = EntityUID::from_components(entity_type, eid, None);

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
        }
    }
}

pub(super) struct RecordBuilder {
    entity_attrs: Option<BTreeMap<SmolStr, Value>>,
    entities: HashMap<EntityUID, PartialEntity>,
}

impl RecordBuilder {
    pub(super) fn new() -> Self {
        Self {
            entity_attrs: None,
            entities: HashMap::new(),
        }
    }

    #[must_use]
    pub(super) fn with_attr<K: Into<SmolStr>, V: Into<Value>>(
        mut self,
        key: K,
        optional_value: Option<V>,
    ) -> Self {
        self.add_attr(key, optional_value);
        self
    }

    #[must_use]
    pub(super) fn with_entity_attr<K: Into<SmolStr>>(
        mut self,
        key: K,
        optional_built: Option<BuiltEntity>,
    ) -> Self {
        self.add_entity_attr(key, optional_built);
        self
    }

    #[must_use]
    pub(super) fn with_string_to_string_map<K: Into<SmolStr>>(
        mut self,
        key: K,
        map: Option<&BTreeMap<String, String>>,
    ) -> Self {
        self.add_string_to_string_map(key, map);
        self
    }

    #[must_use]
    pub(super) fn with_string_to_stringset_map<K: Into<SmolStr>>(
        mut self,
        key: K,
        map: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Self {
        self.add_string_to_stringset_map(key, map);
        self
    }

    #[must_use]
    pub(super) fn with_string_set<K: Into<SmolStr>>(
        mut self,
        key: K,
        set: Option<impl IntoIterator<Item = String>>,
    ) -> Self {
        self.add_string_set(key, set);
        self
    }

    #[must_use]
    pub(super) fn with_record_attr<K: Into<SmolStr>>(
        mut self,
        key: K,
        record: Option<RecordBuilder>,
    ) -> Self {
        self.add_record_attr(key, record);
        self
    }

    pub(super) fn add_attr<K: Into<SmolStr>, V: Into<Value>>(
        &mut self,
        key: K,
        optional_value: Option<V>,
    ) {
        if let Some(value) = optional_value {
            self.entity_attrs
                .get_or_insert(BTreeMap::new())
                .insert(key.into(), value.into());
        }
    }

    pub(super) fn add_entity_attr<K: Into<SmolStr>>(
        &mut self,
        key: K,
        optional_built: Option<BuiltEntity>,
    ) {
        if let Some(built) = optional_built {
            // TODO: This overwrites any existing entities with the same UID, if present, but
            // should not be a problem as long as we use the same constructor functions for entities
            // that might be built several times. Namespace between ServiceAccount and k8s::Resource is an example.
            self.entities.extend(built.entities);
            self.add_attr(key, Some(built.uid));
        }
    }

    pub(super) fn add_record_attr<K: Into<SmolStr>>(
        &mut self,
        key: K,
        optional_record: Option<RecordBuilder>,
    ) {
        if let Some(record) = optional_record {
            // Add any entities generated by the record builder to the current record builder.
            self.entities.extend(record.entities);
            self.add_attr(key, Some(Value::record(record.entity_attrs.unwrap_or_default(), None)));
        }
    }

    pub(super) fn add_string_to_string_map<K: Into<SmolStr>>(
        &mut self,
        key: K,
        map_option: Option<&BTreeMap<String, String>>,
    ) {
        // Note: Maps are usually required in the schema, but can be empty, so fold None into an empty map.
        let map = match map_option {
            Some(map) => map.clone(),
            None => BTreeMap::new(),
        };
        self.add_entity_attr(
            key,
            Some(
                EntityBuilder::new()
                    .with_string_set("keys", Some(map.keys().cloned()))
                    .with_tags(
                        map.into_iter()
                            .map(|(k, v)| (k.into(), v.into()))
                            .collect(),
                    )
                    .build(EntityType::EntityType(MAP_STRINGSTRING.0.name())),
            ),
        );
    }

    pub(super) fn add_string_to_stringset_map<K: Into<SmolStr>>(
        &mut self,
        key: K,
        map_option: Option<&BTreeMap<String, Vec<String>>>,
    ) {
        // Note: Maps are usually required in the schema, but can be empty, so fold None into an empty map.
        let map = match map_option {
            Some(map) => map.clone(),
            None => BTreeMap::new(),
        };
        self.add_entity_attr(
            key,
            Some(
                EntityBuilder::new()
                    .with_string_set("keys", Some(map.keys().cloned()))
                    .with_tags(
                        map.into_iter()
                            .map(|(k, v)| (k.into(), Value::set_of_lits(v.into_iter().map(|s| s.into()), None)))
                            .collect(),
                    )
                    .build(EntityType::EntityType(MAP_STRINGSTRINGSET.0.name())),
            ),
        );
    }

    pub(super) fn add_string_set<K: Into<SmolStr>, V: IntoIterator<Item = String>>(
        &mut self,
        key: K,
        set_option: Option<V>,
    ) {
        // Note: Sets are usually required in the schema, but can be empty, so fold None into an empty set.
        let set: Vec<_> = match set_option {
            Some(set) => set.into_iter().map(|s| s.into()).collect(),
            None => Vec::new(),
        };
        self.add_attr(
            key,
            Some(
                Value::set_of_lits(set, None)
            ),
        );
    }
}



pub(super) struct BuiltEntity {
    uid: EntityUID,
    entities: HashMap<EntityUID, PartialEntity>,
}

impl BuiltEntity {
    pub(super) fn uid(&self) -> &EntityUID {
        &self.uid
    }
    pub(super) fn consume_entities(self) -> HashMap<EntityUID, PartialEntity> {
        self.entities
    }
}

