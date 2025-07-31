use std::collections::{BTreeMap, HashMap};

use cedar_policy_core::{
    ast::{Eid, EntityType, EntityUID, Value},
    tpe::{entities::PartialEntity, request::PartialEntityUID},
    validator::{json_schema::TypeOfAttribute, RawName},
};
use smol_str::{SmolStr, ToSmolStr};
use uuid::Uuid;

pub(super) struct EntityBuilder {
    entity_eid: Option<Eid>,
    entity_attrs: Option<BTreeMap<SmolStr, Value>>,
    entities: HashMap<EntityUID, PartialEntity>,
    entity_tags: Option<BTreeMap<SmolStr, Value>>,
}

impl EntityBuilder {
    pub(super) fn new() -> Self {
        Self {
            entity_eid: None,
            entity_attrs: None,
            entities: HashMap::new(),
            entity_tags: None,
        }
    }

    #[must_use]
    pub(super) fn with_eid(mut self, eid: impl Into<SmolStr>) -> Self {
        self.entity_eid = Some(Eid::new(eid));
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
    pub(super) fn with_tags(mut self, tags: BTreeMap<SmolStr, Value>) -> Self {
        self.entity_tags = Some(tags);
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
            self.entities.extend(built.entities.into_iter());
            self.add_attr(key, Some(built.uid));
        }
    }

    pub(super) fn build(mut self, entity_type: EntityType) -> BuiltEntity {
        let eid = match self.entity_eid {
            Some(eid) => eid,
            None => Eid::new(Uuid::new_v4().to_smolstr()),
        };
        let uid = EntityUID::from_components(entity_type, eid, None);

        self.entities.insert(
            uid.clone(),
            PartialEntity {
                uid: uid.clone(),
                attrs: self.entity_attrs,
                ancestors: None,
                tags: self.entity_tags,
            },
        );

        BuiltEntity {
            uid: uid.into(),
            entities: self.entities,
        }
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

pub(super) fn string_slice<'a>(slice: impl IntoIterator<Item = &'a String>) -> Value {
    Value::set_of_lits(slice.into_iter().map(|s| s.as_str().into()), None)
}
