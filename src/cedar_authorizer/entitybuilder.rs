use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(test)]
use std::sync::{LazyLock, Mutex};

use cedar_policy_core::{
    ast::{Eid, EntityType, EntityUID, Literal, Name, Value},
    tpe::entities::PartialEntity,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use smol_str::{SmolStr, ToSmolStr};
use uuid::Uuid;

use crate::schema::core::{ENTITY_OBJECTMETA, MAP_STRINGSTRING, MAP_STRINGSTRINGSET};

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
    fn add_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(&mut self, key: K, value: V) {
        self.record_builder.add_attr(key, value);
    }
}

pub trait IntoValueWithEntities {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    );
}

// Instead of a blanket impl of impl<T: Into<Value>> IntoValueWithEntities for T, we have these specific impls for the types that are used in the authorizer.
// The reason for this is to make sure that arbitrary values do not implement IntoValueWithEntities, as values could contain e.g.
// EntityUIDs, that would mess things up with tracking the relation between jsonpaths and uids.
impl IntoValueWithEntities for &str {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(Literal::String(self.to_smolstr()).into()),
            HashMap::new(),
            HashMap::new(),
        )
    }
}

impl IntoValueWithEntities for &String {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(Literal::String(self.to_smolstr()).into()),
            HashMap::new(),
            HashMap::new(),
        )
    }
}

impl IntoValueWithEntities for SmolStr {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(Literal::String(self).into()),
            HashMap::new(),
            HashMap::new(),
        )
    }
}

impl IntoValueWithEntities for bool {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (Some(self.into()), HashMap::new(), HashMap::new())
    }
}

impl IntoValueWithEntities for Vec<String> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(Value::set_of_lits(self.into_iter().map(|s| s.into()), None)),
            HashMap::new(),
            HashMap::new(),
        )
    }
}

impl IntoValueWithEntities for HashSet<SmolStr> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(Value::set_of_lits(self.into_iter().map(|s| s.into()), None)),
            HashMap::new(),
            HashMap::new(),
        )
    }
}

impl IntoValueWithEntities for BTreeMap<String, String> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        EntityBuilder::new()
            .with_attr(
                "keys",
                self.keys().map(|s| s.into()).collect::<HashSet<_>>(),
            )
            .with_tags(
                self.into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            )
            .build(MAP_STRINGSTRING.0.name())
            .into_value_with_entities()
    }
}

impl IntoValueWithEntities for BTreeMap<String, Vec<String>> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        EntityBuilder::new()
            .with_attr(
                "keys",
                self.keys().map(|s| s.into()).collect::<HashSet<_>>(),
            )
            .with_tags(
                // TODO: If only one value, add a "first" attribute to the entity.
                self.into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            )
            .build(MAP_STRINGSTRINGSET.0.name())
            .into_value_with_entities()
    }
}

// Some(T) is treated as a known value, None is treated as an unset value.
impl<T: IntoValueWithEntities> IntoValueWithEntities for Option<T> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        self.map(|t| t.into_value_with_entities())
            .unwrap_or((None, HashMap::new(), HashMap::new()))
    }
}

impl IntoValueWithEntities for &metav1::ObjectMeta {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        EntityBuilder::new()
            .with_attr("labels", self.labels.clone())
            .with_attr("annotations", self.annotations.clone())
            .with_attr("finalizers", self.finalizers.clone())
            .with_attr("uid", self.uid.as_ref().map(|s| s.to_smolstr()))
            .with_attr("deleted", self.deletion_timestamp.is_some())
            .build(ENTITY_OBJECTMETA.name.name())
            .into_value_with_entities()
    }
}

pub trait RecordBuilder: Sized {
    /// Adds an attribute to the record being built, if Some(value).
    /// Any entities associated with the value are added to the record builder.
    fn add_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(&mut self, key: K, value: V);

    #[must_use]
    fn with_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(mut self, key: K, value: V) -> Self {
        self.add_attr(key, value);
        self
    }
}

pub enum PartialValue<V: IntoValueWithEntities> {
    Known(V),
    Unknown,
    Unset,
}

pub trait HasUnknownType {
    fn unknown_type() -> Name;
}

impl HasUnknownType for &metav1::ObjectMeta {
    fn unknown_type() -> Name {
        "meta::V1ObjectMeta".parse().unwrap()
    }
}

impl IntoValueWithEntities for PartialValue<SmolStr> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        let entity_type = "meta::UnknownString".parse().unwrap();
        match self {
            PartialValue::Known(v) => EntityBuilder::new()
                .with_attr("value", v)
                .build(entity_type)
                .into_value_with_entities(),
            PartialValue::Unknown => {
                EntityBuilder::build_unknown(entity_type).into_value_with_entities()
            }
            PartialValue::Unset => (None, HashMap::new(), HashMap::new()),
        }
    }
}

impl<T: IntoValueWithEntities + HasUnknownType> IntoValueWithEntities for PartialValue<T> {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        match self {
            PartialValue::Known(v) => v.into_value_with_entities(),
            PartialValue::Unknown => {
                EntityBuilder::build_unknown(T::unknown_type()).into_value_with_entities()
            }
            PartialValue::Unset => (None, HashMap::new(), HashMap::new()),
        }
    }
}

pub(super) struct RecordBuilderImpl {
    entity_attrs: Option<BTreeMap<SmolStr, Value>>,
    entities: HashMap<EntityUID, PartialEntity>,
    unknown_jsonpaths_to_uid: HashMap<String, EntityUID>,
}

impl RecordBuilder for RecordBuilderImpl {
    fn add_attr<K: Into<SmolStr>, V: IntoValueWithEntities>(&mut self, key: K, into_value: V) {
        let (value, entities, unknown_jsonpaths_to_uid) = into_value.into_value_with_entities();
        if let Some(value) = value {
            let key_smolstr = key.into();
            self.unknown_jsonpaths_to_uid
                .extend(add_level_to_unknown_jsonpaths(
                    key_smolstr.as_str(),
                    unknown_jsonpaths_to_uid,
                ));
            // Note: There must be no duplicate UIDs in the entities, as we do not deduplicate them.
            self.entities.extend(entities);
            self.entity_attrs
                .get_or_insert(BTreeMap::new())
                .insert(key_smolstr, value);
        }
    }
}

impl IntoValueWithEntities for RecordBuilderImpl {
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(Value::record(self.entity_attrs.unwrap_or_default(), None)),
            self.entities,
            self.unknown_jsonpaths_to_uid,
        )
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
    fn into_value_with_entities(
        self,
    ) -> (
        Option<Value>,
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            Some(self.uid.into()),
            self.entities,
            self.unknown_jsonpaths_to_uid,
        )
    }
}

impl BuiltEntity {
    pub(super) fn uid(&self) -> &EntityUID {
        &self.uid
    }
    pub(super) fn into_parts(
        self,
        toplevel_name: &str,
    ) -> (
        HashMap<EntityUID, PartialEntity>,
        HashMap<String, EntityUID>,
    ) {
        (
            self.entities,
            add_level_to_unknown_jsonpaths(toplevel_name, self.unknown_jsonpaths_to_uid.clone()),
        )
    }
}
fn add_level_to_unknown_jsonpaths(
    level_name: &str,
    unknown_jsonpaths_to_uid: HashMap<String, EntityUID>,
) -> HashMap<String, EntityUID> {
    unknown_jsonpaths_to_uid
        .into_iter()
        .map(|(jsonpath, uid)| {
            (
                format!(
                    "{}{}{}",
                    level_name,
                    if jsonpath.is_empty() { "" } else { "." },
                    jsonpath
                ),
                uid,
            )
        })
        .collect()
}
