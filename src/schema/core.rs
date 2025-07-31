use cedar_policy_core::ast::Name;
use cedar_policy_core::validator::json_schema::{EntityType, Fragment};
use cedar_policy_core::validator::RawName;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::LazyLock;

use std::str::FromStr;

use super::types::{ActionUID, CedarTypeName, EntityWrapper, TypeKind, TypeWrapper};

use super::util::{make_stringmap_type, namespace_of_fragment};

use super::err::Result;

pub static K8S_NS: LazyLock<Option<Name>> = LazyLock::new(|| Some(Name::from_str("k8s").unwrap()));

// TODO: Make it an error to try to use this manually, e.g. through k8s RBAC.
pub(crate) static ACTION_ANY: LazyLock<ActionUID> =
    LazyLock::new(|| ActionUID(K8S_NS.clone(), "*".to_string()));

// For both Resource- and Non-Resource Requests
static ALL_RESOURCE_ACTIONS: LazyLock<[ActionUID; 4]> = LazyLock::new(|| {
    [
        ACTION_ANY.clone(),
        ActionUID(K8S_NS.clone(), "get".to_string()), // HEAD -> get for resource requests
        ActionUID(K8S_NS.clone(), "patch".to_string()), // Not sure if this applies to non-resource requests
        ActionUID(K8S_NS.clone(), "delete".to_string()), // Not sure if this applies to non-resource requests
    ]
});

// For resource-requests only
static ONLY_RESOURCE_ACTIONS: LazyLock<[ActionUID; 6]> = LazyLock::new(|| {
    [
        ActionUID(K8S_NS.clone(), "list".to_string()),
        ActionUID(K8S_NS.clone(), "watch".to_string()),
        // TIL: Creates can have name from the path already, for subresource requests.
        ActionUID(K8S_NS.clone(), "create".to_string()),
        ActionUID(K8S_NS.clone(), "update".to_string()),
        ActionUID(K8S_NS.clone(), "deletecollection".to_string()),
        // Use "connect" action instead of get/post (or whatever returned from ConnectMethods()),
        // based on "x-kubernetes-action" in OpenAPI schema
        // TODO: Special-case pods/log -> connect although that is get in the schema.
        ActionUID(K8S_NS.clone(), "connect".to_string()),
        // TODO: Is "options" verb possible for resource requests? It's not listed in discovery,
        // and not included in the allowlist of verbs in RequestInfoFactory.
    ]
});
// TODO: There is a special proxy verb through /api/v1/proxy, but it doesn't seem wired up to handlers,
// so we can probably skip it.

// For non-resource requests only
static ONLY_NONRESOURCE_ACTIONS: LazyLock<[ActionUID; 4]> = LazyLock::new(|| {
    [
        ActionUID(K8S_NS.clone(), "put".to_string()),
        ActionUID(K8S_NS.clone(), "post".to_string()),
        ActionUID(K8S_NS.clone(), "head".to_string()),
        ActionUID(K8S_NS.clone(), "options".to_string()),
    ]
});

pub(crate) static PRINCIPALS: [&LazyLock<EntityWrapper>; 3] =
    [&PRINCIPAL_USER, &PRINCIPAL_SERVICEACCOUNT, &PRINCIPAL_NODE];

// Entity ID is user UID, or a random UUID
pub(crate) static PRINCIPAL_USER: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(K8S_NS.clone(), "User").unwrap(),
    attrs: BTreeMap::from([
        // User "interface"
        ("username".into(), TypeWrapper::String.required()),
        (
            "groups".into(),
            TypeWrapper::Set(Box::new(TypeWrapper::String)).required(),
        ),
        ("uid".into(), TypeWrapper::String.optional()),
        (
            "extra".into(),
            TypeWrapper::EntityRef(MAP_STRINGSTRINGSET.0.full_name()).required(),
        ),
    ]),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(), // No entity groups for now
        apply_to_actions_as_principal: Vec::from([
            Vec::from(ALL_RESOURCE_ACTIONS.as_slice()).as_slice(),
            Vec::from(ONLY_RESOURCE_ACTIONS.as_slice()).as_slice(),
            Vec::from(ONLY_NONRESOURCE_ACTIONS.as_slice()).as_slice(),
        ])
        .concat(), // TODO: How to know all verbs at this point?
        apply_to_actions_as_resource: Vec::new(),
        tags: None,
    },
});

pub(crate) static PRINCIPAL_SERVICEACCOUNT: LazyLock<EntityWrapper> =
    LazyLock::new(|| EntityWrapper {
        name: CedarTypeName::new(K8S_NS.clone(), "ServiceAccount").unwrap(),
        attrs: BTreeMap::from([
            // User "interface"
            ("username".into(), TypeWrapper::String.required()),
            (
                "groups".into(),
                TypeWrapper::Set(Box::new(TypeWrapper::String)).required(),
            ),
            ("uid".into(), TypeWrapper::String.optional()),
            (
                "extra".into(),
                TypeWrapper::EntityRef(MAP_STRINGSTRINGSET.0.full_name()).required(),
            ),
            // ServiceAccount-specific
            ("name".into(), TypeWrapper::String.required()), // TODO: Mount in the "whole" SA here?
            (
                "namespace".into(),
                TypeWrapper::CommonRef(ENTITY_NAMESPACE.name.full_name()).required(),
            ),
        ]),
        kind: TypeKind::EntityType {
            members_of_types: Vec::from([&ENTITY_NAMESPACE.name]),
            apply_to_actions_as_principal: Vec::from([
                Vec::from(ALL_RESOURCE_ACTIONS.as_slice()).as_slice(),
                Vec::from(ONLY_RESOURCE_ACTIONS.as_slice()).as_slice(),
                Vec::from(ONLY_NONRESOURCE_ACTIONS.as_slice()).as_slice(),
            ])
            .concat(), // TODO: How to know all verbs at this point?
            apply_to_actions_as_resource: Vec::new(),
            tags: None,
        },
    });

pub(crate) static PRINCIPAL_NODE: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(K8S_NS.clone(), "Node").unwrap(),
    attrs: BTreeMap::from([
        // User "interface"
        ("username".into(), TypeWrapper::String.required()),
        (
            "groups".into(),
            TypeWrapper::Set(Box::new(TypeWrapper::String)).required(),
        ),
        ("uid".into(), TypeWrapper::String.optional()),
        (
            "extra".into(),
            TypeWrapper::EntityRef(MAP_STRINGSTRINGSET.0.full_name()).required(),
        ),
        // Node-specific
        ("name".into(), TypeWrapper::String.required()), // TODO: Mount in the "whole" Node here?
    ]),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::from([
            Vec::from(ALL_RESOURCE_ACTIONS.as_slice()).as_slice(),
            Vec::from(ONLY_RESOURCE_ACTIONS.as_slice()).as_slice(),
            Vec::from(ONLY_NONRESOURCE_ACTIONS.as_slice()).as_slice(),
        ])
        .concat(), // TODO: How to know all verbs at this point?
        apply_to_actions_as_resource: Vec::new(),
        tags: None,
    },
});

// TODO: Generate a random UID if the user UID is empty
// TODO: Generate the entity ID for all resources non-deterministically, so users can't "abuse" it.

// ID is .metadata.uid of Namespace. Or maybe just the name?
pub(crate) static ENTITY_NAMESPACE: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(K8S_NS.clone(), "Namespace").unwrap(),
    attrs: BTreeMap::from([
        ("name".into(), TypeWrapper::String.required()),
        (
            "metadata".into(),
            TypeWrapper::CommonRef(TYPE_OBJECTMETA.name.full_name()).required(),
        ),
    ]),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::new(),
        tags: None,
    },
});

// ID is just a random UUID to avoid people depending on the Entity ID.
pub(crate) static RESOURCE_RESOURCE: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(K8S_NS.clone(), "Resource").unwrap(),
    attrs: BTreeMap::from([
        ("apiGroup".into(), TypeWrapper::String.required()),
        // ("apiVersion".into(), TypeWrapper::String.required()), TODO: Add later if needed
        ("resourceCombined".into(), TypeWrapper::String.required()),
        ("name".into(), TypeWrapper::String.required()),
        (
            "namespace".into(),
            TypeWrapper::EntityRef(ENTITY_NAMESPACE.name.full_name()).optional(),
        ),
    ]),
    kind: TypeKind::EntityType {
        members_of_types: Vec::from([&ENTITY_NAMESPACE.name]),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::from([
            Vec::from(ALL_RESOURCE_ACTIONS.as_slice()).as_slice(),
            Vec::from(ONLY_RESOURCE_ACTIONS.as_slice()).as_slice(),
        ])
        .concat(),
        tags: None,
    },
});

// ID is just a random UUID to avoid people depending on the Entity ID.
pub(crate) static RESOURCE_NONRESOURCEURL: LazyLock<EntityWrapper> =
    LazyLock::new(|| EntityWrapper {
        name: CedarTypeName::new(K8S_NS.clone(), "NonResourceURL").unwrap(),
        attrs: BTreeMap::from([("path".into(), TypeWrapper::String.required())]),
        kind: TypeKind::EntityType {
            members_of_types: Vec::new(),
            apply_to_actions_as_principal: Vec::new(),
            apply_to_actions_as_resource: Vec::from([
                Vec::from(ALL_RESOURCE_ACTIONS.as_slice()).as_slice(),
                Vec::from(ONLY_NONRESOURCE_ACTIONS.as_slice()).as_slice(),
            ])
            .concat(),
            tags: None,
        },
    });

pub(super) static META_NS: LazyLock<Option<Name>> =
    LazyLock::new(|| Some(Name::from_str("meta").unwrap()));

// TODO: Evaluate the EntityWrapper again
pub(super) static MAP_STRINGSTRING: LazyLock<(CedarTypeName, EntityType<RawName>)> =
    LazyLock::new(|| make_stringmap_type((&TypeWrapper::String).into()).unwrap());

pub(crate) static MAP_STRINGSTRINGSET: LazyLock<(CedarTypeName, EntityType<RawName>)> =
    LazyLock::new(|| {
        make_stringmap_type((&TypeWrapper::Set(Box::new(TypeWrapper::String))).into()).unwrap()
    });

pub(super) static TYPE_OBJECTMETA: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(META_NS.clone(), "V1ObjectMeta").unwrap(),
    attrs: BTreeMap::from([
        // Required strings
        ("uid".into(), TypeWrapper::String.optional()),
        ("creationTimestamp".into(), TypeWrapper::String.required()), // TODO: timestamp
        ("resourceVersion".into(), TypeWrapper::String.required()),
        // Required sets
        (
            "labels".into(),
            TypeWrapper::EntityRef(MAP_STRINGSTRING.0.full_name()).required(),
        ),
        (
            "annotations".into(),
            TypeWrapper::EntityRef(MAP_STRINGSTRING.0.full_name()).required(),
        ),
        (
            "finalizers".into(),
            TypeWrapper::Set(Box::new(TypeWrapper::String)).required(),
        ),
        // Optional strings
        ("deletionTimestamp".into(), TypeWrapper::String.optional()), // TODO: timestamp
        ("generateName".into(), TypeWrapper::String.optional()),
    ]),
    kind: TypeKind::CommonType,
});

pub(crate) fn build_base() -> Result<Fragment<RawName>> {
    let mut f = Fragment(BTreeMap::new());

    for a in ALL_RESOURCE_ACTIONS.iter() {
        a.apply(
            &mut f,
            None,
            if a.1 == ACTION_ANY.1 {
                None
            } else {
                Some(Vec::from([ACTION_ANY.deref().into()]))
            },
        );
    }
    for a in ONLY_RESOURCE_ACTIONS.iter() {
        a.apply(&mut f, None, Some(Vec::from([ACTION_ANY.deref().into()])));
    }
    for a in ONLY_NONRESOURCE_ACTIONS.iter() {
        a.apply(&mut f, None, Some(Vec::from([ACTION_ANY.deref().into()])));
    }

    PRINCIPAL_USER.apply(&mut f)?;
    PRINCIPAL_SERVICEACCOUNT.apply(&mut f)?;
    PRINCIPAL_NODE.apply(&mut f)?;

    ENTITY_NAMESPACE.apply(&mut f)?;
    RESOURCE_RESOURCE.apply(&mut f)?;
    RESOURCE_NONRESOURCEURL.apply(&mut f)?;

    TYPE_OBJECTMETA.apply(&mut f)?;
    namespace_of_fragment(&mut f, MAP_STRINGSTRING.0.cedar_namespace.clone())
        .entity_types
        .insert(
            MAP_STRINGSTRING.0.type_name.clone(),
            MAP_STRINGSTRING.1.clone(),
        );
    namespace_of_fragment(&mut f, MAP_STRINGSTRINGSET.0.cedar_namespace.clone())
        .entity_types
        .insert(
            MAP_STRINGSTRINGSET.0.type_name.clone(),
            MAP_STRINGSTRINGSET.1.clone(),
        );

    Ok(f)
}

mod test {

    #[test]
    fn test_core_schema() {
        use std::io::Write;

        let test_schema_str =
            std::fs::read_to_string("src/schema/testfiles/core.cedarschema").unwrap_or_default();

        let core_fragment = super::build_base().expect("to succeed");
        let core_fragment_str = core_fragment
            .to_cedarschema()
            .expect("test schema can be displayed");
        println!("{}", core_fragment);
        // assert test schema file is already formatted
        if core_fragment_str != test_schema_str {
            let mut f = std::fs::File::create("src/schema/testfiles/core.cedarschema")
                .expect("open file works");
            f.write_all(core_fragment_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}
