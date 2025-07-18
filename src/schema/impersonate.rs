use std::collections::BTreeMap;
use std::sync::LazyLock;

use cedar_policy_core::ast::Name;
use cedar_policy_core::validator::json_schema::{ApplySpec, Fragment};
use cedar_policy_core::validator::RawName;

use super::core::{ACTION_ANY, K8S_NS, PRINCIPALS};
use super::err::Result;
use super::types::{ActionUID, CedarTypeName, EntityWrapper, TypeKind, TypeWrapper};

use std::ops::Deref;
use std::str::FromStr;

static AUTHENTICATION_K8S_IO_NS: LazyLock<Option<Name>> =
    LazyLock::new(|| Some(Name::from_str("io::k8s::authentication").unwrap()));

static ACTION_IMPERSONATE: LazyLock<ActionUID> =
    LazyLock::new(|| ActionUID(K8S_NS.clone(), "impersonate".to_string()));

static RESOURCE_USERS: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(AUTHENTICATION_K8S_IO_NS.clone(), "users").unwrap(),
    attrs: BTreeMap::new(),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::from([ACTION_IMPERSONATE.clone()]),
        tags: None,
    },
});

// Entity ID should be "system:serviceaccount:<ns>:<name>"
static RESOURCE_SERVICEACCOUNTS: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(AUTHENTICATION_K8S_IO_NS.clone(), "serviceaccounts").unwrap(),
    attrs: BTreeMap::from([
        ("name".into(), TypeWrapper::String.required()),
        ("namespace".into(), TypeWrapper::String.required()),
    ]),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::from([ACTION_IMPERSONATE.clone()]),
        tags: None,
    },
});

static RESOURCE_GROUPS: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(AUTHENTICATION_K8S_IO_NS.clone(), "groups").unwrap(),
    attrs: BTreeMap::new(),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::from([ACTION_IMPERSONATE.clone()]),
        tags: None,
    },
});

// Entity UID is the UID to impersonate
static RESOURCE_UIDS: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(AUTHENTICATION_K8S_IO_NS.clone(), "uids").unwrap(),
    attrs: BTreeMap::new(),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::from([ACTION_IMPERSONATE.clone()]),
        tags: None,
    },
});

// Entity UID is random
static RESOURCE_USEREXTRAS: LazyLock<EntityWrapper> = LazyLock::new(|| EntityWrapper {
    name: CedarTypeName::new(AUTHENTICATION_K8S_IO_NS.clone(), "userextras").unwrap(),
    attrs: BTreeMap::from([
        ("key".into(), TypeWrapper::String.required()),
        ("value".into(), TypeWrapper::String.required()),
    ]),
    kind: TypeKind::EntityType {
        members_of_types: Vec::new(),
        apply_to_actions_as_principal: Vec::new(),
        apply_to_actions_as_resource: Vec::from([ACTION_IMPERSONATE.clone()]),
        tags: None,
    },
});

pub(crate) fn with_impersonation(mut f: &mut Fragment<RawName>) -> Result<()> {
    ACTION_IMPERSONATE.apply(
        &mut f,
        Some(ApplySpec {
            resource_types: Vec::new(),
            principal_types: Vec::from(PRINCIPALS.map(|p| p.name.full_name())),
            context: Default::default(),
        }),
        Some(Vec::from([ACTION_ANY.deref().into()])),
    );

    RESOURCE_USERS.apply(&mut f)?;
    RESOURCE_SERVICEACCOUNTS.apply(&mut f)?;
    RESOURCE_GROUPS.apply(&mut f)?;
    RESOURCE_UIDS.apply(&mut f)?;
    RESOURCE_USEREXTRAS.apply(&mut f)?;

    Ok(())
    // TODO: Do not break layering, make sure that User, ServiceAccount, and Node (?) requests can be impersonate principals.
}

mod test {
    use std::io::Write;

    #[test]
    fn test_core_schema() {
        use crate::schema;
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy_core::validator::json_schema::Fragment;

        let test_schema_str =
            std::fs::read_to_string("src/schema/testfiles/withimpersonation.cedarschema")
                .unwrap_or_default();

        let mut core_fragment = schema::core::build_base().expect("to succeed");
        schema::impersonate::with_impersonation(&mut core_fragment).expect("should work");
        let core_fragment_str = core_fragment
            .to_cedarschema()
            .expect("test schema can be displayed");
        println!("{}", core_fragment);

        // assert test schema file is already formatted
        if core_fragment_str != test_schema_str {
            let mut f = std::fs::File::create("src/schema/testfiles/withimpersonation.cedarschema")
                .expect("open file works");
            f.write_all(core_fragment_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}
