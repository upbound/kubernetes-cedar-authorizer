use cedar_policy_core::validator::json_schema::{ApplySpec, Fragment};
use cedar_policy_core::validator::RawName;

use crate::schema::core::{RESOURCE_ACTION_ANY, PRINCIPALS, RESOURCE_RESOURCE};

use super::core::K8S_NS;
use super::err::Result;
use super::types::ActionUID;
use std::ops::Deref;
use std::sync::LazyLock;

static CORE_EXTRA_VERBS: LazyLock<[ActionUID; 6]> = LazyLock::new(|| {
    [
        // podsecuritypolicies in either extensions or policy API group
        ActionUID(K8S_NS.clone(), "use".to_string()), // TODO: Attach to the PSP resource type
        // certificates.k8s.io signers; non-namespaced
        ActionUID(K8S_NS.clone(), "attest".to_string()),
        ActionUID(K8S_NS.clone(), "approve".to_string()),
        ActionUID(K8S_NS.clone(), "sign".to_string()),
        // Kubernetes RBAC on ClusterRole or Role
        ActionUID(K8S_NS.clone(), "bind".to_string()), // TODO: Attach to the Role resource types
        ActionUID(K8S_NS.clone(), "escalate".to_string()),
    ]
});

pub(crate) fn with_custom_verbs(
    f: &mut Fragment<RawName>,
    rbac_verbs: Vec<String>, // TODO: Map from verb -> Vec<CedarTypeName> the verb should apply to.
) -> Result<()> {
    let rbac_actions: Vec<ActionUID> = rbac_verbs
        .into_iter()
        .map(|rbac_verb| ActionUID(K8S_NS.clone(), rbac_verb))
        .collect();

    for action_iter in [CORE_EXTRA_VERBS.iter(), rbac_actions.iter()] {
        for action in action_iter {
            action.apply(
                f,
                Some(ApplySpec {
                    resource_types: Vec::from([RESOURCE_RESOURCE.name.full_name()]),
                    principal_types: Vec::from(PRINCIPALS.map(|p| p.name.full_name())),
                    context: Default::default(),
                }),
                Some(Vec::from([RESOURCE_ACTION_ANY.deref().into()])),
            );
        }
    }

    Ok(())
}

mod test {

    #[test]
    fn test_core_schema() {
        use crate::schema;
        use std::io::Write;

        let test_schema_str =
            std::fs::read_to_string("src/schema/testfiles/withcustomverbs.cedarschema")
                .unwrap_or_default();

        let mut core_fragment = schema::core::build_base().expect("to succeed");
        schema::impersonate::with_impersonation(&mut core_fragment).expect("should work");
        schema::customverbs::with_custom_verbs(&mut core_fragment, Vec::new())
            .expect("should work");
        let core_fragment_str = core_fragment
            .to_cedarschema()
            .expect("test schema can be displayed");
        println!("{core_fragment}");
        // assert test schema file is already formatted
        if core_fragment_str != test_schema_str {
            let mut f = std::fs::File::create("src/schema/testfiles/withcustomverbs.cedarschema")
                .expect("open file works");
            f.write_all(core_fragment_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}
