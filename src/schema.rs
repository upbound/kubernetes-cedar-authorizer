use cedar_policy_core::validator::json_schema::Fragment;
use cedar_policy_core::validator::RawName;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;
use serde_json::Value;

use err::Result;

mod connect;
pub(crate) mod core;
mod customverbs;
mod discovery;
mod err;
pub mod fork;
mod impersonate;
mod openapi;
mod types;
mod util; // TODO: Remove this once we use the native kube discovery client

pub use discovery::CedarGroupVersion;

// Pipeline:
// 1. Collect all info about the group, its versions, schemas, and discovery data
// 2. Create a Cedar namespace per group, with given common fields
//   a) Loop APIResourceList, and find from there the gvks to link to. Status gets its own Cedar type, with only status fields filled in?
// 3. Add common types/actions used by all

pub fn build_base_schema(rbac_verbs: Vec<String>) -> Result<Fragment<RawName>> {
    let mut fragment = core::build_base()?;
    impersonate::with_impersonation(&mut fragment)?;
    customverbs::with_custom_verbs(&mut fragment, rbac_verbs)?;
    Ok(fragment)
}

pub fn build_schema_for_gv(
    fragment: &mut Fragment<RawName>,
    gv: &CedarGroupVersion,
    apiresourcelist: &APIResourceList,
    openapi_spec: &Value,
) -> Result<()> {
    discovery::with_kubernetes_groupversion(fragment, gv, apiresourcelist)?;
    connect::with_connect_rewrites(fragment, gv, openapi_spec)?;
    openapi::with_openapi_schemas(fragment, openapi_spec)?;

    // TODO: With status rewrite of CRDs
    Ok(())
}
