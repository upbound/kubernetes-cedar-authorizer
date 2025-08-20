use anyhow::Result;
use kube::config::Config;

use kubernetes_cedar_authorizer::schema::{
    build_base_schema, build_schema_for_gv, fork::K8sSchemaGetter, CedarGroupVersion,
};

#[tokio::main]
async fn main() -> Result<()> {
    let mut cedar_schema = build_base_schema(Vec::new())?;

    let config = Config::infer().await?;

    let schema_getter = K8sSchemaGetter::new(config).await?;

    let discovery_urls = schema_getter.get_all_versioned_schemas().await?;
    for discovery_url in discovery_urls {
        let gv = match discovery_url.as_str() {
            "api/v1" => CedarGroupVersion::new("".to_string(), "v1".to_string())?,
            _ => {
                let parts = discovery_url.split('/').collect::<Vec<&str>>();
                CedarGroupVersion::new(parts[1].to_string(), parts[2].to_string())?
            }
        };

        eprintln!("Fetching API resource list: {discovery_url}");
        let api_resource_list = schema_getter.api_resource_list(&discovery_url).await?;

        eprintln!("Fetching schema for API: {discovery_url}");
        let open_api_spec = schema_getter.get_api_schema(&discovery_url).await?;

        build_schema_for_gv(&mut cedar_schema, &gv, &api_resource_list, &open_api_spec)?;
    }

    println!("{cedar_schema}");
    Ok(())
}
