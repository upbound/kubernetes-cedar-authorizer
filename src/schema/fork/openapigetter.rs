// NOTE: This is a small, temporary fork of
// https://github.com/micahhausler/cedar-access-control-for-k8s/blob/rust-with-schema-rewrite/src/schema/convert/openapi.rs#L27-L104
// by Micah Hausler, and licensed under Apache 2.0.

use anyhow::{anyhow, Result};
use http::Request;
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::client::Client;
use kube::config::Config;
use regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// Equivalent to the Path struct in Go, renamed to avoid collision with std::path::Path
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiPath {
    #[serde(rename = "serverRelativeURL")]
    pub server_relative_url: String,
}

// Equivalent to the PathDocument struct in Go
#[derive(Debug, Serialize, Deserialize)]
struct PathDocument {
    pub paths: HashMap<String, ApiPath>,
}

// Equivalent to the K8sSchemaGetter struct in Go
pub struct K8sSchemaGetter {
    client: Client,
}

impl K8sSchemaGetter {
    pub async fn new(config: Config) -> Result<Self> {
        let client = Client::try_from(config)?;
        Ok(K8sSchemaGetter { client })
    }

    pub async fn get_api_schema(&self, suffix: &str) -> Result<Value> {
        let uri = format!("/openapi/v3/{suffix}");

        let req = Request::get(uri.as_str())
            .body(Vec::<u8>::new())
            .map_err(|e| anyhow!("Failed to create request: {}", e))?;

        // Use the raw HTTP client to make the GET request
        let response = self
            .client
            .request(req)
            .await
            .map_err(|e| anyhow!("Failed to get openapi: {}", e))?;

        Ok(response)
    }

    pub async fn get_all_versioned_schemas(&self) -> Result<Vec<String>> {
        let uri = "/openapi/v3";
        let req = Request::get(uri)
            .body(Vec::<u8>::new())
            .map_err(|e| anyhow!("Failed to create request: {}", e))?;

        let response = self
            .client
            .request(req)
            .await
            .map_err(|e| anyhow!("Failed to get openapi: {}", e))?;

        // Parse the response into a PathDocument
        let path_doc: PathDocument = serde_json::from_value(response)
            .map_err(|e| anyhow!("Failed to parse openapi response: {}", e))?;

        // Create regex pattern for versioned APIs
        let pattern = regex::Regex::new(r"/v\d+(?:alpha\d+|beta\d+)?$")
            .map_err(|e| anyhow!("Failed to create regex pattern: {}", e))?;

        // Filter paths that match the version pattern
        let versioned_paths: Vec<String> = path_doc
            .paths
            .keys()
            .filter(|path| pattern.is_match(path))
            .cloned()
            .collect();

        Ok(versioned_paths)
    }

    pub async fn api_resource_list(&self, api_path: &str) -> Result<metav1::APIResourceList> {
        let api_path = format!("/{api_path}");

        let req = Request::get(api_path)
            .body(Vec::<u8>::new())
            .map_err(|e| anyhow!("Failed to create request: {}", e))?;

        self.client
            .request(req)
            .await
            .map_err(|e| anyhow!("Failed to get API resource list: {}", e))
    }
}
