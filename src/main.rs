use axum::{
    routing::{get, post},
    Router, extract::Json,
};
use itertools::Itertools;
use kube;
use kube::runtime::{reflector, watcher};
use kubernetes_cedar_authorizer::{cedar_authorizer::{self, kubestore::KubeStoreImpl}, k8s_authorizer::{self, KubernetesAuthorizer}};

use k8s_openapi::api::{authorization::v1::{SubjectAccessReview, SubjectAccessReviewStatus}, core::v1 as corev1};
use cedar_policy::{PolicySet};
use cedar_authorizer::kubestore::TestKubeStore;
use tokio_util::sync::CancellationToken;
use std::collections::BTreeMap;
use std::sync::Arc;
use axum_server::tls_rustls::RustlsConfig;
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;

use cedar_policy_core::{extensions::Extensions, validator::json_schema::Fragment};
use tracing::{error, instrument};
use std::net::SocketAddr;
use axum::extract::State;



#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

   match run().await {
    Ok(_) => (),
    Err(e) => {
        // Catch errors into the tracing system
        error!("Setup failed: {e}");
        std::process::exit(1);
    }
   }
}

async fn run() -> Result<(), SetupError> {
 // Initialize rustls crypto provider
 let provider = rustls::crypto::ring::default_provider();
 rustls::crypto::CryptoProvider::install_default(provider).map_err(|_| SetupError::CryptoProviderFailed)?;

 // Load TLS configuration
 let cert_path = std::env::var("TLS_CERT_PATH")
     .unwrap_or_else(|_| "./kubernetes-cedar-authorizer.crt".to_string());
 

 let key_path = std::env::var("TLS_KEY_PATH")
     .unwrap_or_else(|_| "./kubernetes-cedar-authorizer.key".to_string());

 let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
     .await.map_err(|error| SetupError::TLSConfigFailed{ cert_path, key_path, error })?;

 // Load schema for validation; TODO: make dynamic
 let schema_path = std::env::var("CEDAR_SCHEMA_FILE")
     .unwrap_or_else(|_| "k8s.cedarschema".to_string());
 let schema_file = std::fs::read_to_string(schema_path).map_err(SetupError::todo)?;
 let (schema, _warnings) = Fragment::from_cedarschema_str(&schema_file, Extensions::all_available())
     .map_err(SetupError::todo)?;

 // TODO: Source policies from many different stores that update over time
 let policy_file = std::env::var("CEDAR_POLICY_FILE")
     .unwrap_or_else(|_| "policies.cedar".to_string());
 let policy_file = std::fs::read_to_string(policy_file).map_err(SetupError::todo)?;
 let policies = policy_file.parse::<PolicySet>()
     .map_err(SetupError::todo)?;

    let cancel = CancellationToken::new();


// Infer the runtime environment and try to create a Kubernetes Client
let kube_client = kube::Client::try_default().await?;

let namespaces: kube::Api<corev1::Namespace> = kube::Api::all(kube_client);
let namespace_store = KubeStoreImpl::new(namespaces, cancel.clone());

 let schema = cedar_authorizer::kube_invariants::Schema::new(schema).map_err(SetupError::todo)?;
 let policies =
     cedar_authorizer::kube_invariants::PolicySet::new(policies.as_ref(), Arc::new(schema.clone())).map_err(SetupError::todo)?;

 let authorizer = Arc::new(
     cedar_authorizer::CedarKubeAuthorizer::new(policies, namespace_store).map_err(SetupError::todo)?
 );

 // Create our application router
 let app = Router::new()
     .route(
         "/authorize",
         post(authorize_handler),
     )
     .route( // TODO: Add readyz endpoint to say that the initial schema, policies, etc. are loaded
         "/healthz",
         get(healthz_handler),
     )
     .with_state(authorizer);

 // Bind to address
 let port = std::env::var("PORT")
     .ok()
     .and_then(|p| p.parse::<u16>().ok())
     .unwrap_or(8443);
 let addr = SocketAddr::from(([0, 0, 0, 0], port));
 tracing::info!("Starting TLS server on {}", addr);

 axum_server::bind_rustls(addr, tls_config)
     .serve(app.into_make_service())
     .await
     .map_err(SetupError::BindFailed)
}

#[derive(thiserror::Error, Debug)]
enum SetupError {
    #[error(r#"Failed to load TLS config (cert: {cert_path}, key: {key_path}): {error}"#)]
    TLSConfigFailed{ cert_path: String, key_path: String, error: std::io::Error},
    #[error("Failed to bind to address: {0}")]
    BindFailed(std::io::Error),
    #[error("Failed to install crypto provider")]
    CryptoProviderFailed,
    #[error("Failed to create Kubernetes client: {0}")]
    KubernetesClientFailed(#[from] kube::Error),
    #[error("Unknown error: {0}")]
    Unknown(Box<dyn std::error::Error>),
}

impl SetupError {
    fn todo(error: impl std::error::Error + 'static) -> Self {
        Self::Unknown(Box::new(error))
    }
}

type CedarKubeAuthorizer = cedar_authorizer::authorizer::CedarKubeAuthorizer<
    cedar_authorizer::kubestore::KubeStoreImpl<corev1::Namespace>>;

async fn healthz_handler() -> &'static str {
    "ok"
}

#[axum::debug_handler]
#[instrument(skip(authorizer))]
async fn authorize_handler(State(authorizer): State<Arc<CedarKubeAuthorizer>>, Json(review): Json<SubjectAccessReview>) -> Result<Json<SubjectAccessReview>, k8s_authorizer::AuthorizerError> {
    let attrs = k8s_authorizer::Attributes::from_subject_access_review(&review)?;
    let is_authorized = authorizer.is_authorized(attrs)?;
    let status = Some(SubjectAccessReviewStatus {
        allowed: is_authorized.decision == k8s_authorizer::Decision::Allow,
        denied: match is_authorized.decision {
            k8s_authorizer::Decision::Allow => None,
            k8s_authorizer::Decision::Conditional(_) => None,
            k8s_authorizer::Decision::Deny => Some(true),
            k8s_authorizer::Decision::NoOpinion => None,
        },
        reason: Some(is_authorized.reason.to_string()),
        evaluation_error: Some(is_authorized.errors.iter().map(|e| e.to_string()).join("\n")),
    });
    Ok(Json(SubjectAccessReview {
        status,
        ..review
    }))
}