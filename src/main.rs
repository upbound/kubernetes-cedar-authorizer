use axum::{
    extract::Json,
    routing::{get, post},
    Router,
};
use itertools::Itertools;
use kubernetes_cedar_authorizer::{
    cedar_authorizer::{self, kubestore::KubeStoreImpl},
    k8s_authorizer::{self, KubernetesAuthorizer},
};

use axum_server::tls_rustls::RustlsConfig;
use cedar_policy::PolicySet;
use k8s_openapi::api::{
    authorization::v1::{SubjectAccessReview, SubjectAccessReviewStatus},
    core::v1 as corev1,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use axum::extract::State;
use cedar_policy_core::{extensions::Extensions, validator::json_schema::Fragment};
use std::net::SocketAddr;
use tracing::{error, instrument};

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

#[tokio::main]
async fn main() {
    let filter = EnvFilter::from_default_env();

    let mut providerbuilder = SdkTracerProvider::builder();

    match std::env::var("TRACE_STDOUT") {
        Ok(v) => {
            if v == "true" {
                providerbuilder = providerbuilder
                    .with_simple_exporter(opentelemetry_stdout::SpanExporter::default());
            }
        }
        Err(e) => {
            eprintln!(
                "Could not determine whether TRACE_STDOUT is set, skipping stdout tracing: {e}"
            );
        }
    }

    // TODO: Skip tracing if OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not set? Or if it points to a non-4318 port?
    /*match opentelemetry_otlp::SpanExporter::builder().with_http().build() {
        Ok(exporter) => {
            providerbuilder = providerbuilder.with_simple_exporter(exporter);
        },
        Err(e) => {
            eprintln!("Could not build OTLP HTTP span exporter: {e}");
        }
    }*/

    // TODO: Customize the resource here
    let tracer = providerbuilder
        .build()
        .tracer("kubernetes-cedar-authorizer");

    let logger = tracing_subscriber::fmt::layer();

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    Registry::default()
        .with(filter)
        .with(telemetry)
        .with(logger)
        .init();

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
    rustls::crypto::CryptoProvider::install_default(provider)
        .map_err(|_| SetupError::CryptoProviderFailed)?;

    // Load TLS configuration
    let cert_path = std::env::var("TLS_CERT_PATH")
        .unwrap_or_else(|_| "./kubernetes-cedar-authorizer.crt".to_string());

    let key_path = std::env::var("TLS_KEY_PATH")
        .unwrap_or_else(|_| "./kubernetes-cedar-authorizer.key".to_string());

    let tls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .map_err(|error| SetupError::TLSConfigFailed {
            cert_path,
            key_path,
            error,
        })?;

    // Load schema for validation; TODO: make dynamic
    let schema_path =
        std::env::var("CEDAR_SCHEMA_FILE").unwrap_or_else(|_| "k8s.cedarschema".to_string());
    let schema_file = std::fs::read_to_string(schema_path).map_err(SetupError::todo)?;
    let (schema, _warnings) =
        Fragment::from_cedarschema_str(&schema_file, Extensions::all_available())
            .map_err(SetupError::todo)?;

    // TODO: Source policies from many different stores that update over time
    let policy_file =
        std::env::var("CEDAR_POLICY_FILE").unwrap_or_else(|_| "policies.cedar".to_string());
    let policy_file = std::fs::read_to_string(policy_file).map_err(SetupError::todo)?;
    let policies = policy_file.parse::<PolicySet>().map_err(SetupError::todo)?;

    let cancel = CancellationToken::new();

    // Infer the runtime environment and try to create a Kubernetes Client
    let kube_client = kube::Client::try_default().await?;

    let namespaces: kube::Api<corev1::Namespace> = kube::Api::all(kube_client);
    let namespace_store = KubeStoreImpl::new(namespaces, cancel.clone());

    let schema =
        cedar_authorizer::kube_invariants::Schema::new(schema).map_err(SetupError::todo)?;
    let policies = cedar_authorizer::kube_invariants::PolicySet::new(
        policies.as_ref(),
        Arc::new(schema.clone()),
    )
    .map_err(SetupError::todo)?;

    let authorizer = Arc::new(
        cedar_authorizer::CedarKubeAuthorizer::new(policies, namespace_store)
            .map_err(SetupError::todo)?,
    );

    // Create our application router
    let app = Router::new()
        .route("/authorize", post(authorize_handler))
        .route(
            // TODO: Add readyz endpoint to say that the initial schema, policies, etc. are loaded
            "/healthz",
            get(healthz_handler),
        )
        .route("/readyz", get(readyz_handler))
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
    TLSConfigFailed {
        cert_path: String,
        key_path: String,
        error: std::io::Error,
    },
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
    cedar_authorizer::kubestore::KubeStoreImpl<corev1::Namespace>,
>;

async fn healthz_handler() -> &'static str {
    "ok"
}

async fn readyz_handler() -> &'static str {
    "ok"
}

#[axum::debug_handler]
#[instrument(skip(authorizer), ret, err)]
async fn authorize_handler(
    State(authorizer): State<Arc<CedarKubeAuthorizer>>,
    Json(review): Json<SubjectAccessReview>,
) -> Result<Json<SubjectAccessReview>, k8s_authorizer::AuthorizerError> {
    let attrs = k8s_authorizer::Attributes::from_subject_access_review(&review)?;
    let is_authorized = authorizer.is_authorized(attrs)?;
    let status = Some(SubjectAccessReviewStatus {
        allowed: is_authorized.decision == k8s_authorizer::Decision::Allow,
        denied: match is_authorized.decision {
            k8s_authorizer::Decision::Allow => None,
            k8s_authorizer::Decision::Conditional(_, _) => None,
            k8s_authorizer::Decision::Deny => Some(true),
            k8s_authorizer::Decision::NoOpinion => None,
        },
        reason: Some(is_authorized.reason.to_string()),
        evaluation_error: Some(
            is_authorized
                .errors
                .iter()
                .map(|e| e.to_string())
                .join("\n"),
        ),
    });
    let mut review = SubjectAccessReview { status, ..review };
    // TODO: Handle generateName precision; we cannot do an exact match, but we can do a prefix match.
    // Or try it out, most likely the server already generated a name from the prefix at the time AdmissionReview is sent.
    if let k8s_authorizer::Decision::Conditional(policies, jsonpaths_to_uid) =
        is_authorized.decision
    {
        let uid_to_celvar = jsonpaths_to_uid.into_iter().map(|(jsonpath, uid)| {
            (
                uid,
                match jsonpath.as_str() {
                    "resource.namespace.metadata" => "namespaceObject.metadata".to_string(),
                    "resource.namespace" => "namespaceObject".to_string(),
                    "resource.request.metadata" => "object.metadata".to_string(),
                    "resource.stored.metadata" => "oldObject.metadata".to_string(),
                    _ => match (
                        jsonpath.strip_prefix("resource.request.v"),
                        jsonpath.strip_prefix("resource.stored.v"),
                    ) {
                        (Some(_), None) => "object".to_string(),
                        (None, Some(_)) => "oldObject".to_string(),
                        _ => jsonpath,
                    },
                },
            )
        });
        let fixup_mappings = HashMap::from([
            (
                "resource.name.value".to_string(),
                "request.name".to_string(),
            ),
            // TODO: Figure out if how to deal with implicit conversions from e.g. v1beta1 deployments to v1 deployments
            // That is the difference between CEL's request.requestResource and request.resource
            (
                "resource.apiGroup.value".to_string(),
                "request.requestResource.group".to_string(),
            ),
            // TODO: Split resourceCombined into resource and subresource
            (
                "namespaceObject.name".to_string(),
                "namespaceObject.metadata.name".to_string(),
            ),
        ]);
        let mut entity_uid_mapper =
            cedar_authorizer::cel::DefaultEntityToCelVariableMapper::new(uid_to_celvar);
        let cel_conditions =
            cedar_authorizer::kube_invariants::AuthorizationConditions::from_policy_set(
                &policies,
                &mut entity_uid_mapper,
            )?;
        let cel_conditions = cel_conditions.map_cel_exprs(|c| c.rename_variables(&fixup_mappings));
        cel_conditions.apply_to_subject_access_review(&mut review)?;
    }
    Ok(Json(review))
}
