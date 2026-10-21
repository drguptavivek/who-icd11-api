pub mod bootstrap;
pub mod certificate;
pub mod hostfxr;
pub mod privacy;
pub mod processing;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use bootstrap::{
    clean_portable_deps_and_runtimeconfig, download_who_offline_data, ensure_runtime_bundle,
    extract_portable_icdapi_from_oci, install_embedded_bridge_dll,
};
pub use certificate::{
    DEFAULT_ICD11_RELEASE, DorisCertificateError, DorisFieldError, age_days, canonical_json_bytes,
    drop_inapplicable_sections, normalize_certificate,
};
use hostfxr::{DotnetBridgeHost, discover_dotnet_hostfxr};
pub use privacy::{assert_no_pii_in_json, assert_no_pii_in_text};
pub use processing::{
    ProcessorCallOutcome, canonical_digest, certificate_digest, expected_expression_uri_with,
    postcoordination_availability, process_certificate_with, processor_result_digest,
    split_icd11_expression, strip_who_search_markup, valid_subtree_uris,
    validate_processor_envelope, verify_certificate_codes_with, wrap_engine_outcome,
};

#[derive(Debug, thiserror::Error)]
pub enum Icd11Error {
    #[error("ICD-11 bundle not found: {0}")]
    BundleNotFound(String),

    #[error(".NET hostfxr runtime error: {0}")]
    DotnetHostError(String),

    #[error("PII boundary violation at '{path}': {reason}")]
    PiiBoundaryViolation { path: String, reason: String },

    #[error("WHO ICD-11 engine unavailable (HTTP {status}): {body}")]
    UpstreamUnavailable { status: u16, body: String },

    #[error("Malformed JSON response from WHO ICD-11 DLL: {0}")]
    MalformedJson(String),

    #[error(transparent)]
    Certificate(#[from] DorisCertificateError),
}

#[derive(Debug, Clone)]
pub struct Icd11RuntimeConfig {
    pub bundle_dir: PathBuf,
    pub data_dir: PathBuf,
    pub bind_url: String,
    pub default_release: String,
}

impl Icd11RuntimeConfig {
    /// Discover the local portable WHO ICD-11 2.6.0 DLL bundle and 2026-01_en + DORIS 1.2.0 data,
    /// or bootstrap it automatically in pure Rust from the OCI Registry and WHO CDNs if missing.
    pub fn discover() -> Result<Self, Icd11Error> {
        Self::discover_with_bind("http://127.0.0.1:0")
    }

    pub fn discover_with_bind(bind_url: impl Into<String>) -> Result<Self, Icd11Error> {
        let bind_url = bind_url.into();
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let crate_runtime = manifest_dir.join("runtime");
        let desktop_runtime = manifest_dir.join("../../desktop/target/icd11-runtime");

        let bundle_candidates = [
            std::env::var("DIGITVA_ICD11_BUNDLE_DIR").ok().map(PathBuf::from),
            Some(crate_runtime.join("icdapi")),
            Some(desktop_runtime.join("icdapi")),
            Some(PathBuf::from("/tmp/icdapi_portable")),
        ];
        let data_candidates = [
            std::env::var("DIGITVA_ICD11_DATA_DIR").ok().map(PathBuf::from),
            Some(crate_runtime.join("data")),
            Some(desktop_runtime.join("data")),
            Some(PathBuf::from("/tmp/icdapi_bundle/data")),
        ];

        let bundle_opt = bundle_candidates
            .into_iter()
            .flatten()
            .find(|p| p.join("ICD-API.dll").exists() && p.join("DigitvaIcd11Bridge.dll").exists());

        let data_opt = data_candidates
            .into_iter()
            .flatten()
            .find(|p| p.join("DORIS_v2.1_1.2.0").exists());

        if let (Some(bundle_dir), Some(data_dir)) = (bundle_opt, data_opt) {
            bootstrap::verify_bundle_integrity(&bundle_dir, &data_dir)?;
            return Ok(Self {
                bundle_dir,
                data_dir,
                bind_url,
                default_release: DEFAULT_ICD11_RELEASE.to_string(),
            });
        }

        // Pure-Rust zero-Docker bootstrap into `<crate>/runtime`
        let (bundle_dir, data_dir) = ensure_runtime_bundle(&crate_runtime)?;
        Ok(Self {
            bundle_dir,
            data_dir,
            bind_url,
            default_release: DEFAULT_ICD11_RELEASE.to_string(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    pub subtrees_filter: Option<Vec<String>>,
    pub use_flexisearch: bool,
    pub flat_results: bool,
    pub highlighting_enabled: bool,
    pub medical_coding_mode: bool,
    pub include_postcoordination: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DorisEngineOutput {
    pub code: Option<String>,
    #[serde(rename = "stemCode")]
    pub stem_code: Option<String>,
    pub uri: Option<String>,
    #[serde(rename = "stemURI")]
    pub stem_uri: Option<String>,
    pub report: Option<String>,
    #[serde(rename = "tabularReport")]
    pub tabular_report: Option<String>,
    pub reject: bool,
    pub error: Option<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodEditEngineOutput {
    pub report: Option<String>,
    #[serde(rename = "tabularReport")]
    pub tabular_report: Option<String>,
    #[serde(rename = "issueIds")]
    pub issue_ids: Option<String>,
}

static GLOBAL_ENGINE: OnceLock<Arc<Icd11Engine>> = OnceLock::new();
static GLOBAL_ENGINE_INIT_LOCK: Mutex<()> = Mutex::new(());

pub struct Icd11Engine {
    host: DotnetBridgeHost,
    default_release: String,
}

impl Icd11Engine {
    /// Initialize or retrieve the process-wide in-memory WHO ICD-11 2.6.0 + DORIS 1.2.0 DLL host.
    pub fn global() -> Result<Arc<Self>, Icd11Error> {
        if let Some(engine) = GLOBAL_ENGINE.get() {
            return Ok(Arc::clone(engine));
        }
        let cfg = Icd11RuntimeConfig::discover()?;
        Self::init_global(cfg)
    }

    /// Initialize the process-wide in-memory WHO ICD-11 2.6.0 + DORIS 1.2.0 DLL host with explicit config.
    pub fn init_global(config: Icd11RuntimeConfig) -> Result<Arc<Self>, Icd11Error> {
        if let Some(engine) = GLOBAL_ENGINE.get() {
            return Ok(Arc::clone(engine));
        }
        let _guard = GLOBAL_ENGINE_INIT_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(engine) = GLOBAL_ENGINE.get() {
            return Ok(Arc::clone(engine));
        }
        bootstrap::verify_bundle_integrity(&config.bundle_dir, &config.data_dir)?;
        let (dotnet_root, hostfxr_path) = discover_dotnet_hostfxr()?;
        let host = DotnetBridgeHost::initialize(
            &dotnet_root,
            &hostfxr_path,
            &config.bundle_dir,
            &config.data_dir,
            &config.bind_url,
        )?;
        let engine = Arc::new(Self {
            host,
            default_release: config.default_release,
        });
        let _ = GLOBAL_ENGINE.set(Arc::clone(&engine));
        Ok(GLOBAL_ENGINE.get().cloned().unwrap_or(engine))
    }

    pub fn bound_port(&self) -> u16 {
        self.host.bound_port()
    }

    pub fn base_url(&self) -> String {
        self.host.base_url()
    }

    pub fn default_release(&self) -> &str {
        &self.default_release
    }

    /// Perform a raw in-process request against the loaded `ICD-API.dll` pipeline.
    pub fn raw_request(
        &self,
        method: &str,
        path_and_query: &str,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(u16, String), Icd11Error> {
        assert_no_pii_in_text(path_and_query, "request.path")?;
        if let Some(b) = body {
            assert_no_pii_in_text(b, "request.body")?;
        }
        self.host.request(method, path_and_query, body, content_type)
    }

    /// Resolve an ICD-11 code or post-coordinated expression (`BA41.Z`, `1B12.2&XA0G74`) via `codeinfo`.
    /// Returns `Ok(None)` when the expression is unknown (`404`).
    pub fn codeinfo(&self, code: &str, release: Option<&str>) -> Result<Option<Value>, Icd11Error> {
        let trimmed = code.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return Ok(None);
        }
        assert_no_pii_in_text(trimmed, "codeinfo.code")?;
        let rel = release.unwrap_or(&self.default_release);
        let encoded = urlencoding::encode(trimmed);
        let path = format!("/icd/release/11/{rel}/mms/codeinfo/{encoded}");
        let (status, body) = self.host.request("GET", &path, None, None)?;
        if status == 404 || status == 400 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(Icd11Error::UpstreamUnavailable { status, body });
        }
        let val: Value = serde_json::from_str(&body)
            .map_err(|e| Icd11Error::MalformedJson(e.to_string()))?;
        if !val.is_object() {
            return Err(Icd11Error::MalformedJson(
                "codeinfo payload is not a JSON object".to_string(),
            ));
        }
        Ok(Some(val))
    }

    /// Search ICD-11 MMS terminology via `OCT.dll` / `ICDTextAnalyzers.dll` in-process.
    pub fn search(
        &self,
        query: &str,
        options: &SearchOptions,
        release: Option<&str>,
    ) -> Result<Value, Icd11Error> {
        assert_no_pii_in_text(query, "search.q")?;
        if let Some(subtrees) = &options.subtrees_filter
            && !valid_subtree_uris(Some(subtrees))
        {
            return Err(Icd11Error::Certificate(DorisCertificateError::single(
                "subtree_uris",
                "Invalid WHO subtree URI.",
            )));
        }
        let rel = release.unwrap_or(&self.default_release);
        let path = format!("/icd/release/11/{rel}/mms/search");
        let mut form_parts = vec![
            format!("q={}", urlencoding::encode(query.trim())),
            format!("useFlexisearch={}", options.use_flexisearch),
            format!("flatResults={}", options.flat_results),
            format!("highlightingEnabled={}", options.highlighting_enabled),
            format!("medicalCodingMode={}", options.medical_coding_mode),
            format!("includePostcoordination={}", options.include_postcoordination),
        ];
        if let Some(subtrees) = &options.subtrees_filter
            && !subtrees.is_empty()
        {
            let joined = subtrees.join(",");
            form_parts.push(format!("subtreesFilter={}", urlencoding::encode(&joined)));
        }
        let form_body = form_parts.join("&");
        let (status, body) = self.host.request(
            "POST",
            &path,
            Some(&form_body),
            Some("application/x-www-form-urlencoded"),
        )?;
        if !(200..300).contains(&status) {
            return Err(Icd11Error::UpstreamUnavailable { status, body });
        }
        serde_json::from_str(&body).map_err(|e| Icd11Error::MalformedJson(e.to_string()))
    }

    /// Autocode clinical text to the best-matching ICD-11 MMS entity.
    pub fn autocode(
        &self,
        search_text: &str,
        subtrees_filter: Option<&str>,
        match_threshold: Option<f32>,
        release: Option<&str>,
    ) -> Result<Value, Icd11Error> {
        assert_no_pii_in_text(search_text, "autocode.searchText")?;
        let rel = release.unwrap_or(&self.default_release);
        let mut path = format!(
            "/icd/release/11/{rel}/mms/autocode?searchText={}",
            urlencoding::encode(search_text.trim())
        );
        if let Some(sf) = subtrees_filter
            && !sf.trim().is_empty()
        {
            path.push_str(&format!("&subtreesFilter={}", urlencoding::encode(sf.trim())));
        }
        if let Some(th) = match_threshold {
            path.push_str(&format!("&matchThreshold={th}"));
        }
        let (status, body) = self.host.request("GET", &path, None, None)?;
        if !(200..300).contains(&status) {
            return Err(Icd11Error::UpstreamUnavailable { status, body });
        }
        serde_json::from_str(&body).map_err(|e| Icd11Error::MalformedJson(e.to_string()))
    }

    /// Fetch an ICD-11 MMS linearization entity by numeric entity ID (and optional `other`/`unspecified` residual).
    pub fn entity(
        &self,
        entity_id: &str,
        residual: Option<&str>,
        release: Option<&str>,
    ) -> Result<Value, Icd11Error> {
        assert_no_pii_in_text(entity_id, "entity.id")?;
        let rel = release.unwrap_or(&self.default_release);
        let path = match residual {
            Some(res) if !res.trim().is_empty() => {
                format!("/icd/release/11/{rel}/mms/{}/{}", entity_id.trim(), res.trim())
            }
            _ => format!("/icd/release/11/{rel}/mms/{}", entity_id.trim()),
        };
        let (status, body) = self.host.request("GET", &path, None, None)?;
        if !(200..300).contains(&status) {
            return Err(Icd11Error::UpstreamUnavailable { status, body });
        }
        serde_json::from_str(&body).map_err(|e| Icd11Error::MalformedJson(e.to_string()))
    }

    /// Run `DorisRuleEngine.dll` underlying cause of death detection on a WHO death certificate JSON object.
    pub fn doris(
        &self,
        certificate: &Value,
        release: Option<&str>,
    ) -> Result<DorisEngineOutput, Icd11Error> {
        let rel = release.unwrap_or(&self.default_release);
        let normalized = normalize_certificate(certificate, rel)?;
        let cert_json = serde_json::to_string(&normalized)
            .map_err(|e| Icd11Error::MalformedJson(e.to_string()))?;
        let (status, body) = self.host.doris(rel, &cert_json)?;
        if !(200..300).contains(&status) {
            return Err(Icd11Error::UpstreamUnavailable { status, body });
        }
        serde_json::from_str(&body).map_err(|e| Icd11Error::MalformedJson(e.to_string()))
    }

    /// Run `DorisRuleEngine.dll` CoDEdit mortality certificate check on a WHO death certificate JSON object.
    pub fn codedit(
        &self,
        certificate: &Value,
        release: Option<&str>,
    ) -> Result<CodEditEngineOutput, Icd11Error> {
        let rel = release.unwrap_or(&self.default_release);
        let normalized = normalize_certificate(certificate, rel)?;
        let cert_json = serde_json::to_string(&normalized)
            .map_err(|e| Icd11Error::MalformedJson(e.to_string()))?;
        let (status, body) = self.host.codedit(rel, &cert_json)?;
        if !(200..300).contains(&status) {
            return Err(Icd11Error::UpstreamUnavailable { status, body });
        }
        serde_json::from_str(&body).map_err(|e| Icd11Error::MalformedJson(e.to_string()))
    }

    /// Validate a DigitVA phase-0 DORIS process payload (`{schema_version: 1, client_revision, certificate}`),
    /// verify every code/URI against `codeinfo`, run both `doris` and `codedit` engines, and return the
    /// canonical envelope with `certificate_digest` and `result_digest`.
    pub fn process_certificate(
        &self,
        payload: &Value,
        release: Option<&str>,
        who_image_digest: &str,
    ) -> Result<Value, DorisCertificateError> {
        let rel = release.unwrap_or(&self.default_release);
        process_certificate_with(
            payload,
            rel,
            who_image_digest,
            |code, r| self.codeinfo(code, Some(r)).ok().flatten(),
            |name, cert, r| {
                let Ok(cert_json) = serde_json::to_string(cert) else {
                    return ProcessorCallOutcome::Unavailable;
                };
                let res = if name == "doris" {
                    self.host.doris(r, &cert_json)
                } else {
                    self.host.codedit(r, &cert_json)
                };
                match res {
                    Ok((status, body)) => ProcessorCallOutcome::Response(status, body),
                    Err(_) => ProcessorCallOutcome::Unavailable,
                }
            },
        )
    }
}
