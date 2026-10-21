use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::certificate::{
    DorisCertificateError, canonical_json_bytes, normalize_certificate,
};

const DORIS_KEYS: &[&str] = &[
    "code",
    "stemCode",
    "uri",
    "stemURI",
    "report",
    "tabularReport",
    "reject",
    "error",
    "warning",
];

const CODEDIT_KEYS: &[&str] = &["report", "tabularReport", "issueIds"];

static EXPR_SEP_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s*([&/])\s*").expect("valid expression separator regex"));

static WHO_SUBTREE_URI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^http://id\.who\.int/icd/(?:entity/\d+|release/11/20\d\d-\d\d/mms/\d+(?:/(?:other|unspecified))?)$")
        .expect("valid WHO subtree URI regex")
});

static HTML_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<[^>]+>").expect("valid HTML tag regex"));

pub fn canonical_digest(value: &Value) -> String {
    let bytes = canonical_json_bytes(value);
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn certificate_digest(certificate: &Value) -> String {
    canonical_digest(certificate)
}

pub fn processor_result_digest(
    doris: &Value,
    codedit: &Value,
    release: &str,
    who_image_digest: &str,
) -> String {
    canonical_digest(&json!({
        "icd_release": release,
        "who_image_digest": who_image_digest,
        "doris": doris,
        "codedit": codedit,
    }))
}

pub fn validate_processor_envelope(name: &str, envelope: &Value) -> Result<Value, String> {
    if name != "doris" && name != "codedit" {
        return Err("Invalid DORIS processor result.".to_string());
    }
    let Some(obj) = envelope.as_object() else {
        return Err("Invalid DORIS processor result.".to_string());
    };
    if obj.len() != 2 || !obj.contains_key("status") || !obj.contains_key("result") {
        return Err("Invalid DORIS processor result.".to_string());
    }
    let Some(status) = obj["status"].as_str() else {
        return Err("Invalid DORIS processor status.".to_string());
    };
    if !matches!(
        status,
        "completed" | "rejected" | "timeout" | "malformed_response" | "unavailable"
    ) {
        return Err("Invalid DORIS processor status.".to_string());
    }
    let result = &obj["result"];
    if matches!(status, "timeout" | "malformed_response" | "unavailable") {
        if !result.is_null() {
            return Err("Failed DORIS processor results must be empty.".to_string());
        }
        return Ok(envelope.clone());
    }

    let expected_keys = if name == "doris" {
        DORIS_KEYS
    } else {
        CODEDIT_KEYS
    };
    let Some(res_obj) = result.as_object() else {
        return Err("Invalid DORIS processor result.".to_string());
    };
    for &k in expected_keys {
        if !res_obj.contains_key(k) {
            return Err("Invalid DORIS processor result.".to_string());
        }
    }

    if name == "doris" {
        let Some(reject) = res_obj.get("reject").and_then(Value::as_bool) else {
            return Err("DORIS rejection status does not match its result.".to_string());
        };
        if (status == "rejected") != reject {
            return Err("DORIS rejection status does not match its result.".to_string());
        }
    } else if status != "completed" {
        return Err("CoDEdit cannot have a rejected status.".to_string());
    }

    Ok(envelope.clone())
}

/// Split an ICD-11 expression (`1B12.2&XA0G74` or `1B12.2/5A13`) into `(tokens, separators)`.
pub fn split_icd11_expression(code: &str) -> (Vec<String>, Vec<String>) {
    let mut tokens = Vec::new();
    let mut seps = Vec::new();
    let mut last = 0usize;
    for m in EXPR_SEP_RE.find_iter(code) {
        tokens.push(code[last..m.start()].to_string());
        let caps = EXPR_SEP_RE.captures(m.as_str()).unwrap();
        seps.push(caps[1].to_string());
        last = m.end();
    }
    tokens.push(code[last..].to_string());
    (tokens, seps)
}

/// Resolve the canonical release-pinned URI expression through a `codeinfo` lookup closure.
pub fn expected_expression_uri_with<F>(code: &str, release: &str, mut get_codeinfo: F) -> Option<String>
where
    F: FnMut(&str, &str) -> Option<Value>,
{
    let (tokens, seps) = split_icd11_expression(code);
    let expr_info = get_codeinfo(code, release)?;
    let expr_obj = expr_info.as_object()?;
    if expr_obj.get("code").and_then(Value::as_str) != Some(code) {
        return None;
    }
    if tokens.len() == 1 {
        let uri = expr_obj.get("stemId").and_then(Value::as_str)?;
        return if uri.is_empty() {
            None
        } else {
            Some(uri.to_string())
        };
    }

    let mut uris = Vec::with_capacity(tokens.len());
    for token in &tokens {
        let info = get_codeinfo(token, release)?;
        let obj = info.as_object()?;
        if obj.get("code").and_then(Value::as_str) != Some(token.as_str()) {
            return None;
        }
        let uri = obj.get("stemId").and_then(Value::as_str)?;
        if uri.is_empty() {
            return None;
        }
        uris.push(uri.to_string());
    }

    let mut expected = uris[0].clone();
    for (sep, uri) in seps.iter().zip(uris.iter().skip(1)) {
        expected.push(' ');
        expected.push_str(sep);
        expected.push(' ');
        expected.push_str(uri);
    }
    Some(expected)
}

pub fn verify_certificate_codes_with<F>(
    certificate: &Value,
    release: &str,
    mut get_codeinfo: F,
) -> Result<(), DorisCertificateError>
where
    F: FnMut(&str, &str) -> Option<Value>,
{
    let Some(cert_obj) = certificate.as_object() else {
        return Err(DorisCertificateError::single(
            "certificate",
            "Must be an object.",
        ));
    };

    if let Some(part1) = cert_obj.get("Part1").and_then(Value::as_array) {
        for (line_idx, line) in part1.iter().enumerate() {
            if let Some(conds) = line
                .as_object()
                .and_then(|m| m.get("Conditions"))
                .and_then(Value::as_array)
            {
                let group_path = format!("certificate.Part1[{line_idx}].Conditions");
                for (cond_idx, cond) in conds.iter().enumerate() {
                    verify_single_condition(cond, &group_path, cond_idx, release, &mut get_codeinfo)?;
                }
            }
        }
    }

    if let Some(conds) = cert_obj
        .get("Part2")
        .and_then(Value::as_object)
        .and_then(|m| m.get("Conditions"))
        .and_then(Value::as_array)
    {
        for (cond_idx, cond) in conds.iter().enumerate() {
            verify_single_condition(
                cond,
                "certificate.Part2.Conditions",
                cond_idx,
                release,
                &mut get_codeinfo,
            )?;
        }
    }

    Ok(())
}

fn verify_single_condition<F>(
    cond: &Value,
    group_path: &str,
    cond_idx: usize,
    release: &str,
    get_codeinfo: &mut F,
) -> Result<(), DorisCertificateError>
where
    F: FnMut(&str, &str) -> Option<Value>,
{
    let Some(obj) = cond.as_object() else {
        return Ok(());
    };
    let Some(code) = obj.get("Code").and_then(Value::as_str) else {
        return Ok(());
    };
    let supplied_uri = obj.get("LinearizationURI").and_then(Value::as_str);
    let expected = expected_expression_uri_with(code, release, &mut *get_codeinfo);
    if expected.as_deref() != supplied_uri {
        return Err(DorisCertificateError::single(
            format!("{group_path}[{cond_idx}].LinearizationURI"),
            "Does not match the selected ICD-11 code.",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessorCallOutcome {
    Response(u16, String),
    Timeout,
    Unavailable,
}

pub fn wrap_engine_outcome(name: &str, outcome: ProcessorCallOutcome) -> Value {
    let (status_code, content) = match outcome {
        ProcessorCallOutcome::Timeout => {
            return json!({"status": "timeout", "result": Value::Null});
        }
        ProcessorCallOutcome::Unavailable => {
            return json!({"status": "unavailable", "result": Value::Null});
        }
        ProcessorCallOutcome::Response(sc, body) => (sc, body),
    };

    if !(200..300).contains(&status_code) {
        return json!({"status": "unavailable", "result": Value::Null});
    }
    if content.len() > 512 * 1024 {
        return json!({"status": "unavailable", "result": Value::Null});
    }

    let Ok(parsed) = serde_json::from_str::<Value>(&content) else {
        return json!({"status": "malformed_response", "result": Value::Null});
    };
    let Some(res_obj) = parsed.as_object() else {
        return json!({"status": "malformed_response", "result": Value::Null});
    };

    let expected_keys = if name == "doris" {
        DORIS_KEYS
    } else {
        CODEDIT_KEYS
    };
    for &k in expected_keys {
        if !res_obj.contains_key(k) {
            return json!({"status": "malformed_response", "result": Value::Null});
        }
    }

    if name == "doris" && !res_obj["reject"].is_boolean() {
        return json!({"status": "malformed_response", "result": Value::Null});
    }

    let status = if name == "doris" && res_obj["reject"].as_bool() == Some(true) {
        "rejected"
    } else {
        "completed"
    };

    json!({
        "status": status,
        "result": parsed,
    })
}

pub fn process_certificate_with<FC, FP>(
    payload: &Value,
    release: &str,
    who_image_digest: &str,
    get_codeinfo: FC,
    mut run_processor: FP,
) -> Result<Value, DorisCertificateError>
where
    FC: FnMut(&str, &str) -> Option<Value>,
    FP: FnMut(&str, &Value, &str) -> ProcessorCallOutcome,
{
    let Some(obj) = payload.as_object() else {
        return Err(DorisCertificateError::single(
            "payload",
            "Unsupported DORIS process schema version.",
        ));
    };
    if obj.get("schema_version").and_then(Value::as_i64) != Some(1) {
        return Err(DorisCertificateError::single(
            "schema_version",
            "Unsupported DORIS process schema version.",
        ));
    }
    for k in obj.keys() {
        if !matches!(k.as_str(), "schema_version" | "client_revision" | "certificate") {
            return Err(DorisCertificateError::single(
                "payload",
                "DORIS process payload contains unsupported fields.",
            ));
        }
    }
    let Some(rev_val) = obj.get("client_revision") else {
        return Err(DorisCertificateError::single(
            "client_revision",
            "client_revision must be a non-negative integer.",
        ));
    };
    if rev_val.is_boolean() {
        return Err(DorisCertificateError::single(
            "client_revision",
            "client_revision must be a non-negative integer.",
        ));
    }
    let Some(revision) = rev_val.as_i64() else {
        return Err(DorisCertificateError::single(
            "client_revision",
            "client_revision must be a non-negative integer.",
        ));
    };
    if revision < 0 {
        return Err(DorisCertificateError::single(
            "client_revision",
            "client_revision must be a non-negative integer.",
        ));
    }

    let raw_cert = obj.get("certificate").unwrap_or(&Value::Null);
    let certificate = normalize_certificate(raw_cert, release)?;
    verify_certificate_codes_with(&certificate, release, get_codeinfo)?;

    let doris_outcome = run_processor("doris", &certificate, release);
    let codedit_outcome = run_processor("codedit", &certificate, release);

    let doris = wrap_engine_outcome("doris", doris_outcome);
    let codedit = wrap_engine_outcome("codedit", codedit_outcome);
    let cert_dig = certificate_digest(&certificate);
    let res_dig = processor_result_digest(&doris, &codedit, release, who_image_digest);

    Ok(json!({
        "schema_version": 1,
        "client_revision": revision,
        "icd_release": release,
        "certificate": certificate,
        "certificate_digest": cert_dig,
        "result_digest": res_dig,
        "doris": doris,
        "codedit": codedit,
    }))
}

/// Validate WHO subtree URIs (`app/services/icd11_postcoordination.py::valid_subtree_uris`).
pub fn valid_subtree_uris(uris: Option<&[String]>) -> bool {
    let Some(list) = uris else {
        return true;
    };
    if list.is_empty() || list.len() > 40 {
        return false;
    }
    list.iter()
        .all(|u| u.len() <= 200 && WHO_SUBTREE_URI_RE.is_match(u))
}

/// Normalize WHO search `postcoordinationAvailability` values (`0`, `1`, `2`).
pub fn postcoordination_availability(raw: &Value) -> (bool, Option<i64>) {
    if raw.is_boolean() {
        return (false, None);
    }
    match raw.as_i64() {
        Some(0) => (false, Some(0)),
        Some(v @ (1 | 2)) => (true, Some(v)),
        _ => (false, None),
    }
}

/// Strip `<em class='found'>...</em>` and similar HTML tags from WHO search titles.
pub fn strip_who_search_markup(text: &str) -> String {
    HTML_TAG_RE.replace_all(text, "").trim().to_string()
}
