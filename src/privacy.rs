use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::Icd11Error;

const FORBIDDEN_PII_KEYS: &[&str] = &[
    "name",
    "deceased_name",
    "informant_name",
    "respondent_name",
    "father_name",
    "mother_name",
    "spouse_name",
    "phone",
    "informant_phone",
    "respondent_phone",
    "mobile",
    "contact_number",
    "address",
    "house_address",
    "permanent_address",
    "aadhaar",
    "aadhaar_number",
    "aadhaar_last3",
    "abha",
    "abha_id",
    "abha_number",
    "national_id",
    "identifiers",
    "registration_number",
    "crs_number",
    "mccd_number",
    "certificate_number",
];

static AADHAAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").expect("valid Aadhaar regex")
});

static PHONE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^\d])(?:\+91[\s-]?)?[6-9]\d{9}(?:$|[^\d])").expect("valid phone regex")
});

static WHO_URI_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://id\.who\.int/icd/[^\s&]+").expect("valid WHO URI regex")
});

/// Enforce Rule 6: SmartVA and ICD-11 / DORIS inputs must contain clinical/demographic
/// data only and must never receive names, phones, addresses, Aadhaar, ABHA, or
/// registration numbers.
pub fn assert_no_pii_in_text(text: &str, context_path: &str) -> Result<(), Icd11Error> {
    let scrubbed = WHO_URI_RE.replace_all(text, "");
    if AADHAAR_RE.is_match(&scrubbed) {
        return Err(Icd11Error::PiiBoundaryViolation {
            path: context_path.to_string(),
            reason: "Input contains a 12-digit Aadhaar-like identifier pattern.".to_string(),
        });
    }
    if PHONE_RE.is_match(&scrubbed) {
        return Err(Icd11Error::PiiBoundaryViolation {
            path: context_path.to_string(),
            reason: "Input contains a 10-digit phone number pattern.".to_string(),
        });
    }
    Ok(())
}

/// Recursively inspect a JSON payload and reject any forbidden PII or registration
/// identifier keys or embedded Aadhaar/phone patterns before passing to ICD-11 / DORIS.
pub fn assert_no_pii_in_json(value: &Value, path: &str) -> Result<(), Icd11Error> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = key.trim().to_ascii_lowercase();
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if FORBIDDEN_PII_KEYS.contains(&normalized.as_str()) {
                    return Err(Icd11Error::PiiBoundaryViolation {
                        path: child_path,
                        reason: format!(
                            "Field '{key}' is personal or registration identifier data and must never cross the ICD-11/DORIS boundary."
                        ),
                    });
                }
                assert_no_pii_in_json(child, &child_path)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                let child_path = format!("{path}[{idx}]");
                assert_no_pii_in_json(item, &child_path)?;
            }
            Ok(())
        }
        Value::String(s) => assert_no_pii_in_text(s, path),
        _ => Ok(()),
    }
}
