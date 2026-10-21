use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::privacy::assert_no_pii_in_json;

pub const DEFAULT_ICD11_RELEASE: &str = "2026-01";
pub const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub const MAX_PART1_LINES: usize = 5;
pub const MAX_CONDITIONS_PER_LINE: usize = 8;
pub const MAX_TOTAL_CONDITIONS: usize = 20;
pub const MAX_TEXT_LENGTH: usize = 500;

const CERTIFICATE_KEYS: &[&str] = &[
    "ICDVersion",
    "ICDMinorVersion",
    "AdministrativeData",
    "Part1",
    "Part2",
    "Surgery",
    "Autopsy",
    "MannerOfDeath",
    "FetalOrInfantDeath",
    "MaternalDeath",
];

const CONDITION_KEYS: &[&str] = &[
    "Text",
    "Code",
    "LinearizationURI",
    "FoundationURI",
    "Interval",
];

const UNKNOWN_MEASUREMENTS: &[&str] = &["BirthWeight", "PregnancyWeeks", "AgeMother"];

const EXTERNAL_CAUSE_KEYS: &[&str] = &[
    "DateOfExternalCauseOrPoisoning",
    "DescriptionExternalCause",
    "PlaceOfOccuranceExternalCause",
];

static DATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<year>\d{4})(?:-(?P<month>\d{2})(?:-(?P<day>\d{2}))?)?(?:T(?P<hour>\d{2}):(?P<minute>\d{2})(?::(?P<second>\d{2})(?:\.\d+)?)?(?P<timezone>Z|[+-]\d{2}:\d{2})?)?$",
    )
    .expect("valid DATE_RE")
});

static DURATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^P(?:(?:(?:\d+(?:\.\d+)?Y)?(?:\d+(?:\.\d+)?M)?(?:\d+(?:\.\d+)?D)?)(?:T(?:\d+(?:\.\d+)?H)?(?:\d+(?:\.\d+)?M)?(?:\d+(?:\.\d+)?S)?)?|\d+(?:\.\d+)?W)?$",
    )
    .expect("valid DURATION_RE")
});

static AGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^P(?:(\d+(?:\.\d+)?)([YMWD]))?(?:T(\d+(?:\.\d+)?)([HMS]))?$")
        .expect("valid AGE_RE")
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DorisFieldError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("The DORIS certificate is invalid.")]
pub struct DorisCertificateError {
    pub fields: Vec<DorisFieldError>,
}

impl DorisCertificateError {
    pub fn single(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            fields: vec![DorisFieldError {
                path: path.into(),
                message: message.into(),
            }],
        }
    }
}

/// Recursively sort all JSON object keys and serialize with compact `,` and `:` separators,
/// matching Python `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))`.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let sorted = sort_json_keys(value);
    serde_json::to_vec(&sorted).expect("canonical JSON serialization")
}

fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::with_capacity(map.len());
            for k in keys {
                out.insert(k.clone(), sort_json_keys(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

/// Days in a simple ISO age (`P65Y`, `P3D`, `PT5H`, `PT30M`, `PT90S`); `None` if blank or complex.
/// Mirrors `_age_days` in `app/services/doris_certificate.py` and `durationDays` in `doris_rules.js`.
pub fn age_days(duration: &str) -> Option<f64> {
    let trimmed = duration.trim();
    let caps = AGE_RE.captures(trimmed)?;
    let has_date = caps.get(1).is_some();
    let has_time = caps.get(3).is_some();
    if !has_date && !has_time {
        return None;
    }

    let date_val: f64 = caps
        .get(1)
        .and_then(|m| m.as_str().parse::<f64>().ok())
        .unwrap_or(0.0);
    let date_unit = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let date_factor = match date_unit {
        "Y" => 365.25,
        "M" => 30.4375,
        "W" => 7.0,
        "D" => 1.0,
        _ => 0.0,
    };

    let time_val: f64 = caps
        .get(3)
        .and_then(|m| m.as_str().parse::<f64>().ok())
        .unwrap_or(0.0);
    let time_unit = caps.get(4).map(|m| m.as_str()).unwrap_or("");
    let time_factor = match time_unit {
        "H" => 1.0 / 24.0,
        "M" => 1.0 / 1440.0,
        "S" => 1.0 / 86400.0,
        _ => 0.0,
    };

    Some(date_val * date_factor + time_val * time_factor)
}

/// Remove the keys rules V1-V6 hide, in place; return the dropped `Section.Field` paths.
pub fn drop_inapplicable_sections(certificate: &mut Map<String, Value>) -> Vec<String> {
    let mut dropped = Vec::new();

    let est_age = certificate
        .get("AdministrativeData")
        .and_then(Value::as_object)
        .and_then(|m| m.get("EstimatedAge"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let days = est_age.as_deref().and_then(age_days);

    let stillborn = certificate
        .get("FetalOrInfantDeath")
        .and_then(Value::as_object)
        .and_then(|m| m.get("Stillborn"))
        .and_then(Value::as_i64);

    if let Some(d) = days
        && d >= 365.0
    {
        drop_section(certificate, "FetalOrInfantDeath", None, &mut dropped);
    } else if days.is_some_and(|d| d >= 7.0) || stillborn == Some(1) {
        drop_section(
            certificate,
            "FetalOrInfantDeath",
            Some(&["DeathWithin24h"]),
            &mut dropped,
        );
    }

    let sex = certificate
        .get("AdministrativeData")
        .and_then(Value::as_object)
        .and_then(|m| m.get("Sex"))
        .and_then(Value::as_i64);

    let was_pregnant = certificate
        .get("MaternalDeath")
        .and_then(Value::as_object)
        .and_then(|m| m.get("WasPregnant"))
        .and_then(Value::as_i64);

    if sex != Some(2) {
        drop_section(certificate, "MaternalDeath", None, &mut dropped);
    } else if was_pregnant != Some(1) {
        drop_section(
            certificate,
            "MaternalDeath",
            Some(&["TimeFromPregnancy", "PregnancyContribute"]),
            &mut dropped,
        );
    }

    let surgery_performed = certificate
        .get("Surgery")
        .and_then(Value::as_object)
        .and_then(|m| m.get("WasPerformed"))
        .and_then(Value::as_i64);
    if surgery_performed != Some(1) {
        drop_section(
            certificate,
            "Surgery",
            Some(&["Date", "Reason"]),
            &mut dropped,
        );
    }

    let autopsy_requested = certificate
        .get("Autopsy")
        .and_then(Value::as_object)
        .and_then(|m| m.get("WasRequested"))
        .and_then(Value::as_i64);
    if autopsy_requested != Some(1) {
        drop_section(certificate, "Autopsy", Some(&["Findings"]), &mut dropped);
    }

    let manner = certificate
        .get("MannerOfDeath")
        .and_then(Value::as_object)
        .and_then(|m| m.get("MannerOfDeath"))
        .and_then(Value::as_i64);
    if !matches!(manner, Some(1..=7)) {
        drop_section(
            certificate,
            "MannerOfDeath",
            Some(EXTERNAL_CAUSE_KEYS),
            &mut dropped,
        );
    }

    dropped
}

fn drop_section(
    certificate: &mut Map<String, Value>,
    section: &str,
    fields: Option<&[&str]>,
    dropped: &mut Vec<String>,
) {
    let Some(Value::Object(sec_map)) = certificate.get_mut(section) else {
        return;
    };
    let keys_to_remove: Vec<String> = match fields {
        Some(f) => f.iter().map(|s| (*s).to_string()).collect(),
        None => sec_map.keys().cloned().collect(),
    };
    for key in keys_to_remove {
        if sec_map.shift_remove(&key).is_some() {
            dropped.push(format!("{section}.{key}"));
        }
    }
    if sec_map.is_empty() {
        certificate.shift_remove(section);
    }
}

/// Bound and normalize a WHO death certificate JSON object without mutating caller data.
/// Enforces Rule 6 (no PII/registration identifiers) and all DigitVA DORIS certificate rules.
pub fn normalize_certificate(
    certificate: &Value,
    release: &str,
) -> Result<Value, DorisCertificateError> {
    assert_no_pii_in_json(certificate, "certificate").map_err(|e| {
        DorisCertificateError::single("certificate", e.to_string())
    })?;

    let Some(cert_obj) = certificate.as_object() else {
        return Err(DorisCertificateError::single(
            "certificate",
            "Must be an object.",
        ));
    };

    for key in cert_obj.keys() {
        if !CERTIFICATE_KEYS.contains(&key.as_str()) {
            return Err(DorisCertificateError::single(
                "certificate",
                "Contains unsupported fields.",
            ));
        }
    }

    if cert_obj.get("ICDVersion").and_then(Value::as_str) != Some("ICD11") {
        return Err(DorisCertificateError::single(
            "certificate.ICDVersion",
            "Must be ICD11.",
        ));
    }

    if let Some(supplied_release) = cert_obj.get("ICDMinorVersion")
        && !supplied_release.is_null()
        && supplied_release.as_str() != Some(release)
    {
        return Err(DorisCertificateError::single(
            "certificate.ICDMinorVersion",
            "Must match the configured release.",
        ));
    }

    let mut result = cert_obj.clone();
    result.insert(
        "ICDMinorVersion".to_string(),
        Value::String(release.to_string()),
    );

    if let Some(v) = result.get("AdministrativeData").cloned() {
        result.insert(
            "AdministrativeData".to_string(),
            normalize_administrative_data(&v, "certificate.AdministrativeData")?,
        );
    }
    if let Some(v) = result.get("Surgery").cloned() {
        result.insert(
            "Surgery".to_string(),
            normalize_surgery(&v, "certificate.Surgery")?,
        );
    }
    if let Some(v) = result.get("Autopsy").cloned() {
        result.insert(
            "Autopsy".to_string(),
            normalize_autopsy(&v, "certificate.Autopsy")?,
        );
    }
    if let Some(v) = result.get("MannerOfDeath").cloned() {
        result.insert(
            "MannerOfDeath".to_string(),
            normalize_manner_of_death(&v, "certificate.MannerOfDeath")?,
        );
    }
    if let Some(v) = result.get("FetalOrInfantDeath").cloned() {
        result.insert(
            "FetalOrInfantDeath".to_string(),
            normalize_fetal_or_infant_death(&v, "certificate.FetalOrInfantDeath")?,
        );
    }
    if let Some(v) = result.get("MaternalDeath").cloned() {
        result.insert(
            "MaternalDeath".to_string(),
            normalize_maternal_death(&v, "certificate.MaternalDeath")?,
        );
    }

    drop_inapplicable_sections(&mut result);

    let Some(part1_val) = result.get("Part1").and_then(Value::as_array) else {
        return Err(DorisCertificateError::single(
            "certificate.Part1",
            "Enter at least one Part I line.",
        ));
    };
    if part1_val.is_empty() {
        return Err(DorisCertificateError::single(
            "certificate.Part1",
            "Enter at least one Part I line.",
        ));
    }
    if part1_val.len() > MAX_PART1_LINES {
        return Err(DorisCertificateError::single(
            "certificate.Part1",
            "Part I may contain at most 5 lines.",
        ));
    }

    let mut normalized_lines = Vec::with_capacity(part1_val.len());
    let mut total_conditions = 0usize;
    for (idx, line) in part1_val.iter().enumerate() {
        let path = format!("certificate.Part1[{idx}]");
        let Some(line_obj) = line.as_object() else {
            return Err(DorisCertificateError::single(
                path,
                "Must contain only Conditions.",
            ));
        };
        if line_obj.len() != 1 || !line_obj.contains_key("Conditions") {
            return Err(DorisCertificateError::single(
                path,
                "Must contain only Conditions.",
            ));
        }
        let conds = normalize_conditions(&line_obj["Conditions"], &format!("{path}.Conditions"))?;
        total_conditions += conds.len();
        let mut new_line = Map::new();
        new_line.insert("Conditions".to_string(), Value::Array(conds));
        normalized_lines.push(Value::Object(new_line));
    }
    result.insert("Part1".to_string(), Value::Array(normalized_lines));

    if let Some(part2_val) = result.get("Part2").cloned()
        && !part2_val.is_null()
    {
        let Some(part2_obj) = part2_val.as_object() else {
            return Err(DorisCertificateError::single(
                "certificate.Part2",
                "Must contain only Conditions.",
            ));
        };
        if part2_obj.len() != 1 || !part2_obj.contains_key("Conditions") {
            return Err(DorisCertificateError::single(
                "certificate.Part2",
                "Must contain only Conditions.",
            ));
        }
        let Some(raw_part2) = part2_obj["Conditions"].as_array() else {
            return Err(DorisCertificateError::single(
                "certificate.Part2.Conditions",
                "Must be a list.",
            ));
        };
        let mut new_part2 = Map::new();
        if !raw_part2.is_empty() {
            let conds = normalize_conditions(
                &part2_obj["Conditions"],
                "certificate.Part2.Conditions",
            )?;
            total_conditions += conds.len();
            new_part2.insert("Conditions".to_string(), Value::Array(conds));
        } else {
            new_part2.insert("Conditions".to_string(), Value::Array(Vec::new()));
        }
        result.insert("Part2".to_string(), Value::Object(new_part2));
    }

    if total_conditions > MAX_TOTAL_CONDITIONS {
        return Err(DorisCertificateError::single(
            "certificate",
            "A certificate may contain at most 20 conditions.",
        ));
    }

    let out_val = Value::Object(result);
    if canonical_json_bytes(&out_val).len() > MAX_REQUEST_BYTES {
        return Err(DorisCertificateError::single(
            "certificate",
            "The certificate is too large.",
        ));
    }

    Ok(out_val)
}

fn normalize_conditions(raw: &Value, path: &str) -> Result<Vec<Value>, DorisCertificateError> {
    let Some(arr) = raw.as_array() else {
        return Err(DorisCertificateError::single(
            path,
            "Enter at least one condition.",
        ));
    };
    if arr.is_empty() {
        return Err(DorisCertificateError::single(
            path,
            "Enter at least one condition.",
        ));
    }
    if arr.len() > MAX_CONDITIONS_PER_LINE {
        return Err(DorisCertificateError::single(
            path,
            "A line may contain at most 8 conditions.",
        ));
    }

    let mut conditions = Vec::with_capacity(arr.len());
    let mut intervals: BTreeSet<Option<String>> = BTreeSet::new();

    for (idx, item) in arr.iter().enumerate() {
        let cond = validate_condition(item, &format!("{path}[{idx}]"))?;
        let interval = cond
            .as_object()
            .and_then(|m| m.get("Interval"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        intervals.insert(interval);
        conditions.push(cond);
    }

    if intervals.len() > 1 {
        return Err(DorisCertificateError::single(
            path,
            "All conditions on a line must use the same interval.",
        ));
    }

    Ok(conditions)
}

fn validate_condition(condition: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(obj) = condition.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    for key in obj.keys() {
        if !CONDITION_KEYS.contains(&key.as_str()) {
            return Err(DorisCertificateError::single(
                path,
                "Contains unsupported fields.",
            ));
        }
    }

    let mut result = obj.clone();
    let Some(text) = result.get("Text").and_then(Value::as_str) else {
        return Err(DorisCertificateError::single(
            format!("{path}.Text"),
            "Enter condition text.",
        ));
    };
    if text.trim().is_empty() {
        return Err(DorisCertificateError::single(
            format!("{path}.Text"),
            "Enter condition text.",
        ));
    }
    if text.chars().count() > MAX_TEXT_LENGTH {
        return Err(DorisCertificateError::single(
            format!("{path}.Text"),
            "Must be 500 characters or fewer.",
        ));
    }
    result.insert(
        "Text".to_string(),
        Value::String(text.trim().to_string()),
    );

    let code_opt = result.get("Code").filter(|v| !v.is_null());
    let uri_opt = result.get("LinearizationURI").filter(|v| !v.is_null());
    if code_opt.is_some() != uri_opt.is_some() {
        return Err(DorisCertificateError::single(
            path,
            "Code and LinearizationURI must be supplied together.",
        ));
    }
    if let (Some(code_val), Some(uri_val)) = (code_opt, uri_opt) {
        let Some(code_str) = code_val.as_str() else {
            return Err(DorisCertificateError::single(
                format!("{path}.Code"),
                "Must be a valid ICD-11 expression.",
            ));
        };
        if code_str.trim().is_empty() || code_str.chars().count() > 128 {
            return Err(DorisCertificateError::single(
                format!("{path}.Code"),
                "Must be a valid ICD-11 expression.",
            ));
        }
        let Some(uri_str) = uri_val.as_str() else {
            return Err(DorisCertificateError::single(
                format!("{path}.LinearizationURI"),
                "Must be a valid WHO URI.",
            ));
        };
        if uri_str.trim().is_empty() || uri_str.chars().count() > 2048 {
            return Err(DorisCertificateError::single(
                format!("{path}.LinearizationURI"),
                "Must be a valid WHO URI.",
            ));
        }
        let code_trimmed = code_str.trim().to_string();
        let uri_trimmed = uri_str.trim().to_string();
        result.insert("Code".to_string(), Value::String(code_trimmed));
        result.insert("LinearizationURI".to_string(), Value::String(uri_trimmed));
    }

    for key in ["FoundationURI", "Interval"] {
        if let Some(val) = result.get(key).cloned()
            && !val.is_null()
        {
            let Some(s) = val.as_str() else {
                return Err(DorisCertificateError::single(
                    format!("{path}.{key}"),
                    "Must be text.",
                ));
            };
            result.insert(key.to_string(), Value::String(s.trim().to_string()));
        }
    }

    if let Some(interval_str) = result.get("Interval").and_then(Value::as_str)
        && !interval_str.is_empty()
    {
        let validated = validate_duration(interval_str, &format!("{path}.Interval"))?;
        result.insert("Interval".to_string(), Value::String(validated));
    }

    Ok(Value::Object(result))
}

fn validate_integer(
    value: &Value,
    path: &str,
    allowed: Option<&[i64]>,
    min: Option<i64>,
    max: Option<i64>,
) -> Result<Value, DorisCertificateError> {
    if value.is_boolean() {
        return Err(DorisCertificateError::single(path, "Must be an integer."));
    }
    let Some(n) = value.as_i64() else {
        return Err(DorisCertificateError::single(path, "Must be an integer."));
    };
    if let Some(set) = allowed
        && !set.contains(&n)
    {
        return Err(DorisCertificateError::single(
            path,
            "Contains an unsupported value.",
        ));
    }
    if let Some(lo) = min
        && n < lo
    {
        return Err(DorisCertificateError::single(
            path,
            format!("Must be at least {lo}."),
        ));
    }
    if let Some(hi) = max
        && n > hi
    {
        return Err(DorisCertificateError::single(
            path,
            format!("Must be at most {hi}."),
        ));
    }
    Ok(Value::Number(n.into()))
}

fn validate_text(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(s) = value.as_str() else {
        return Err(DorisCertificateError::single(
            path,
            "Must be non-empty text.",
        ));
    };
    if s.trim().is_empty() {
        return Err(DorisCertificateError::single(
            path,
            "Must be non-empty text.",
        ));
    }
    if s.chars().count() > MAX_TEXT_LENGTH {
        return Err(DorisCertificateError::single(
            path,
            format!("Must be {MAX_TEXT_LENGTH} characters or fewer."),
        ));
    }
    Ok(Value::String(s.trim().to_string()))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

fn validate_date(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(raw) = value.as_str() else {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    };
    let s = raw.trim();
    if s.is_empty() || s.len() > 64 {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    let Some(caps) = DATE_RE.captures(s) else {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    };
    let year: i32 = caps["year"]
        .parse()
        .map_err(|_| DorisCertificateError::single(path, "Must be a valid date."))?;
    if year < 1 {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    let month: Option<u32> = caps.name("month").and_then(|m| m.as_str().parse().ok());
    let day: Option<u32> = caps.name("day").and_then(|m| m.as_str().parse().ok());
    if let Some(m) = month
        && !(1..=12).contains(&m)
    {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    if let Some(d) = day {
        let Some(m) = month else {
            return Err(DorisCertificateError::single(path, "Must be a valid date."));
        };
        if d < 1 || d > days_in_month(year, m) {
            return Err(DorisCertificateError::single(path, "Must be a valid date."));
        }
    }
    if let Some(h) = caps.name("hour").and_then(|m| m.as_str().parse::<u32>().ok())
        && h > 23
    {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    if let Some(min) = caps.name("minute").and_then(|m| m.as_str().parse::<u32>().ok())
        && min > 59
    {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    if let Some(sec) = caps.name("second").and_then(|m| m.as_str().parse::<u32>().ok())
        && sec > 59
    {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    if let Some(tz) = caps.name("timezone").map(|m| m.as_str())
        && tz != "Z"
    {
        let tz_h: u32 = tz[1..3].parse().unwrap_or(99);
        let tz_m: u32 = tz[4..6].parse().unwrap_or(99);
        if tz_h > 23 || tz_m > 59 {
            return Err(DorisCertificateError::single(path, "Must be a valid date."));
        }
    }
    if s.contains('T') && day.is_none() {
        return Err(DorisCertificateError::single(path, "Must be a valid date."));
    }
    Ok(Value::String(s.to_string()))
}

fn validate_duration(raw: &str, path: &str) -> Result<String, DorisCertificateError> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 64 || !DURATION_RE.is_match(s) {
        return Err(DorisCertificateError::single(
            path,
            "Must be a valid ISO 8601 duration.",
        ));
    }
    Ok(s.to_string())
}

fn validate_duration_value(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(s) = value.as_str() else {
        return Err(DorisCertificateError::single(
            path,
            "Must be a valid ISO 8601 duration.",
        ));
    };
    Ok(Value::String(validate_duration(s, path)?))
}

fn normalize_administrative_data(
    value: &Value,
    path: &str,
) -> Result<Value, DorisCertificateError> {
    let Some(obj) = value.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    let mut out = Map::new();
    for (k, v) in obj {
        let p = format!("{path}.{k}");
        let nv = match k.as_str() {
            "DateBirth" | "DateDeath" => validate_date(v, &p)?,
            "Sex" => validate_integer(v, &p, Some(&[1, 2, 9]), None, None)?,
            "EstimatedAge" => validate_duration_value(v, &p)?,
            _ => {
                return Err(DorisCertificateError::single(
                    path,
                    "Contains unsupported fields.",
                ));
            }
        };
        out.insert(k.clone(), nv);
    }
    Ok(Value::Object(out))
}

fn normalize_surgery(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(obj) = value.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    let mut out = Map::new();
    for (k, v) in obj {
        let p = format!("{path}.{k}");
        let nv = match k.as_str() {
            "WasPerformed" => validate_integer(v, &p, Some(&[0, 1, 9]), None, None)?,
            "Date" => validate_date(v, &p)?,
            "Reason" => validate_text(v, &p)?,
            _ => {
                return Err(DorisCertificateError::single(
                    path,
                    "Contains unsupported fields.",
                ));
            }
        };
        out.insert(k.clone(), nv);
    }
    Ok(Value::Object(out))
}

fn normalize_autopsy(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(obj) = value.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    let mut out = Map::new();
    for (k, v) in obj {
        let p = format!("{path}.{k}");
        let nv = match k.as_str() {
            "WasRequested" | "Findings" => validate_integer(v, &p, Some(&[0, 1, 9]), None, None)?,
            _ => {
                return Err(DorisCertificateError::single(
                    path,
                    "Contains unsupported fields.",
                ));
            }
        };
        out.insert(k.clone(), nv);
    }
    Ok(Value::Object(out))
}

fn normalize_manner_of_death(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(obj) = value.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    let mut out = Map::new();
    for (k, v) in obj {
        let p = format!("{path}.{k}");
        let nv = match k.as_str() {
            "MannerOfDeath" => {
                validate_integer(v, &p, Some(&[0, 1, 2, 3, 4, 5, 6, 7, 9]), None, None)?
            }
            "DateOfExternalCauseOrPoisoning" => validate_date(v, &p)?,
            "DescriptionExternalCause" => validate_text(v, &p)?,
            "PlaceOfOccuranceExternalCause" => {
                validate_integer(v, &p, Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), None, None)?
            }
            _ => {
                return Err(DorisCertificateError::single(
                    path,
                    "Contains unsupported fields.",
                ));
            }
        };
        out.insert(k.clone(), nv);
    }
    Ok(Value::Object(out))
}

fn normalize_fetal_or_infant_death(
    value: &Value,
    path: &str,
) -> Result<Value, DorisCertificateError> {
    let Some(obj) = value.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    let allowed_keys = [
        "MultiplePregnancy",
        "Stillborn",
        "DeathWithin24h",
        "BirthWeight",
        "PregnancyWeeks",
        "AgeMother",
        "PerinatalDescription",
    ];
    for k in obj.keys() {
        if !allowed_keys.contains(&k.as_str()) {
            return Err(DorisCertificateError::single(
                path,
                "Contains unsupported fields.",
            ));
        }
    }

    let mut out = Map::new();
    for (k, v) in obj {
        if UNKNOWN_MEASUREMENTS.contains(&k.as_str())
            && (v.is_null() || v.as_str() == Some(""))
        {
            continue;
        }
        let p = format!("{path}.{k}");
        let nv = match k.as_str() {
            "MultiplePregnancy" | "Stillborn" => {
                validate_integer(v, &p, Some(&[0, 1, 9]), None, None)?
            }
            "DeathWithin24h" => validate_integer(v, &p, None, Some(0), Some(24))?,
            "BirthWeight" => validate_integer(v, &p, None, Some(1), Some(9999))?,
            "PregnancyWeeks" => validate_integer(v, &p, None, Some(1), Some(50))?,
            "AgeMother" => validate_integer(v, &p, None, Some(10), Some(80))?,
            "PerinatalDescription" => validate_text(v, &p)?,
            _ => unreachable!(),
        };
        out.insert(k.clone(), nv);
    }
    Ok(Value::Object(out))
}

fn normalize_maternal_death(value: &Value, path: &str) -> Result<Value, DorisCertificateError> {
    let Some(obj) = value.as_object() else {
        return Err(DorisCertificateError::single(path, "Must be an object."));
    };
    let mut out = Map::new();
    for (k, v) in obj {
        let p = format!("{path}.{k}");
        let nv = match k.as_str() {
            "WasPregnant" | "PregnancyContribute" => {
                validate_integer(v, &p, Some(&[0, 1, 9]), None, None)?
            }
            "TimeFromPregnancy" => validate_integer(v, &p, Some(&[0, 1, 2, 3, 9]), None, None)?,
            _ => {
                return Err(DorisCertificateError::single(
                    path,
                    "Contains unsupported fields.",
                ));
            }
        };
        out.insert(k.clone(), nv);
    }
    Ok(Value::Object(out))
}
