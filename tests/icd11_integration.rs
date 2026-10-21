use std::path::PathBuf;

use serde_json::{Value, json};
use who_icd11_api::{
    DEFAULT_ICD11_RELEASE, Icd11Engine, Icd11Error, ProcessorCallOutcome, SearchOptions, age_days,
    assert_no_pii_in_json, assert_no_pii_in_text, drop_inapplicable_sections,
    normalize_certificate, postcoordination_availability, process_certificate_with,
    strip_who_search_markup, valid_subtree_uris,
};

const TB_URI: &str = "http://id.who.int/icd/release/11/2026-01/mms/882244568/unspecified";

fn sample_payload() -> Value {
    json!({
        "schema_version": 1,
        "client_revision": 3,
        "certificate": {
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 1, "EstimatedAge": "P44Y"},
            "Part1": [
                {
                    "Conditions": [
                        {
                            "Text": "Respiratory tuberculosis",
                            "Code": "1B10.Z",
                            "LinearizationURI": TB_URI,
                            "Interval": "P14D"
                        }
                    ]
                }
            ]
        }
    })
}

#[test]
fn test_age_days_matches_editor_and_server_contract() {
    let cases: &[(&str, Option<f64>)] = &[
        ("PT30M", Some(30.0 / 1440.0)),
        ("PT90S", Some(90.0 / 86400.0)),
        ("PT23H", Some(23.0 / 24.0)),
        ("P6D", Some(6.0)),
        ("P7D", Some(7.0)),
        ("P364D", Some(364.0)),
        ("P1Y", Some(365.25)),
        ("PT", None),
        ("P1H", None),
        ("abc", None),
        ("", None),
    ];
    for (iso, expected) in cases {
        let got = age_days(iso);
        match expected {
            None => assert!(got.is_none(), "expected None for {iso}, got {got:?}"),
            Some(exp) => {
                let g = got.unwrap_or_else(|| panic!("expected Some for {iso}"));
                assert!(
                    (g - exp).abs() < 1e-12,
                    "mismatch for {iso}: got {g}, expected {exp}"
                );
            }
        }
    }
}

#[test]
fn test_drop_inapplicable_sections_v1_to_v6_rules() {
    let fetal = json!({"Stillborn": 0, "DeathWithin24h": 5, "BirthWeight": 2000});
    let external = json!({
        "DateOfExternalCauseOrPoisoning": "2025-01-02",
        "DescriptionExternalCause": "fell",
        "PlaceOfOccuranceExternalCause": 4
    });

    let adult = normalize_certificate(
        &json!({
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 1, "EstimatedAge": "P65Y"},
            "Part1": [{"Conditions": [{"Text": "Fall"}]}],
            "FetalOrInfantDeath": fetal,
        }),
        DEFAULT_ICD11_RELEASE,
    )
    .unwrap();
    assert!(adult.get("FetalOrInfantDeath").is_none());

    let p6d = normalize_certificate(
        &json!({
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 1, "EstimatedAge": "P6D"},
            "Part1": [{"Conditions": [{"Text": "Fall"}]}],
            "FetalOrInfantDeath": fetal,
        }),
        DEFAULT_ICD11_RELEASE,
    )
    .unwrap();
    assert!(p6d["FetalOrInfantDeath"].get("DeathWithin24h").is_some());

    let p7d = normalize_certificate(
        &json!({
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 1, "EstimatedAge": "P7D"},
            "Part1": [{"Conditions": [{"Text": "Fall"}]}],
            "FetalOrInfantDeath": fetal,
        }),
        DEFAULT_ICD11_RELEASE,
    )
    .unwrap();
    assert!(p7d["FetalOrInfantDeath"].get("DeathWithin24h").is_none());

    let maternal = json!({"WasPregnant": 1, "TimeFromPregnancy": 1, "PregnancyContribute": 1});
    let male_mat = normalize_certificate(
        &json!({
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 1, "EstimatedAge": "P30Y"},
            "Part1": [{"Conditions": [{"Text": "Haemorrhage"}]}],
            "MaternalDeath": maternal,
        }),
        DEFAULT_ICD11_RELEASE,
    )
    .unwrap();
    assert!(male_mat.get("MaternalDeath").is_none());

    let fem_not_preg = normalize_certificate(
        &json!({
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 2, "EstimatedAge": "P30Y"},
            "Part1": [{"Conditions": [{"Text": "Haemorrhage"}]}],
            "MaternalDeath": {"WasPregnant": 0, "TimeFromPregnancy": 1, "PregnancyContribute": 1},
        }),
        DEFAULT_ICD11_RELEASE,
    )
    .unwrap();
    assert_eq!(fem_not_preg["MaternalDeath"], json!({"WasPregnant": 0}));

    let manner_0 = normalize_certificate(
        &json!({
            "ICDVersion": "ICD11",
            "AdministrativeData": {"Sex": 1, "EstimatedAge": "P30Y"},
            "Part1": [{"Conditions": [{"Text": "Fall"}]}],
            "MannerOfDeath": {
                "MannerOfDeath": 0,
                "DateOfExternalCauseOrPoisoning": external["DateOfExternalCauseOrPoisoning"],
                "DescriptionExternalCause": external["DescriptionExternalCause"],
                "PlaceOfOccuranceExternalCause": external["PlaceOfOccuranceExternalCause"]
            }
        }),
        DEFAULT_ICD11_RELEASE,
    )
    .unwrap();
    assert_eq!(manner_0["MannerOfDeath"], json!({"MannerOfDeath": 0}));

    let mut raw_map = json!({
        "AdministrativeData": {"Sex": 1, "EstimatedAge": "P40Y"},
        "FetalOrInfantDeath": fetal
    })
    .as_object()
    .unwrap()
    .clone();
    let dropped = drop_inapplicable_sections(&mut raw_map);
    assert_eq!(
        dropped,
        vec![
            "FetalOrInfantDeath.Stillborn",
            "FetalOrInfantDeath.DeathWithin24h",
            "FetalOrInfantDeath.BirthWeight"
        ]
    );
    assert!(drop_inapplicable_sections(&mut raw_map).is_empty());
}

#[test]
fn test_normalize_certificate_validation_and_postcoordination_helpers() {
    let mut cert = sample_payload()["certificate"].clone();
    cert["AdministrativeData"]["EstimatedAge"] = json!("P2D");
    cert["FetalOrInfantDeath"] = json!({
        "Stillborn": 9,
        "BirthWeight": null,
        "PregnancyWeeks": "",
        "AgeMother": null
    });
    let normalized = normalize_certificate(&cert, DEFAULT_ICD11_RELEASE).unwrap();
    assert_eq!(normalized["ICDMinorVersion"], "2026-01");
    assert_eq!(normalized["FetalOrInfantDeath"], json!({"Stillborn": 9}));

    let mut multi_line = sample_payload()["certificate"].clone();
    multi_line["Part1"][0]["Conditions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "Text": "Tuberculous otitis media",
            "Code": "1B12.2&XA0G74",
            "LinearizationURI": "http://id.who.int/icd/release/11/2026-01/mms/883140666 & http://id.who.int/icd/release/11/2026-01/mms/1902897114",
            "Interval": "P60D"
        }));
    let err = normalize_certificate(&multi_line, DEFAULT_ICD11_RELEASE).unwrap_err();
    assert!(err.fields[0].message.contains("same interval"));

    assert!(valid_subtree_uris(None));
    assert!(valid_subtree_uris(Some(&[
        "http://id.who.int/icd/release/11/2026-01/mms/979408586".to_string()
    ])));
    assert!(!valid_subtree_uris(Some(&[])));
    assert!(!valid_subtree_uris(Some(&[
        "https://not-who.example/icd/1".to_string()
    ])));

    assert_eq!(postcoordination_availability(&json!(0)), (false, Some(0)));
    assert_eq!(postcoordination_availability(&json!(1)), (true, Some(1)));
    assert_eq!(postcoordination_availability(&json!(2)), (true, Some(2)));
    assert_eq!(postcoordination_availability(&json!("2")), (false, None));
    assert_eq!(postcoordination_availability(&json!(true)), (false, None));

    assert_eq!(
        strip_who_search_markup("<em class='found'>Type 2</em> diabetes"),
        "Type 2 diabetes"
    );
}

#[test]
fn test_rule6_pii_boundary_rejects_personal_and_identifier_data() {
    let mut bad_cert = sample_payload()["certificate"].clone();
    bad_cert["informant_phone"] = json!("9876543210");
    let err = normalize_certificate(&bad_cert, DEFAULT_ICD11_RELEASE).unwrap_err();
    assert!(err.fields[0].message.contains("PII boundary violation"));

    let mut aadhaar_cert = sample_payload()["certificate"].clone();
    aadhaar_cert["Part1"][0]["Conditions"][0]["Text"] =
        json!("Respiratory tuberculosis patient 2345 6789 0123");
    let err2 = normalize_certificate(&aadhaar_cert, DEFAULT_ICD11_RELEASE).unwrap_err();
    assert!(err2.fields[0].message.contains("Aadhaar"));

    assert!(assert_no_pii_in_text("diabetes 9876543210", "search.q").is_err());

    assert!(
        assert_no_pii_in_json(
            &json!({"identifiers": {"CRS": "ABC12345"}}),
            "payload"
        )
        .is_err()
    );
}

#[test]
fn test_process_certificate_independent_statuses_and_digests() {
    let payload = sample_payload();
    let mock_codeinfo = |code: &str, _rel: &str| -> Option<Value> {
        match code {
            "1B10.Z" => Some(json!({"code": "1B10.Z", "stemId": TB_URI})),
            _ => None,
        }
    };

    let res = process_certificate_with(
        &payload,
        DEFAULT_ICD11_RELEASE,
        "sha256:test",
        mock_codeinfo,
        |name, _cert, _rel| {
            if name == "doris" {
                ProcessorCallOutcome::Timeout
            } else {
                ProcessorCallOutcome::Response(
                    200,
                    json!({"report": "check", "tabularReport": "table", "issueIds": "A|B"})
                        .to_string(),
                )
            }
        },
    )
    .unwrap();
    assert_eq!(res["doris"]["status"], "timeout");
    assert_eq!(res["codedit"]["status"], "completed");
    assert_eq!(res["codedit"]["result"]["issueIds"], "A|B");

    let rejected = process_certificate_with(
        &payload,
        DEFAULT_ICD11_RELEASE,
        "sha256:test",
        mock_codeinfo,
        |name, _cert, _rel| {
            if name == "doris" {
                ProcessorCallOutcome::Response(
                    200,
                    json!({
                        "code": null,
                        "stemCode": null,
                        "uri": null,
                        "stemURI": null,
                        "report": "Rejected",
                        "tabularReport": "",
                        "reject": true,
                        "error": "No valid code",
                        "warning": null
                    })
                    .to_string(),
                )
            } else {
                ProcessorCallOutcome::Response(
                    200,
                    json!({"report": "check", "tabularReport": "table", "issueIds": ""})
                        .to_string(),
                )
            }
        },
    )
    .unwrap();
    assert_eq!(rejected["doris"]["status"], "rejected");
    assert_eq!(rejected["codedit"]["status"], "completed");
}

#[test]
fn test_live_in_process_who_icd11_and_doris_dll_engine() {
    let engine = Icd11Engine::global().expect("initialize in-process WHO ICD-11 + DORIS DLLs");
    assert!(engine.bound_port() > 0);

    let ba41 = engine
        .codeinfo("BA41.Z", None)
        .expect("codeinfo BA41.Z")
        .expect("BA41.Z exists");
    assert_eq!(ba41["code"], "BA41.Z");
    assert_eq!(
        ba41["stemId"],
        "http://id.who.int/icd/release/11/2026-01/mms/1334938734/unspecified"
    );

    let postcoord = engine
        .codeinfo("1B12.2&XA0G74", None)
        .expect("codeinfo 1B12.2&XA0G74")
        .expect("1B12.2&XA0G74 exists");
    assert_eq!(postcoord["code"], "1B12.2&XA0G74");
    assert_eq!(postcoord["stemCode"], "1B12.2");
    assert_eq!(
        postcoord["stemId"],
        "http://id.who.int/icd/release/11/2026-01/mms/883140666"
    );
    assert_eq!(postcoord["specificAnatomy"], json!(["XA0G74"]));

    let unknown = engine
        .codeinfo("NOT_A_CODE_999", None)
        .expect("unknown codeinfo call");
    assert!(unknown.is_none());

    let search_res = engine
        .search(
            "diabetes",
            &SearchOptions {
                flat_results: true,
                highlighting_enabled: true,
                ..Default::default()
            },
            None,
        )
        .expect("search diabetes");
    let entities = search_res["destinationEntities"]
        .as_array()
        .expect("destinationEntities array");
    assert!(!entities.is_empty());
    let first_code = entities[0]["theCode"].as_str().unwrap_or("");
    let first_title = strip_who_search_markup(entities[0]["title"].as_str().unwrap_or(""));
    assert!(first_code.starts_with("5A1"));
    assert!(first_title.to_lowercase().contains("diabetes"));

    let auto = engine
        .autocode("acute myocardial infarction", None, None, None)
        .expect("autocode AMI");
    assert_eq!(auto["theCode"], "BA41.Z");

    let ent = engine
        .entity("883140666", None, None)
        .expect("entity 883140666");
    assert_eq!(ent["code"], "1B12.2");
    assert!(ent["postcoordinationScale"].as_array().is_some());

    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/doris_help_examples.json");
    let fixture_text =
        std::fs::read_to_string(&fixture_path).expect("read tests/fixtures/doris_help_examples.json");
    let fixture_json: Value = serde_json::from_str(&fixture_text).unwrap();
    let examples = fixture_json["examples"].as_array().unwrap();
    assert_eq!(examples.len(), 6);

    for ex in examples {
        let ex_id = ex["id"].as_str().unwrap();
        let cert = &ex["certificate"];
        let obs_doris = &ex["observed"]["doris"];
        let obs_codedit = &ex["observed"]["codedit"];

        let payload = json!({
            "schema_version": 1,
            "client_revision": 1,
            "certificate": cert,
        });
        let processed = engine
            .process_certificate(&payload, None, "rust-dll-2.6.0")
            .unwrap_or_else(|e| panic!("process_certificate failed for {ex_id}: {e:?}"));

        assert_eq!(
            processed["doris"]["status"], "completed",
            "doris status for {ex_id}"
        );
        assert_eq!(
            processed["codedit"]["status"], "completed",
            "codedit status for {ex_id}"
        );

        let doris_res = &processed["doris"]["result"];
        let codedit_res = &processed["codedit"]["result"];

        assert_eq!(
            doris_res["reject"], obs_doris["reject"],
            "doris.reject mismatch on {ex_id}"
        );
        assert_eq!(
            doris_res["code"], obs_doris["code"],
            "doris.code mismatch on {ex_id}"
        );
        assert_eq!(
            doris_res["warning"], obs_doris["warning"],
            "doris.warning mismatch on {ex_id}"
        );
        assert_eq!(
            codedit_res["issueIds"], obs_codedit["issueIds"],
            "codedit.issueIds mismatch on {ex_id}"
        );

        let processed_again = engine
            .process_certificate(&payload, None, "rust-dll-2.6.0")
            .unwrap();
        assert_eq!(
            processed["certificate_digest"],
            processed_again["certificate_digest"]
        );
        assert_eq!(
            processed["result_digest"],
            processed_again["result_digest"]
        );
    }

    let (ct_redirect, _) = engine
        .raw_request("GET", "/ct", None, None)
        .expect("GET /ct redirect");
    assert_eq!(ct_redirect, 302);

    let (ct_status, ct_html) = engine
        .raw_request("GET", "/ct/2026-01/mms/en", None, None)
        .expect("GET /ct/2026-01/mms/en");
    assert_eq!(ct_status, 200);
    assert!(ct_html.contains("ECT.Handler.configure"));

    let (browse_status, browse_html) = engine
        .raw_request("GET", "/browse/2026-01/mms/en", None, None)
        .expect("GET /browse/2026-01/mms/en");
    assert_eq!(browse_status, 200);
    assert!(browse_html.contains("ECT.Handler.configure"));

    let pii_err = engine
        .search(
            "diabetes informant 9876543210",
            &SearchOptions::default(),
            None,
        )
        .unwrap_err();
    assert!(matches!(pii_err, Icd11Error::PiiBoundaryViolation { .. }));
}

#[test]
fn test_sha256_pinned_bundle_integrity_and_tamper_detection() {
    use who_icd11_api::bootstrap::{
        PINNED_DLL_SHA256, PINNED_DORIS_FILES_SHA256, verify_bundle_integrity, verify_file_sha256,
    };

    assert_eq!(PINNED_DLL_SHA256.len(), 79);
    assert_eq!(PINNED_DORIS_FILES_SHA256.len(), 7);

    // Ensure the engine bundle exists and verify all 79 DLLs + 10 WHO data files via Rust sha2::Sha256
    let _engine = Icd11Engine::global().expect("initialize in-process WHO ICD-11 + DORIS DLLs");
    let bridge_dll = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bridge/DigitvaIcd11Bridge.dll");
    verify_file_sha256(
        &bridge_dll,
        "1783241ff66b061c4a15eeae66a07d29f4391848b6dce844859f807a3d850953",
    )
    .expect("embedded DigitvaIcd11Bridge.dll matches pinned SHA-256");

    // Verify tamper detection rejects wrong SHA-256
    let tamper_err = verify_file_sha256(
        &bridge_dll,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap_err();
    assert!(tamper_err.to_string().contains("SHA-256 mismatch"));

    let workspace_bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../desktop/target/icd11-runtime");
    if workspace_bundle.join("icdapi").exists() && workspace_bundle.join("data").exists() {
        verify_bundle_integrity(
            &workspace_bundle.join("icdapi"),
            &workspace_bundle.join("data"),
        )
        .expect("all 79 DLLs and 10 offline WHO data files match pinned SHA-256");
    }
}
