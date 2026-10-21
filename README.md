# `who-icd11-api` — Native Rust In-Process DLL Host & Zero-Docker Server for WHO ICD-11 `2.6.0` & DORIS `1.2.0`

`who-icd11-api` loads the official WHO ICD-11 `2.6.0` and DORIS `1.2.0` portable AnyCPU `.dll` assemblies (`ICD-API.dll`, `DorisRuleEngine.dll`, `OCT.dll`, `ICDTextAnalyzers.dll`, `Expressions.dll`) directly in-process in Rust via `.NET`'s native `libhostfxr` (`libhostfxr.dylib` / `libhostfxr.so` / `hostfxr.dll`), completely eliminating the `whoicd/icd-api:2.6.0` Docker container.

## Key Features

- **Zero Docker Runtime & Zero `.NET SDK` Compilation**:
  - **No `dotnet build` happens during `docker pull`, `cargo build`, or runtime**: WHO ships `ICD-API.dll`, `DorisRuleEngine.dll`, and `OCT.dll` as pre-compiled AnyCPU CIL assemblies, and our 13 KB C-ABI bridge (`DigitvaIcd11Bridge.dll`) is pre-compiled AnyCPU CIL embedded directly into the Rust binary via `include_bytes!`.
  - **Pure-Rust Bootstrap (`who_icd11_api::ensure_runtime_bundle`)**: When no local bundle is present on disk, Rust streams the `/usr/share/icdapi` layer directly from the OCI Registry (`registry-1.docker.io`) over HTTPS (`ureq` + `flate2` + `tar`), strips the 328 Linux-specific `runtimepack.*` binaries on the fly to leave only the 78 portable AnyCPU DLLs (`67 MB`), and downloads the 3 official WHO offline archives (`icd11_2026-01-17_release-icf-mms_en.pbf.gz`, `ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip`, `DORIS_v2.1_1.2.0.zip`) directly from WHO's CDNs (`zip`).
- **In-Process Rust FFI Engine (`Icd11Engine`)**:
  - `codeinfo("BA41.Z")`, `codeinfo("1B12.2&XA0G74")`
  - `search("diabetes", &SearchOptions)`
  - `autocode("acute myocardial infarction", ...)`
  - `entity("883140666", ...)`
  - `doris(&certificate, None)` & `codedit(&certificate, None)`
  - `process_certificate(&payload, None, "rust-dll-2.6.0")` (full V1–V6 `drop_inapplicable_sections`, `normalize_certificate`, `verify_certificate_codes`, and SHA-256 `certificate_digest` / `result_digest`)
- **Non-PII Clinical Boundary (Rule 6)**:
  - Rejects any JSON payload or query string containing personal or registration identifier keys (`name`, `informant_phone`, `address`, `aadhaar`, `abha`, `identifiers`, `crs_number`, `mccd_number`) or embedded 12-digit Aadhaar / 10-digit phone numbers before crossing into the WHO DLLs.
- **Standalone Drop-In Server Binary (`who-icd11-server`)**:
  - Serves the full WHO ICD-11 HTTP API (`/icd/release/11/2026-01/...`, `/icd/entity/...`) plus the Embedded Coding Tool (`/ct`) and Browser (`/browse`) on `127.0.0.1:8382`.

## Quick Start

```bash
# 1. Bootstrap the portable DLL bundle and offline 2026-01 + DORIS 1.2.0 data in pure Rust (zero Docker):
cargo run --release --bin who-icd11-server -- --bootstrap

# 2. Run the full integration test suite (including all 6 WHO DORIS & CoDEdit reference certificates):
cargo test -- --nocapture

# 3. Run the drop-in WHO ICD-11 HTTP server on 127.0.0.1:8382:
cargo run --release --bin who-icd11-server -- --port 8382
```
