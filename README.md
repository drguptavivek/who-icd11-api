# `who-icd11-api` — Native Rust In-Process DLL Host & Zero-Docker Server for WHO ICD-11 `2.6.0` & DORIS `1.2.0`

`who-icd11-api` loads the official WHO ICD-11 `2.6.0` and DORIS `1.2.0` portable AnyCPU `.dll` assemblies (`ICD-API.dll`, `DorisRuleEngine.dll`, `OCT.dll`, `ICDTextAnalyzers.dll`, `Expressions.dll`) directly in-process in Rust via `.NET`'s native `libhostfxr` (`libhostfxr.dylib` / `libhostfxr.so` / `hostfxr.dll`), completely eliminating the `whoicd/icd-api:2.6.0` Docker container.

## Key Features

- **Zero Docker Runtime & Zero `.NET SDK` Compilation**:
  - **No `dotnet build` happens during `docker pull`, `cargo build`, or runtime**: WHO ships `ICD-API.dll`, `DorisRuleEngine.dll`, and `OCT.dll` as pre-compiled AnyCPU CIL assemblies, and our 13 KB C-ABI bridge (`DigitvaIcd11Bridge.dll`) is pre-compiled AnyCPU CIL embedded directly into the Rust binary via `include_bytes!`.
  - **Pure-Rust Bootstrap with Cryptographic SHA-256 Pinning (`who_icd11_api::ensure_runtime_bundle`)**: When no local bundle is present on disk, Rust streams the `/usr/share/icdapi` layer directly from the OCI Registry (`registry-1.docker.io`) over HTTPS (`ureq` + `flate2` + `tar`), verifies the OCI Image Index, `linux/amd64` manifest, compressed layer blob, all 79 `.dll` assemblies (`PINNED_DLL_SHA256`), and all 3 WHO CDN offline archives + 7 immutable DORIS rule files (`PINNED_DORIS_FILES_SHA256`) using `sha2::Sha256` in Rust.

## Pinned Versions & SHA-256 Digests (`src/bootstrap.rs`)

| Artifact | Pinned Version / Source | SHA-256 Digest |
| --- | --- | --- |
| OCI Image Index | `whoicd/icd-api:2.6.0` | `1b77eb6dc43e0c65a12e9e9340ad178493c93488e728d0d936507cc57ada1b7c` |
| OCI `linux/amd64` Manifest | `whoicd/icd-api:2.6.0` | `a63a4c1c73329ff2ebff616a0cde2089b6b0595dec25255844f57f5b1903a4b8` |
| OCI `/usr/share/icdapi` Layer Blob | `registry-1.docker.io` | `d4527f82f3377c545daf8ff6de89dff08d1467970ed1343b96c8a1a515860663` |
| `ICD-API.dll` | WHO ICD-11 API `2.6.0` | `0ab8e927fd4201526c1eac3792c8608fbf873d00c2c87c0d5065a97abb56011b` |
| `DorisRuleEngine.dll` | WHO DORIS `1.2.0` | `c3c17cf191e3b2c0190aaef77f933d7bd81f0cdede0636d086737497437104fb` |
| `OCT.dll` | WHO ICD-11 API `2.6.0` | `0c761cdd87d8f4a3494d9775a18c69cab4ff8cd112481b19882ccc9f88df3ab9` |
| `DigitvaIcd11Bridge.dll` | Embedded C-ABI Bridge `1.0.0` | `1783241ff66b061c4a15eeae66a07d29f4391848b6dce844859f807a3d850953` |
| `icd11_2026-01-17_release-icf-mms_en.pbf.gz` | `icdcdn.who.int` (`2026-01_en`) | `2fd67533b4c838723bd68b833a98ee6dab284339a6262f3f972251e97c331901` |
| `ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip` | `icdcdn.who.int` (`2026-01_en`) | `f7c1b463075b64bb49987a9fac66c2f072a2684e9654d0ddbcc2b408ef9e9952` |
| `ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf` | Extracted Index PBF | `cb64df32bb077a126ad339bab0fe61018cc857616293c7f3bcf974dcaaacbdaa` |
| `DORIS_v2.1_1.2.0.zip` | `icd11files.blob.core.windows.net` | `c4876903346d7bdd1ab6c83cfa1aa8690340174089703ecdce382cfa5a3a59ae` |
| `DORIS_v2.1_1.2.0/Rules.json` | Extracted DORIS Rules | `6fc6c900c911dd582a6401e9aafeebe12892600126c915b9fc6ae5746ff1d6fa` |
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
