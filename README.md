# who-icd11-api

## What it is

`who-icd11-server` runs WHO's ICD-11 API 2.6.0, the DORIS 1.2.0 underlying-cause-of-death rule engine and CoDEdit certificate checks without Docker. It loads WHO's .NET assemblies in-process through the .NET host (`hostfxr`) and serves the same HTTP API as WHO's `whoicd/icd-api:2.6.0` container, plus the Embedded Coding Tool (`/ct`) and Browser (`/browse`), by default on `127.0.0.1:8382`. After a one-time `--bootstrap` it needs no network. The same engine is available as a Rust library (`who_icd11_api`). It is meant for death certification, mortality coding units and civil registration systems that need ICD-11 search, code lookup and DORIS / CoDEdit on their own hardware, including offline.

## What is and is not included

This repository and its release archives contain only this project's own code and its own small bridge assembly (`bridge/DigitvaIcd11Bridge.dll`, built from `bridge/Bridge.cs`, embedded in the binary). They contain **no WHO assemblies and no WHO data**. WHO has not given written permission to redistribute them.

`--bootstrap` downloads WHO's files to your machine, directly from WHO's own sources, and checks every file against SHA-256 digests pinned in `src/bootstrap.rs`:

- the ICD-API / DORIS assemblies, from the Docker Hub image `whoicd/icd-api:2.6.0` (read over HTTPS, no Docker daemon needed);
- the ICD-11 `2026-01` English release and search index, from `icdcdn.who.int`;
- the DORIS `1.2.0` rules, from `icd11files.blob.core.windows.net`.

Those files stay under WHO's terms. See [NOTICE](NOTICE). Only English and release `2026-01` are pinned.

## Prerequisites

- .NET 10 runtime with both `Microsoft.NETCore.App` and `Microsoft.AspNetCore.App` 10.0.0 or later (the ASP.NET Core runtime, not only the base runtime). `dotnet --list-runtimes` must show both.
- `DOTNET_ROOT` pointing at the .NET install if it is not in `/usr/local/share/dotnet`, `/usr/share/dotnet` or `/opt/homebrew/opt/dotnet/libexec` (`src/hostfxr.rs` looks there when `DOTNET_ROOT` is unset).
- About 310 MB of disk for the bootstrapped files, and network access to Docker Hub, `icdcdn.who.int` and `icd11files.blob.core.windows.net` once.
- To build from source: Rust 1.88 or later (edition 2024 with let-chains). The .NET SDK is not needed.

## Install

From a release archive (when one is published): unpack `who-icd11-server-<tag>-<target>.tar.gz` and check it against `SHA256SUMS`. The archive holds the binary, `LICENSE`, `NOTICE` and this README.

From source:

```bash
cargo install --git https://github.com/drguptavivek/who-icd11-api --locked who-icd11-api
```

## Bootstrap

```bash
who-icd11-server --bootstrap          # into ./runtime; or --output-dir <dir>
```

This creates `runtime/icdapi` (assemblies) and `runtime/data` (ICD-11 and DORIS data) and verifies them. It is safe to re-run: present files are re-verified, not downloaded again.

## Run

From the directory holding `runtime/`, start it:

```bash
who-icd11-server --port 8382          # or --bind http://127.0.0.1:8382, or DIGITVA_ICD11_BIND
```

For a bundle elsewhere, set `DIGITVA_ICD11_BUNDLE_DIR` (the `icdapi` directory) and `DIGITVA_ICD11_DATA_DIR` (the `data` directory). With neither set and no `./runtime`, the server bootstraps into `./runtime` first. The server prints `who-icd11-server listening on ...` when ready. Notes:

- It binds loopback by default and has **no authentication**. Do not expose it beyond a trusted host without a reverse proxy.
- On macOS it did not exit on `SIGTERM` in testing; stop it with Ctrl-C or `SIGKILL`.
- Unrecognised arguments are ignored silently, so check the "listening on" line.
- If port 8382 is taken (for example by WHO's own container) the start fails with "address already in use"; choose another `--port`.

## Examples

Requests go to WHO's own API, so they need the headers it requires: `API-Version: v2` always, and `Accept-Language: en` for search, autocode and entity requests. The release is `2026-01`.

```bash
B=http://127.0.0.1:8382
H1='API-Version: v2'; H2='Accept-Language: en'
```

**Look up a code** (`&` in a post-coordinated expression must be sent as `%26`):

```bash
curl -s -H "$H1" "$B/icd/release/11/2026-01/mms/codeinfo/BA41.Z"
# {"@context":...,"code":"BA41.Z","stemId":"http://id.who.int/icd/release/11/2026-01/mms/1334938734/unspecified"}

curl -s -H "$H1" "$B/icd/release/11/2026-01/mms/codeinfo/1B12.2%26XA0G74"
# "code":"1B12.2&XA0G74","stemCode":"1B12.2","specificAnatomy":["XA0G74"]
```

**Search** (GET with a query string, or POST with a form body). Titles contain `<em class='found'>` markup:

```bash
curl -s -H "$H1" -H "$H2" "$B/icd/release/11/2026-01/mms/search?q=diabetes&flatResults=true"
# {"destinationEntities":[{"id":".../mms/1697306310","title":"<em class='found'>Diabetes</em> mellitus, type unspecified", ...

curl -s -H "$H1" -H "$H2" -X POST -d 'q=diabetes&flatResults=true' "$B/icd/release/11/2026-01/mms/search"
```

Autocoding (`.../mms/autocode?searchText=acute%20myocardial%20infarction`) and entities (`.../mms/883140666`) follow the same pattern.

**DORIS and CoDEdit** take a WHO death-certificate JSON object as the POST body. `tests/fixtures/doris_help_examples.json` in the git repository (not in the crate) holds six certificates with the results observed from this engine. Take the `adult` one for DORIS:

```bash
jq -c '.examples[] | select(.id=="adult") | .certificate' tests/fixtures/doris_help_examples.json > adult.json

curl -s -H "$H1" -H "$H2" -H 'Content-Type: application/json' \
  --data @adult.json "$B/icd/release/11/2026-01/doris"
# {"stemCode":"BA41.Z","code":"BA41.Z",...,"report":"SP3: BA52.Z is the first condition ...","reject":false,"error":null,"warning":null}
```

The underlying cause is in `code`; `report` gives the rule steps. The `child` certificate (no sex recorded) triggers a CoDEdit finding:

```bash
jq -c '.examples[] | select(.id=="child") | .certificate' tests/fixtures/doris_help_examples.json > child.json

curl -s -H "$H1" -H "$H2" -H 'Content-Type: application/json' \
  --data @child.json "$B/icd/release/11/2026-01/codedit"
# {"report":...,"tabularReport":...,"issueIds":"BER-CE-2"}
```

An empty `issueIds` (as for `adult`) means CoDEdit found no issue. Certificate shape, abridged from the fixture: `ICDVersion`, `AdministrativeData` (`Sex`, `EstimatedAge` as an ISO 8601 duration such as `P62Y`), `Part1` (a list of lines, each with `Conditions` carrying `Text`, `Code`, `LinearizationURI`, `Interval`) and optional `Part2`.

## Library use from Rust

```toml
who-icd11-api = { git = "https://github.com/drguptavivek/who-icd11-api" }
```

```rust
use who_icd11_api::{Icd11Engine, Icd11RuntimeConfig, SearchOptions};

let cfg = Icd11RuntimeConfig {
    bundle_dir: "runtime/icdapi".into(),
    data_dir: "runtime/data".into(),
    bind_url: "http://127.0.0.1:0".into(), // port 0: any free port; the engine is also an HTTP server
    default_release: "2026-01".into(),
};
let engine = Icd11Engine::init_global(cfg)?;          // once per process
let info = engine.codeinfo("BA41.Z", None)?;          // Option<Value>; None if unknown
let hits = engine.search("diabetes", &SearchOptions { flat_results: true, ..Default::default() }, None)?;
let doris = engine.doris(&certificate, None)?;        // DorisEngineOutput { code, reject, report, warning, .. }
let codedit = engine.codedit(&certificate, None)?;    // CodEditEngineOutput { issue_ids, report, .. }
```

Also available: `autocode`, `entity`, `raw_request`, and `process_certificate(&payload, None, "<engine id>")`. The last takes `{schema_version: 1, client_revision, certificate}`, checks every code and URI against `codeinfo`, runs both engines and returns the results with `certificate_digest` and `result_digest`. `Icd11Engine::global()` finds the bundle through the environment variables above, then paths under the crate's source directory, and otherwise **downloads WHO's files there**. Use `init_global` with an explicit config in applications. The .NET runtime is process-wide: one engine per process.

## Non-PII guard

`src/privacy.rs` (`assert_no_pii_in_json`, `assert_no_pii_in_text`) keeps personal identifiers out of the engine. The library entry points (`codeinfo`, `search`, `autocode`, `entity`, `raw_request`, `doris`, `codedit`, `process_certificate`) call it before anything reaches WHO's code. It rejects:

- JSON object keys (case-insensitive) such as `name`, `deceased_name`, `informant_name`, `phone`, `mobile`, `address`, `aadhaar`, `abha`, `national_id`, `identifiers`, `registration_number`, `crs_number`, `mccd_number`, `certificate_number` (full list in `FORBIDDEN_PII_KEYS`), at any depth;
- any string containing a 12-digit run, optionally split in groups of four (Aadhaar-like), or a 10-digit number starting 6-9, optionally with `+91` (Indian mobile). WHO ICD-11 URIs are exempt.

The patterns come from the Indian deployment this was written for. They are not a general PII detector and will not catch other countries' identifiers, and a 10- or 12-digit number in free text can be a false positive. **The HTTP server does not apply the guard**: the examples above go straight to WHO's code.

## Pinned versions

| Artifact | Source | SHA-256 |
| --- | --- | --- |
| OCI image index `whoicd/icd-api:2.6.0` | Docker Hub | `1b77eb6dc43e0c65a12e9e9340ad178493c93488e728d0d936507cc57ada1b7c` |
| OCI `linux/amd64` manifest | Docker Hub | `a63a4c1c73329ff2ebff616a0cde2089b6b0595dec25255844f57f5b1903a4b8` |
| `/usr/share/icdapi` layer | Docker Hub | `d4527f82f3377c545daf8ff6de89dff08d1467970ed1343b96c8a1a515860663` |
| `icd11_2026-01-17_release-icf-mms_en.pbf.gz` | `icdcdn.who.int` | `2fd67533b4c838723bd68b833a98ee6dab284339a6262f3f972251e97c331901` |
| `ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip` | `icdcdn.who.int` | `f7c1b463075b64bb49987a9fac66c2f072a2684e9654d0ddbcc2b408ef9e9952` |
| `DORIS_v2.1_1.2.0.zip` | `icd11files.blob.core.windows.net` | `c4876903346d7bdd1ab6c83cfa1aa8690340174089703ecdce382cfa5a3a59ae` |
| `DigitvaIcd11Bridge.dll` (embedded, ours) | this repository | `1783241ff66b061c4a15eeae66a07d29f4391848b6dce844859f807a3d850953` |

The 79 assembly digests, the extracted index and the seven DORIS rule files are pinned in `src/bootstrap.rs`. The assemblies are WHO's portable AnyCPU builds from the `linux/amd64` image, so the same download serves every platform.

## Supported platforms

| Platform | Status |
| --- | --- |
| macOS arm64 | Built, bootstrapped, full test suite and every example above run by the author. |
| Linux x86_64 | CI is set up to run the full suite and the release builds an archive; not run by the author. |
| Linux arm64, macOS x86_64 | The release builds archives; the engine has not been run on them. |
| Linux, older distributions | Linux archives are built on Ubuntu 24.04 and need glibc 2.39 or newer (not Ubuntu 22.04 or Debian 12); build from source there. |
| Windows | **Not supported.** `src/hostfxr.rs` converts paths to UTF-8 `char*` and passes them to `hostfxr_initialize_for_dotnet_command_line`, which takes `wchar_t*` (UTF-16) on Windows, and the bridge reads UTF-8. A port is not attempted, so no Windows archive is published. |

## Development

```bash
cargo test -- --skip test_live_in_process --skip test_sha256_pinned   # offline
who-icd11-server --bootstrap --output-dir runtime                    # then, with the two env vars set:
cargo test                                                           # full suite incl. six WHO reference certificates
```

Plain `cargo test` on a machine without a bundle starts a download into `runtime/`. CI (`.github/workflows/ci.yml`) runs both modes; `release.yml` builds archives for a `v*` tag and opens a **draft** GitHub release, after checking that no archive contains a `.dll`, `.pbf`, DORIS archive or `Rules.json`.

## Licence and attribution

Code: MIT, Copyright (c) 2026 Vivek Gupta ([LICENSE](LICENSE)). ICD-11 content is licensed by WHO under CC BY-ND 3.0 IGO and keeps WHO's attribution. ICD-API, DORIS and CoDEdit are WHO's. This project is not endorsed by WHO. See [NOTICE](NOTICE).
