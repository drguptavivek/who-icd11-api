//! Pure-Rust, zero-Docker bootstrapper for the WHO ICD-11 2.6.0 & DORIS 1.2.0 portable DLL
//! bundle and offline data archives, with pinned OCI digests and SHA-256 verification.
//!
//! Pulls the `usr/share/icdapi` layer directly from the Docker Hub OCI Registry over HTTPS
//! (`flate2` + `tar`), verifies the OCI layer SHA-256 and extracted DLL SHA-256 checksums,
//! strips Linux-specific `runtimepack.*` binaries to leave only the 78 AnyCPU portable CIL
//! assemblies, and downloads & SHA-256 verifies the 3 official WHO CDN archives (`2026-01_en`
//! `.pbf.gz`, `.pbf.zip`, and `DORIS_v2.1_1.2.0.zip`).

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tar::Archive;
use zip::ZipArchive;

use crate::Icd11Error;

const EMBEDDED_BRIDGE_DLL: &[u8] = include_bytes!("../bridge/DigitvaIcd11Bridge.dll");

/// Pinned Docker image reference matching `docker-compose.yml` (`whoicd/icd-api:2.6.0`).
pub const WHO_ICD11_IMAGE_REF: &str =
    "whoicd/icd-api:2.6.0@sha256:1b77eb6dc43e0c65a12e9e9340ad178493c93488e728d0d936507cc57ada1b7c";
pub const WHO_ICD11_IMAGE_INDEX_SHA256: &str =
    "1b77eb6dc43e0c65a12e9e9340ad178493c93488e728d0d936507cc57ada1b7c";
pub const WHO_ICD11_LINUX_AMD64_MANIFEST_SHA256: &str =
    "a63a4c1c73329ff2ebff616a0cde2089b6b0595dec25255844f57f5b1903a4b8";
pub const OCI_ICDAPI_LAYER_SHA256: &str =
    "d4527f82f3377c545daf8ff6de89dff08d1467970ed1343b96c8a1a515860663";

pub const OCI_TOKEN_URL: &str =
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:whoicd/icd-api:pull";
pub const OCI_ICDAPI_LAYER_BLOB_URL: &str = "https://registry-1.docker.io/v2/whoicd/icd-api/blobs/sha256:d4527f82f3377c545daf8ff6de89dff08d1467970ed1343b96c8a1a515860663";

pub const WHO_CDN_PBF_GZ_URL: &str =
    "https://icdcdn.who.int/customversions/icd11_2026-01-17_release-icf-mms_en.pbf.gz";
pub const WHO_CDN_PBF_GZ_SHA256: &str =
    "2fd67533b4c838723bd68b833a98ee6dab284339a6262f3f972251e97c331901";

pub const WHO_CDN_INDEX_ZIP_URL: &str =
    "https://icdcdn.who.int/released-index-files/ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip";
pub const WHO_CDN_INDEX_ZIP_SHA256: &str =
    "f7c1b463075b64bb49987a9fac66c2f072a2684e9654d0ddbcc2b408ef9e9952";
pub const WHO_CDN_INDEX_PBF_SHA256: &str =
    "cb64df32bb077a126ad339bab0fe61018cc857616293c7f3bcf974dcaaacbdaa";

pub const WHO_CDN_DORIS_ZIP_URL: &str =
    "https://icd11files.blob.core.windows.net/doris/DORIS_v2.1_1.2.0.zip";
pub const WHO_CDN_DORIS_ZIP_SHA256: &str =
    "c4876903346d7bdd1ab6c83cfa1aa8690340174089703ecdce382cfa5a3a59ae";
pub const WHO_CDN_DORIS_RULES_JSON_SHA256: &str =
    "6fc6c900c911dd582a6401e9aafeebe12892600126c915b9fc6ae5746ff1d6fa";

/// Pinned SHA-256 digests of all 79 AnyCPU portable `.dll` assemblies in `icdapi/`
/// (78 official WHO ICD-11 2.6.0 & DORIS 1.2.0 assemblies + `DigitvaIcd11Bridge.dll`).
pub const PINNED_DLL_SHA256: &[(&str, &str)] = &[
    ("AnalyticsCore.dll", "91307d522f6e64c7af6c4ba5431797047d73d53c68c99096e530e38d0279b10d"),
    ("Antlr4.Runtime.Standard.dll", "20ebdc23930b87c2a1c64c0571aefcc9a504e2dedf34f7ff704e399fd8206eb5"),
    ("Azure.Core.dll", "b74cdb738903bb6abe8269105c0ae4e71269f10dd7367b1fd562f573d0ebcfaf"),
    ("Azure.Data.Tables.dll", "a3405357a00c84e8538d79f5d84e4f70efc5ac64db396550437154d4bba6bda5"),
    ("Azure.Storage.Blobs.dll", "99dc7b31fabc16604e17f32f762f29e059035b94f4e81772e8d306f87214c7b5"),
    ("Azure.Storage.Common.dll", "de7aa743ea04d02fb9375ab09ad3b07f8015c61c092f9c1fb7ed6fcd67a247f7"),
    ("CSharpFastPFOR.dll", "607ea5d6e199910f6ae89919a9efe9ef78f402b420ce3b3a789ba4e1517d1829"),
    ("CsvHelper.dll", "a21dfde4cab01ce76ff3b8209742f67295840d96461587b70955179f34a8f2b6"),
    ("DiffMatchPatch.dll", "42c5a6fb1d7a0e1816926ec92c739f4ab126183d6d6d77ca7ac54a752530e238"),
    ("DigitvaIcd11Bridge.dll", "1783241ff66b061c4a15eeae66a07d29f4391848b6dce844859f807a3d850953"),
    ("DorisRuleEngine.dll", "c3c17cf191e3b2c0190aaef77f933d7bd81f0cdede0636d086737497437104fb"),
    ("Expressions.dll", "82c7fb07038f3745dc398a83446e9e64bcc0148b4d6871c6dadc52cf5bc342ac"),
    ("Fhir.Metrics.dll", "e8be84de1db60ed9cfe0287fec3ad2691d0034cdc96801c6d91b21e5915093a2"),
    ("Hl7.Fhir.Base.dll", "1eaf9f92bff26cfa5e2268545ce9a2817b6a9251f92be8b4ff046da67b18a187"),
    ("Hl7.Fhir.Conformance.dll", "d656459eea37cb68a3f69f90811379d3d03a90a97db55b3a9000f5e2d3ca19d2"),
    ("Hl7.Fhir.R5.dll", "0918d8a42daf1dccad5dddd0d073b1842bac5d76c2760552acd9a65768e4404d"),
    ("ICD-API.dll", "0ab8e927fd4201526c1eac3792c8608fbf873d00c2c87c0d5065a97abb56011b"),
    ("ICDTextAnalyzers.dll", "c7280137ae5674067b8bafcaea4fba24c825436ce2ec9e656782cb8171ee3d1a"),
    ("ICU4N.dll", "ebeed749cc12cf2dc1214dd642899b30059098270b8deb3d876ed4e5ece29541"),
    ("ICU4N.resources.dll", "47f83cbb504f188d124e91bf54af167c0a50a2c80eb4051b30e6064fea3d2cbb"),
    ("IdentityModel.AspNetCore.OAuth2Introspection.dll", "a06cd963c8306f74b66383253fe56f67836be699c86709ee03efaa0334f1d4c8"),
    ("IdentityModel.dll", "35e45c681f0f3e524885571c282a706ad05814d6deba779caf5eae612ee3de14"),
    ("IdentityServer4.AccessTokenValidation.dll", "a58a2eb31f1051837144b5237de6ea6132a5c77340ada278d8ca996287564c79"),
    ("J2N.dll", "3418db8abfff0be10f8cd81cf70b606cb7bf6949b45a96606deef753e4971625"),
    ("JiebaNet.Analyser.dll", "a1aae380cef557a0e6796bc3d13afffe053646b7546bca9ece69d7656e45bd61"),
    ("JiebaNet.Segmenter.dll", "576fcd4e93bee948c22889b27e00a4ffd6bb81d5cca43f7ac4bb190fff657123"),
    ("Lucene.Net.Analysis.Common.dll", "0e5d888c369690bc0a1057e5cb5d77a19f3ce83bb23f542dc1115b036f4b6c49"),
    ("Lucene.Net.Analysis.Kuromoji.dll", "303eff2513abf55e27d2b8a029f847211a873b30bb8ccde8409f1d8e4b9c618c"),
    ("Lucene.Net.Analysis.Morfologik.dll", "9811fbefc17a3ea4f423ad54f976b543370299f26a32ecc7124fb6acc2da966b"),
    ("Lucene.Net.Analysis.Stempel.dll", "f32d6e3dd7ba0b7b2daf7928ccc62be2894007b18d557b4c9cd15e88d738e14d"),
    ("Lucene.Net.Highlighter.dll", "094f53223962a1c688d3157e8132b3f39489887a32a7a7c0ae17c3d8bd29c83b"),
    ("Lucene.Net.ICU.dll", "7b799f9b68ef5dba5675a5728e59d25c277964b31d990051b46ef410ac7da27f"),
    ("Lucene.Net.Memory.dll", "067cc24640635ecf0e2a6020607a3d6101a42be76c68affb2132006a784b37d1"),
    ("Lucene.Net.Queries.dll", "cfb23012bed03fa9dab1984905eaeaa087836c781c67e1025ee1f6c70fa3afb4"),
    ("Lucene.Net.dll", "d2764212383e5f115015af46dff4df3f5fb6046a389223fd94d2dbe27f089ebb"),
    ("Microsoft.AspNetCore.Authentication.JwtBearer.dll", "898ffc6174d79544d120771f569c671a15bc8178f7973bc9e1c5039be5fe5a43"),
    ("Microsoft.Bcl.AsyncInterfaces.dll", "5705d245072d3eb78400547b32147dbb6e2c8b02ba8bda76729798f5efdeaecb"),
    ("Microsoft.Extensions.DependencyModel.dll", "0d7fae30684654fa9173ad248ab41b713a48d81df0ef446ee4e40c8d380893e8"),
    ("Microsoft.Extensions.Hosting.Systemd.dll", "e9b5b7ec8043ab5237ed932c35c2fefb3ff06c18ca2e3f15b6ed58fba0905567"),
    ("Microsoft.Extensions.Hosting.WindowsServices.dll", "b03358adf951f8474c3d150e9344b1504ac0137cd1d578ad87b339e65b4bb289"),
    ("Microsoft.IdentityModel.Abstractions.dll", "c3b97d1b1c42faa95bb92eabb7511ca61e89075388f122197040fcfdfb492013"),
    ("Microsoft.IdentityModel.JsonWebTokens.dll", "e85d3d751b4254771f59ff8a14444ef701ba65efb84e312281d675c44536da71"),
    ("Microsoft.IdentityModel.Logging.dll", "32ebeeb2163db6aa0a81659ff0b590894d78350c50c459196b6cc33c98ba21f3"),
    ("Microsoft.IdentityModel.Protocols.OpenIdConnect.dll", "d1f7dbbb71cbf69f5242a74e43b632610ff5dca913f164d1dcf53b2f6e0046ac"),
    ("Microsoft.IdentityModel.Protocols.dll", "7c8702a7f6c019d962faf4b8af2da751dc32af9b6be998688e774394fb5f8730"),
    ("Microsoft.IdentityModel.Tokens.dll", "b2dacc5120971efceb60f6febfe9685fe5a509ddb803c45956a63fc36e67631b"),
    ("Microsoft.OpenApi.dll", "aa0968baccfff6fe3b3069a22071a795da6090da587effccef58407a148d7356"),
    ("Microsoft.Win32.SystemEvents.dll", "d27ecc9df37937ae9b703692f0997573727ab44ff8989b91c0adbf32894a5e5b"),
    ("MiniExcel.dll", "e1b6665f443391dbcf18d139278ec4961b23c1d7ed525eaac7bd5bfc2103c1d0"),
    ("Morfologik.Fsa.dll", "a430d0d9a27939e4398008cc1595292e489d8d82ef51bb0f41fb5c6741712a49"),
    ("Morfologik.Polish.dll", "e923f7a9d479c3cc2bd8f061637eae6af1b41043ff15371cfc1056beef81ae12"),
    ("Morfologik.Stemming.dll", "764fbfdc37ebb9e9dcb2d1f0759840011a0c1e75fb122cac64d8195e011ef15c"),
    ("NCalc.dll", "6461a009bc3233b30fc8954f6f367ce2b103e53a64429ad527dc8be277c4f778"),
    ("Newtonsoft.Json.dll", "22c649f75fce5be7c7ccda8880473b634ef69ecf33f5d1ab8ad892caf47d5a07"),
    ("OCT.dll", "0c761cdd87d8f4a3494d9775a18c69cab4ff8cd112481b19882ccc9f88df3ab9"),
    ("Serilog.AspNetCore.dll", "a550c57df7a04edbed00da036fc14be12acd0d425b7401855975fb628e3dbada"),
    ("Serilog.Extensions.Hosting.dll", "3e6d0284179ee0e1c197568fd79b58f869d15298fff8ecb8447322fe87d44f47"),
    ("Serilog.Extensions.Logging.dll", "80d3edbe3e3ac0b4c5bc764474220e7da11df8d285e0098f3dc1b65a734c8507"),
    ("Serilog.Formatting.Compact.dll", "319fbcefc2161dd50ccdd8d60b30edee48a09f794aedb28421a23f35ddd670d9"),
    ("Serilog.Settings.Configuration.dll", "ec8cfd1f8970a44e2aa3f7bcc71116ca2691b196564bff83e3e3ead0c1143b67"),
    ("Serilog.Sinks.Console.dll", "dc88002ddd9f5fd0ffec9a6568ef89954671f60f2c9161593ee78932538c1e3e"),
    ("Serilog.Sinks.Debug.dll", "df543d3df8bd00d72e5eb2b9b2a15e67a6e4d10c13834de4cedbf500b8793e01"),
    ("Serilog.Sinks.File.dll", "4f4282671c2ac68284b4dc99f7a76eac9cbd4e659978cef642cff9e6c01b676d"),
    ("Serilog.dll", "9fbf7441a9bdc9459652dc66e18f008040651f14cb8d7a7bb806ac4a8b722d10"),
    ("Swashbuckle.AspNetCore.Swagger.dll", "23ce5113396f3516f389ccbc6eeb89d976df21cb9d79c31cc99d2c5003952206"),
    ("Swashbuckle.AspNetCore.SwaggerGen.dll", "1cbec95c664c096d5c1c5ed1e6ad1fd54f6fbaf4ffb147ab9727861826a16efc"),
    ("Swashbuckle.AspNetCore.SwaggerUI.dll", "d4f15e91cece13cfe5518f969cbb08619997ba87e998776bb67edfac7059ed0e"),
    ("System.ClientModel.dll", "db26ba55aa35083a9ff53f0ae44401e65d514c2c9837fd46f629e3292cfff77c"),
    ("System.Configuration.ConfigurationManager.dll", "df795025f207b4940ec9a48deddaedab3333b031b15303fda4f148b09c456d6d"),
    ("System.Drawing.Common.dll", "9033ce87d2307cbc102b23e4096e61e504dce0eb4e56ff045bd779c6e7d0c094"),
    ("System.IO.Hashing.dll", "64702bf2241b954882ce87396189e2b55642f7880209c7ac89f50359e429d30d"),
    ("System.IdentityModel.Tokens.Jwt.dll", "83218e29958e265b4eebce62cda6d69d41e7bf1898b7fa21ed52102675f6dfe3"),
    ("System.Memory.Data.dll", "8817d16a629710c78b3757f220b74878283c56fe7d9a866ece0eaef0be0a2bf1"),
    ("System.Private.ServiceModel.dll", "1d32d193f9a16e5025f69a45392da811bf5e9bb4406b9df3d0edb4aa16d2cc8d"),
    ("System.Security.Cryptography.ProtectedData.dll", "b761c998813562ba9edeb4ac492d9e9bd79a2ebd88078684181694a62627015f"),
    ("System.ServiceModel.Primitives.dll", "6bf7e009f104a70d01545e9ad8189a4a66f69a06c5d89dfe24bc1f04d0b8624a"),
    ("System.ServiceModel.dll", "8bfdd56d33e98aa5fe9726cd41c589b6e8e8c67a072e9682139872068ed29133"),
    ("System.ServiceProcess.ServiceController.dll", "3cbdea50bc270353ef535e097323953d0cbbc34bcf38294611a4ac8c8a6c2db0"),
    ("protobuf-net.dll", "2073cfbd2736181bec88cd409628dd1425fe54c3d2559b0ffc92ce7a752d5e8b"),
];

/// `ICD-API.dll` as shipped in the pinned `linux/amd64` layer (`OCI_ICDAPI_LAYER_SHA256`), which
/// is what `extract_portable_icdapi_from_oci` installs. WHO compiles it per architecture
/// (ReadyToRun), so it differs from the `linux/arm64` image's copy pinned in `PINNED_DLL_SHA256`;
/// both are unmodified WHO 2.6.0 builds and either is accepted (digitva-ke83.12).
pub const OCI_LINUX_AMD64_ICD_API_DLL_SHA256: &str =
    "8a901c52c9f396bb8cfb1d39f0ce070734a897a7e67f3f1467ba53fb872279a7";

/// Pinned SHA-256 digests of all 7 immutable DORIS `v2.1_1.2.0` rule & mapping files inside
/// `data/DORIS_v2.1_1.2.0/` (`log.txt` is excluded because `DorisRuleEngine.dll` writes to it at runtime).
pub const PINNED_DORIS_FILES_SHA256: &[(&str, &str)] = &[
    ("AddCodes.json", "180375a08bb600b3e321bcc302de759cd486ad8e775b0f9723307d964d9828f5"),
    ("AgeRelated.csv", "8c7c433cdedcbd47f0e67b85d42f4bb7dfab1bdbb1959e910642a05f98f67201"),
    ("MainSteps.json", "f2c4b054a7a6f25b5c223d94705a9f3adaf04783b439eaf727ac3a0a9f516cc4"),
    ("OtherConditionMappings.json", "a9d6dbacdfb12f8f2f9e2ed520d6f2a06851c4c23dea7a3a6297d9dcf356839f"),
    ("Rules.json", "6fc6c900c911dd582a6401e9aafeebe12892600126c915b9fc6ae5746ff1d6fa"),
    ("ValueSets.json", "ce76256b57d99383da7d77133c6ab52488c6ca2453a71f214280b829751ced75"),
    ("info.json", "edbe18d54167ea0d3ff3763336c538eb39487defa16e3054015b92e0905c3a31"),
];

/// Ensure that `target_root` contains a ready-to-run `icdapi/` portable DLL bundle
/// (with `DigitvaIcd11Bridge.dll`) and `data/` offline `2026-01_en` + `DORIS_v2.1_1.2.0` directory,
/// verified against all pinned SHA-256 digests. Uses zero Docker runtime.
pub fn ensure_runtime_bundle(target_root: &Path) -> Result<(PathBuf, PathBuf), Icd11Error> {
    let dst_icdapi = target_root.join("icdapi");
    let dst_data = target_root.join("data");

    if !dst_icdapi.join("ICD-API.dll").exists() {
        extract_portable_icdapi_from_oci(&dst_icdapi)?;
    }
    if !dst_icdapi.join("DigitvaIcd11Bridge.dll").exists() {
        install_embedded_bridge_dll(&dst_icdapi)?;
    }
    if !dst_data.join("DORIS_v2.1_1.2.0").join("Rules.json").exists()
        || !dst_data
            .join("icd11_2026-01-17_release-icf-mms_en.pbf.gz")
            .exists()
    {
        download_who_offline_data(&dst_data)?;
    }

    verify_bundle_integrity(&dst_icdapi, &dst_data)?;
    Ok((dst_icdapi, dst_data))
}

/// Cryptographically verify the SHA-256 digests of all 79 `.dll` assemblies and all
/// WHO offline `2026-01_en` / `DORIS_v2.1_1.2.0` files in `dst_icdapi` and `dst_data`.
pub fn verify_bundle_integrity(dst_icdapi: &Path, dst_data: &Path) -> Result<(), Icd11Error> {
    for (dll_name, expected_sha256) in PINNED_DLL_SHA256 {
        let path = dst_icdapi.join(dll_name);
        if *dll_name == "ICD-API.dll"
            && verify_file_sha256(&path, OCI_LINUX_AMD64_ICD_API_DLL_SHA256).is_ok()
        {
            continue;
        }
        verify_file_sha256(&path, expected_sha256)?;
    }
    verify_file_sha256(
        &dst_data.join("icd11_2026-01-17_release-icf-mms_en.pbf.gz"),
        WHO_CDN_PBF_GZ_SHA256,
    )?;
    verify_file_sha256(
        &dst_data.join("ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf"),
        WHO_CDN_INDEX_PBF_SHA256,
    )?;
    let doris_dir = dst_data.join("DORIS_v2.1_1.2.0");
    for (fname, expected_sha256) in PINNED_DORIS_FILES_SHA256 {
        verify_file_sha256(&doris_dir.join(fname), expected_sha256)?;
    }
    Ok(())
}

/// Compute and verify the SHA-256 hex digest of `path` against `expected_sha256`.
pub fn verify_file_sha256(path: &Path, expected_sha256: &str) -> Result<(), Icd11Error> {
    let mut f = File::open(path).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Cannot open {} for SHA-256 check: {e}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            Icd11Error::BundleNotFound(format!("Read error hashing {}: {e}", path.display()))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(Icd11Error::BundleNotFound(format!(
            "SHA-256 mismatch for {}: expected {expected_sha256}, got {actual}",
            path.display()
        )));
    }
    Ok(())
}

/// Verify in pure Rust (`sha2::Sha256`) that the Docker Hub OCI Image Index and `linux/amd64`
/// manifest match `WHO_ICD11_IMAGE_INDEX_SHA256`, `WHO_ICD11_LINUX_AMD64_MANIFEST_SHA256`,
/// and `OCI_ICDAPI_LAYER_SHA256`.
pub fn verify_oci_manifests(token: &str) -> Result<(), Icd11Error> {
    let index_url = format!(
        "https://registry-1.docker.io/v2/whoicd/icd-api/manifests/sha256:{WHO_ICD11_IMAGE_INDEX_SHA256}"
    );
    let mut index_bytes = Vec::new();
    ureq::get(&index_url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.oci.image.index.v1+json")
        .call()
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI index fetch failed: {e}")))?
        .into_reader()
        .read_to_end(&mut index_bytes)
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI index read failed: {e}")))?;

    let index_sha = format!("{:x}", Sha256::digest(&index_bytes));
    if !index_sha.eq_ignore_ascii_case(WHO_ICD11_IMAGE_INDEX_SHA256) {
        return Err(Icd11Error::BundleNotFound(format!(
            "OCI image index SHA-256 mismatch: expected {WHO_ICD11_IMAGE_INDEX_SHA256}, got {index_sha}"
        )));
    }

    let manifest_url = format!(
        "https://registry-1.docker.io/v2/whoicd/icd-api/manifests/sha256:{WHO_ICD11_LINUX_AMD64_MANIFEST_SHA256}"
    );
    let mut manifest_bytes = Vec::new();
    ureq::get(&manifest_url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.oci.image.manifest.v1+json")
        .call()
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI manifest fetch failed: {e}")))?
        .into_reader()
        .read_to_end(&mut manifest_bytes)
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI manifest read failed: {e}")))?;

    let manifest_sha = format!("{:x}", Sha256::digest(&manifest_bytes));
    if !manifest_sha.eq_ignore_ascii_case(WHO_ICD11_LINUX_AMD64_MANIFEST_SHA256) {
        return Err(Icd11Error::BundleNotFound(format!(
            "OCI linux/amd64 manifest SHA-256 mismatch: expected {WHO_ICD11_LINUX_AMD64_MANIFEST_SHA256}, got {manifest_sha}"
        )));
    }

    let manifest_json: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Icd11Error::BundleNotFound(format!("Invalid OCI manifest JSON: {e}")))?;
    let expected_layer_digest = format!("sha256:{OCI_ICDAPI_LAYER_SHA256}");
    let has_pinned_layer = manifest_json["layers"]
        .as_array()
        .is_some_and(|layers| {
            layers.iter().any(|l| {
                l["digest"]
                    .as_str()
                    .is_some_and(|d| d.eq_ignore_ascii_case(&expected_layer_digest))
            })
        });
    if !has_pinned_layer {
        return Err(Icd11Error::BundleNotFound(format!(
            "OCI manifest does not contain pinned layer {expected_layer_digest}"
        )));
    }
    Ok(())
}

/// Stream the `/usr/share/icdapi` layer directly from the Docker Hub OCI Registry in pure Rust
/// (no Docker daemon or CLI), verify the compressed layer blob SHA-256 against
/// `OCI_ICDAPI_LAYER_SHA256`, strip all `runtimepack.*` Linux native binaries, and write the
/// portable AnyCPU `ICD-API.deps.json` and `ICD-API.runtimeconfig.json`.
pub fn extract_portable_icdapi_from_oci(dst_icdapi: &Path) -> Result<(), Icd11Error> {
    fs::create_dir_all(dst_icdapi).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed to create {}: {e}", dst_icdapi.display()))
    })?;

    let tok_resp: Value = ureq::get(OCI_TOKEN_URL)
        .call()
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI token request failed: {e}")))?
        .into_json()
        .map_err(|e| Icd11Error::BundleNotFound(format!("Invalid OCI token JSON: {e}")))?;

    let token = tok_resp["token"]
        .as_str()
        .ok_or_else(|| Icd11Error::BundleNotFound("Missing token in OCI auth response".into()))?;

    verify_oci_manifests(token)?;

    let layer_tmp = dst_icdapi.join(".icdapi_layer.tar.gz.part");
    let blob_resp = ureq::get(OCI_ICDAPI_LAYER_BLOB_URL)
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI layer blob download failed: {e}")))?;

    {
        let mut reader = blob_resp.into_reader();
        let mut out = File::create(&layer_tmp).map_err(|e| {
            Icd11Error::BundleNotFound(format!("Create {} failed: {e}", layer_tmp.display()))
        })?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).map_err(|e| {
                Icd11Error::BundleNotFound(format!("OCI layer download read failed: {e}"))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(|e| {
                Icd11Error::BundleNotFound(format!("OCI layer write failed: {e}"))
            })?;
        }
        let actual_sha = format!("{:x}", hasher.finalize());
        if !actual_sha.eq_ignore_ascii_case(OCI_ICDAPI_LAYER_SHA256) {
            let _ = fs::remove_file(&layer_tmp);
            return Err(Icd11Error::BundleNotFound(format!(
                "OCI layer blob SHA-256 mismatch: expected {OCI_ICDAPI_LAYER_SHA256}, got {actual_sha}"
            )));
        }
    }

    let layer_file = File::open(&layer_tmp).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Open {} failed: {e}", layer_tmp.display()))
    })?;
    let gz = GzDecoder::new(layer_file);
    let mut archive = Archive::new(gz);
    let prefix = Path::new("usr/share/icdapi");

    for entry_res in archive
        .entries()
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI tar read error: {e}")))?
    {
        let mut entry =
            entry_res.map_err(|e| Icd11Error::BundleNotFound(format!("OCI tar entry error: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| Icd11Error::BundleNotFound(format!("OCI tar path error: {e}")))?
            .into_owned();
        let Ok(rel) = path.strip_prefix(prefix) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out_path = dst_icdapi.join(rel);
        if let Some(parent) = out_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        entry.unpack(&out_path).map_err(|e| {
            Icd11Error::BundleNotFound(format!("Failed unpacking {}: {e}", out_path.display()))
        })?;
    }
    let _ = fs::remove_file(&layer_tmp);

    let _ = fs::write(
        dst_icdapi.join("containerId"),
        "who_icd11_rust_standalone\n",
    );
    clean_portable_deps_and_runtimeconfig(dst_icdapi)?;
    Ok(())
}

/// Strip `runtimepack.*` Linux-specific files from `dst_icdapi` using `ICD-API.deps.json`
/// and write a framework-dependent `net10.0` `ICD-API.runtimeconfig.json`.
pub fn clean_portable_deps_and_runtimeconfig(dst_icdapi: &Path) -> Result<(), Icd11Error> {
    let deps_path = dst_icdapi.join("ICD-API.deps.json");
    let deps_str = fs::read_to_string(&deps_path).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed reading {}: {e}", deps_path.display()))
    })?;
    let mut deps: Value = serde_json::from_str(&deps_str)
        .map_err(|e| Icd11Error::BundleNotFound(format!("Malformed ICD-API.deps.json: {e}")))?;

    let targets = deps["targets"]
        .as_object()
        .ok_or_else(|| Icd11Error::BundleNotFound("Missing targets in ICD-API.deps.json".into()))?;
    let (_, raw_target_val) = targets
        .iter()
        .find(|(_, v)| v.as_object().is_some_and(|m| !m.is_empty()))
        .ok_or_else(|| Icd11Error::BundleNotFound("No non-empty target in deps.json".into()))?;

    let raw_target = raw_target_val.as_object().unwrap();
    let mut clean_target = Map::new();
    let mut app_dlls = HashSet::new();
    let mut runtimepack_files = HashSet::new();

    for (pkg, info) in raw_target {
        let Some(info_obj) = info.as_object() else {
            continue;
        };
        if pkg.starts_with("runtimepack.") {
            for section in ["runtime", "native"] {
                if let Some(sec_obj) = info_obj.get(section).and_then(Value::as_object) {
                    for rpath in sec_obj.keys() {
                        if let Some(fname) = rpath.rsplit('/').next() {
                            runtimepack_files.insert(fname.to_string());
                        }
                    }
                }
            }
            continue;
        }
        let mut new_info = info_obj.clone();
        if let Some(rt_obj) = new_info.get("runtime").and_then(Value::as_object) {
            let mut new_rt = Map::new();
            for (rpath, rmeta) in rt_obj {
                let fname = rpath.rsplit('/').next().unwrap_or(rpath).to_string();
                app_dlls.insert(fname.clone());
                new_rt.insert(fname, rmeta.clone());
            }
            new_info.insert("runtime".to_string(), Value::Object(new_rt));
        }
        new_info.shift_remove("native");
        clean_target.insert(pkg.clone(), Value::Object(new_info));
    }

    // Remove Linux runtimepack files and native .so/.a binaries from dst_icdapi
    for fname in &runtimepack_files {
        if !app_dlls.contains(fname) {
            let _ = fs::remove_file(dst_icdapi.join(fname));
        }
    }
    if let Ok(entries) = fs::read_dir(dst_icdapi) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name.ends_with(".so") || name.ends_with(".a") || name == "ICD-API")
                && p.is_file()
            {
                let _ = fs::remove_file(p);
            }
        }
    }

    clean_target.insert(
        "DigitvaIcd11Bridge/1.0.0".to_string(),
        json!({
            "dependencies": {"ICD-API": "2.6.0"},
            "runtime": {"DigitvaIcd11Bridge.dll": {}}
        }),
    );

    let mut new_targets = Map::new();
    new_targets.insert(
        ".NETCoreApp,Version=v10.0".to_string(),
        Value::Object(clean_target),
    );
    deps["runtimeTarget"] = json!({"name": ".NETCoreApp,Version=v10.0", "signature": ""});
    deps["targets"] = Value::Object(new_targets);

    if let Some(libs) = deps.get_mut("libraries").and_then(Value::as_object_mut) {
        libs.retain(|k, _| !k.starts_with("runtimepack."));
        libs.insert(
            "DigitvaIcd11Bridge/1.0.0".to_string(),
            json!({
                "type": "project",
                "serviceable": false,
                "sha512": ""
            }),
        );
    }

    fs::write(&deps_path, serde_json::to_string_pretty(&deps).unwrap()).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed writing {}: {e}", deps_path.display()))
    })?;

    let rt_config = json!({
        "runtimeOptions": {
            "tfm": "net10.0",
            "rollForward": "LatestMinor",
            "frameworks": [
                {"name": "Microsoft.NETCore.App", "version": "10.0.0"},
                {"name": "Microsoft.AspNetCore.App", "version": "10.0.0"}
            ],
            "configProperties": {
                "System.GC.Server": true,
                "System.Reflection.Metadata.MetadataUpdater.IsSupported": false,
                "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization": false,
                "System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault": true
            }
        }
    });
    fs::write(
        dst_icdapi.join("ICD-API.runtimeconfig.json"),
        serde_json::to_string_pretty(&rt_config).unwrap(),
    )
    .map_err(|e| Icd11Error::BundleNotFound(format!("Failed writing runtimeconfig.json: {e}")))?;

    Ok(())
}

/// Download the 3 official WHO ICD-11 `2026-01_en` and `DORIS_v2.1_1.2.0` offline data archives
/// directly from WHO's public CDNs in pure Rust and verify their SHA-256 checksums.
pub fn download_who_offline_data(dst_data: &Path) -> Result<(), Icd11Error> {
    fs::create_dir_all(dst_data).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed creating {}: {e}", dst_data.display()))
    })?;

    let pbf_gz_path = dst_data.join("icd11_2026-01-17_release-icf-mms_en.pbf.gz");
    if !pbf_gz_path.exists() {
        download_url_to_file(WHO_CDN_PBF_GZ_URL, &pbf_gz_path, WHO_CDN_PBF_GZ_SHA256)?;
    }

    let ix_zip_path = dst_data.join("ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip");
    if !ix_zip_path.exists() {
        download_url_to_file(WHO_CDN_INDEX_ZIP_URL, &ix_zip_path, WHO_CDN_INDEX_ZIP_SHA256)?;
    }
    let ix_pbf_path = dst_data.join("ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf");
    if !ix_pbf_path.exists() {
        unzip_file(&ix_zip_path, dst_data)?;
        verify_file_sha256(&ix_pbf_path, WHO_CDN_INDEX_PBF_SHA256)?;
    }

    let doris_dir = dst_data.join("DORIS_v2.1_1.2.0");
    fs::create_dir_all(&doris_dir).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed creating {}: {e}", doris_dir.display()))
    })?;
    let doris_zip_path = doris_dir.join("DORIS_v2.1_1.2.0.zip");
    if !doris_zip_path.exists() {
        download_url_to_file(WHO_CDN_DORIS_ZIP_URL, &doris_zip_path, WHO_CDN_DORIS_ZIP_SHA256)?;
    }
    let rules_json_path = doris_dir.join("Rules.json");
    if !rules_json_path.exists() {
        unzip_file(&doris_zip_path, &doris_dir)?;
        verify_file_sha256(&rules_json_path, WHO_CDN_DORIS_RULES_JSON_SHA256)?;
    }

    Ok(())
}

/// Write the embedded pre-compiled AnyCPU `DigitvaIcd11Bridge.dll` (13 KB) into `dst_icdapi`.
/// No `.NET SDK` or `dotnet build` is required at build or runtime.
pub fn install_embedded_bridge_dll(dst_icdapi: &Path) -> Result<(), Icd11Error> {
    fs::create_dir_all(dst_icdapi).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed creating {}: {e}", dst_icdapi.display()))
    })?;
    let bridge_path = dst_icdapi.join("DigitvaIcd11Bridge.dll");
    fs::write(&bridge_path, EMBEDDED_BRIDGE_DLL).map_err(|e| {
        Icd11Error::DotnetHostError(format!("Failed writing DigitvaIcd11Bridge.dll: {e}"))
    })?;
    verify_file_sha256(
        &bridge_path,
        "1783241ff66b061c4a15eeae66a07d29f4391848b6dce844859f807a3d850953",
    )?;
    Ok(())
}

fn download_url_to_file(
    url: &str,
    dest: &Path,
    expected_sha256: &str,
) -> Result<(), Icd11Error> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| Icd11Error::BundleNotFound(format!("GET {url} failed: {e}")))?;
    let tmp_path = dest.with_extension("part");
    {
        let mut out = File::create(&tmp_path).map_err(|e| {
            Icd11Error::BundleNotFound(format!("Create {} failed: {e}", tmp_path.display()))
        })?;
        let mut reader = resp.into_reader();
        io::copy(&mut reader, &mut out).map_err(|e| {
            Icd11Error::BundleNotFound(format!("Download {url} failed: {e}"))
        })?;
    }
    if let Err(e) = verify_file_sha256(&tmp_path, expected_sha256) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    fs::rename(&tmp_path, dest).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Rename {} failed: {e}", dest.display()))
    })?;
    Ok(())
}

fn unzip_file(zip_path: &Path, out_dir: &Path) -> Result<(), Icd11Error> {
    let file = File::open(zip_path).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Open {} failed: {e}", zip_path.display()))
    })?;
    let mut archive = ZipArchive::new(file).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Invalid zip {}: {e}", zip_path.display()))
    })?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| Icd11Error::BundleNotFound(format!("Zip entry error: {e}")))?;
        let Some(rel) = entry.enclosed_name() else {
            continue;
        };
        let dest = out_dir.join(rel);
        if entry.is_dir() {
            let _ = fs::create_dir_all(&dest);
        } else {
            if let Some(p) = dest.parent() {
                let _ = fs::create_dir_all(p);
            }
            let mut out = File::create(&dest).map_err(|e| {
                Icd11Error::BundleNotFound(format!("Create {} failed: {e}", dest.display()))
            })?;
            io::copy(&mut entry, &mut out).map_err(|e| {
                Icd11Error::BundleNotFound(format!("Extract {} failed: {e}", dest.display()))
            })?;
        }
    }
    Ok(())
}
