//! Pure-Rust, zero-Docker bootstrapper for the WHO ICD-11 2.6.0 & DORIS 1.2.0 portable DLL
//! bundle and offline data archives.
//!
//! Pulls the `usr/share/icdapi` layer directly from the Docker Hub OCI Registry over HTTPS
//! (`flate2` + `tar`), strips Linux-specific `runtimepack.*` binaries to leave only the 78
//! AnyCPU portable CIL assemblies, downloads the 3 official WHO CDN archives (`2026-01_en`
//! `.pbf.gz`, `.pbf.zip`, and `DORIS_v2.1_1.2.0.zip`), and compiles `DigitvaIcd11Bridge.dll`.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde_json::{Map, Value, json};
use tar::Archive;
use zip::ZipArchive;

use crate::Icd11Error;

const EMBEDDED_BRIDGE_DLL: &[u8] = include_bytes!("../bridge/DigitvaIcd11Bridge.dll");

pub const OCI_TOKEN_URL: &str =
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:whoicd/icd-api:pull";
pub const OCI_ICDAPI_LAYER_BLOB_URL: &str = "https://registry-1.docker.io/v2/whoicd/icd-api/blobs/sha256:d4527f82f3377c545daf8ff6de89dff08d1467970ed1343b96c8a1a515860663";

pub const WHO_CDN_PBF_GZ_URL: &str =
    "https://icdcdn.who.int/customversions/icd11_2026-01-17_release-icf-mms_en.pbf.gz";
pub const WHO_CDN_INDEX_ZIP_URL: &str =
    "https://icdcdn.who.int/released-index-files/ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip";
pub const WHO_CDN_DORIS_ZIP_URL: &str =
    "https://icd11files.blob.core.windows.net/doris/DORIS_v2.1_1.2.0.zip";

/// Ensure that `target_root` contains a ready-to-run `icdapi/` portable DLL bundle
/// (with `DigitvaIcd11Bridge.dll`) and `data/` offline `2026-01_en` + `DORIS_v2.1_1.2.0` directory.
/// Uses zero Docker runtime.
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

    Ok((dst_icdapi, dst_data))
}

/// Stream the `/usr/share/icdapi` layer directly from the Docker Hub OCI Registry in pure Rust
/// (no Docker daemon or CLI), strip all `runtimepack.*` Linux native binaries, and write the
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

    let blob_resp = ureq::get(OCI_ICDAPI_LAYER_BLOB_URL)
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(|e| Icd11Error::BundleNotFound(format!("OCI layer blob download failed: {e}")))?;

    let gz = GzDecoder::new(blob_resp.into_reader());
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
/// directly from WHO's public CDNs in pure Rust.
pub fn download_who_offline_data(dst_data: &Path) -> Result<(), Icd11Error> {
    fs::create_dir_all(dst_data).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed creating {}: {e}", dst_data.display()))
    })?;

    let pbf_gz_path = dst_data.join("icd11_2026-01-17_release-icf-mms_en.pbf.gz");
    if !pbf_gz_path.exists() {
        download_url_to_file(WHO_CDN_PBF_GZ_URL, &pbf_gz_path)?;
    }

    let ix_zip_path = dst_data.join("ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf.zip");
    if !ix_zip_path.exists() {
        download_url_to_file(WHO_CDN_INDEX_ZIP_URL, &ix_zip_path)?;
    }
    if !dst_data
        .join("ix_(2026-01-17)_foundation-icf-mms_en_v5.7.pbf")
        .exists()
    {
        unzip_file(&ix_zip_path, dst_data)?;
    }

    let doris_dir = dst_data.join("DORIS_v2.1_1.2.0");
    fs::create_dir_all(&doris_dir).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed creating {}: {e}", doris_dir.display()))
    })?;
    let doris_zip_path = doris_dir.join("DORIS_v2.1_1.2.0.zip");
    if !doris_zip_path.exists() {
        download_url_to_file(WHO_CDN_DORIS_ZIP_URL, &doris_zip_path)?;
    }
    if !doris_dir.join("Rules.json").exists() {
        unzip_file(&doris_zip_path, &doris_dir)?;
    }

    Ok(())
}

/// Write the embedded pre-compiled AnyCPU `DigitvaIcd11Bridge.dll` (13 KB) into `dst_icdapi`.
/// No `.NET SDK` or `dotnet build` is required at build or runtime.
pub fn install_embedded_bridge_dll(dst_icdapi: &Path) -> Result<(), Icd11Error> {
    fs::create_dir_all(dst_icdapi).map_err(|e| {
        Icd11Error::BundleNotFound(format!("Failed creating {}: {e}", dst_icdapi.display()))
    })?;
    fs::write(dst_icdapi.join("DigitvaIcd11Bridge.dll"), EMBEDDED_BRIDGE_DLL).map_err(|e| {
        Icd11Error::DotnetHostError(format!("Failed writing DigitvaIcd11Bridge.dll: {e}"))
    })?;
    Ok(())
}

fn download_url_to_file(url: &str, dest: &Path) -> Result<(), Icd11Error> {
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
