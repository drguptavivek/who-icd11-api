use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use who_icd11_api::{Icd11Engine, Icd11RuntimeConfig, ensure_runtime_bundle};

fn main() -> anyhow::Result<()> {
    let mut bind_url = std::env::var("DIGITVA_ICD11_BIND")
        .unwrap_or_else(|_| "http://127.0.0.1:8382".to_string());
    let mut bootstrap_only = false;
    let mut output_dir: Option<PathBuf> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--bootstrap" => {
                bootstrap_only = true;
                idx += 1;
            }
            "--output-dir" if idx + 1 < args.len() => {
                output_dir = Some(PathBuf::from(&args[idx + 1]));
                idx += 2;
            }
            "--bind" if idx + 1 < args.len() => {
                bind_url = args[idx + 1].clone();
                idx += 2;
            }
            "--port" if idx + 1 < args.len() => {
                bind_url = format!("http://127.0.0.1:{}", args[idx + 1]);
                idx += 2;
            }
            "--help" | "-h" => {
                println!(
                    "who-icd11-server [--bootstrap] [--output-dir ./runtime] [--bind http://127.0.0.1:8382] [--port 8382]\n\
                     Native Rust in-process DLL host and pure-Rust OCI/CDN bootstrapper for WHO ICD-11 2.6.0 + DORIS 1.2.0"
                );
                return Ok(());
            }
            _ => idx += 1,
        }
    }

    if bootstrap_only {
        let target = output_dir
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("runtime"));
        let (icdapi_dir, data_dir) = ensure_runtime_bundle(&target)?;
        println!(
            "Bootstrapped WHO ICD-11 2.6.0 + DORIS 1.2.0 runtime (zero Docker):\n  bundle: {}\n  data:   {}",
            icdapi_dir.display(),
            data_dir.display()
        );
        return Ok(());
    }

    let cfg = Icd11RuntimeConfig::discover_with_bind(&bind_url)?;
    let engine = Icd11Engine::init_global(cfg)?;
    println!(
        "who-icd11-server listening on {} (release {})",
        engine.base_url(),
        engine.default_release()
    );

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
