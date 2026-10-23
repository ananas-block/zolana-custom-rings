use std::path::Path;

use anyhow::{bail, Result};
use custom_ring_cli::release::RingKey;
use serde_json::{json, Value};
use xtask::create_release::{
    self, binary_json, build_rust_binary, pinned_sha256, read_json, release_targets, repo_root,
    require_file, stage_file, stage_program, CliBinary, Options, ProgramSource, ReleaseSet,
    PROVING_KEYS_DIR,
};

const RING_KEYS_LOCK: &str = "prover/ring/proving-keys.lock";

/// Deployed per ring under its own id.
const RING_PROGRAM_SOURCE: ProgramSource = ProgramSource {
    role: "ring_program",
    file: "custom_ring_program.so",
    asset_stem: "custom-ring-program",
};

struct CustomRings;

impl ReleaseSet for CustomRings {
    fn lock_path(&self) -> &'static str {
        "cli/release-artifacts.lock"
    }

    fn title(&self, tag: &str) -> String {
        format!("custom-rings {tag}")
    }

    fn notes(&self, tag: &str) -> String {
        format!("Zolana custom ring artifacts {tag}")
    }

    fn cli_binaries(&self) -> &'static [CliBinary] {
        &[CliBinary {
            package: "custom-ring-cli",
            bin: "zolana-ring",
            asset_stem: "zolana-ring",
        }]
    }

    fn lock(&self, options: &Options, staging: &Path, host: (&str, &str)) -> Result<Value> {
        let path = options.deploy_dir.join(RING_PROGRAM_SOURCE.file);
        require_file(&path, "run `just build-programs` first")?;
        let repo = repo_root()?;
        let zolana = repo.join("zolana");
        let mut lock = json!({
            "release_tag": options.tag,
            "ring_program": stage_program(&RING_PROGRAM_SOURCE, &path, &options.tag, staging)?,
        });
        let ring_lock = read_json(&repo.join(RING_KEYS_LOCK))?;
        for key in RingKey::ALL {
            let key_source = zolana.join(PROVING_KEYS_DIR).join(key.file_name());
            require_file(&key_source, "run `just fetch-custom-ring-keys` first")?;
            let asset = ring_key_asset(key, &options.tag);
            let staged = stage_file(&key_source, &staging.join(&asset))?;
            let pinned = pinned_sha256(&ring_lock, key.file_name())?;
            if staged.sha256 != pinned {
                bail!(
                    "{} hashes to {}, {RING_KEYS_LOCK} pins {pinned}, run `just regen-custom-ring-keys` to rotate both",
                    key.file_name(),
                    staged.sha256
                );
            }
            lock[key.lock_section()] = json!({
                "asset": asset,
                "size": staged.size,
                "sha256": staged.sha256,
            });
        }
        let mut binaries = Vec::new();
        for (os, arch) in release_targets(host) {
            let asset = format!("ring-rpc-{os}-{arch}-{}", options.tag);
            let path = staging.join(&asset);
            build_rust_binary(
                &repo,
                "zolana-ring-rpc",
                "ring-rpc",
                &path,
                (os, arch) == host,
            )?;
            binaries.push(binary_json("ring_rpc", os, arch, &asset, &path)?);
        }
        lock["binaries"] = json!(binaries);
        Ok(lock)
    }
}

/// `custom_ring_policy.key` ships as `custom-ring-policy-key-<tag>.key`.
fn ring_key_asset(key: RingKey, tag: &str) -> String {
    let stem = key.file_name().trim_end_matches(".key").replace('_', "-");
    let stem = stem.trim_end_matches("-key");
    format!("{stem}-key-{tag}.key")
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("create-release") => {
            if let Err(error) =
                create_release::run(Options::parse(args.collect(), &CustomRings), &CustomRings)
            {
                eprintln!("create-release failed: {error:?}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: ring-xtask create-release --tag <tag> [options]");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_key_assets_keep_the_released_names() {
        let assets: Vec<_> = RingKey::ALL
            .into_iter()
            .map(|key| ring_key_asset(key, "v1"))
            .collect();
        assert_eq!(
            assets,
            [
                "custom-ring-policy-key-v1.key",
                "custom-ring-base-key-v1.key",
                "custom-ring-compressed-policy-key-v1.key",
                "custom-ring-delegate-policy-key-v1.key",
                "custom-ring-register-key-v1.key",
                "custom-ring-deposit-key-v1.key",
            ]
        );
    }
}
