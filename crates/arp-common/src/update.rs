//! Self-update functionality for ARP binaries from GitHub Releases.
//!
//! Shared by both `arpc` and `arps`. Caller passes their binary name
//! and version; the rest (download, checksum, replace) is identical.

use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};

// ANSI style helpers (only used when stderr/stdout is a TTY)
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";

const DEFAULT_GITHUB_REPO: &str = "offgrid-ing/arp";

/// Ed25519 public key for verifying release signatures.
/// Set to all zeros during development; replace with actual key when signing is enabled.
/// Generate with: RELEASE_SIGNING_KEY=<hex_seed> cargo run -p arp-common --example sign
const RELEASE_SIGNING_PUBKEY: [u8; 32] = [0u8; 32];

/// Returns the GitHub repository slug (e.g. `owner/repo`) for update checks.
///
/// Precedence: runtime env `ARP_GITHUB_REPO` → compile-time env `ARP_GITHUB_REPO`
/// → `Cargo.toml` `repository` field → built-in default.
fn github_repo() -> String {
    // 1. Runtime env var (for operators/packagers)
    if let Ok(repo) = std::env::var("ARP_GITHUB_REPO")
        && !repo.is_empty()
    {
        if is_valid_repo_slug(&repo) {
            return repo;
        }
        eprintln!(
            "warning: ARP_GITHUB_REPO '{}' must be in 'owner/repo' format, ignoring",
            repo
        );
    }
    // 2. Compile-time env var (for forks building from source)
    if let Some(repo) = option_env!("ARP_GITHUB_REPO")
        && !repo.is_empty()
    {
        if is_valid_repo_slug(repo) {
            return repo.to_string();
        }
        // Compile-time value is developer-controlled; still warn at runtime
        eprintln!(
            "warning: compile-time ARP_GITHUB_REPO '{}' must be in 'owner/repo' format, ignoring",
            repo
        );
    }
    // 3. Derive from Cargo.toml repository field
    let pkg_repo = env!("CARGO_PKG_REPOSITORY");
    if let Some(slug) = pkg_repo.strip_prefix("https://github.com/") {
        let slug = slug.trim_end_matches('/');
        if !slug.is_empty() {
            return slug.to_string();
        }
    }
    // 4. Built-in constant
    DEFAULT_GITHUB_REPO.to_string()
}

/// Validates that a string is in `owner/repo` format.
fn is_valid_repo_slug(s: &str) -> bool {
    match s.split_once('/') {
        Some((owner, repo)) => {
            !owner.is_empty()
                && !repo.is_empty()
                && !repo.contains('/')
                && owner
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
                && repo
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        }
        None => false,
    }
}

fn github_api_url() -> String {
    format!(
        "https://api.github.com/repos/{}/releases/latest",
        github_repo()
    )
}

fn github_download_base() -> String {
    format!(
        "https://github.com/{}/releases/latest/download",
        github_repo()
    )
}

/// Returns the platform-specific download name (e.g. `arpc-linux-x86_64`).
fn platform_binary(name: &str) -> Result<String, anyhow::Error> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => anyhow::bail!("unsupported OS: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => anyhow::bail!("unsupported architecture: {other}"),
    };
    Ok(format!("{name}-{os}-{arch}"))
}

/// Builds a reqwest client with User-Agent.
fn http_client(name: &str, version: &str) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(format!("{name}/{version}"))
        .build()
}

/// Fetches the latest release tag from GitHub API.
async fn fetch_latest_tag(client: &reqwest::Client) -> Result<String, anyhow::Error> {
    let resp = client
        .get(github_api_url())
        .send()
        .await?
        .error_for_status()?;

    let body: serde_json::Value = resp.json().await?;
    let tag = body["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing tag_name in GitHub API response"))?
        .to_string();
    Ok(tag)
}

/// Verifies a SHA-256 checksum against expected hex digest.
pub fn verify_checksum(data: &[u8], expected_hex: &str) -> bool {
    let digest = Sha256::digest(data);
    let mut actual = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(actual, "{byte:02x}");
    }
    actual == expected_hex
}

/// Verifies an Ed25519 signature of release data.
///
/// Returns `true` if the signature is valid for the given data and public key.
/// Returns `false` if the public key is invalid, the signature is malformed,
/// or verification fails.
fn verify_release_signature(data: &[u8], signature: &[u8], public_key: &[u8; 32]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key.verify(data, &sig).is_ok()
}

/// Check if an update is available. Prints status and returns.
///
/// # Errors
///
/// Returns an error if the GitHub API request fails.
pub async fn check_for_update(name: &str, version: &str) -> Result<(), anyhow::Error> {
    let client = http_client(name, version)?;
    let current = format!("v{version}");
    let tty = std::io::stdout().is_terminal();

    if tty {
        eprintln!("  {DIM}Checking for updates...{RESET}");
    } else {
        eprintln!("Checking for updates...");
    }

    let latest = fetch_latest_tag(&client).await?;

    if latest == current {
        if tty {
            println!("  {GREEN}\u{2713}{RESET} {name} {BOLD}{current}{RESET} is up to date");
        } else {
            println!("{name} {current} is up to date");
        }
    } else if tty {
        println!(
            "  {CYAN}\u{25cf}{RESET} {name} {DIM}{current}{RESET} \u{2192} {BOLD}{latest}{RESET}"
        );
        println!("    Run {BOLD}{name} update{RESET} to install");
    } else {
        println!("{name} {current} (latest: {latest}) \u{2014} update available");
    }
    Ok(())
}

/// Quietly check if an update is available (for background daemon check).
/// Returns `Ok(Some(latest_tag))` if outdated, `Ok(None)` if up-to-date.
///
/// # Errors
///
/// Returns an error if the GitHub API request fails.
pub async fn check_for_update_quiet(
    name: &str,
    version: &str,
) -> Result<Option<String>, anyhow::Error> {
    let client = http_client(name, version)?;
    let current = format!("v{version}");
    let latest = fetch_latest_tag(&client).await?;
    if latest == current {
        Ok(None)
    } else {
        Ok(Some(latest))
    }
}

/// Self-update: download latest binary, verify checksum, replace current executable.
///
/// # Errors
///
/// Returns an error if the download, checksum verification, or binary replacement fails.
pub async fn perform_update(name: &str, version: &str) -> Result<(), anyhow::Error> {
    let client = http_client(name, version)?;
    let current = format!("v{version}");
    let tty = std::io::stderr().is_terminal();

    if tty {
        eprintln!("  {DIM}Checking for updates...{RESET}");
    } else {
        eprintln!("Checking for updates...");
    }

    let latest = fetch_latest_tag(&client).await?;

    if latest == current {
        if tty {
            println!("  {GREEN}\u{2713}{RESET} {name} {BOLD}{current}{RESET} is up to date");
        } else {
            println!("{name} {current} is up to date");
        }
        return Ok(());
    }

    if tty {
        eprintln!(
            "  {CYAN}\u{25cf}{RESET} {name} {DIM}{current}{RESET} \u{2192} {BOLD}{latest}{RESET}"
        );
    } else {
        println!("{name} {current} \u{2192} {latest}");
    }

    let bin_name = platform_binary(name)?;
    let download_base = github_download_base();
    let download_url = format!("{download_base}/{bin_name}");
    let checksum_url = format!("{download_base}/{bin_name}.sha256");

    // Download checksum first (small)
    if tty {
        eprint!("  {DIM}Downloading checksum...{RESET}");
    } else {
        eprint!("Downloading checksum...");
    }
    let checksum_resp = client.get(&checksum_url).send().await?.error_for_status()?;
    let checksum_text = checksum_resp.text().await?;
    let expected_hash = checksum_text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty checksum file"))?
        .to_lowercase();
    eprintln!(" ok");

    // Download binary
    if tty {
        eprint!("  {DIM}Downloading {bin_name}...{RESET}");
    } else {
        eprint!("Downloading {bin_name}...");
    }
    let bin_resp = client.get(&download_url).send().await?.error_for_status()?;
    let bin_data = bin_resp.bytes().await?;
    eprintln!(" {} bytes", bin_data.len());

    // Verify checksum
    if tty {
        eprint!("  {DIM}Verifying checksum...{RESET}");
    } else {
        eprint!("Verifying checksum...");
    }
    if !verify_checksum(&bin_data, &expected_hash) {
        if tty {
            eprintln!();
            eprintln!("  {RED}\u{2717}{RESET} Checksum verification failed! Aborting update.");
        }
        anyhow::bail!("checksum verification failed! Aborting update.");
    }
    eprintln!(" ok");

    // Verify release signature (if signing is configured)
    let signing_configured = RELEASE_SIGNING_PUBKEY != [0u8; 32];
    if signing_configured {
        let sig_url = format!("{download_base}/{bin_name}.sig");
        if tty {
            eprint!("  {DIM}Verifying signature...{RESET}");
        } else {
            eprint!("Verifying signature...");
        }
        match client.get(&sig_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let sig_data = resp.bytes().await?;
                if !verify_release_signature(&bin_data, &sig_data, &RELEASE_SIGNING_PUBKEY) {
                    if tty {
                        eprintln!();
                        eprintln!(
                            "  {RED}\u{2717}{RESET} Signature verification failed! Aborting update."
                        );
                    }
                    anyhow::bail!("release signature verification failed! Aborting update.");
                }
                eprintln!(" ok");
            }
            Ok(resp) => {
                // .sig file not found (404) — warn but proceed during transition
                eprintln!();
                if tty {
                    eprintln!(
                        "  {DIM}\u{26a0} No signature file found (HTTP {}), proceeding without verification{RESET}",
                        resp.status()
                    );
                } else {
                    eprintln!(
                        "Warning: no signature file found (HTTP {}), proceeding without verification",
                        resp.status()
                    );
                }
            }
            Err(e) => {
                // Network error fetching .sig — warn but proceed
                eprintln!();
                if tty {
                    eprintln!(
                        "  {DIM}\u{26a0} Could not fetch signature: {e}, proceeding without verification{RESET}"
                    );
                } else {
                    eprintln!(
                        "Warning: could not fetch signature: {e}, proceeding without verification"
                    );
                }
            }
        }
    }

    // Write to temp file next to the current binary, then rename
    let current_exe = std::env::current_exe()?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine parent directory of current binary"))?;
    let tmp_path = parent.join(format!(
        ".{name}-update-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));

    {
        let mut tmp_file = std::fs::File::create(&tmp_path)?;
        tmp_file.write_all(&bin_data)?;
        tmp_file.flush()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }

    std::fs::rename(&tmp_path, &current_exe)?;

    if tty {
        println!("  {GREEN}\u{2713}{RESET} Updated {name} to {BOLD}{latest}{RESET}");
    } else {
        println!("Updated {name} to {latest}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_binary_arpc() {
        let name =
            platform_binary("arpc").expect("platform_binary should succeed on supported platforms");
        assert!(
            name.starts_with("arpc-"),
            "should start with 'arpc-': {name}"
        );
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "should have 3 parts: {name}");
    }

    #[test]
    fn platform_binary_arps() {
        let name =
            platform_binary("arps").expect("platform_binary should succeed on supported platforms");
        assert!(
            name.starts_with("arps-"),
            "should start with 'arps-': {name}"
        );
    }

    #[test]
    fn verify_checksum_valid() {
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_checksum(data, expected));
    }

    #[test]
    fn verify_checksum_invalid() {
        let data = b"hello world";
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_checksum(data, wrong));
    }

    #[test]
    fn http_client_builds() {
        let client = http_client("arpc", "0.0.0");
        assert!(client.is_ok(), "http_client should build successfully");
    }

    #[test]
    fn verify_release_signature_valid() {
        use ed25519_dalek::{Signer, SigningKey};
        let seed = [42u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let data = b"test binary data";
        let sig = key.sign(data);
        let pubkey = key.verifying_key().to_bytes();
        assert!(verify_release_signature(data, &sig.to_bytes(), &pubkey));
    }

    #[test]
    fn verify_release_signature_wrong_data() {
        use ed25519_dalek::{Signer, SigningKey};
        let seed = [42u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let sig = key.sign(b"correct data");
        let pubkey = key.verifying_key().to_bytes();
        assert!(!verify_release_signature(
            b"wrong data",
            &sig.to_bytes(),
            &pubkey
        ));
    }

    #[test]
    fn verify_release_signature_invalid_sig() {
        let pubkey = [1u8; 32];
        assert!(!verify_release_signature(b"data", &[0u8; 64], &pubkey));
    }

    #[test]
    fn verify_release_signature_zero_pubkey() {
        assert!(!verify_release_signature(b"data", &[0u8; 64], &[0u8; 32]));
    }

    #[test]
    fn verify_release_signature_short_sig() {
        let pubkey = [1u8; 32];
        assert!(!verify_release_signature(b"data", &[0u8; 10], &pubkey));
    }
}
