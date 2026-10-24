use ed25519_dalek::SigningKey;
use rand::rng;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;
#[cfg(unix)]
const KEY_FILE_PERMS: u32 = 0o600;

/// # Errors
///
/// Returns an error if the key file has wrong permissions, wrong length,
/// or if file I/O fails.
pub fn load_or_generate_keypair(path: &Path) -> anyhow::Result<SigningKey> {
    // AUDIT CFG-02: Warn if config directory permissions are too open
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(meta) = fs::metadata(parent)
    {
        let dir_mode = meta.permissions().mode() & 0o777;
        if dir_mode & 0o077 != 0 {
            tracing::warn!(
                "config directory {} has loose permissions ({:o}), recommend 0700",
                parent.display(),
                dir_mode
            );
        }
    }

    if path.exists() {
        #[cfg(unix)]
        {
            let metadata = fs::metadata(path)?;
            let permissions = metadata.permissions().mode();
            if permissions & 0o077 != 0 {
                anyhow::bail!(
                    "key file {} has overly permissive permissions ({:o}), must be 0600",
                    path.display(),
                    permissions & 0o777
                );
            }
        }

        // AUDIT CFG-01: Windows does not enforce key file permissions via Unix mode bits.
        // Users on Windows should manually restrict access to this file via ACLs.
        #[cfg(not(unix))]
        tracing::warn!(
            "key file permission checks are not available on this platform; \
             ensure {} is only readable by the current user",
            path.display()
        );

        let seed = fs::read(path)?;
        if seed.len() != 32 {
            anyhow::bail!("key file must contain exactly 32 bytes, got {}", seed.len());
        }

        let mut seed_array = Zeroizing::new([0u8; 32]);
        seed_array.copy_from_slice(&seed);
        let signing_key = SigningKey::from_bytes(&seed_array);

        let pub_path = path.with_extension("pub");
        if !pub_path.exists() {
            fs::write(&pub_path, signing_key.verifying_key().as_bytes())?;
        }

        Ok(signing_key)
    } else {
        let signing_key = SigningKey::generate(&mut rng());
        let seed = signing_key.to_bytes();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create file with restrictive permissions atomically
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(KEY_FILE_PERMS)
            .open(path)?;
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&seed)?;
        drop(file);

        let pub_path = path.with_extension("pub");
        fs::write(&pub_path, signing_key.verifying_key().as_bytes())?;

        Ok(signing_key)
    }
}

/// Generate a fresh Ed25519 keypair using OS randomness.
pub fn generate_keypair() -> SigningKey {
    SigningKey::generate(&mut rng())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_path() -> std::path::PathBuf {
        let random_suffix: u64 = rand::random();
        std::env::temp_dir().join(format!("arp_test_{random_suffix}"))
    }

    #[test]
    fn test_generate_keypair_returns_valid_signing_key() {
        let key = generate_keypair();
        let verifying_key = key.verifying_key();
        assert_eq!(verifying_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_load_or_generate_keypair_creates_file_when_not_exists() {
        let test_dir = get_test_path();
        let key_path = test_dir.join("test_key");
        let _ = fs::remove_dir_all(&test_dir);
        let key = load_or_generate_keypair(&key_path).unwrap();
        assert!(key_path.exists());
        let verifying_key = key.verifying_key();
        assert_eq!(verifying_key.as_bytes().len(), 32);
        let pub_path = key_path.with_extension("pub");
        assert!(pub_path.exists());
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_load_or_generate_keypair_loads_existing_file() {
        let test_dir = get_test_path();
        let key_path = test_dir.join("test_key");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();
        let seed: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        fs::write(&key_path, seed).unwrap();
        let mut permissions = fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&key_path, permissions).unwrap();
        let key = load_or_generate_keypair(&key_path).unwrap();
        assert_eq!(key.to_bytes(), seed);
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_load_or_generate_keypair_rejects_wrong_permissions() {
        let test_dir = get_test_path();
        let key_path = test_dir.join("test_key");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();
        let seed: [u8; 32] = [1; 32];
        fs::write(&key_path, seed).unwrap();
        let mut permissions = fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&key_path, permissions).unwrap();
        let result = load_or_generate_keypair(&key_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("overly permissive permissions"));
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_load_or_generate_keypair_rejects_wrong_length() {
        let test_dir = get_test_path();
        let key_path = test_dir.join("test_key");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();
        let seed: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        fs::write(&key_path, seed).unwrap();
        let mut permissions = fs::metadata(&key_path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&key_path, permissions).unwrap();
        let result = load_or_generate_keypair(&key_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("must contain exactly 32 bytes"));
        let _ = fs::remove_dir_all(&test_dir);
    }
}
