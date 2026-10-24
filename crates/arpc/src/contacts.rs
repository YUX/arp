//! Contact management and inbound message filtering.
//!
//! Provides a thread-safe contact store backed by a TOML file. Contacts are
//! identified by Ed25519 public keys (base58-encoded) and can be filtered at
//! the relay layer to silently drop messages from unknown senders.

use arp_common::Pubkey;
use arp_common::base58;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// Controls which inbound messages are delivered to the agent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterMode {
    /// Only deliver messages from known contacts.
    #[default]
    ContactsOnly,
    /// Deliver messages from any sender.
    AcceptAll,
}

/// A single contact entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Display name for the contact.
    pub name: String,
    /// Base58-encoded Ed25519 public key.
    pub pubkey: String,
    /// Free-form notes.
    #[serde(default)]
    pub notes: String,
}

/// Serialization wrapper matching the TOML file format.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ContactsFile {
    #[serde(default)]
    filter_mode: FilterMode,
    #[serde(default)]
    contacts: Vec<Contact>,
}

struct Inner {
    filter_mode: FilterMode,
    by_pubkey: HashMap<Pubkey, Contact>,
    name_to_pubkey: HashMap<String, Pubkey>,
}

/// Thread-safe contact store backed by a TOML file on disk.
///
/// Uses `std::sync::RwLock` internally so the hot-path `should_deliver()`
/// check is a cheap read lock with no async overhead.
pub struct ContactStore {
    inner: RwLock<Inner>,
    path: PathBuf,
}

impl ContactStore {
    /// Load contacts from a TOML file, creating a default file if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        let file_data = if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            toml::from_str::<ContactsFile>(&contents)?
        } else {
            let default = ContactsFile::default();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, toml::to_string_pretty(&default)?)?;
            default
        };

        let mut by_pubkey = HashMap::new();
        let mut name_to_pubkey = HashMap::new();

        for contact in &file_data.contacts {
            if let Ok(pk) = base58::decode_pubkey(&contact.pubkey) {
                by_pubkey.insert(pk, contact.clone());
                name_to_pubkey.insert(contact.name.to_lowercase(), pk);
            }
        }

        Ok(Self {
            inner: RwLock::new(Inner {
                filter_mode: file_data.filter_mode,
                by_pubkey,
                name_to_pubkey,
            }),
            path,
        })
    }

    /// Add a contact. Validates the pubkey, rejects duplicates, and saves to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is empty, the pubkey is invalid, or a
    /// duplicate name/pubkey already exists.
    pub fn add(&self, name: &str, pubkey_b58: &str, notes: &str) -> Result<(), String> {
        if name.is_empty() || name.len() > 32 {
            return Err("contact name must be 1-32 characters".to_string());
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("contact name must contain only letters and digits".to_string());
        }
        if base58::decode_pubkey(name).is_ok() {
            return Err("contact name must not be a public key".to_string());
        }

        let pk = base58::decode_pubkey(pubkey_b58).map_err(|e| format!("invalid pubkey: {e}"))?;

        let mut inner = self.inner.write().map_err(|e| e.to_string())?;

        let lower = name.to_lowercase();
        if inner.name_to_pubkey.contains_key(&lower) {
            return Err(format!("duplicate contact name: {name}"));
        }
        if inner.by_pubkey.contains_key(&pk) {
            return Err(format!("duplicate pubkey: {pubkey_b58}"));
        }

        let contact = Contact {
            name: name.to_string(),
            pubkey: pubkey_b58.to_string(),
            notes: notes.to_string(),
        };

        inner.by_pubkey.insert(pk, contact);
        inner.name_to_pubkey.insert(lower, pk);

        self.save_locked(&inner)
    }

    /// Remove a contact by display name (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns an error if no contact with that name exists.
    pub fn remove_by_name(&self, name: &str) -> Result<Contact, String> {
        let mut inner = self.inner.write().map_err(|e| e.to_string())?;
        let lower = name.to_lowercase();

        let pk = inner
            .name_to_pubkey
            .remove(&lower)
            .ok_or_else(|| format!("no contact named '{name}'"))?;

        let contact = inner
            .by_pubkey
            .remove(&pk)
            .ok_or_else(|| "internal inconsistency".to_string())?;

        self.save_locked(&inner)?;
        Ok(contact)
    }

    /// Remove a contact by base58-encoded pubkey.
    ///
    /// # Errors
    ///
    /// Returns an error if no contact with that pubkey exists.
    pub fn remove_by_pubkey(&self, pubkey_b58: &str) -> Result<Contact, String> {
        let pk = base58::decode_pubkey(pubkey_b58).map_err(|e| format!("invalid pubkey: {e}"))?;

        let mut inner = self.inner.write().map_err(|e| e.to_string())?;

        let contact = inner
            .by_pubkey
            .remove(&pk)
            .ok_or_else(|| format!("no contact with pubkey '{pubkey_b58}'"))?;

        inner.name_to_pubkey.remove(&contact.name.to_lowercase());

        self.save_locked(&inner)?;
        Ok(contact)
    }

    /// List all contacts sorted by name.
    #[must_use]
    pub fn list(&self) -> Vec<Contact> {
        let inner = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("contacts lock poisoned in list(), using recovered data");
                poisoned.into_inner()
            }
        };
        let mut contacts: Vec<Contact> = inner.by_pubkey.values().cloned().collect();
        contacts.sort_by_key(|c| c.name.to_lowercase());
        contacts
    }

    /// Look up a contact by display name (case-insensitive).
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<Contact> {
        let inner = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("contacts lock poisoned in lookup_by_name()");
                poisoned.into_inner()
            }
        };
        let pk = inner.name_to_pubkey.get(&name.to_lowercase())?;
        inner.by_pubkey.get(pk).cloned()
    }

    /// Look up a contact by base58-encoded pubkey.
    #[must_use]
    pub fn lookup_by_pubkey(&self, pubkey_b58: &str) -> Option<Contact> {
        let pk = base58::decode_pubkey(pubkey_b58).ok()?;
        let inner = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("contacts lock poisoned in lookup_by_pubkey()");
                poisoned.into_inner()
            }
        };
        inner.by_pubkey.get(&pk).cloned()
    }

    /// Returns `true` if a message from `from` should be delivered to the agent.
    ///
    /// In `AcceptAll` mode this always returns `true`. In `ContactsOnly` mode
    /// only messages from known contacts are delivered.
    #[must_use]
    pub fn should_deliver(&self, from: &Pubkey) -> bool {
        let inner = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("contacts lock poisoned in should_deliver(), failing closed");
                poisoned.into_inner()
            }
        };
        match inner.filter_mode {
            FilterMode::AcceptAll => true,
            FilterMode::ContactsOnly => inner.by_pubkey.contains_key(from),
        }
    }

    /// Get the current filter mode.
    #[must_use]
    pub fn filter_mode(&self) -> FilterMode {
        let inner = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "contacts lock poisoned in filter_mode(), defaulting to ContactsOnly"
                );
                poisoned.into_inner()
            }
        };
        inner.filter_mode
    }

    /// Set the filter mode and persist to disk.
    pub fn set_filter_mode(&self, mode: FilterMode) {
        let mut inner = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!("contacts lock poisoned in set_filter_mode()");
                poisoned.into_inner()
            }
        };
        inner.filter_mode = mode;
        if let Err(e) = self.save_locked(&inner) {
            tracing::warn!("failed to persist filter_mode change: {}", e);
        }
    }

    /// Serialize the current state and write to disk.
    fn save_locked(&self, inner: &Inner) -> Result<(), String> {
        let mut contacts: Vec<Contact> = inner.by_pubkey.values().cloned().collect();
        contacts.sort_by_key(|c| c.name.to_lowercase());

        let file = ContactsFile {
            filter_mode: inner.filter_mode,
            contacts,
        };

        let contents =
            toml::to_string_pretty(&file).map_err(|e| format!("serialize error: {e}"))?;
        // Atomic save: write to temp file, then rename
        let tmp_path = self.path.with_extension("toml.tmp");
        std::fs::write(&tmp_path, &contents).map_err(|e| format!("write error: {e}"))?;
        std::fs::rename(&tmp_path, &self.path).map_err(|e| format!("rename error: {e}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("arpc_contacts_test");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn valid_pubkey_b58(byte: u8) -> String {
        base58::encode(&[byte; 32])
    }

    #[test]
    fn test_default_filter_mode_is_contacts_only() {
        assert_eq!(FilterMode::default(), FilterMode::ContactsOnly);
    }

    #[test]
    fn test_load_creates_default_file() {
        let path = temp_path("load_creates_default.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        assert!(path.exists());
        assert_eq!(store.filter_mode(), FilterMode::ContactsOnly);
        assert!(store.list().is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_add_and_list_contacts() {
        let path = temp_path("add_and_list.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &valid_pubkey_b58(0x01), "").unwrap();
        store
            .add("Alice", &valid_pubkey_b58(0x02), "research agent")
            .unwrap();

        let list = store.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "Alice");
        assert_eq!(list[1].name, "Bob");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_add_rejects_duplicate_name() {
        let path = temp_path("dup_name.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &valid_pubkey_b58(0x01), "").unwrap();

        let err = store.add("bob", &valid_pubkey_b58(0x02), "").unwrap_err();
        assert!(err.contains("duplicate contact name"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_add_rejects_duplicate_pubkey() {
        let path = temp_path("dup_pubkey.toml");
        let _ = fs::remove_file(&path);

        let pk = valid_pubkey_b58(0x01);
        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &pk, "").unwrap();

        let err = store.add("Alice", &pk, "").unwrap_err();
        assert!(err.contains("duplicate pubkey"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_add_rejects_invalid_pubkey() {
        let path = temp_path("invalid_pk.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        let err = store.add("Bob", "not-a-valid-key", "").unwrap_err();
        assert!(err.contains("invalid pubkey"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_add_rejects_empty_name() {
        let path = temp_path("empty_name.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        let err = store.add("", &valid_pubkey_b58(0x01), "").unwrap_err();
        assert!(err.contains("1-32 characters"), "unexpected error: {err}");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_remove_by_name() {
        let path = temp_path("remove_name.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &valid_pubkey_b58(0x01), "").unwrap();

        let removed = store.remove_by_name("Bob").unwrap();
        assert_eq!(removed.name, "Bob");
        assert!(store.list().is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_remove_by_pubkey() {
        let path = temp_path("remove_pk.toml");
        let _ = fs::remove_file(&path);

        let pk = valid_pubkey_b58(0x01);
        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &pk, "").unwrap();

        let removed = store.remove_by_pubkey(&pk).unwrap();
        assert_eq!(removed.name, "Bob");
        assert!(store.list().is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_remove_nonexistent_returns_error() {
        let path = temp_path("remove_none.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        let err = store.remove_by_name("Ghost").unwrap_err();
        assert!(err.contains("no contact named"));

        let err = store.remove_by_pubkey(&valid_pubkey_b58(0xFF)).unwrap_err();
        assert!(err.contains("no contact with pubkey"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_lookup_by_name_case_insensitive() {
        let path = temp_path("lookup_name.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &valid_pubkey_b58(0x01), "notes").unwrap();

        assert!(store.lookup_by_name("bob").is_some());
        assert!(store.lookup_by_name("BOB").is_some());
        assert!(store.lookup_by_name("Bob").is_some());
        assert!(store.lookup_by_name("charlie").is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_lookup_by_pubkey() {
        let path = temp_path("lookup_pk.toml");
        let _ = fs::remove_file(&path);

        let pk = valid_pubkey_b58(0x01);
        let store = ContactStore::load(path.clone()).unwrap();
        store.add("Bob", &pk, "").unwrap();

        assert!(store.lookup_by_pubkey(&pk).is_some());
        assert!(store.lookup_by_pubkey(&valid_pubkey_b58(0xFF)).is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_should_deliver_contacts_only_mode() {
        let path = temp_path("deliver_contacts.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        assert_eq!(store.filter_mode(), FilterMode::ContactsOnly);

        let known_pk = [0x01u8; 32];
        store.add("Known", &base58::encode(&known_pk), "").unwrap();

        let unknown_pk = [0x02u8; 32];
        assert!(store.should_deliver(&known_pk));
        assert!(!store.should_deliver(&unknown_pk));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_should_deliver_accept_all_mode() {
        let path = temp_path("deliver_all.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        store.set_filter_mode(FilterMode::AcceptAll);

        let unknown_pk = [0x99u8; 32];
        assert!(store.should_deliver(&unknown_pk));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_set_filter_mode_persists() {
        let path = temp_path("filter_persist.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        assert_eq!(store.filter_mode(), FilterMode::ContactsOnly);

        store.set_filter_mode(FilterMode::AcceptAll);
        assert_eq!(store.filter_mode(), FilterMode::AcceptAll);

        let store2 = ContactStore::load(path.clone()).unwrap();
        assert_eq!(store2.filter_mode(), FilterMode::AcceptAll);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_roundtrip_save_and_load() {
        let path = temp_path("roundtrip.toml");
        let _ = fs::remove_file(&path);

        let store = ContactStore::load(path.clone()).unwrap();
        store
            .add("Alice", &valid_pubkey_b58(0x0A), "agent a")
            .unwrap();
        store
            .add("Bob", &valid_pubkey_b58(0x0B), "agent b")
            .unwrap();
        store.set_filter_mode(FilterMode::AcceptAll);

        let store2 = ContactStore::load(path.clone()).unwrap();
        assert_eq!(store2.filter_mode(), FilterMode::AcceptAll);

        let list = store2.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "Alice");
        assert_eq!(list[0].notes, "agent a");
        assert_eq!(list[1].name, "Bob");
        assert_eq!(list[1].notes, "agent b");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_concurrent_add_and_read() {
        let path = temp_path("concurrent_add_read.toml");
        let _ = fs::remove_file(&path);

        let store = Arc::new(ContactStore::load(path.clone()).unwrap());
        let mut handles = vec![];

        for i in 0..20u8 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let name = format!("Agent{i:02}");
                let pk = valid_pubkey_b58(i);
                store.add(&name, &pk, "").unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(store.list().len(), 20);

        let mut read_handles = vec![];
        for i in 0..20u8 {
            let store = Arc::clone(&store);
            read_handles.push(std::thread::spawn(move || {
                let name = format!("Agent{i:02}");
                assert!(store.lookup_by_name(&name).is_some());
                assert!(store.should_deliver(&[i; 32]));
            }));
        }

        for h in read_handles {
            h.join().unwrap();
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_concurrent_add_and_remove() {
        let path = temp_path("concurrent_add_remove.toml");
        let _ = fs::remove_file(&path);

        let store = Arc::new(ContactStore::load(path.clone()).unwrap());

        for i in 0..10u8 {
            store
                .add(&format!("Pre{i}"), &valid_pubkey_b58(i), "")
                .unwrap();
        }

        let mut handles = vec![];

        for i in 10..20u8 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let name = format!("New{i}");
                let pk = valid_pubkey_b58(i);
                store.add(&name, &pk, "").unwrap();
            }));
        }

        for i in 0..10u8 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let name = format!("Pre{i}");
                store.remove_by_name(&name).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let list = store.list();
        assert_eq!(list.len(), 10);
        for c in &list {
            assert!(c.name.starts_with("New"));
        }

        let _ = fs::remove_file(&path);
    }
}
