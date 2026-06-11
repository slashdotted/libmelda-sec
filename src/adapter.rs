// Melda Sec
// A pluggable security layer for Melda providing signed delta verification,
// role-based access control and policy enforcement on object-level changes
// Copyright (C) 2026 Amos Brocco <contact@amosbrocco.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use anyhow::{anyhow, Result};
use ed25519_dalek::Signature;
use melda::adapter::Adapter;
use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::keystore::KeyStore;
use crate::policy::PolicyEngine;
use crate::utils::{extract_object_ids, sig_key};

pub struct SecureAdapter<A: Adapter> {
    inner: A,
    keystore: KeyStore,
    policy: PolicyEngine,
    strict_read: bool,
    strict_write: bool,
}

#[derive(Serialize, Deserialize)]
struct SignatureFile {
    alg: String,
    pubkey: String,
    sig: String,
}

impl<A: Adapter> SecureAdapter<A> {
    pub fn new(inner: A, keystore: KeyStore, policy: PolicyEngine) -> Self {
        Self {
            inner,
            keystore,
            policy,
            strict_read: true,
            strict_write: false,
        }
    }

    pub fn strict_read(mut self, value: bool) -> Self {
        self.strict_read = value;
        self
    }

    pub fn strict_write(mut self, value: bool) -> Self {
        self.strict_write = value;
        self
    }
}

impl<A: Adapter> Adapter for SecureAdapter<A> {
    fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
        if key.ends_with(".delta") && self.strict_write {
            let ids = extract_object_ids(data);

            let sk = self
                .keystore
                .signing_key
                .as_ref()
                .ok_or_else(|| anyhow!("missing signing key"))?;

            let pubkey = sk.verifying_key().to_bytes();

            for id in ids {
                if !self.policy.allows(&self.keystore, &pubkey, &id) {
                    return Err(anyhow!("write denied by policy: {}", id));
                }
            }
        }

        self.inner.write_object(key, data)?;

        if key.ends_with(".delta") {
            if let Some(sig) = self.keystore.sign(data) {
                let sk = self.keystore.signing_key.as_ref().unwrap();

                let sig_file = SignatureFile {
                    alg: "ed25519".into(),
                    pubkey: STANDARD.encode(sk.verifying_key().to_bytes()),
                    sig: STANDARD.encode(sig.to_bytes()),
                };

                let bytes = serde_json::to_vec(&sig_file)?;
                self.inner.write_object(&sig_key(key), &bytes)?;
            }
        }

        Ok(())
    }

    fn read_object(&self, key: &str, offset: usize, length: usize) -> Result<Vec<u8>> {
        let data = self.inner.read_object(key, offset, length)?;

        if !key.ends_with(".delta") || offset != 0 || length != 0 {
            return Ok(data);
        }

        let sig_bytes = match self.inner.read_object(&sig_key(key), 0, 0) {
            Ok(b) => b,
            Err(_) => {
                return if self.strict_read {
                    Err(anyhow!("missing signature"))
                } else {
                    Ok(data)
                };
            }
        };

        let sig_file: SignatureFile = serde_json::from_slice(&sig_bytes)?;

        let _pk = STANDARD.decode(sig_file.pubkey)?;
        let sg = STANDARD.decode(sig_file.sig)?;

        let sig = Signature::from_bytes(sg[..64].try_into()?);

        let verified = self.keystore.verify(&data, &sig);

        let pubkey = match verified {
            Some(pk) => pk,
            None => {
                return if self.strict_read {
                    Err(anyhow!("invalid signature or untrusted key"))
                } else {
                    Ok(Vec::new())
                };
            }
        };

        let ids = extract_object_ids(&data);

        for id in ids {
            if !self.policy.allows(&self.keystore, &pubkey.to_bytes(), &id) {
                return if self.strict_read {
                    Err(anyhow!("policy violation: {}", id))
                } else {
                    Ok(Vec::new())
                };
            }
        }

        Ok(data)
    }

    fn list_objects(&self, ext: &str) -> Result<Vec<String>> {
        self.inner.list_objects(ext)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use melda::{adapter::Adapter, melda::Melda, memoryadapter::MemoryAdapter};
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::{Arc, RwLock};

    #[derive(Clone)]
    struct SharedMemoryAdapter {
        inner: Arc<RwLock<MemoryAdapter>>,
    }

    impl SharedMemoryAdapter {
        fn new() -> Self {
            Self {
                inner: Arc::new(RwLock::new(MemoryAdapter::new())),
            }
        }
    }

    impl Adapter for SharedMemoryAdapter {
        fn read_object(&self, key: &str, offset: usize, length: usize) -> Result<Vec<u8>> {
            self.inner.read().unwrap().read_object(key, offset, length)
        }

        fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
            self.inner.write().unwrap().write_object(key, data)
        }

        fn list_objects(&self, ext: &str) -> Result<Vec<String>> {
            self.inner.read().unwrap().list_objects(ext)
        }
    }

    fn gen_keys() -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        (
            sk.to_bytes().to_vec(),
            sk.verifying_key().to_bytes().to_vec(),
        )
    }

    #[test]
    fn test_missing_signature_non_strict() {
        let (_privk, pubk) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let ks_write = KeyStore::new();

        let secure_write = SecureAdapter::new(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        )
        .strict_read(false);

        let adapter: Box<dyn Adapter> = Box::new(secure_write);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"a":1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        melda.commit(None).unwrap();

        let mut ks_read = KeyStore::new();
        ks_read.add_public_key(&pubk).unwrap();

        let secure_read = SecureAdapter::new(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        )
        .strict_read(false);

        let adapter: Box<dyn Adapter> = Box::new(secure_read);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let _ = melda.reload();

        assert!(melda.get_all_objects().contains("x"));
    }

    #[test]
    fn test_missing_signature_strict() {
        let (_privk, pubk) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let ks_write = KeyStore::new();

        let secure_write = SecureAdapter::new(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        )
        .strict_read(true);

        let adapter: Box<dyn Adapter> = Box::new(secure_write);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"a":1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        melda.commit(None).unwrap();

        let mut ks_read = KeyStore::new();
        ks_read.add_public_key(&pubk).unwrap();

        let secure_read = SecureAdapter::new(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        )
        .strict_read(true);

        let adapter: Box<dyn Adapter> = Box::new(secure_read);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let _ = melda.reload();

        assert!(!melda.get_all_objects().contains("x"));
    }

    #[test]
    fn test_untrusted_key_filtered() {
        let (_p1, pub1) = gen_keys();
        let (priv2, _pub2) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks_joe = KeyStore::new();
        ks_joe.set_private_key(&priv2).unwrap();

        let secure_joe = SecureAdapter::new(
            shared.clone(),
            ks_joe,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_joe);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"hack":1}).as_object().unwrap().clone();
        let _ = melda.create_object("joe", v);
        melda.commit(None).unwrap();

        let mut ks_read = KeyStore::new();
        ks_read.add_public_key(&pub1).unwrap();

        let secure_read = SecureAdapter::new(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_read);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let _ = melda.reload();

        assert!(!melda.get_all_objects().contains("joe"));
    }

    #[test]
    fn test_strict_write_blocks() {
        let (privk, pubk) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks = KeyStore::new();
        ks.set_private_key(&privk).unwrap();
        ks.add_public_key(&pubk).unwrap();

        let secure = SecureAdapter::new(
            shared,
            ks,
            PolicyEngine::from_yaml(r#"rules: [{ deny: { objects: "*" } }]"#).unwrap(),
        )
        .strict_write(true);

        let adapter: Box<dyn Adapter> = Box::new(secure);
        let adapter = Arc::new(RwLock::new(adapter));

        let melda = Melda::new(adapter).unwrap();

        let v = json!({"x":1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);

        assert!(melda.commit(None).is_err());
    }

    #[test]
    fn test_policy_violation_non_strict() {
        let (privk, pubk) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks = KeyStore::new();
        ks.set_private_key(&privk).unwrap();
        ks.add_public_key(&pubk).unwrap();

        let secure = SecureAdapter::new(
            shared,
            ks,
            PolicyEngine::from_yaml(r#"rules: [{ deny: { objects: "*" } }]"#).unwrap(),
        )
        .strict_read(false);

        let adapter: Box<dyn Adapter> = Box::new(secure);
        let adapter = Arc::new(RwLock::new(adapter));

        let melda = Melda::new(adapter).unwrap();

        let v = json!({"x":1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        melda.commit(None).unwrap();

        let _ = melda.reload();

        assert!(!melda.get_all_objects().contains("x"));
    }
}
