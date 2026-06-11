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

use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
        }
    }
}

impl<A: Adapter> Adapter for SecureAdapter<A> {
    fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
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
            Err(_) => return Ok(data),
        };

        let sig_file: SignatureFile = serde_json::from_slice(&sig_bytes)?;

        let pk = STANDARD.decode(sig_file.pubkey)?;
        let sg = STANDARD.decode(sig_file.sig)?;

        let pubkey = VerifyingKey::from_bytes(pk[..32].try_into()?)?;
        let sig = Signature::from_bytes(sg[..64].try_into()?);

        if pubkey.verify(&data, &sig).is_err() {
            return Ok(Vec::new());
        }

        let ids = extract_object_ids(&data);

        for id in ids {
            if !self.policy.allows(&self.keystore, &pubkey.to_bytes(), &id) {
                return Ok(Vec::new());
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
    use ed25519_dalek::SigningKey;
    use melda::{melda::Melda, memoryadapter::MemoryAdapter};
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::{Arc, RwLock};

    fn gen_keys() -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        (
            sk.to_bytes().to_vec(),
            sk.verifying_key().to_bytes().to_vec(),
        )
    }

    #[test]
    fn test_policy_blocks_change() {
        let (privk, pubk) = gen_keys();

        let mut ks = KeyStore::new();
        ks.set_private_key(&privk).unwrap();
        ks.add_public_key(&pubk).unwrap();

        let policy = PolicyEngine::from_yaml(
            r#"
rules:
  - deny:
      objects: "*"
"#,
        )
        .unwrap();

        let base = MemoryAdapter::new();
        let secure = SecureAdapter::new(base, ks, policy);

        let adapter: Box<dyn Adapter> = Box::new(secure);
        let adapter = Arc::new(RwLock::new(adapter));

        let melda = Melda::new(adapter).unwrap();

        let obj = json!({"x":1}).as_object().unwrap().clone();
        let _ = melda.create_object("blocked", obj);

        melda.commit(None).unwrap();
        let _ = melda.reload();

        // ✅ oggetto NON creato
        assert!(!melda.get_all_objects().contains("blocked"));
    }

    #[test]
    fn test_policy_allows_change() {
        let (privk, pubk) = gen_keys();

        let mut ks = KeyStore::new();
        ks.set_private_key(&privk).unwrap();
        ks.add_public_key(&pubk).unwrap();

        let policy = PolicyEngine::from_yaml(
            r#"
rules:
  - allow:
      objects: "*"
"#,
        )
        .unwrap();

        let base = MemoryAdapter::new();
        let secure = SecureAdapter::new(base, ks, policy);

        let adapter: Box<dyn Adapter> = Box::new(secure);
        let adapter = Arc::new(RwLock::new(adapter));

        let melda = Melda::new(adapter).unwrap();

        let obj = json!({"x":1}).as_object().unwrap().clone();
        let _ = melda.create_object("ok", obj);

        let _ = melda.commit(None).unwrap();
        let _ = melda.reload();

        assert!(melda.get_all_objects().contains("ok"));
    }
}
