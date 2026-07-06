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
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct KeyStore {
    pub endorsement_key: Option<SigningKey>,
    trusted_keys: HashSet<VerifyingKey>,
    roles: HashMap<Vec<u8>, String>,
}

// ******************************************
// Serialization types
// ******************************************
#[derive(Serialize, Deserialize)]
struct KeyEntry {
    pubkey: String,
    role: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct KeyStoreConfig {
    keys: Vec<KeyEntry>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            endorsement_key: None,
            trusted_keys: HashSet::new(),
            roles: HashMap::new(),
        }
    }

    pub fn set_endorsement_credentials(
        &mut self,
        private_key: &[u8],
        public_key: Option<&[u8]>,
    ) -> Result<()> {
        if private_key.len() != 32 {
            return Err(anyhow!("invalid endorsement private key"));
        }
        let sk = SigningKey::from_bytes(private_key.try_into()?);
        if let Some(pubkey) = public_key {
            if pubkey.len() != 32 {
                return Err(anyhow!("invalid endorsement public key"));
            }
            let vk = sk.verifying_key();
            let expected: [u8; 32] = pubkey.try_into()?;
            if vk.to_bytes() != expected {
                return Err(anyhow!("endorsement public key does not match private key"));
            }
            self.add_trusted_public_key(pubkey).unwrap(); // trust the endorsement public key
        }
        self.endorsement_key = Some(sk);
        Ok(())
    }

    pub fn set_endorsement_credentials_with_role(
        &mut self,
        private_key: &[u8],
        public_key: &[u8],
        role: &str,
    ) -> Result<()> {
        self.set_endorsement_credentials(private_key, Some(public_key))?;
        self.add_trusted_public_key_with_role(public_key, role)
    }

    pub fn add_trusted_public_key(&mut self, bytes: &[u8]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(bytes.try_into()?)?;
        self.trusted_keys.insert(vk);
        Ok(())
    }

    pub fn add_trusted_public_key_with_role(&mut self, bytes: &[u8], role: &str) -> Result<()> {
        let vk = VerifyingKey::from_bytes(bytes.try_into()?)?;
        let b = vk.to_bytes().to_vec();
        self.trusted_keys.insert(vk);
        self.roles.insert(b, role.to_string());
        Ok(())
    }

    pub fn is_trusted(&self, vk: &VerifyingKey) -> bool {
        self.trusted_keys.contains(vk)
    }

    pub fn is_trusted_public_key(&self, bytes: &[u8]) -> bool {
        if let Ok(vk) = VerifyingKey::from_bytes(bytes.try_into().unwrap()) {
            self.is_trusted(&vk)
        } else {
            false
        }
    }

    pub fn get_role(&self, pubkey: &[u8]) -> Option<&str> {
        self.roles.get(pubkey).map(|s| s.as_str())
    }

    pub fn get_trusted_public_keys(&self) -> Vec<Vec<u8>> {
        self.trusted_keys
            .iter()
            .map(|k| k.to_bytes().to_vec())
            .collect()
    }

    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    pub fn endorsement_public_key(&self) -> Option<Vec<u8>> {
        self.endorsement_key
            .as_ref()
            .map(|k| k.verifying_key().to_bytes().to_vec())
    }

    pub fn endorse(&self, data: &[u8]) -> Option<Signature> {
        self.endorsement_key.as_ref().map(|k| k.sign(data))
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Option<VerifyingKey> {
        for k in &self.trusted_keys {
            if k.verify(data, sig).is_ok() {
                return Some(*k);
            }
        }
        None
    }

    pub fn to_json(&self) -> Result<Value> {
        let mut keys = Vec::new();

        for vk in &self.trusted_keys {
            let key_bytes = vk.to_bytes();

            let role = self.roles.get(key_bytes.as_slice()).cloned();

            keys.push(KeyEntry {
                pubkey: STANDARD.encode(key_bytes),
                role,
            });
        }

        let config = KeyStoreConfig { keys };

        Ok(serde_json::to_value(config)?)
    }

    pub fn from_json(json: Value) -> Result<Self> {
        let config: KeyStoreConfig = serde_json::from_value(json)?;

        let mut ks = KeyStore::new();

        for key in config.keys {
            let pubkey = STANDARD.decode(key.pubkey)?;

            match key.role {
                Some(role) => {
                    ks.add_trusted_public_key_with_role(&pubkey, &role)?;
                }
                None => {
                    ks.add_trusted_public_key(&pubkey)?;
                }
            }
        }
        Ok(ks)
    }
}
