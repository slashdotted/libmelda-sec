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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;

pub struct KeyStore {
    pub signing_key: Option<SigningKey>,
    trusted_keys: Vec<VerifyingKey>,
    roles: HashMap<Vec<u8>, String>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            signing_key: None,
            trusted_keys: vec![],
            roles: HashMap::new(),
        }
    }

    pub fn set_private_key(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != 32 {
            return Err(anyhow!("invalid private key"));
        }
        let sk = SigningKey::from_bytes(bytes.try_into()?);
        self.signing_key = Some(sk);
        Ok(())
    }

    pub fn add_public_key(&mut self, bytes: &[u8]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(bytes.try_into()?)?;
        self.trusted_keys.push(vk);
        Ok(())
    }

    pub fn add_public_key_with_role(&mut self, bytes: &[u8], role: &str) -> Result<()> {
        let vk = VerifyingKey::from_bytes(bytes.try_into()?)?;
        let b = vk.to_bytes().to_vec();
        self.trusted_keys.push(vk);
        self.roles.insert(b, role.to_string());
        Ok(())
    }

    pub fn get_role(&self, pubkey: &[u8]) -> Option<&str> {
        self.roles.get(pubkey).map(|s| s.as_str())
    }

    pub fn sign(&self, data: &[u8]) -> Option<Signature> {
        self.signing_key.as_ref().map(|k| k.sign(data))
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Option<VerifyingKey> {
        for k in &self.trusted_keys {
            if k.verify(data, sig).is_ok() {
                return Some(*k);
            }
        }
        None
    }
}
