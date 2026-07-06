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

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use anyhow::{anyhow, Result};
use melda::adapter::Adapter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::sync::{Arc, RwLock};

pub struct EncryptionAdapter<A: Adapter> {
    inner: A,
    key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct EncryptedBlob {
    alg: String,
    nonce: Vec<u8>,
    data: Vec<u8>,
}

impl<A: Adapter> EncryptionAdapter<A> {
    pub fn new(inner: A, key: [u8; 32]) -> Self {
        Self { inner, key }
    }

    fn derive_nonce(plaintext: &[u8]) -> [u8; 12] {
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let hash = hasher.finalize();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash[..12]);
        nonce
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let nonce = Self::derive_nonce(plaintext);

        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow!("encryption failed"))?;

        let blob = EncryptedBlob {
            alg: "aes-256-gcm".into(),
            nonce: nonce.to_vec(),
            data: ciphertext,
        };

        Ok(serde_json::to_vec(&blob)?)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let blob: EncryptedBlob =
            serde_json::from_slice(data).map_err(|_| anyhow!("invalid encrypted blob"))?;

        if blob.alg != "aes-256-gcm" {
            return Err(anyhow!("unsupported algorithm: {}", blob.alg));
        }

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));

        let plaintext = cipher
            .decrypt(GenericArray::from_slice(&blob.nonce), blob.data.as_ref())
            .map_err(|_| anyhow!("decryption failed"))?;

        Ok(plaintext)
    }
}

impl<A: Adapter + 'static> Adapter for EncryptionAdapter<A> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
        let enc = self.encrypt(data)?;
        self.inner.write_object(key, &enc)
    }

    fn read_object(&self, key: &str, offset: usize, length: usize) -> Result<Vec<u8>> {
        let enc = self.inner.read_object(key, 0, 0)?;

        let dec = self.decrypt(&enc)?;

        if offset == 0 && length == 0 {
            Ok(dec)
        } else {
            if offset + length > dec.len() {
                return Err(anyhow!("invalid slice"));
            }
            Ok(dec[offset..offset + length].to_vec())
        }
    }

    fn list_objects(&self, ext: &str) -> Result<Vec<String>> {
        self.inner.list_objects(ext)
    }
}

impl<A: Adapter + 'static> EncryptionAdapter<A> {
    pub fn into_dyn(self) -> Arc<RwLock<Box<dyn Adapter>>> {
        Arc::new(RwLock::new(Box::new(self)))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use melda::{adapter::Adapter, memoryadapter::MemoryAdapter};

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let base = MemoryAdapter::new();
        let enc = EncryptionAdapter::new(base, key());

        let data = b"hello world";

        enc.write_object("a", data).unwrap();
        let out = enc.read_object("a", 0, 0).unwrap();

        assert_eq!(data.to_vec(), out);
    }

    #[test]
    fn test_deterministic_encryption() {
        let base = MemoryAdapter::new();
        let enc = EncryptionAdapter::new(base, key());

        let data = b"same data";

        enc.write_object("a", data).unwrap();
        enc.write_object("b", data).unwrap();

        let a = enc.inner.read_object("a", 0, 0).unwrap();
        let b = enc.inner.read_object("b", 0, 0).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn test_different_plaintext_produces_different_ciphertext() {
        let base = MemoryAdapter::new();
        let enc = EncryptionAdapter::new(base, key());

        enc.write_object("a", b"foo").unwrap();
        enc.write_object("b", b"bar").unwrap();

        let a = enc.inner.read_object("a", 0, 0).unwrap();
        let b = enc.inner.read_object("b", 0, 0).unwrap();

        assert_ne!(a, b);
    }

    #[test]
    fn test_wrong_key_fails() {
        let base = MemoryAdapter::new();
        let enc = EncryptionAdapter::new(base, key());

        enc.write_object("a", b"secret").unwrap();

        let wrong = EncryptionAdapter::new(enc.inner, [1u8; 32]);

        let res = wrong.read_object("a", 0, 0);

        assert!(res.is_err());
    }

    #[test]
    fn test_slice_read() {
        let base = MemoryAdapter::new();
        let enc = EncryptionAdapter::new(base, key());

        enc.write_object("a", b"abcdef").unwrap();

        let out = enc.read_object("a", 2, 2).unwrap();

        assert_eq!(out, b"cd");
    }

    #[test]
    fn test_list_objects_passthrough() {
        let base = MemoryAdapter::new();
        let enc = EncryptionAdapter::new(base, key());

        enc.write_object("a.test", b"1").unwrap();
        enc.write_object("b.test", b"2").unwrap();

        let list = enc.list_objects("test").unwrap();

        assert_eq!(list.len(), 2);
    }
}
