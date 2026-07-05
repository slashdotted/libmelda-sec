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

use crate::keystore::KeyStore;
use crate::policy::PolicyEngine;
use crate::utils::extract_created_and_modified_object_ids;
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use lazy_static::lazy_static;
use melda::adapter::Adapter;
use melda::melda::DeltaId;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::any::Any;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

lazy_static! {
    static ref ENDORSEMENT_KEY: Regex =
        Regex::new(r"(?P<deltaid>[\d+]+-[a-f0-9]+)\.delta\.(?P<pubkey>[a-f0-9]+)(\.sig)?").unwrap();
}

pub struct EndorsementKey(DeltaId, Vec<u8>);

impl EndorsementKey {
    pub fn new(delta_id: DeltaId, pubkey: Vec<u8>) -> Self {
        Self(delta_id, pubkey)
    }

    pub fn file_name(&self) -> String {
        format!("{}.{}.sig", self.0.key(), hex::encode(&self.1))
    }

    pub fn delta_id(&self) -> &DeltaId {
        &self.0
    }

    pub fn pubkey(&self) -> &Vec<u8> {
        &self.1
    }

    pub fn from(s: &str) -> Result<EndorsementKey> {
        match ENDORSEMENT_KEY.captures(s) {
            Some(r) => Ok(EndorsementKey(
                DeltaId::from(r.name("deltaid").unwrap().as_str()).unwrap(),
                hex::decode(r.name("pubkey").unwrap().as_str()).unwrap(),
            )),
            None => bail!("invalid_endorsement_key: {}", s),
        }
    }
}

pub struct TrustAdapter<A: Adapter> {
    inner: A,
    keystore: KeyStore,
    policy: PolicyEngine,
    endorsement_mode: EndorsementMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndorsementMode {
    DISABLED,
    SINGLE,
    MAJORITY,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndorsementRecord {
    pub version: u32,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EndorsementFetchResult {
    pub valid: HashSet<Vec<u8>>,
    pub invalid: HashSet<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct TrustConfiguration {
    endorsement_mode: EndorsementMode,
    keystore: Value,
    policy: Value,
}

impl<A: Adapter + 'static> TrustAdapter<A> {
    pub fn new_single(inner: A, keystore: KeyStore, policy: PolicyEngine) -> Self {
        Self {
            inner,
            keystore,
            policy,
            endorsement_mode: EndorsementMode::SINGLE,
        }
    }

    pub fn new_majority(inner: A, keystore: KeyStore, policy: PolicyEngine) -> Self {
        Self {
            inner,
            keystore,
            policy,
            endorsement_mode: EndorsementMode::MAJORITY,
        }
    }

    pub fn new_disabled(inner: A, keystore: KeyStore, policy: PolicyEngine) -> Self {
        Self {
            inner,
            keystore,
            policy,
            endorsement_mode: EndorsementMode::DISABLED,
        }
    }

    pub fn set_endorsement_mode(&mut self, mode: EndorsementMode) -> &Self {
        self.endorsement_mode = mode;
        self
    }

    pub fn set_keystore(&mut self, keystore: KeyStore) -> &Self {
        self.keystore = keystore;
        self
    }

    pub fn set_policy(&mut self, policy: PolicyEngine) -> &Self {
        self.policy = policy;
        self
    }

    pub fn get_endorsement_mode(&self) -> EndorsementMode {
        self.endorsement_mode.clone()
    }

    pub fn get_keystore(&self) -> &KeyStore {
        &self.keystore
    }

    pub fn get_keystore_mut(&mut self) -> &mut KeyStore {
        &mut self.keystore
    }

    pub fn get_policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn get_policy_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy
    }

    pub fn add_delta_to_whitelist(&mut self, delta_id: &DeltaId) -> Result<bool> {
        self.keystore.add_to_delta_id_whitelist(delta_id)
    }

    pub fn add_delta_to_blacklist(&mut self, delta_id: &DeltaId) -> Result<bool> {
        self.keystore.add_to_delta_id_blacklist(delta_id)
    }

    pub fn read_endorsement_record(&self, key: &EndorsementKey) -> Result<EndorsementRecord> {
        let bytes = self.inner.read_object(&key.file_name(), 0, 0)?;
        let sig_file: EndorsementRecord = serde_json::from_slice(&bytes)?;
        if sig_file.version != 1 || sig_file.algorithm != "Ed25519" {
            return Err(anyhow!("unsupported endorsement format"));
        }
        Ok(sig_file)
    }

    pub fn fetch_endorsements(&self, delta_id: &DeltaId) -> Result<EndorsementFetchResult> {
        let mut result = EndorsementFetchResult {
            valid: HashSet::new(),
            invalid: HashSet::new(),
        };
        if let Ok(sig_files) = self.inner.list_objects(".sig") {
            for sig_file in sig_files {
                if let Ok(endorsement_key) = EndorsementKey::from(&sig_file) {
                    if endorsement_key.delta_id() == delta_id {
                        let endorsement = self.read_endorsement_record(&endorsement_key)?;
                        let sig_bytes = STANDARD.decode(&endorsement.signature)?;
                        let sig_arr: [u8; 64] = sig_bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("invalid signature length"))?;
                        let sig = Signature::from_bytes(&sig_arr);
                        let pk = endorsement_key.pubkey().clone();
                        let pub_key_slice = pk.as_slice().as_array().unwrap();
                        let vk: VerifyingKey = VerifyingKey::from_bytes(pub_key_slice)
                            .map_err(|_| anyhow!("invalid endorsement public key"))?;
                        if self.keystore.is_trusted(&vk)
                            && vk.verify(delta_id.digest().as_bytes(), &sig).is_ok()
                        {
                            result.valid.insert(pk);
                        } else {
                            result.invalid.insert(pk);
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn endorse(&self, delta_id: &DeltaId) -> Result<()> {
        let sk = self
            .keystore
            .endorsement_key
            .as_ref()
            .ok_or_else(|| anyhow!("missing endorsement key"))?;
        let pubkey = sk.verifying_key().to_bytes();
        let endorsement_key = EndorsementKey::new(delta_id.clone(), pubkey.to_vec());

        // Check if a signature file already exists for this delta and public key. If it does, verify the signature.
        if let Ok(endorsement_record) = self.read_endorsement_record(&endorsement_key) {
            let sg = STANDARD.decode(&endorsement_record.signature)?;
            if sg.len() == 64 {
                let arr: [u8; 64] = sg
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("invalid signature length"))?;
                let sig = Signature::from_bytes(&arr);
                let vk = VerifyingKey::from_bytes(&pubkey)
                    .map_err(|_| anyhow!("invalid endorsement public key"))?;
                if vk.verify(delta_id.digest().as_bytes(), &sig).is_ok() {
                    return Ok(());
                }
            }
        }
        // Sign the delta and write the signature file.
        let sig = sk.sign(delta_id.digest().as_bytes());
        let sig_file = EndorsementRecord {
            version: 1,
            algorithm: "Ed25519".into(),
            signature: STANDARD.encode(sig.to_bytes()),
        };

        let bytes = serde_json::to_vec(&sig_file)?;
        self.inner
            .write_object(&endorsement_key.file_name(), &bytes)
    }

    /// Returns true if the given delta ID is valid according to the current
    /// trust configuration (i.e., it is readable, it is either whitelisted orit has sufficient endorsements from trusted public keys and
    /// is not blacklisted). Returns false otherwise.
    pub fn check_delta(&self, delta_id: &DeltaId) -> bool {
        self.read_object(&delta_id.key(), 0, 0).is_ok()
    }

    pub fn to_json(&self) -> Result<Value> {
        let config = TrustConfiguration {
            endorsement_mode: self.endorsement_mode.clone(),
            keystore: self.keystore.to_json()?,
            policy: self.policy.to_json()?,
        };
        Ok(serde_json::to_value(&config)?)
    }

    pub fn from_json(inner: A, json: Value) -> Result<Self> {
        let config: TrustConfiguration = serde_json::from_value(json)?;
        Ok(Self {
            inner,
            keystore: KeyStore::from_json(config.keystore)?,
            policy: PolicyEngine::from_json(config.policy)?,
            endorsement_mode: config.endorsement_mode,
        })
    }
}

impl<A: Adapter + 'static> TrustAdapter<A> {
    pub fn into_dyn(self) -> Arc<RwLock<Box<dyn Adapter>>> {
        Arc::new(RwLock::new(Box::new(self)))
    }
}

impl<A: Adapter + 'static> Adapter for TrustAdapter<A> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
        // TODO: do not prevent write even when the policy does not allow it
        // ... a byzantine participant would just ignore the rule
        // and we must ensure that the written data is simply ignored by others
        /*if key.ends_with(".delta") {
            let ids = extract_created_and_modified_object_ids(data);
            let pubkey = self
                .keystore
                .endorsement_public_key()
                .ok_or_else(|| anyhow!("missing endorsement public key"))?;
            for id in ids {
                if !self.policy.allows(&self.keystore, &pubkey, &id) {
                    return Err(anyhow!(
                        "write denied to {:?} by policy: {}",
                        STANDARD.encode(pubkey),
                        id
                    ));
                }
            }
        }*/
        self.inner.write_object(key, data)
    }

    fn read_object(&self, key: &str, offset: usize, length: usize) -> Result<Vec<u8>> {
        // Read the object data from the inner adapter
        let data = self.inner.read_object(key, 0, 0)?;

        // If it's not a delta file or if offset and length are not zero, return the data or the requested slice
        if !key.ends_with(".delta") || offset != 0 || length != 0 {
            return if offset == 0 && length == 0 {
                Ok(data)
            } else {
                if offset + length > data.len() {
                    return Err(anyhow!("invalid_slice"));
                }
                Ok(data[offset..offset + length].to_vec())
            };
        }

        // Decode the delta ID
        if let Ok(delta_id) = DeltaId::from(key) {
            // If the delta is blacklisted prevent reading
            if self.keystore.is_delta_id_blacklisted(&delta_id) {
                return Err(anyhow!("blacklisted_object_key"));
            }

            // If the delta is whitelisted, allow reading without checking endorsements
            if self.keystore.is_delta_id_whitelisted(&delta_id)
                || self.endorsement_mode == EndorsementMode::DISABLED
            {
                if offset == 0 && length == 0 {
                    return Ok(data);
                } else {
                    if offset + length > data.len() {
                        return Err(anyhow!("invalid_slice"));
                    }
                    return Ok(data[offset..offset + length].to_vec());
                }
            }

            // Fetch endorsements and check if there are enough valid endorsements from trusted keys
            let endorsements = self.fetch_endorsements(&delta_id)?;
            let trusted_count = self.keystore.trusted_key_count();

            let enough = match self.endorsement_mode {
                EndorsementMode::DISABLED => true,
                EndorsementMode::SINGLE => !endorsements.valid.is_empty(),
                EndorsementMode::MAJORITY => {
                    if trusted_count == 0 {
                        false
                    } else {
                        endorsements.valid.len() * 2 > trusted_count
                    }
                }
            };

            if !enough {
                Err(anyhow!("missing_or_insufficient_endorsements"))
            } else {
                // Check the policy to see if changes can be accepted
                let ids = extract_created_and_modified_object_ids(&data);
                let mut allowed_endorsers = 0;
                for e in endorsements.valid {
                    let allowed_ids = ids
                        .iter()
                        .filter(|id| self.policy.allows(&self.keystore, &e, id))
                        .count();
                    if allowed_ids == ids.len() {
                        allowed_endorsers += 1;
                    }
                }

                let enough = match self.endorsement_mode {
                    EndorsementMode::DISABLED => true,
                    EndorsementMode::SINGLE => allowed_endorsers > 0,
                    EndorsementMode::MAJORITY => {
                        if trusted_count == 0 {
                            false
                        } else {
                            allowed_endorsers * 2 > trusted_count
                        }
                    }
                };

                if !enough {
                    return Err(anyhow!("not_allowed_by_policy"));
                }

                if offset == 0 && length == 0 {
                    Ok(data)
                } else {
                    if offset + length > data.len() {
                        return Err(anyhow!("invalid slice"));
                    }
                    Ok(data[offset..offset + length].to_vec())
                }
            }
        } else {
            Err(anyhow!("invalid delta"))
        }
    }

    fn list_objects(&self, ext: &str) -> Result<Vec<String>> {
        self.inner.list_objects(ext)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::policy::rule::RuleEffect;
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
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

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

    #[derive(Clone)]
    struct SkipSigSharedMemoryAdapter {
        inner: Arc<RwLock<MemoryAdapter>>,
    }

    impl SkipSigSharedMemoryAdapter {
        fn new() -> Self {
            Self {
                inner: Arc::new(RwLock::new(MemoryAdapter::new())),
            }
        }
    }

    impl Adapter for SkipSigSharedMemoryAdapter {
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn read_object(&self, key: &str, offset: usize, length: usize) -> Result<Vec<u8>> {
            self.inner.read().unwrap().read_object(key, offset, length)
        }

        fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
            if !key.ends_with(".sig") {
                self.inner.write().unwrap().write_object(key, data)
            } else {
                Ok(())
            }
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
    fn test_valid_signature() {
        let (privk, pubk) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let mut ks_write = KeyStore::new();

        let _ = ks_write.add_trusted_public_key(&pubk);
        let _ = ks_write.set_endorsement_credentials(&privk, Some(&pubk));

        let (_privk2, pubk2) = gen_keys();
        let _ = ks_write.add_trusted_public_key(&pubk2);

        let secure_adapter: TrustAdapter<SharedMemoryAdapter> = TrustAdapter::new_single(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_adapter);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter.clone()).unwrap();

        let v = json!({"a":1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        let blockid = melda.commit(None).unwrap().unwrap();
        assert!(blockid.len() == 1);
        let blockid = blockid.first().unwrap();

        let tadapter = melda.get_adapter();
        let tadapter = tadapter.read().unwrap();
        let tadapter = tadapter
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();
        tadapter.endorse(blockid).unwrap();

        let guard = adapter.read().unwrap();
        let adapter_ref = guard
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();
        assert!(adapter_ref.fetch_endorsements(blockid).is_ok());
        assert_eq!(
            adapter
                .read()
                .unwrap()
                .as_any()
                .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
                .unwrap()
                .fetch_endorsements(blockid)
                .unwrap()
                .valid
                .len(),
            1
        );

        assert!(adapter
            .read()
            .unwrap()
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap()
            .fetch_endorsements(blockid)
            .unwrap()
            .valid
            .contains(pubk.as_slice()));
    }

    #[test]
    fn test_json_serialization() {
        let (privk, pubk) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let mut ks = KeyStore::new();
        ks.set_endorsement_credentials(&privk, Some(&pubk)).unwrap();
        let _ = ks.add_to_delta_id_whitelist(&DeltaId::from("1-allowed.delta").unwrap());
        let _ = ks.add_to_delta_id_blacklist(&DeltaId::from("1-blocked.delta").unwrap());

        let mut policy = PolicyEngine::new();
        policy
            .add_rule(
                None,
                Some("owner".to_string()),
                "*".to_string(),
                RuleEffect::Allow,
            )
            .unwrap();

        let trust_adapter = TrustAdapter::new_single(shared.clone(), ks, policy);

        let config_value = trust_adapter.to_json().unwrap();

        let config_obj = config_value.as_object().unwrap();

        assert!(config_obj.contains_key("keystore"));
        assert!(config_obj.contains_key("policy"));
        assert!(config_obj.contains_key("endorsement_mode"));

        let keystore_value = &config_value["keystore"];

        assert_eq!(keystore_value["keys"].as_array().unwrap().len(), 1);

        assert_eq!(
            keystore_value["deltaid_whitelist"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            keystore_value["deltaid_blacklist"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        assert!(keystore_value.get("endorsement_key").is_none());

        // Verify the exported configuration includes the policy.
        assert!(config_value.get("policy").is_some());

        let policy_value = &config_value["policy"];

        assert!(policy_value.get("rules").is_some());

        // Round-trip

        let adapter_roundtrip = TrustAdapter::from_json(shared, config_value).unwrap();

        assert!(adapter_roundtrip
            .keystore
            .endorsement_public_key()
            .is_none());

        assert!(adapter_roundtrip.keystore.endorse(&[1, 2, 3]).is_none());

        assert_eq!(
            adapter_roundtrip.keystore.get_trusted_public_keys().len(),
            1
        );

        assert!(adapter_roundtrip
            .keystore
            .is_delta_id_whitelisted(&DeltaId::from("1-allowed.delta").unwrap()));

        assert!(adapter_roundtrip
            .keystore
            .is_delta_id_blacklisted(&DeltaId::from("1-blocked.delta").unwrap()));
    }

    #[test]
    fn test_endorse_explicit() {
        let (privk, pubk) = gen_keys();
        let (privk2, pubk2) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let mut ks_write = KeyStore::new();
        let _ = ks_write.add_trusted_public_key(&pubk);
        let _ = ks_write.set_endorsement_credentials(&privk, Some(&pubk));

        let secure_adapter = TrustAdapter::new_single(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_adapter);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter.clone()).unwrap();

        let v = json!({"a": 1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        let blockid = melda.commit(None).unwrap().unwrap();
        let blockid = blockid.first().unwrap();

        let mut guard = adapter.write().unwrap();
        let adapter_mut_ref = guard
            .as_any_mut()
            .downcast_mut::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();

        assert!(adapter_mut_ref.fetch_endorsements(blockid).is_ok());
        // No endorsements yet
        assert_eq!(
            adapter_mut_ref
                .fetch_endorsements(blockid)
                .unwrap()
                .valid
                .len(),
            0
        );

        adapter_mut_ref
            .get_keystore_mut()
            .set_endorsement_credentials(&privk2, Some(&pubk2))
            .unwrap();

        assert!(adapter_mut_ref.endorse(blockid).is_ok());
        assert_eq!(
            adapter_mut_ref
                .fetch_endorsements(blockid)
                .unwrap()
                .valid
                .len(),
            1
        );

        assert!(adapter_mut_ref
            .fetch_endorsements(blockid)
            .unwrap()
            .valid
            .contains(pubk2.as_slice()));
    }

    #[test]
    fn test_signature_file_json_format() {
        let (privk, pubk) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let mut ks_write = KeyStore::new();
        let _ = ks_write.add_trusted_public_key(&pubk);
        let _ = ks_write.set_endorsement_credentials(&privk, Some(&pubk));

        let secure_adapter = TrustAdapter::new_single(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_adapter);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter.clone()).unwrap();

        let v = json!({"a": 1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        let blockid = melda.commit(None).unwrap().unwrap();
        let blockid = blockid.first().unwrap();

        let guard = adapter.read().unwrap();
        let adapter_ref = guard
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();

        assert!(adapter_ref.endorse(blockid).is_ok());
        let sig_path = EndorsementKey::new(blockid.clone(), pubk);

        let endorsement = adapter_ref.read_endorsement_record(&sig_path).unwrap();
        assert_eq!(endorsement.version, 1);
        assert_eq!(endorsement.algorithm, "Ed25519");
        assert!(!endorsement.signature.is_empty());
    }

    #[test]
    fn test_majority_endorsement() {
        let (priv1, pub1) = gen_keys();
        let (priv2, pub2) = gen_keys();
        let (_priv3, pub3) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let mut ks_write = KeyStore::new();
        let _ = ks_write.set_endorsement_credentials(&priv1, Some(&pub1));

        let secure_adapter = TrustAdapter::new_majority(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_adapter);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter.clone()).unwrap();

        let v = json!({"a": 2}).as_object().unwrap().clone();
        let _ = melda.create_object("y", v);
        let blockid = melda.commit(None).unwrap().unwrap();

        let adapter = melda.get_adapter();
        let adapter = adapter.read().unwrap();
        let adapter = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();
        adapter.endorse(blockid.first().unwrap()).unwrap();

        let blockid = blockid.first().unwrap();

        let mut ks_read = KeyStore::new();
        let _ = ks_read.add_trusted_public_key(&pub1);
        let _ = ks_read.add_trusted_public_key(&pub2);
        let _ = ks_read.add_trusted_public_key(&pub3);

        let secure_read = TrustAdapter::new_majority(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter_read: Box<dyn Adapter> = Box::new(secure_read);
        let adapter_read = Arc::new(RwLock::new(adapter_read));
        let melda_read = Melda::new(adapter_read.clone()).unwrap();

        let _ = melda_read.reload();
        assert!(!melda_read.get_all_objects().contains("y"));

        let mut ks_second = KeyStore::new();
        let _ = ks_second.set_endorsement_credentials(&priv2, Some(&pub2));

        let secure_second = TrustAdapter::new_majority(
            shared.clone(),
            ks_second,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter_second: Box<dyn Adapter> = Box::new(secure_second);
        let adapter_second = Arc::new(RwLock::new(adapter_second));
        let guard2 = adapter_second.read().unwrap();
        let secure_second_ref = guard2
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();

        assert!(secure_second_ref.endorse(blockid).is_ok());

        let adapter_read2: Box<dyn Adapter> = Box::new(TrustAdapter::new_majority(
            shared.clone(),
            {
                let mut ks = KeyStore::new();
                let _ = ks.add_trusted_public_key(&pub1);
                let _ = ks.add_trusted_public_key(&pub2);
                let _ = ks.add_trusted_public_key(&pub3);
                ks
            },
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        ));
        let adapter_read2 = Arc::new(RwLock::new(adapter_read2));
        let melda_read2 = Melda::new(adapter_read2.clone()).unwrap();

        let _ = melda_read2.reload();
        assert!(melda_read2.get_all_objects().contains("y"));
    }

    #[test]
    fn test_majority_endorsement_not_enough() {
        let (priv1, pub1) = gen_keys();
        let (_priv2, pub2) = gen_keys();
        let (_priv3, pub3) = gen_keys();
        let shared = SharedMemoryAdapter::new();

        let mut ks_write = KeyStore::new();
        let _ = ks_write.set_endorsement_credentials(&priv1, Some(&pub1));

        let secure_adapter = TrustAdapter::new_majority(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_adapter);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter.clone()).unwrap();

        let v = json!({"a": 2}).as_object().unwrap().clone();
        let _ = melda.create_object("y", v);
        let blockid = melda.commit(None).unwrap().unwrap();
        let _ = blockid.first().unwrap();

        let mut ks_read = KeyStore::new();
        let _ = ks_read.add_trusted_public_key(&pub1);
        let _ = ks_read.add_trusted_public_key(&pub2);
        let _ = ks_read.add_trusted_public_key(&pub3);

        let secure_read = TrustAdapter::new_majority(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter_read: Box<dyn Adapter> = Box::new(secure_read);
        let adapter_read = Arc::new(RwLock::new(adapter_read));
        let melda_read = Melda::new(adapter_read.clone()).unwrap();

        let _ = melda_read.reload();
        assert!(!melda_read.get_all_objects().contains("y"));

        let adapter_read2: Box<dyn Adapter> = Box::new(TrustAdapter::new_majority(
            shared.clone(),
            {
                let mut ks = KeyStore::new();
                let _ = ks.add_trusted_public_key(&pub1);
                let _ = ks.add_trusted_public_key(&pub2);
                let _ = ks.add_trusted_public_key(&pub3);
                ks
            },
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        ));
        let adapter_read2 = Arc::new(RwLock::new(adapter_read2));
        let melda_read2 = Melda::new(adapter_read2.clone()).unwrap();

        let _ = melda_read2.reload();
        assert!(!melda_read2.get_all_objects().contains("y"));
    }

    #[test]
    fn test_missing_signature() {
        let (privk, pubk) = gen_keys();
        let shared = SkipSigSharedMemoryAdapter::new();

        let mut ks_write = KeyStore::new();
        ks_write
            .set_endorsement_credentials(&privk, Some(&pubk))
            .unwrap();

        let secure_write = TrustAdapter::new_single(
            shared.clone(),
            ks_write,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_write);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"a":1}).as_object().unwrap().clone();
        let _ = melda.create_object("x", v);
        assert!(melda.commit(None).is_ok());

        let mut ks_read = KeyStore::new();
        ks_read.add_trusted_public_key(&pubk).unwrap();

        let secure_read = TrustAdapter::new_single(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_read);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let _ = melda.reload();

        assert!(!melda.get_all_objects().contains("x"));
    }

    #[test]
    fn test_untrusted_key_filtered() {
        let (_p1, pub1) = gen_keys();
        let (priv2, pub2) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks_joe = KeyStore::new();
        ks_joe
            .set_endorsement_credentials(&priv2, Some(&pub2))
            .unwrap();

        let secure_joe = TrustAdapter::new_single(
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
        ks_read.add_trusted_public_key(&pub1).unwrap();

        let secure_read = TrustAdapter::new_single(
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
    fn test_whitelist() {
        let (_p1, pub1) = gen_keys();
        let (priv2, pub2) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks_joe = KeyStore::new();
        ks_joe
            .set_endorsement_credentials(&priv2, Some(&pub2))
            .unwrap();

        let secure_joe = TrustAdapter::new_single(
            shared.clone(),
            ks_joe,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_joe);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"hack":1}).as_object().unwrap().clone();
        let _ = melda.create_object("joe", v);
        let deltaids = melda.commit(None).unwrap();

        let mut ks_read = KeyStore::new();
        ks_read.add_trusted_public_key(&pub1).unwrap();
        let _ = ks_read.add_to_delta_id_whitelist(&deltaids.unwrap().first().unwrap());

        let secure_read = TrustAdapter::new_single(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_read);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();
        let _ = melda.reload();
        assert!(melda.get_all_objects().contains("joe"));
    }

    #[test]
    fn test_trusted_key() {
        let (_p1, pub1) = gen_keys();
        let (priv2, pub2) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks_joe = KeyStore::new();
        ks_joe
            .set_endorsement_credentials(&priv2, Some(&pub2))
            .unwrap();

        let secure_joe = TrustAdapter::new_single(
            shared.clone(),
            ks_joe,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_joe);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"hack":1}).as_object().unwrap().clone();
        let _ = melda.create_object("joe", v);
        let delta_id = melda.commit(None).unwrap().unwrap();

        let adapter = melda.get_adapter();
        let adapter = adapter.read().unwrap();
        let adapter = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<SharedMemoryAdapter>>()
            .unwrap();
        adapter.endorse(delta_id.first().unwrap()).unwrap();

        let mut ks_read = KeyStore::new();
        ks_read.add_trusted_public_key(&pub1).unwrap();
        ks_read.add_trusted_public_key(&pub2).unwrap();

        let secure_read = TrustAdapter::new_single(
            shared.clone(),
            ks_read,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_read);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let _ = melda.reload();

        assert!(melda.get_all_objects().contains("joe"));
    }

    #[test]
    fn test_blacklist() {
        let (_p1, pub1) = gen_keys();
        let (priv2, pub2) = gen_keys();

        let shared = SharedMemoryAdapter::new();

        let mut ks_joe = KeyStore::new();
        ks_joe
            .set_endorsement_credentials(&priv2, Some(&pub2))
            .unwrap();

        let secure_joe = TrustAdapter::new_single(
            shared.clone(),
            ks_joe,
            PolicyEngine::from_yaml(r#"rules: [{ allow: { objects: "*" } }]"#).unwrap(),
        );

        let adapter: Box<dyn Adapter> = Box::new(secure_joe);
        let adapter = Arc::new(RwLock::new(adapter));
        let melda = Melda::new(adapter).unwrap();

        let v = json!({"hack":1}).as_object().unwrap().clone();
        let _ = melda.create_object("joe", v);
        let deltaids = melda.commit(None).unwrap();

        let mut ks_read = KeyStore::new();
        ks_read.add_trusted_public_key(&pub1).unwrap();
        ks_read.add_trusted_public_key(&pub2).unwrap();
        let _ = ks_read.add_to_delta_id_blacklist(&deltaids.unwrap().first().unwrap());

        let secure_read = TrustAdapter::new_single(
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
}
