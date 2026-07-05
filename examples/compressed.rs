// Note: run with cargo run --example compressed --features melda/brotliadapter

use melda::{
    adapter::Adapter, brotliadapter::BrotliAdapter, filesystemadapter::FilesystemAdapter,
    melda::Melda,
};

use melda_sec::{EncryptionAdapter, KeyStore, PolicyEngine, TrustAdapter};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};

fn gen_keys() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::generate(&mut OsRng);
    (
        sk.to_bytes().to_vec(),
        sk.verifying_key().to_bytes().to_vec(),
    )
}

fn main() {
    type TrustCompressedFsAdapter = TrustAdapter<BrotliAdapter<Arc<RwLock<Box<dyn Adapter>>>>>;

    _ = fs::remove_dir_all("alice");
    _ = fs::remove_dir_all("bob");

    let (alice_sk, alice_pk) = gen_keys();
    let (bob_sk, bob_pk) = gen_keys();

    let enc_key = [42u8; 32];

    let policy_yaml = r#"
rules:
  - allow:
      role: owner
      objects: "*"
  - allow:
      role: editor
      objects: "^*@items♭"
  - allow:
      role: editor
      objects: "bob_*"
"#;

    let mut ks_alice = KeyStore::new();
    ks_alice
        .set_endorsement_credentials(&alice_sk, Some(&alice_pk))
        .unwrap();
    ks_alice
        .add_trusted_public_key_with_role(&alice_pk, "owner")
        .unwrap();
    ks_alice
        .add_trusted_public_key_with_role(&bob_pk, "editor")
        .unwrap();

    let policy_alice = PolicyEngine::from_yaml(policy_yaml).unwrap();

    let base_alice = FilesystemAdapter::new("alice").unwrap();

    let enc_alice = EncryptionAdapter::new(base_alice, enc_key).into_dyn();
    let comp_alice = BrotliAdapter::new(enc_alice);
    let secure_alice = TrustAdapter::new_single(comp_alice, ks_alice, policy_alice).into_dyn();

    let mut melda_alice = Melda::new(secure_alice).unwrap();

    let v = json!({
        "software":"MeldaDo",
        "version":"1.0.0",
        "items♭":[]
    })
    .as_object()
    .unwrap()
    .clone();

    melda_alice.update(v).unwrap();
    let delta_id = melda_alice.commit(None).unwrap().unwrap();
    {
        let adapter = melda_alice.get_adapter();
        let adapter = adapter.read().unwrap();
        let trust_adapter = adapter
            .as_any()
            .downcast_ref::<TrustCompressedFsAdapter>()
            .unwrap();

        trust_adapter.endorse(delta_id.first().unwrap()).unwrap();
    }

    let v = json!({
        "software":"MeldaDo",
        "version":"1.0.0",
        "items♭":[
            {"_id":"alice_todo_01","title":"Buy milk"}
        ]
    })
    .as_object()
    .unwrap()
    .clone();

    melda_alice.update(v).unwrap();
    let delta_id = melda_alice.commit(None).unwrap().unwrap();
    {
        let adapter = melda_alice.get_adapter();
        let adapter = adapter.read().unwrap();
        let trust_adapter = adapter
            .as_any()
            .downcast_ref::<TrustCompressedFsAdapter>()
            .unwrap();

        trust_adapter.endorse(delta_id.first().unwrap()).unwrap();
    }

    copy_recursively("alice", "bob").unwrap();

    let mut ks_bob = KeyStore::new();
    ks_bob
        .set_endorsement_credentials(&bob_sk, Some(&bob_pk))
        .unwrap();
    ks_bob
        .add_trusted_public_key_with_role(&alice_pk, "owner")
        .unwrap();
    ks_bob
        .add_trusted_public_key_with_role(&bob_pk, "editor")
        .unwrap();

    let policy_bob = PolicyEngine::from_yaml(policy_yaml).unwrap();
    let base_bob = FilesystemAdapter::new("bob").unwrap();
    let enc_bob = EncryptionAdapter::new(base_bob, enc_key).into_dyn();
    let comp_bob = BrotliAdapter::new(enc_bob);
    let secure_bob = TrustAdapter::new_single(comp_bob, ks_bob, policy_bob).into_dyn();
    let mut melda_bob = Melda::new(secure_bob).unwrap();

    let v = json!({
        "software":"MeldaDo",
        "version":"1.0.0",
        "items♭":[
            {"_id":"alice_todo_01","title":"Buy milk"},
            {"_id":"bob_todo_01","title":"Pay bills"}
        ]
    })
    .as_object()
    .unwrap()
    .clone();

    melda_bob.update(v).unwrap();
    let delta_id = melda_bob.commit(None).unwrap().unwrap();
    {
        let adapter = melda_bob.get_adapter();
        let adapter = adapter.read().unwrap();
        let trust_adapter = adapter
            .as_any()
            .downcast_ref::<TrustCompressedFsAdapter>()
            .unwrap();

        trust_adapter.endorse(delta_id.first().unwrap()).unwrap();
    }

    melda_alice.meld(&melda_bob).unwrap();
    melda_alice.refresh().unwrap();

    let data = melda_alice.read(None).unwrap();
    println!("{}", serde_json::to_string_pretty(&data).unwrap());

    melda_bob.meld(&melda_alice).unwrap();
    melda_bob.refresh().unwrap();

    let data = melda_bob.read(None).unwrap();
    println!("{}", serde_json::to_string_pretty(&data).unwrap());
}

pub fn copy_recursively(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let filetype = entry.file_type()?;
        if filetype.is_dir() {
            copy_recursively(entry.path(), destination.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), destination.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}
