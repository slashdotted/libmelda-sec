use melda::{adapter::Adapter, filesystemadapter::FilesystemAdapter, melda::Melda};
use melda_sec::{KeyStore, PolicyEngine, SecureAdapter};

use serde_json::json;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn gen_keys() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::generate(&mut OsRng);
    (
        sk.to_bytes().to_vec(),
        sk.verifying_key().to_bytes().to_vec(),
    )
}

fn main() {
    _ = fs::remove_dir_all("alice");
    _ = fs::remove_dir_all("bob");
    _ = fs::remove_dir_all("joe");

    let (alice_sk, alice_pk) = gen_keys();
    let (bob_sk, bob_pk) = gen_keys();
    let (joe_sk, _) = gen_keys();

    let policy_yaml = r#"
rules:
  - allow:
      role: owner
      objects: "*"
  - allow:
      role: editor
      objects: "^items♭"
  - allow:
      role: editor
      objects: "bob_*"
"#;

    let mut ks_alice = KeyStore::new();
    ks_alice.set_private_key(&alice_sk).unwrap();
    ks_alice
        .add_public_key_with_role(&alice_pk, "owner")
        .unwrap();
    ks_alice
        .add_public_key_with_role(&bob_pk, "editor")
        .unwrap();

    let policy_alice = PolicyEngine::from_yaml(policy_yaml).unwrap();

    let base_alice = FilesystemAdapter::new("alice").unwrap();
    let secure_alice = SecureAdapter::new(base_alice, ks_alice, policy_alice);

    let adapter_alice: Box<dyn Adapter> = Box::new(secure_alice);
    let adapter_alice = Arc::new(RwLock::new(adapter_alice));

    let mut melda_alice = Melda::new(adapter_alice).unwrap();

    let v = json!({
        "software":"MeldaDo",
        "version":"1.0.0",
        "items♭":[]
    })
    .as_object()
    .unwrap()
    .clone();

    melda_alice.update(v).unwrap();
    melda_alice.commit(None).unwrap();

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
    melda_alice.commit(None).unwrap();

    copy_recursively("alice", "bob").unwrap();

    let mut ks_bob = KeyStore::new();
    ks_bob.set_private_key(&bob_sk).unwrap();
    ks_bob.add_public_key_with_role(&alice_pk, "owner").unwrap();
    ks_bob.add_public_key_with_role(&bob_pk, "editor").unwrap();

    let policy_bob = PolicyEngine::from_yaml(policy_yaml).unwrap();

    let base_bob = FilesystemAdapter::new("bob").unwrap();
    let secure_bob = SecureAdapter::new(base_bob, ks_bob, policy_bob);

    let adapter_bob: Box<dyn Adapter> = Box::new(secure_bob);
    let adapter_bob = Arc::new(RwLock::new(adapter_bob));

    let mut melda_bob = Melda::new(adapter_bob).unwrap();

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
    melda_bob.commit(None).unwrap();

    copy_recursively("alice", "joe").unwrap();

    let mut ks_joe = KeyStore::new();
    ks_joe.set_private_key(&joe_sk).unwrap();

    let policy_joe = PolicyEngine::from_yaml(
        r#"
rules:
  - allow:
      objects: "*"
"#,
    )
    .unwrap();

    let base_joe = FilesystemAdapter::new("joe").unwrap();
    let secure_joe = SecureAdapter::new(base_joe, ks_joe, policy_joe);

    let adapter_joe: Box<dyn Adapter> = Box::new(secure_joe);
    let adapter_joe = Arc::new(RwLock::new(adapter_joe));

    let melda_joe = Melda::new(adapter_joe).unwrap();

    let v = json!({
        "software":"MeldaDo",
        "version":"1.0.0",
        "items♭":[
            {"_id":"joe_todo_01","title":"Hack system"}
        ]
    })
    .as_object()
    .unwrap()
    .clone();

    melda_joe.update(v).unwrap();
    melda_joe.commit(None).unwrap();

    melda_alice.meld(&melda_bob).unwrap();
    melda_alice.meld(&melda_joe).unwrap();
    melda_alice.refresh().unwrap();

    melda_bob.meld(&melda_alice).unwrap();
    melda_bob.meld(&melda_joe).unwrap();
    melda_bob.refresh().unwrap();

    let data_alice = melda_alice.read(None).unwrap();
    let data_bob = melda_bob.read(None).unwrap();

    println!("{}", serde_json::to_string_pretty(&data_alice).unwrap());
    println!("{}", serde_json::to_string_pretty(&data_bob).unwrap());
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
