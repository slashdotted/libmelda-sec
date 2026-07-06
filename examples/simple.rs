use melda::{filesystemadapter::FilesystemAdapter, melda::Melda};
use melda_sec::TrustAdapter;

use serde_json::json;
use std::fs;
use std::io;
use std::path::Path;

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
    // Clean up the stage :)
    _ = fs::remove_dir_all("alice");
    _ = fs::remove_dir_all("bob");
    _ = fs::remove_dir_all("joe");

    // Generate key pairs
    let (alice_sk, alice_pk) = gen_keys();
    let (bob_sk, bob_pk) = gen_keys();
    let (joe_sk, joe_pk) = gen_keys();

    // **********************************************************
    // TRUST CONFIGURATION (POLICY)
    // **********************************************************

    // The policy allows creation/update to any owner
    // Adding new items can be performed also by editors
    // Editors can also create or modify objects with id starting with bob_
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

    // **********************************************************
    // ALICE
    // **********************************************************
    let base_alice = FilesystemAdapter::new("alice").unwrap();
    let mut secure_alice = TrustAdapter::new_single(base_alice);
    secure_alice
        .get_policy_mut()
        .parse_yaml(policy_yaml)
        .unwrap();
    // Alice trusts herself and Bob, and assigns them roles
    secure_alice
        .get_keystore_mut()
        .set_endorsement_credentials(&alice_sk, Some(&alice_pk))
        .unwrap();
    secure_alice
        .get_keystore_mut()
        .add_trusted_public_key_with_role(&alice_pk, "owner")
        .unwrap();
    secure_alice
        .get_keystore_mut()
        .add_trusted_public_key_with_role(&bob_pk, "editor")
        .unwrap();
    let mut melda_alice = Melda::new(secure_alice.into_dyn()).unwrap();

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
        // Endorse the delta
        let adapter = melda_alice.get_adapter();
        let adapter = adapter.read().unwrap();
        let alice_trustadapter = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();
        alice_trustadapter
            .endorse(delta_id.first().unwrap())
            .unwrap();
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
        // Endorse the delta
        let adapter = melda_alice.get_adapter();
        let adapter = adapter.read().unwrap();
        let alice_trustadapter = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();
        alice_trustadapter
            .endorse(delta_id.first().unwrap())
            .unwrap();
    }

    // **********************************************************
    // BOB
    // **********************************************************

    copy_recursively("alice", "bob").unwrap();

    let base_bob = FilesystemAdapter::new("bob").unwrap();
    let mut secure_bob = TrustAdapter::new_single(base_bob);
    secure_bob.get_policy_mut().parse_yaml(policy_yaml).unwrap();
    // Bob trusts himself and Bob, and assigns them roles
    secure_bob
        .get_keystore_mut()
        .set_endorsement_credentials(&bob_sk, Some(&bob_pk))
        .unwrap();
    secure_bob
        .get_keystore_mut()
        .add_trusted_public_key_with_role(&alice_pk, "owner")
        .unwrap();
    secure_bob
        .get_keystore_mut()
        .add_trusted_public_key_with_role(&bob_pk, "editor")
        .unwrap();
    let mut melda_bob = Melda::new(secure_bob.into_dyn()).unwrap();

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
        let bob_trustadapter = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();
        bob_trustadapter.endorse(delta_id.first().unwrap()).unwrap();
    }

    // **********************************************************
    // JOE (The Hacker)
    // **********************************************************

    copy_recursively("alice", "joe").unwrap();

    let base_joe = FilesystemAdapter::new("joe").unwrap();
    let mut secure_joe = TrustAdapter::new_single(base_joe);
    secure_joe.get_policy_mut().allow_all();
    // Joe trusts himself and Bob, and assigns them roles
    secure_joe
        .get_keystore_mut()
        .set_endorsement_credentials(&joe_sk, Some(&joe_pk))
        .unwrap();
    secure_joe
        .get_keystore_mut()
        .add_trusted_public_key_with_role(&alice_pk, "owner")
        .unwrap();
    secure_joe
        .get_keystore_mut()
        .add_trusted_public_key_with_role(&bob_pk, "editor")
        .unwrap();
    let melda_joe = Melda::new(secure_joe.into_dyn()).unwrap();

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
    let delta_id = melda_joe.commit(None).unwrap().unwrap();
    {
        let adapter = melda_joe.get_adapter();
        let adapter = adapter.read().unwrap();
        let joe_trustadapter = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();
        joe_trustadapter.endorse(delta_id.first().unwrap()).unwrap();
    }

    // **********************************************************
    // MELD BACK INTO ALICE AND BOB AND REFRESH
    // **********************************************************

    melda_alice.meld(&melda_bob).unwrap();
    melda_alice.meld(&melda_joe).unwrap();
    melda_alice.refresh().unwrap();
    let data_alice = melda_alice.read(None).unwrap();
    eprintln!("{}", serde_json::to_string_pretty(&data_alice).unwrap());
    melda_bob.meld(&melda_alice).unwrap();
    melda_bob.meld(&melda_joe).unwrap();
    melda_bob.refresh().unwrap();
    let data_bob = melda_bob.read(None).unwrap();
    eprintln!("{}", serde_json::to_string_pretty(&data_bob).unwrap());
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
