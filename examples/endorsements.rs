use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use melda::{filesystemadapter::FilesystemAdapter, melda::Melda};
use melda_sec::{KeyStore, PolicyEngine, TrustAdapter};
use rand::rngs::OsRng;
use serde_json::json;
use std::fs;

fn gen_keys() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::generate(&mut OsRng);
    (
        sk.to_bytes().to_vec(),
        sk.verifying_key().to_bytes().to_vec(),
    )
}

fn main() -> Result<()> {
    let _ = fs::remove_dir_all("data");
    let _ = fs::remove_dir_all("trust");

    let (michael_sk, michael_pk) = gen_keys();
    let (eve_sk, eve_pk) = gen_keys();
    let (lukas_sk, lukas_pk) = gen_keys();
    let (david_sk, david_pk) = gen_keys();
    let (anna_sk, anna_pk) = gen_keys();

    eprintln!("Generated public and private keys for Michael, Eve, Lukas, David and Anna:  ");
    eprintln!("Michael: {}", STANDARD.encode(&michael_pk));
    eprintln!("Eve: {}", STANDARD.encode(&eve_pk));
    eprintln!("Lukas: {}", STANDARD.encode(&lukas_pk));
    eprintln!("David: {}", STANDARD.encode(&david_pk));
    eprintln!("Anna: {}", STANDARD.encode(&anna_pk));

    // We initially want the following rules
    // - Michael, Eve and Lukas are trustees of the trust configuration.
    // - The trust configuration update policy requires a majority of the trustees to endorse a change.
    // - Michael and David can modify the data
    // - The data update policy requires a single endorsement.
    let initial_trust_rules = json!({
        "keystore" : {
            "keys": [
                {
                    "pubkey": STANDARD.encode(&michael_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&eve_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&lukas_pk),
                    "role": "trustee"
                }
            ],
             "deltaid_whitelist": [],
             "deltaid_blacklist": []
        },
        "policy": {
                "rules": [
                    {
                        "effect": "Allow",
                        "role": "trustee",
                        "objects": "*"
                    }
                ]
        },
        "endorsement_mode": "MAJORITY",
        "data_trust_config": {
            "keystore": {
                "keys": [
                    {
                        "pubkey" : STANDARD.encode(&michael_pk),
                        "role" : "data_editor"
                    },
                    {
                        "pubkey" : STANDARD.encode(&david_pk),
                        "role" : "data_editor"
                    }
                ],
                "deltaid_whitelist": [],
                "deltaid_blacklist": []
            },
            "policy": {
                "rules": [
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&michael_pk),
                            "objects": "*"
                        },
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&david_pk),
                                "objects": "*"
                        }
                    ]
                },
                "endorsement_mode": "SINGLE"
    }});

    // Initialize the Trust CRDT
    let trust_crdt_backend = FilesystemAdapter::new("trust").map_err(|e| anyhow!(e))?;
    let trust_melda_genesis = Melda::new(trust_crdt_backend.into_dyn())?;
    trust_melda_genesis.update(initial_trust_rules.as_object().unwrap().clone())?;
    println!("Initial trust configuration written to trust Melda");
    let trust_genesis_commit = trust_melda_genesis.commit(None).unwrap().unwrap();
    let trust_genesis_commit = trust_genesis_commit.first().unwrap();
    // Print the initial trust configuration from the trust_melda_genesis
    println!("\n\nInitial Trust Trust Configuration:");
    let trust_config = trust_melda_genesis.read(None)?;
    println!("{}", serde_json::to_string_pretty(&trust_config)?);
    println!("\n\nInitial Data Trust Configuration:");
    println!(
        "{}",
        serde_json::to_string_pretty(&trust_config["data_trust_config"])?
    );

    {
        // Michael, Eve and Lukas must create an instance of the TrustAdapter and
        // endorse the trust_genesis_commit
        let mut michael_ks = KeyStore::new();
        michael_ks.set_endorsement_credentials(&michael_sk, Some(&michael_pk))?;
        let mut eve_ks = KeyStore::new();
        eve_ks.set_endorsement_credentials(&eve_sk, Some(&eve_pk))?;
        let mut lukas_ks = KeyStore::new();
        lukas_ks.set_endorsement_credentials(&lukas_sk, Some(&lukas_pk))?;
        let michael_adapter: TrustAdapter<FilesystemAdapter> = TrustAdapter::new_disabled(
            FilesystemAdapter::new("trust").unwrap(),
            michael_ks,
            PolicyEngine::new(),
        );
        let eve_adapter = TrustAdapter::new_disabled(
            FilesystemAdapter::new("trust").unwrap(),
            eve_ks,
            PolicyEngine::new(),
        );
        let lukas_adapter = TrustAdapter::new_disabled(
            FilesystemAdapter::new("trust").unwrap(),
            lukas_ks,
            PolicyEngine::new(),
        );
        michael_adapter.endorse(trust_genesis_commit)?;
        println!("Michael endorsed trust genesis");
        eve_adapter.endorse(trust_genesis_commit)?;
        println!("Eve endorsed trust genesis");
        lukas_adapter.endorse(trust_genesis_commit)?;
        println!("Lukas endorsed trust genesis");
    }

    // Michael bootstrap

    // Use trusted bootstrap configuration
    println!("Bootstrapping trust CRDT on Michael");
    let mut michael_trust_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("trust").unwrap(),
        initial_trust_rules.clone(),
    )?;
    println!("Configuring trust adapter on Michael with credentials");
    michael_trust_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&michael_sk, Some(&michael_pk))?;
    println!("Configuring trust CRDT on Michael");
    let michael_trust_melda = Melda::new(michael_trust_adapter.into_dyn())?;
    println!("Getting trust configuration for data on Michael");
    let data_trust_configuration = michael_trust_melda.read(None)?;
    // Setup data CRDT
    let mut michael_data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        data_trust_configuration["data_trust_config"].clone(),
    )?;
    michael_data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&michael_sk, Some(&michael_pk))?;
    let michael_data_melda = Melda::new(michael_data_adapter.into_dyn())?;

    // Eve bootstrap

    // Use trusted bootstrap configuration
    println!("Bootstrapping trust CRDT on Eve");
    let mut eve_trust_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("trust").unwrap(),
        initial_trust_rules.clone(),
    )?;
    println!("Configuring trust adapter on Eve with credentials");
    eve_trust_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&eve_sk, Some(&eve_pk))?;
    println!("Configuring trust CRDT on Eve");
    let eve_trust_melda = Melda::new(eve_trust_adapter.into_dyn())?;
    println!("Getting trust configuration for data on Eve");
    let data_trust_configuration = eve_trust_melda.read(None)?;
    // Setup data CRDT
    let mut eve_data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        data_trust_configuration["data_trust_config"].clone(),
    )?;
    eve_data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&eve_sk, Some(&eve_pk))?;
    let eve_data_melda = Melda::new(eve_data_adapter.into_dyn())?;

    // Lukas bootstrap

    // Use trusted bootstrap configuration
    println!("Bootstrapping trust CRDT on Lukas");
    let mut lukas_trust_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("trust").unwrap(),
        initial_trust_rules.clone(),
    )?;
    println!("Configuring trust adapter on Lukas with credentials");
    lukas_trust_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&lukas_sk, Some(&lukas_pk))?;
    println!("Configuring trust CRDT on Lukas");
    let lukas_trust_melda = Melda::new(lukas_trust_adapter.into_dyn())?;
    println!("Getting trust configuration for data on Lukas");
    let data_trust_configuration = lukas_trust_melda.read(None)?;
    // Setup data CRDT
    let mut lukas_data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        data_trust_configuration["data_trust_config"].clone(),
    )?;
    lukas_data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&lukas_sk, Some(&lukas_pk))?;
    let lukas_data_melda = Melda::new(lukas_data_adapter.into_dyn())?;

    // David bootstrap

    // Use trusted bootstrap configuration
    println!("Bootstrapping trust CRDT on David");
    let mut david_trust_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("trust").unwrap(),
        initial_trust_rules.clone(),
    )?;
    println!("Configuring trust adapter on David with credentials");
    david_trust_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&david_sk, Some(&david_pk))?;
    println!("Configuring trust CRDT on David");
    let david_trust_melda = Melda::new(david_trust_adapter.into_dyn())?;
    println!("Getting trust configuration for data on David");
    let data_trust_configuration = david_trust_melda.read(None)?;
    // Setup data CRDT
    let mut david_data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        data_trust_configuration["data_trust_config"].clone(),
    )?;
    david_data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&david_sk, Some(&david_pk))?;
    let david_data_melda = Melda::new(david_data_adapter.into_dyn())?;

    // Anna bootstrap

    // Use trusted bootstrap configuration
    println!("Bootstrapping trust CRDT on Anna");
    let mut anna_trust_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("trust").unwrap(),
        initial_trust_rules.clone(),
    )?;
    println!("Configuring trust adapter on Anna with credentials");
    anna_trust_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&anna_sk, Some(&anna_pk))?;
    println!("Configuring trust CRDT on Anna");
    let anna_trust_melda = Melda::new(anna_trust_adapter.into_dyn())?;
    println!("Getting trust configuration for data on Anna");
    let data_trust_configuration = anna_trust_melda.read(None)?;
    // Setup data CRDT
    let mut anna_data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        data_trust_configuration["data_trust_config"].clone(),
    )?;
    anna_data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&anna_sk, Some(&anna_pk))?;
    let anna_data_melda = Melda::new(anna_data_adapter.into_dyn())?;

    println!("\n=== DATA MODIFICATION TEST ===");

    // Michael writes
    let v = json!({
        "items♭": [{
            "_id": "michael_1",
            "text": "created by Michael"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    michael_data_melda.update(v)?;
    let michael_delta = michael_data_melda.commit(None)?.unwrap();
    let michael_delta = michael_delta.first().unwrap();

    {
        let adapter = michael_data_melda.get_adapter();
        let adapter = adapter.read().unwrap();

        let trust = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();

        trust.endorse(michael_delta)?;
    }

    // David writes
    let v = json!({
        "items♭": [{
            "_id": "david_1",
            "text": "created by David"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    david_data_melda.update(v)?;
    let david_delta = david_data_melda.commit(None)?.unwrap();
    let david_delta = david_delta.first().unwrap();

    {
        let adapter = david_data_melda.get_adapter();
        let adapter = adapter.read().unwrap();

        let trust = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();

        trust.endorse(david_delta)?;
    }

    // Eve writes
    let v = json!({
        "items♭": [{
            "_id": "eve_1",
            "text": "created by Eve"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    eve_data_melda.update(v)?;
    let eve_delta = eve_data_melda.commit(None)?.unwrap();
    let eve_delta = eve_delta.first().unwrap();

    {
        let adapter = eve_data_melda.get_adapter();
        let adapter = adapter.read().unwrap();

        let trust = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();

        trust.endorse(eve_delta)?;
    }

    // Lukas writes
    let v = json!({
        "items♭": [{
            "_id": "lukas_1",
            "text": "created by Lukas"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    lukas_data_melda.update(v)?;
    let lukas_delta = lukas_data_melda.commit(None)?.unwrap();
    let lukas_delta = lukas_delta.first().unwrap();

    {
        let adapter = lukas_data_melda.get_adapter();
        let adapter = adapter.read().unwrap();

        let trust = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();

        trust.endorse(lukas_delta)?;
    }

    // Anna writes
    let v = json!({
        "items♭": [{
            "_id": "anna_1",
            "text": "created by Anna"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    anna_data_melda.update(v)?;
    let anna_delta = anna_data_melda.commit(None)?.unwrap();
    let anna_delta = anna_delta.first().unwrap();

    {
        let adapter = anna_data_melda.get_adapter();
        let adapter = adapter.read().unwrap();

        let trust = adapter
            .as_any()
            .downcast_ref::<TrustAdapter<FilesystemAdapter>>()
            .unwrap();

        trust.endorse(anna_delta)?;
    }

    println!("Reloading all participants...");

    michael_data_melda.reload()?;
    eve_data_melda.reload()?;
    lukas_data_melda.reload()?;
    david_data_melda.reload()?;
    anna_data_melda.reload()?;

    let michael_view = michael_data_melda.read(None)?;
    let eve_view = eve_data_melda.read(None)?;
    let lukas_view = lukas_data_melda.read(None)?;
    let david_view = david_data_melda.read(None)?;
    let anna_view = anna_data_melda.read(None)?;

    // Everyone should see the same state
    assert_eq!(michael_view, eve_view);
    assert_eq!(michael_view, lukas_view);
    assert_eq!(michael_view, david_view);
    assert_eq!(michael_view, anna_view);

    println!(
        "\nFinal state:\n{}",
        serde_json::to_string_pretty(&michael_view)?
    );

    // Michael and David modifications survive

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("michael_1"))
        })
        .unwrap_or(false);
    assert!(found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("david_1"))
        })
        .unwrap_or(false);
    assert!(found);

    // Eve, Lukas and Anna modifications are filtered out
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("eve_1"))
        })
        .unwrap_or(false);
    assert!(!found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("lukas_1"))
        })
        .unwrap_or(false);
    assert!(!found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("anna_1"))
        })
        .unwrap_or(false);
    assert!(!found);

    println!("SUCCESS");
    println!("  - Michael update visible");
    println!("  - David update visible");
    println!("  - Eve update rejected");
    println!("  - Lukas update rejected");
    println!("  - Anna update rejected");

    Ok(())
}
