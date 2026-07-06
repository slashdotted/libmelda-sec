use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use melda::{filesystemadapter::FilesystemAdapter, melda::DeltaId, melda::Melda};
use melda_sec::TrustAdapter;
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

fn endorse_trust_delta(delta_id: &DeltaId, sk: &Vec<u8>, pk: &Vec<u8>) {
    let mut adapter = TrustAdapter::new_permissive(FilesystemAdapter::new("trust").unwrap());
    adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&sk, Some(&pk))
        .unwrap();
    adapter.endorse(delta_id).unwrap();
}

fn endorse_data_delta(delta_id: &DeltaId, sk: &Vec<u8>, pk: &Vec<u8>) {
    let mut adapter = TrustAdapter::new_permissive(FilesystemAdapter::new("data").unwrap());
    adapter
        .get_keystore_mut()
        .set_endorsement_credentials(&sk, Some(&pk))
        .unwrap();
    adapter.endorse(delta_id).unwrap();
}

fn update_trust_configuration(config: &serde_json::Value) -> Result<DeltaId> {
    let trust_crdt_backend = FilesystemAdapter::new("trust").map_err(|e| anyhow!(e))?;
    let trust_melda_genesis = Melda::new(trust_crdt_backend.into_dyn())?;
    trust_melda_genesis.update(config.as_object().unwrap().clone())?;
    let trust_genesis_commit = trust_melda_genesis.commit(None).unwrap().unwrap();
    Ok(trust_genesis_commit.first().unwrap().clone())
}

fn get_trust_configuration(
    latest_trust_config: &serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let trust_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("trust").unwrap(),
        latest_trust_config.clone(),
    )?;
    let trust_melda = Melda::new(trust_adapter.into_dyn())?;
    let trust_configuration = trust_melda.read(None)?;
    Ok(trust_configuration.clone())
}

fn get_data_trust_configuration(
    latest_trust_config: &serde_json::Value,
) -> Result<serde_json::Value> {
    let data_trust_configuration = get_trust_configuration(latest_trust_config)?;
    Ok(data_trust_configuration["data_trust_config"].clone())
}

fn bootstrap(
    trust_bootstrap_config: &serde_json::Value,
    sk: &Vec<u8>,
    pk: &Vec<u8>,
) -> Result<Melda> {
    let mut data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        get_data_trust_configuration(trust_bootstrap_config)?,
    )
    .unwrap();
    data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(sk, Some(pk))?;
    Melda::new(data_adapter.into_dyn())
}

fn bootstrap_byzantine(
    trust_bootstrap_config: &serde_json::Value,
    sk: &Vec<u8>,
    pk: &Vec<u8>,
) -> Result<Melda> {
    let mut data_adapter = TrustAdapter::from_json(
        FilesystemAdapter::new("data").unwrap(),
        get_data_trust_configuration(trust_bootstrap_config)?,
    )
    .unwrap();
    data_adapter.get_policy_mut().strict_write(false);
    data_adapter
        .get_keystore_mut()
        .set_endorsement_credentials(sk, Some(pk))?;
    Melda::new(data_adapter.into_dyn())
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
    // - Michael, David and Lukas are trustees of the trust configuration.
    // - The trust configuration update policy requires a majority of the trustees to endorse a change.
    // - Michael and David can modify the data
    // - The data update policy requires a single endorsement.
    let trust_rules_v1 = json!({
        "version" : "v1",
        "keystore" : {
            "keys": [
                {
                    "pubkey": STANDARD.encode(&michael_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&david_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&lukas_pk),
                    "role": "trustee"
                }
            ],
        },
        "delta_filter" : {
            "whitelist": [],
            "blacklist": []
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
        "endorsement_mode": "Majority",
        "data_trust_config": {
            "keystore": {
                "keys": [
                    {
                        "pubkey" : STANDARD.encode(&michael_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&eve_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&lukas_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&david_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&anna_pk),
                        "role" : "participant"
                    },
                ],
            },
            "delta_filter" : {
                "whitelist": [],
                "blacklist": []
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
                "endorsement_mode": "Single"
    }});

    // Initialize the Trust CRDT
    let trust_genesis_commit = update_trust_configuration(&trust_rules_v1).unwrap();

    // Michael, David and Lukas must endorse the trust_genesis_commit
    endorse_trust_delta(&trust_genesis_commit, &michael_sk, &michael_pk);
    endorse_trust_delta(&trust_genesis_commit, &david_sk, &david_pk);
    endorse_trust_delta(&trust_genesis_commit, &lukas_sk, &lukas_pk);

    println!(
        "\nTrust configuration:\n{}",
        serde_json::to_string_pretty(&trust_rules_v1)?
    );

    let initial_config = get_trust_configuration(&trust_rules_v1).unwrap();

    // Bootstrap the data CRDT
    let michael_data_melda = bootstrap(&initial_config.clone().into(), &michael_sk, &michael_pk)?;
    let eve_data_melda = bootstrap_byzantine(&initial_config.clone().into(), &eve_sk, &eve_pk)?;
    let mut lukas_data_melda = bootstrap(&initial_config.clone().into(), &lukas_sk, &lukas_pk)?;
    let david_data_melda = bootstrap(&initial_config.clone().into(), &david_sk, &david_pk)?;
    let mut anna_data_melda = bootstrap(&initial_config.clone().into(), &anna_sk, &anna_pk)?;

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
    endorse_data_delta(michael_delta, &michael_sk, &michael_pk);

    // Eve tries to write even though she has not permissions (strict write is off for her)
    let v = json!({
        "items♭": [{
            "_id": "eve_1",
            "text": "created by Eve"
        }]
    });

    eve_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(eve_data_melda.commit(None).is_ok());

    // Lukas tries to write even but will fail due to policy
    let v = json!({
        "items♭": [{
            "_id": "lukas_1",
            "text": "created by Lukas"
        }]
    });

    lukas_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(lukas_data_melda.commit(None).is_err());
    lukas_data_melda.unstage().unwrap(); // Unstage to allow for reloading

    // David writes
    let v = json!({
        "items♭": [{
            "_id": "david_1",
            "text": "created by David"
        }]
    });

    david_data_melda.update(v.as_object().unwrap().clone())?;
    let david_delta = david_data_melda.commit(None)?.unwrap();
    let david_delta = david_delta.first().unwrap();
    endorse_data_delta(david_delta, &david_sk, &david_pk);

    // Anna tries to write even but will fail due to policy
    let v = json!({
        "items♭": [{
            "_id": "anna_1",
            "text": "created by Anna"
        }]
    });

    anna_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(anna_data_melda.commit(None).is_err());
    anna_data_melda.unstage().unwrap(); // Unstage to allow for reloading

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

    // Michael and David modifications should be visible
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

    // Eve update must be filtered out because the policy does not allow her to write
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

    // Lukas and Anna updates must not be there
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
    println!("  - Eve update invisible");
    println!("  - Lukas update not there");
    println!("  - Anna update not there");

    println!("\n=== TRUST EVOLUTION TEST ===");

    // We now change the trust configuration
    // - Michael, David and Anna become the new trustees of the trust configuration.
    // - The trust configuration update policy requires a majority of the "old" trustees to endorse a change.
    // - Anna and Lukas can now modify the data
    // - The data update policy requires a single endorsement.

    let deltas: Vec<String> = michael_data_melda
        .get_deltas()
        .iter()
        .map(|d| d.key())
        .collect();

    let trust_rules_v2 = json!({
        "version" : "v2",
        "keystore" : {
            "keys": [
                {
                    "pubkey": STANDARD.encode(&michael_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&david_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&anna_pk),
                    "role": "trustee"
                }
            ],
        },
        "delta_filter" : {
            "whitelist": [ trust_genesis_commit.key() ],
            "blacklist": []
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
        "endorsement_mode": "Majority",
        "data_trust_config": {
            "keystore": {
                "keys": [
                    {
                        "pubkey" : STANDARD.encode(&michael_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&eve_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&lukas_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&david_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&anna_pk),
                        "role" : "participant"
                    },
                ],
            },
            "delta_filter" : {
                "whitelist": deltas,
                "blacklist": []
            },
            "policy": {
                "rules": [
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&anna_pk),
                            "objects": "*"
                        },
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&lukas_pk),
                                "objects": "*"
                        }
                    ]
                },
                "endorsement_mode": "Single"
    }});

    // Get the current trust configuration (to verify it will not change if it's not endorsed)
    let current_config = get_trust_configuration(&trust_rules_v1).unwrap();
    let updated_genesis_commit = update_trust_configuration(&trust_rules_v2).unwrap();
    let not_yet_updated_config = get_trust_configuration(&trust_rules_v1).unwrap();
    assert_eq!(current_config, not_yet_updated_config);

    println!("SUCCESS");
    println!("  - Updated trust config not yet active");

    // Michael, David and Lukas must endorse the updated trust configuration
    endorse_trust_delta(&updated_genesis_commit, &michael_sk, &michael_pk);
    endorse_trust_delta(&updated_genesis_commit, &david_sk, &david_pk);
    endorse_trust_delta(&updated_genesis_commit, &lukas_sk, &lukas_pk);

    let updated_config = get_trust_configuration(&trust_rules_v1).unwrap();
    assert_ne!(current_config, updated_config);

    println!("SUCCESS");
    println!("  - Updated trust config now active");

    println!(
        "\nTrust configuration:\n{}",
        serde_json::to_string_pretty(&updated_config)?
    );

    println!("\n=== DATA MODIFICATION TEST WITH UPDATED TRUST CONFIGURATION ===");

    // We bootstrap again the data CRDT (with the new trust configuration)
    let mut michael_data_melda =
        bootstrap(&updated_config.clone().into(), &michael_sk, &michael_pk)?;
    let eve_data_melda = bootstrap_byzantine(&updated_config.clone().into(), &eve_sk, &eve_pk)?;
    let lukas_data_melda = bootstrap(&updated_config.clone().into(), &lukas_sk, &lukas_pk)?;
    let mut david_data_melda = bootstrap(&updated_config.clone().into(), &david_sk, &david_pk)?;
    let anna_data_melda = bootstrap(&updated_config.clone().into(), &anna_sk, &anna_pk)?;

    // Michael tries to write even but will fail due to policy
    let v = json!({
        "items♭": [{
            "_id": "michael_2",
            "text": "created by Michael"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    michael_data_melda.update(v)?;
    assert!(michael_data_melda.commit(None).is_err());
    michael_data_melda.unstage().unwrap(); // Unstage to allow for reloading

    // Eve tries to write even though she has not permissions (strict write is off for her)
    let v = json!({
        "items♭": [{
            "_id": "eve_2",
            "text": "created by Eve"
        }]
    });

    eve_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(eve_data_melda.commit(None).is_ok());

    // Lukas writes
    let v = json!({
        "items♭": [{
            "_id": "lukas_2",
            "text": "created by Lukas"
        }]
    });

    lukas_data_melda.update(v.as_object().unwrap().clone())?;
    let lukas_delta = lukas_data_melda.commit(None)?.unwrap();
    let lukas_delta = lukas_delta.first().unwrap();
    endorse_data_delta(lukas_delta, &lukas_sk, &lukas_pk);

    // David tries to write even but will fail due to policy
    let v = json!({
        "items♭": [{
            "_id": "david_2",
            "text": "created by David"
        }]
    });

    david_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(david_data_melda.commit(None).is_err());
    david_data_melda.unstage().unwrap(); // Unstage to allow for reloading

    // Anna writes
    let v = json!({
        "items♭": [{
            "_id": "anna_2",
            "text": "created by Anna"
        }]
    });

    anna_data_melda.update(v.as_object().unwrap().clone())?;
    let anna_delta = anna_data_melda.commit(None)?.unwrap();
    let anna_delta = anna_delta.first().unwrap();
    endorse_data_delta(anna_delta, &anna_sk, &anna_pk);

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

    // Anna and Lukas modifications should be visible
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("anna_2"))
        })
        .unwrap_or(false);
    assert!(found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("lukas_2"))
        })
        .unwrap_or(false);
    assert!(found);

    // Eve update must be filtered out because the policy does not allow her to write
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("eve_2"))
        })
        .unwrap_or(false);
    assert!(!found);

    // Michael and David updates must not be there
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("michael_2"))
        })
        .unwrap_or(false);
    assert!(!found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("david_2"))
        })
        .unwrap_or(false);
    assert!(!found);

    println!("SUCCESS");
    println!("  - Michael update not there");
    println!("  - David update not there");
    println!("  - Eve update invisible");
    println!("  - Lukas update visible");
    println!("  - Anna update visible");

    println!("\n=== TRUST EVOLUTION TEST (AGAIN) ===");

    // We now change the trust configuration
    // - Michael, David and Anna are still the trustees of the trust configuration.
    // - Anna and David can now modify the data
    // - The data update policy requires a single endorsement.

    let deltas: Vec<String> = anna_data_melda
        .get_deltas()
        .iter()
        .map(|d| d.key())
        .collect();

    let trust_rules_v3 = json!({
        "version" : "v3",
        "keystore" : {
            "keys": [
                {
                    "pubkey": STANDARD.encode(&michael_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&david_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&anna_pk),
                    "role": "trustee"
                }
            ],
        },
        "delta_filter" : {
            "whitelist": [ trust_genesis_commit.key() ],
            "blacklist": []
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
        "endorsement_mode": "Majority",
        "data_trust_config": {
            "keystore": {
                "keys": [
                    {
                        "pubkey" : STANDARD.encode(&michael_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&eve_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&lukas_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&david_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&anna_pk),
                        "role" : "participant"
                    },
                ],
            },
            "delta_filter" : {
                "whitelist": deltas,
                "blacklist": []
            },
            "policy": {
                "rules": [
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&anna_pk),
                            "objects": "*"
                        },
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&david_pk),
                                "objects": "*"
                        }
                    ]
                },
                "endorsement_mode": "Single"
    }});

    // Get the current trust configuration (to verify it will not change if it's not endorsed)
    let current_config = get_trust_configuration(&updated_config.clone().into()).unwrap();
    let updated_genesis_commit = update_trust_configuration(&trust_rules_v3).unwrap();
    let not_yet_updated_config = get_trust_configuration(&current_config.clone().into()).unwrap();
    assert_eq!(current_config, not_yet_updated_config);

    println!("SUCCESS");
    println!("  - Updated trust config not yet active");

    // Michael, David and Lukas must endorse the updated trust configuration
    endorse_trust_delta(&updated_genesis_commit, &michael_sk, &michael_pk);
    endorse_trust_delta(&updated_genesis_commit, &david_sk, &david_pk);
    endorse_trust_delta(&updated_genesis_commit, &anna_sk, &anna_pk);

    let updated_config = get_trust_configuration(&updated_config.clone().into()).unwrap();
    assert_ne!(current_config, updated_config);

    println!("SUCCESS");
    println!("  - Updated trust config now active");

    println!(
        "\nTrust configuration:\n{}",
        serde_json::to_string_pretty(&updated_config)?
    );

    println!("\n=== DATA MODIFICATION TEST (AGAIN) ===");

    // We bootstrap again the data CRDT (with the new trust configuration)
    let mut michael_data_melda =
        bootstrap(&updated_config.clone().into(), &michael_sk, &michael_pk)?;
    let eve_data_melda = bootstrap_byzantine(&updated_config.clone().into(), &eve_sk, &eve_pk)?;
    let mut lukas_data_melda = bootstrap(&updated_config.clone().into(), &lukas_sk, &lukas_pk)?;
    let david_data_melda = bootstrap(&updated_config.clone().into(), &david_sk, &david_pk)?;
    let anna_data_melda = bootstrap(&updated_config.clone().into(), &anna_sk, &anna_pk)?;

    // Michael tries to write even but will fail due to policy
    let v = json!({
        "items♭": [{
            "_id": "michael_3",
            "text": "created by Michael"
        }]
    })
    .as_object()
    .unwrap()
    .clone();

    michael_data_melda.update(v)?;
    assert!(michael_data_melda.commit(None).is_err());
    michael_data_melda.unstage().unwrap(); // Unstage to allow for reloading

    // Eve tries to write even though she has not permissions (strict write is off for her)
    let v = json!({
        "items♭": [{
            "_id": "eve_3",
            "text": "created by Eve"
        }]
    });

    eve_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(eve_data_melda.commit(None).is_ok());

    // Lukas tries to write even but will fail due to policy
    let v = json!({
        "items♭": [{
            "_id": "lukas_3",
            "text": "created by Lukas"
        }]
    });

    lukas_data_melda.update(v.as_object().unwrap().clone())?;
    assert!(lukas_data_melda.commit(None).is_err());
    lukas_data_melda.unstage().unwrap(); // Unstage to allow for reloading

    // David writes
    let v = json!({
        "items♭": [{
            "_id": "david_3",
            "text": "created by David"
        }]
    });

    david_data_melda.update(v.as_object().unwrap().clone())?;
    let david_delta = david_data_melda.commit(None)?.unwrap();
    let david_delta = david_delta.first().unwrap();
    endorse_data_delta(david_delta, &david_sk, &david_pk);

    // Anna writes
    let v = json!({
        "items♭": [{
            "_id": "anna_3",
            "text": "created by Anna"
        }]
    });

    anna_data_melda.update(v.as_object().unwrap().clone())?;
    let anna_delta = anna_data_melda.commit(None)?.unwrap();
    let anna_delta = anna_delta.first().unwrap();
    endorse_data_delta(anna_delta, &anna_sk, &anna_pk);

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

    // Anna and David modifications should be visible
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("anna_3"))
        })
        .unwrap_or(false);
    assert!(found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("david_3"))
        })
        .unwrap_or(false);
    assert!(found);

    // Eve update must be filtered out because the policy does not allow her to write
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("eve_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    // Michael and Lukas updates must not be there
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("michael_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("lukas_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    println!("SUCCESS");
    println!("  - Michael update not there");
    println!("  - Lukas update not there");
    println!("  - Eve update invisible");
    println!("  - David update visible");
    println!("  - Anna update visible");

    println!("\n=== DATA BLACKLISTING EVOLUTION TEST (AGAIN) ===");

    // We now change the trust configuration
    // - The last update commited by David was wrong, we must blacklist it.

    let deltas: Vec<String> = anna_data_melda
        .get_deltas()
        .iter()
        .map(|d| d.key())
        .collect();

    let trust_rules_v4 = json!({
        "version" : "v4",
        "keystore" : {
            "keys": [
                {
                    "pubkey": STANDARD.encode(&michael_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&david_pk),
                    "role": "trustee"
                },
                {
                    "pubkey": STANDARD.encode(&anna_pk),
                    "role": "trustee"
                }
            ],
        },
        "delta_filter" : {
            "whitelist": [ trust_genesis_commit.key() ],
            "blacklist": []
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
        "endorsement_mode": "Majority",
        "data_trust_config": {
            "keystore": {
                "keys": [
                    {
                        "pubkey" : STANDARD.encode(&michael_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&eve_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&lukas_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&david_pk),
                        "role" : "participant"
                    },
                    {
                        "pubkey" : STANDARD.encode(&anna_pk),
                        "role" : "participant"
                    },
                ],
            },
            "delta_filter" : {
                "whitelist": deltas,
                "blacklist": [david_delta.key()]
            },
            "policy": {
                "rules": [
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&anna_pk),
                            "objects": "*"
                        },
                        {
                            "effect": "Allow",
                            "key": STANDARD.encode(&david_pk),
                                "objects": "*"
                        }
                    ]
                },
                "endorsement_mode": "Single"
    }});

    // Get the current trust configuration (to verify it will not change if it's not endorsed)
    let current_config = get_trust_configuration(&updated_config.clone().into()).unwrap();
    let updated_genesis_commit = update_trust_configuration(&trust_rules_v4).unwrap();
    let not_yet_updated_config = get_trust_configuration(&current_config.clone().into()).unwrap();
    assert_eq!(current_config, not_yet_updated_config);

    println!("SUCCESS");
    println!("  - Updated trust config not yet active");

    // Michael, David and Lukas must endorse the updated trust configuration
    endorse_trust_delta(&updated_genesis_commit, &michael_sk, &michael_pk);
    endorse_trust_delta(&updated_genesis_commit, &david_sk, &david_pk);
    endorse_trust_delta(&updated_genesis_commit, &anna_sk, &anna_pk);

    let updated_config = get_trust_configuration(&updated_config.clone().into()).unwrap();
    assert_ne!(current_config, updated_config);

    println!("SUCCESS");
    println!("  - Updated trust config now active");

    println!(
        "\nTrust configuration:\n{}",
        serde_json::to_string_pretty(&updated_config)?
    );

    // We bootstrap again the data CRDT (with the new trust configuration)
    let michael_data_melda = bootstrap(&updated_config.clone().into(), &michael_sk, &michael_pk)?;
    let eve_data_melda = bootstrap_byzantine(&updated_config.clone().into(), &eve_sk, &eve_pk)?;
    let lukas_data_melda = bootstrap(&updated_config.clone().into(), &lukas_sk, &lukas_pk)?;
    let david_data_melda = bootstrap(&updated_config.clone().into(), &david_sk, &david_pk)?;
    let anna_data_melda = bootstrap(&updated_config.clone().into(), &anna_sk, &anna_pk)?;

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
        "\nCurrent state:\n{}",
        serde_json::to_string_pretty(&michael_view)?
    );

    // Anna modifications should be visible
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("anna_3"))
        })
        .unwrap_or(false);
    assert!(found);

    // David modifications should not be there anymore
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("david_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    // Eve update must be filtered out because the policy does not allow her to write
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("eve_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    // Michael and Lukas updates must not be there
    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("michael_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    let found = michael_view
        .get("items♭")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("_id").and_then(|id| id.as_str()) == Some("lukas_3"))
        })
        .unwrap_or(false);
    assert!(!found);

    println!("SUCCESS");
    println!("  - Michael update not there");
    println!("  - Lukas update not there");
    println!("  - Eve update invisible");
    println!("  - David update discarded (blacklisted)");
    println!("  - Anna update visible");

    println!("\n=== RECOVER LATEST TRUST CONFIGURATION ===");
    let mut prev = trust_rules_v1; // This is the bootstrap configuration
    loop {
        println!(
            "\n\nTrust configuration: {}",
            serde_json::to_string_pretty(&prev)?
        );
        let next: serde_json::Value = get_trust_configuration(&prev).unwrap().into();
        if next == prev {
            break;
        }
        prev = next;
    }

    assert_eq!(prev, Into::<serde_json::Value>::into(updated_config));

    println!("SUCCESS");
    println!("  - recovered latest trust configuration");

    Ok(())
}
