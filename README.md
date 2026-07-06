# melda-sec (Encryption, Trust and Governance Layer for Melda)

**Warning this is still experimental / alpha software. Use at your own risk.**

**melda-sec** is a pluggable encryption, trust and governance layer for [Melda](https://github.com/slashdotted/libmelda), a delta-state JSON CRDT. Rather than preventing data from being stored, *melda-sec* controls which changes are allowed to contribute to the reconstructed state of a CRDT. The library is implemented as a decorator around a standard Melda *Adapter*, making it possible to add trust management, endorsements, access control policies, encryption and compression without modifying Melda itself.
The core idea is simple: **Anyone may propose a change. Only sufficiently endorsed and authorized changes contribute to the reconstructed state.**
To fully understand how **melda-sec** works you should first read the documentation of the [Melda](https://github.com/slashdotted/libmelda) library, or one of the papers listed in the bibliography down below.

The design goal of **melda** and **melda-sec** is to investigate and possibly validate a CRDT solution providing:

- Byzantine-resiliency
- Decoupled trust management
- Data encryption (and compression)
- Cryptographic endorsements
- Authorization policies
- Fine-grained post-compromise handling
- Deterministic reconstruction

## Architecture
The central component is **TrustAdapter**, a wrapper around any Melda adapter, and relies on the latter for storing data (deltas, signatures, packs).
This library also implements an **EncryptionAdapter** which allows for encrypting data using **Aes256**. 

**TrustAdapter** is the trust and governance layer of **melda-sec**. Instead of preventing participants from creating or exchanging deltas, it treats every delta as a proposal and determines whether that proposal is allowed to contribute to CRDT state reconstruction. This decision is based on a *Trust Configuration* composed of trusted identities, authorization policies, endorsement requirements, and optional whitelist/blacklist rules. A delta becomes visible only if it receives sufficient endorsements from trusted and authorized participants, or if it is explicitly whitelisted. In this way, TrustAdapter transforms a regular CRDT into a governed CRDT, where trust is not based on who created a change, but on who is willing to approve and take responsibility for it.

**EncryptionAdapter** is responsible for confidentiality. Its purpose is to encrypt deltas before they are stored and decrypt them when they are read, ensuring that only participants possessing the correct cryptographic keys can access the underlying data. Unlike TrustAdapter, it does not evaluate endorsements, policies, or trust relationships; it simply protects the contents of the repository from unauthorized access. Because Melda uses a composable adapter architecture, EncryptionAdapter can be used independently when only data confidentiality is required, or combined with TrustAdapter to provide both confidentiality of data and decentralized governance of changes within the same CRDT system.


## TrustAdapter

Before a `Melda` instance can evaluate endorsements, it must be configured with:

- the local endorsement credentials used to sign approvals;
- the set of trusted public keys;
- optional roles assigned to those keys;
- the authorization policy used to determine which roles may approve which changes.

In the example below, Alice creates a **TrustAdapter** in **Single** endorsement mode (more on that later) and loads a policy (written in yaml) defining two roles: *owner* and *editor*. Owners may perform any modification, while editors may only create or modify todo items (JSON objects) whose identifier begins with *bob_*.

```rust
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

let base_alice = FilesystemAdapter::new("alice").unwrap();
let mut trust_adapter = TrustAdapter::new_single(base_alice);

trust_adapter
    .get_policy_mut()
    .parse_yaml(policy_yaml)
    .unwrap();
```

Alice then configures her local signing key and defines the trusted participants:

```rust
trust_adapter
    .get_keystore_mut()
    .set_endorsement_credentials(&alice_sk, Some(&alice_pk))
    .unwrap();

trust_adapter
    .get_keystore_mut()
    .add_trusted_public_key_with_role(&alice_pk, "owner")
    .unwrap();

trust_adapter
    .get_keystore_mut()
    .add_trusted_public_key_with_role(&bob_pk, "editor")
    .unwrap();
```

This trust configuration means that:

- Alice is a trusted participant with role `owner`;
- Bob is a trusted participant with role `editor`;
- endorsements produced by Alice or Bob are considered valid;
- endorsements from any other participant are ignored;
- owners may approve any object;
- editors may only approve changes allowed by the policy.

Once configured, the TrustAdapter is wrapped by Melda exactly like any other adapter:

```rust
let melda = Melda::new(trust_adapter.into_dyn()).unwrap();
```

From this point on, every delta visible through this `Melda` instance must satisfy the configured trust rules before it can contribute to state reconstruction.

## EncryptionAdapter

While **TrustAdapter** determines which deltas are trusted, **EncryptionAdapter** protects the confidentiality of those deltas. The adapter encrypts data before it is written to the underlying storage backend and transparently decrypts it when it is read back. As a result:

- application data is never stored in plaintext;
- repositories may be replicated through untrusted storage;
- only participants possessing the correct encryption key can reconstruct the original data.

Unlike **TrustAdapter**, **EncryptionAdapter** does not evaluate trust relationships, endorsements, roles, or authorization policies. Its sole purpose is to ensure that stored data remains confidential.
Nonetheless, adapters can be stacked together: a common configuration wraps an **EncryptionAdapter** inside a **TrustAdapter**. In this configuration:

- `TrustAdapter` decides which deltas are accepted;
- `EncryptionAdapter` encrypts accepted deltas before storage (using a third adapter);

This provides both, decentralized trust validation as well as confidentiality of the stored data.

### Example usage

The **EncryptionAdapter** is initialized with an existing adapter and a 256-bit AES key.

```rust
let enc_key = [42u8; 32];

let filesystem =
    FilesystemAdapter::new("data")?;

let encrypted =
    EncryptionAdapter::new(
        filesystem,
        enc_key
    );
```

The encrypted adapter can then be wrapped by a **TrustAdapter**:

```rust
let encrypted =
    EncryptionAdapter::new(
        FilesystemAdapter::new("data")?,
        enc_key
    );

let mut trust_adapter =
    TrustAdapter::new_single(
        encrypted
    );

let melda =
    Melda::new(
        trust_adapter.into_dyn()
    )?;
```

You can find a complete example in the **examples** directory.

## Trust Model

Traditional access control systems typically focus on answering a single question *who is allowed to create a change?*. But since in a decentralized environment it is difficult, and often impossible, to prevent participants from creating, storing, or exchanging data, **melda-sec** takes a different approach. In particular we assume that a participant can always generate a delta and distribute it to other nodes. For this reason, **melda-sec** does not attempt to control what can be stored. Instead, it controls what is allowed to contribute to CRDT state reconstruction.

Every delta is initially treated as a **proposal**.
- A participant creates a delta.
- The delta is stored and replicated normally.
- The delta does not automatically become part of the trusted state.
- The TrustAdapter evaluates whether the delta should contribute to reconstruction.

In other words:
- **Stored** does not mean **trusted**.
- **Trusted** does not necessarily mean **authorized**.
- Only deltas satisfying the trust configuration become visible.

## Endorsements
Approval is expressed through **endorsements**. An endorsement is a cryptographically signed statement associating a public key (identity of a participant) with a specific delta. A delta may receive endorsements from multiple participants:
- Alice endorses the delta.
- Bob endorses the delta.
- David endorses the delta.

Endorsements provide cryptographic accountability, non-repudiation of approval, and decentralized validation. Such a trust model focuses on the question  *who is willing to approve this change?* rather than *who originally created this change?*. Therefore, the creator of a delta and the participants endorsing it are not necessarily the same.

## Trusted Identities
Not every endorsement is considered valid. Each trust configuration defines a set of trusted public keys. For example:

- Alice may be trusted.
- Bob may be trusted.
- David may be trusted.
- Eve may not be trusted.

Only endorsements from trusted identities contribute to trust evaluation. As a result:

- An untrusted participant may create a delta.
- An untrusted participant may even endorse that delta.
- The delta remains invisible unless sufficiently endorsed by trusted participants.

## Authorization Policies

Trust alone is not always sufficient. Trusted participants may have different responsibilities.
For example:

- Alice is an `owner`.
- Bob is an `editor`.
- David is a `reviewer`.

Authorization policies determine which identities or roles are allowed to approve specific changes.
Typical examples include:

- Owners may approve any object.
- Editors may approve modifications to specific objects.
- Reviewers may approve document revisions.

A delta can therefore:

- have valid endorsements;
- come from trusted participants;

and still be rejected because the endorsers are not authorized for the affected objects.

## Endorsement Requirements

Applications may require different levels of approval before accepting a delta. We currently support three different levels of approval, namely:

- **Permissive**
  - All deltas are accepted.
  - No endorsement verification is performed.

- **Single**
  - At least one trusted and authorized endorsement is required.

- **Majority**
  - More than half of the trusted participants must endorse the delta. Example:
    - Trusted participants: 5
    - Required endorsements: 3
    
    A delta endorsed by only two trusted participants would not be accepted.

## Deterministic Reconstruction

During synchronization (using **meld** or whatever dissemnation and replication mechanisms has been implemented), nodes may receive many deltas. Some of the delta object may be:

- valid;
- unauthorized;
- malicious;
- incomplete;
- obsolete.

The **TrustAdapter** evaluates each delta independently according to the current trust configuration.
A delta contributes to reconstruction only if:

- it satisfies the endorsement requirements;
- the endorsers are trusted;
- the endorsers satisfy the authorization policy;
- it is not explicitly blacklisted.

Otherwise the delta is ignored. Please note that **Melda** performs other deterministic checks such as validating the JSON structure of the delta, check if the digest matches, checking if referenced content (anchor deltas and data packs) are available and valid. This guarantees that honest nodes converge towards the same trusted state even when untrusted or malicious data is present in the repository.

## Managing Trust Evolution

Trust is not necessarily static. A **Melda** CRDT can be used to store and evolve the trust configuration itself. **melda-sec supports this evolution of trust through a pair of CRDTs**.

The first CRDT, called the *Trust CRDT*, stores the trust configuration itself: trusted public keys, roles, authorization policies, endorsement requirements, whitelists and blacklists. Changes to this configuration are governed by the same endorsement and policy mechanisms used elsewhere in the system. As a result, trust is no longer a static property hard-coded into an application, but a shared state that can evolve over time.

The second CRDT, called the *Data CRDT*, stores the application data. Rather than maintaining its own trust configuration, the Data CRDT obtains it from the current state of the Trust CRDT. This allows participants to collaboratively manage not only the data itself, but also the rules that determine which data updates are considered valid.

The *Trust CRDT* manages and defines the *Trust Configuration* which governs the *Data CRDT*

This architecture provides a form of decentralized trust governance. A node bootstraps from an initial trust anchor, reconstructs the current Trust CRDT state, and then uses the resulting trust configuration to validate updates in the Data CRDT. Subsequent changes to trusted participants, roles, policies, or endorsement requirements can be performed through the Trust CRDT itself, without requiring manual reconfiguration of the participating nodes.

## Bootstrapping
A node joining a system requires an initial trust anchor. This may be:

- a genesis trust configuration;
- a trusted snapshot;
- an out-of-band configuration distributed by trusted parties.

Once an initial trust configuration is available, subsequent versions can be validated using the governance rules stored in the Trust CRDT itself. 

## Example of trust evolution and content revocation
The example included in this repository (see **examples/endorsements.rs**) demonstrates how trust can evolve over time using a dedicated Trust CRDT while independently governing a Data CRDT.
Initially, three participants (Michael, David, and Lukas) act as trustees. The trust configuration requires a majority of trustees to endorse any change to the Trust CRDT. The Data CRDT is governed separately: only Michael and David are authorized to modify application data.
Several participants attempt to modify the Data CRDT. Updates created by Michael and David are accepted because they satisfy the current policy and endorsement requirements. Updates created by Eve, Lukas, and Anna do not contribute to the reconstructed state because they are not authorized by the active policy. Even when a participant bypasses local write checks, unauthorized content is filtered during reconstruction and remains invisible to all nodes.
The system then undergoes a first trust evolution. A new trust configuration is proposed in which Anna becomes a trustee, replacing Lukas. At the same time, the data policy is modified so that Anna and Lukas become authorized data contributors. The proposal is stored in the Trust CRDT but does not immediately become active. It only takes effect after receiving the required endorsements from the trustees defined by the previous configuration.
Once the new trust configuration is accepted, all participants reconstruct the Trust CRDT and obtain the updated governance rules. The Data CRDT is then reloaded using the newly reconstructed trust configuration. As a result, updates produced by Anna and Lukas are now accepted, while updates from Michael and David are no longer authorized.
A second trust evolution demonstrates that governance can continue to evolve. The trustees remain Michael, David, and Anna, while the data policy changes again so that only Anna and David are authorized to modify application data. The new configuration is endorsed by the current trustees and becomes the active governance state.
Finally, the example demonstrates selective content revocation through blacklisting. An update previously created and endorsed by David is later discovered to be incorrect. Rather than revoking David's identity or removing him from the set of trusted participants, a new trust configuration explicitly blacklists the corresponding delta. Once the updated trust configuration is accepted, the blacklisted delta disappears from the reconstructed state on every node, while David remains both trusted and authorized to create future updates.
This illustrates an important property of the model:

  - trust in an identity and trust in a specific piece of content are separate concerns;
  - governance rules can evolve through a Trust CRDT;
  - application data is governed by the current trust configuration;
  - previously accepted content can be selectively revoked without revoking the participant that created it;
  - all participants deterministically reconstruct the same final state.

The example therefore demonstrates endorsement-based validation, trust evolution, decentralized governance, and fine-grained content revocation using a pair of CRDTs: a Trust CRDT governing a Data CRDT.

# Publications

## 2026

Amos Brocco, **Decoupling Trust in Byzantine CRDTs: Fine-grained Post-Compromise Handling without Breaking Causality**, https://arxiv.org/abs/2606.31759

Amos Brocco, **A Composable CRDT Layer for Byzantine-Resilient Deterministic Reconstruction**, https://arxiv.org/abs/2606.18966

## 2025

Amos Brocco, **Introducing Support for Move Operations in Melda CRDT**, https://arxiv.org/abs/2503.04811

## 2022

Amos Brocco **Melda: A General Purpose Delta State JSON CRDT**, PaPoC 2022, [PDF](https://amosbrocco.ch/pubs/PaPoC_2022_Submission.pdf)

## 2021

Amos Brocco, **Delta-State JSON CRDT: Putting Collaboration on Solid Ground**, SSS 2021, [PDF](https://amosbrocco.ch/pubs/sss_2021_submission_13.pdf)

# License

(c) 2026 Amos Brocco
GPL v3 (subject to future review).
