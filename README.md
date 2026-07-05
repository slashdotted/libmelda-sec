# melda-sec (Trust and Governance Layer for Melda)

## WARNING

**This is experimental / alpha software. Use at your own risk.**

`melda-sec` is a pluggable trust and governance layer for https://github.com/slashdotted/libmelda.
Rather than preventing data from being stored, `melda-sec` controls which changes are allowed to contribute to the reconstructed state of a CRDT. The library is implemented as a decorator around a standard Melda `Adapter`, making it possible to add trust management, endorsements, access control policies, encryption and compression without modifying Melda itself.
The core idea is simple:
> Anyone may propose a change. Only sufficiently endorsed and authorized changes contribute to the reconstructed state.
---

# Architecture

`melda-sec` wraps any existing Melda adapter. The TrustAdapter relies on another adapter for storing data (deltas, signatures, packs).

# Trust Model

A change (delta) is treated as a proposal. Nodes can create endorsements for a delta. An endorsement is a cryptographically signed statement indicating that a participant accepts responsibility for that change. A delta contributes to state reconstruction only if:

1. it has enough valid endorsements;
2. the endorsers are trusted;
3. the endorsers satisfy the configured authorization policy.

This design decouples **who created a change** from **who is willing to endorse it**: the latter determines whether a change is accepted.

# Endorsements

Endorsements are represented as separate objects associated with a delta.

```text
delta
delta.<pubkey>.sig
```

Multiple endorsements may exist for the same delta.

Endorsements provide:

- cryptographic accountability;
- non-repudiation of approval;
- decentralized validation.

The system focuses on **who approves a change** rather than **who originally created it**.
Applications may still attach author information inside their data model if desired.

# Trust Configuration

A trust configuration defines:

- trusted public keys;
- optional roles;
- whitelist and blacklist entries;
- authorization policies;
- endorsement requirements.

Typical examples:

```text
SINGLE
```

At least one trusted endorsement is required.

```text
MAJORITY
```

A majority of trusted participants must endorse the change.

# Policies

Policies define which trusted participants are allowed to approve changes affecting specific objects.

Policies may target:

- specific public keys;
- roles;
- object identifier patterns.

A delta is accepted only if a sufficient number of endorsers are authorized by the policy.


# Trust Evolution

Trust is not necessarily static. A Melda CRDT can be used to store and evolve the trust configuration itself. melda-sec supports this evolution of trust through a pair of CRDTs.
The first CRDT, called the Trust CRDT, stores the trust configuration itself: trusted public keys, roles, authorization policies, endorsement requirements, whitelists and blacklists. Changes to this configuration are governed by the same endorsement and policy mechanisms used elsewhere in the system. As a result, trust is no longer a static property hard-coded into an application, but a shared state that can evolve over time.
The second CRDT, called the Data CRDT, stores the application data. Rather than maintaining its own trust configuration, the Data CRDT obtains it from the current state of the Trust CRDT. This allows participants to collaboratively manage not only the data itself, but also the rules that determine which data updates are considered valid.

The *Trust CRDT* manages and defines the *Trust Configuration* which governs the *Data CRDT*

This architecture provides a form of decentralized trust governance. A node bootstraps from an initial trust anchor, reconstructs the current Trust CRDT state, and then uses the resulting trust configuration to validate updates in the Data CRDT. Subsequent changes to trusted participants, roles, policies, or endorsement requirements can be performed through the Trust CRDT itself, without requiring manual reconfiguration of the participating nodes.

# Bootstrapping

A node joining a system requires an initial trust anchor.

This may be:

- a genesis trust configuration;
- a trusted snapshot;
- an out-of-band configuration distributed by trusted parties.

Once an initial trust configuration is available, subsequent versions can be validated using the governance rules stored in the Trust CRDT itself.

# Design Goals
This branch contains a work-in-progress. The goal is to investigate and possibly validate a solid approach providing:

- Decoupled trust management
- Cryptographic endorsements
- Authorization policies
- Fine-grained post-compromise handling
- Offline-friendly synchronization
- Deterministic reconstruction
- Pluggable storage backends
- Composable adapter architecture

`melda-sec` does **not** provide:

- global consensus;
- leader election;
- total ordering of updates;
- Byzantine agreement.

Its goal is to filter and validate changes during reconstruction while preserving the decentralized nature of CRDTs.

# Publications

## 2026

Amos Brocco

**Decoupling Trust in Byzantine CRDTs: Fine-grained Post-Compromise Handling without Breaking Causality**

ArXiv (forthcoming)

Amos Brocco

**A Composable CRDT Layer for Byzantine-Resilient Deterministic Reconstruction**

https://arxiv.org/abs/2606.18966

## 2025

Amos Brocco

**Introducing Support for Move Operations in Melda CRDT**

https://arxiv.org/abs/2503.04811

## 2022

Amos Brocco

**Melda: A General Purpose Delta State JSON CRDT**

PaPoC 2022

https://amosbrocco.ch/pubs/PaPoC_2022_Submission.pdf

## 2021

Amos Brocco

**Delta-State JSON CRDT: Putting Collaboration on Solid Ground**

SSS 2021

https://amosbrocco.ch/pubs/sss_2021_submission_13.pdf

---

# License

(c) 2026 Amos Brocco

GPL v3 (subject to future review).
