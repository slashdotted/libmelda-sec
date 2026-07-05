# melda-sec (Trust Adapter with )

## WARNING

**This is experimental / alpha software. Use at your own risk.**

`melda-sec` is a pluggable trust and governance layer for https://github.com/slashdotted/libmelda.
Rather than preventing data from being stored, `melda-sec` controls which changes are allowed to contribute to the reconstructed state of a CRDT. The library is implemented as a decorator around a standard Melda `Adapter`, making it possible to add trust management, endorsements, access control policies, encryption and compression without modifying Melda itself.
The core idea is simple:
> Anyone may propose a change. Only sufficiently endorsed and authorized changes contribute to the reconstructed state.
---

# Architecture

`melda-sec` wraps any existing Melda adapter.

```text
Melda
  ↓
TrustAdapter
  ↓
Any Adapter
```

Adapters can be composed:

```text
Melda
  ↓
TrustAdapter
  ↓
EncryptionAdapter
  ↓
CompressionAdapter
  ↓
FilesystemAdapter
```

The trust layer is completely independent from storage.

---

# Trust Model

A change (delta) is treated as a proposal. Nodes can create endorsements for a delta. An endorsement is a cryptographically signed statement indicating that a participant accepts responsibility for that change. A delta contributes to state reconstruction only if:

1. it has enough valid endorsements;
2. the endorsers are trusted;
3. the endorsers satisfy the configured authorization policy.

This design decouples:

```text
Who created a change
```

from

```text
Who is willing to endorse it
```

The latter determines whether a change is accepted.

---

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

The system focuses on:

```text
Who approves a change
```

rather than:

```text
Who originally created it
```

Applications may still attach author information inside their data model if desired.

---

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

---

# Policies

Policies define which trusted participants are allowed to approve changes affecting specific objects.

Policies may target:

- specific public keys;
- roles;
- object identifier patterns.

A delta is accepted only if a sufficient number of endorsers are authorized by the policy.

---

# Trust Evolution

Trust is not necessarily static.

A Melda CRDT can be used to store and evolve the trust configuration itself.

```text
Trust CRDT
        ↓
Defines trust configuration
        ↓
Data CRDT
```

This allows trusted participants to collaboratively manage:

- trusted keys;
- roles;
- authorization rules;
- endorsement policies.

Changes to the trust configuration are themselves governed by endorsements and policies.

This enables decentralized trust governance without requiring a central administrator.

---

# Bootstrapping

A node joining a system requires an initial trust anchor.

This may be:

- a genesis trust configuration;
- a trusted snapshot;
- an out-of-band configuration distributed by trusted parties.

Once an initial trust configuration is available, subsequent versions can be validated using the governance rules stored in the Trust CRDT itself.

---

# Design Goals

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

---

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
