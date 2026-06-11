# melda-sec, a pluggable security layer for Melda

## WARNING: This is a very early preview / alpha code! Use at your own risk!

`melda-sec` is a pluggable security layer for [Melda](https://github.com/slashdotted/libmelda) that adds cryptographic signing, signature verification, and policy-based authorization on object-level changes. It is implemented as a decorator over a standard Melda `Adapter`, allowing it to wrap any existing backend without modifying the core behavior of Melda. The purpose of `melda-sec` is to control which changes are considered valid: all data is still written and stored, but only changes that pass signature verification and policy rules are applied when the state is reconstructed. Invalid or unauthorized changes are silently ignored.

## Architecture

The library acts as a wrapper around an existing adapter:

```
Melda
  ↓
SecureAdapter
  ↓
Any Adapter (Memory, Filesystem, S3, etc.)
```

When writing data, the secure adapter signs `.delta` objects. When reading data, it verifies signatures and applies authorization rules before allowing changes to affect the resulting state.

## Basic Usage

```rust
use melda::memoryadapter::MemoryAdapter;
use melda_sec::{SecureAdapter, KeyStore, PolicyEngine};

let base = MemoryAdapter::new();

let mut ks = KeyStore::new();
ks.set_private_key(&private_key_bytes)?;
ks.add_public_key(&public_key_bytes)?;

let policy = PolicyEngine::from_yaml(r#"
rules:
  - allow:
      objects: "*"
"#)?;

let secure = SecureAdapter::new(base, ks, policy);
```

Then wrap it for Melda:

```rust
let adapter: Box<dyn Adapter> = Box::new(secure);
let adapter = Arc::new(RwLock::new(adapter));
let melda = Melda::new(adapter)?;
```

## KeyStore

The `KeyStore` manages the cryptographic identity of the node and the trust configuration. It holds a private key used for signing, a set of trusted public keys, and optional role assignments.

```rust
let mut ks = KeyStore::new();
ks.set_private_key(&private_key_bytes)?;
ks.add_public_key(&public_key_bytes)?;
ks.add_public_key_with_role(&public_key_bytes, "accountant")?;
```

Roles allow grouping keys logically and defining policies at a higher level.

## Policy Engine

The `PolicyEngine` defines which keys or roles are allowed to modify specific objects. A policy is evaluated using the signing public key, its role (if any), and the object identifiers affected.

## Policy DSL

Policies are defined in YAML.

Allow everything:

```yaml
rules:
  - allow:
      objects: "*"
```

Only accountants can modify invoice-related objects:

```yaml
rules:
  - allow:
      role: accountant
      objects: "invoice_*"
```

Different roles with different permissions:

```yaml
rules:
  - allow:
      role: accountant
      objects: "invoice_*"

  - allow:
      role: clerk
      objects: "invoice_item_*"

  - deny:
      role: clerk
      objects: "invoice_total_*"
```

Specific key allowed everywhere:

```yaml
rules:
  - allow:
      key: "BASE64_PUBLIC_KEY"
      objects: "*"
```

Combining roles and keys:

```yaml
rules:
  - allow:
      role: accountant
      objects: "invoice_*"

  - allow:
      key: "SPECIAL_KEY"
      objects: "*"
```

Deny example:

```yaml
rules:
  - deny:
      objects: "admin_*"
```

Rules are evaluated in order: deny first, then allow, default deny.

## Object Matching

Policies operate on object identifiers. These identifiers are derived from Melda’s internal representation and are limited to the following forms:

- Plain object identifiers (e.g. values of `_id` fields)
- Flattened array identifiers of the form: `^parentid@field♭`

Field-level control for arbitrary object properties is not supported. Policies can only target flattened arrays, because only those generate dedicated object identifiers.

Patterns use glob syntax:

```
*           matches anything
prefix*     matches prefixes
```

Examples:

```
specificid            object with _id equal to specificid
^order123@items♭      flattened array "items♭" of object "order123"
user_*                namespace-like grouping of objects
```

## Behavior

On write:
- data is always written
- `.delta` objects are signed if a private key exists
- a `.sig` sidecar file is created

On read:
- signatures are verified if present
- only signatures from trusted keys are accepted
- policy rules are applied per object identifier
- invalid or untrusted changes are ignored

Rejected changes do not raise errors and simply do not affect the resulting state.

## Design Properties

This system provides cryptographic integrity, fine-grained authorization, deterministic validation, and compatibility with distributed offline-first workflows. It is resilient to untrusted or malicious writers because invalid data is filtered at read time.

This system does not provide global consensus, total ordering of operations, or automatic convergence across nodes with different policies.

## License

GPL-3.0

## Author

Amos Brocco
