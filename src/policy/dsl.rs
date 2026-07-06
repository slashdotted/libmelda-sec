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

//! Policy DSL and YAML loader
//!
//! This module parses a compact YAML DSL for object-level access policies and
//! compiles them into a `PolicyEngine` with efficient glob matchers.
//!
//! Format summary
//! --------------
//! The top-level document contains a `rules` array. Each entry in `rules` is
//! an object with either an `allow` or a `deny` mapping. A rule mapping may
//! contain the following fields:
//!
//! - `key` (optional): base64-encoded public key bytes identifying a single
//!   trusted signer. When provided, the rule applies only to that public key.
//! - `role` (optional): role name (string). When provided the rule applies to
//!   any public key that the `KeyStore` maps to that role. Use either `key` or
//!   `role` (or neither) to target principals.
//! - `objects` (required): a glob pattern (uses `globset`) matching object
//!   identifiers affected by the rule. To match everything use `"*"`.
//!
//! Semantics
//! ---------
//! - `deny` rules take precedence: if any `deny` matches the candidate public
//!   key (or role) and the object id, the evaluation returns `false`.
//! - If no denying rule matches, any matching `allow` rule grants access.
//! - If neither allow nor deny matches, access is denied by default.
//! - The `PolicyEngine::from_yaml` helper decodes `key` values from base64 and
//!   compiles the `objects` patterns into `GlobSet`s for fast matching.
//!
//! Encoding notes
//! --------------
//! - Public keys in the DSL are expressed as base64 strings. The loader decodes
//!   them into raw bytes and stores them in the compiled rules.
//! - Role names are plain strings. The runtime resolves roles by asking the
//!   `KeyStore` for the role associated to a given public key.
//!
//! Examples
//! --------
//! 1) Simple: allow owners only
//!
//! ```yaml
//! rules:
//!   - allow:
//!       role: owner
//!       objects: "*"
//! ```
//!
//! Any principal mapped to the `owner` role may modify all objects; other
//! principals are denied because no `allow` matches them.
//!
//! 2) Deny a single key for sensitive objects
//!
//! ```yaml
//! rules:
//!   - deny:
//!       key: "<base64-pubkey>"
//!       objects: "sensitive_*"
//!   - allow:
//!       role: maintainer
//!       objects: "sensitive_*"
//! ```
//!
//! The explicit `deny` blocks a single compromised key even if other rules
//! would allow access; deny rules always take precedence.
//!
//! 3) Mixed rules and multiple patterns
//!
//! ```yaml
//! rules:
//!   - allow:
//!       role: release-team
//!       objects: "release/*"
//!   - allow:
//!       role: owner
//!       objects: "*"
//!   - deny:
//!       key: "<base64-pubkey-rotated>"
//!       objects: "release/*"
//! ```
//!
//! Use multiple rule entries to express different object spaces or principals.
//!
//! 4) Use case: combined with endorsements
//!
//! The `MultisigAdapter` enforces endorsement policies (ONE / MAJORITY). Use
//! `PolicyEngine` rules to express which keys/roles are allowed to endorse
//! particular object patterns. For example, require that only `signers` may
//! endorse release deltas:
//!
//! ```yaml
//! rules:
//!   - allow:
//!       role: signers
//!       objects: "release/*"
//! ```
//!
//! Implementation note
//! -------------------
//! `PolicyEngine::from_yaml` will fail if a `key` is not valid base64 or if an
//! `objects` pattern is an invalid glob. Prefer small, explicit rules over a
//! single catch-all when you need fine-grained control.
//!
//! Example YAML is intentionally compact; comments and extra fields are not
//! interpreted by the loader.
use super::engine::PolicyEngine;
use super::rule::{Rule, RuleEffect};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use globset::{Glob, GlobSetBuilder};
use serde::Deserialize;

#[derive(Deserialize)]
struct PolicyFile {
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
struct RawRule {
    allow: Option<RuleDef>,
    deny: Option<RuleDef>,
}

#[derive(Deserialize)]
struct RuleDef {
    key: Option<String>,
    role: Option<String>,
    objects: String,
}

impl PolicyEngine {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let parsed: PolicyFile = serde_yaml::from_str(yaml)?;
        let mut engine = PolicyEngine::new();

        for r in parsed.rules {
            if let Some(def) = r.allow {
                engine.add_rule_from_def(def, RuleEffect::Allow)?;
            }
            if let Some(def) = r.deny {
                engine.add_rule_from_def(def, RuleEffect::Deny)?;
            }
        }

        Ok(engine)
    }

    pub fn parse_yaml(&mut self, yaml: &str) -> Result<()> {
        let parsed: PolicyFile = serde_yaml::from_str(yaml)?;

        for r in parsed.rules {
            if let Some(def) = r.allow {
                self.add_rule_from_def(def, RuleEffect::Allow)?;
            }
            if let Some(def) = r.deny {
                self.add_rule_from_def(def, RuleEffect::Deny)?;
            }
        }
        Ok(())
    }

    pub fn allow_all(&mut self) {
        self.parse_yaml(r#"rules: [{ allow: { objects: "*" } }]"#)
            .unwrap();
    }

    fn add_rule_from_def(&mut self, def: RuleDef, effect: RuleEffect) -> Result<()> {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new(&def.objects)?);
        let matcher = builder.build()?;

        let pubkey = if let Some(k) = def.key {
            Some(STANDARD.decode(k)?)
        } else {
            None
        };

        self.rules.push(Rule {
            pubkey,
            role: def.role,
            matcher,
            pattern: def.objects,
            effect,
        });

        Ok(())
    }
}
