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

use super::rule::{Rule, RuleEffect};
use crate::keystore::KeyStore;
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ******************************************
// Serialization types
// ******************************************
#[derive(Serialize, Deserialize)]
struct PolicyRuleDef {
    effect: RuleEffect,
    key: Option<String>,
    role: Option<String>,
    objects: String,
}

#[derive(Serialize, Deserialize)]
struct PolicyEngineConfig {
    rules: Vec<PolicyRuleDef>,
}

/// Policy engine holding compiled rules for object-level access control.
///
/// The `PolicyEngine` evaluates a set of `Rule`s against a candidate
/// public key (or role resolved via `KeyStore`) and an object identifier.
/// Rules are applied with deny-first semantics: any matching `Deny` rule
/// blocks access, otherwise the first matching `Allow` grants it.
pub struct PolicyEngine {
    pub rules: Vec<Rule>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    pub fn allows(&self, ks: &KeyStore, pubkey: &[u8], object_id: &str) -> bool {
        for r in &self.rules {
            if matches!(r.effect, RuleEffect::Deny) && self.match_rule(r, ks, pubkey, object_id) {
                return false;
            }
        }

        for r in &self.rules {
            if matches!(r.effect, RuleEffect::Allow) && self.match_rule(r, ks, pubkey, object_id) {
                return true;
            }
        }

        false
    }

    fn match_rule(&self, rule: &Rule, ks: &KeyStore, pubkey: &[u8], object_id: &str) -> bool {
        if let Some(ref k) = rule.pubkey {
            if k != pubkey {
                return false;
            }
        }

        if let Some(ref role) = rule.role {
            match ks.get_role(pubkey) {
                Some(r) if r == role => {}
                _ => return false,
            }
        }

        rule.matcher.is_match(object_id)
    }

    pub fn add_rule(
        &mut self,
        pubkey: Option<Vec<u8>>,
        role: Option<String>,
        pattern: String,
        effect: RuleEffect,
    ) -> Result<()> {
        let mut builder = GlobSetBuilder::new();
        builder.add(Glob::new(&pattern)?);
        let matcher = builder.build()?;

        self.rules.push(Rule {
            pubkey,
            role,
            matcher,
            pattern,
            effect,
        });

        Ok(())
    }

    pub fn to_json(&self) -> Result<Value> {
        let config = PolicyEngineConfig {
            rules: self
                .rules
                .iter()
                .map(|rule| PolicyRuleDef {
                    effect: rule.effect.clone(),
                    key: rule.pubkey.as_ref().map(|k| STANDARD.encode(k)),
                    role: rule.role.clone(),
                    objects: rule.pattern.clone(),
                })
                .collect(),
        };

        Ok(serde_json::to_value(&config)?)
    }

    pub fn from_json(json: Value) -> Result<Self> {
        let config: PolicyEngineConfig = serde_json::from_value(json)?;
        let mut engine = PolicyEngine::new();
        for raw in config.rules {
            let pubkey = if let Some(k) = raw.key {
                Some(STANDARD.decode(k)?)
            } else {
                None
            };
            engine.add_rule(pubkey, raw.role, raw.objects, raw.effect)?;
        }
        Ok(engine)
    }
}
