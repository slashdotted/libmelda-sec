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
                engine.add_rule(def, RuleEffect::Allow)?;
            }
            if let Some(def) = r.deny {
                engine.add_rule(def, RuleEffect::Deny)?;
            }
        }

        Ok(engine)
    }

    fn add_rule(&mut self, def: RuleDef, effect: RuleEffect) -> Result<()> {
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
            effect,
        });

        Ok(())
    }
}
