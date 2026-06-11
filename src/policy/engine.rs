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
}
