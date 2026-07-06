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

use anyhow::Result;
use melda::melda::DeltaId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Default)]
pub struct DeltaFilter {
    whitelist: HashSet<String>,
    blacklist: HashSet<String>,
}

// ******************************************
// Serialization type
// ******************************************
#[derive(Serialize, Deserialize)]
struct DeltaFilterConfig {
    whitelist: Vec<String>,
    blacklist: Vec<String>,
}

impl DeltaFilter {
    pub fn new() -> Self {
        Self {
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
        }
    }

    pub fn add_to_whitelist(&mut self, delta_id: &DeltaId) -> Result<bool> {
        Ok(self.whitelist.insert(delta_id.key()))
    }

    pub fn is_whitelisted(&self, delta_id: &DeltaId) -> bool {
        self.whitelist.contains(&delta_id.key())
    }

    pub fn add_to_blacklist(&mut self, delta_id: &DeltaId) -> Result<bool> {
        Ok(self.blacklist.insert(delta_id.key()))
    }

    pub fn is_blacklisted(&self, delta_id: &DeltaId) -> bool {
        self.blacklist.contains(&delta_id.key())
    }

    pub fn get_whitelist(&self) -> Vec<String> {
        self.whitelist.iter().cloned().collect()
    }

    pub fn get_blacklist(&self) -> Vec<String> {
        self.blacklist.iter().cloned().collect()
    }

    pub fn to_json(&self) -> Result<Value> {
        let config = DeltaFilterConfig {
            whitelist: self.whitelist.iter().cloned().collect(),
            blacklist: self.blacklist.iter().cloned().collect(),
        };

        Ok(serde_json::to_value(config)?)
    }

    pub fn from_json(json: Value) -> Result<Self> {
        let config: DeltaFilterConfig = serde_json::from_value(json)?;

        let mut df = DeltaFilter::new();

        for delta_id in config.whitelist {
            df.add_to_whitelist(&DeltaId::from(&delta_id)?)?;
        }

        for delta_id in config.blacklist {
            df.add_to_blacklist(&DeltaId::from(&delta_id)?)?;
        }

        Ok(df)
    }
}
