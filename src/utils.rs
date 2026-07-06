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

use serde_json::Value;

pub fn sig_key(key: &str) -> String {
    format!("{}.sig", key)
}

pub fn extract_created_and_modified_object_ids(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();

    let parsed: Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return result,
    };

    if let Some(obj) = parsed.as_object() {
        if let Some(changes) = obj.get("c") {
            if let Some(arr) = changes.as_array() {
                for entry in arr {
                    if let Some(record) = entry.as_array() {
                        if let Some(uuid) = record.first() {
                            if let Some(s) = uuid.as_str() {
                                result.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    result
}
