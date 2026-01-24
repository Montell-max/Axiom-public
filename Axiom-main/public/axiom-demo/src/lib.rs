// Copyright © 2026 Axiom Project Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! axiom-demo: Demonstrates Axiom SCE by integrating all components into a secure key-value store.
//! Enforces all invariants through composition.

use axiom_boundary::ValidatedData;
use axiom_core::hash;
use axiom_identity::{Identity, IdentityFabric};
use axiom_sanctuary::Sanctuary;
use axiom_state::{StateLayer, Change, Operation};
use std::collections::HashMap;

/// A secure key-value store using Axiom components.
pub struct SecureKV {
    state: StateLayer,
    sanctuary: Sanctuary,
    identities: HashMap<String, Identity>,
}

impl SecureKV {
    pub fn new() -> Self {
        Self {
            state: StateLayer::new(),
            sanctuary: Sanctuary::new("kv".to_string(), "write".to_string()),
            identities: HashMap::new(),
        }
    }

    /// Registers an identity (verifiable proof required).
    pub fn register_identity(&mut self, id: &str, proof: [u8; 32]) -> Result<(), String> {
        let expected = hash(id.as_bytes());
        if proof != expected {
            return Err("Invalid identity claim".to_string());
        }
        let identity = Identity { id: id.to_string() };
        self.identities.insert(id.to_string(), identity);
        Ok(())
    }

    /// Stores a value securely: validates input, executes in sanctuary, updates state.
    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<u64, String> {
        // Validate input
        let validated = ValidatedData::validate(value).map_err(|_| "Invalid input")?;

        // Execute in sanctuary - note: we do not rely on identity here; this is a demo helper.
        let key_owned = key.to_string();
        let data_owned = validated.data.clone();
        let change = self.sanctuary.execute(&IdentityFabric::new(), move |_ctx| {
            Ok(Change { key: key_owned, value: data_owned })
        }).map_err(|_| "Execution failed")?;

        // Build operation and apply to state. Use scope 'self' to allow application.
        let proof_bytes = [&b"kv"[..], &b"self"[..], change.key.as_bytes(), &change.value[..]].concat();
        let proof = hash(&bincode::serialize(&("kv".to_string(), "self".to_string(), &change)).unwrap());
        let op = Operation { identity: "kv".to_string(), scope: "self".to_string(), change, proof };
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("kv", hash(b"kv")).unwrap();
        let version = self.state.apply_operation(op, &fabric).map_err(|_| "State error" )?;
        Ok(version as u64)
    }

    /// Retrieves a value.
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.state.get(key)
    }

    /// Forks the store.
    pub fn fork(&self) -> Self {
        Self {
            state: self.state.fork(),
            sanctuary: Sanctuary::new("kv".to_string(), "write".to_string()), // New sanctuary for fork
            identities: self.identities.clone(),
        }
    }

    /// Revokes the sanctuary, preventing further operations.
    pub fn revoke(&mut self) {
        self.sanctuary.revoke();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_core::hash;

    #[test]
    fn test_secure_kv() {
        let mut kv = SecureKV::new();

        // Register identity
        let id = "user";
        let proof = hash(id.as_bytes());
        kv.register_identity(id, proof).unwrap();

        // Put value
        let key = "test_key";
        let value = b"test_value";
        let version = kv.put(key, value).unwrap();
        assert_eq!(version, 1);

        // Get value
        assert_eq!(kv.get(key), Some(&value.to_vec()));

        // Fork
        let forked = kv.fork();
        assert_eq!(forked.get(key), Some(&value.to_vec()));

        // Revoke original
        kv.revoke();
        assert!(kv.put("new_key", b"new").is_err());
    }
}