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

//! axiom-state: State & Memory Layer - Defines authoritative, versioned system state.
//! Detects: Unauthorized mutation, rollback, silent corruption.
//! Survives: Compromise via versioning and authority binding.
//! Refuses to trust: Storage backends, wall-clock time.
//!
//! State transitions are explicit, bound to identity + authority, preserve history, allow forks.

use axiom_core::hash;
use axiom_identity::IdentityFabric;
use axiom_integrity::{IntegrityChain, Entry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub identity: String,
    pub scope: String,
    pub change: Change,
    pub proof: [u8; 32], // hash(identity + scope + change)
}

#[derive(Debug)]
pub enum StateError {
    Unauthorized,
    InvalidProof,
    IntegrityViolation,
}

pub struct StateLayer {
    state: HashMap<String, Vec<u8>>,
    chain: IntegrityChain,
}

impl StateLayer {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            chain: IntegrityChain::new(),
        }
    }

    /// Applies a state operation, binding to identity + authority.
    /// Verifies authority and proof, logs to integrity chain, updates state.
    pub fn apply_operation(&mut self, operation: Operation, fabric: &IdentityFabric) -> Result<usize, StateError> {
        // Check authority
        if !fabric.has_authority(&operation.identity, &operation.scope) {
            return Err(StateError::Unauthorized);
        }

        // Verify proof
        let expected_proof = hash(&bincode::serialize(&(operation.identity.clone(), operation.scope.clone(), &operation.change)).unwrap());
        if operation.proof != expected_proof {
            return Err(StateError::InvalidProof);
        }

        // Apply change
        let entry = Entry { data: bincode::serialize(&operation).unwrap() };
        self.chain.append(entry);
        self.state.insert(operation.change.key, operation.change.value);

        Ok(self.chain.len())
    }

    /// Gets current state value.
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.state.get(key)
    }

    /// Forks the state layer.
    /// Creates independent copy with full history.
    pub fn fork(&self) -> Self {
        Self {
            state: self.state.clone(),
            chain: self.chain.fork(),
        }
    }

    /// Verifies integrity of the state history.
    /// Detects tampering, rollback, corruption.
    pub fn verify(&self) -> Result<(), StateError> {
        if !self.chain.verify() {
            return Err(StateError::IntegrityViolation);
        }
        // Reconstruct state from chain
        let mut reconstructed = HashMap::new();
        for entry in self.chain.entries() {
            let operation: Operation = bincode::deserialize(&entry.data).map_err(|_| StateError::IntegrityViolation)?;
            reconstructed.insert(operation.change.key, operation.change.value);
        }
        if reconstructed != self.state {
            return Err(StateError::IntegrityViolation);
        }
        Ok(())
    }

    /// Gets current version (chain length).
    pub fn version(&self) -> usize {
        self.chain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_identity::IdentityFabric;

    fn setup_fabric() -> IdentityFabric {
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("alice", hash(b"alice")).unwrap();
        fabric.register_identity("bob", hash(b"bob")).unwrap();
        // Delegate authority
        let proof = hash(b"alicealicewrite");
        fabric.delegate("alice", "alice", "write", proof).unwrap();
        fabric
    }

    #[test]
    fn test_versioned_state_evolution() {
        let mut state = StateLayer::new();
        let fabric = setup_fabric();

        let change = Change { key: "k1".to_string(), value: b"v1".to_vec() };
        let proof = hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &change)).unwrap());
        let operation = Operation { identity: "alice".to_string(), scope: "write".to_string(), change, proof };

        let version = state.apply_operation(operation, &fabric).unwrap();
        assert_eq!(version, 1);
        assert_eq!(state.get("k1"), Some(&b"v1".to_vec()));
        assert_eq!(state.version(), 1);

        // Another operation
        let change2 = Change { key: "k2".to_string(), value: b"v2".to_vec() };
        let proof2 = hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &change2)).unwrap());
        let operation2 = Operation { identity: "alice".to_string(), scope: "write".to_string(), change: change2, proof: proof2 };

        let version2 = state.apply_operation(operation2, &fabric).unwrap();
        assert_eq!(version2, 2);
        assert_eq!(state.version(), 2);
        assert!(state.verify().is_ok());
    }

    #[test]
    fn test_fork_correctness() {
        let mut state = StateLayer::new();
        let fabric = setup_fabric();

        let change = Change { key: "k".to_string(), value: b"v".to_vec() };
        let proof = hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &change)).unwrap());
        let operation = Operation { identity: "alice".to_string(), scope: "write".to_string(), change, proof };

        state.apply_operation(operation, &fabric).unwrap();

        let forked = state.fork();
        assert_eq!(forked.get("k"), Some(&b"v".to_vec()));
        assert_eq!(forked.version(), 1);
        assert!(forked.verify().is_ok());

        // Original and fork diverge
        let change2 = Change { key: "k2".to_string(), value: b"v2".to_vec() };
        let proof2 = hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &change2)).unwrap());
        let operation2 = Operation { identity: "alice".to_string(), scope: "write".to_string(), change: change2, proof: proof2 };

        state.apply_operation(operation2, &fabric).unwrap();
        assert_eq!(state.version(), 2);
        assert_eq!(forked.version(), 1); // Fork unchanged
    }

    #[test]
    fn test_detection_unauthorized_transition() {
        let mut state = StateLayer::new();
        let fabric = setup_fabric();

        // Bob tries to write without authority
        let change = Change { key: "k".to_string(), value: b"v".to_vec() };
        let proof = hash(&bincode::serialize(&("bob".to_string(), "write".to_string(), &change)).unwrap());
        let operation = Operation { identity: "bob".to_string(), scope: "write".to_string(), change, proof };

        assert!(matches!(state.apply_operation(operation, &fabric), Err(StateError::Unauthorized)));
    }

    #[test]
    fn test_detection_tampered_transition() {
        let mut state = StateLayer::new();
        let fabric = setup_fabric();

        let change = Change { key: "k".to_string(), value: b"v".to_vec() };
        let wrong_proof = hash(b"wrong");
        let operation = Operation { identity: "alice".to_string(), scope: "write".to_string(), change, proof: wrong_proof };

        assert!(matches!(state.apply_operation(operation, &fabric), Err(StateError::InvalidProof)));
    }

    #[test]
    fn test_detection_corruption() {
        let mut state = StateLayer::new();
        let fabric = setup_fabric();

        let change = Change { key: "k".to_string(), value: b"v".to_vec() };
        let proof = hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &change)).unwrap());
        let operation = Operation { identity: "alice".to_string(), scope: "write".to_string(), change, proof };

        state.apply_operation(operation, &fabric).unwrap();

        // Tamper state
        if let Some(val) = state.state.get_mut("k") {
            val.push(b'x');
        }

        assert!(matches!(state.verify(), Err(StateError::IntegrityViolation)));
    }
}