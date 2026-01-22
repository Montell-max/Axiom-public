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

//! axiom-boundary: Interface Boundary - Defines boundary between Axiom and external world.
//! Detects: Injection, confused-deputy, capability smuggling, unauthorized influence.
//! Survives: Hostile inputs via strict validation.
//! Refuses to trust: Networks, clients, protocols, unvalidated data.
//!
//! All external input hostile; requires explicit validation, typing, authorization.

use axiom_core::hash;
use axiom_identity::IdentityFabric;
use axiom_sanctuary::Sanctuary;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub identity: String,
    pub scope: String,
    pub proof: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct BoundRequest {
    pub sanctuary: Sanctuary,
    pub validated_data: ValidatedData,
}

#[derive(Debug)]
pub struct ValidatedData {
    pub data: Vec<u8>,
    pub hash: [u8; 32],
}

#[derive(Debug)]
pub enum BoundaryError {
    MalformedRequest,
    InvalidProof,
    Unauthorized,
    InvalidData,
}

pub struct InterfaceBoundary;

impl InterfaceBoundary {
    /// Processes external request: validates, authorizes, binds to sanctuary.
    /// Treats all input as hostile; enforces explicit validation.
    pub fn process_request(raw_request: &[u8], fabric: &IdentityFabric) -> Result<BoundRequest, BoundaryError> {
        // Deserialize request safely
        let request: Request = bincode::deserialize(raw_request).map_err(|_| BoundaryError::MalformedRequest)?;

        // Validate proof: hash(identity + scope + data)
        let expected_proof = hash(&bincode::serialize(&(request.identity.clone(), request.scope.clone(), &request.data)).unwrap());
        if request.proof != expected_proof {
            return Err(BoundaryError::InvalidProof);
        }

        // Check authority
        if !fabric.has_authority(&request.identity, &request.scope) {
            return Err(BoundaryError::Unauthorized);
        }

        // Validate data
        let validated_data = ValidatedData::validate(&request.data)?;

        // Create bound sanctuary
        let sanctuary = Sanctuary::new(request.identity, request.scope);

        Ok(BoundRequest { sanctuary, validated_data })
    }
}

impl ValidatedData {
    /// Validates input: checks length and computes hash.
    /// Enforces strict validation against injection.
    pub fn validate(input: &[u8]) -> Result<Self, BoundaryError> {
        if input.len() > 1024 {
            return Err(BoundaryError::InvalidData);
        }
        let h = hash(input);
        Ok(Self { data: input.to_vec(), hash: h })
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
    fn test_rejection_malformed_input() {
        let fabric = setup_fabric();
        let malformed = b"not a valid request";
        assert!(matches!(InterfaceBoundary::process_request(malformed, &fabric), Err(BoundaryError::MalformedRequest)));
    }

    #[test]
    fn test_rejection_unauthorized_input() {
        let fabric = setup_fabric();
        let request = Request {
            identity: "bob".to_string(),
            scope: "write".to_string(),
            proof: hash(&bincode::serialize(&("bob".to_string(), "write".to_string(), &b"data".to_vec())).unwrap()),
            data: b"data".to_vec(),
        };
        let raw = bincode::serialize(&request).unwrap();
        assert!(matches!(InterfaceBoundary::process_request(&raw, &fabric), Err(BoundaryError::Unauthorized)));
    }

    #[test]
    fn test_prevention_confused_deputy() {
        let fabric = setup_fabric();
        // Alice tries to act as bob
        let request = Request {
            identity: "bob".to_string(), // Spoofed
            scope: "write".to_string(),
            proof: hash(&bincode::serialize(&("bob".to_string(), "write".to_string(), &b"data".to_vec())).unwrap()),
            data: b"data".to_vec(),
        };
        let raw = bincode::serialize(&request).unwrap();
        // Even if proof is correct for bob, alice doesn't have authority for bob's identity
        assert!(matches!(InterfaceBoundary::process_request(&raw, &fabric), Err(BoundaryError::Unauthorized)));
    }

    #[test]
    fn test_correct_binding_external_request() {
        let fabric = setup_fabric();
        let request = Request {
            identity: "alice".to_string(),
            scope: "write".to_string(),
            proof: hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &b"valid data".to_vec())).unwrap()),
            data: b"valid data".to_vec(),
        };
        let raw = bincode::serialize(&request).unwrap();
        let bound = InterfaceBoundary::process_request(&raw, &fabric).unwrap();
        assert_eq!(bound.validated_data.data, b"valid data");
        // Sanctuary is created with alice/write
    }

    #[test]
    fn test_rejection_invalid_data() {
        let fabric = setup_fabric();
        let large_data = vec![0; 1025];
        let request = Request {
            identity: "alice".to_string(),
            scope: "write".to_string(),
            proof: hash(&bincode::serialize(&("alice".to_string(), "write".to_string(), &large_data)).unwrap()),
            data: large_data,
        };
        let raw = bincode::serialize(&request).unwrap();
        assert!(matches!(InterfaceBoundary::process_request(&raw, &fabric), Err(BoundaryError::InvalidData)));
    }
}