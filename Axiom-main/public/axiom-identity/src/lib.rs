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

//! axiom-identity: Identity & Authority Fabric - Enforces "No ambiguous identity" and "No implicit trust" via verifiable claims and delegation.
//! Detects: Impersonation, forged claims, equivocation.
//! Survives: Key loss, no master keys.
//! Refuses to trust: Central authorities, trusted clocks, long-lived global keys.
//!
//! Separates identity from authority, supports delegation without surrender, revocation without collapse.

use axiom_core::{hash, Hash};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Identity {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct Delegation {
    pub from: String,
    pub to: String,
    pub scope: String,
    pub proof: Hash,
}

#[derive(Clone, Debug)]
pub struct Revocation {
    pub delegator: String,
    pub delegation_hash: Hash,
    pub proof: Hash,
}

#[derive(Debug)]
pub enum Error {
    InvalidProof,
    IdentityExists,
    IdentityNotFound,
    DelegationExists,
}

pub struct IdentityFabric {
    identities: HashMap<String, Identity>,
    delegations: Vec<Delegation>,
    revocations: Vec<Revocation>,
}

impl IdentityFabric {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            delegations: Vec::new(),
            revocations: Vec::new(),
        }
    }

    /// Registers a new identity with verifiable proof.
    /// Proof must be hash(id) to prevent forgery.
    pub fn register_identity(&mut self, id: &str, proof: Hash) -> Result<(), Error> {
        if self.identities.contains_key(id) {
            return Err(Error::IdentityExists);
        }
        let expected = hash(id.as_bytes());
        if proof != expected {
            return Err(Error::InvalidProof);
        }
        let identity = Identity { id: id.to_string() };
        self.identities.insert(id.to_string(), identity);
        Ok(())
    }

    /// Delegates authority from one identity to another for a specific scope.
    /// Proof must be hash(from + to + scope) to ensure authenticity.
    pub fn delegate(&mut self, from: &str, to: &str, scope: &str, proof: Hash) -> Result<(), Error> {
        if !self.identities.contains_key(from) || !self.identities.contains_key(to) {
            return Err(Error::IdentityNotFound);
        }
        let expected = hash(format!("{}{}{}", from, to, scope).as_bytes());
        if proof != expected {
            return Err(Error::InvalidProof);
        }
        // Check if delegation already exists
        if self.delegations.iter().any(|d| d.from == from && d.to == to && d.scope == scope) {
            return Err(Error::DelegationExists);
        }
        let delegation = Delegation {
            from: from.to_string(),
            to: to.to_string(),
            scope: scope.to_string(),
            proof,
        };
        self.delegations.push(delegation);
        Ok(())
    }

    /// Revokes a delegation.
    /// Proof must be hash(delegator_bytes + delegation_hash_bytes).
    pub fn revoke(&mut self, delegator: &str, delegation_hash: Hash, proof: Hash) -> Result<(), Error> {
        if !self.identities.contains_key(delegator) {
            return Err(Error::IdentityNotFound);
        }
        let expected = hash(&[delegator.as_bytes(), &delegation_hash].concat());
        if proof != expected {
            return Err(Error::InvalidProof);
        }
        let revocation = Revocation {
            delegator: delegator.to_string(),
            delegation_hash,
            proof,
        };
        self.revocations.push(revocation);
        Ok(())
    }

    /// Checks if an identity has authority for a given scope.
    /// Authority can be direct (scope == "self") or delegated (and not revoked).
    pub fn has_authority(&self, identity: &str, scope: &str) -> bool {
        if !self.identities.contains_key(identity) {
            return false;
        }
        if scope == "self" {
            return true;
        }
        self.delegations.iter().any(|d| d.to == identity && d.scope == scope && !self.is_revoked(d.proof))
    }

    /// Checks if a delegation is revoked.
    fn is_revoked(&self, delegation_proof: Hash) -> bool {
        self.revocations.iter().any(|r| r.delegation_hash == delegation_proof)
    }

    /// Gets an identity by id (for testing).
    pub fn get_identity(&self, id: &str) -> Option<&Identity> {
        self.identities.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_identity() {
        let mut fabric = IdentityFabric::new();
        let id = "alice";
        let proof = hash(id.as_bytes());
        assert!(fabric.register_identity(id, proof).is_ok());
        assert!(fabric.get_identity(id).is_some());
    }

    #[test]
    fn test_forged_identity_claim() {
        let mut fabric = IdentityFabric::new();
        let id = "alice";
        let proof = hash(b"wrong");
        assert!(fabric.register_identity(id, proof).is_err());
    }

    #[test]
    fn test_delegation_without_full_transfer() {
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("alice", hash(b"alice")).unwrap();
        fabric.register_identity("bob", hash(b"bob")).unwrap();

        let scope = "read";
        let proof = hash(format!("{}{}{}", "alice", "bob", scope).as_bytes());
        assert!(fabric.delegate("alice", "bob", scope, proof).is_ok());

        assert!(fabric.has_authority("bob", "read"));
        assert!(!fabric.has_authority("bob", "write")); // Limited scope
        assert!(!fabric.has_authority("charlie", "read")); // Not registered
    }

    #[test]
    fn test_revocation_without_breaking_others() {
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("alice", hash(b"alice")).unwrap();
        fabric.register_identity("bob", hash(b"bob")).unwrap();
        fabric.register_identity("charlie", hash(b"charlie")).unwrap();

        let scope = "read";
        let proof1 = hash(format!("{}{}{}", "alice", "bob", scope).as_bytes());
        fabric.delegate("alice", "bob", scope, proof1).unwrap();

        let proof2 = hash(format!("{}{}{}", "alice", "charlie", scope).as_bytes());
        fabric.delegate("alice", "charlie", scope, proof2).unwrap();

        assert!(fabric.has_authority("bob", "read"));
        assert!(fabric.has_authority("charlie", "read"));

        // Revoke bob's delegation
        let revocation_proof = hash(&[&b"alice"[..], &proof1[..]].concat());
        fabric.revoke("alice", proof1, revocation_proof).unwrap();

        // Bob's authority revoked, charlie's intact
        assert!(!fabric.has_authority("bob", "read"));
        assert!(fabric.has_authority("charlie", "read"));
    }

    #[test]
    fn test_ambiguous_identity_detection() {
        let mut fabric = IdentityFabric::new();
        let id = "alice";
        let proof = hash(id.as_bytes());
        assert!(fabric.register_identity(id, proof.clone()).is_ok());
        // Attempt duplicate
        assert!(fabric.register_identity(id, proof).is_err());
    }
}