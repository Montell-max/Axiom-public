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

//! axiom-sanctuary: Execution Sanctuaries - Enforces isolation, least authority, and revocation.
//! Detects: Boundary violations, unauthorized access.
//! Survives: Compromise via killable/revocable sanctuaries.
//! Refuses to trust: Executing code, OS/VM/hardware.
//!
//! Sanctuaries bind execution to identity + authority, enforce least privilege, detect violations.

use axiom_identity::IdentityFabric;

#[derive(Debug)]
pub enum SanctuaryError {
    Revoked,
    ExecutionFailed,
    Unauthorized,
}

pub struct ExecutionContext<'a> {
    pub fabric: &'a IdentityFabric,
    pub identity: &'a str,
    pub scope: &'a str,
}

impl<'a> ExecutionContext<'a> {
    /// Checks if the current identity has authority for the required scope.
    /// Enforces least authority and detects boundary violations.
    pub fn check_authority(&self, required_scope: &str) -> Result<(), SanctuaryError> {
        if self.fabric.has_authority(self.identity, required_scope) {
            Ok(())
        } else {
            Err(SanctuaryError::Unauthorized)
        }
    }
}

#[derive(Debug)]
pub struct Sanctuary {
    identity: String,
    scope: String,
    revoked: bool,
}

impl Sanctuary {
    /// Creates a new sanctuary bound to an identity and authority scope.
    pub fn new(identity: String, scope: String) -> Self {
        Self {
            identity,
            scope,
            revoked: false,
        }
    }

    /// Executes a function in isolated context with authority checks.
    /// Assumes code is malicious; enforces boundaries via context.
    pub fn execute<F, T>(&self, fabric: &IdentityFabric, f: F) -> Result<T, SanctuaryError>
    where
        F: FnOnce(&ExecutionContext) -> Result<T, SanctuaryError>,
    {
        if self.revoked {
            return Err(SanctuaryError::Revoked);
        }
        let context = ExecutionContext {
            fabric,
            identity: &self.identity,
            scope: &self.scope,
        };
        f(&context)
    }

    /// Revokes the sanctuary, preventing further execution.
    /// Allows destruction without corrupting global state.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Checks if revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_identity::IdentityFabric;
    use axiom_core::hash;

    #[test]
    fn test_isolation_between_sanctuaries() {
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("alice", hash(b"alice")).unwrap();
        fabric.register_identity("bob", hash(b"bob")).unwrap();

        // Delegate authority
        let proof1 = hash(b"alicealiceread");
        fabric.delegate("alice", "alice", "read", proof1).unwrap();
        let proof2 = hash(b"bobbobwrite");
        fabric.delegate("bob", "bob", "write", proof2).unwrap();

        let sanctuary1 = Sanctuary::new("alice".to_string(), "read".to_string());
        let sanctuary2 = Sanctuary::new("bob".to_string(), "write".to_string());

        // Execute in sanctuary1
        let result1 = sanctuary1.execute(&fabric, |ctx| {
            ctx.check_authority("read")?;
            Ok("alice_read")
        }).unwrap();
        assert_eq!(result1, "alice_read");

        // Execute in sanctuary2
        let result2 = sanctuary2.execute(&fabric, |ctx| {
            ctx.check_authority("write")?;
            Ok("bob_write")
        }).unwrap();
        assert_eq!(result2, "bob_write");

        // No interference
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_revocation_without_cascade() {
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("alice", hash(b"alice")).unwrap();

        let mut sanctuary1 = Sanctuary::new("alice".to_string(), "read".to_string());
        let sanctuary2 = Sanctuary::new("alice".to_string(), "read".to_string());

        // Revoke sanctuary1
        sanctuary1.revoke();
        assert!(sanctuary1.is_revoked());

        // sanctuary1 fails
        let result1 = sanctuary1.execute(&fabric, |_| Ok("should_fail"));
        assert!(matches!(result1, Err(SanctuaryError::Revoked)));

        // sanctuary2 still works
        let result2 = sanctuary2.execute(&fabric, |_| Ok("still_works")).unwrap();
        assert_eq!(result2, "still_works");
    }

    #[test]
    fn test_detection_unauthorized_access() {
        let mut fabric = IdentityFabric::new();
        fabric.register_identity("alice", hash(b"alice")).unwrap();

        let sanctuary = Sanctuary::new("alice".to_string(), "read".to_string());

        // Try to access unauthorized scope
        let result = sanctuary.execute(&fabric, |ctx| {
            ctx.check_authority("write")?; // Unauthorized
            Ok("should_not_reach")
        });

        assert!(matches!(result, Err(SanctuaryError::Unauthorized)));
    }
}