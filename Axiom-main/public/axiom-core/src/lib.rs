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

//! axiom-core: Enforces "No security through obscurity" and "Forkability without permission" by providing minimal, public cryptographic primitives.
//! Detects: Weak or obscured crypto attacks.
//! Survives: Compromised implementations via proofs.
//! Refuses to trust: Proprietary algorithms or human-verified security.

use sha2::{Digest, Sha256};
use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};

pub type Hash = [u8; 32];
pub type PubKey = VerifyingKey;
pub type PrivKey = SigningKey;
pub type Sig = Signature;

/// Computes a SHA-256 hash of the input data.
/// Enforces forkability by using standard, verifiable hashing.
pub fn hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verifies a signature against a public key and message.
/// Enforces no obscurity by using open crypto; detects invalid sigs as attacks.
pub fn verify_sig(pubkey: &PubKey, msg: &[u8], sig: &Sig) -> bool {
    pubkey.verify(msg, sig).is_ok()
}

/// Signs a message with a private key.
/// For completeness, but keys are not trusted for authority.
pub fn sign(privkey: &PrivKey, msg: &[u8]) -> Sig {
    privkey.sign(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"test";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sig_verify() {
        let secret_key_bytes = [0u8; 32];
        let privkey = SigningKey::from_bytes(&secret_key_bytes);
        let pubkey = privkey.verifying_key();
        let msg = b"message";
        let sig = sign(&privkey, msg);
        assert!(verify_sig(&pubkey, msg, &sig));
        assert!(!verify_sig(&pubkey, b"wrong", &sig));
    }
}