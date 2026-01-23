# Axiom Public Layer

Axiom Public is the **verifiable, protocol-critical, open-source layer** of the Axiom Secure Compute Environment.

## What is Axiom Public?

Axiom Public implements:
- **Cryptographic core** — Verifiable hashing and signing (axiom-core)
- **Identity & authority** — Unambiguous identity claims and delegation (axiom-identity)
- **Integrity chains** — Append-only, tamper-evident logs (axiom-integrity)
- **Execution sanctuaries** — Isolated, authority-bound execution contexts (axiom-sanctuary)
- **Versioned state** — Authoritative, auditable state management (axiom-state)
- **Boundary validation** — Hostile input handling and authorization (axiom-boundary)
- **Reference demonstration** — Secure key-value store example (axiom-demo)

**Axiom Public is the protocol layer.** It contains no:
- Runtime services or hosted infrastructure
- Telemetry, analytics, or phone-home behavior
- Enterprise acceleration or proprietary optimization
- Assumption of centralized authority

## License

Axiom Public is licensed under the **Apache License 2.0**.

Copyright © 2026 Axiom Project Contributors

All source files in the public layer include the Apache 2.0 header. See [LICENSE](LICENSE) for the complete legal text.

**Contributors to Axiom Public grant rights to the public verification layer only. Contributions do NOT grant rights to proprietary enterprise components.**

## Open Core Model

### Axiom Public is Fully Open and Forkable

- The protocol, verification logic, and identity model are **public by design**
- Anyone may fork the entire Axiom Public codebase **without permission**
- Verification and cryptographic correctness are **verifiable and auditable**
- No hidden dependencies on proprietary services or centralized authority

### AIVE is Separate and Optional

- **AIVE** (enterprise compute acceleration) is a **separate, proprietary component**
- AIVE is **not** included in Axiom Public
- AIVE is **optional** — the public verification layer is correct without it
- Commercial acceleration and monetizable primitives live in `enterprise/` only

### Public Verification Remains Correct Without Enterprise Components

- The public codebase makes **no assumptions** about enterprise acceleration
- Verification, integrity, and identity work correctly with or without proprietary components
- Public verification does **not depend on** enterprise layers
- Enterprise components **may depend on** public layers (one-way dependency rule)

### Contributors to Public Layer Do NOT Grant Rights to Proprietary Components

When you contribute to Axiom Public, you are granting rights **to the public verification layer only**.

- Your contribution does **not** grant rights to commercial implementations
- Proprietary enterprise code is **separate and licensed separately**
- The Apache 2.0 license applies **only to Axiom Public**
- Enterprise licensing is handled independently

## Security Model

### Verification Logic is Public by Design

- All cryptographic verification is **open-source and auditable**
- Proof generation and validation are **transparent**
- There is **no security through obscurity** — all verification can be inspected
- Anyone can verify that identity, integrity, and authority claims are cryptographically sound

### User Data and Histories are Never Public

- While **verification logic** is public, **user data is private**
- Identity claims are verifiable without exposing the underlying identity
- State histories are immutable and auditable without being globally visible
- Access control ensures only authorized parties see data

### Public Verifiability Does Not Imply Public Visibility

- **Public** means the verification logic and protocols are open
- **Visible** means accessible to all parties — not the case
- A user's data history is:
  - **Verifiable**: Anyone can audit the cryptographic proofs
  - **Private**: Only authorized parties can see the content
  - **Immutable**: Tampering is cryptographically detectable
  - **Auditable**: The owner controls visibility of their audit log

## Relationship to Enterprise Components

```
┌─ Axiom Public (Apache 2.0)
│  ├─ axiom-core (cryptographic primitives)
│  ├─ axiom-identity (verifiable claims)
│  ├─ axiom-integrity (append-only logs)
│  ├─ axiom-sanctuary (execution contexts)
│  ├─ axiom-state (versioned state)
│  ├─ axiom-boundary (input validation)
│  └─ axiom-demo (reference implementation)
│
└─ Enterprise (Proprietary, Separate)
   ├─ AIVE (acceleration & optimization)
   └─ Billing (commercial services)
```

**Dependency Rule:**
- ✅ Public can **not** depend on Enterprise (no coupling)
- ✅ Enterprise can depend on Public (leverage verification)
- ✅ No circular imports
- ✅ No hidden protocol authority in Enterprise code

## Principles

All code in Axiom Public enforces:

1. **No security through obscurity** — All verification is transparent
2. **Forkability without permission** — Use standard algorithms, no proprietary gates
3. **No ambiguous identity** — Claims are verifiable, not assumed
4. **No implicit trust** — Authority is explicit and delegatable
5. **No undetectable state changes** — All state transitions are logged
6. **Integrity over convenience** — Correctness first, optimization optional
7. **Forkability survives compromise** — The codebase works correctly even if components fail

## Development

All public source files include Apache 2.0 headers. When adding new files to the public layer:

```rust
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
```

## Contributing

Contributions to Axiom Public are welcome under the Apache 2.0 license. By contributing, you:

- Grant a perpetual, worldwide, non-exclusive license to your contribution
- Agree that your contribution is available under Apache 2.0
- Understand that contributors are **not** granting rights to proprietary enterprise components
- Certify that you have the right to grant such a license

## Questions?

- See the root [README.md](../README.md) for Axiom system overview
- See individual crate READMEs and design documents for technical details
- Review [LICENSE](LICENSE) for the complete Apache 2.0 legal text

---

**Axiom Public: Open, Verifiable, Forkable.**
