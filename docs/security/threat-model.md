# Threat Model

Last updated: 2026-02-25

## Scope

In-scope components:

- Session establishment (`X3DH`-style flow)
- Message ratchet and decrypt/encrypt state transitions
- Group sender key flows
- Storage adapters and session/prekey lifecycle
- Worker-thread crypto API surface

Out-of-scope:

- Endpoint/device compromise
- Host kernel/runtime compromise
- Transport-layer guarantees outside this library

## Assets

Primary assets:

- Identity private keys
- Signed prekeys and one-time prekeys
- Session state (root keys, chain keys, pending prekeys)
- Sender key state for group messaging

Security goals:

- Forward secrecy
- Post-compromise security (ratchet evolution)
- Identity continuity / trust checks
- Anti-replay and counter monotonicity
- Integrity of persisted state transitions

## Trust Boundaries

1. `Application` -> `Library API` boundary  
2. `Library` -> `Storage adapter` boundary  
3. `Main thread` -> `Worker thread` boundary  
4. `Serialized message payload` -> `In-memory session state` boundary

## Threats and Mitigations

### Identity Substitution / MITM

Threat:

- Remote identity key substitution during session bootstrap.

Mitigations:

- `isTrustedIdentity` checks in session builder/cipher paths.
- Optional strict identity policies (`trustOnFirstUse`, `onIdentityMismatch`).
- Signature verification on signed prekey with explicit compatibility fallback signals.

Residual risk:

- Deployments using permissive TOFU without user/operator verification.

### Message Replay / Counter Reuse

Threat:

- Replay or out-of-window messages to force state confusion.

Mitigations:

- Message counter checks and replay rejection.
- Message-key deletion after use.
- Chain/key budget enforcement to bound memory/time amplification.

Residual risk:

- Operational abuse in systems that disable or bypass standard exception handling.

### State Desynchronization and Partial Writes

Threat:

- Crash during session+prekey updates leaving inconsistent state.

Mitigations:

- Atomic `storeSessionAndRemovePreKey` path.
- Transaction-aware adapters and strict guard (`requireAtomicSessionAndPreKey`).
- SQLite adapter transaction support and rollback semantics.

Residual risk:

- Non-transactional third-party adapters that do not enforce atomicity.

### Worker Abuse / Backpressure DoS

Threat:

- Flooding async API to exhaust worker queues and degrade availability.

Mitigations:

- Configurable pending/queued job limits.
- Explicit backpressure rejection path.
- Worker crash detection and automatic revival.
- Observability events for queue pressure and worker lifecycle.

Residual risk:

- Application-level abuse when limits are set too high for available resources.

### Serialization / Parser Abuse

Threat:

- Malformed protobuf payloads causing parser instability.

Mitigations:

- Size limits and field validation in codecs.
- Fuzz/property tests for malformed payload handling.

Residual risk:

- Unknown parser edge cases not covered by current corpus and generators.

## Security Validation Strategy

- Unit/integration coverage for ratchet, storage and dual-API worker branches.
- Interoperability test against upstream `WhiskeySockets/libsignal-node`.
- Dedicated fuzz suite (`npm run test:fuzz`) with property-based generators.
- CI security gates (CodeQL, dependency review, scheduled fuzz and scorecard).

## Hardening Roadmap

1. Independent third-party cryptographic review
2. Continuous corpus-based fuzzing expansion
3. Multi-runtime interoperability matrix (Node LTS + reference implementations)
4. Release provenance enforcement for all published artifacts

