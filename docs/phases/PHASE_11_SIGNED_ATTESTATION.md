# Phase 11: Signed Attestation

## Overview

Phase 11 introduces cryptographically signed attestation statements using Ed25519.
This enables verifiable claims about system state without enforcement.

**Critical: Signed attestation only. No enforcement in this phase.**

## What Phase 11 Does

- Generates Ed25519 signatures on attestation statements
- Binds evidence bundles, boot measurements, and invariant results
- Provides explicit signature verification with public key
- Requires `--dangerous` flag for all signing operations
- Outputs key fingerprint for verification tracking

## What Phase 11 Does NOT Do

Phase 11 explicitly does NOT:

1. **Enforce policy** - Signed attestation does not control execution
2. **Grant authorization** - Attestation is not authorization
3. **Prove identity** - Attestation is not authentication
4. **Auto-generate keys** - Keys must be explicitly created
5. **Use trust stores** - Verification requires explicit public key
6. **Access hardware** - No TPM or HSM operations
7. **Make network calls** - All operations are offline

## Threat Model

### In Scope

- Detecting tampering of attestation statements
- Binding attestation to specific signing key
- Providing non-repudiation for attestation content

### Out of Scope

- Key management and rotation
- Trust establishment
- Revocation checking
- Time-stamping authority
- Multi-party attestation

## Why --dangerous is Required

The `--dangerous` flag is required for signed attestation because:

1. **Explicit consent** - Signing commits you to the attestation content
2. **Key usage awareness** - Using a key has security implications
3. **No silent operations** - Cryptographic operations should be intentional
4. **Audit trail** - The flag provides clear indication of user intent

## CLI Interface

### Generate Unsigned Attestation (Default)

```bash
aictrl attest generate
```

Outputs warning about unsigned status.

### Generate Signed Attestation

```bash
aictrl attest generate --key /path/to/key.pem --dangerous
```

Requires:
- `--key` - Path to Ed25519 private key
- `--dangerous` - Explicit acknowledgment

### Verify Signature

```bash
aictrl attest verify --statement /path/to/attestation.json --pubkey /path/to/key.pem.pub
```

Requires:
- `--statement` - Path to attestation statement
- `--pubkey` - Path to public key (no trust store)

## Signed Attestation Content

A signed attestation includes:

| Field | Description |
|-------|-------------|
| `signature.signed` | Boolean: true for signed statements |
| `signature.algorithm` | "Ed25519" |
| `signature.content_hash` | SHA-256 of signed content |
| `signature.value` | Base64-encoded signature |
| `signature.key_fingerprint` | First 16 chars of pubkey SHA-256 |

## Safety Guarantees

1. Missing `--dangerous` returns exit code 2
2. Wrong public key verification fails explicitly
3. Tampered content is detected via hash mismatch
4. All operations produce ASCII-only output
5. No implicit key loading or trust

## Baseline Tests

| Test ID | Description |
|---------|-------------|
| BL-210 | Unsigned attestation emits warning |
| BL-211 | Signed attestation includes valid signature |
| BL-212 | Verification fails with wrong public key |
| BL-213 | Tampered attestation fails verification |
| BL-214 | Missing --dangerous fails safely |

## Related Documentation

- [Attestation Model](../security/ATTESTATION_MODEL.md)
- [Crypto Operations](../security/CRYPTO_OPERATIONS.md)

## Version History

- v1.3.0: Phase 11 initial release
