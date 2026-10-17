# Security Policy: langchain-nti

## Security Philosophy

`langchain-nti` provides post-quantum cryptographic security and Zero-Trust policy enforcement for LangChain AI agents using NTI (Neutral Trust Infrastructure). Security is our highest priority.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Cryptographic Standards & Standards Compliance

- **Post-Quantum Signatures:** NIST CRYSTALS-Dilithium5 (NIST Level 5) via `ube_foundation`.
- **Envelope Encryption:** NIST CRYSTALS-Kyber1024 + ChaCha20Poly1305.
- **Zero-Trust Policy Engine:** Real-time capability authorization and caveat enforcement.
- **Audit Logging:** SHA-256 Merkle-chained audit trails.

## Reporting Vulnerabilities

If you discover a potential security vulnerability within `langchain-nti`, please do **NOT** open a public issue.

Instead, please send a report to `abisheakp197@gmail.com` with:
1. A description of the vulnerability and its potential impact.
2. Steps to reproduce or proof-of-concept code.
3. Affected versions.

We will acknowledge receipt within 24 hours and provide regular updates until the issue is resolved.

## Security Guarantees

- **Fail-Closed Execution:** Any cryptographic signature failure, missing capability, or policy evaluation error halts tool execution (`raise_error = True`).
- **Zero Private Key Exposure:** Private cryptographic key material is never exposed in log outputs, error strings, or external LangChain messages.
