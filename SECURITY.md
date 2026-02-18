# Security Policy

## Project
**VaultWire** — MERN-based PKI-enabled security platform for:
- user/admin portals
- encrypted vault sharing
- digital signatures and verification
- certificate lifecycle management
- secure messaging with expiry controls

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes     |
| <1.0    | ❌ No      |

---

## Reporting a Vulnerability

If you discover a security issue, please report privately:

- Contact: **[your-email-here]**
- Subject: `VaultWire Security Report`
- Include:
  - clear reproduction steps
  - affected module(s)
  - impact level (confidentiality / integrity / availability)
  - proof-of-concept if possible

Please do **not** disclose publicly before a fix is available.

---

## Security Architecture Summary

VaultWire applies layered controls across authentication, PKI, cryptography, and auditability:

1. **Authentication & Authorization**
   - Role-based access control (user/admin/superadmin separation)
   - JWT-based authenticated routes
   - Protected admin-only operations for CA and governance actions

2. **PKI & Certificate Lifecycle**
   - CA initialization (admin action)
   - certificate issue / renew / revoke
   - certificate validity checks on sensitive operations

3. **Cryptographic Controls**
   - Digital signatures for authenticity and integrity checks
   - Hybrid encryption for vault files (symmetric payload encryption + per-recipient key wrapping)
   - Hash verification (SHA-256) in signature workflow

4. **Secure Storage**
   - sensitive key material stored encrypted at rest
   - environment-based secret management (no hardcoded production secrets)

5. **Operational Controls**
   - audit logging for critical actions
   - replay protection patterns in message flow
   - file size limits and input validation on uploads

---

## Cryptography Used

- **Digital Signatures:** RSA signing/verification workflow
- **Asymmetric Cryptography:** RSA and ECC usage for key exchange/wrapping contexts
- **Symmetric Cryptography:** AES-GCM based payload protection
- **Hashing:** SHA-256 integrity checks

> Note: cryptographic primitives and implementation details are for coursework demonstration and should be independently security-reviewed before production use.

---

## Key Management Policy

- User private keys are stored in encrypted form.
- Public keys are used for verification and recipient-specific key wrapping.
- Certificate lifecycle is governed by admin PKI actions.
- Key exposure prevention relies on secure server secret management and restricted admin access.

---

## Transport and MITM Defense

- Intended deployment is behind HTTPS/TLS.
- Plain HTTP deployment is not considered secure for production.
- Production should enforce:
  - secure cookies
  - strict CORS allowlist
  - HSTS
  - reverse proxy TLS termination with modern cipher settings

---

## Known Limitations

1. **Messaging E2EE scope**
   - Current design provides strong encrypted messaging controls but is not positioned as full Signal-style, client-only double-ratchet E2EE.
   - This is tracked as future enhancement.

2. **Key custody model**
   - Current key protection is application-level encrypted storage, not external HSM-backed custody.

3. **Coursework demo credentials**
   - Any demo hardcoded admin credentials are for local evaluation only and must be removed for production.

---

## Security Testing Coverage

The project includes tests/demos for:
- authorized vs unauthorized access paths
- signing + verification success
- tamper detection via hash/signature mismatch
- certificate lifecycle effects (issue/revoke/renew)
- encrypted vault access control by recipient

Recommended additional hardening tests:
- TLS downgrade/MITM simulation in deployment
- expanded replay and nonce abuse test suite
- full threat-model walkthrough per module

---

## Secrets Handling Guidelines

- Never commit `.env` or private keys to Git.
- Use `.env.example` with placeholders only.
- Rotate secrets before deployment.
- Use different secrets per environment (dev/stage/prod).

---

## Dependency and Supply-Chain Hygiene

- Keep dependencies updated.
- Run vulnerability scans (`npm audit` / CI security checks).
- Pin critical dependency versions where practical.
- Review transitive dependency risk before release.

---

## Responsible Disclosure Process

1. Receive report privately
2. Validate issue
3. Assign severity
4. Fix and test
5. Release patch
6. Publish advisory summary (without exposing sensitive exploit details)
