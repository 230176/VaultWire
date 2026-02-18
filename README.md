## Security Model

VaultWire applies layered security controls across authentication, PKI, cryptography, and auditing.

### 1) Authentication and Authorization
- JWT-protected APIs
- Role-based separation (`user`, `admin`, `superadmin`)
- Admin-only PKI governance actions

### 2) PKI and Certificate Lifecycle
- Certificate Authority (CA) initialization
- Certificate issue, renewal, and revocation
- Certificate validity checks on sensitive routes

### 3) Cryptographic Controls
- Digital signatures for authenticity and integrity
- Hybrid encryption for vault files (symmetric encryption + per-recipient key wrapping)
- SHA-256 hashing in signature workflows

### 4) Key Management
- User private keys are stored in encrypted form
- Public keys are used for verification and recipient wrapping
- Sensitive actions are certificate-gated and audited

### 5) Auditability and Abuse Controls
- Audit logs for security-critical actions
- Replay-resistance patterns in messaging
- Input validation and file-size limits for upload surfaces

---

## Security Testing Summary

Validated flows include:
- authorized vs unauthorized access attempts
- sign + verify success path
- tamper detection (hash/signature mismatch)
- certificate lifecycle checks (issue/revoke/renew effects)
- recipient-based encrypted vault access

---

## Limitations and Future Enhancements

- Messaging provides strong encrypted protections but is not currently positioned as full Signal-style client-only double-ratchet E2EE.
- Key custody is application-level encrypted storage, not external HSM-backed custody.
- Coursework demo credentials are for local evaluation only and must be removed before real deployment.

Planned improvements:
- full client-only E2EE message protocol with ratcheting
- stronger production hardening (TLS policy, security headers, key-rotation automation)
- expanded attack simulation coverage and reporting

---

## Responsible Use Notice

This project is developed for academic coursework and demonstration.  
Before production use, perform independent security review, penetration testing, and infrastructure hardening.

---

## License

This project is licensed under the MIT License.  
See the [LICENSE](./LICENSE) file.
