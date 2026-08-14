# NepShield

NepShield is a FastAPI and MongoDB cybersecurity thesis application. The current milestone provides browser authentication, server-managed sessions, employee and administrator authorization, auditing, administrator-managed employee accounts, an encrypted employee vault, and controlled non-owner document sharing.

## Set up

In PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Configure `MONGODB_URI` and `MONGODB_DATABASE` in the process environment as needed. Their local defaults are `mongodb://localhost:27017` and `nepshield`. Set `SESSION_COOKIE_SECURE=true` whenever the application is served over HTTPS; it defaults to `false` only in development and testing.

The employee vault additionally requires `VAULT_ENCRYPTION_KEY`, a stable URL-safe base64 encoding of 32 random bytes. Generate it once, store it in deployment secrets/environment configuration, and back it up securely:

```powershell
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

`VAULT_STORAGE_DIR` defaults to `./vault_storage`, and `VAULT_MAX_FILE_SIZE_BYTES` defaults to 1 MiB for this research build. The storage directory contains AES-256-GCM ciphertext under random physical filenames; MongoDB's `vault_documents` collection contains owner-bound metadata and nonces. Losing or changing the key makes existing documents unrecoverable.

## Create the first administrator

Start MongoDB, then run the interactive utility:

```powershell
python -m app.cli.create_admin
```

The utility prompts for the username and asks for the password twice without displaying it. Passwords must be 12–1024 characters. Usernames are normalized to lowercase and may contain 3–64 letters, numbers, dots, underscores, or hyphens.

## Run locally

```powershell
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/`. The health check remains available at `http://127.0.0.1:8000/health`.

## Run tests

```powershell
pytest
```

The tests use in-memory authentication repositories, so they do not require a running MongoDB instance.

## Administrator user management

Administrators can open **Users** from their workspace to create employee accounts, view account metadata, and disable or re-enable accounts. Creation and status changes are recorded in the append-only audit log. An administrator cannot disable the account they are currently using.

All browser forms that change state, including login and logout, require a short-lived opaque CSRF token that is issued and validated server-side.

## Controlled document access

Employees can request access to another employee's usable vault document with a required reason, review request decisions under **My Requests**, and download currently valid grants under **Shared With Me**. Administrators approve or reject pending requests with a required decision reason and may set an optional UTC expiry. Administrators can revoke active shared permissions with a required reason, but do not receive document-content access themselves.

Requests and permissions are separate retained records. Approval creates or reactivates the single permission relationship for a grantee/document pair; rejection never grants access. Download authorization is centralized and checks document usability before owner or shared access.

Administrators can use **Documents** to lock or unlock encrypted document content with a required reason. The `active`/`locked` state is stored in document metadata, while lock and unlock history is retained in the append-only audit log. A lock overrides owner and shared download access without changing ownership, requests, or permission records; administrators still receive no document-content access. Legacy documents without a state field are treated as active.

## Authentication storage

- `users`: display name, canonical unique username, Argon2id password hash, role, enabled state, and creation time
- `sessions`: SHA-256 digest of a random opaque session token, user reference, creation time, and expiration time
- `audit_events`: append-only authentication, user-management, vault, access-decision, shared-download, and revocation records
- `vault_documents`: employee owner reference, display filename, media type, size, random ciphertext storage name, AES-GCM nonce, upload time, and current governance state/lock metadata
- `access_requests`: requester/document references, request reason and time, retained pending/approved/rejected decision data, and resulting permission reference when approved
- `document_permissions`: one durable grantee/document relationship with grant, expiry, revocation state, and an embedded grant/revoke transition history

Only the `employee` and `administrator` roles are implemented. Administrator document-content access, document locking, monitoring, policies, and alerts are intentionally outside this milestone.
