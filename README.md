# CryptoDB

A cryptographic database with immutable audit ledger. All data is encrypted at rest using envelope encryption (AES-256-GCM / XChaCha20-Poly1305). Every create, read, and delete operation is recorded in a tamper-evident hash chain.

## Features

- **Envelope Encryption**: Data Encryption Keys (DEKs) encrypt records; DEKs are encrypted by a Master Key (KEK).
- **Blob Store**: Encrypted ciphertext stored on filesystem with sharded paths.
- **Metadata DB**: SQLite (async via aiosqlite) stores record metadata, users, ACLs, and audit log pointers.
- **Audit Ledger**: Immutable hash chain (SHA3-256) with Merkle-like linkage. Tamper detection via `verify_ledger()`.
- **Signed Checkpoints**: Periodic HMAC-signed ledger checkpoints prevent historical tampering.
- **Access Control**: RBAC (admin, writer, reader, auditor) + per-record ACLs.
- **Blind Search**: Deterministic searchable encryption for equality queries without decryption.
- **Homomorphic Encryption**: Paillier additive HE for encrypted sums/averages on numeric fields.
- **Replication**: Push/pull multi-node replication with TLS enforcement, dead-letter queue, and conflict resolution.
- **Hardware Tokens**: FIDO2 (YubiKey) and TPM sealing support for key protection.
- **Compliance**: Built-in GDPR, HIPAA, and SOC2 evidence exports.
- **Observability**: Prometheus metrics, structured JSON logging (structlog), health checks, and anomaly detection.

## Quick Start

### Install

```bash
pip install -e ".[dev]"
```

Build Package
```bash
pip -m build
```


### Initialize

```bash
# Create directories and DB schema
cryptodb init

# Create the master encryption key
cryptodb create-master-key
```

### Run the server

```bash
cryptodb serve
```

The API will be available at `http://127.0.0.1:8000/api/v1`. Interactive docs (Swagger UI) are at `/docs`.

### Use the CLI

```bash
# Store a file
cryptodb put secret.txt --username alice --password secret

# Retrieve a record
cryptodb get <record-id> --output recovered.txt --username alice --password secret

# View audit log
cryptodb audit --username alice --password secret

# Search by blind index
cryptodb search email alice@example.com --username alice --password secret

# List records with pagination
cryptodb list-records --page 1 --page-size 20 --username alice --password secret

# Grant/revoke record access
cryptodb grant-access <record-id> read --user-id <user-id> --username admin --password secret
cryptodb revoke-access <record-id> <grant-id> --username admin --password secret

# Purge soft-deleted records older than retention
cryptodb purge-deleted --username admin --password secret

# Export ledger
cryptodb ledger-export audit_export.json --format json --username admin --password secret

# User management (admin only)
cryptodb user-list --username admin --password secret
cryptodb user-set-role <user-id> writer --username admin --password secret
```

## Environment Variables

All configuration is driven by environment variables with the `CRYPTODB_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `CRYPTODB_DATA_DIR` | `./data` | Base directory for all data |
| `CRYPTODB_DB_PATH` | `./data/cryptodb.db` | Metadata SQLite database |
| `CRYPTODB_BLOB_DIR` | `./data/blobs` | Encrypted blob storage |
| `CRYPTODB_KEYS_DIR` | `./data/keys` | Key material directory |
| `CRYPTODB_MASTER_KEY_ID` | `master-key-v1` | Active master key identifier |
| `CRYPTODB_DEFAULT_CIPHER` | `aes-256-gcm` | Default symmetric cipher |
| `CRYPTODB_JWT_SECRET` | `change-me-in-production` | JWT signing secret |
| `CRYPTODB_JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token TTL |
| `CRYPTODB_JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token TTL |
| `CRYPTODB_GEO_ALLOW` | ` ` | Comma-separated allowed CIDRs |
| `CRYPTODB_GEO_DENY` | ` ` | Comma-separated denied CIDRs |
| `CRYPTODB_RATE_LIMIT_RPM` | `60` | Requests per minute per user |
| `CRYPTODB_RATE_LIMIT_LOGIN_RPM` | `5` | Login attempts per minute |
| `CRYPTODB_RATE_LIMIT_HW_AUTH_RPM` | `5` | Hardware auth attempts per minute |
| `CRYPTODB_MAX_RECORD_SIZE_MB` | `100` | Max record size in MB |
| `CRYPTODB_CORS_ORIGINS` | ` ` | Comma-separated CORS origins |
| `CRYPTODB_LEDGER_CHECKPOINT_INTERVAL` | `1000` | Entries between signed checkpoints |
| `CRYPTODB_WEBHOOK_URL` | ` ` | Webhook URL for critical audit events |
| `CRYPTODB_WEBHOOK_SECRET` | ` ` | HMAC secret for webhook signing |
| `CRYPTODB_PURGE_AFTER_DAYS` | `30` | Days before purging soft-deleted records |
| `CRYPTODB_INTEGRITY_SCAN_INTERVAL_HOURS` | `24` | Hours between blob integrity scans |
| `CRYPTODB_DB_POOL_SIZE` | `5` | DB connection pool size |
| `CRYPTODB_DB_MAX_OVERFLOW` | `10` | DB connection max overflow |
| `CRYPTODB_REPLICATION_ENABLED` | `false` | Enable push replication |
| `CRYPTODB_REPLICATION_ALLOW_HTTP` | `false` | Allow HTTP replication endpoints (dev only) |
| `CRYPTODB_RECOVERY_SHARDS` | `0` | Shamir secret sharing shards (0=disabled) |
| `CRYPTODB_RECOVERY_THRESHOLD` | `0` | Shamir threshold |
| `CRYPTODB_LOG_LEVEL` | `INFO` | Logging level |

## API Endpoints

### Auth
- `POST /api/v1/auth/register` — Register a new user
- `POST /api/v1/auth/login` — Login and receive JWT tokens
- `POST /api/v1/auth/logout` — Revoke current token
- `POST /api/v1/auth/refresh` — Rotate refresh token
- `POST /api/v1/auth/hardware/register-begin` — Begin FIDO2/TPM registration
- `POST /api/v1/auth/hardware/register-finish` — Complete hardware token registration
- `POST /api/v1/auth/hardware/authenticate-begin` — Begin hardware auth
- `POST /api/v1/auth/hardware/authenticate-finish` — Complete hardware auth

### Records
- `POST /api/v1/records` — Store an encrypted record
- `GET /api/v1/records/{id}` — Retrieve and decrypt a record
- `DELETE /api/v1/records/{id}` — Soft-delete a record
- `GET /api/v1/records` — List records (paginated)
- `POST /api/v1/records/search` — Search by blind index
- `POST /api/v1/records/{id}/grants` — Grant access
- `DELETE /api/v1/records/{id}/grants/{grant_id}` — Revoke access
- `GET /api/v1/records/{id}/grants` — List grants

### Audit & Ledger
- `GET /api/v1/audit` — List audit log entries
- `GET /api/v1/audit/anomalies` — Detect anomalies (off-hours, bulk access)
- `POST /api/v1/ledger/verify` — Verify ledger integrity
- `GET /api/v1/ledger/export` — Export ledger (JSON/CSV)

### Admin
- `GET /api/v1/health` — Health check with disk usage and ledger status
- `GET /api/v1/metrics` — Prometheus metrics
- `POST /api/v1/admin/purge-deleted` — Purge soft-deleted records past TTL

### Users (admin only)
- `GET /api/v1/users` — List users
- `PATCH /api/v1/users/{id}/role` — Set user role

### Replication (admin only)
- `POST /api/v1/replication/nodes` — Register a standby node
- `GET /api/v1/replication/nodes` — List nodes
- `DELETE /api/v1/replication/nodes/{id}` — Unregister a node
- `POST /api/v1/replication/health-check` — Run health checks on nodes
- `POST /api/v1/replication/retry` — Retry failed replication
- `GET /api/v1/replication/changes` — Pull replication feed
- `POST /api/v1/replication/reset-sync` — Force full re-sync for a node
- `GET /api/v1/replication/dead-letter` — List dead-letter queue

### HE (Homomorphic Encryption)
- `POST /api/v1/he/init` — Initialize HE context
- `POST /api/v1/he/sum` — Compute encrypted sum
- `POST /api/v1/he/decrypt` — Decrypt an HE result

### Master Key
- `POST /api/v1/master-key` — Create master key
- `POST /api/v1/master-key/unlock` — Unlock master key
- `POST /api/v1/master-key/seal` — Seal master key with TPM
- `POST /api/v1/master-key/unseal` — Unseal master key with TPM

## SDK Usage

```python
import asyncio
from cryptodb.sdk.client import CryptoDBClient

async def main():
    client = CryptoDBClient("http://127.0.0.1:8000/api/v1")
    await client.login("alice", "secret")

    # Store data
    result = await client.put(b"hello world", searchable={"email": "alice@example.com"})
    record_id = result["record_id"]

    # Retrieve
    data = await client.get(record_id)
    print(data)

    # Batch operations
    results = await client.put_batch([b"a", b"b", b"c"])
    await client.delete_batch([r["record_id"] for r in results])

    # Audit
    entries = await client.audit()
    print(f"{len(entries)} audit entries")

    await client.logout()
    await client.close()

asyncio.run(main())
```

## Hardware Token Setup (FIDO2)

1. Register a hardware token:
   ```bash
   # Log in normally first
   cryptodb hardware-register-begin --username alice --password secret
   # Follow the prompt, then finish with the client response JSON
   ```

2. Authenticate with hardware token:
   ```bash
   cryptodb hardware-authenticate-begin --username alice --password secret
   # Touch the token, then finish with the client response JSON
   ```

## Replication Topology

1. On the primary node, register standby nodes:
   ```bash
   curl -X POST http://primary:8000/api/v1/replication/nodes \
     -H "Authorization: Bearer <token>" \
     -d '{"name": "standby-1", "endpoint_url": "https://standby1:8000/api/v1"}'
   ```

2. Standby nodes expose `POST /api/v1/replication/record` and `POST /api/v1/replication/audit` to receive replicated data.

3. Pull replication allows standbys to catch up using `GET /api/v1/replication/changes?since_sequence={n}`.

## Compliance Reports

```bash
# GDPR Right to Erasure report
curl http://localhost:8000/api/v1/compliance/gdpr/erasure/<user-id> \
  -H "Authorization: Bearer <token>"

# HIPAA access report
curl "http://localhost:8000/api/v1/compliance/hipaa/access?start=2024-01-01&end=2024-12-31" \
  -H "Authorization: Bearer <token>"

# SOC2 evidence export
curl http://localhost:8000/api/v1/compliance/soc2/evidence \
  -H "Authorization: Bearer <token>"
```

## Schema Migrations

CryptoDB uses Alembic for schema evolution.

```bash
# Generate a new migration after model changes
.venv/bin/alembic revision --autogenerate -m "Description"

# Apply migrations
.venv/bin/alembic upgrade head

# Downgrade
.venv/bin/alembic downgrade -1
```

## Architecture

- **Envelope Encryption**: Each record gets a unique DEK. The DEK is encrypted by the master KEK and stored alongside metadata.
- **Blob Store**: Filesystem-backed storage with content-addressed sharding and HMAC integrity tokens.
- **Audit Ledger**: Every operation appends an entry to an in-memory hash chain, which is periodically flushed to the `audit_log` table. Checkpoints are signed with the master key.
- **Rate Limiting**: In-memory sliding window per `(client_ip, endpoint)`. Configurable per endpoint.
- **Geofencing**: IP-based allow/deny lists using CIDR notation.

## Security Notes

- The master key passphrase is the single point of failure. Store it in a vault or HSM in production.
- Deterministic searchable encryption leaks equality. Enable only for fields where this tradeoff is acceptable.
- Crypto-shredding deletes the DEK metadata row, rendering the blob irrecoverable.
- All outbound webhooks are signed with HMAC-SHA3-256 to prevent spoofing.
- Replication endpoints require HTTPS unless explicitly allowed in development.

## Testing

```bash
pytest
```

Current status: 42 tests passing, 1 skipped.
