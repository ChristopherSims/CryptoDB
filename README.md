# CryptoDB

A cryptographic database with immutable audit ledger. All data is encrypted at rest using envelope encryption (AES-256-GCM / XChaCha20-Poly1305). Every create, read, and delete operation is recorded in a tamper-evident hash chain.

## Quick Start

### Install

```bash
pip install -e ".[dev]"
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

### Use the API / CLI

Register a user and log in via the REST API at `http://127.0.0.1:8000/api/v1/docs`.

Or use the CLI:

```bash
# Store a file
cryptodb put secret.txt --username alice --password secret

# Retrieve a record
cryptodb get <record-id> --output recovered.txt --username alice --password secret

# View audit log
cryptodb audit --username alice --password secret
```

## Architecture

- **Envelope Encryption**: Data Encryption Keys (DEKs) encrypt records; DEKs are encrypted by a Master Key (KEK).
- **Blob Store**: Encrypted ciphertext stored on filesystem with sharded paths.
- **Metadata DB**: SQLite (or PostgreSQL) stores record metadata, users, ACLs, and audit log pointers.
- **Audit Ledger**: Immutable hash chain (SHA3-256) with Merkle-like linkage. Tamper detection via `verify_ledger()`.
- **Access Control**: RBAC (admin, writer, reader, auditor) + per-record ACLs.

## Security Notes

- The master key passphrase is the single point of failure. Store it in a vault or HSM in production.
- Deterministic searchable encryption leaks equality. Enable only for fields where this tradeoff is acceptable.
- Crypto-shredding deletes the DEK metadata row, rendering the blob irrecoverable.

## Testing

```bash
pytest
```
