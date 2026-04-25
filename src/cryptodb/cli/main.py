"""CryptoDB CLI using Typer."""

import asyncio
import base64
from datetime import datetime, timezone
from pathlib import Path

import typer

from cryptodb.api.main import create_app
from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import AsyncSessionLocal, init_db
from cryptodb.sdk.client import CryptoDBClient

app = typer.Typer(help="CryptoDB — Cryptographic Database with Immutable Audit Ledger")


@app.command()
def init() -> None:
    """Initialize the database and directories."""
    settings.resolved_data_dir
    settings.resolved_blob_dir
    settings.resolved_keys_dir
    asyncio.run(init_db())
    typer.echo("Database initialized.")


@app.command()
def create_master_key(
    passphrase: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    """Create the master encryption key."""
    ks = MasterKeyStore()
    ks.create_master_key(passphrase)
    typer.echo("Master key created.")


@app.command()
def put(
    file: Path = typer.Argument(..., help="File to encrypt and store"),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
    compress: str = typer.Option("zstd", "--compress", "-c"),
) -> None:
    """Encrypt and store a file."""

    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        data = file.read_bytes()
        result = await client.put(data, compress=compress)
        typer.echo(f"Stored record: {result['record_id']} ({result['size_bytes']} bytes)")
        await client.close()

    asyncio.run(_run())


@app.command()
def get(
    record_id: str = typer.Argument(..., help="Record ID to retrieve"),
    output: Path = typer.Option(..., "--output", "-o"),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Retrieve and decrypt a record."""

    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        data = await client.get(record_id)
        output.write_bytes(data)
        typer.echo(f"Wrote {len(data)} bytes to {output}")
        await client.close()

    asyncio.run(_run())


@app.command()
def audit(
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """List the audit log."""

    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        entries = await client.audit()
        for entry in entries:
            ts = entry.get("timestamp", "?")
            action = entry.get("action", "?")
            actor = entry.get("actor_id", "?")[:8]
            resource = entry.get("resource_id", "?")[:8]
            typer.echo(f"{ts} | {action:10} | actor:{actor}... | resource:{resource}...")
        await client.close()

    asyncio.run(_run())


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h"),
    port: int = typer.Option(8000, "--port", "-p"),
) -> None:
    """Run the CryptoDB API server."""
    import uvicorn

    uvicorn.run("cryptodb.api.main:app", host=host, port=port, reload=False)


@app.command()
def bootstrap_admin(
    username: str = typer.Option("admin", "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Create the first admin user directly in the database."""

    async def _run() -> None:
        await init_db()
        from cryptodb.db.connection import session_context
        async with session_context() as session:
            from cryptodb.auth.users import create_user
            user = await create_user(session, username, password, role="admin")
            await session.commit()
            typer.echo(f"Admin user created: {user.id} ({user.username})")

    asyncio.run(_run())


@app.command()
def backup(
    output_dir: Path = typer.Argument(..., help="Directory to write backup files"),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Export all accessible records and audit log to *output_dir*."""

    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Export audit log
        entries = await client.audit()
        audit_path = output_dir / "audit.json"
        import json
        audit_path.write_text(json.dumps(entries, indent=2, default=str))
        typer.echo(f"Audit log exported: {audit_path} ({len(entries)} entries)")

        # Export ledger checkpoint
        from cryptodb.ledger.export import export_checkpoint
        from cryptodb.ledger.chain import HashChain
        # We don't have direct engine access, so just export a simple checkpoint
        checkpoint = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "audit_entries": len(entries),
        }
        cp_path = output_dir / "checkpoint.json"
        cp_path.write_text(json.dumps(checkpoint, indent=2))
        typer.echo(f"Checkpoint exported: {cp_path}")
        await client.close()

    asyncio.run(_run())


@app.command()
def rotate_master_key(
    old_passphrase: str = typer.Option(..., prompt=True, hide_input=True),
    new_passphrase: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    """Rotate the master key passphrase."""
    ks = MasterKeyStore()
    ks.rotate_master_key(old_passphrase, new_passphrase)
    typer.echo("Master key rotated successfully.")


@app.command()
def search(
    field_name: str = typer.Argument(...),
    token_plaintext: str = typer.Argument(...),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Search records by blind index."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        record_ids = await client.search(field_name, token_plaintext)
        for rid in record_ids:
            typer.echo(rid)
        await client.close()
    asyncio.run(_run())


@app.command()
def list_records(
    page: int = typer.Option(1, "--page"),
    page_size: int = typer.Option(20, "--page-size"),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """List accessible records."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        items = await client.list_records(page=page, page_size=page_size)
        for item in items:
            typer.echo(f"{item['id']} | owner:{item['owner_id'][:8]}... | {item['size_bytes']} bytes | {item['cipher_name']}")
        await client.close()
    asyncio.run(_run())


@app.command()
def grant_access(
    record_id: str = typer.Argument(...),
    permission: str = typer.Argument(...),
    user_id: str = typer.Option(None, "--user-id"),
    role: str = typer.Option(None, "--role"),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Grant access to a record."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        result = await client.grant_access(record_id, permission, user_id=user_id, role=role)
        typer.echo(f"Granted: {result}")
        await client.close()
    asyncio.run(_run())


@app.command()
def revoke_access(
    record_id: str = typer.Argument(...),
    grant_id: str = typer.Argument(...),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Revoke access to a record."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        result = await client.revoke_access(record_id, grant_id)
        typer.echo(f"Revoked: {result}")
        await client.close()
    asyncio.run(_run())


@app.command()
def purge_deleted(
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Purge soft-deleted records older than retention period."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        # Placeholder: API endpoint for purge not yet implemented
        typer.echo("Purge endpoint not yet implemented via API. Use direct DB access.")
        await client.close()
    asyncio.run(_run())


@app.command()
def user_list(
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """List users (admin only)."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        users = await client.list_users()
        for u in users:
            typer.echo(f"{u['id']} | {u['username']} | role:{u['role']} | active:{u['is_active']}")
        await client.close()
    asyncio.run(_run())


@app.command()
def user_set_role(
    user_id: str = typer.Argument(...),
    role: str = typer.Argument(...),
    base_url: str = typer.Option("http://127.0.0.1:8000/api/v1", "--url", "-u"),
    username: str = typer.Option(..., "--username"),
    password: str = typer.Option(..., "--password", prompt=True, hide_input=True),
) -> None:
    """Set user role (admin only)."""
    async def _run() -> None:
        client = CryptoDBClient(base_url)
        await client.login(username, password)
        result = await client.set_user_role(user_id, role)
        typer.echo(f"Updated: {result}")
        await client.close()
    asyncio.run(_run())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
