"""CryptoDB CLI using Typer."""

import asyncio
import base64
from pathlib import Path

import typer

from cryptodb.api.main import create_app
from cryptodb.config import settings
from cryptodb.crypto.keystore import MasterKeyStore
from cryptodb.db.connection import init_db
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
