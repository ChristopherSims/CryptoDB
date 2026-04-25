"""Application configuration using Pydantic Settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """CryptoDB runtime settings."""

    model_config = SettingsConfigDict(
        env_prefix="CRYPTODB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Paths
    data_dir: Path = Field(default=Path("./data"), description="Base directory for all data")
    blob_dir: Path = Field(default=Path("./data/blobs"), description="Encrypted blob storage")
    db_path: Path = Field(default=Path("./data/cryptodb.db"), description="Metadata SQLite DB")
    ledger_path: Path = Field(
        default=Path("./data/ledger.db"), description="Audit ledger SQLite DB"
    )
    keys_dir: Path = Field(default=Path("./data/keys"), description="Key material directory")

    # Crypto
    master_key_id: str = Field(default="master-key-v1", description="Active master key identifier")
    default_cipher: Literal["aes-256-gcm", "xchacha20-poly1305"] = Field(
        default="aes-256-gcm", description="Default symmetric cipher"
    )
    dek_key_size: int = Field(default=32, description="Data encryption key size in bytes")
    kek_key_size: int = Field(default=32, description="Key encryption key size in bytes")

    # Argon2id params
    argon2_time_cost: int = Field(default=3, description="Argon2id iterations")
    argon2_memory_cost: int = Field(default=65536, description="Argon2id memory in KiB")
    argon2_parallelism: int = Field(default=4, description="Argon2id parallelism")

    # Auth
    jwt_secret: str = Field(default="change-me-in-production", description="JWT signing secret")
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=15)
    jwt_refresh_token_expire_days: int = Field(default=7)

    # Ledger
    ledger_hash_algorithm: str = Field(default="sha3_256")
    ledger_checkpoint_interval: int = Field(
        default=1000, description="Entries between signed checkpoints"
    )

    # API
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000)
    api_workers: int = Field(default=1)

    @property
    def resolved_data_dir(self) -> Path:
        """Return absolute data directory, creating if needed."""
        path = self.data_dir.resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def resolved_blob_dir(self) -> Path:
        path = self.blob_dir.resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def resolved_keys_dir(self) -> Path:
        path = self.keys_dir.resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path


# Singleton instance
settings = Settings()
