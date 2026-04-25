"""Application configuration using Pydantic Settings."""

import ipaddress
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
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

    # Geofencing
    geo_allow: list[str] = Field(default=[], description="Allowed CIDR networks")
    geo_deny: list[str] = Field(default=[], description="Denied CIDR networks")

    # Rate limiting
    rate_limit_rpm: int = Field(default=60, description="Requests per minute per user")
    rate_limit_login_rpm: int = Field(default=5, description="Login attempts per minute")
    rate_limit_hw_auth_rpm: int = Field(default=5, description="Hardware auth attempts per minute")

    # Request limits
    max_record_size_mb: int = Field(default=100, description="Max record size in MB")
    cors_origins: list[str] = Field(default=[], description="Allowed CORS origins")

    # Ledger
    ledger_hash_algorithm: str = Field(default="sha3_256")
    ledger_checkpoint_interval: int = Field(
        default=1000, description="Entries between signed checkpoints"
    )

    # Webhook
    webhook_url: str | None = Field(default=None, description="Webhook URL for critical audit events")
    webhook_secret: str | None = Field(default=None, description="HMAC secret for webhook signing")

    # Data lifecycle
    purge_after_days: int = Field(default=30, description="Days before purging soft-deleted records")
    integrity_scan_interval_hours: int = Field(
        default=24, description="Hours between blob integrity scans"
    )

    # API
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8000)
    api_workers: int = Field(default=1)
    log_level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)")

    # DB pool
    db_pool_size: int = Field(default=5)
    db_max_overflow: int = Field(default=10)

    # Replication
    replication_enabled: bool = Field(default=False, description="Enable push replication to standby nodes")
    replication_batch_size: int = Field(default=100, description="Max records per replication batch")
    replication_retry_max: int = Field(default=3, description="Max retry attempts per standby node")
    replication_interval_seconds: int = Field(default=60, description="Background replication interval")
    replication_allow_http: bool = Field(default=False, description="Allow HTTP (non-TLS) replication endpoints")

    # Key rotation
    key_rotation_interval_hours: int = Field(
        default=0, description="Hours between automatic key rotations (0=disabled)"
    )

    # Key recovery
    recovery_shards: int = Field(default=0, description="Shamir secret sharing shards (0=disabled)")
    recovery_threshold: int = Field(default=0, description="Shamir threshold")

    @field_validator("jwt_secret", mode="after")
    @classmethod
    def _warn_default_jwt(cls, v: str) -> str:
        if v == "change-me-in-production":
            import warnings
            warnings.warn(
                "CRYPTODB_JWT_SECRET is using the default insecure value. "
                "Set a strong secret in production.",
                stacklevel=2,
            )
        return v

    @field_validator("geo_allow", "geo_deny", mode="before")
    @classmethod
    def _parse_cidr(cls, v: list[str] | str | None) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_origins(cls, v: list[str] | str | None) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @model_validator(mode="after")
    def _check_recovery(self) -> "Settings":
        if self.recovery_shards > 0 and self.recovery_threshold > self.recovery_shards:
            raise ValueError("recovery_threshold cannot exceed recovery_shards")
        return self

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

    def get_geo_rule(self) -> "GeoRule | None":
        """Build a GeoRule from settings if any networks are configured."""
        from cryptodb.auth.geo import GeoRule
        if not self.geo_allow and not self.geo_deny:
            return None
        return GeoRule(
            allowed_networks=[self._to_network(a) for a in self.geo_allow],
            denied_networks=[self._to_network(d) for d in self.geo_deny],
        )

    @staticmethod
    def _to_network(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        if "/" in addr:
            return ipaddress.ip_network(addr, strict=False)
        return ipaddress.ip_network(addr + "/32", strict=False)


# Singleton instance
settings = Settings()
