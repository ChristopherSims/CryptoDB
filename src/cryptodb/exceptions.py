"""Unified exception hierarchy for CryptoDB.

All business-logic and service-layer code should raise subclasses of
CryptoDBException. FastAPI routes catch these and convert them to structured
HTTP responses via the global exception handler in api/main.py.
"""


class CryptoDBException(Exception):
    """Base exception for all CryptoDB errors."""

    http_status: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, detail: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class AuthenticationError(CryptoDBException):
    """Invalid credentials or expired/closed session."""

    http_status = 401
    error_code = "AUTHENTICATION_ERROR"


class AuthorizationError(CryptoDBException):
    """Insufficient permissions for the requested operation."""

    http_status = 403
    error_code = "AUTHORIZATION_ERROR"


class RecordNotFoundError(CryptoDBException):
    """Requested record does not exist or is inaccessible."""

    http_status = 404
    error_code = "RECORD_NOT_FOUND"


class IntegrityError(CryptoDBException):
    """Data integrity violation (tampered blob, hash mismatch, etc.)."""

    http_status = 409
    error_code = "INTEGRITY_VIOLATION"


class KeyManagementError(CryptoDBException):
    """Master key, DEK, or keystore operation failed."""

    http_status = 500
    error_code = "KEY_MANAGEMENT_ERROR"


class ReplicationError(CryptoDBException):
    """Replication push/pull or standby sync failure."""

    http_status = 502
    error_code = "REPLICATION_ERROR"


class ConfigurationError(CryptoDBException):
    """Invalid configuration or environment state."""

    http_status = 500
    error_code = "CONFIGURATION_ERROR"


class RateLimitError(CryptoDBException):
    """Rate limit exceeded."""

    http_status = 429
    error_code = "RATE_LIMIT_EXCEEDED"


class ValidationError(CryptoDBException):
    """Request payload validation failure."""

    http_status = 422
    error_code = "VALIDATION_ERROR"
