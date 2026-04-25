"""Multi-factor authentication flow with hardware tokens."""

import secrets
import time
from dataclasses import dataclass, field
from typing import ClassVar

from cryptodb.auth.hardware import FIDO2Credential, HardwareTokenManager
from cryptodb.auth.session import create_access_token, create_refresh_token
from cryptodb.db.metadata import User


@dataclass
class MFAChallenge:
    """In-memory challenge for two-step hardware token auth."""

    user_id: str
    challenge_type: str  # "fido2"
    state: dict
    created_at: float = field(default_factory=time.time)
    ttl_seconds: ClassVar[int] = 120

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class MFAChallengeStore:
    """Simple in-memory store for pending MFA challenges."""

    def __init__(self) -> None:
        self._challenges: dict[str, MFAChallenge] = {}

    def create(self, user_id: str, challenge_type: str, state: dict) -> str:
        token = secrets.token_urlsafe(32)
        self._challenges[token] = MFAChallenge(
            user_id=user_id,
            challenge_type=challenge_type,
            state=state,
        )
        self._cleanup()
        return token

    def get(self, token: str) -> MFAChallenge | None:
        self._cleanup()
        challenge = self._challenges.get(token)
        if challenge is None or challenge.is_expired():
            self._challenges.pop(token, None)
            return None
        return challenge

    def remove(self, token: str) -> None:
        self._challenges.pop(token, None)

    def _cleanup(self) -> None:
        expired = [k for k, v in self._challenges.items() if v.is_expired()]
        for k in expired:
            del self._challenges[k]


# Singleton challenge store
_mfa_store = MFAChallengeStore()


def get_mfa_store() -> MFAChallengeStore:
    return _mfa_store


async def issue_tokens(user: User) -> tuple[str, str]:
    """Issue access and refresh tokens for a fully-authenticated user."""
    access = create_access_token(user.id, {"role": user.role, "hw_verified": True})
    refresh = create_refresh_token(user.id)
    return access, refresh
