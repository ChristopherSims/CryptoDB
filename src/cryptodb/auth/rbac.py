"""Role-based access control."""

from dataclasses import dataclass

from cryptodb.db.metadata import User


@dataclass(frozen=True, slots=True)
class Permission:
    """A permission action on a resource."""

    action: str  # create, read, write, delete, audit, admin
    resource: str  # record, user, system


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {"create", "read", "write", "delete", "audit", "admin"},
    "writer": {"create", "read", "write"},
    "reader": {"read"},
    "auditor": {"read", "audit"},
}


def has_permission(user: User, action: str) -> bool:
    """Check if *user* role allows *action*."""
    if not user.is_active:
        return False
    perms = ROLE_PERMISSIONS.get(user.role, set())
    return action in perms


def require_permission(user: User, action: str) -> None:
    """Raise PermissionError if user lacks permission."""
    if not has_permission(user, action):
        raise PermissionError(f"User '{user.username}' lacks permission to '{action}'")
