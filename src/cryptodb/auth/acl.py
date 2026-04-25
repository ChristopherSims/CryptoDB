"""Record-level access control lists."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cryptodb.db.metadata import Record, RecordACL, User


async def grant_access(
    session: AsyncSession,
    record: Record,
    granted_by: User,
    permission: str,
    user: User | None = None,
    role: str | None = None,
) -> RecordACL:
    """Grant *permission* on *record* to a user or role."""
    acl = RecordACL(
        record_id=record.id,
        user_id=user.id if user else None,
        role=role,
        permission=permission,
        granted_by=granted_by.id,
    )
    session.add(acl)
    await session.flush()
    return acl


async def can_access(
    session: AsyncSession,
    user: User,
    record: Record,
    permission: str,
) -> bool:
    """Check ACL and ownership for *permission*."""
    # Owner always has full access
    if record.owner_id == user.id:
        return True

    # Explicit ACL entry
    result = await session.execute(
        select(RecordACL).where(
            RecordACL.record_id == record.id,
            RecordACL.permission == permission,
            (RecordACL.user_id == user.id) | (RecordACL.role == user.role),
        )
    )
    if result.scalar_one_or_none():
        return True
    return False
