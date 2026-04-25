"""Webhook integration for critical audit events."""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import httpx

from cryptodb.config import settings

logger = logging.getLogger(__name__)
WEBHOOK_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def sign_payload(payload: dict, secret: str) -> str:
    """Sign a webhook payload with HMAC-SHA3-256."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret.encode(), body, hashlib.sha3_256).hexdigest()


async def send_webhook(event_type: str, payload: dict, retries: int = 3) -> bool:
    """Send a signed webhook payload with retry and backoff."""
    if not settings.webhook_url or not settings.webhook_secret:
        return False

    full_payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    signature = sign_payload(full_payload, settings.webhook_secret)

    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
                resp = await client.post(
                    settings.webhook_url,
                    json=full_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-CryptoDB-Signature": signature,
                    },
                )
                if resp.status_code < 500:
                    return resp.status_code < 400
        except Exception as exc:
            logger.warning("Webhook attempt %d failed: %s", attempt + 1, exc)

        import asyncio
        await asyncio.sleep(2 ** attempt)

    logger.error("Webhook failed after %d retries", retries)
    return False
