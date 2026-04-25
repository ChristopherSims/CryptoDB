"""Ledger tamper detection and periodic verification."""

from cryptodb.ledger.chain import HashChain


class TamperError(Exception):
    """Raised when the ledger hash chain is broken."""


def verify_ledger(chain: HashChain) -> None:
    """Verify the ledger and raise TamperError on any failure."""
    failures = chain.verify()
    if failures:
        messages = [f"Entry #{n}: {msg}" for n, msg in failures]
        raise TamperError("; ".join(messages))
