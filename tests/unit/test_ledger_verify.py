"""Tests for ledger tamper detection."""

import pytest

from cryptodb.ledger.chain import HashChain
from cryptodb.ledger.verify import TamperError, verify_ledger


class TestVerifyLedger:
    def test_valid_chain_raises_no_error(self):
        chain = HashChain()
        chain.append(actor_id="a1", action="create", resource_type="record", resource_id="r1")
        # Should not raise
        verify_ledger(chain)

    def test_empty_chain_raises_no_error(self):
        chain = HashChain()
        verify_ledger(chain)

    def test_tampered_chain_raises(self):
        chain = HashChain()
        chain.append(actor_id="a1", action="create", resource_type="record", resource_id="r1")
        # Tamper by replacing entries with a modified one
        from dataclasses import replace
        tampered = replace(chain._entries[0], actor_id="attacker")
        chain._entries[0] = tampered
        with pytest.raises(TamperError) as exc_info:
            verify_ledger(chain)
        assert "Entry #1" in str(exc_info.value)

    def test_tamper_error_is_exception(self):
        assert issubclass(TamperError, Exception)
