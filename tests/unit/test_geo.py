"""Tests for geofencing module."""

import pytest

from cryptodb.auth.geo import GeoRule, create_rule, is_allowed


class TestIsAllowed:
    def test_no_rule_allows_all(self) -> None:
        assert is_allowed("192.168.1.1", None) is True

    def test_empty_rule_allows_all(self) -> None:
        rule = create_rule()
        assert is_allowed("192.168.1.1", rule) is True

    def test_allowed_network_permits(self) -> None:
        rule = create_rule(allow=["192.168.1.0/24"])
        assert is_allowed("192.168.1.50", rule) is True

    def test_allowed_network_denies_outside(self) -> None:
        rule = create_rule(allow=["192.168.1.0/24"])
        assert is_allowed("10.0.0.1", rule) is False

    def test_denied_network_blocks(self) -> None:
        rule = create_rule(deny=["192.168.1.0/24"])
        assert is_allowed("192.168.1.50", rule) is False

    def test_denied_network_allows_others(self) -> None:
        rule = create_rule(deny=["192.168.1.0/24"])
        assert is_allowed("10.0.0.1", rule) is True

    def test_deny_takes_precedence(self) -> None:
        rule = create_rule(allow=["192.168.0.0/16"], deny=["192.168.1.0/24"])
        assert is_allowed("192.168.1.50", rule) is False
        assert is_allowed("192.168.2.1", rule) is True

    def test_ipv6_allowed(self) -> None:
        rule = create_rule(allow=["::1/128"])
        assert is_allowed("::1", rule) is True

    def test_invalid_ip_returns_false(self) -> None:
        rule = create_rule(allow=["192.168.1.0/24"])
        assert is_allowed("not-an-ip", rule) is False

    def test_single_ip_without_cidr(self) -> None:
        rule = create_rule(allow=["192.168.1.1"])
        assert is_allowed("192.168.1.1", rule) is True
        assert is_allowed("192.168.1.2", rule) is False


class TestCreateRule:
    def test_from_strings(self) -> None:
        rule = create_rule(allow=["10.0.0.0/8", "172.16.0.0/12"], deny=["10.1.0.0/16"])
        assert len(rule.allowed_networks) == 2
        assert len(rule.denied_networks) == 1

    def test_empty_lists(self) -> None:
        rule = create_rule(allow=[], deny=[])
        assert len(rule.allowed_networks) == 0
        assert len(rule.denied_networks) == 0

    def test_none_lists(self) -> None:
        rule = create_rule(allow=None, deny=None)
        assert len(rule.allowed_networks) == 0
        assert len(rule.denied_networks) == 0


class TestGeoRule:
    def test_frozen_dataclass(self) -> None:
        rule = create_rule(allow=["192.168.1.0/24"])
        with pytest.raises(AttributeError):
            rule.allowed_networks = []
