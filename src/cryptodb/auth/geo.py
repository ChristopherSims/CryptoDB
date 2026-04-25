"""Geofencing: restrict operations by source IP or network."""

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GeoRule:
    """A geofencing rule."""

    allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    denied_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]


def _to_network(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if "/" in addr:
        return ipaddress.ip_network(addr, strict=False)
    return ipaddress.ip_network(addr + "/32", strict=False)


def is_allowed(client_ip: str, rule: GeoRule | None) -> bool:
    """Check if *client_ip* satisfies the geofencing *rule*."""
    if rule is None:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    # Explicit deny takes precedence
    for net in rule.denied_networks:
        if addr in net:
            return False

    # If no allowed networks specified, allow everything not denied
    if not rule.allowed_networks:
        return True

    for net in rule.allowed_networks:
        if addr in net:
            return True
    return False


def create_rule(
    allow: list[str] | None = None,
    deny: list[str] | None = None,
) -> GeoRule:
    """Build a GeoRule from string CIDR lists."""
    return GeoRule(
        allowed_networks=[_to_network(a) for a in (allow or [])],
        denied_networks=[_to_network(d) for d in (deny or [])],
    )
