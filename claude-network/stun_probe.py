"""Independent UDP STUN reachability control (RFC 8489, no credentials).

This Python traffic may legitimately use the daily/TUN route. It is a positive
control for server reachability, never evidence that Chrome leaked an address.
No environment proxy, raw packet, transaction ID or exception text is returned.
"""
from __future__ import annotations

import ipaddress
import math
import re
import secrets
import socket
import struct


MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111
MAPPED_ADDRESS = 0x0001
XOR_MAPPED_ADDRESS = 0x0020

ERRORS = frozenset({
    "invalid_arguments", "dns_failed", "no_udp_address", "socket_error", "timeout",
    "invalid_transaction_id", "response_too_short", "response_length_invalid",
    "response_truncated", "response_extra_data", "bad_magic_cookie",
    "transaction_mismatch", "not_binding_success", "binding_error_response",
    "attribute_truncated", "mapped_address_malformed", "unsupported_address_family",
    "mapped_address_missing",
})


def _failed(error):
    return {"ok": False, "address": None, "error": error}


def _decode_address(value: bytes, transaction_id: bytes, xor: bool):
    if len(value) < 4:
        return None, "mapped_address_malformed"
    family = value[1]
    if family not in (1, 2):
        return None, "unsupported_address_family"
    size = 4 if family == 1 else 16
    if len(value) != size + 4:
        return None, "mapped_address_malformed"
    # The leading reserved octet is deliberately ignored, as RFC 8489 requires.
    mapped_port = struct.unpack("!H", value[2:4])[0]
    address = value[4:]
    if xor:
        mapped_port ^= MAGIC_COOKIE >> 16
        mask = struct.pack("!I", MAGIC_COOKIE) + transaction_id
        address = bytes(byte ^ mask[index] for index, byte in enumerate(address))
    if mapped_port == 0:
        return None, "mapped_address_malformed"
    return str(ipaddress.ip_address(address)), None


def _decode_response(packet: bytes, transaction_id: bytes) -> dict:
    """Validate framing and transaction before reading mapped-address data."""
    if not isinstance(transaction_id, bytes) or len(transaction_id) != 12:
        return _failed("invalid_transaction_id")
    if not isinstance(packet, bytes) or len(packet) < 20:
        return _failed("response_too_short")
    message_type, message_length, cookie = struct.unpack("!HHI", packet[:8])
    if cookie != MAGIC_COOKIE:
        return _failed("bad_magic_cookie")
    if not secrets.compare_digest(packet[8:20], transaction_id):
        return _failed("transaction_mismatch")
    if message_type != BINDING_SUCCESS:
        return _failed("binding_error_response" if message_type == BINDING_ERROR else "not_binding_success")
    if message_length % 4:
        return _failed("response_length_invalid")
    end = 20 + message_length
    if len(packet) < end:
        return _failed("response_truncated")
    if len(packet) > end:
        return _failed("response_extra_data")
    offset = 20
    mapped = {}
    while offset < end:
        if end - offset < 4:
            return _failed("attribute_truncated")
        attribute, size = struct.unpack("!HH", packet[offset:offset + 4])
        start = offset + 4
        next_offset = start + ((size + 3) & ~3)
        if start + size > end or next_offset > end:
            return _failed("attribute_truncated")
        # First occurrence wins; padding is excluded from the address bytes.
        if attribute in (MAPPED_ADDRESS, XOR_MAPPED_ADDRESS) and attribute not in mapped:
            address, error = _decode_address(packet[start:start + size], transaction_id,
                                              attribute == XOR_MAPPED_ADDRESS)
            if error:
                return _failed(error)
            mapped[attribute] = address
        offset = next_offset
    address = mapped.get(XOR_MAPPED_ADDRESS) or mapped.get(MAPPED_ADDRESS)
    if address is None:
        return _failed("mapped_address_missing")
    return {"ok": True, "address": address, "error": None}


def probe_stun(host="stun.cloudflare.com", port=3478, timeout=4) -> dict:
    """Perform one bounded UDP binding exchange with a cryptorandom 96-bit ID.

    ``timeout`` bounds socket operations; hostname resolution uses the operating
    system resolver. A timeout/bad packet is inconclusive, never a positive
    control. A connected UDP socket accepts responses only from its peer.
    """
    safe_host = isinstance(host, str) and 0 < len(host) <= 253 and re.fullmatch(r"[A-Za-z0-9._:-]+", host) is not None
    result = {"ok": False, "address": None, "source_port": None,
              "server": host if safe_host else None,
              "server_port": port if isinstance(port, int) and not isinstance(port, bool) else None,
              "error": None}
    if not safe_host or not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535 or not isinstance(timeout, (float, int)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        result["error"] = "invalid_arguments"
        return result
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except (OSError, UnicodeError):
        result["error"] = "dns_failed"
        return result
    addresses = [a for a in addresses if a[0] in (socket.AF_INET, socket.AF_INET6) and a[1] == socket.SOCK_DGRAM]
    if not addresses:
        result["error"] = "no_udp_address"
        return result
    # IPv4 first makes the control comparable to the current IPv4 TUN route.
    addresses.sort(key=lambda a: a[0] != socket.AF_INET)
    family, kind, protocol, _, target = addresses[0]
    transaction_id = secrets.token_bytes(12)
    request = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + transaction_id
    try:
        with socket.socket(family, kind, protocol) as connection:
            connection.settimeout(float(timeout))
            connection.connect(target)
            result["source_port"] = connection.getsockname()[1]
            connection.send(request)
            packet = connection.recv(65535)
        result.update(_decode_response(packet, transaction_id))
    except (TimeoutError, socket.timeout):
        result["error"] = "timeout"
    except OSError:
        result["error"] = "socket_error"
    return result
