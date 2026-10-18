"""RFC vectors and fail-closed regressions, with no network in unit tests."""
import json
import socket
import struct
import unittest
from unittest import mock

import stun_probe as stun


TRANSACTION = bytes.fromhex("b7e7a701bc34d686fa87dfae")
# Independent published packets: https://www.rfc-editor.org/rfc/rfc5769#section-2.2
IPV4_RESPONSE = bytes.fromhex(
    "0101003c2112a442b7e7a701bc34d686fa87dfae"
    "8022000b7465737420766563746f7220"
    "002000080001a147e112a643"
    "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7"
    "80280004c07d4c96")
IPV6_RESPONSE = bytes.fromhex(
    "010100482112a442b7e7a701bc34d686fa87dfae"
    "8022000b7465737420766563746f7220"
    "002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9"
    "00080014a382954e4be67bf11784c97c8292c275bfe3ed41"
    "80280004c8fb0b4c")


def response(attributes, length=None, kind=stun.BINDING_SUCCESS):
    return struct.pack("!HHI", kind, len(attributes) if length is None else length, stun.MAGIC_COOKIE) + TRANSACTION + attributes


class ParseResponseTests(unittest.TestCase):
    def assert_error(self, packet, error, xid=TRANSACTION):
        result = stun._decode_response(packet, xid)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["address"])
        self.assertEqual(result["error"], error)
        self.assertIn(error, stun.ERRORS)

    def test_rfc_ipv4_vector_including_nonzero_padding(self):
        self.assertEqual(stun._decode_response(IPV4_RESPONSE, TRANSACTION),
                         {"ok": True, "address": "192.0.2.1", "error": None})

    def test_rfc_ipv6_vector_uses_cookie_and_full_transaction(self):
        self.assertEqual(stun._decode_response(IPV6_RESPONSE, TRANSACTION),
                         {"ok": True, "address": "2001:db8:1234:5678:11:2233:4455:6677", "error": None})

    def test_wrong_transaction_never_passes(self):
        self.assert_error(IPV4_RESPONSE, "transaction_mismatch", b"wrong-id-123")

    def test_short_transaction_is_rejected(self):
        self.assert_error(IPV4_RESPONSE, "invalid_transaction_id", b"short")

    def test_truncated_header_and_body_never_pass(self):
        self.assert_error(IPV4_RESPONSE[:19], "response_too_short")
        self.assert_error(IPV4_RESPONSE[:-1], "response_truncated")

    def test_wrong_cookie_is_rejected(self):
        packet = IPV4_RESPONSE[:4] + b"\0\0\0\0" + IPV4_RESPONSE[8:]
        self.assert_error(packet, "bad_magic_cookie")

    def test_request_and_error_response_are_not_success(self):
        self.assert_error(response(b"", kind=stun.BINDING_REQUEST), "not_binding_success")
        self.assert_error(response(b"", kind=stun.BINDING_ERROR), "binding_error_response")

    def test_unaligned_length_and_extra_data_are_rejected(self):
        self.assert_error(response(b"abc", length=3), "response_length_invalid")
        self.assert_error(IPV4_RESPONSE + b"extra", "response_extra_data")

    def test_attribute_cannot_claim_bytes_outside_message(self):
        self.assert_error(response(bytes.fromhex("00200008")), "attribute_truncated")

    def test_short_mapped_address_and_unknown_family_are_rejected(self):
        self.assert_error(response(bytes.fromhex("002000040001a147")), "mapped_address_malformed")
        self.assert_error(response(bytes.fromhex("002000040003a147")), "unsupported_address_family")

    def test_success_without_mapped_address_is_not_control_success(self):
        self.assert_error(response(bytes.fromhex("802200044e6f7065")), "mapped_address_missing")

    def test_plain_mapped_address_fallback(self):
        packet = response(bytes.fromhex("0001000800018055c0000201"))
        self.assertEqual(stun._decode_response(packet, TRANSACTION)["address"], "192.0.2.1")

    def test_xor_address_takes_precedence_over_legacy_mapped(self):
        packet = response(bytes.fromhex("0001000800018055c0000202" "002000080001a147e112a643"))
        self.assertEqual(stun._decode_response(packet, TRANSACTION)["address"], "192.0.2.1")


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.connection = mock.MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.getsockname.return_value = ("192.0.2.200", 51321)
        self.connection.recv.return_value = IPV4_RESPONSE
        self.addresses = [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("192.0.2.50", 3478))]

    def probe(self):
        with mock.patch.object(stun.socket, "getaddrinfo", return_value=self.addresses), \
             mock.patch.object(stun.socket, "socket", return_value=self.connection), \
             mock.patch.object(stun.secrets, "token_bytes", return_value=TRANSACTION):
            return stun.probe_stun()

    def test_success_binds_response_to_request_and_reports_local_source_port(self):
        result = self.probe()
        self.assertTrue(result["ok"])
        self.assertEqual(result["source_port"], 51321)
        self.assertEqual(result["server"], "stun.cloudflare.com")
        self.assertEqual(result["server_port"], 3478)
        request = self.connection.send.call_args.args[0]
        self.assertEqual(request, struct.pack("!HHI", 1, 0, stun.MAGIC_COOKIE) + TRANSACTION)
        self.assertEqual(set(result), {"ok", "address", "source_port", "server", "server_port", "error"})
        self.assertNotIn(TRANSACTION.hex(), json.dumps(result))

    def test_timeout_is_inconclusive_and_never_success(self):
        self.connection.recv.side_effect = socket.timeout()
        result = self.probe()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "timeout")
        self.assertIsNone(result["address"])
        self.assertEqual(result["source_port"], 51321)

    def test_wrong_transaction_and_truncation_remain_failure_through_public_api(self):
        for packet in (IPV4_RESPONSE[:8] + b"X" * 12 + IPV4_RESPONSE[20:], IPV4_RESPONSE[:-1]):
            self.connection.recv.return_value = packet
            result = self.probe()
            self.assertFalse(result["ok"])
            self.assertIn(result["error"], {"transaction_mismatch", "response_truncated"})

    def test_dns_error_does_not_expose_exception_message(self):
        with mock.patch.object(stun.socket, "getaddrinfo", side_effect=socket.gaierror("RAW-ERROR-CANARY")):
            result = stun.probe_stun()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "dns_failed")
        self.assertNotIn("RAW-ERROR-CANARY", json.dumps(result))

    def test_invalid_arguments_do_not_open_socket(self):
        with mock.patch.object(stun.socket, "getaddrinfo") as resolve:
            for kwargs in ({"timeout": 0}, {"timeout": float("nan")}, {"port": 0}, {"host": "https://token@example.com"}):
                self.assertEqual(stun.probe_stun(**kwargs)["error"], "invalid_arguments")
            resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
