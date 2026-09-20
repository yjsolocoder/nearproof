import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BoundAttestedObservation,
    Consensus,
    RangeDecision,
    VerifierTrust,
    attest_observation_for_point,
    cert,
    locate_cert,
)

ROOT = b"\x09" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, root=ROOT, key=None, x=None, y=None):
    px, py = POSITIONS[ident]
    return cert(ident, x if x is not None else px, y if y is not None else py,
                key or KEYS[ident], root)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), point, context, 0.0,
        key or KEYS[ident],
    )


def triangle_records(upper_bound=5.0, **kwargs):
    # Verifier c sits at the origin, so any non-negative bound covers it.
    return [
        record("a", upper_bound, **kwargs),
        record("b", upper_bound, **kwargs),
        record("c", upper_bound, **kwargs),
    ]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


class VerifierTrustContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        first = trust("a")
        second = VerifierTrust(1, "a", 3.0, 0.0, KEY_A, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.x = 9.0

    def test_positional_field_order(self):
        record = VerifierTrust(1, "a", 1.0, 2.0, KEY_A, b"\x00" * 32)
        self.assertEqual(
            (record.version, record.id, record.x, record.y,
             record.key, record.mac),
            (1, "a", 1.0, 2.0, KEY_A, b"\x00" * 32),
        )

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                VerifierTrust(bad, "a", 0.0, 0.0, KEY_A, b"\x00" * 32)

    def test_id_must_be_non_empty_str(self):
        for bad in ("", 1, None, b"a"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                VerifierTrust(1, bad, 0.0, 0.0, KEY_A, b"\x00" * 32)

    def test_coordinates_must_be_finite_non_bool_non_negative(self):
        for bad in (True, "1", None, -1.0, float("inf"), float("nan")):
            for name in ("x", "y"):
                fields = {"x": 0.0, "y": 0.0, name: bad}
                with self.assertRaises(ValueError, msg=repr((name, bad))):
                    VerifierTrust(1, "a", fields["x"], fields["y"], KEY_A,
                                  b"\x00" * 32)

    def test_key_and_mac_must_be_32_bytes(self):
        for name in ("key", "mac"):
            for bad in (b"\x00" * 31, b"\x00" * 33, "ab" * 32, None):
                fields = {"key": KEY_A, "mac": b"\x00" * 32, name: bad}
                with self.assertRaises(ValueError, msg=repr((name, bad))):
                    VerifierTrust(1, "a", 0.0, 0.0, fields["key"], fields["mac"])


class VerifierTrustEncodingTest(unittest.TestCase):
    def test_to_bytes_is_compact_json_in_field_order(self):
        record = trust("a")
        payload = {
            "version": 1,
            "id": "a",
            "x": 3.0,
            "y": 0.0,
            "key": KEY_A.hex(),
            "mac": record.mac.hex(),
        }
        expected = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.assertEqual(record.to_bytes(), expected)

    def test_mac_formula(self):
        record = trust("a")
        payload = {
            "version": 1,
            "id": "a",
            "x": 3.0,
            "y": 0.0,
            "key": KEY_A.hex(),
        }
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(ROOT, b"NPVT1" + encoding, hashlib.sha256).digest()
        self.assertEqual(record.mac, expected)

    def test_round_trip(self):
        for record in triangle_trusts():
            self.assertEqual(VerifierTrust.from_bytes(record.to_bytes()), record)

    def test_from_bytes_rejects_non_bytes(self):
        record = trust("a")
        for bad in (record.to_bytes().decode("utf-8"), None, 42, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                VerifierTrust.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_encodings(self):
        data = trust("a").to_bytes()
        reordered = data.replace(
            b'"id":"a","x":3.0', b'"x":3.0,"id":"a"'
        )
        duplicated = data[:-1] + b',"version":1}'
        uppercased = data.replace(b'"x":3.0', b'"x":3.00')
        for bad in (data + b" ", reordered, duplicated, uppercased, b"{}",
                    b"[]", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                VerifierTrust.from_bytes(bad)

    def test_from_bytes_rejects_uppercase_hex(self):
        record = trust("a")
        hex_mac = record.mac.hex()
        index = next(i for i, char in enumerate(hex_mac) if char.isalpha())
        data = record.to_bytes().replace(
            hex_mac[index].encode(), hex_mac[index].upper().encode(), 1
        )
        with self.assertRaises(ValueError):
            VerifierTrust.from_bytes(data)

    def test_from_bytes_does_not_verify_mac(self):
        record = trust("a")
        obj = json.loads(record.to_bytes())
        obj["mac"] = "00" * 32
        forged = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        decoded = VerifierTrust.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class CertTest(unittest.TestCase):
    def test_signs_a_valid_record(self):
        record = cert("a", 1.0, 2.0, KEY_A, ROOT)
        self.assertIsInstance(record, VerifierTrust)
        self.assertEqual(record.version, 1)
        self.assertEqual((record.id, record.x, record.y), ("a", 1.0, 2.0))
        self.assertEqual(record.key, KEY_A)
        self.assertNotEqual(record.mac, b"\x00" * 32)

    def test_empty_root_rejected(self):
        with self.assertRaises(ValueError):
            cert("a", 0.0, 0.0, KEY_A, b"")

    def test_non_bytes_root_type_rejected(self):
        for bad in (bytearray(), bytearray(b"\x09" * 32), "root", "", None,
                    42, 4.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                cert("a", 0.0, 0.0, KEY_A, bad)

    def test_field_violations_rejected(self):
        with self.assertRaises(ValueError):
            cert("", 0.0, 0.0, KEY_A, ROOT)
        with self.assertRaises(ValueError):
            cert("a", -1.0, 0.0, KEY_A, ROOT)
        with self.assertRaises(ValueError):
            cert("a", 0.0, 0.0, b"short", ROOT)


class LocateCertTest(unittest.TestCase):
    def test_accepts_mixed_objects_and_bytes(self):
        records = triangle_records()
        trusts = triangle_trusts()
        mixed_records = [records[0].to_bytes(), records[1], records[2].to_bytes()]
        mixed_trusts = [trusts[0], trusts[1].to_bytes(), trusts[2]]
        consensus = locate_cert(mixed_records, POINT, CONTEXT, mixed_trusts, ROOT)
        self.assertIsInstance(consensus, Consensus)
        self.assertEqual(consensus.total, 3)
        self.assertEqual(consensus.support, 3)
        self.assertEqual(consensus.rejected, ())
        self.assertTrue(consensus.accepted)

    def test_quorum_is_fixed_at_three(self):
        # Four verifiers, one of them too far away: 3 supporters still accept.
        records = triangle_records() + [
            attest_observation_for_point(
                "d", 50.0, 50.0, decision(5.0), POINT, CONTEXT, 0.0, b"\xdd" * 32
            )
        ]
        trusts = triangle_trusts() + [cert("d", 50.0, 50.0, b"\xdd" * 32, ROOT)]
        consensus = locate_cert(records, POINT, CONTEXT, trusts, ROOT)
        self.assertEqual(consensus.support, 3)
        self.assertEqual(consensus.rejected, ("d",))
        self.assertTrue(consensus.accepted)

    def test_rejection_is_reported_not_raised(self):
        # Upper bound 1.0 covers only the verifier at the origin.
        records = triangle_records(upper_bound=1.0)
        consensus = locate_cert(records, POINT, CONTEXT, triangle_trusts(), ROOT)
        self.assertEqual(consensus.support, 1)
        self.assertEqual(consensus.rejected, ("a", "b"))
        self.assertFalse(consensus.accepted)

    def test_empty_root_rejected(self):
        with self.assertRaises(ValueError):
            locate_cert(triangle_records(), POINT, CONTEXT, triangle_trusts(), b"")

    def test_non_bytes_root_type_rejected(self):
        for bad in (bytearray(ROOT), "root", "", None, 42, 4.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                locate_cert(triangle_records(), POINT, CONTEXT,
                            triangle_trusts(), bad)

    def test_wrong_root_rejected(self):
        with self.assertRaises(ValueError):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), b"\x08" * 32
            )

    def test_duplicate_trust_id_rejected(self):
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_cert(triangle_records(), POINT, CONTEXT,
                        trusts + [trusts[0]], ROOT)

    def test_missing_trust_rejected(self):
        with self.assertRaises(ValueError):
            locate_cert(triangle_records(), POINT, CONTEXT,
                        triangle_trusts()[:2], ROOT)

    def test_tampered_trust_rejected(self):
        trusts = triangle_trusts()
        forged = VerifierTrust.from_bytes(trusts[0].to_bytes())
        forged = dataclasses.replace(forged, mac=b"\x00" * 32)
        with self.assertRaises(ValueError):
            locate_cert(triangle_records(), POINT, CONTEXT,
                        [forged] + trusts[1:], ROOT)

    def test_wrong_record_key_rejected(self):
        records = triangle_records()
        forged = record("a", key=KEY_B)
        with self.assertRaises(ValueError):
            locate_cert([forged] + records[1:], POINT, CONTEXT,
                        triangle_trusts(), ROOT)

    def test_trust_coordinates_must_match_the_record(self):
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_cert(triangle_records(), POINT, CONTEXT,
                        [trust("a", x=9.0)] + trusts[1:], ROOT)

    def test_point_and_context_binding_enforced(self):
        records = triangle_records()
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_cert(records, (1.0, 0.0), CONTEXT, trusts, ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, "room-8", trusts, ROOT)

    def test_query_contract_enforced(self):
        records = triangle_records()
        trusts = triangle_trusts()
        for bad_point in ([0.0, 0.0], (0.0,), (0.0, 0.0, 0.0),
                          (float("nan"), 0.0), (True, 0.0)):
            with self.assertRaises(ValueError, msg=repr(bad_point)):
                locate_cert(records, bad_point, CONTEXT, trusts, ROOT)
        for bad_context in ("", None, 7):
            with self.assertRaises(ValueError, msg=repr(bad_context)):
                locate_cert(records, POINT, bad_context, trusts, ROOT)

    def test_too_few_records_rejected(self):
        with self.assertRaises(ValueError):
            locate_cert(triangle_records()[:2], POINT, CONTEXT,
                        triangle_trusts()[:2], ROOT)

    def test_duplicate_record_id_rejected(self):
        records = triangle_records()
        with self.assertRaises(ValueError):
            locate_cert([records[0], records[0], records[1]], POINT, CONTEXT,
                        triangle_trusts(), ROOT)

    def test_invalid_item_types_rejected(self):
        records = triangle_records()
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, [42], ROOT)
        with self.assertRaises(ValueError):
            locate_cert([42], POINT, CONTEXT, trusts, ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts[0].to_bytes() + b" ",
                        ROOT)


if __name__ == "__main__":
    unittest.main()
