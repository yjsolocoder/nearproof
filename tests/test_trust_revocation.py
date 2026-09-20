import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    Consensus,
    RangeDecision,
    TrustRevocation,
    attest_observation_for_point,
    cert,
    locate_cert,
    revoke_trust,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
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
    return [
        record("a", upper_bound, **kwargs),
        record("b", upper_bound, **kwargs),
        record("c", upper_bound, **kwargs),
    ]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


class TrustRevocationContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        signed = revoke_trust(trust("a"), ROOT)
        second = TrustRevocation(1, "a", signed.target, signed.mac)
        self.assertEqual(signed, second)
        self.assertEqual(hash(signed), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            signed.id = "b"

    def test_positional_field_order(self):
        revocation = TrustRevocation(1, "a", b"\x01" * 32, b"\x02" * 32)
        self.assertEqual(
            (revocation.version, revocation.id, revocation.target,
             revocation.mac),
            (1, "a", b"\x01" * 32, b"\x02" * 32),
        )

    def test_version_type_and_value(self):
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation(bad, "a", b"\x00" * 32, b"\x00" * 32)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation(bad, "a", b"\x00" * 32, b"\x00" * 32)

    def test_id_type_and_value(self):
        for bad in (1, b"a", None, 1.0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation(1, bad, b"\x00" * 32, b"\x00" * 32)
        with self.assertRaises(ValueError):
            TrustRevocation(1, "", b"\x00" * 32, b"\x00" * 32)

    def test_target_type_and_length(self):
        for bad in ("00" * 32, None, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation(1, "a", bad, b"\x00" * 32)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation(1, "a", bad, b"\x00" * 32)

    def test_mac_type_and_length(self):
        for bad in ("00" * 32, None, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation(1, "a", b"\x00" * 32, bad)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation(1, "a", b"\x00" * 32, bad)


class TrustRevocationEncodingTest(unittest.TestCase):
    def test_to_bytes_is_compact_json_in_field_order(self):
        signed = revoke_trust(trust("a"), ROOT)
        payload = {
            "version": 1,
            "id": "a",
            "target": signed.target.hex(),
            "mac": signed.mac.hex(),
        }
        expected = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.assertEqual(signed.to_bytes(), expected)

    def test_mac_formula(self):
        certificate = trust("a")
        signed = revoke_trust(certificate, ROOT)
        payload = {"version": 1, "id": "a", "target": certificate.mac.hex()}
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(ROOT, b"NPVR1" + encoding, hashlib.sha256).digest()
        self.assertEqual(signed.mac, expected)

    def test_target_is_the_certificate_mac(self):
        certificate = trust("a")
        signed = revoke_trust(certificate, ROOT)
        self.assertEqual(signed.target, certificate.mac)

    def test_round_trip(self):
        for certificate in triangle_trusts():
            signed = revoke_trust(certificate, ROOT)
            self.assertEqual(TrustRevocation.from_bytes(signed.to_bytes()), signed)

    def test_from_bytes_rejects_non_bytes_with_type_error(self):
        signed = revoke_trust(trust("a"), ROOT)
        for bad in (signed.to_bytes().decode("utf-8"), None, 42, [1]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_encodings(self):
        signed = revoke_trust(trust("a"), ROOT)
        data = signed.to_bytes()
        obj = json.loads(data)
        reordered = json.dumps(
            {"version": obj["version"], "target": obj["target"],
             "id": obj["id"], "mac": obj["mac"]},
            separators=(",", ":"),
        ).encode()
        duplicated = data[:-1] + b',"version":1}'
        for bad in (data + b" ", reordered, duplicated, b"{}", b"[]",
                    b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation.from_bytes(bad)

    def test_from_bytes_rejects_field_type_errors_with_type_error(self):
        signed = revoke_trust(trust("a"), ROOT)
        obj = json.loads(signed.to_bytes())
        wrong_version = dict(obj)
        wrong_version["version"] = "1"
        wrong_id = dict(obj)
        wrong_id["id"] = 1
        for altered in (wrong_version, wrong_id):
            data = json.dumps(altered, separators=(",", ":")).encode()
            with self.assertRaises(TypeError):
                TrustRevocation.from_bytes(data)

    def test_from_bytes_rejects_empty_id(self):
        signed = revoke_trust(trust("a"), ROOT)
        obj = json.loads(signed.to_bytes())
        obj["id"] = ""
        data = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(data)

    def test_from_bytes_rejects_uppercase_hex(self):
        signed = revoke_trust(trust("a"), ROOT)
        for field in ("target", "mac"):
            hex_value = getattr(signed, field).hex()
            index = next(
                (i for i, char in enumerate(hex_value) if char.isalpha()), 0
            )
            data = signed.to_bytes().replace(
                hex_value[index].encode(),
                hex_value[index].upper().encode(),
                1,
            )
            with self.assertRaises(ValueError, msg=field):
                TrustRevocation.from_bytes(data)

    def test_from_bytes_rejects_wrong_hex_length(self):
        signed = revoke_trust(trust("a"), ROOT)
        obj = json.loads(signed.to_bytes())
        obj["target"] = "00" * 31
        data = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(data)

    def test_from_bytes_does_not_verify_mac(self):
        signed = revoke_trust(trust("a"), ROOT)
        obj = json.loads(signed.to_bytes())
        obj["mac"] = "00" * 32
        forged = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        decoded = TrustRevocation.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class RevokeTrustTest(unittest.TestCase):
    def test_signs_a_valid_revocation(self):
        signed = revoke_trust(trust("a"), ROOT)
        self.assertIsInstance(signed, TrustRevocation)
        self.assertEqual(signed.version, 1)
        self.assertEqual(signed.id, "a")
        self.assertEqual(signed.target, trust("a").mac)
        self.assertNotEqual(signed.mac, b"\x00" * 32)

    def test_trust_must_be_verifier_trust(self):
        for bad in ("a", b"x", None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                revoke_trust(bad, ROOT)

    def test_empty_root_is_value_error(self):
        with self.assertRaises(ValueError):
            revoke_trust(trust("a"), b"")

    def test_non_bytes_root_is_type_error(self):
        for bad in (bytearray(ROOT), "root", "", None, 42, 4.0, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                revoke_trust(trust("a"), bad)

    def test_root_not_stored(self):
        signed = revoke_trust(trust("a"), ROOT)
        self.assertFalse(hasattr(signed, "root"))


class LocateCertRevocationTest(unittest.TestCase):
    def test_revoked_certificate_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        revocation = revoke_trust(trusts[0], ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[revocation])

    def test_revocation_bytes_mixed_with_objects(self):
        trusts = triangle_trusts()
        records = triangle_records()
        revocations = [
            revoke_trust(trusts[0], ROOT).to_bytes(),
        ]
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=revocations)

    def test_revocation_for_present_but_unused_certificate_rejected(self):
        # A revocation must hit a certificate actually used by a record:
        # an extra trust that no record uses is presented, but revoking it
        # is still rejected as unmatched rather than silently ignored.
        trusts = triangle_trusts()
        records = triangle_records()
        extra = cert("d", 50.0, 50.0, b"\xdd" * 32, ROOT)
        revocation = revoke_trust(extra, ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts + [extra], ROOT,
                        revocations=[revocation])

    def test_empty_revocations_equals_default(self):
        trusts = triangle_trusts()
        records = triangle_records()
        default = locate_cert(records, POINT, CONTEXT, trusts, ROOT)
        explicit = locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                               revocations=[])
        self.assertEqual(default, explicit)
        self.assertIsInstance(explicit, Consensus)
        self.assertTrue(explicit.accepted)

    def test_duplicate_revocation_pair_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        revocation = revoke_trust(trusts[0], ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[revocation, revocation.to_bytes()])

    def test_unknown_id_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        absent = cert("z", 1.0, 1.0, b"\x77" * 32, ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[revoke_trust(absent, ROOT)])

    def test_target_mismatch_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        # A validly root-MAC'd revocation naming id "a" but a different
        # target must not revoke the presented "a" certificate and must be
        # rejected because it hits nothing.
        placeholder = TrustRevocation(1, "a", b"\x12" * 32, b"\x00" * 32)
        placeholder = dataclasses.replace(
            placeholder,
            mac=hmac.new(
                ROOT,
                b"NPVR1" + json.dumps(
                    {"version": 1, "id": "a", "target": "12" * 32},
                    separators=(",", ":"),
                ).encode(),
                hashlib.sha256,
            ).digest(),
        )
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[placeholder])

    def test_revocation_target_is_bound_to_one_certificate_mac(self):
        # A certificate for the same id "a" but with a different mac (here
        # issued under another root) yields a revocation that does not hit
        # the presented chain's "a" certificate, and is rejected as
        # unmatched rather than revoking the live cert.
        old_cert = cert("a", 3.0, 0.0, KEY_A, OTHER_ROOT)
        old_revocation = revoke_trust(old_cert, ROOT)
        new_trusts = triangle_trusts()
        records = triangle_records()
        # Its MAC was made under ROOT but target names the other-root cert's
        # mac, so it matches nothing under the presented chain.
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, new_trusts, ROOT,
                        revocations=[old_revocation])

    def test_wrong_root_revocation_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        forged = revoke_trust(trusts[0], OTHER_ROOT)
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[forged])

    def test_tampered_revocation_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        forged = dataclasses.replace(
            revoke_trust(trusts[0], ROOT), mac=b"\x00" * 32
        )
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[forged])

    def test_invalid_revocation_item_types_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        for bad in (42, "x", None, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                            revocations=[bad])

    def test_non_iterable_revocations_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        for bad in (42, 1, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                            revocations=bad)

    def test_non_bytes_root_type_rejected(self):
        trusts = triangle_trusts()
        records = triangle_records()
        revocation = revoke_trust(trusts[0], ROOT)
        with self.assertRaises(TypeError):
            locate_cert(records, POINT, CONTEXT, trusts, bytearray(ROOT),
                        revocations=[revocation])

    def test_empty_root_value_error_even_without_revocations(self):
        with self.assertRaises(ValueError):
            locate_cert(triangle_records(), POINT, CONTEXT,
                        triangle_trusts(), b"")

    def test_revocation_only_applies_to_named_target(self):
        # Two revocations with distinct targets: one hits cert a, the other
        # names a's id but a nonexistent target. The call must fail for the
        # unmatched one (and the matched one would fail too); either way no
        # consensus is produced.
        trusts = triangle_trusts()
        records = triangle_records()
        good = revoke_trust(trusts[0], ROOT)
        placeholder = TrustRevocation(1, "a", b"\x34" * 32, b"\x00" * 32)
        placeholder = dataclasses.replace(
            placeholder,
            mac=hmac.new(
                ROOT,
                b"NPVR1" + json.dumps(
                    {"version": 1, "id": "a", "target": "34" * 32},
                    separators=(",", ":"),
                ).encode(),
                hashlib.sha256,
            ).digest(),
        )
        with self.assertRaises(ValueError):
            locate_cert(records, POINT, CONTEXT, trusts, ROOT,
                        revocations=[good, placeholder])

    def test_revocations_is_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_cert(triangle_records(), POINT, CONTEXT,
                        triangle_trusts(), ROOT, [])


if __name__ == "__main__":
    unittest.main()
