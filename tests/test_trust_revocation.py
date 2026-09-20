import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
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
    def make(self, **overrides):
        values = {
            "version": 1,
            "id": "a",
            "target": trust("a").mac,
            "mac": b"\x00" * 32,
        }
        values.update(overrides)
        return TrustRevocation(
            values["version"], values["id"], values["target"], values["mac"]
        )

    def test_is_frozen_and_equal_by_fields(self):
        first = revoke_trust(trust("a"), ROOT)
        second = TrustRevocation(1, "a", bytes(first.target), bytes(first.mac))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.target = b"\x01" * 32

    def test_positional_field_order(self):
        revocation = self.make()
        self.assertEqual(
            (revocation.version, revocation.id,
             revocation.target, revocation.mac),
            (1, "a", trust("a").mac, b"\x00" * 32),
        )

    def test_valid_construction(self):
        target = trust("a").mac
        revocation = TrustRevocation(1, "a", target, b"\x00" * 32)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.id, "a")
        self.assertEqual(revocation.target, target)
        self.assertEqual(revocation.mac, b"\x00" * 32)

    def test_version_shape_type_error(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(version=bad)

    def test_version_must_be_one(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)

    def test_id_shape_type_error(self):
        for bad in (b"a", None, 7, bytearray(b"a")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(id=bad)

    def test_id_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            self.make(id="")

    def test_target_shape_type_error(self):
        for bad in ("ab" * 32, None, 7, bytearray(b"\x00" * 32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(target=bad)

    def test_mac_shape_type_error(self):
        for bad in ("00" * 32, None, 7, bytearray(b"\x00" * 32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(mac=bad)

    def test_target_and_mac_must_be_exactly_32_bytes(self):
        for name in ("target", "mac"):
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=repr((name, bad))):
                    self.make(**{name: bad})


class RevokeTrustTest(unittest.TestCase):
    def test_signs_a_revocation_targeting_the_certificate_mac(self):
        certificate = trust("a")
        revocation = revoke_trust(certificate, ROOT)
        self.assertIsInstance(revocation, TrustRevocation)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.id, "a")
        self.assertEqual(revocation.target, certificate.mac)
        self.assertEqual(len(revocation.mac), 32)
        self.assertNotEqual(revocation.mac, b"\x00" * 32)

    def test_mac_uses_npvr1_prefix_and_canonical_payload(self):
        certificate = trust("a")
        revocation = revoke_trust(certificate, ROOT)
        payload = {
            "version": 1,
            "id": "a",
            "target": certificate.mac.hex(),
        }
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(ROOT, b"NPVR1" + encoding, hashlib.sha256).digest()
        self.assertEqual(revocation.mac, expected)

    def test_prefix_has_no_length_prefix(self):
        # A length-prefixed construction must not authenticate.
        certificate = trust("a")
        revocation = revoke_trust(certificate, ROOT)
        payload = json.dumps(
            {"version": 1, "id": "a", "target": certificate.mac.hex()},
            separators=(",", ":"),
        ).encode("utf-8")
        forged = hmac.new(
            ROOT, b"NPVR1" + str(len(payload)).encode() + payload, hashlib.sha256
        ).digest()
        self.assertNotEqual(revocation.mac, forged)

    def test_different_roots_give_different_macs(self):
        certificate = trust("a")
        self.assertNotEqual(
            revoke_trust(certificate, ROOT).mac,
            revoke_trust(certificate, OTHER_ROOT).mac,
        )

    def test_revocation_is_pure_data(self):
        certificate = trust("a")
        first = revoke_trust(certificate, ROOT)
        second = revoke_trust(certificate, ROOT)
        self.assertEqual(first, second)
        # The trust record is not mutated.
        self.assertEqual(certificate, trust("a"))

    def test_only_verifier_trust_accepted(self):
        for bad in (trust("a").to_bytes(), b"not json", None, 42, object(),
                    record("a")):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                revoke_trust(bad, ROOT)

    def test_empty_root_rejected(self):
        with self.assertRaises(ValueError):
            revoke_trust(trust("a"), b"")

    def test_non_bytes_root_rejected(self):
        for bad in (bytearray(ROOT), "", None, 0, bytearray()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                revoke_trust(trust("a"), bad)


class TrustRevocationSerializationTest(unittest.TestCase):
    def test_round_trip(self):
        revocation = revoke_trust(trust("a"), ROOT)
        self.assertEqual(
            TrustRevocation.from_bytes(revocation.to_bytes()), revocation
        )

    def test_canonical_encoding(self):
        target = b"\xab" * 32
        revocation = TrustRevocation(1, "a", target, b"\x00" * 32)
        blob = revocation.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(list(obj), ["version", "id", "target", "mac"])
        self.assertEqual(obj["target"], "ab" * 32)
        self.assertEqual(obj["mac"], "00" * 32)

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "id": "a",
            "target": "ab" * 32,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", None, 42, bytearray(b"{}")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3,4]", b'"s"', b"1", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation.from_bytes(bad)

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["target"]
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"id":"b"}'
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_target_encoding(self):
        for bad in ("ab" * 31, "ab" * 33, "0g" * 32, "AB" * 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation.from_bytes(self._blob(target=bad))
        for bad in (123, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation.from_bytes(self._blob(target=bad))

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0g" * 32, "AA" * 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocation.from_bytes(self._blob(mac=bad))
        for bad in (123, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(self._blob(version=2))
        with self.assertRaises(TypeError):
            TrustRevocation.from_bytes(self._blob(version="1"))
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(self._blob(id=""))
        with self.assertRaises(TypeError):
            TrustRevocation.from_bytes(self._blob(id=7))

    def test_from_bytes_rejects_whitespace_and_framing(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            TrustRevocation.from_bytes(blob.replace(b",", b", ", 1))
        for bad in (b" " + blob, blob + b"\n",
                    bytes([len(blob)]) + blob):
            with self.assertRaises(ValueError, msg=repr(bad[:8])):
                TrustRevocation.from_bytes(bad)

    def test_from_bytes_does_not_verify_mac(self):
        record = TrustRevocation.from_bytes(self._blob())
        self.assertEqual(record.mac, b"\x00" * 32)
        # A forged mac decodes fine; locate_cert is what rejects it.
        self.assertEqual(record.target, b"\xab" * 32)


class LocateCertRevocationsTest(unittest.TestCase):
    def consensus(self, *, revocations):
        return locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
            revocations=revocations,
        )

    def test_none_and_empty_leave_consensus_unchanged(self):
        expected = locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )
        self.assertEqual(
            locate_cert(triangle_records(), POINT, CONTEXT, triangle_trusts(),
                        ROOT, revocations=None),
            expected,
        )
        self.assertEqual(
            locate_cert(triangle_records(), POINT, CONTEXT, triangle_trusts(),
                        ROOT, revocations=[]),
            expected,
        )

    def test_revocation_is_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                [],
            )

    def test_accepts_mixed_objects_and_bytes(self):
        # Every valid revocation hits a used certificate, so the call fails;
        # mixing the object and bytes forms must still parse and verify both
        # (failure happens at the revoked-certificate check, message and all,
        # not at an "invalid item" rejection).
        trusts = triangle_trusts()
        revocations = [
            revoke_trust(trusts[0], ROOT),          # object form, hits a
            revoke_trust(trusts[2], ROOT).to_bytes(),  # bytes form, hits c
        ]
        with self.assertRaisesRegex(ValueError, "revoked"):
            self.consensus(revocations=revocations)

    def test_bytes_alone_parses_and_hits(self):
        # Records verify in order a, b, c; only c is revoked, so the error
        # message proves the bytes blob parsed, root-verified and hit.
        trusts = triangle_trusts()
        with self.assertRaisesRegex(ValueError, r"revoked: 'c'"):
            self.consensus(
                revocations=[revoke_trust(trusts[2], ROOT).to_bytes()]
            )

    def test_hit_revokes_the_certificate(self):
        trusts = triangle_trusts()
        for index in range(3):
            with self.assertRaises(ValueError, msg=f"index {index}"):
                self.consensus(
                    revocations=[revoke_trust(trusts[index], ROOT).to_bytes()]
                )

    def test_revoked_object_form_equally_rejected(self):
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revoke_trust(trusts[1], ROOT)])

    def test_miss_target_against_used_id_rejected(self):
        # Same id, target of a different certificate: never silently ignored.
        other = cert("a", 9.0, 9.0, KEY_A, ROOT)
        revocation = revoke_trust(other, ROOT)
        self.assertEqual(revocation.id, "a")
        self.assertNotEqual(revocation.target, trust("a").mac)
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revocation])

    def test_miss_unknown_id_rejected(self):
        foreign = cert("zzz", 0.0, 0.0, b"\x77" * 32, ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revoke_trust(foreign, ROOT)])

    def test_target_of_certified_but_unused_trust_also_rejected(self):
        # The revocation names a trust present in `trusts`, but no record
        # uses that id: the pair hits none of the certificates the records
        # use, so it is a miss and a ValueError like any other miss.
        trusts = triangle_trusts() + [
            cert("d", 50.0, 50.0, b"\xdd" * 32, ROOT)
        ]
        revocation = revoke_trust(trusts[-1], ROOT)
        with self.assertRaises(ValueError):
            locate_cert(
                triangle_records(), POINT, CONTEXT, trusts, ROOT,
                revocations=[revocation.to_bytes()],
            )

    def test_duplicate_pair_rejected(self):
        trusts = triangle_trusts()
        revocation = revoke_trust(trusts[0], ROOT)
        with self.assertRaises(ValueError):
            self.consensus(
                revocations=[revocation, TrustRevocation.from_bytes(
                    revocation.to_bytes()
                )]
            )

    def test_same_id_different_target_is_not_a_duplicate_but_still_rejected(self):
        # Distinct pairs both miss the actually-used a-certificate: the
        # second one is a miss, not a duplicate, but still a ValueError.
        other = cert("a", 9.0, 9.0, KEY_A, ROOT)
        with self.assertRaises(ValueError):
            self.consensus(
                revocations=[
                    revoke_trust(other, ROOT),
                    revoke_trust(cert("a", 8.0, 8.0, KEY_A, ROOT), ROOT),
                ]
            )

    def test_wrong_root_rejected(self):
        revocation = revoke_trust(trust("a"), OTHER_ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revocation])

    def test_tampered_revocation_rejected(self):
        revocation = revoke_trust(trust("a"), ROOT)
        tampered = dataclasses.replace(revocation, id="b")
        with self.assertRaises(ValueError):
            self.consensus(revocations=[tampered])

    def test_tampered_revocation_bytes_rejected(self):
        blob = revoke_trust(trust("a"), ROOT).to_bytes().replace(
            b'"id":"a"', b'"id":"b"'
        )
        with self.assertRaises(ValueError):
            self.consensus(revocations=[blob])

    def test_invalid_revocation_items_rejected(self):
        for bad in ([1], [None], ["revocation"], [b"not json"], [object()],
                    [record("a")]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.consensus(revocations=bad)

    def test_non_iterable_revocations_rejected(self):
        for bad in (42, revoke_trust(trust("a"), ROOT)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.consensus(revocations=bad)

    def test_revoked_cert_rejected_before_geometry(self):
        # Revocation rejection is an exception regardless of geometry: even
        # the at-origin verifier c being revoked kills the call.
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revoke_trust(trusts[2], ROOT)])


if __name__ == "__main__":
    unittest.main()
