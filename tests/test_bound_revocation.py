import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BoundEvidence,
    BoundEvidenceRevocation,
    Measurement,
    Prover,
    Verifier,
    audit_bound,
    audit_bound_policy,
    context_digest,
    revoke_bound,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret-key"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def make_bound(trip=0.5, verifier_key=KEY, prover_key=KEY):
    clock = SteppedClock(start=100.0)
    prover = Prover(prover_key)
    verifier = Verifier(verifier_key, clock=clock, replay_protection=True)
    challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
    started = clock.now
    response = prover.reveal(challenge, CONTEXT, OPENING)
    clock.now += trip
    record = verifier.verify_bound(challenge, response, started, opening=OPENING)
    return record, clock.now


def revoke(record, revoked_at, *, key=KEY):
    return revoke_bound(record, revoked_at, key)


class BoundEvidenceRevocationContractTest(unittest.TestCase):
    def setUp(self):
        self.record, _ = make_bound()

    def test_is_frozen(self):
        revocation = revoke(self.record, 1.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            revocation.revoked_at = 9.0

    def test_valid_construction(self):
        revocation = BoundEvidenceRevocation(
            1, 7, b"\xaa" * 16, 3.5, b"\x00" * 32
        )
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.round_index, 7)
        self.assertEqual(revocation.nonce, b"\xaa" * 16)
        self.assertEqual(revocation.revoked_at, 3.5)
        self.assertEqual(revocation.mac, b"\x00" * 32)

    def test_u64_boundary_valid(self):
        revocation = BoundEvidenceRevocation(
            1, 2**64 - 1, b"\xaa" * 16, 0.0, b"\x00" * 32
        )
        self.assertEqual(revocation.round_index, 2**64 - 1)

    def test_equality_is_field_wise(self):
        one = revoke(self.record, 1.0)
        two = BoundEvidenceRevocation(
            1, one.round_index, one.nonce, 1.0, bytes(one.mac)
        )
        self.assertEqual(one, two)
        changed = dataclasses.replace(two, revoked_at=2.0)
        self.assertNotEqual(one, changed)

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(bad, 1, b"n" * 16, 0.0, b"\x00" * 32)

    def test_round_index_must_be_non_bool_u64(self):
        for bad in (1.0, True, False, "1", None, -1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, bad, b"n" * 16, 0.0, b"\x00" * 32)

    def test_nonce_must_be_exactly_16_bytes(self):
        for bad in (b"", b"n" * 15, b"n" * 17, "00" * 16, None, 16):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, 1, bad, 0.0, b"\x00" * 32)

    def test_revoked_at_must_be_finite_non_bool_non_negative(self):
        for bad in (True, -1.0, -0.5, math.inf, -math.inf, math.nan, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, 1, b"n" * 16, bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "00" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, 1, b"n" * 16, 0.0, bad)


class RevokeBoundTest(unittest.TestCase):
    def setUp(self):
        self.record, self.end = make_bound()

    def test_signs_with_key(self):
        revocation = revoke_bound(self.record, 3.0, KEY)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.round_index, self.record.evidence.round_index)
        self.assertEqual(revocation.nonce, self.record.evidence.nonce)
        self.assertEqual(revocation.revoked_at, 3.0)
        self.assertEqual(len(revocation.mac), 32)
        # The signed record is accepted by audit_bound_policy.
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, revocations=[revocation]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_mac_uses_npbr1_prefix_and_canonical_payload(self):
        revocation = revoke_bound(self.record, 2.5, KEY)
        payload = {
            "version": 1,
            "round_index": self.record.evidence.round_index,
            "nonce": self.record.evidence.nonce.hex(),
            "revoked_at": 2.5,
        }
        expected = hmac.new(
            KEY,
            b"NPBR1"
            + json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self.assertEqual(revocation.mac, expected)

    def test_accepts_bound_evidence_bytes(self):
        revocation = revoke_bound(self.record.to_bytes(), 3.0, KEY)
        self.assertEqual(revocation.round_index, self.record.evidence.round_index)
        self.assertEqual(revocation.nonce, self.record.evidence.nonce)

    def test_rejects_invalid_bound(self):
        for bad in (None, 42, "record", object(), b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_bound(bad, 3.0, KEY)

    def test_empty_key_rejected(self):
        for bad in (b"", "", None, 0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_bound(self.record, 3.0, bad)

    def test_invalid_revoked_at_rejected(self):
        for bad in (-1.0, math.nan, math.inf, True, "now"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_bound(self.record, bad, KEY)

    def test_different_keys_give_different_macs(self):
        one = revoke_bound(self.record, 3.0, KEY)
        two = revoke_bound(self.record, 3.0, OTHER_KEY)
        self.assertNotEqual(one.mac, two.mac)


class BoundRevocationSerializationTest(unittest.TestCase):
    def setUp(self):
        self.record, _ = make_bound()

    def test_round_trip(self):
        revocation = revoke(self.record, 7.25)
        clone = BoundEvidenceRevocation.from_bytes(revocation.to_bytes())
        self.assertEqual(clone, revocation)

    def test_canonical_encoding(self):
        revocation = BoundEvidenceRevocation(1, 5, b"\xab" * 16, 3.0, b"\x00" * 32)
        blob = revocation.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj), ["version", "round_index", "nonce", "revoked_at", "mac"]
        )
        self.assertEqual(obj["nonce"], "ab" * 16)
        self.assertEqual(obj["mac"], "00" * 32)

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "round_index": 5,
            "nonce": "ab" * 16,
            "revoked_at": 3.0,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", None, 42, bytearray(b"{}")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3]", b'"s"', b"1", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation.from_bytes(bad)

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["revoked_at"]
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"nonce":"' + "cd" * 16 + '"}'
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_nonce_encoding(self):
        for bad in ("ab" * 15, "ab" * 17, "0G" * 16, "AB" * 16, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation.from_bytes(self._blob(nonce=bad))

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0G" * 32, "AA" * 32, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(version=2))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(round_index=True))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(round_index=2**64))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(revoked_at=-1.0))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(revoked_at=True))

    def test_from_bytes_rejects_whitespace(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(blob.replace(b",", b", ", 1))
        for padded in (b" " + blob, blob + b"\n"):
            with self.assertRaises(ValueError, msg=repr(padded[:8])):
                BoundEvidenceRevocation.from_bytes(padded)

    def test_from_bytes_rejects_pretty_printed_json(self):
        obj = json.loads(self._blob())
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(json.dumps(obj, indent=2).encode())

    def test_from_bytes_rejects_noncanonical_numbers(self):
        blob = self._blob().replace(
            b'"revoked_at":3.0', b'"revoked_at":3.00'
        )
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(blob)

    def test_from_bytes_preserves_integer_revoked_at(self):
        blob = self._blob(revoked_at=3)
        record = BoundEvidenceRevocation.from_bytes(blob)
        self.assertEqual(record.revoked_at, 3)
        self.assertIs(type(record.revoked_at), int)
        self.assertEqual(record.to_bytes(), blob)

    def test_from_bytes_preserves_float_revoked_at(self):
        blob = self._blob(revoked_at=3.5)
        record = BoundEvidenceRevocation.from_bytes(blob)
        self.assertEqual(record.revoked_at, 3.5)
        self.assertIs(type(record.revoked_at), float)
        self.assertEqual(record.to_bytes(), blob)

    def test_from_bytes_integer_revoked_at_contract(self):
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(revoked_at=-3))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(
                self._blob(revoked_at="3")
            )

    def test_from_bytes_rejects_length_prefix(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(bytes([len(blob)]) + blob)

    def test_from_bytes_does_not_verify_mac(self):
        record = BoundEvidenceRevocation.from_bytes(self._blob())
        self.assertEqual(record.mac, b"\x00" * 32)


class AuditBoundPolicyRevocationsTest(unittest.TestCase):
    def setUp(self):
        self.record, self.end = make_bound()

    def test_none_keeps_original_behaviour(self):
        for now in (None, 0.0, 1e9, "junk", object()):
            with self.subTest(now=now):
                measurement = audit_bound_policy(
                    self.record, KEY, now=now, revocations=None
                )
                self.assertIsInstance(measurement, Measurement)
        self.assertEqual(
            audit_bound_policy(self.record, KEY),
            audit_bound(self.record, KEY),
        )

    def test_empty_revocations_requires_now(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(self.record, KEY, revocations=[])
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, revocations=[]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_accepts_bytes_bound(self):
        blob = self.record.to_bytes()
        revocation = revoke_bound(blob, self.end - 1.0, KEY)
        measurement = audit_bound_policy(
            blob, KEY, now=self.end, revocations=[revocation.to_bytes()]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_mixed_objects_and_bytes(self):
        record_two, _ = make_bound()
        revocation_one = revoke(self.record, self.end - 1.0).to_bytes()
        revocation_two = revoke_bound(record_two, 0.0, KEY)
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end,
            revocations=[revocation_one, revocation_two],
        )
        self.assertIsInstance(measurement, Measurement)

    def test_non_matching_revocation_does_not_affect(self):
        other, _ = make_bound()
        # A different (round_index, nonce) pair never matches; its MAC and
        # timestamp are still validated. Dated in the past, it is accepted.
        revocation = revoke_bound(other, 0.0, KEY)
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, revocations=[revocation]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_revocation_strictly_before_end_survives(self):
        revocation = revoke(self.record, self.end - 1e-9)
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, revocations=[revocation]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_revocation_at_end_rejected(self):
        revocation = revoke(self.record, self.end)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )

    def test_revocation_after_end_rejected(self):
        revocation = revoke(self.record, self.end + 1.0)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end + 2.0, revocations=[revocation]
            )

    def test_future_revocation_rejected_even_without_match(self):
        other, _ = make_bound()
        revocation = revoke_bound(other, self.end + 10.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )

    def test_wrong_key_rejected(self):
        revocation = revoke_bound(self.record, self.end - 1.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )

    def test_tampered_revocation_rejected(self):
        tampered = dataclasses.replace(
            revoke(self.record, self.end - 1.0), revoked_at=self.end
        )
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[tampered]
            )

    def test_tampered_revocation_bytes_rejected(self):
        blob = revoke(self.record, 1.0).to_bytes().replace(
            b'"revoked_at":1.0', b'"revoked_at":2.0'
        )
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[blob]
            )

    def test_duplicate_revocation_pair_rejected(self):
        one = revoke(self.record, 0.0)
        two = revoke_bound(self.record, 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[one, two]
            )

    def test_invalid_revocation_items_rejected(self):
        for bad in ([1], [None], ["revocation"], [b"not json"], [object()]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_bound_policy(
                    self.record, KEY, now=self.end, revocations=bad
                )
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=42
            )

    def test_now_contract_with_revocations(self):
        revocation = revoke(self.record, 0.0)
        for bad in (None, math.inf, math.nan, True, "now"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_bound_policy(
                    self.record, KEY, now=bad, revocations=[revocation]
                )

    def test_revocation_composes_with_max_age(self):
        revocation = revoke(self.record, self.end - 1.0)
        # Survives the revocation and is fresh: accepted.
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, max_age=10.0,
            revocations=[revocation],
        )
        self.assertIsInstance(measurement, Measurement)
        # Same setup but stale per max_age: rejected.
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end + 11.0, max_age=10.0,
                revocations=[revocation],
            )

    def test_cryptographic_failure_surfaces_first(self):
        tampered = bytearray(self.record.to_bytes())
        tampered[-3] = ord("0") if tampered[-3] != ord("0") else ord("1")
        with self.assertRaises(ValueError):
            audit_bound_policy(
                bytes(tampered), KEY, now=self.end, revocations=[]
            )
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, b"wrong-key", now=self.end, revocations=[]
            )

    def test_audit_is_pure(self):
        revocation = revoke(self.record, self.end - 1.0)
        for _ in range(2):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )
        # Nothing is consumed or mutated; the same record audits standalone.
        self.assertIsInstance(audit_bound(self.record, KEY), Measurement)


if __name__ == "__main__":
    unittest.main()
