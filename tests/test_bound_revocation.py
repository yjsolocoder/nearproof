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
OTHER_KEY = b"other-shared-secret"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)

MAC0 = b"\x00" * 32


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def fixture():
    clock = SteppedClock()
    prover = Prover(KEY)
    verifier = Verifier(KEY, clock=clock, replay_protection=True)
    return clock, prover, verifier


def bound_round(verifier, prover, clock, trip=0.5):
    """Run one successful bound round and return its BoundEvidence."""
    challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
    started = clock.now
    response = prover.reveal(challenge, CONTEXT, OPENING)
    clock.now += trip
    return verifier.verify_bound(challenge, response, started, opening=OPENING)


def sign(round_index, nonce, revoked_at, key=KEY):
    """Build a revocation with a valid NPBR1 MAC, independently of the library."""
    payload = {
        "version": 1,
        "round_index": round_index,
        "nonce": nonce.hex(),
        "revoked_at": revoked_at,
    }
    canonical = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
    mac = hmac.new(key, b"NPBR1" + canonical, hashlib.sha256).digest()
    return BoundEvidenceRevocation(1, round_index, nonce, revoked_at, mac)


class BoundEvidenceRevocationContractTest(unittest.TestCase):
    def setUp(self):
        clock, prover, verifier = fixture()
        self.bound = bound_round(verifier, prover, clock)

    def test_is_frozen(self):
        record = revoke_bound(self.bound, 1.0, KEY)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.revoked_at = 9.0

    def test_valid_construction(self):
        record = BoundEvidenceRevocation(1, 7, b"n" * 16, 3, MAC0)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.round_index, 7)
        self.assertEqual(record.nonce, b"n" * 16)
        self.assertEqual(record.revoked_at, 3)
        self.assertEqual(record.mac, MAC0)

    def test_u64_boundaries_valid(self):
        BoundEvidenceRevocation(1, 0, b"n" * 16, 0.0, MAC0)
        BoundEvidenceRevocation(1, 0xFFFFFFFFFFFFFFFF, b"n" * 16, 0.0, MAC0)

    def test_equality_is_by_field(self):
        one = revoke_bound(self.bound, 1.0, KEY)
        two = BoundEvidenceRevocation(
            one.version, one.round_index, bytes(one.nonce),
            one.revoked_at, bytes(one.mac),
        )
        self.assertEqual(one, two)

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(bad, 1, b"n" * 16, 0.0, MAC0)

    def test_round_index_must_be_non_bool_u64(self):
        for bad in (True, False, 1.0, "1", None, -1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, bad, b"n" * 16, 0.0, MAC0)

    def test_nonce_must_be_exactly_16_bytes(self):
        for bad in (b"", b"n" * 15, b"n" * 17, "00" * 16, bytearray(16), None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, 1, bad, 0.0, MAC0)

    def test_revoked_at_must_be_finite_non_bool_non_negative(self):
        for bad in (True, False, -1.0, -0.5, math.inf, -math.inf, math.nan, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, 1, b"n" * 16, bad, MAC0)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "00" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation(1, 1, b"n" * 16, 0.0, bad)


class RevokeBoundTest(unittest.TestCase):
    def setUp(self):
        clock, prover, verifier = fixture()
        self.bound = bound_round(verifier, prover, clock)

    def test_signs_with_key(self):
        record = revoke_bound(self.bound, 3.0, KEY)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.round_index, self.bound.evidence.round_index)
        self.assertEqual(record.nonce, self.bound.evidence.nonce)
        self.assertEqual(record.revoked_at, 3.0)
        self.assertEqual(len(record.mac), 32)
        # The mac verifies under the signing key (checked via the policy).
        with self.assertRaises(ValueError):
            # end=0.5 <= revoked_at=3.0 -> revoked
            audit_bound_policy(self.bound, KEY, revocations=[record], now=4.0)

    def test_accepts_canonical_bytes(self):
        record = revoke_bound(self.bound.to_bytes(), 3.0, KEY)
        self.assertEqual(record.round_index, self.bound.evidence.round_index)
        self.assertEqual(record.nonce, self.bound.evidence.nonce)

    def test_rejects_non_bound_evidence(self):
        for bad in (42, object(), b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_bound(bad, 3.0, KEY)

    def test_empty_key_rejected(self):
        for bad in (b"", "", None, 0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_bound(self.bound, 3.0, bad)

    def test_invalid_fields_rejected(self):
        with self.assertRaises(ValueError):
            revoke_bound(self.bound, -3.0, KEY)
        with self.assertRaises(ValueError):
            revoke_bound(self.bound, math.nan, KEY)

    def test_different_keys_give_different_macs(self):
        one = revoke_bound(self.bound, 3.0, KEY)
        two = revoke_bound(self.bound, 3.0, OTHER_KEY)
        self.assertNotEqual(one.mac, two.mac)

    def test_different_rounds_give_different_records(self):
        clock, prover, verifier = fixture()
        first = bound_round(verifier, prover, clock)
        second = bound_round(verifier, prover, clock)
        self.assertNotEqual(
            revoke_bound(first, 1.0, KEY), revoke_bound(second, 1.0, KEY)
        )


class BoundEvidenceRevocationSerializationTest(unittest.TestCase):
    def setUp(self):
        clock, prover, verifier = fixture()
        self.record = revoke_bound(bound_round(verifier, prover, clock), 7.25, KEY)

    def test_round_trip(self):
        clone = BoundEvidenceRevocation.from_bytes(self.record.to_bytes())
        self.assertEqual(clone, self.record)

    def test_integer_revoked_at_round_trip(self):
        # An int revoked_at must keep its int spelling through the canonical
        # re-encoding comparison (not be widened to 3.0).
        record = sign(1, b"n" * 16, 3)
        self.assertEqual(type(record.revoked_at), int)
        blob = record.to_bytes()
        self.assertIn(b'"revoked_at":3,', blob)
        clone = BoundEvidenceRevocation.from_bytes(blob)
        self.assertEqual(clone, record)
        self.assertEqual(type(clone.revoked_at), int)

    def test_canonical_encoding(self):
        record = BoundEvidenceRevocation(1, 42, b"\xab" * 16, 3.0, MAC0)
        blob = record.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj), ["version", "round_index", "nonce", "revoked_at", "mac"]
        )
        self.assertEqual(obj["nonce"], "ab" * 16)
        self.assertEqual(obj["mac"], "00" * 32)
        # A single JSON document with no length prefix or framing.
        self.assertEqual(
            blob,
            b'{"version":1,"round_index":42,"nonce":"' + b"ab" * 16
            + b'","revoked_at":3.0,"mac":"' + b"00" * 32 + b'"}',
        )

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "round_index": 1,
            "nonce": "00" * 16,
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
        text = text[:-1] + ',"round_index":2}'
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
        for bad in ("00" * 15, "00" * 17, "0g" * 16, "AB" * 16, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation.from_bytes(self._blob(nonce=bad))

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0g" * 32, "AA" * 32, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidenceRevocation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(version=2))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(round_index=True))
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(self._blob(round_index=-1))
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
        blob = self._blob().replace(b'"revoked_at":3.0', b'"revoked_at":3.00')
        with self.assertRaises(ValueError):
            BoundEvidenceRevocation.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        record = BoundEvidenceRevocation.from_bytes(self._blob())
        self.assertEqual(record.mac, MAC0)


class AuditBoundPolicyRevocationsTest(unittest.TestCase):
    def setUp(self):
        self.clock, self.prover, self.verifier = fixture()
        self.bound = bound_round(self.verifier, self.prover, self.clock)
        self.end = self.bound.evidence.end  # 0.5

    def _audit(self, revocations, *, now=2.0, **kwargs):
        return audit_bound_policy(
            self.bound, KEY, revocations=revocations, now=now, **kwargs
        )

    def test_none_keeps_original_behaviour(self):
        expected = audit_bound(self.bound, KEY)
        self.assertEqual(audit_bound_policy(self.bound, KEY, revocations=None), expected)
        # `now` stays ignored, even with junk values, without revocations.
        for now in (None, "junk", object()):
            measurement = audit_bound_policy(self.bound, KEY, now=now)
            self.assertEqual(measurement, expected)

    def test_empty_revocations_accepted_with_now(self):
        measurement = self._audit([])
        self.assertIsInstance(measurement, Measurement)

    def test_empty_revocations_requires_now(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(self.bound, KEY, revocations=[])

    def test_round_completed_strictly_after_revocation_survives(self):
        revocation = revoke_bound(self.bound, self.end - 0.1, KEY)
        measurement = self._audit([revocation])
        self.assertIsInstance(measurement, Measurement)

    def test_round_completed_at_revocation_rejected(self):
        revocation = revoke_bound(self.bound, self.end, KEY)
        with self.assertRaises(ValueError):
            self._audit([revocation])

    def test_round_completed_before_revocation_rejected(self):
        revocation = revoke_bound(self.bound, self.end + 1.0, KEY)
        with self.assertRaises(ValueError):
            self._audit([revocation], now=self.end + 2.0)

    def test_mixed_objects_and_bytes(self):
        surviving = revoke_bound(self.bound, self.end - 0.1, KEY)
        # A non-matching revocation mixed in does not affect the result and
        # lets objects and byte encodings coexist without duplicate matching.
        other = sign(self.bound.evidence.round_index + 99, b"q" * 16, 0.1)
        self.assertIsInstance(
            self._audit([surviving, other.to_bytes()]), Measurement
        )
        self.assertIsInstance(
            self._audit([surviving.to_bytes(), other]), Measurement
        )

    def test_duplicate_matching_revocation_rejected(self):
        surviving = revoke_bound(self.bound, self.end - 0.1, KEY)
        with self.assertRaises(ValueError):
            self._audit([surviving, surviving])
        with self.assertRaises(ValueError):
            self._audit([surviving, surviving.to_bytes()])

    def test_revocation_for_other_round_ignored(self):
        # Same round index, different nonce: does not match.
        other_nonce = sign(
            self.bound.evidence.round_index, b"z" * 16, 0.1
        )
        self.assertIsInstance(self._audit([other_nonce]), Measurement)
        # Different round index, same nonce: does not match.
        other_round = sign(
            self.bound.evidence.round_index + 1, self.bound.evidence.nonce, 100.0
        )
        self.assertIsInstance(self._audit([other_round]), Measurement)

    def test_revocation_from_other_bound_round_ignored(self):
        other_bound = bound_round(self.verifier, self.prover, self.clock, trip=0.0)
        self.assertNotEqual(
            (other_bound.evidence.round_index, other_bound.evidence.nonce),
            (self.bound.evidence.round_index, self.bound.evidence.nonce),
        )
        other_revocation = revoke_bound(other_bound, self.clock.now, KEY)
        self.assertIsInstance(self._audit([other_revocation]), Measurement)

    def test_wrong_key_rejected(self):
        revocation = revoke_bound(self.bound, self.end - 0.1, OTHER_KEY)
        with self.assertRaises(ValueError):
            self._audit([revocation])

    def test_tampered_revocation_rejected(self):
        tampered = dataclasses.replace(
            revoke_bound(self.bound, self.end - 0.1, KEY), revoked_at=0.01
        )
        with self.assertRaises(ValueError):
            self._audit([tampered])

    def test_tampered_revocation_bytes_rejected(self):
        blob = revoke_bound(self.bound, 0.1, KEY).to_bytes()
        tampered = blob.replace(b'"revoked_at":0.1', b'"revoked_at":0.2')
        self.assertNotEqual(tampered, blob)
        with self.assertRaises(ValueError):
            self._audit([tampered])

    def test_invalid_revocation_items_rejected(self):
        for bad in ([1], [None], ["revocation"], [b"not json"], [object()]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self._audit(bad)
        with self.assertRaises(ValueError):
            self._audit(42)

    def test_future_revocation_rejected(self):
        revocation = revoke_bound(self.bound, 3.0, KEY)
        with self.assertRaises(ValueError):
            self._audit([revocation], now=2.0)

    def test_now_contract_with_revocations(self):
        surviving = revoke_bound(self.bound, self.end - 0.1, KEY)
        for bad in (math.inf, math.nan, True, False, "now"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self._audit([surviving], now=bad)

    def test_accepts_canonical_bound_bytes(self):
        surviving = revoke_bound(self.bound, self.end - 0.1, KEY)
        measurement = audit_bound_policy(
            self.bound.to_bytes(), KEY, revocations=[surviving], now=2.0
        )
        self.assertIsInstance(measurement, Measurement)

    def test_cryptographic_failure_surfaces_first(self):
        tampered = bytearray(self.bound.to_bytes())
        tampered[-3] = ord("0") if tampered[-3] != ord("0") else ord("1")
        # audit_bound's checks run before the now/revocation contract.
        with self.assertRaises(ValueError):
            audit_bound_policy(bytes(tampered), KEY, revocations=[])
        with self.assertRaises(ValueError):
            audit_bound_policy(self.bound, b"wrong-key", revocations=[])

    def test_revocation_composes_with_max_age(self):
        surviving = revoke_bound(self.bound, self.end - 0.1, KEY)
        # Fresh enough and completed after revocation: accepted.
        measurement = audit_bound_policy(
            self.bound, KEY, revocations=[surviving], now=self.end + 1.0,
            max_age=10.0,
        )
        self.assertIsInstance(measurement, Measurement)
        # Same revocation but stale per max_age: rejected.
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.bound, KEY, revocations=[surviving], now=self.end + 11.0,
                max_age=10.0,
            )
        # Revoked (end <= revoked_at) even though fresh per max_age: rejected.
        revoked = revoke_bound(self.bound, self.end, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.bound, KEY, revocations=[revoked], now=self.end + 1.0,
                max_age=10.0,
            )

    def test_audit_is_pure(self):
        surviving = revoke_bound(self.bound, self.end - 0.1, KEY)
        for _ in range(2):
            self._audit([surviving])
        # The verifier can still run new rounds and the record still verifies.
        self.assertIsInstance(
            bound_round(self.verifier, self.prover, self.clock), BoundEvidence
        )


if __name__ == "__main__":
    unittest.main()
