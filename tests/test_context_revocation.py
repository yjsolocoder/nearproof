import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BoundEvidence,
    BoundEvidenceRevocation,
    ContextRevocation,
    Measurement,
    Prover,
    Verifier,
    audit_bound,
    audit_bound_policy,
    context_digest,
    revoke_bound,
    revoke_context,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret-key"
CONTEXT = b"c" * 32
OTHER_CONTEXT = b"x" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def make_bound(trip=0.5, verifier_key=KEY, prover_key=KEY, context=CONTEXT):
    clock = SteppedClock(start=100.0)
    prover = Prover(prover_key)
    verifier = Verifier(verifier_key, clock=clock, replay_protection=True)
    digest = context_digest(context, OPENING)
    challenge = verifier.new_challenge(context=context, digest=digest)
    started = clock.now
    response = prover.reveal(challenge, context, OPENING)
    clock.now += trip
    record = verifier.verify_bound(challenge, response, started, opening=OPENING)
    return record, clock.now


class ContextRevocationContractTest(unittest.TestCase):
    def test_is_frozen(self):
        revocation = revoke_context(CONTEXT, 1.0, KEY)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            revocation.revoked_at = 9.0

    def test_valid_construction(self):
        revocation = ContextRevocation(1, CONTEXT, 3.5, b"\x00" * 32)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.context, CONTEXT)
        self.assertEqual(revocation.revoked_at, 3.5)
        self.assertEqual(revocation.mac, b"\x00" * 32)

    def test_revoked_at_stored_as_float(self):
        revocation = ContextRevocation(1, CONTEXT, 3, b"\x00" * 32)
        self.assertEqual(revocation.revoked_at, 3.0)
        self.assertIs(type(revocation.revoked_at), float)

    def test_equality_is_field_wise(self):
        one = revoke_context(CONTEXT, 1.0, KEY)
        two = ContextRevocation(1, CONTEXT, 1.0, bytes(one.mac))
        self.assertEqual(one, two)
        changed = dataclasses.replace(two, revoked_at=2.0)
        self.assertNotEqual(one, changed)

    def test_version_shape_type_error(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation(bad, CONTEXT, 0.0, b"\x00" * 32)

    def test_version_must_be_one(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation(bad, CONTEXT, 0.0, b"\x00" * 32)

    def test_context_shape_type_error(self):
        for bad in ("c" * 32, None, 32, bytearray(CONTEXT)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation(1, bad, 0.0, b"\x00" * 32)

    def test_context_must_be_exactly_32_bytes(self):
        for bad in (b"", b"c" * 31, b"c" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation(1, bad, 0.0, b"\x00" * 32)

    def test_revoked_at_shape_type_error(self):
        for bad in ("0", None, b"\x00"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation(1, CONTEXT, bad, b"\x00" * 32)

    def test_revoked_at_must_be_finite_non_bool_non_negative(self):
        for bad in (True, -1.0, -0.5, math.inf, -math.inf, math.nan):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation(1, CONTEXT, bad, b"\x00" * 32)

    def test_mac_shape_type_error(self):
        for bad in ("00" * 32, None, 32, bytearray(b"\x00" * 32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation(1, CONTEXT, 0.0, bad)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation(1, CONTEXT, 0.0, bad)


class RevokeContextTest(unittest.TestCase):
    def test_signs_with_key(self):
        revocation = revoke_context(CONTEXT, 3.0, KEY)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.context, CONTEXT)
        self.assertEqual(revocation.revoked_at, 3.0)
        self.assertEqual(len(revocation.mac), 32)

    def test_mac_uses_npcr1_prefix_and_canonical_payload(self):
        revocation = revoke_context(CONTEXT, 2.5, KEY)
        payload = {
            "version": 1,
            "context": CONTEXT.hex(),
            "revoked_at": 2.5,
        }
        expected = hmac.new(
            KEY,
            b"NPCR1"
            + json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self.assertEqual(revocation.mac, expected)

    def test_revoked_at_stored_as_float(self):
        revocation = revoke_context(CONTEXT, 3, KEY)
        self.assertEqual(revocation.revoked_at, 3.0)
        self.assertIs(type(revocation.revoked_at), float)

    def test_empty_key_rejected(self):
        for bad in (b"", "", None, 0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_context(CONTEXT, 3.0, bad)

    def test_invalid_context_rejected(self):
        for bad in (b"", b"c" * 31, b"c" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_context(bad, 3.0, KEY)
        for bad in ("c" * 32, None, 32):
            with self.assertRaises(TypeError, msg=repr(bad)):
                revoke_context(bad, 3.0, KEY)

    def test_invalid_revoked_at_rejected(self):
        for bad in (-1.0, math.nan, math.inf, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_context(CONTEXT, bad, KEY)
        with self.assertRaises(TypeError):
            revoke_context(CONTEXT, "now", KEY)

    def test_different_keys_give_different_macs(self):
        one = revoke_context(CONTEXT, 3.0, KEY)
        two = revoke_context(CONTEXT, 3.0, OTHER_KEY)
        self.assertNotEqual(one.mac, two.mac)


class ContextRevocationSerializationTest(unittest.TestCase):
    def test_round_trip(self):
        revocation = revoke_context(CONTEXT, 7.25, KEY)
        clone = ContextRevocation.from_bytes(revocation.to_bytes())
        self.assertEqual(clone, revocation)

    def test_canonical_encoding(self):
        revocation = ContextRevocation(1, b"\xab" * 32, 3.0, b"\x00" * 32)
        blob = revocation.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(list(obj), ["version", "context", "revoked_at", "mac"])
        self.assertEqual(obj["context"], "ab" * 32)
        self.assertEqual(obj["mac"], "00" * 32)

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "context": "ab" * 32,
            "revoked_at": 3.0,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", None, 42, bytearray(b"{}")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3]", b'"s"', b"1", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation.from_bytes(bad)

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["revoked_at"]
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"context":"' + "cd" * 32 + '"}'
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_context_encoding(self):
        for bad in ("ab" * 31, "ab" * 33, "0G" * 32, "AB" * 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation.from_bytes(self._blob(context=bad))
        for bad in (123, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation.from_bytes(self._blob(context=bad))

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0G" * 32, "AA" * 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ContextRevocation.from_bytes(self._blob(mac=bad))
        for bad in (123, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ContextRevocation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(self._blob(version=2))
        with self.assertRaises(TypeError):
            ContextRevocation.from_bytes(self._blob(version="1"))
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(self._blob(revoked_at=-1.0))
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(self._blob(revoked_at=True))
        with self.assertRaises(TypeError):
            ContextRevocation.from_bytes(self._blob(revoked_at="3.0"))

    def test_from_bytes_rejects_integer_revoked_at_spelling(self):
        # revoked_at is stored as float, so only the float spelling is
        # canonical: 3 re-encodes as 3.0 and is rejected.
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(self._blob(revoked_at=3))

    def test_from_bytes_rejects_whitespace(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(blob.replace(b",", b", ", 1))
        for padded in (b" " + blob, blob + b"\n"):
            with self.assertRaises(ValueError, msg=repr(padded[:8])):
                ContextRevocation.from_bytes(padded)

    def test_from_bytes_rejects_pretty_printed_json(self):
        obj = json.loads(self._blob())
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(json.dumps(obj, indent=2).encode())

    def test_from_bytes_rejects_noncanonical_numbers(self):
        blob = self._blob().replace(
            b'"revoked_at":3.0', b'"revoked_at":3.00'
        )
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(blob)

    def test_from_bytes_rejects_length_prefix(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            ContextRevocation.from_bytes(bytes([len(blob)]) + blob)

    def test_from_bytes_does_not_verify_mac(self):
        record = ContextRevocation.from_bytes(self._blob())
        self.assertEqual(record.mac, b"\x00" * 32)


class AuditBoundPolicyContextRevocationsTest(unittest.TestCase):
    def setUp(self):
        self.record, self.end = make_bound()

    def test_matching_revocation_at_end_rejected(self):
        revocation = revoke_context(CONTEXT, self.end, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )

    def test_matching_revocation_after_end_rejected(self):
        revocation = revoke_context(CONTEXT, self.end + 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end + 2.0, revocations=[revocation]
            )

    def test_revocation_strictly_before_end_survives(self):
        revocation = revoke_context(CONTEXT, self.end - 1e-9, KEY)
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, revocations=[revocation]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_non_matching_context_ignored(self):
        revocation = revoke_context(OTHER_CONTEXT, self.end, KEY)
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, revocations=[revocation]
        )
        self.assertIsInstance(measurement, Measurement)

    def test_accepts_bytes_and_mixed_kinds(self):
        bound_revocation = revoke_bound(self.record, self.end - 1.0, KEY)
        context_revocation = revoke_context(OTHER_CONTEXT, 0.0, KEY)
        measurement = audit_bound_policy(
            self.record,
            KEY,
            now=self.end,
            revocations=[
                bound_revocation.to_bytes(),
                context_revocation,
                revoke_context(CONTEXT, 0.0, KEY).to_bytes(),
            ],
        )
        self.assertIsInstance(measurement, Measurement)

    def test_mixed_matching_kinds_each_apply(self):
        # A matching context revocation rejects even when a bound-evidence
        # revocation for the same round survives.
        bound_revocation = revoke_bound(self.record, self.end - 1.0, KEY)
        context_revocation = revoke_context(CONTEXT, self.end, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record,
                KEY,
                now=self.end,
                revocations=[bound_revocation, context_revocation],
            )

    def test_duplicate_context_rejected(self):
        one = revoke_context(CONTEXT, 0.0, KEY)
        two = revoke_context(CONTEXT, 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[one, two]
            )

    def test_same_context_as_bound_revocation_is_not_a_duplicate(self):
        # The two kinds dedup independently: a (round_index, nonce) pair and
        # a context do not collide.
        bound_revocation = revoke_bound(self.record, 0.0, KEY)
        context_revocation = revoke_context(CONTEXT, 0.0, KEY)
        measurement = audit_bound_policy(
            self.record,
            KEY,
            now=self.end,
            revocations=[bound_revocation, context_revocation],
        )
        self.assertIsInstance(measurement, Measurement)

    def test_wrong_key_rejected(self):
        revocation = revoke_context(OTHER_CONTEXT, 0.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )

    def test_tampered_revocation_rejected(self):
        tampered = dataclasses.replace(
            revoke_context(OTHER_CONTEXT, 0.0, KEY), revoked_at=1.0
        )
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[tampered]
            )

    def test_tampered_revocation_bytes_rejected(self):
        blob = revoke_context(OTHER_CONTEXT, 1.0, KEY).to_bytes().replace(
            b'"revoked_at":1.0', b'"revoked_at":2.0'
        )
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[blob]
            )

    def test_future_revocation_rejected_even_without_match(self):
        revocation = revoke_context(OTHER_CONTEXT, self.end + 10.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )

    def test_invalid_revocation_items_rejected(self):
        for bad in ([1], [None], ["revocation"], [b"not json"], [object()]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_bound_policy(
                    self.record, KEY, now=self.end, revocations=bad
                )

    def test_now_contract_with_context_revocations(self):
        revocation = revoke_context(OTHER_CONTEXT, 0.0, KEY)
        for bad in (None, math.inf, math.nan, True, "now"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_bound_policy(
                    self.record, KEY, now=bad, revocations=[revocation]
                )

    def test_revocation_composes_with_max_age(self):
        revocation = revoke_context(CONTEXT, self.end - 1.0, KEY)
        measurement = audit_bound_policy(
            self.record, KEY, now=self.end, max_age=10.0,
            revocations=[revocation],
        )
        self.assertIsInstance(measurement, Measurement)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end + 11.0, max_age=10.0,
                revocations=[revocation],
            )

    def test_revokes_every_bound_with_the_context(self):
        # One context revocation covers any number of rounds bound to it.
        other, other_end = make_bound()
        revocation = revoke_context(CONTEXT, max(self.end, other_end), KEY)
        for record, end in ((self.record, self.end), (other, other_end)):
            with self.assertRaises(ValueError, msg=repr(end)):
                audit_bound_policy(
                    record, KEY, now=end, revocations=[revocation]
                )

    def test_audit_is_pure(self):
        revocation = revoke_context(CONTEXT, self.end - 1.0, KEY)
        for _ in range(2):
            audit_bound_policy(
                self.record, KEY, now=self.end, revocations=[revocation]
            )
        self.assertIsInstance(audit_bound(self.record, KEY), Measurement)


if __name__ == "__main__":
    unittest.main()
