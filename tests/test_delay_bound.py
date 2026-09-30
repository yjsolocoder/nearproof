"""Tests for the delay-bound challenge extension.

Covers Verifier.new_delay_challenge / verify_delay_bound, the
DelayBoundEvidence record (canonical bytes, MAC) and audit_delay_bound.
The legacy entry points and default replay-protection-off behaviour must
remain unchanged, so the last section pins a few compatibility facts.
"""

import dataclasses
import json
import math
import threading
import unittest

from nearproof import (
    Challenge,
    ChallengeStateError,
    DelayBoundEvidence,
    Measurement,
    Prover,
    Verifier,
    audit_bound,
    audit_delay_bound,
    context_digest,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
CONTEXT = b"c" * 32
OTHER_CONTEXT = b"x" * 32
OPENING = b"o" * 32
OTHER_OPENING = b"p" * 32
DIGEST = context_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self, start: float = 100.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def make_verifier(*, ttl=None, key=KEY, clock=None):
    clock = clock or SteppedClock()
    verifier = Verifier(
        key,
        clock=clock,
        replay_protection=True,
        challenge_ttl_seconds=ttl,
    )
    return clock, verifier


def make_delay_round(
    trip=0.005,
    *,
    max_delay=0.01,
    ttl=None,
    verifier_key=KEY,
    prover_key=KEY,
    context=CONTEXT,
    opening=OPENING,
    clock=None,
):
    clock, verifier = make_verifier(ttl=ttl, key=verifier_key, clock=clock)
    prover = Prover(prover_key)
    digest = context_digest(context, opening)
    challenge, issued_at = verifier.new_delay_challenge(
        context, digest, max_delay_seconds=max_delay
    )
    response = prover.reveal(challenge, context, opening)
    clock.now += trip
    record = verifier.verify_delay_bound(
        challenge, response, issued_at, opening=opening
    )
    return record, verifier, prover, clock, challenge, issued_at


class NewDelayChallengeTest(unittest.TestCase):
    def test_returns_challenge_and_clock_reading(self):
        clock, verifier = make_verifier()
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=1.5
        )
        self.assertIsInstance(challenge, Challenge)
        self.assertEqual(challenge.round_index, 1)
        self.assertEqual(len(challenge.nonce), 16)
        self.assertEqual(issued_at, clock.now)

    def test_requires_replay_protection(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=False)
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(CONTEXT, DIGEST, max_delay_seconds=1.0)
        # Nothing was issued.
        self.assertEqual(verifier.round_count, 0)

    def test_context_and_digest_types(self):
        _, verifier = make_verifier()
        with self.assertRaises(TypeError):
            verifier.new_delay_challenge("c" * 32, DIGEST, max_delay_seconds=1.0)
        with self.assertRaises(TypeError):
            verifier.new_delay_challenge(CONTEXT, "d" * 32, max_delay_seconds=1.0)

    def test_context_and_digest_lengths(self):
        _, verifier = make_verifier()
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(b"c" * 31, DIGEST, max_delay_seconds=1.0)
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(CONTEXT, b"d" * 33, max_delay_seconds=1.0)

    def test_max_delay_contract(self):
        _, verifier = make_verifier()
        for bad in (0, -1.0, 0.0, math.nan, math.inf, -math.inf, "1", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                verifier.new_delay_challenge(CONTEXT, DIGEST, max_delay_seconds=bad)
        # bool is not a valid number even though it is an int subclass.
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(CONTEXT, DIGEST, max_delay_seconds=True)

    def test_max_delay_is_keyword_only(self):
        _, verifier = make_verifier()
        with self.assertRaises(TypeError):
            verifier.new_delay_challenge(CONTEXT, DIGEST, 1.0)

    def test_argument_shape_checked_before_replay_flag(self):
        # A type/shape error must not be masked by the replay-protection
        # ValueError, matching new_challenge's binding validation order.
        verifier = Verifier(KEY, replay_protection=False)
        with self.assertRaises(TypeError):
            verifier.new_delay_challenge("c" * 32, DIGEST, max_delay_seconds=1.0)
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(
                CONTEXT, DIGEST, max_delay_seconds=0.0
            )

    def test_each_issue_gets_fresh_round_and_nonce(self):
        _, verifier = make_verifier()
        first, _ = verifier.new_delay_challenge(CONTEXT, DIGEST, max_delay_seconds=1.0)
        second, _ = verifier.new_delay_challenge(CONTEXT, DIGEST, max_delay_seconds=1.0)
        self.assertEqual((first.round_index, second.round_index), (1, 2))
        self.assertNotEqual(first.nonce, second.nonce)


class VerifyDelayBoundHappyPathTest(unittest.TestCase):
    def test_record_fields(self):
        record, verifier, _prover, clock, challenge, issued_at = make_delay_round(
            trip=0.004
        )
        self.assertIsInstance(record, DelayBoundEvidence)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.context, CONTEXT)
        self.assertEqual(record.digest, DIGEST)
        self.assertEqual(record.opening, OPENING)
        self.assertEqual(record.issued_at, issued_at)
        self.assertEqual(record.max_delay_seconds, 0.01)
        self.assertEqual(len(record.mac), 32)
        evidence = record.evidence
        self.assertEqual(evidence.round_index, challenge.round_index)
        self.assertEqual(evidence.nonce, challenge.nonce)
        # The evidence start is bound to issued_at, end to the verify clock.
        self.assertEqual(evidence.start, issued_at)
        self.assertEqual(evidence.end, clock.now)
        self.assertAlmostEqual(evidence.elapsed, 0.004)
        self.assertEqual(evidence.distance, evidence.elapsed * evidence.speed / 2.0)

    def test_zero_delay_is_within_bound(self):
        record, *_ = make_delay_round(trip=0.0, max_delay=0.5)
        self.assertEqual(record.evidence.elapsed, 0.0)
        # Equality at the boundary is accepted (0.5 is exactly representable).
        record2, *_ = make_delay_round(trip=0.5, max_delay=0.5)
        self.assertEqual(record2.evidence.elapsed, 0.5)
        measurement = audit_delay_bound(record2, KEY)
        self.assertEqual(measurement.elapsed_seconds, 0.5)

    def test_record_audits_clean(self):
        record, *_ = make_delay_round()
        measurement = audit_delay_bound(record, KEY)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.response, record.evidence.response)
        self.assertEqual(measurement.elapsed_seconds, record.evidence.elapsed)
        # Encoding is accepted too.
        measurement2 = audit_delay_bound(record.to_bytes(), KEY)
        self.assertEqual(measurement, measurement2)

    def test_inner_evidence_is_the_standard_bound_evidence(self):
        # The nested Evidence uses the bound (NPR1) response exactly like
        # verify_bound's: wrapping the same fields in a BoundEvidence audits
        # clean under audit_bound, proving the evidence bytes are unchanged.
        from dataclasses import replace as dc_replace

        from nearproof import BoundEvidence

        record, *_ = make_delay_round()
        wrapped = BoundEvidence(
            version=1,
            evidence=record.evidence,
            context=record.context,
            digest=record.digest,
            opening=record.opening,
            mac=b"\x00" * 32,
        )
        wrapped = dc_replace(
            wrapped,
            mac=__import__("nearproof")._bound_evidence_mac(
                KEY, __import__("nearproof")._bound_evidence_payload(wrapped)
            ),
        )
        measurement = audit_bound(wrapped, KEY)
        self.assertEqual(measurement.elapsed_seconds, record.evidence.elapsed)


class VerifyDelayBoundFailureTest(unittest.TestCase):
    def _issue(self, **kwargs):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=kwargs.pop("max_delay", 0.01)
        )
        return clock, verifier, prover, challenge, issued_at

    def test_delay_over_bound_rejected_with_distinct_text(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        clock.now = issued_at + 0.010001
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError) as caught:
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        self.assertIn("delay", str(caught.exception).lower())
        self.assertIn("max_delay", str(caught.exception))
        # Not consumed: a successful retry within the bound still works.
        clock.now = issued_at + 0.005
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_started_at_mismatch_rejected_with_distinct_text(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        clock.now = issued_at + 0.002
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError) as caught:
            verifier.verify_delay_bound(
                challenge, response, issued_at + 1e-9, opening=OPENING
            )
        self.assertIn("issued_at", str(caught.exception))
        # Challenge stays pending.
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_commitment_mismatch_rejected_with_distinct_text(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        clock.now = issued_at + 0.002
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError) as caught:
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OTHER_OPENING
            )
        message = str(caught.exception).lower()
        self.assertIn("opening", message)
        self.assertIn("binding", message)
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_wrong_response_rejected_and_not_consumed(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        clock.now = issued_at + 0.002
        good = prover.reveal(challenge, CONTEXT, OPENING)
        forged = bytes(255 - b for b in bytearray(good))
        self.assertNotEqual(forged, good)
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, forged, issued_at, opening=OPENING
            )
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, good, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_response_for_other_key_rejected(self):
        clock, verifier, _prover, challenge, issued_at = self._issue()
        other = Prover(OTHER_KEY)
        clock.now = issued_at + 0.002
        response = other.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_opening_types(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        response = prover.reveal(challenge, CONTEXT, OPENING)
        for bad in (None, "o" * 32, 1, b"o" * 32):
            if isinstance(bad, bytes):
                continue
            with self.assertRaises(TypeError, msg=repr(bad)):
                verifier.verify_delay_bound(
                    challenge, response, issued_at, opening=bad
                )
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=b"o" * 31
            )

    def test_argument_types(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound("challenge", response, issued_at, opening=OPENING)
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound(challenge, "response", issued_at, opening=OPENING)
        for bad in (None, "1.0", [issued_at]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verifier.verify_delay_bound(
                    challenge, response, bad, opening=OPENING
                )
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound(
                challenge, response, True, opening=OPENING
            )

    def test_non_finite_started_at_rejected(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        clock.now = issued_at + 0.002
        response = prover.reveal(challenge, CONTEXT, OPENING)
        for bad in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError, msg=repr(bad)):
                verifier.verify_delay_bound(
                    challenge, response, bad, opening=OPENING
                )

    def test_clock_rolled_back_gives_negative_delay(self):
        # If the verifier clock reads before issued_at (rolled back), the
        # measured delay is negative and rejected; the challenge survives.
        clock, verifier, prover, challenge, issued_at = self._issue()
        clock.now = issued_at - 1.0
        response = prover.reveal(challenge, CONTEXT, OPENING)
        # started_at must equal issued_at even though the clock went back.
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        clock.now = issued_at + 0.002
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_unknown_challenge_is_state_error(self):
        clock = SteppedClock()
        _, verifier = make_verifier(clock=clock)
        forged = Challenge(1, b"n" * 16)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                forged, b"r" * 32, clock.now, opening=OPENING
            )

    def test_consumed_challenge_is_state_error(self):
        record, verifier, prover, clock, challenge, issued_at = make_delay_round()
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_revoked_challenge_is_state_error(self):
        clock, verifier, prover, challenge, issued_at = self._issue()
        verifier.revoke(challenge)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_expired_challenge_is_state_error(self):
        clock, verifier, prover = make_verifier(ttl=0.01)[:2] + (Prover(KEY),)
        digest = context_digest(CONTEXT, OPENING)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, digest, max_delay_seconds=1.0
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 0.02
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_ttl_state_check_runs_before_delay(self):
        # Past the TTL but still inside the delay bound: the TTL/state check
        # runs first and wins as ChallengeStateError.
        clock, verifier = make_verifier(ttl=0.01)
        prover = Prover(KEY)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=1.0
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 0.5
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_plain_bound_challenge_has_no_delay_binding(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, clock.now, opening=OPENING
            )

    def test_unbound_challenge_has_no_delay_binding(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, clock.now, opening=OPENING
            )

    def test_delay_challenge_cannot_be_verified_without_delay_check(self):
        # Protocol binding: verify/verify_bound must not consume a
        # delay-bound challenge (that would bypass issued_at/max_delay).
        from nearproof import BoundEvidence  # noqa: F401

        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=1.0
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 100.0  # far past max_delay
        for call in (
            lambda: verifier.verify(
                challenge, response, issued_at, opening=OPENING
            ),
            lambda: verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            ),
        ):
            with self.assertRaises(ValueError, msg=call.__doc__):
                call()
        # Still pending: the proper entry point then consumes it exactly
        # once after the clock is back inside the window.
        clock.now = issued_at + 0.002
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_delay_challenge_can_still_be_revoked(self):
        clock, verifier = make_verifier()
        challenge, _ = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=1.0
        )
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class AtomicConsumptionTest(unittest.TestCase):
    def test_at_most_one_success_under_race(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=1.0
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)

        successes = []
        errors = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()
            try:
                successes.append(
                    verifier.verify_delay_bound(
                        challenge, response, issued_at, opening=OPENING
                    )
                )
            except ChallengeStateError as error:
                errors.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 15)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )


_DELAY_FIELDS = (
    "version",
    "evidence",
    "context",
    "digest",
    "opening",
    "issued_at",
    "max_delay_seconds",
    "mac",
)


class DelayBoundEvidenceContractTest(unittest.TestCase):
    def setUp(self):
        self.record, *_ = make_delay_round()

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.record.issued_at = 9.0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.record.max_delay_seconds = 9.0

    def test_construction_contract(self):
        good = self.record
        kwargs = dict(
            version=1,
            evidence=good.evidence,
            context=CONTEXT,
            digest=DIGEST,
            opening=OPENING,
            issued_at=1.0,
            max_delay_seconds=0.01,
            mac=b"m" * 32,
        )
        for bad_version in ("1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad_version)):
                DelayBoundEvidence(**{**kwargs, "version": bad_version})
        with self.assertRaises(ValueError):
            DelayBoundEvidence(**{**kwargs, "version": 2})
        with self.assertRaises(ValueError):
            DelayBoundEvidence(**{**kwargs, "evidence": b"nope"})
        for name in ("context", "digest", "opening", "mac"):
            with self.assertRaises(ValueError):
                DelayBoundEvidence(**{**kwargs, name: b"x" * 31})
        for bad in (math.nan, math.inf, "1.0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                DelayBoundEvidence(**{**kwargs, "issued_at": bad})
        for bad in (0.0, -1.0, math.nan, math.inf, "1.0", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                DelayBoundEvidence(
                    **{**kwargs, "max_delay_seconds": bad}
                )

    def test_to_bytes_is_compact_canonical_json(self):
        data = self.record.to_bytes()
        self.assertIsInstance(data, bytes)
        obj = json.loads(data)
        self.assertEqual(list(obj), list(_DELAY_FIELDS))
        # Compact: no whitespace outside strings.
        self.assertNotIn(b" ", data)
        # The nested evidence keeps its own field order.
        self.assertEqual(
            list(obj["evidence"]),
            [
                "version",
                "round_index",
                "nonce",
                "response",
                "start",
                "end",
                "speed",
                "elapsed",
                "distance",
                "result",
                "mac",
            ],
        )

    def test_round_trip(self):
        data = self.record.to_bytes()
        decoded = DelayBoundEvidence.from_bytes(data)
        self.assertEqual(decoded, self.record)
        self.assertEqual(decoded.to_bytes(), data)

    def test_from_bytes_rejects_non_bytes(self):
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(self.record.to_bytes().decode())

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = self.record.to_bytes()
        obj = json.loads(data)
        # Whitespace / pretty printing.
        pretty = json.dumps(obj, indent=2).encode()
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(pretty)
        # Reordered keys.
        reordered = dict(reversed(list(obj.items())))
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(json.dumps(reordered).encode())
        # Missing and extra keys.
        missing = dict(obj)
        del missing["mac"]
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(json.dumps(missing).encode())
        extra = dict(obj)
        extra["extra"] = 1
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(json.dumps(extra).encode())
        # Duplicate keys.
        duplicated = data.replace(b'"mac":', b'"mac":"00", "mac":', 1)
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(duplicated)
        # Uppercase hex spelling is non-canonical.
        upper = json.dumps(obj).encode().upper().replace(b"VERSION", b"version")
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(upper)

    def test_from_bytes_field_violations(self):
        obj = json.loads(self.record.to_bytes())
        def enc(mod):
            clone = json.loads(json.dumps(obj))
            mod(clone)
            return json.dumps(clone, separators=(",", ":")).encode()

        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(enc(lambda o: o.update(version=2)))
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(
                enc(lambda o: o.update(context="ab"))
            )
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(
                enc(lambda o: o.update(issued_at="soon"))
            )
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(
                enc(lambda o: o.update(issued_at=float("nan")))
            )
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(
                enc(lambda o: o.update(max_delay_seconds=0))
            )
        with self.assertRaises(ValueError):
            DelayBoundEvidence.from_bytes(
                enc(lambda o: o.update(mac="00"))
            )

    def test_integer_time_spellings_round_trip(self):
        # An int issued_at / max_delay keeps its int spelling through bytes.
        record = dataclasses.replace(
            self.record,
            issued_at=100,
            max_delay_seconds=1,
            mac=b"m" * 32,
        )
        data = record.to_bytes()
        decoded = DelayBoundEvidence.from_bytes(data)
        self.assertEqual(decoded.issued_at, 100)
        self.assertIs(type(decoded.issued_at), int)
        self.assertEqual(decoded.max_delay_seconds, 1)
        self.assertIs(type(decoded.max_delay_seconds), int)
        self.assertEqual(decoded.to_bytes(), data)


class AuditDelayBoundTest(unittest.TestCase):
    def setUp(self):
        self.record, *_ = make_delay_round(trip=0.003)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_delay_bound(self.record, OTHER_KEY)

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_delay_bound(self.record, b"")

    def test_record_and_key_types(self):
        with self.assertRaises(TypeError):
            audit_delay_bound("not a record", KEY)
        with self.assertRaises(TypeError):
            audit_delay_bound(self.record, "key")
        with self.assertRaises(TypeError):
            audit_delay_bound(self.record, None)
        with self.assertRaises(TypeError):
            audit_delay_bound(None, KEY)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_delay_bound(b"{not json", KEY)

    def test_outer_mac_tampering_rejected(self):
        tampered = dataclasses.replace(self.record, issued_at=1.0)
        with self.assertRaises(ValueError):
            audit_delay_bound(tampered, KEY)

    def test_commitment_tampering_rejected(self):
        # A wrong digest with a valid outer MAC still fails the commitment.
        import nearproof

        record = dataclasses.replace(
            self.record, digest=context_digest(CONTEXT, OTHER_OPENING)
        )
        resigned = dataclasses.replace(
            record,
            mac=nearproof._delay_bound_evidence_mac(
                KEY, nearproof._delay_bound_evidence_payload(record)
            ),
        )
        with self.assertRaises(ValueError):
            audit_delay_bound(resigned, KEY)

    def test_response_tampering_rejected(self):
        import nearproof

        evidence = dataclasses.replace(
            self.record.evidence, response=b"r" * 32
        )
        record = dataclasses.replace(self.record, evidence=evidence)
        resigned = dataclasses.replace(
            record,
            mac=nearproof._delay_bound_evidence_mac(
                KEY, nearproof._delay_bound_evidence_payload(record)
            ),
        )
        with self.assertRaises(ValueError):
            audit_delay_bound(resigned, KEY)

    def test_round_trip_tampering_rejected(self):
        import nearproof

        # issued_at moved away from evidence.start, MAC re-done: the round
        # trip check must catch it.
        record = dataclasses.replace(self.record, issued_at=1.0)
        resigned = dataclasses.replace(
            record,
            mac=nearproof._delay_bound_evidence_mac(
                KEY, nearproof._delay_bound_evidence_payload(record)
            ),
        )
        with self.assertRaises(ValueError):
            audit_delay_bound(resigned, KEY)

    def test_delay_over_bound_rejected(self):
        import nearproof

        # Forge a record whose end exceeds its own max_delay but whose MACs
        # and arithmetic are otherwise consistent (the nested evidence is
        # rebuilt coherently and re-MAC'd, so only the bound check fires).
        record = self.record
        evidence = record.evidence
        end = evidence.start + record.max_delay_seconds + 0.001
        elapsed = end - evidence.start
        new_evidence_payload = {
            "version": 1,
            "round_index": evidence.round_index,
            "nonce": evidence.nonce.hex(),
            "response": evidence.response.hex(),
            "start": evidence.start,
            "end": end,
            "speed": evidence.speed,
            "elapsed": elapsed,
            "distance": elapsed * evidence.speed / 2.0,
            "result": "accepted",
        }
        new_evidence = dataclasses.replace(
            evidence,
            end=end,
            elapsed=elapsed,
            distance=elapsed * evidence.speed / 2.0,
            mac=nearproof._evidence_mac(KEY, new_evidence_payload),
        )
        forged = dataclasses.replace(
            record,
            evidence=new_evidence,
            mac=b"\x00" * 32,
        )
        forged = dataclasses.replace(
            forged,
            mac=nearproof._delay_bound_evidence_mac(
                KEY, nearproof._delay_bound_evidence_payload(forged)
            ),
        )
        with self.assertRaises(ValueError):
            audit_delay_bound(forged, KEY)

    def test_audit_does_not_touch_state(self):
        # Auditing twice returns the same result and needs no verifier.
        first = audit_delay_bound(self.record, KEY)
        second = audit_delay_bound(self.record.to_bytes(), KEY)
        self.assertEqual(first, second)


class CompatibilityTest(unittest.TestCase):
    """The delay feature is purely additive."""

    def test_legacy_verify_unchanged_without_protection(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock)
        prover = Prover(KEY)
        challenge = verifier.new_challenge()
        measurement = verifier.verify(
            challenge, prover.respond(challenge), clock.now
        )
        self.assertIsInstance(measurement, Measurement)

    def test_bound_round_and_audit_bound_bytes_unchanged(self):
        clock = SteppedClock(start=100.0)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        started = clock.now
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now += 0.002
        record = verifier.verify_bound(challenge, response, started, opening=OPENING)
        data = record.to_bytes()
        again = type(record).from_bytes(data)
        self.assertEqual(again.to_bytes(), data)
        self.assertIsInstance(audit_bound(record, KEY), Measurement)

    def test_delay_record_is_distinct_from_bound_record(self):
        # Separate domain prefixes and field sets: a delay record's bytes
        # are not a bound record and vice versa.
        from nearproof import BoundEvidence

        record, *_ = make_delay_round()
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(record.to_bytes())


if __name__ == "__main__":
    unittest.main()
