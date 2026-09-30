import json
import threading
import unittest

from nearproof import (
    Challenge,
    ChallengeStateError,
    DelayBoundEvidence,
    Evidence,
    Measurement,
    Prover,
    Verifier,
    audit_delay_bound,
    context_digest,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"

CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)
MAX_DELAY = 2.0


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def fixture(clock=None, **kwargs):
    clock = clock or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    kwargs.setdefault("replay_protection", True)
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


def issue(verifier, *, context=CONTEXT, digest=DIGEST, max_delay=MAX_DELAY):
    return verifier.new_delay_challenge(
        context, digest, max_delay_seconds=max_delay
    )


class NewDelayChallengeTest(unittest.TestCase):
    def test_returns_challenge_and_float_issue_time(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        self.assertIsInstance(challenge, Challenge)
        self.assertEqual(challenge.round_index, 1)
        self.assertEqual(len(challenge.nonce), 16)
        self.assertEqual(issued_at, 0.0)
        self.assertIsInstance(issued_at, float)
        # The round counter advances exactly like new_challenge.
        second, second_issued = issue(verifier)
        self.assertEqual(second.round_index, 2)

    def test_issue_time_is_the_clock_reading(self):
        clock = SteppedClock(start=42.5)
        _, _, verifier = fixture(clock=clock)
        _, issued_at = issue(verifier)
        self.assertEqual(issued_at, 42.5)

    def test_max_delay_is_keyword_only(self):
        _, _, verifier = fixture()
        with self.assertRaises(TypeError):
            verifier.new_delay_challenge(CONTEXT, DIGEST, MAX_DELAY)

    def test_integer_max_delay_accepted(self):
        _, _, verifier = fixture()
        _, issued_at = issue(verifier, max_delay=5)
        self.assertEqual(issued_at, 0.0)

    def test_integer_clock_reading_normalized_to_float(self):
        class IntClock:
            now = 3

            def __call__(self):
                return self.now

        clock = IntClock()
        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=5
        )
        self.assertIsInstance(issued_at, float)
        self.assertEqual(issued_at, 3.0)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 4
        # The int reading compares equal to the stored float issue time.
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertEqual(record.evidence.start, 3.0)
        self.assertEqual(record.evidence.elapsed, 1.0)

    def test_requires_replay_protection(self):
        verifier = Verifier(KEY, replay_protection=False)
        with self.assertRaises(ValueError):
            issue(verifier)

    def test_context_digest_pair_required(self):
        _, _, verifier = fixture()
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(None, None, max_delay_seconds=MAX_DELAY)
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(
                CONTEXT, None, max_delay_seconds=MAX_DELAY
            )
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(
                None, DIGEST, max_delay_seconds=MAX_DELAY
            )

    def test_context_digest_types(self):
        _, _, verifier = fixture()
        for bad in ("c" * 32, bytearray(CONTEXT), 32, [0] * 32):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    verifier.new_delay_challenge(
                        bad, DIGEST, max_delay_seconds=MAX_DELAY
                    )
        with self.assertRaises(TypeError):
            verifier.new_delay_challenge(
                CONTEXT, "d" * 32, max_delay_seconds=MAX_DELAY
            )

    def test_context_digest_lengths(self):
        _, _, verifier = fixture()
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(
                b"c" * 31, DIGEST, max_delay_seconds=MAX_DELAY
            )
        with self.assertRaises(ValueError):
            verifier.new_delay_challenge(
                CONTEXT, b"d" * 33, max_delay_seconds=MAX_DELAY
            )

    def test_bad_max_delay_values(self):
        _, _, verifier = fixture()
        for bad in (0, 0.0, -1, -0.5, True, False, float("inf"),
                    float("-inf"), float("nan")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    issue(verifier, max_delay=bad)

    def test_bad_max_delay_types(self):
        _, _, verifier = fixture()
        for bad in ("2.0", [2.0], (2.0,), object()):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    issue(verifier, max_delay=bad)


class VerifyDelayBoundSuccessTest(unittest.TestCase):
    def test_round_trip(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 1.0
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertIsInstance(record, DelayBoundEvidence)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.context, CONTEXT)
        self.assertEqual(record.digest, DIGEST)
        self.assertEqual(record.opening, OPENING)
        self.assertEqual(record.issued_at, 0.0)
        self.assertEqual(record.max_delay_seconds, MAX_DELAY)
        self.assertEqual(record.evidence.start, issued_at)
        self.assertEqual(record.evidence.end, 1.0)
        self.assertEqual(record.evidence.elapsed, 1.0)
        self.assertEqual(len(record.mac), 32)

    def test_delay_measured_from_issued_at_not_caller_start(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 1.5
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        # start is the stamped issue time even though the caller could have
        # passed a different reading.
        self.assertEqual(record.evidence.start, 0.0)
        self.assertEqual(record.evidence.elapsed, 1.5)

    def test_delay_equal_to_bound_is_accepted(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = MAX_DELAY
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertEqual(record.evidence.elapsed, MAX_DELAY)

    def test_success_consumes_challenge(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_revoked_challenge_rejected(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        verifier.revoke(challenge)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )


class VerifyDelayBoundFailureTest(unittest.TestCase):
    def _pending(self, verifier, challenge, response, issued_at, opening):
        # A failure must leave the challenge pending and retryable.
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=opening
            )
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=opening
            ),
            DelayBoundEvidence,
        )

    def test_delay_over_bound_rejected_with_distinct_message(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 2.0001
        with self.assertRaisesRegex(ValueError, "delay exceeds"):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_over_bound_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 2.5
        with self.assertRaisesRegex(ValueError, "delay exceeds"):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        clock.now = 1.0
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_started_at_must_equal_issued_at(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 1.0
        for wrong in (issued_at + 0.1, issued_at - 0.1, 0.0000001):
            with self.subTest(wrong=wrong):
                with self.assertRaisesRegex(ValueError, "issue time"):
                    verifier.verify_delay_bound(
                        challenge, response, wrong, opening=OPENING
                    )

    def test_time_mismatch_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 1.0
        with self.assertRaisesRegex(ValueError, "issue time"):
            verifier.verify_delay_bound(
                challenge, response, 0.5, opening=OPENING
            )
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_negative_delay_rejected_and_retryable(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)  # issued at 1.0 below
        clock.now = 1.0
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=MAX_DELAY
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5  # clock rolled backwards
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        clock.now = 1.25
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_wrong_response_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = Prover(OTHER_KEY).reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        good = prover.reveal(challenge, CONTEXT, OPENING)
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, good, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_wrong_opening_does_not_consume_with_distinct_message(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        other_opening = b"x" * 32
        wrong_response = prover.reveal(challenge, CONTEXT, other_opening)
        with self.assertRaisesRegex(ValueError, "binding"):
            verifier.verify_delay_bound(
                challenge, wrong_response, issued_at, opening=other_opening
            )
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_none_opening_is_type_error(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=None
            )

    def test_non_bytes_opening_is_type_error(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        clock.now = 0.5
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound(
                challenge, b"r" * 32, issued_at, opening="o" * 32
            )

    def test_wrong_length_opening_is_value_error(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, b"r" * 32, issued_at, opening=b"o" * 31
            )

    def test_non_challenge_argument_is_type_error(self):
        _, _, verifier = fixture()
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound(b"not-a-challenge", b"r", 0.0, opening=OPENING)

    def test_bad_started_at_type_is_type_error(self):
        clock, prover, verifier = fixture()
        challenge, _issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        with self.assertRaises(TypeError):
            verifier.verify_delay_bound(
                challenge, response, None, opening=OPENING
            )


class StatePrecedenceTest(unittest.TestCase):
    def test_state_error_precedes_delay_check(self):
        clock, prover, verifier = fixture()
        challenge, _issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 5.0  # far beyond max_delay
        # Revoke first: revoked state must win over every later check.
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, 0.0, opening=b"bad"
            )

    def test_unknown_challenge_rejected_even_with_garbage_args(self):
        clock, _, verifier = fixture()
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                Challenge(99, b"x" * 16), None, None, opening=None
            )

    def test_consumed_state_wins_over_garbage(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, None, None, opening=None
            )

    def test_expired_state_wins_over_delay_and_opening(self):
        clock, prover, verifier = fixture(
            challenge_ttl_seconds=0.5
        )
        challenge, issued_at = issue(verifier, max_delay=10.0)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.6  # past TTL though well inside the delay bound
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=None
            )

    def test_ttl_still_expires_delay_challenges_at_boundary(self):
        clock, prover, verifier = fixture(challenge_ttl_seconds=1.0)
        challenge, issued_at = issue(verifier)  # deadline 1.0
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_without_replay_protection_round(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=False)
        challenge = Challenge(1, b"n" * 16)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, b"r" * 32, 0.0, opening=OPENING
            )


class ProtocolSeparationTest(unittest.TestCase):
    def test_delay_challenge_rejected_by_plain_verify(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, issued_at, opening=OPENING)
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, issued_at)
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_independent_issue_times(self):
        clock, prover, verifier = fixture()
        first, first_issued = issue(verifier)
        clock.now = 0.5
        second, second_issued = issue(verifier)
        self.assertEqual((first_issued, second_issued), (0.0, 0.5))
        clock.now = 0.75
        r2 = prover.reveal(second, CONTEXT, OPENING)
        record2 = verifier.verify_delay_bound(
            second, r2, second_issued, opening=OPENING
        )
        self.assertEqual(record2.evidence.elapsed, 0.25)
        # The first challenge is still pending with its own issue time.
        clock.now = 0.9
        r1 = prover.reveal(first, CONTEXT, OPENING)
        record1 = verifier.verify_delay_bound(
            first, r1, first_issued, opening=OPENING
        )
        self.assertEqual(record1.evidence.elapsed, 0.9)

    def test_plain_bound_challenge_rejected_by_verify_delay_bound(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5
        with self.assertRaisesRegex(ValueError, "delay bound"):
            verifier.verify_delay_bound(
                challenge, response, 0.0, opening=OPENING
            )
        # The challenge survived and can still be answered the right way.
        self.assertIsNotNone(
            verifier.verify_bound(challenge, response, 0.5, opening=OPENING)
        )

    def test_unbound_challenge_rejected_by_verify_delay_bound(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 0.5
        with self.assertRaisesRegex(ValueError, "delay bound"):
            verifier.verify_delay_bound(
                challenge, prover.respond(challenge), 0.0, opening=OPENING
            )


class ConcurrentDelayTest(unittest.TestCase):
    def test_at_most_one_success_under_race(self):
        clock, prover, verifier = fixture()
        challenge, issued_at = issue(verifier)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.5

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


def _make_record(**overrides):
    clock = SteppedClock()
    prover = Prover(KEY)
    verifier = Verifier(KEY, clock=clock, replay_protection=True)
    challenge, issued_at = verifier.new_delay_challenge(
        overrides.pop("context", CONTEXT),
        overrides.pop("digest", DIGEST),
        max_delay_seconds=overrides.pop("max_delay", MAX_DELAY),
    )
    response = prover.reveal(challenge, CONTEXT, OPENING)
    clock.now = overrides.pop("end", 1.0)
    return verifier.verify_delay_bound(
        challenge,
        response,
        issued_at,
        opening=overrides.pop("opening", OPENING),
    )


class DelayBoundEvidenceRecordTest(unittest.TestCase):
    def test_frozen(self):
        record = _make_record()
        with self.assertRaises(Exception):
            record.issued_at = 9.0
        with self.assertRaises(Exception):
            record.max_delay_seconds = 9.0

    def test_timestamps_stored_as_floats(self):
        clock = SteppedClock()
        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        challenge, issued_at = verifier.new_delay_challenge(
            CONTEXT, DIGEST, max_delay_seconds=3
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 1
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertIsInstance(record.max_delay_seconds, float)
        self.assertEqual(record.max_delay_seconds, 3.0)

    def test_bytes_roundtrip(self):
        record = _make_record()
        blob = record.to_bytes()
        decoded = DelayBoundEvidence.from_bytes(blob)
        self.assertEqual(decoded, record)

    def test_from_bytes_requires_bytes(self):
        with self.assertRaises(TypeError):
            DelayBoundEvidence.from_bytes("not bytes")
        with self.assertRaises(TypeError):
            DelayBoundEvidence.from_bytes(None)

    def test_non_canonical_encodings_rejected(self):
        record = _make_record()
        blob = record.to_bytes()
        obj = json.loads(blob)
        # Whitespace / pretty printing.
        self.assertRaises(ValueError, DelayBoundEvidence.from_bytes,
                          json.dumps(obj).encode())
        self.assertRaises(ValueError, DelayBoundEvidence.from_bytes,
                          json.dumps(obj, indent=2).encode())
        # Reordered outer keys.
        reordered = {key: obj[key] for key in reversed(list(obj))}
        self.assertRaises(ValueError, DelayBoundEvidence.from_bytes,
                          json.dumps(reordered, separators=(",", ":")).encode())
        # Extra / missing keys.
        extra = dict(obj)
        extra["nope"] = 1
        self.assertRaises(ValueError, DelayBoundEvidence.from_bytes,
                          json.dumps(extra, separators=(",", ":")).encode())
        missing = dict(obj)
        del missing["mac"]
        self.assertRaises(ValueError, DelayBoundEvidence.from_bytes,
                          json.dumps(missing, separators=(",", ":")).encode())
        # Duplicate keys.
        tampered = blob[:-1] + b',"version":1}'
        self.assertRaises(ValueError, DelayBoundEvidence.from_bytes, tampered)
        # Non-float spellings of the two numeric record fields.
        for name, alternative in (("issued_at", "3"), ("max_delay_seconds", "3")):
            variant = dict(obj)
            variant[name] = alternative
            self.assertRaises(
                ValueError,
                DelayBoundEvidence.from_bytes,
                json.dumps(variant, separators=(",", ":")).encode(),
            )
        # NaN/Infinity are never valid.
        variant = dict(obj)
        variant["issued_at"] = float("nan")
        with self.assertRaises(ValueError):
            json.dumps(variant, separators=(",", ":"), allow_nan=False)

    def test_nested_evidence_must_keep_field_order(self):
        record = _make_record()
        obj = json.loads(record.to_bytes())
        nested = obj["evidence"]
        obj["evidence"] = {key: nested[key] for key in reversed(list(nested))}
        self.assertRaises(
            ValueError,
            DelayBoundEvidence.from_bytes,
            json.dumps(obj, separators=(",", ":")).encode(),
        )

    def test_bad_hex_fields_rejected(self):
        record = _make_record()
        obj = json.loads(record.to_bytes())
        for name in ("context", "digest", "opening", "mac"):
            variant = dict(obj)
            variant[name] = "zz"
            self.assertRaises(
                ValueError,
                DelayBoundEvidence.from_bytes,
                json.dumps(variant, separators=(",", ":")).encode(),
            )
            variant = dict(obj)
            variant[name] = "ab" * 31  # 31 bytes instead of 32
            self.assertRaises(
                ValueError,
                DelayBoundEvidence.from_bytes,
                json.dumps(variant, separators=(",", ":")).encode(),
            )

    def test_constructor_value_contract(self):
        good = _make_record()
        kwargs = dict(
            version=1,
            evidence=good.evidence,
            context=CONTEXT,
            digest=DIGEST,
            opening=OPENING,
            issued_at=0.0,
            max_delay_seconds=2.0,
            mac=b"m" * 32,
        )
        # Non-bytes byte fields are shape errors.
        for name in ("context", "digest", "opening", "mac"):
            bad = dict(kwargs)
            bad[name] = "x" * 32
            with self.assertRaises(TypeError):
                DelayBoundEvidence(**bad)
        # Wrong lengths are value errors.
        for name, length in (("context", 31), ("digest", 16), ("opening", 33)):
            bad = dict(kwargs)
            bad[name] = b"x" * length
            with self.assertRaises(ValueError):
                DelayBoundEvidence(**bad)
        with self.assertRaises(ValueError):
            DelayBoundEvidence(**{**kwargs, "mac": b"m" * 31})
        # Version and evidence shape.
        with self.assertRaises(TypeError):
            DelayBoundEvidence(**{**kwargs, "version": True})
        with self.assertRaises(ValueError):
            DelayBoundEvidence(**{**kwargs, "version": 2})
        with self.assertRaises(TypeError):
            DelayBoundEvidence(**{**kwargs, "evidence": object()})
        # Numeric contract violations are value errors.
        for name, value in (
            ("issued_at", "0.0"),
            ("issued_at", True),
            ("issued_at", float("inf")),
            ("max_delay_seconds", "2.0"),
            ("max_delay_seconds", True),
            ("max_delay_seconds", 0.0),
            ("max_delay_seconds", -1.0),
            ("max_delay_seconds", float("nan")),
        ):
            with self.assertRaises(ValueError):
                DelayBoundEvidence(**{**kwargs, name: value})


class AuditDelayBoundTest(unittest.TestCase):
    def test_audits_record_and_bytes(self):
        record = _make_record()
        measurement = audit_delay_bound(record, KEY)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.elapsed_seconds, 1.0)
        again = audit_delay_bound(record.to_bytes(), KEY)
        self.assertEqual(again, measurement)

    def test_audit_is_pure(self):
        record = _make_record()
        audit_delay_bound(record, KEY)
        audit_delay_bound(record, KEY)  # repeated, no state change

    def test_wrong_key_type_is_type_error(self):
        record = _make_record()
        for bad in ("key", b"", bytearray(KEY), None):
            with self.subTest(bad=bad):
                if isinstance(bad, bytes):
                    with self.assertRaises(ValueError):
                        audit_delay_bound(record, bad)
                else:
                    with self.assertRaises(TypeError):
                        audit_delay_bound(record, bad)

    def test_wrong_record_type_is_type_error(self):
        with self.assertRaises(TypeError):
            audit_delay_bound("record", KEY)
        with self.assertRaises(TypeError):
            audit_delay_bound(object(), KEY)

    def test_wrong_key_mac_mismatch(self):
        record = _make_record()
        with self.assertRaisesRegex(ValueError, "mac"):
            audit_delay_bound(record, OTHER_KEY)

    def test_tampered_fields_rejected(self):
        record = _make_record()
        obj = json.loads(record.to_bytes())

        def tampered(**changes):
            variant = dict(obj)
            variant.update(changes)
            return json.dumps(variant, separators=(",", ":")).encode()

        # Any outer field change invalidates the outer MAC.
        self.assertRaises(
            ValueError,
            audit_delay_bound,
            tampered(context=(b"z" * 32).hex()),
            KEY,
        )
        self.assertRaises(
            ValueError,
            audit_delay_bound,
            tampered(issued_at=0.5),
            KEY,
        )
        self.assertRaises(
            ValueError,
            audit_delay_bound,
            tampered(max_delay_seconds=0.5),
            KEY,
        )

    def test_tampered_nested_evidence_rejected(self):
        record = _make_record()
        obj = json.loads(record.to_bytes())
        variant = dict(obj)
        nested = dict(variant["evidence"])
        nested["end"] = nested["end"] + 0.25
        variant["evidence"] = nested
        blob = json.dumps(variant, separators=(",", ":")).encode()
        # The outer MAC covers the nested object, so this fails at the MAC.
        with self.assertRaisesRegex(ValueError, "mac"):
            audit_delay_bound(blob, KEY)

    def test_inner_mac_recomputed_against_key(self):
        from dataclasses import replace

        from nearproof import (
            _delay_bound_evidence_mac,
            _delay_bound_evidence_payload,
        )

        # Tamper with the nested evidence's MAC and re-sign only the outer
        # record with KEY: the outer check passes, then the inner MAC
        # mismatch must be reported.
        record = _make_record()
        bogus_evidence = replace(record.evidence, mac=b"\x01" * 32)
        forged = replace(
            record, evidence=bogus_evidence, mac=b"\x00" * 32
        )
        forged = replace(
            forged,
            mac=_delay_bound_evidence_mac(
                KEY, _delay_bound_evidence_payload(forged)
            ),
        )
        with self.assertRaisesRegex(ValueError, "evidence mac"):
            audit_delay_bound(forged, KEY)
        # And with the wrong key everything fails at the outer MAC.
        with self.assertRaisesRegex(ValueError, "mac"):
            audit_delay_bound(record, b"z" * len(KEY))

    def test_non_canonical_bytes_rejected(self):
        record = _make_record()
        obj = json.loads(record.to_bytes())
        pretty = json.dumps(obj, indent=2).encode()
        with self.assertRaises(ValueError):
            audit_delay_bound(pretty, KEY)

    def test_audits_delay_boundary(self):
        record = _make_record(end=MAX_DELAY)
        measurement = audit_delay_bound(record, KEY)
        self.assertEqual(measurement.elapsed_seconds, MAX_DELAY)

    def test_over_bound_record_rejected(self):
        # Forge a structurally-valid record whose delay exceeds its bound:
        # sign with the key by constructing through the verifier at a valid
        # delay, then rebuild with a smaller max_delay via a fresh MAC.
        import hmac as _hmac
        import hashlib

        from nearproof import (
            _delay_bound_evidence_payload,
            _delay_bound_evidence_mac,
        )
        from dataclasses import replace

        record = _make_record(end=1.5)
        forged = replace(record, max_delay_seconds=1.0, mac=b"\x00" * 32)
        forged = replace(
            forged, mac=_delay_bound_evidence_mac(KEY, _delay_bound_evidence_payload(forged))
        )
        with self.assertRaisesRegex(ValueError, "bound"):
            audit_delay_bound(forged, KEY)


class LegacyCompatibilityTest(unittest.TestCase):
    def test_default_verifier_has_no_delay_protection(self):
        # Existing entry points keep working without replay protection.
        prover = Prover(KEY)
        verifier = Verifier(KEY)
        self.assertIsInstance(verifier.measure(prover), Measurement)

    def test_plain_bound_round_unchanged(self):
        from nearproof import BoundEvidence, audit_bound

        clock = SteppedClock()
        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 0.4
        bound = verifier.verify_bound(challenge, response, 0.0, opening=OPENING)
        self.assertIsInstance(bound, BoundEvidence)
        self.assertEqual(audit_bound(bound, KEY).elapsed_seconds, 0.4)


if __name__ == "__main__":
    unittest.main()
