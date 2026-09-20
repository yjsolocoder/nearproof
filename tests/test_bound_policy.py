import dataclasses
import math
import unittest

from nearproof import (
    Challenge,
    ChallengeStateError,
    Measurement,
    Prover,
    Verifier,
    audit_bound,
    audit_bound_policy,
    context_digest,
)

KEY = b"shared-secret-key"
CONTEXT = b"context-" * 4                   # exactly 32 bytes
OPENING = b"opening!" * 4                   # exactly 32 bytes
DIGEST = context_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def make_bound(verifier, clock, *, started=0.0, end=0.2, prover=None):
    """Issue and complete one bound round; return (challenge, response, bound)."""
    challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
    clock.now = end
    response = (prover or Prover(KEY)).reveal(challenge, CONTEXT, OPENING)
    bound = verifier.verify_bound(
        challenge, response, started, opening=OPENING
    )
    return challenge, response, bound


class VerifyBoundSuccessTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.prover = Prover(KEY)
        self.verifier = Verifier(KEY, clock=self.clock, replay_protection=True)

    def test_success_returns_record_and_consumes(self):
        challenge, _response, bound = make_bound(
            self.verifier, self.clock, prover=self.prover
        )
        self.assertEqual(bound.version, 1)
        self.assertEqual(bound.context, CONTEXT)
        self.assertEqual(bound.digest, DIGEST)
        self.assertEqual(bound.opening, OPENING)
        # The round is consumed: a second attempt, even with correct
        # arguments, is a state error.
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge,
                self.prover.reveal(challenge, CONTEXT, OPENING),
                0.0,
                opening=OPENING,
            )

    def test_record_passes_audit_bound_and_roundtrips(self):
        _challenge, _response, bound = make_bound(
            self.verifier, self.clock, prover=self.prover
        )
        measurement = audit_bound(bound, KEY)
        self.assertIsInstance(measurement, Measurement)
        self.assertAlmostEqual(measurement.elapsed_seconds, 0.2)
        blob = bound.to_bytes()
        self.assertEqual(audit_bound(blob, KEY), measurement)

    def test_evidence_end_is_the_clock_reading(self):
        _challenge, _response, bound = make_bound(
            self.verifier, self.clock, started=0.05, end=0.25,
            prover=self.prover,
        )
        self.assertEqual(bound.evidence.start, 0.05)
        self.assertEqual(bound.evidence.end, 0.25)

    def test_non_challenge_is_type_error(self):
        with self.assertRaises(TypeError):
            self.verifier.verify_bound("nope", b"r", 0.0, opening=OPENING)

    def test_requires_replay_protection(self):
        verifier = Verifier(KEY, clock=SteppedClock(), replay_protection=False)
        challenge = Challenge(1, b"n" * 16)
        with self.assertRaises(ValueError):
            verifier.verify_bound(challenge, b"r", 0.0, opening=OPENING)


class VerifyBoundStateGateFirstTest(unittest.TestCase):
    """State/TTL must win over opening, ranging and response validation."""

    def setUp(self):
        self.clock = SteppedClock()
        self.prover = Prover(KEY)
        self.verifier = Verifier(KEY, clock=self.clock, replay_protection=True)

    def test_unknown_challenge_state_error_with_garbage_args(self):
        forged = Challenge(1, b"n" * 16)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(forged, None, None, opening=None)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(forged, b"", math.nan, opening=123)

    def test_consumed_challenge_state_error_with_garbage_args(self):
        challenge, response, _bound = make_bound(
            self.verifier, self.clock, prover=self.prover
        )
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(challenge, None, None, opening=None)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge, response, math.nan, opening=b"short"
            )

    def test_revoked_challenge_state_error_with_garbage_args(self):
        challenge = self.verifier.new_challenge(
            context=CONTEXT, digest=DIGEST
        )
        self.verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(challenge, None, None, opening=None)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge, b"bad", math.nan, opening=7
            )


class VerifyBoundTTLGateFirstTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.prover = Prover(KEY)
        self.verifier = Verifier(
            KEY, clock=self.clock, replay_protection=True,
            challenge_ttl_seconds=1.0,
        )

    def _bound_challenge(self):
        return self.verifier.new_challenge(context=CONTEXT, digest=DIGEST)

    def test_expired_state_error_precedes_every_check(self):
        challenge = self._bound_challenge()
        self.clock.now = 1.0  # exactly the deadline -> expired
        # None opening would be TypeError, bad response/started_at ValueError:
        # expiry must win.
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(challenge, None, None, opening=None)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge, b"bad", math.nan, opening="no"
            )

    def test_expiry_is_terminal_with_clock_rolled_back(self):
        challenge = self._bound_challenge()
        self.clock.now = 2.0
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge, b"r", 0.0, opening=OPENING
            )
        self.clock.now = 0.5
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge,
                self.prover.reveal(challenge, CONTEXT, OPENING),
                0.0,
                opening=OPENING,
            )

    def test_succeeds_before_deadline(self):
        challenge = self._bound_challenge()
        self.clock.now = 0.9
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        bound = self.verifier.verify_bound(
            challenge, response, 0.0, opening=OPENING
        )
        self.assertEqual(bound.evidence.end, 0.9)

    def test_failure_does_not_refresh_deadline(self):
        challenge = self._bound_challenge()  # deadline stays 1.0
        self.clock.now = 0.5
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, b"wrong", 0.0, opening=OPENING
            )
        # A retry at the original deadline is expired, not 0.5 + TTL.
        self.clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                challenge,
                self.prover.reveal(challenge, CONTEXT, OPENING),
                0.0,
                opening=OPENING,
            )


class VerifyBoundFailureKeepsPendingTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.prover = Prover(KEY)
        self.verifier = Verifier(KEY, clock=self.clock, replay_protection=True)

    def _challenge(self):
        return self.verifier.new_challenge(context=CONTEXT, digest=DIGEST)

    def _retry_succeeds(self, challenge):
        self.clock.now = 0.9
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        bound = self.verifier.verify_bound(
            challenge, response, 0.0, opening=OPENING
        )
        self.assertEqual(bound.digest, DIGEST)

    def test_none_opening_is_type_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        with self.assertRaises(TypeError):
            self.verifier.verify_bound(challenge, b"r", 0.0, opening=None)
        self._retry_succeeds(challenge)

    def test_non_bytes_opening_is_type_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        with self.assertRaises(TypeError):
            self.verifier.verify_bound(challenge, b"r", 0.0, opening="32b")
        self._retry_succeeds(challenge)

    def test_wrong_length_opening_is_value_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, b"r", 0.0, opening=b"short"
            )
        self._retry_succeeds(challenge)

    def test_wrong_opening_is_value_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        other_opening = b"x" * 32
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, response, 0.0, opening=other_opening
            )
        self._retry_succeeds(challenge)

    def test_wrong_response_is_value_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, b"bad", 0.0, opening=OPENING
            )
        self._retry_succeeds(challenge)

    def test_negative_elapsed_is_value_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, response, 5.0, opening=OPENING
            )
        self._retry_succeeds(challenge)

    def test_non_finite_values_are_value_error_then_retry(self):
        challenge = self._challenge()
        self.clock.now = 0.2
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, response, math.nan, opening=OPENING
            )
        self._retry_succeeds(challenge)

    def test_unbound_challenge_rejected_and_still_pending(self):
        challenge = self.verifier.new_challenge()
        self.clock.now = 0.2
        with self.assertRaises(ValueError):
            self.verifier.verify_bound(
                challenge, b"r", 0.0, opening=OPENING
            )
        # Not consumed: the legacy protocol still completes it.
        response = self.prover.respond(challenge)
        measurement = self.verifier.verify(challenge, response, 0.0)
        self.assertIsInstance(measurement, Measurement)

    def test_concurrent_attempts_succeed_at_most_once(self):
        import threading

        challenge = self._challenge()
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        outcomes = []

        def attempt():
            try:
                self.verifier.verify_bound(
                    challenge, response, 0.0, opening=OPENING
                )
                outcomes.append("ok")
            except (ValueError, ChallengeStateError):
                outcomes.append("fail")

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("ok"), 1)


class BoundVerifyLegacyPathUnchangedTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.prover = Prover(KEY)
        self.verifier = Verifier(KEY, clock=self.clock, replay_protection=True)

    def test_verify_with_opening_still_runs_bound_protocol(self):
        challenge = self.verifier.new_challenge(
            context=CONTEXT, digest=DIGEST
        )
        self.clock.now = 0.3
        response = self.prover.reveal(challenge, CONTEXT, OPENING)
        measurement = self.verifier.verify(
            challenge, response, 0.0, opening=OPENING
        )
        self.assertIsInstance(measurement, Measurement)

    def test_protocol_mixing_still_rejected(self):
        bound_challenge = self.verifier.new_challenge(
            context=CONTEXT, digest=DIGEST
        )
        self.clock.now = 0.2
        with self.assertRaises(ValueError):
            self.verifier.verify(
                bound_challenge,
                self.prover.respond(bound_challenge),
                0.0,
            )
        plain_challenge = self.verifier.new_challenge()
        with self.assertRaises(ValueError):
            self.verifier.verify(
                plain_challenge, b"r", 0.0, opening=OPENING
            )


class AuditBoundPolicyTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.verifier = Verifier(KEY, clock=self.clock, replay_protection=True)
        self.clock.now = 100.0
        _c, _r, self.bound = make_bound(self.verifier, self.clock, end=100.0)
        self.end = self.bound.evidence.end

    def test_no_policy_ignores_now_and_reads_no_clock(self):
        first = audit_bound(self.bound, KEY)
        # A nonsensical ``now`` is ignored entirely when freshness is off.
        second = audit_bound_policy(
            self.bound, KEY, now="not-a-number", max_age=None
        )
        self.assertEqual(first, second)
        self.assertEqual(
            audit_bound_policy(self.bound.to_bytes(), KEY), first
        )

    def test_fresh_within_window(self):
        measurement = audit_bound_policy(
            self.bound, KEY, now=self.end + 10.0, max_age=60.0
        )
        self.assertEqual(measurement, audit_bound(self.bound, KEY))

    def test_closed_interval_boundaries(self):
        # Age exactly zero and exactly max_age are both valid.
        self.assertIsInstance(
            audit_bound_policy(self.bound, KEY, now=self.end, max_age=0.0),
            Measurement,
        )
        self.assertIsInstance(
            audit_bound_policy(
                self.bound, KEY, now=self.end + 60.0, max_age=60.0
            ),
            Measurement,
        )

    def test_integer_now_and_max_age_accepted(self):
        self.assertIsInstance(
            audit_bound_policy(self.bound, KEY, now=self.end + 5, max_age=10),
            Measurement,
        )

    def test_future_evidence_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.bound, KEY, now=self.end - 0.001, max_age=60.0
            )

    def test_too_old_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.bound, KEY, now=self.end + 60.001, max_age=60.0
            )

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(self.bound, KEY, max_age=60.0)

    def test_max_age_contract(self):
        for bad in (True, False, "60", object(), math.inf, math.nan, -0.01):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit_bound_policy(
                        self.bound, KEY, now=self.end + 1.0, max_age=bad
                    )

    def test_now_contract(self):
        for bad in (True, False, "100", object(), math.inf, math.nan):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit_bound_policy(
                        self.bound, KEY, now=bad, max_age=60.0
                    )

    def test_crypto_check_runs_first(self):
        tampered = dataclasses.replace(self.bound, opening=b"z" * 32)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                tampered, KEY, now=self.end + 1.0, max_age=60.0
            )
        with self.assertRaises(ValueError):
            audit_bound_policy(self.bound, b"other-key", now=self.end, max_age=0)
        # Valid-looking freshness arguments never rescue a bad record.
        with self.assertRaises(ValueError):
            audit_bound_policy(b"not-json", KEY, now=self.end, max_age=0.0)

    def test_bound_type_must_be_record_or_bytes(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(123, KEY, now=self.end, max_age=0.0)

    def test_pure_check_touches_no_state(self):
        # A second record, left pending in its verifier, can still be
        # completed after policy audits of the first one.
        challenge = self.verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        for _ in range(3):
            audit_bound_policy(self.bound, KEY, now=self.end + 1.0, max_age=60.0)
        self.clock.now = 101.0
        response = Prover(KEY).reveal(challenge, CONTEXT, OPENING)
        bound = self.verifier.verify_bound(
            challenge, response, 100.5, opening=OPENING
        )
        self.assertEqual(bound.evidence.end, 101.0)
        # And a fresh policy audit over bytes uses evidence.end, not a clock.
        self.assertIsInstance(
            audit_bound_policy(
                bound.to_bytes(), KEY, now=101.0, max_age=0.0
            ),
            Measurement,
        )


if __name__ == "__main__":
    unittest.main()
