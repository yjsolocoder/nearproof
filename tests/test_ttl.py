import threading
import unittest

from nearproof import (
    SPEED_OF_LIGHT_MPS,
    ChallengeStateError,
    Measurement,
    Prover,
    Verifier,
)

KEY = b"shared-secret-key"
TTL = 1.0


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def fixture(ttl=TTL, **kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    kwargs.setdefault("replay_protection", True)
    verifier = Verifier(
        kwargs.pop("verifier_key", KEY),
        clock=clock,
        challenge_ttl_seconds=ttl,
        **kwargs,
    )
    return clock, prover, verifier


class TTLConfigurationTest(unittest.TestCase):
    def test_ttl_requires_replay_protection(self):
        with self.assertRaises(ValueError):
            Verifier(KEY, replay_protection=False, challenge_ttl_seconds=1.0)

    def test_ttl_none_keeps_default_without_protection(self):
        clock = SteppedClock()
        prover = Prover(KEY)
        verifier = Verifier(
            KEY, clock=clock, replay_protection=False, challenge_ttl_seconds=None
        )
        # No registry, no expiry: externally built challenges verify forever.
        from nearproof import Challenge, keyed_response

        challenge = Challenge(1, b"0" * 16)
        clock.now = 1_000_000.0
        self.assertIsInstance(
            verifier.verify(
                challenge, keyed_response(KEY, challenge.nonce), 0.0
            ),
            Measurement,
        )

    def test_ttl_is_keyword_only(self):
        with self.assertRaises(TypeError):
            Verifier(KEY, SPEED_OF_LIGHT_MPS, SteppedClock(), True, 1.0)

    def test_bool_ttl_rejected(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Verifier(KEY, replay_protection=True, challenge_ttl_seconds=value)

    def test_non_numeric_ttl_rejected(self):
        for value in ("1.0", [1.0], (1.0,), object()):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Verifier(KEY, replay_protection=True, challenge_ttl_seconds=value)

    def test_non_positive_ttl_rejected(self):
        for value in (0, 0.0, -1.0, -0.001):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Verifier(KEY, replay_protection=True, challenge_ttl_seconds=value)

    def test_non_finite_ttl_rejected(self):
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Verifier(KEY, replay_protection=True, challenge_ttl_seconds=value)

    def test_integer_ttl_accepted(self):
        verifier = Verifier(
            KEY, replay_protection=True, challenge_ttl_seconds=5
        )
        self.assertIsNotNone(verifier)


class TTLExpiryTest(unittest.TestCase):
    def test_verify_succeeds_before_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()  # issued at 0, deadline 1.0
        response = prover.respond(challenge)
        clock.now = 0.999
        self.assertIsInstance(
            verifier.verify(challenge, response, clock.now), Measurement
        )

    def test_verify_fails_exactly_at_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 1.0  # equal to the deadline -> expired
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), 0.0)

    def test_verify_fails_after_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 2.5
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), 0.0)

    def test_expiry_is_terminal_for_verify(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), 0.0)
        # Rolling the clock back must not revive it.
        clock.now = 0.5
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), 0.0)

    def test_expiry_is_terminal_for_revoke(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)
        clock.now = 0.5
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_revoke_succeeds_before_deadline(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 0.999
        verifier.revoke(challenge)  # no error
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_revoke_fails_exactly_at_deadline(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_expired_state_error_precedes_response_validation(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 1.0
        # Garbage response and started_at: expiry wins over TypeError/ValueError.
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, None, None)

    def test_unknown_challenge_still_rejected_with_ttl(self):
        clock, _, verifier = fixture()
        verifier.new_challenge()
        from nearproof import Challenge

        with self.assertRaises(ChallengeStateError):
            verifier.verify(Challenge(1, b"x" * 16), b"y", clock.now)

    def test_consumed_before_deadline_stays_dead(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        verifier.verify(challenge, prover.respond(challenge), clock.now)
        clock.now = 0.5
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)


class TTLNoRefreshTest(unittest.TestCase):
    """Errors must not refresh the issue time or extend the deadline."""

    def test_wrong_response_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()  # deadline stays 1.0
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        # A retry at the original deadline is expired, not 0.5 + TTL.
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), 0.0)

    def test_retry_after_wrong_response_succeeds_before_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        clock.now = 0.9
        self.assertIsInstance(
            verifier.verify(challenge, prover.respond(challenge), 0.0), Measurement
        )

    def test_negative_elapsed_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, clock.now + 10.0)
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, 0.0)

    def test_bad_response_type_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = 0.5
        with self.assertRaises(TypeError):
            verifier.verify(challenge, "not bytes", clock.now)
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), 0.0)

    def test_bad_started_at_type_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = 0.5
        with self.assertRaises(TypeError):
            verifier.verify(challenge, response, None)
        clock.now = 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, 0.0)


class TTLDeadlineTest(unittest.TestCase):
    def test_deadline_anchored_to_issue_time(self):
        clock = SteppedClock(start=10.0)
        prover = Prover(KEY)
        verifier = Verifier(
            KEY, clock=clock, replay_protection=True, challenge_ttl_seconds=2.0
        )
        challenge = verifier.new_challenge()  # deadline 12.0
        response = prover.respond(challenge)
        clock.now = 11.999
        self.assertIsInstance(
            verifier.verify(challenge, response, 10.0), Measurement
        )

    def test_new_challenge_gets_fresh_deadline(self):
        clock, prover, verifier = fixture()
        first = verifier.new_challenge()
        clock.now = 5.0  # first long expired
        second = verifier.new_challenge()  # fresh deadline at 6.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(first, prover.respond(first), 0.0)
        clock.now = 5.5
        self.assertIsInstance(
            verifier.verify(second, prover.respond(second), 5.0), Measurement
        )


class TTLMeasureTest(unittest.TestCase):
    def test_measure_succeeds_within_deadline(self):
        clock, prover, verifier = fixture(ttl=10.0)
        self.assertIsInstance(verifier.measure(prover), Measurement)

    def test_measure_fails_when_response_crosses_deadline(self):
        clock = SteppedClock()
        prover = Prover(KEY)
        verifier = Verifier(
            KEY, clock=clock, replay_protection=True, challenge_ttl_seconds=1.0
        )

        class SlowProver:
            def respond(self, challenge):
                clock.now = 1.5  # answer arrives after the deadline
                return prover.respond(challenge)

        with self.assertRaises(ChallengeStateError):
            verifier.measure(SlowProver())

    def test_measure_fails_exactly_at_deadline(self):
        clock = SteppedClock()
        prover = Prover(KEY)
        verifier = Verifier(
            KEY, clock=clock, replay_protection=True, challenge_ttl_seconds=1.0
        )

        class BoundaryProver:
            def respond(self, challenge):
                clock.now = 1.0
                return prover.respond(challenge)

        with self.assertRaises(ChallengeStateError):
            verifier.measure(BoundaryProver())


class TTLConcurrentTest(unittest.TestCase):
    def test_at_most_one_success_before_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = 0.999  # all threads see an unexpired challenge

        successes = []
        errors = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()
            try:
                successes.append(verifier.verify(challenge, response, 0.0))
            except ChallengeStateError as error:
                errors.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 15)

    def test_all_fail_at_or_after_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = 1.0  # deadline reached

        successes = []
        errors = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()
            try:
                successes.append(verifier.verify(challenge, response, 0.0))
            except ChallengeStateError as error:
                errors.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(successes, [])
        self.assertEqual(len(errors), 16)


class NoTTLCompatibilityTest(unittest.TestCase):
    """Without a TTL the distance math and registry semantics are unchanged."""

    def test_no_deadline_means_no_expiry(self):
        clock = SteppedClock()
        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        challenge = verifier.new_challenge()
        clock.now = 1_000_000.0
        self.assertIsInstance(
            verifier.verify(challenge, prover.respond(challenge), 0.0), Measurement
        )

    def test_distance_math_unchanged_with_ttl(self):
        clock, prover, verifier = fixture(ttl=10.0)
        challenge = verifier.new_challenge()
        clock.now = 2.0e-6
        measurement = verifier.verify(challenge, prover.respond(challenge), 0.0)
        self.assertAlmostEqual(measurement.elapsed_seconds, 2.0e-6)
        self.assertAlmostEqual(
            measurement.distance_meters, 2.0e-6 * SPEED_OF_LIGHT_MPS / 2.0
        )


if __name__ == "__main__":
    unittest.main()
