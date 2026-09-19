import math
import threading
import unittest

from nearproof import (
    SPEED_OF_LIGHT_MPS,
    Challenge,
    ChallengeStateError,
    Measurement,
    Prover,
    Verifier,
)

KEY = b"shared-secret-key"
TTL = 10.0


class SteppedClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class CountingClock(SteppedClock):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.now


def fixture(**kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    kwargs.setdefault("replay_protection", True)
    kwargs.setdefault("challenge_ttl_seconds", TTL)
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


class TtlConfigurationTest(unittest.TestCase):
    def test_ttl_is_keyword_only(self):
        with self.assertRaises(TypeError):
            Verifier(KEY, SPEED_OF_LIGHT_MPS, SteppedClock(), True, TTL)

    def test_ttl_requires_replay_protection(self):
        with self.assertRaises(ValueError):
            Verifier(KEY, challenge_ttl_seconds=TTL)
        with self.assertRaises(ValueError):
            Verifier(KEY, replay_protection=False, challenge_ttl_seconds=TTL)

    def test_non_number_ttl_rejected(self):
        for bad in (True, False, "10", b"10", object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                Verifier(KEY, replay_protection=True, challenge_ttl_seconds=bad)

    def test_non_finite_or_non_positive_ttl_rejected(self):
        for bad in (0, 0.0, -1, -0.5, math.inf, -math.inf, math.nan):
            with self.assertRaises(ValueError, msg=repr(bad)):
                Verifier(KEY, replay_protection=True, challenge_ttl_seconds=bad)

    def test_valid_ttl_accepted(self):
        for good in (1, 0.5, TTL, 1e9):
            Verifier(KEY, replay_protection=True, challenge_ttl_seconds=good)

    def test_none_ttl_keeps_challenges_valid_forever(self):
        clock, prover, verifier = fixture(challenge_ttl_seconds=None)
        challenge = verifier.new_challenge()
        clock.now += 1e9
        measurement = verifier.verify(challenge, prover.respond(challenge), clock.now)
        self.assertIsInstance(measurement, Measurement)


class TtlVerifyTest(unittest.TestCase):
    def test_verify_before_deadline_succeeds(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL - 1e-9
        measurement = verifier.verify(challenge, prover.respond(challenge), clock.now)
        self.assertIsInstance(measurement, Measurement)

    def test_verify_at_deadline_expires(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL  # exactly at the deadline: expired
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_verify_after_deadline_expires(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL + 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_expiry_is_terminal_for_verify(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL + 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)
        # Even if the clock moves back before the deadline, it stays expired.
        clock.now = 0.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_expiry_is_terminal_for_revoke(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)
        clock.now = 0.0
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_expiry_error_is_state_error_not_value_error(self):
        # State errors win over response validation: garbage response on an
        # expired challenge still reports the state, not the response.
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)

    def test_failed_verify_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL - 1.0
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        # Retry before the (unmoved) deadline still works.
        measurement = verifier.verify(challenge, prover.respond(challenge), clock.now)
        self.assertIsInstance(measurement, Measurement)

    def test_failed_verify_then_deadline_still_expires(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = TTL - 1.0
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        # The failure did not refresh issuance: the original deadline holds.
        clock.now = TTL
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, clock.now)

    def test_negative_elapsed_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = TTL - 1.0
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, clock.now + 100.0)
        clock.now = TTL
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, clock.now)

    def test_bad_argument_type_does_not_extend_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL - 1.0
        with self.assertRaises(TypeError):
            verifier.verify(challenge, "not bytes", clock.now)
        clock.now = TTL
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_consumed_before_deadline_stays_consumed_after(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        verifier.verify(challenge, prover.respond(challenge), clock.now)
        clock.now = TTL + 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_revoked_before_deadline_stays_revoked_after(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        verifier.revoke(challenge)
        clock.now = TTL + 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_revoke_before_deadline_still_works(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        clock.now = TTL - 1e-9
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_each_challenge_has_its_own_deadline(self):
        clock, prover, verifier = fixture()
        first = verifier.new_challenge()
        clock.now = TTL - 1.0
        second = verifier.new_challenge()
        clock.now = TTL + 1.0  # first expired, second still valid
        with self.assertRaises(ChallengeStateError):
            verifier.verify(first, prover.respond(first), clock.now)
        self.assertIsInstance(
            verifier.verify(second, prover.respond(second), clock.now), Measurement
        )

    def test_verify_reads_clock_once(self):
        clock = CountingClock()
        _, prover, verifier = fixture(clock=clock)
        challenge = verifier.new_challenge()
        calls_after_issue = clock.calls
        verifier.verify(challenge, prover.respond(challenge), clock.now)
        self.assertEqual(clock.calls - calls_after_issue, 1)

    def test_revoke_reads_clock_once(self):
        clock = CountingClock()
        _, _, verifier = fixture(clock=clock)
        challenge = verifier.new_challenge()
        calls_after_issue = clock.calls
        verifier.revoke(challenge)
        self.assertEqual(clock.calls - calls_after_issue, 1)


class TtlMeasureTest(unittest.TestCase):
    class SlowProver:
        """Advances the clock while "answering" to simulate a slow round trip."""

        def __init__(self, prover, clock, delay):
            self._prover = prover
            self._clock = clock
            self._delay = delay

        def respond(self, challenge):
            self._clock.now += self._delay
            return self._prover.respond(challenge)

    def test_measure_within_ttl_succeeds(self):
        clock, prover, verifier = fixture()
        slow = self.SlowProver(prover, clock, TTL / 2.0)
        self.assertIsInstance(verifier.measure(slow), Measurement)

    def test_measure_crossing_deadline_fails(self):
        clock, prover, verifier = fixture()
        slow = self.SlowProver(prover, clock, TTL)
        with self.assertRaises(ChallengeStateError):
            verifier.measure(slow)


class TtlConcurrencyTest(unittest.TestCase):
    def _race(self, verifier, challenge, response, started, threads=16):
        successes = []
        errors = []
        barrier = threading.Barrier(threads)

        def attempt():
            barrier.wait()
            try:
                successes.append(verifier.verify(challenge, response, started))
            except ChallengeStateError as error:
                errors.append(error)

        workers = [threading.Thread(target=attempt) for _ in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        return successes, errors

    def test_at_most_one_success_before_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = TTL / 2.0

        successes, errors = self._race(verifier, challenge, response, clock.now)
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 15)

        # Past the deadline every further attempt fails.
        clock.now = TTL
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, clock.now)

    def test_all_fail_at_deadline(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now = TTL  # exactly at the deadline

        successes, errors = self._race(verifier, challenge, response, clock.now)
        self.assertEqual(len(successes), 0)
        self.assertEqual(len(errors), 16)


if __name__ == "__main__":
    unittest.main()
