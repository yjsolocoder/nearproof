import threading
import unittest

from nearproof import (
    Challenge,
    ChallengeStateError,
    Measurement,
    Prover,
    Verifier,
    keyed_response,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


class SteppedClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def protected_fixture(**kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    verifier = Verifier(
        kwargs.pop("verifier_key", KEY),
        clock=clock,
        replay_protection=True,
        **kwargs,
    )
    return clock, prover, verifier


class ChallengeStateErrorTest(unittest.TestCase):
    def test_is_value_error_and_exported(self):
        self.assertTrue(issubclass(ChallengeStateError, ValueError))
        self.assertIsInstance(ChallengeStateError("boom"), ValueError)

    def test_replay_protection_is_keyword_only(self):
        # Every option after ``shared_key`` is keyword-only, so a positional
        # True cannot accidentally enable replay protection.
        with self.assertRaises(TypeError):
            Verifier(KEY, True)


class DefaultCompatibilityTest(unittest.TestCase):
    """With protection off (the default), nothing about verify/measure changes."""

    def test_externally_constructed_challenge_still_verifies(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock)
        self.assertFalse(verifier.replay_protection)
        external = Challenge(99, b"external-nonce!!")
        response = Prover(KEY).respond(external)
        measurement = verifier.verify(external, response, clock.now)
        self.assertIsInstance(measurement, Measurement)

    def test_successful_challenge_can_be_replayed(self):
        clock = SteppedClock()
        prover, verifier = Prover(KEY), Verifier(KEY, clock=clock)
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        first = verifier.verify(challenge, response, clock.now)
        clock.now += 1.0e-6
        second = verifier.verify(challenge, response, clock.now)
        self.assertEqual(first.nonce, second.nonce)

    def test_measure_unchanged(self):
        measurement = Verifier(KEY).measure(Prover(KEY))
        self.assertEqual(measurement.response, keyed_response(KEY, measurement.nonce))

    def test_revoke_unavailable_without_protection(self):
        verifier = Verifier(KEY)
        challenge = verifier.new_challenge()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class PendingLifecycleTest(unittest.TestCase):
    def test_issued_challenge_verifies_once_then_is_consumed(self):
        clock, prover, verifier = protected_fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        measurement = verifier.verify(challenge, response, clock.now)
        self.assertIsInstance(measurement, Measurement)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, clock.now)

    def test_externally_constructed_challenge_rejected_even_with_valid_response(self):
        clock, prover, verifier = protected_fixture()
        verifier.new_challenge()  # advance to round 1
        external = Challenge(1, b"a-different-nonce")
        # A perfectly valid keyed response for the external nonce:
        response = prover.respond(external)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(external, response, clock.now)

    def test_challenge_from_another_instance_rejected(self):
        clock = SteppedClock()
        prover = Prover(KEY)
        issuer = Verifier(KEY, clock=clock, replay_protection=True)
        other = Verifier(KEY, clock=clock, replay_protection=True)
        challenge = issuer.new_challenge()
        response = prover.respond(challenge)
        with self.assertRaises(ChallengeStateError):
            other.verify(challenge, response, clock.now)
        # The real issuer can still verify it.
        self.assertIsInstance(issuer.verify(challenge, response, clock.now), Measurement)

    def test_state_binds_full_challenge_content_not_round_index(self):
        clock, prover, verifier = protected_fixture()
        real = verifier.new_challenge()
        # Same round index, different nonce; and same nonce, different index.
        same_round = Challenge(real.round_index, b"x" * 16)
        same_nonce = Challenge(real.round_index + 1, real.nonce)
        for forged in (same_round, same_nonce):
            with self.subTest(forged=forged):
                with self.assertRaises(ChallengeStateError):
                    verifier.verify(forged, prover.respond(forged), clock.now)
        # The genuine, full-content challenge still verifies.
        self.assertIsInstance(
            verifier.verify(real, prover.respond(real), clock.now), Measurement
        )

    def test_non_challenge_argument_is_type_error(self):
        clock, _, verifier = protected_fixture()
        with self.assertRaises(TypeError):
            verifier.verify(b"not-a-challenge", b"", clock.now)


class RetryAfterFailureTest(unittest.TestCase):
    def _fresh_pending(self, verifier, prover):
        challenge = verifier.new_challenge()
        return challenge, prover.respond(challenge)

    def test_wrong_response_does_not_consume(self):
        clock, prover, verifier = protected_fixture()
        challenge, response = self._fresh_pending(verifier, prover)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        # Corrected caller retries successfully.
        self.assertIsInstance(
            verifier.verify(challenge, response, clock.now), Measurement
        )

    def test_negative_elapsed_does_not_consume(self):
        clock, prover, verifier = protected_fixture()
        challenge, response = self._fresh_pending(verifier, prover)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, 1.0)  # started in the future
        self.assertIsInstance(
            verifier.verify(challenge, response, clock.now), Measurement
        )

    def test_bad_argument_types_do_not_consume(self):
        clock, prover, verifier = protected_fixture()
        challenge, response = self._fresh_pending(verifier, prover)
        with self.assertRaises(TypeError):
            verifier.verify(challenge, object(), clock.now)
        with self.assertRaises(TypeError):
            verifier.verify(challenge, response, object())
        self.assertIsInstance(
            verifier.verify(challenge, response, clock.now), Measurement
        )

    def test_failed_then_retried_then_replayed(self):
        clock, prover, verifier = protected_fixture()
        challenge, response = self._fresh_pending(verifier, prover)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, Prover(OTHER_KEY).respond(challenge), clock.now)
        verifier.verify(challenge, response, clock.now)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, clock.now)


class RevokeTest(unittest.TestCase):
    def test_revoked_challenge_cannot_verify(self):
        clock, prover, verifier = protected_fixture()
        challenge = verifier.new_challenge()
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_revoke_unknown_raises(self):
        _, _, verifier = protected_fixture()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(Challenge(123, b"never-issued!!!!"))

    def test_revoke_external_or_other_instance_raises(self):
        _, _, verifier = protected_fixture()
        issuer = Verifier(KEY, replay_protection=True)
        foreign = issuer.new_challenge()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(foreign)

    def test_revoke_consumed_raises(self):
        clock, prover, verifier = protected_fixture()
        challenge = verifier.new_challenge()
        verifier.verify(challenge, prover.respond(challenge), clock.now)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_double_revoke_raises(self):
        _, _, verifier = protected_fixture()
        challenge = verifier.new_challenge()
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_revoking_pending_keeps_other_pending_usable(self):
        clock, prover, verifier = protected_fixture()
        first, second = verifier.new_challenge(), verifier.new_challenge()
        verifier.revoke(first)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(first, prover.respond(first), clock.now)
        self.assertIsInstance(
            verifier.verify(second, prover.respond(second), clock.now), Measurement
        )

    def test_revoke_wrong_type(self):
        _, _, verifier = protected_fixture()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(b"not-a-challenge")


class RecordingProver(Prover):
    """Remembers the challenge of its last respond() call."""

    def __init__(self, key: bytes) -> None:
        super().__init__(key)
        self.last_challenge: Challenge | None = None

    def respond(self, challenge: Challenge) -> bytes:
        self.last_challenge = challenge
        return super().respond(challenge)


class ProtectedMeasureTest(unittest.TestCase):
    def test_measure_follows_same_rules(self):
        verifier = Verifier(KEY, replay_protection=True)
        first = verifier.measure(Prover(KEY))
        second = verifier.measure(Prover(KEY))
        self.assertNotEqual((first.round_index, first.nonce),
                            (second.round_index, second.nonce))
        # Each internally issued challenge was consumed by its own measure().
        for measurement in (first, second):
            used = Challenge(measurement.round_index, measurement.nonce)
            with self.assertRaises(ChallengeStateError):
                verifier.verify(used, measurement.response, verifier.clock())

    def test_measure_wrong_key_does_not_consume_challenge(self):
        verifier = Verifier(KEY, replay_protection=True)
        bad_prover = RecordingProver(OTHER_KEY)
        with self.assertRaises(ValueError):
            verifier.measure(bad_prover)
        # The challenge created inside the failed measure() stayed pending;
        # retrying it with the correct response succeeds exactly once.
        pending = bad_prover.last_challenge
        self.assertIsNotNone(pending)
        measurement = verifier.verify(
            pending, Prover(KEY).respond(pending), verifier.clock()
        )
        self.assertIsInstance(measurement, Measurement)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(
                pending, Prover(KEY).respond(pending), verifier.clock()
            )


class ConcurrentVerifyTest(unittest.TestCase):
    def test_concurrent_verifies_have_at_most_one_success(self):
        verifier = Verifier(KEY, replay_protection=True)
        challenge = verifier.new_challenge()
        response = Prover(KEY).respond(challenge)
        started_at = verifier.clock()

        n_threads = 32
        barrier = threading.Barrier(n_threads)
        results: list[object] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            try:
                result = verifier.verify(challenge, response, started_at)
            except ChallengeStateError as exc:
                result = exc
            except BaseException as exc:  # pragma: no cover - surfaced below
                with lock:
                    errors.append(exc)
                return
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), n_threads)
        successes = [r for r in results if isinstance(r, Measurement)]
        state_errors = [r for r in results if isinstance(r, ChallengeStateError)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(state_errors), n_threads - 1)
        # Even after the race, the challenge stays consumed.
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, started_at)


if __name__ == "__main__":
    unittest.main()
