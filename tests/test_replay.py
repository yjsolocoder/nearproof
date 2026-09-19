import dataclasses
import os
import threading
import unittest

from nearproof import (
    SPEED_OF_LIGHT_MPS,
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


def fixture(**kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    kwargs.setdefault("replay_protection", True)
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


class ErrorExportTest(unittest.TestCase):
    def test_state_error_is_value_error(self):
        self.assertTrue(issubclass(ChallengeStateError, ValueError))
        with self.assertRaises(ValueError):
            raise ChallengeStateError("boom")

    def test_replay_protection_is_keyword_only(self):
        with self.assertRaises(TypeError):
            Verifier(KEY, SPEED_OF_LIGHT_MPS, SteppedClock(), True)


class DefaultCompatibilityTest(unittest.TestCase):
    """With replay protection off, legacy single-round behaviour is unchanged."""

    def test_externally_built_challenge_verifies(self):
        clock, prover, verifier = fixture(replay_protection=False)
        challenge = Challenge(1, b"0" * 16)
        measurement = verifier.verify(
            challenge, keyed_response(KEY, challenge.nonce), clock.now
        )
        self.assertIsInstance(measurement, Measurement)

    def test_same_challenge_can_be_verified_repeatedly(self):
        clock, prover, verifier = fixture(replay_protection=False)
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        first = verifier.verify(challenge, response, clock.now)
        clock.now += 0.001
        second = verifier.verify(challenge, response, clock.now)
        self.assertIsInstance(first, Measurement)
        self.assertIsInstance(second, Measurement)

    def test_revoke_unavailable_without_protection(self):
        _, _, verifier = fixture(replay_protection=False)
        challenge = verifier.new_challenge()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_measure_still_works(self):
        prover, verifier = Prover(KEY), Verifier(KEY)
        self.assertIsInstance(verifier.measure(prover), Measurement)


class RegistrationTest(unittest.TestCase):
    def test_externally_constructed_challenge_rejected(self):
        clock, _, verifier = fixture()
        verifier.new_challenge()  # round 1 exists, but the forged object is not it
        forged = Challenge(1, os.urandom(16))
        with self.assertRaises(ChallengeStateError):
            verifier.verify(forged, keyed_response(KEY, forged.nonce), clock.now)

    def test_content_equal_copy_is_rejected(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        copy = dataclasses.replace(challenge)
        self.assertEqual(copy, challenge)
        self.assertIsNot(copy, challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(copy, prover.respond(copy), clock.now)

    def test_round_index_collision_is_not_enough(self):
        clock, _, verifier = fixture()
        issued = verifier.new_challenge()
        collision = Challenge(issued.round_index, b"different-nonce!")
        with self.assertRaises(ChallengeStateError):
            verifier.verify(collision, keyed_response(KEY, collision.nonce), clock.now)

    def test_challenge_from_another_instance_rejected(self):
        clock, prover, other = fixture()
        _, _, verifier = fixture(clock=clock)
        challenge = other.new_challenge()
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_challenge_from_another_instance_even_after_same_round(self):
        clock, _, verifier = fixture()
        _, _, other = fixture(clock=clock)
        verifier.new_challenge()
        foreign = other.new_challenge()  # also round 1, fresh nonce
        with self.assertRaises(ChallengeStateError):
            verifier.verify(foreign, keyed_response(KEY, foreign.nonce), clock.now)

    def test_non_challenge_argument_still_type_error(self):
        clock, _, verifier = fixture()
        with self.assertRaises(TypeError):
            verifier.verify(b"not-a-challenge", b"x", clock.now)


class ConsumeTest(unittest.TestCase):
    def test_success_consumes_challenge(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        measurement = verifier.verify(challenge, prover.respond(challenge), clock.now)
        self.assertIsInstance(measurement, Measurement)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_wrong_response_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify(challenge, Prover(OTHER_KEY).respond(challenge), clock.now)
        # Caller corrects the response and retries the same challenge.
        measurement = verifier.verify(challenge, prover.respond(challenge), clock.now)
        self.assertIsInstance(measurement, Measurement)

    def test_forged_response_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        self.assertIsInstance(
            verifier.verify(challenge, prover.respond(challenge), clock.now), Measurement
        )

    def test_negative_elapsed_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, clock.now + 1.0)
        self.assertIsInstance(verifier.verify(challenge, response, clock.now), Measurement)

    def test_bad_response_type_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(TypeError):
            verifier.verify(challenge, "not bytes", clock.now)
        self.assertIsInstance(
            verifier.verify(challenge, prover.respond(challenge), clock.now), Measurement
        )

    def test_bad_started_at_type_does_not_consume(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        with self.assertRaises(TypeError):
            verifier.verify(challenge, response, None)
        self.assertIsInstance(verifier.verify(challenge, response, clock.now), Measurement)

    def test_bad_state_is_reported_before_response_validation(self):
        clock, _, verifier = fixture()
        # Unknown challenge and garbage response: state error wins.
        with self.assertRaises(ChallengeStateError):
            verifier.verify(Challenge(99, b"x"), None, clock.now)


class RevokeTest(unittest.TestCase):
    def test_revoked_challenge_cannot_verify(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, prover.respond(challenge), clock.now)

    def test_revoke_unknown_rejected(self):
        _, _, verifier = fixture()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(Challenge(1, os.urandom(16)))

    def test_revoke_foreign_instance_rejected(self):
        _, _, verifier = fixture()
        _, _, other = fixture()
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(other.new_challenge())

    def test_revoke_consumed_rejected(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        verifier.verify(challenge, prover.respond(challenge), clock.now)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_double_revoke_rejected(self):
        _, _, verifier = fixture()
        challenge = verifier.new_challenge()
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_revoke_type_checked(self):
        _, _, verifier = fixture()
        with self.assertRaises(TypeError):
            verifier.revoke(b"not-a-challenge")

    def test_revoke_failed_verify_then_revoke_then_dead(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)
        verifier.revoke(challenge)  # still pending, so revocation succeeds
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class MeasureProtectedTest(unittest.TestCase):
    def test_measure_uses_pending_challenge(self):
        _, prover, verifier = fixture()
        measurement = verifier.measure(prover)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.response, keyed_response(KEY, measurement.nonce))

    def test_repeated_measures_are_independent(self):
        clock, prover, verifier = fixture()
        first = verifier.measure(prover)
        clock.now += 0.001
        second = verifier.measure(prover)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertEqual((first.round_index, second.round_index), (1, 2))


class ConcurrentVerifyTest(unittest.TestCase):
    def test_at_most_one_success_under_race(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        started = clock.now
        clock.now += 1.0e-6

        successes = []
        errors = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()
            try:
                successes.append(verifier.verify(challenge, response, started))
            except ChallengeStateError as error:
                errors.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 15)
        # And the winner cannot be replayed either.
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, started)


if __name__ == "__main__":
    unittest.main()
