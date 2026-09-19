import unittest

from nearproof import (
    SPEED_OF_LIGHT_MPS,
    Challenge,
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
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


class ProverTest(unittest.TestCase):
    def test_response_is_keyed(self):
        challenge = Challenge(1, b"nonce")
        self.assertEqual(Prover(KEY).respond(challenge), keyed_response(KEY, b"nonce"))

    def test_different_keys_give_different_responses(self):
        challenge = Challenge(1, b"nonce")
        self.assertNotEqual(Prover(KEY).respond(challenge), Prover(OTHER_KEY).respond(challenge))

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            Prover(b"")

    def test_challenge_type_checked(self):
        with self.assertRaises(TypeError):
            Prover(KEY).respond(b"nonce")


class ChallengeTest(unittest.TestCase):
    def test_nonces_differ_and_rounds_increment(self):
        _, _, verifier = fixture()
        first, second = verifier.new_challenge(), verifier.new_challenge()
        self.assertEqual((first.round_index, second.round_index), (1, 2))
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertEqual(len(first.nonce), 16)

    def test_round_count_tracks_challenges(self):
        _, _, verifier = fixture()
        for _ in range(3):
            verifier.new_challenge()
        self.assertEqual(verifier.round_count, 3)


class VerifierTest(unittest.TestCase):
    def test_distance_is_half_the_round_trip(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        started = clock.now
        response = prover.respond(challenge)
        clock.now += 2.0e-6
        measurement = verifier.verify(challenge, response, started)
        self.assertAlmostEqual(measurement.elapsed_seconds, 2.0e-6)
        self.assertAlmostEqual(measurement.distance_meters, 2.0e-6 * SPEED_OF_LIGHT_MPS / 2.0)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.round_index, challenge.round_index)

    def test_wrong_key_is_rejected(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify(challenge, Prover(OTHER_KEY).respond(challenge), clock.now)

    def test_forged_response_is_rejected(self):
        clock, _, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify(challenge, b"\x00" * 32, clock.now)

    def test_negative_elapsed_is_rejected(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, 1.0)

    def test_custom_speed_scales_distance(self):
        clock, prover, verifier = fixture(speed_mps=1000.0)
        challenge = verifier.new_challenge()
        started = clock.now
        response = prover.respond(challenge)
        clock.now += 0.5
        self.assertAlmostEqual(verifier.verify(challenge, response, started).distance_meters, 250.0)

    def test_invalid_speed_rejected(self):
        with self.assertRaises(ValueError):
            Verifier(KEY, speed_mps=0)

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            Verifier(b"")


class MeasureTest(unittest.TestCase):
    def test_measure_round_trips_against_live_clock(self):
        prover, verifier = Prover(KEY), Verifier(KEY)
        measurement = verifier.measure(prover)
        self.assertGreaterEqual(measurement.elapsed_seconds, 0.0)
        self.assertGreaterEqual(measurement.distance_meters, 0.0)
        self.assertEqual(measurement.response, keyed_response(KEY, measurement.nonce))


if __name__ == "__main__":
    unittest.main()
