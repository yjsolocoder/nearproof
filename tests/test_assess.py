import dataclasses
import math
import unittest

from nearproof import (
    Evidence,
    Measurement,
    Prover,
    RangeDecision,
    Verifier,
    assess,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


def make_measurement(round_index, distance, *, elapsed=None, nonce=None):
    if nonce is None:
        nonce = bytes([round_index & 0xFF]) * 16
    if elapsed is None:
        elapsed = distance / 100.0
    return Measurement(
        round_index=round_index,
        nonce=nonce,
        response=b"r" * 32,
        elapsed_seconds=elapsed,
        distance_meters=float(distance),
    )


class AutoClock:
    """Two readings per round, ``step`` apart, giving deterministic RTTs."""

    def __init__(self, step=1e-7):
        self.readings = 0
        self.step = step

    def __call__(self):
        value = self.readings * self.step
        self.readings += 1
        return value


def make_evidence_list(count, key=KEY):
    prover = Prover(key)
    verifier = Verifier(key, clock=AutoClock(), replay_protection=True)
    records = []
    for _i in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, records


class RangeDecisionContractTest(unittest.TestCase):
    def test_is_frozen(self):
        decision = RangeDecision(5, 1.0, True)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decision.accepted = False

    def test_fields(self):
        decision = assess(
            [make_measurement(i, 10.0) for i in range(1, 6)], limit=20.0
        )
        self.assertIsInstance(decision, RangeDecision)
        self.assertEqual(decision.sample_count, 5)
        self.assertEqual(decision.upper_bound, 10.0)
        self.assertIs(decision.accepted, True)


class AssessMedianMadTest(unittest.TestCase):
    def test_inlier_interval_keeps_cluster_drops_outlier(self):
        samples = [
            make_measurement(1, 10.0),
            make_measurement(2, 10.2),
            make_measurement(3, 9.8),
            make_measurement(4, 10.1),
            make_measurement(5, 9.9),
            make_measurement(6, 1000.0),
        ]
        decision = assess(samples, limit=11.0)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.upper_bound, 10.2)
        self.assertTrue(decision.accepted)

    def test_even_count_median_uses_middle_average(self):
        # 6 samples: median of [10, 10, 10, 12, 12, 12] is 11, MAD = 1,
        # interval [8, 14] keeps every sample.
        samples = [
            make_measurement(1, 10.0),
            make_measurement(2, 10.0),
            make_measurement(3, 10.0),
            make_measurement(4, 12.0),
            make_measurement(5, 12.0),
            make_measurement(6, 12.0),
        ]
        decision = assess(samples, limit=14.0)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.upper_bound, 12.0)

    def test_mad_zero_keeps_only_equal_distances(self):
        samples = [make_measurement(i, 5.0) for i in range(1, 6)]
        samples.append(make_measurement(6, 9.0))
        decision = assess(samples, limit=5.0)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.upper_bound, 5.0)
        self.assertTrue(decision.accepted)

    def test_closed_interval_keeps_boundary_samples(self):
        # median 10, MAD 2 -> interval [4, 16]; values exactly at both
        # endpoints stay inliers.
        samples = [
            make_measurement(1, 4.0),
            make_measurement(2, 8.0),
            make_measurement(3, 10.0),
            make_measurement(4, 12.0),
            make_measurement(5, 16.0),
        ]
        decision = assess(samples, limit=16.0)
        self.assertEqual(decision.upper_bound, 16.0)
        self.assertTrue(decision.accepted)

    def test_accepted_false_when_bound_exceeds_limit(self):
        # median 10, MAD 0.2 -> interval [9.4, 10.6]: every sample is an
        # inlier but the largest distance still exceeds a 10.2 m limit.
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([9.5, 9.8, 10.0, 10.2, 10.5], start=1)
        ]
        decision = assess(samples, limit=10.2)
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.upper_bound, 10.5)
        self.assertTrue(assess(samples, limit=10.5).accepted)

    def test_order_independence(self):
        samples = [
            make_measurement(1, 10.0),
            make_measurement(2, 10.2),
            make_measurement(3, 9.8),
            make_measurement(4, 10.1),
            make_measurement(5, 9.9),
            make_measurement(6, 1000.0),
        ]
        first = assess(samples, limit=11.0)
        second = assess(list(reversed(samples)), limit=11.0)
        self.assertEqual(first, second)

    def test_too_few_inliers_raises(self):
        # median 100, MAD 100: interval [-200, 400] keeps the 100 cluster
        # but with min_samples=4 only three inliers remain.
        samples = [
            make_measurement(1, 0.0),
            make_measurement(2, 0.0),
            make_measurement(3, 100.0),
            make_measurement(4, 100.0),
            make_measurement(5, 100.0),
        ]
        with self.assertRaises(ValueError):
            assess(samples, limit=1000.0, min_samples=4)


class AssessValidationTest(unittest.TestCase):
    def setUp(self):
        self.five = [make_measurement(i, 5.0) for i in range(1, 6)]

    def test_too_few_samples(self):
        with self.assertRaises(ValueError):
            assess(self.five[:3], limit=100.0)
        with self.assertRaises(ValueError):
            assess([], limit=100.0)

    def test_custom_min_samples(self):
        samples = [make_measurement(i, 5.0) for i in range(1, 4)]
        decision = assess(samples, limit=5.0, min_samples=3)
        self.assertEqual(decision.sample_count, 3)

    def test_non_iterable_samples(self):
        for bad in (123, None, 5.0, object()):
            with self.assertRaises(ValueError, msg=bad):
                assess(bad, limit=100.0)

    def test_invalid_element_type(self):
        for bad in ("x", 123, None, object(), b"raw-bytes"):
            samples = [bad] + self.five[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess(samples, limit=100.0)

    def test_mixed_measurement_and_evidence(self):
        _verifier, records = make_evidence_list(5)
        with self.assertRaises(ValueError):
            assess(records[:3] + self.five[:2], limit=100.0, key=KEY)

    def test_duplicate_round_and_nonce(self):
        samples = [make_measurement(1, 5.0) for _ in range(5)]
        with self.assertRaises(ValueError):
            assess(samples, limit=100.0)

    def test_same_round_different_nonce_allowed(self):
        samples = [
            make_measurement(1, 5.0, nonce=bytes([i]) * 16) for i in range(5)
        ]
        decision = assess(samples, limit=5.0)
        self.assertEqual(decision.sample_count, 5)

    def test_same_nonce_different_round_allowed(self):
        shared_nonce = b"n" * 16
        samples = [make_measurement(i, 5.0, nonce=shared_nonce) for i in range(1, 6)]
        decision = assess(samples, limit=5.0)
        self.assertEqual(decision.sample_count, 5)

    def test_negative_or_non_finite_values(self):
        for field, value in (
            ("distance_meters", -0.1),
            ("distance_meters", math.nan),
            ("distance_meters", math.inf),
            ("distance_meters", -math.inf),
            ("elapsed_seconds", -1.0),
            ("elapsed_seconds", math.nan),
        ):
            samples = [make_measurement(i, 5.0) for i in range(1, 6)]
            samples[0] = dataclasses.replace(samples[0], **{field: value})
            with self.assertRaises(ValueError, msg=(field, value)):
                assess(samples, limit=100.0)

    def test_limit_validation(self):
        for bad in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "10", None):
            with self.assertRaises(ValueError, msg=bad):
                assess(self.five, bad)

    def test_zero_limit_accepted(self):
        samples = [make_measurement(i, 0.0) for i in range(1, 6)]
        decision = assess(samples, limit=0)
        self.assertTrue(decision.accepted)
        self.assertEqual(decision.upper_bound, 0.0)

    def test_integer_limit_allowed(self):
        decision = assess(self.five, limit=100)
        self.assertTrue(decision.accepted)

    def test_min_samples_validation(self):
        for bad in (0, -1, True, False, 1.0, "5", None):
            with self.assertRaises(ValueError, msg=bad):
                assess(self.five, 100.0, min_samples=bad)


class AssessEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_evidence_instances(self):
        decision = assess(self.records, limit=10.0, key=KEY)
        self.assertEqual(decision.sample_count, 6)
        # step=1e-7 s rounds measure about 15 m, so a 10 m limit fails...
        self.assertFalse(decision.accepted)
        self.assertGreater(decision.upper_bound, 10.0)
        # ...and a 20 m limit accepts; equal distances make MAD 0.
        self.assertTrue(assess(self.records, limit=20.0, key=KEY).accepted)

    def test_evidence_bytes(self):
        decision_objects = assess(self.records, limit=10.0, key=KEY)
        decision_bytes = assess(self.blobs, limit=10.0, key=KEY)
        self.assertEqual(decision_objects, decision_bytes)

    def test_mixed_objects_and_bytes(self):
        mixed = [
            self.records[0],
            self.blobs[1],
            self.records[2],
            self.blobs[3],
            self.records[4],
            self.blobs[5],
        ]
        self.assertEqual(
            assess(mixed, limit=10.0, key=KEY),
            assess(self.records, limit=10.0, key=KEY),
        )

    def test_missing_key_rejected(self):
        with self.assertRaises(ValueError):
            assess(self.records, limit=10.0)
        with self.assertRaises(ValueError):
            assess(self.blobs, limit=10.0, key=None)

    def test_empty_key_rejected(self):
        for bad in (b"", "", bytearray()):
            with self.assertRaises(ValueError):
                assess(self.records, limit=10.0, key=bad)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            assess(self.records, limit=10.0, key=OTHER_KEY)

    def test_tampered_bytes_rejected(self):
        tampered = bytearray(self.blobs[0])
        tampered[20] ^= 0xFF
        samples = self.blobs[:5] + [bytes(tampered)]
        with self.assertRaises(ValueError):
            assess(samples, limit=10.0, key=KEY)

    def test_malformed_bytes_rejected(self):
        samples = self.blobs[:5] + [b"not json"]
        with self.assertRaises(ValueError):
            assess(samples, limit=10.0, key=KEY)

    def test_duplicate_evidence_pair_rejected(self):
        with self.assertRaises(ValueError):
            assess([self.records[0]] * 5, limit=10.0, key=KEY)

    def test_validly_macced_negative_elapsed_rejected(self):
        # audit() does not by itself forbid end < start, so assess must
        # reject the resulting negative elapsed/distance independently.
        import hashlib
        import hmac
        import json as jsonlib

        base = self.records[0]
        payload = {
            "version": 1,
            "round_index": base.round_index,
            "nonce": base.nonce.hex(),
            "response": base.response.hex(),
            "start": 2.0,
            "end": 1.0,
            "speed": base.speed,
            "elapsed": -1.0,
            "distance": -base.speed / 2.0,
            "result": "accepted",
        }
        encoded = jsonlib.dumps(
            payload, separators=(",", ":"), allow_nan=False
        ).encode()
        mac = hmac.new(KEY, encoded, hashlib.sha256).digest()
        negative = dataclasses.replace(
            base,
            start=2.0,
            end=1.0,
            elapsed=-1.0,
            distance=-base.speed / 2.0,
            mac=mac,
        )
        samples = [negative] + self.records[1:5]
        with self.assertRaises(ValueError):
            assess(samples, limit=10.0, key=KEY)

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        assess(self.records, limit=10.0, key=KEY)
        assess(self.blobs, limit=10.0, key=KEY)
        self.assertEqual(self.verifier.round_count, before)
        # Issued challenges were all consumed by verify_evidence; the
        # verifier registry must not gain or lose entries from assess.
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
