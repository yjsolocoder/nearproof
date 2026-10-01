import dataclasses
import math
import unittest

from nearproof import (
    NoiseDecision,
    assess,
    assess_confidence,
)

from test_assess import KEY, OTHER_KEY, make_evidence_list, make_measurement


class NoiseDecisionContractTest(unittest.TestCase):
    def test_is_frozen(self):
        decision = NoiseDecision(5, 5, 5.0, 0.0, 0.95, 5.0, 5.0, True)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decision.accepted = False

    def test_equality_covers_every_field(self):
        values = (6, 5, 10.05, 0.15, 0.95, 9.8, 10.2, True)
        decision = NoiseDecision(*values)
        self.assertEqual(decision, NoiseDecision(*values))
        self.assertEqual(hash(decision), hash(NoiseDecision(*values)))
        bumped = (7, 6, 11.05, 1.15, 0.99, 10.8, 11.2, False)
        for index, changed_value in enumerate(bumped):
            changed = list(values)
            changed[index] = changed_value
            self.assertNotEqual(decision, NoiseDecision(*changed), index)
        self.assertNotEqual(decision, NoiseDecision(*bumped))

    def test_field_order(self):
        samples = [
            make_measurement(1, 10.0),
            make_measurement(2, 10.2),
            make_measurement(3, 9.8),
            make_measurement(4, 10.1),
            make_measurement(5, 9.9),
            make_measurement(6, 1000.0),
        ]
        decision = assess_confidence(samples, limit=11.0)
        self.assertIsInstance(decision, NoiseDecision)
        self.assertEqual(
            [field.name for field in dataclasses.fields(NoiseDecision)],
            [
                "sample_count",
                "inlier_count",
                "center",
                "mad",
                "coverage",
                "lower_bound",
                "upper_bound",
                "accepted",
            ],
        )
        # center and mad come from ALL six valid distances, inlier_count
        # from the five clustered ones.
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.inlier_count, 5)
        self.assertEqual(decision.center, 10.05)
        self.assertAlmostEqual(decision.mad, 0.15)
        self.assertEqual(decision.coverage, 0.95)
        self.assertEqual(decision.lower_bound, 9.8)
        self.assertEqual(decision.upper_bound, 10.2)
        self.assertIs(decision.accepted, True)


class AssessConfidenceIntervalTest(unittest.TestCase):
    def test_odd_inlier_ranks_default_coverage(self):
        # n = 5, p = 0.95, alpha = 0.05:
        # lower rank = max(1, ceil(0.125)) = 1
        # upper rank = min(5, ceil(4.9375)) = 5
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([9.5, 9.8, 10.0, 10.2, 10.5], start=1)
        ]
        decision = assess_confidence(samples, limit=20.0)
        self.assertEqual(decision.inlier_count, 5)
        self.assertEqual(decision.lower_bound, 9.5)
        self.assertEqual(decision.upper_bound, 10.5)

    def test_even_inlier_ranks(self):
        # n = 6, p = 0.95, alpha = 0.05:
        # lower rank = max(1, ceil(0.15)) = 1
        # upper rank = min(6, ceil(5.925)) = 6
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([9.5, 9.8, 10.0, 10.1, 10.2, 10.5], start=1)
        ]
        decision = assess_confidence(samples, limit=20.0)
        self.assertEqual(decision.inlier_count, 6)
        self.assertEqual(decision.lower_bound, 9.5)
        self.assertEqual(decision.upper_bound, 10.5)

    def test_boundary_rank_odd_n_half_coverage(self):
        # n = 5, p = 0.5, alpha = 0.5:
        # lower rank = max(1, ceil(1.25)) = 2
        # upper rank = min(5, ceil(3.75)) = 4
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([1.0, 2.0, 3.0, 4.0, 5.0], start=1)
        ]
        decision = assess_confidence(samples, limit=20.0, coverage=0.5)
        self.assertEqual(decision.lower_bound, 2.0)
        self.assertEqual(decision.upper_bound, 4.0)

    def test_boundary_rank_even_n_half_coverage(self):
        # n = 6, p = 0.5, alpha = 0.5:
        # lower rank = max(1, ceil(1.5)) = 2
        # upper rank = min(6, ceil(4.5)) = 5
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([1.0, 2.0, 3.0, 4.0, 5.0, 6.0], start=1)
        ]
        decision = assess_confidence(samples, limit=20.0, coverage=0.5)
        self.assertEqual(decision.lower_bound, 2.0)
        self.assertEqual(decision.upper_bound, 5.0)

    def test_near_zero_coverage_gives_median_ranks(self):
        # n = 5, p = 0.01, alpha = 0.99:
        # lower rank = max(1, ceil(2.475)) = 3
        # upper rank = min(5, ceil(2.525)) = 3
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([1.0, 2.0, 3.0, 4.0, 5.0], start=1)
        ]
        decision = assess_confidence(samples, limit=20.0, coverage=0.01)
        self.assertEqual(decision.coverage, 0.01)
        self.assertEqual(decision.lower_bound, 3.0)
        self.assertEqual(decision.upper_bound, 3.0)

    def test_high_coverage_clamps_to_extremes(self):
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([1.0, 2.0, 3.0, 4.0, 5.0], start=1)
        ]
        for level in (0.8, 0.999):
            decision = assess_confidence(samples, limit=20.0, coverage=level)
            self.assertEqual(decision.lower_bound, 1.0)
            self.assertEqual(decision.upper_bound, 5.0)

    def test_mad_zero_keeps_only_equals_and_collapses_interval(self):
        samples = [make_measurement(i, 5.0) for i in range(1, 6)]
        samples.append(make_measurement(6, 9.0))
        decision = assess_confidence(samples, limit=5.0)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.inlier_count, 5)
        self.assertEqual(decision.center, 5.0)
        self.assertEqual(decision.mad, 0.0)
        self.assertEqual(decision.lower_bound, 5.0)
        self.assertEqual(decision.upper_bound, 5.0)
        self.assertIs(decision.accepted, True)

    def test_outliers_counted_in_sample_count_but_not_bounds(self):
        samples = [
            make_measurement(1, 10.0),
            make_measurement(2, 10.2),
            make_measurement(3, 9.8),
            make_measurement(4, 10.1),
            make_measurement(5, 9.9),
            make_measurement(6, 1000.0),
        ]
        accepted = assess_confidence(samples, limit=10.2)
        self.assertEqual(accepted.sample_count, 6)
        self.assertEqual(accepted.inlier_count, 5)
        self.assertEqual(accepted.upper_bound, 10.2)
        self.assertIs(accepted.accepted, True)
        rejected = assess_confidence(samples, limit=10.1)
        self.assertEqual(rejected.upper_bound, 10.2)
        self.assertIs(rejected.accepted, False)

    def test_agrees_with_assess_upper_bound_and_acceptance(self):
        samples = [
            make_measurement(1, 4.0),
            make_measurement(2, 8.0),
            make_measurement(3, 10.0),
            make_measurement(4, 12.0),
            make_measurement(5, 16.0),
        ]
        plain = assess(samples, limit=16.0)
        decision = assess_confidence(samples, limit=16.0)
        self.assertEqual(decision.sample_count, plain.sample_count)
        self.assertEqual(decision.inlier_count, plain.sample_count)
        self.assertEqual(decision.upper_bound, plain.upper_bound)
        self.assertIs(decision.accepted, plain.accepted)
        self.assertIs(decision.accepted, True)

    def test_order_independence(self):
        samples = [
            make_measurement(1, 10.0),
            make_measurement(2, 10.2),
            make_measurement(3, 9.8),
            make_measurement(4, 10.1),
            make_measurement(5, 9.9),
            make_measurement(6, 1000.0),
        ]
        first = assess_confidence(samples, limit=11.0)
        second = assess_confidence(list(reversed(samples)), limit=11.0)
        self.assertEqual(first, second)

    def test_values_not_rounded(self):
        samples = [
            make_measurement(i, d)
            for i, d in enumerate([1 / 3, 2 / 3, 1.0, 4 / 3, 5 / 3], start=1)
        ]
        decision = assess_confidence(samples, limit=10.0, coverage=0.5)
        self.assertEqual(decision.lower_bound, 2 / 3)
        self.assertEqual(decision.upper_bound, 4 / 3)


class AssessConfidenceValidationTest(unittest.TestCase):
    def setUp(self):
        self.five = [make_measurement(i, 5.0) for i in range(1, 6)]

    def test_too_few_samples(self):
        with self.assertRaises(ValueError):
            assess_confidence(self.five[:3], limit=100.0)

    def test_too_few_inliers(self):
        samples = [
            make_measurement(1, 0.0),
            make_measurement(2, 0.0),
            make_measurement(3, 100.0),
            make_measurement(4, 100.0),
            make_measurement(5, 100.0),
        ]
        with self.assertRaises(ValueError):
            assess_confidence(samples, limit=1000.0, min_samples=4)

    def test_coverage_validation(self):
        for bad in (
            0,
            1,
            0,
            1.0,
            0.0,
            -0.1,
            1.1,
            True,
            False,
            math.nan,
            math.inf,
            -math.inf,
            "0.95",
            None,
        ):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(self.five, limit=100.0, coverage=bad)

    def test_integer_limits_and_min_samples_contract(self):
        decision = assess_confidence(self.five, limit=100, min_samples=5)
        self.assertTrue(decision.accepted)
        for bad in (0, -1, True, False, 1.0, "5"):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(self.five, 100.0, min_samples=bad)
        for bad in (True, False, -0.1, math.nan, math.inf):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(self.five, bad)

    def test_mixed_and_bad_samples_rejected(self):
        _verifier, records = make_evidence_list(5)
        with self.assertRaises(ValueError):
            assess_confidence(records[:3] + self.five[:2], limit=100.0, key=KEY)
        with self.assertRaises(ValueError):
            assess_confidence([1, 2, 3], limit=100.0)
        samples = [make_measurement(1, 5.0) for _ in range(5)]
        with self.assertRaises(ValueError):
            assess_confidence(samples, limit=100.0)


class AssessConfidenceEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_evidence_objects_bytes_and_mixed_agree(self):
        objects = assess_confidence(self.records, limit=100.0, key=KEY)
        as_bytes = assess_confidence(self.blobs, limit=100.0, key=KEY)
        mixed = assess_confidence(
            [
                self.records[0],
                self.blobs[1],
                self.records[2],
                self.blobs[3],
                self.records[4],
                self.blobs[5],
            ],
            limit=100.0,
            key=KEY,
        )
        self.assertEqual(objects, as_bytes)
        self.assertEqual(objects, mixed)
        plain = assess(self.records, limit=100.0, key=KEY)
        self.assertEqual(objects.sample_count, plain.sample_count)
        self.assertEqual(objects.upper_bound, plain.upper_bound)
        self.assertIs(objects.accepted, plain.accepted)

    def test_missing_or_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            assess_confidence(self.records, limit=100.0)
        with self.assertRaises(ValueError):
            assess_confidence(self.blobs, limit=100.0, key=None)
        for bad in (b"", "", bytearray()):
            with self.assertRaises(ValueError):
                assess_confidence(self.records, limit=100.0, key=bad)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            assess_confidence(self.records, limit=100.0, key=OTHER_KEY)

    def test_bad_evidence_rejected(self):
        tampered = bytearray(self.blobs[0])
        tampered[20] ^= 0xFF
        with self.assertRaises(ValueError):
            assess_confidence(
                self.blobs[:5] + [bytes(tampered)], limit=100.0, key=KEY
            )
        with self.assertRaises(ValueError):
            assess_confidence(
                self.blobs[:5] + [b"not json"], limit=100.0, key=KEY
            )

    def test_duplicate_evidence_rejected(self):
        with self.assertRaises(ValueError):
            assess_confidence([self.records[0]] * 5, limit=100.0, key=KEY)

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        assess_confidence(self.records, limit=100.0, key=KEY)
        assess_confidence(self.blobs, limit=100.0, key=KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
