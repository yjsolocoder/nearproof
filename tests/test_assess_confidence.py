import dataclasses
import math
import unittest

from nearproof import (
    Measurement,
    NoiseDecision,
    Prover,
    RangeDecision,
    Verifier,
    assess,
    assess_confidence,
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


class NoiseDecisionContractTest(unittest.TestCase):
    def test_is_frozen(self):
        decision = assess_confidence(
            [make_measurement(i, 10.0) for i in range(1, 6)], limit=20.0
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decision.accepted = False

    def test_fields_in_order(self):
        decision = assess_confidence(
            [make_measurement(i, 10.0) for i in range(1, 6)], limit=20.0
        )
        self.assertIsInstance(decision, NoiseDecision)
        self.assertEqual(
            decision,
            NoiseDecision(5, 5, 10.0, 0.0, 0.95, 10.0, 10.0, True),
        )
        self.assertEqual(decision.sample_count, 5)
        self.assertEqual(decision.inlier_count, 5)
        self.assertEqual(decision.center, 10.0)
        self.assertEqual(decision.mad, 0.0)
        self.assertEqual(decision.coverage, 0.95)
        self.assertEqual(decision.lower_bound, 10.0)
        self.assertEqual(decision.upper_bound, 10.0)
        self.assertIs(decision.accepted, True)

    def test_equality_covers_every_field(self):
        base = NoiseDecision(8, 7, 10.0, 0.2, 0.9, 9.5, 10.5, True)
        variants = (
            ("sample_count", 9),
            ("inlier_count", 6),
            ("center", 10.1),
            ("mad", 0.3),
            ("coverage", 0.95),
            ("lower_bound", 9.4),
            ("upper_bound", 10.6),
            ("accepted", False),
        )
        for name, value in variants:
            changed = dataclasses.replace(base, **{name: value})
            self.assertNotEqual(base, changed, name)
        self.assertEqual(base, NoiseDecision(8, 7, 10.0, 0.2, 0.9, 9.5, 10.5, True))

    def test_is_distinct_from_range_decision(self):
        decision = NoiseDecision(5, 5, 10.0, 0.0, 0.95, 10.0, 10.0, True)
        self.assertNotEqual(decision, RangeDecision(5, 10.0, True))


class OddInlierCountTest(unittest.TestCase):
    def test_five_inliers_ranks_one_and_five(self):
        # median 10.05, MAD 0.15 over six distances -> interval
        # [9.6, 10.5] keeps the five cluster members, drops 1000.0.
        samples = [
            make_measurement(i, d)
            for i, d in enumerate(
                [9.8, 9.9, 10.0, 10.1, 10.2, 1000.0], start=1
            )
        ]
        decision = assess_confidence(samples, limit=11.0)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.inlier_count, 5)
        # center/mad come from ALL legal distances, including the outlier.
        self.assertEqual(decision.center, 10.05)
        self.assertAlmostEqual(decision.mad, 0.15)
        # n=5, alpha=0.05: lower rank ceil(0.125)=1, upper rank ceil(4.875)=5
        self.assertEqual(decision.lower_bound, 9.8)
        self.assertEqual(decision.upper_bound, 10.2)
        self.assertTrue(decision.accepted)

    def test_seven_distinct_inliers(self):
        # distances 1..7: median 4; deviations 0,1,1,2,2,3,3 give MAD 2,
        # interval [-2, 10] keeps all seven.
        samples = [make_measurement(i, float(d))
                   for i, d in enumerate(range(1, 8), start=1)]
        decision = assess_confidence(samples, limit=8.0)
        self.assertEqual(decision.inlier_count, 7)
        self.assertEqual(decision.center, 4.0)
        self.assertEqual(decision.mad, 2.0)
        # lower rank ceil(0.175)=1, upper rank ceil(6.825)=7
        self.assertEqual(decision.lower_bound, 1.0)
        self.assertEqual(decision.upper_bound, 7.0)


class EvenInlierCountTest(unittest.TestCase):
    def test_six_distinct_inliers_half_coverage_drops_one_each_side(self):
        # distances 1..6: median 3.5, MAD 1.5, interval [-1, 8] keeps all.
        samples = [make_measurement(i, float(d))
                   for i, d in enumerate(range(1, 7), start=1)]
        # p=0.5: alpha=0.5, lower rank ceil(1.5)=2, upper rank ceil(4.5)=5
        decision = assess_confidence(samples, limit=8.0, coverage=0.5)
        self.assertEqual(decision.inlier_count, 6)
        self.assertEqual(decision.coverage, 0.5)
        self.assertEqual(decision.lower_bound, 2.0)
        self.assertEqual(decision.upper_bound, 5.0)

    def test_six_cluster_default_coverage_uses_extremes(self):
        # median 11, MAD 1 -> every sample kept; p=0.95 ranks 1 and 6.
        samples = [
            make_measurement(i, d)
            for i, d in enumerate(
                [10.0, 10.0, 10.0, 12.0, 12.0, 12.0], start=1
            )
        ]
        decision = assess_confidence(samples, limit=14.0)
        self.assertEqual(decision.inlier_count, 6)
        self.assertEqual(decision.center, 11.0)
        self.assertEqual(decision.mad, 1.0)
        self.assertEqual(decision.lower_bound, 10.0)
        self.assertEqual(decision.upper_bound, 12.0)


class MadZeroTest(unittest.TestCase):
    def test_mad_zero_bounds_equal_center(self):
        samples = [make_measurement(i, 5.0) for i in range(1, 6)]
        samples.append(make_measurement(6, 9.0))
        decision = assess_confidence(samples, limit=5.0)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.inlier_count, 5)
        self.assertEqual(decision.center, 5.0)
        self.assertEqual(decision.mad, 0.0)
        self.assertEqual(decision.lower_bound, 5.0)
        self.assertEqual(decision.upper_bound, 5.0)
        self.assertTrue(decision.accepted)

    def test_mad_zero_inlier_count_feeds_min_samples(self):
        # median 5 with three 5s among five samples: MAD is 0, so only the
        # three equal distances are inliers despite the 9/10 neighbours.
        samples = [
            make_measurement(1, 5.0),
            make_measurement(2, 5.0),
            make_measurement(3, 5.0),
            make_measurement(4, 9.0),
            make_measurement(5, 10.0),
        ]
        with self.assertRaises(ValueError):
            assess_confidence(samples, limit=9.0, min_samples=4)
        decision = assess_confidence(samples, limit=9.0, min_samples=3)
        self.assertEqual(decision.sample_count, 5)
        self.assertEqual(decision.inlier_count, 3)
        self.assertEqual(decision.lower_bound, 5.0)
        self.assertEqual(decision.upper_bound, 5.0)


class BoundaryRankTest(unittest.TestCase):
    def test_hundred_inliers_95_percent_ranks_three_and_ninety_eight(self):
        # distances 1..100 plus 10000: median 51, MAD 25, interval
        # [-24, 126] keeps 1..100 and drops the outlier.
        samples = [make_measurement(i, float(d))
                   for i, d in enumerate(range(1, 101), start=1)]
        samples.append(make_measurement(101, 10000.0))
        decision = assess_confidence(samples, limit=200.0)
        self.assertEqual(decision.sample_count, 101)
        self.assertEqual(decision.inlier_count, 100)
        # alpha=0.05: lower rank ceil(2.5)=3, upper rank ceil(97.5)=98
        self.assertEqual(decision.lower_bound, 3.0)
        self.assertEqual(decision.upper_bound, 98.0)

    def test_hundred_inliers_90_percent_ranks_five_and_ninety_five(self):
        samples = [make_measurement(i, float(d))
                   for i, d in enumerate(range(1, 101), start=1)]
        decision = assess_confidence(samples, limit=200.0, coverage=0.9)
        # alpha=0.1: lower rank ceil(5)=5, upper rank ceil(95)=95
        self.assertEqual(decision.lower_bound, 5.0)
        self.assertEqual(decision.upper_bound, 95.0)

    def test_ten_inliers_80_percent_drops_only_the_largest(self):
        # 1..10 plus 100: median 6, MAD 3, interval [-3, 15] keeps 1..10.
        # p=0.8: ranks ceil(1)=1 and ceil(9)=9.
        samples = [make_measurement(i, float(d))
                   for i, d in enumerate(range(1, 11), start=1)]
        samples.append(make_measurement(11, 100.0))
        decision = assess_confidence(samples, limit=50.0, coverage=0.8)
        self.assertEqual(decision.inlier_count, 10)
        self.assertEqual(decision.lower_bound, 1.0)
        self.assertEqual(decision.upper_bound, 9.0)

    def test_rank_clamps_at_both_ends(self):
        # n=5, sorted 1..5: ranks are max(1, ceil(alpha*n/2)) from below and
        # min(n, ceil((1-alpha/2)*n)) from above.
        samples = [make_measurement(i, float(d))
                   for i, d in enumerate([1.0, 2.0, 3.0, 4.0, 5.0], start=1)]
        # p=0.99: alpha=0.01 -> ceil(0.025)=1 and ceil(4.975)=5 (outer clamp)
        wide = assess_confidence(samples, limit=9.0, coverage=0.99)
        self.assertEqual((wide.lower_bound, wide.upper_bound), (1.0, 5.0))
        # p=0.50: alpha=0.5 -> ceil(1.25)=2 and ceil(3.75)=4
        middle = assess_confidence(samples, limit=9.0, coverage=0.5)
        self.assertEqual((middle.lower_bound, middle.upper_bound), (2.0, 4.0))
        # p=0.01: alpha=0.99 -> ceil(2.475)=3 and ceil(2.525)=3 (inner meet)
        narrow = assess_confidence(samples, limit=9.0, coverage=0.01)
        self.assertEqual((narrow.lower_bound, narrow.upper_bound), (3.0, 3.0))


class CoverageAndAcceptedTest(unittest.TestCase):
    def setUp(self):
        # six inliers 1..6
        self.samples = [make_measurement(i, float(d))
                        for i, d in enumerate(range(1, 7), start=1)]

    def test_accepted_only_when_upper_bound_at_most_limit(self):
        rejected = assess_confidence(self.samples, limit=4.9, coverage=0.5)
        self.assertEqual(rejected.upper_bound, 5.0)
        self.assertFalse(rejected.accepted)
        boundary = assess_confidence(self.samples, limit=5.0, coverage=0.5)
        self.assertTrue(boundary.accepted)

    def test_coverage_is_echoed_unrounded(self):
        decision = assess_confidence(self.samples, limit=9.0, coverage=0.123)
        self.assertEqual(decision.coverage, 0.123)

    def test_floats_not_rounded(self):
        samples = [
            make_measurement(i, d)
            for i, d in enumerate(
                [9.8, 9.9, 10.0, 10.1, 10.2, 1000.0], start=1
            )
        ]
        decision = assess_confidence(samples, limit=11.0)
        self.assertEqual(decision.mad, 0.14999999999999947)
        self.assertEqual(decision.center, 10.05)

    def test_coverage_validation(self):
        for bad in (
            0,
            1,
            -0.1,
            1.1,
            True,
            False,
            math.nan,
            math.inf,
            -math.inf,
            0.0,
            1.0,
            "0.95",
            None,
        ):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(self.samples, 9.0, coverage=bad)


class OutlierAndOrderTest(unittest.TestCase):
    def test_sample_count_includes_outliers(self):
        samples = [
            make_measurement(1, 0.0),
            make_measurement(2, 0.0),
            make_measurement(3, 100.0),
            make_measurement(4, 100.0),
            make_measurement(5, 100.0),
        ]
        # median 100 with three 100s among five: MAD 0, so only the three
        # equal 100 distances are inliers and the two 0s are outliers.
        decision = assess_confidence(samples, limit=100.0, min_samples=3)
        self.assertEqual(decision.sample_count, 5)
        self.assertEqual(decision.inlier_count, 3)
        self.assertEqual(decision.lower_bound, 100.0)
        self.assertEqual(decision.upper_bound, 100.0)
        self.assertTrue(decision.accepted)

    def test_closed_interval_keeps_boundary_samples(self):
        # median 10, MAD 2 -> interval [4, 16].
        samples = [
            make_measurement(1, 4.0),
            make_measurement(2, 8.0),
            make_measurement(3, 10.0),
            make_measurement(4, 12.0),
            make_measurement(5, 16.0),
        ]
        decision = assess_confidence(samples, limit=16.0)
        self.assertEqual(decision.inlier_count, 5)
        self.assertEqual(decision.lower_bound, 4.0)
        self.assertEqual(decision.upper_bound, 16.0)

    def test_order_independence(self):
        samples = [
            make_measurement(i, d)
            for i, d in enumerate(
                [9.8, 9.9, 10.0, 10.1, 10.2, 1000.0, 9.95], start=1
            )
        ]
        first = assess_confidence(samples, limit=11.0)
        second = assess_confidence(list(reversed(samples)), limit=11.0)
        self.assertEqual(first, second)
        third = assess_confidence(
            [samples[3], samples[0], samples[6], samples[2],
             samples[5], samples[1], samples[4]],
            limit=11.0,
        )
        self.assertEqual(first, third)

    def test_consistent_with_assess_inlier_rule(self):
        samples = [
            make_measurement(i, d)
            for i, d in enumerate(
                [10.0, 10.2, 9.8, 10.1, 9.9, 1000.0], start=1
            )
        ]
        decision = assess(samples, limit=11.0)
        confident = assess_confidence(samples, limit=11.0)
        self.assertEqual(confident.sample_count, decision.sample_count)
        # p=0.95 with five inliers reaches the largest inlier, matching
        # assess' upper bound.
        self.assertEqual(confident.inlier_count, 5)
        self.assertEqual(confident.upper_bound, decision.upper_bound)
        self.assertEqual(confident.accepted, decision.accepted)


class LargeDistanceOverflowTest(unittest.TestCase):
    """Large-but-finite distances must not overflow the median/MAD math."""

    def test_even_count_large_distances(self):
        # statistics.median would compute (1e308 + 1e308) / 2 == inf here.
        samples = [make_measurement(i, 1e308) for i in range(1, 7)]
        decision = assess_confidence(samples, limit=1e308, min_samples=5)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.inlier_count, 6)
        self.assertEqual(decision.center, 1e308)
        self.assertEqual(decision.mad, 0.0)
        self.assertEqual(decision.lower_bound, 1e308)
        self.assertEqual(decision.upper_bound, 1e308)
        self.assertTrue(decision.accepted)

    def test_even_count_large_distances_rejected_below_bound(self):
        samples = [make_measurement(i, 1e308) for i in range(1, 7)]
        decision = assess_confidence(samples, limit=9e307, min_samples=5)
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.upper_bound, 1e308)

    def test_mixed_large_distances_statistics(self):
        samples = [make_measurement(i, 1e308) for i in (1, 2, 3)]
        samples += [make_measurement(i, 1.2e308) for i in (4, 5, 6)]
        decision = assess_confidence(samples, limit=1.2e308)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.inlier_count, 6)
        self.assertTrue(math.isclose(decision.center, 1.1e308, rel_tol=1e-12))
        self.assertTrue(math.isclose(decision.mad, 1e307, rel_tol=1e-9))
        # Default coverage 0.95 over six inliers brackets the extremes.
        self.assertEqual(decision.lower_bound, 1e308)
        self.assertEqual(decision.upper_bound, 1.2e308)
        self.assertTrue(decision.accepted)
        for value in (
            decision.center,
            decision.mad,
            decision.lower_bound,
            decision.upper_bound,
        ):
            self.assertTrue(math.isfinite(value), msg=value)

    def test_large_distances_order_and_iterator_consistency(self):
        distances = [1e308, 1e308, 1e308, 1.2e308, 1.2e308, 1.2e308]
        samples = [make_measurement(i + 1, d) for i, d in enumerate(distances)]
        expected = assess_confidence(samples, limit=1.2e308)
        self.assertEqual(
            assess_confidence(list(reversed(samples)), limit=1.2e308), expected
        )
        self.assertEqual(assess_confidence(iter(samples), limit=1.2e308), expected)

    def test_large_distances_inputs_untouched(self):
        samples = [make_measurement(i, 1e308) for i in range(1, 7)]
        snapshot = list(samples)
        assess_confidence(samples, limit=1e308)
        self.assertEqual(samples, snapshot)


class AssessConfidenceValidationTest(unittest.TestCase):
    def setUp(self):
        self.five = [make_measurement(i, 5.0) for i in range(1, 6)]

    def test_too_few_samples(self):
        with self.assertRaises(ValueError):
            assess_confidence(self.five[:3], limit=100.0)

    def test_too_few_inliers(self):
        # [0, 0, 100, 100, 100]: median 100, MAD 0 -> only the three 100s
        # survive, fewer than min_samples=4.
        samples = [
            make_measurement(1, 0.0),
            make_measurement(2, 0.0),
            make_measurement(3, 100.0),
            make_measurement(4, 100.0),
            make_measurement(5, 100.0),
        ]
        with self.assertRaises(ValueError):
            assess_confidence(samples, limit=1000.0, min_samples=4)

    def test_non_iterable_samples(self):
        for bad in (123, None, 5.0, object()):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(bad, limit=100.0)

    def test_invalid_element_type(self):
        for bad in ("x", 123, None, object(), b"raw-bytes"):
            samples = [bad] + self.five[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(samples, limit=100.0)

    def test_mixed_measurement_and_evidence(self):
        _verifier, records = make_evidence_list(5)
        with self.assertRaises(ValueError):
            assess_confidence(
                records[:3] + self.five[:2], limit=100.0, key=KEY
            )

    def test_duplicate_round_and_nonce(self):
        samples = [make_measurement(1, 5.0) for _ in range(5)]
        with self.assertRaises(ValueError):
            assess_confidence(samples, limit=100.0)

    def test_negative_or_non_finite_values(self):
        for field, value in (
            ("distance_meters", -0.1),
            ("distance_meters", math.nan),
            ("distance_meters", math.inf),
            ("elapsed_seconds", -1.0),
        ):
            samples = [make_measurement(i, 5.0) for i in range(1, 6)]
            samples[0] = dataclasses.replace(samples[0], **{field: value})
            with self.assertRaises(ValueError, msg=(field, value)):
                assess_confidence(samples, limit=100.0)

    def test_limit_validation_matches_assess(self):
        for bad in (True, False, -0.1, math.nan, math.inf, "10", None):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(self.five, bad)

    def test_min_samples_validation_matches_assess(self):
        for bad in (0, -1, True, False, 1.0, "5", None):
            with self.assertRaises(ValueError, msg=bad):
                assess_confidence(self.five, 100.0, min_samples=bad)


class AssessConfidenceEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_evidence_instances_bytes_and_mixed_agree(self):
        objects = assess_confidence(self.records, limit=10.0, key=KEY)
        as_bytes = assess_confidence(self.blobs, limit=10.0, key=KEY)
        mixed = [
            self.records[0],
            self.blobs[1],
            self.records[2],
            self.blobs[3],
            self.records[4],
            self.blobs[5],
        ]
        mixed_decision = assess_confidence(mixed, limit=10.0, key=KEY)
        self.assertIsInstance(objects, NoiseDecision)
        self.assertEqual(objects, as_bytes)
        self.assertEqual(objects, mixed_decision)
        self.assertEqual(objects.sample_count, 6)
        # The six printed distances are equal but one differs by a single
        # ulp, so with MAD 0 the exact-equality rule keeps five inliers; the
        # surviving bounds all coincide at the measured distance.
        self.assertEqual(objects.inlier_count, 5)
        self.assertEqual(objects.mad, 0.0)
        self.assertEqual(objects.center, objects.lower_bound)
        self.assertEqual(objects.lower_bound, objects.upper_bound)

    def test_evidence_agrees_with_assess(self):
        confident = assess_confidence(self.records, limit=20.0, key=KEY)
        decision = assess(self.records, limit=20.0, key=KEY)
        self.assertEqual(confident.sample_count, decision.sample_count)
        self.assertEqual(confident.upper_bound, decision.upper_bound)
        self.assertEqual(confident.accepted, decision.accepted)

    def test_missing_key_rejected(self):
        with self.assertRaises(ValueError):
            assess_confidence(self.records, limit=10.0)
        with self.assertRaises(ValueError):
            assess_confidence(self.blobs, limit=10.0, key=None)

    def test_empty_key_rejected(self):
        for bad in (b"", "", bytearray()):
            with self.assertRaises(ValueError):
                assess_confidence(self.records, limit=10.0, key=bad)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            assess_confidence(self.records, limit=10.0, key=OTHER_KEY)

    def test_tampered_or_malformed_bytes_rejected(self):
        tampered = bytearray(self.blobs[0])
        tampered[20] ^= 0xFF
        with self.assertRaises(ValueError):
            assess_confidence(
                self.blobs[:5] + [bytes(tampered)], limit=10.0, key=KEY
            )
        with self.assertRaises(ValueError):
            assess_confidence(
                self.blobs[:5] + [b"not json"], limit=10.0, key=KEY
            )

    def test_duplicate_evidence_pair_rejected(self):
        with self.assertRaises(ValueError):
            assess_confidence(
                [self.records[0]] * 5, limit=10.0, key=KEY
            )

    def test_order_independence_with_evidence(self):
        first = assess_confidence(self.records, limit=10.0, key=KEY)
        second = assess_confidence(
            list(reversed(self.records)), limit=10.0, key=KEY
        )
        self.assertEqual(first, second)

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        assess_confidence(self.records, limit=10.0, key=KEY)
        assess_confidence(self.blobs, limit=10.0, key=KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
