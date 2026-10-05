import dataclasses
import itertools
import math
import unittest

from nearproof import (
    ConsensusPolicy,
    Observation,
    RangeDecision,
    WeightedConsensus,
    reconcile_region,
)


def decision(upper_bound, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True, sample_count=1):
    return Observation(
        id=ident,
        x=x,
        y=y,
        decision=decision(upper_bound, accepted=accepted, sample_count=sample_count),
    )


def policy(weights, threshold=1):
    return ConsensusPolicy(weights, threshold)


# Three disks sharing a common region (the third contains the lens of the
# first two), weighted 1, 2, 3.
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
    obs("c", 3.0, 0.0, 10.0),
]
LENS_WEIGHTS = {"a": 1, "b": 2, "c": 3}

# Every pair overlaps but no point lies in all three disks.
TRIPLE = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 1.8, 0.0, 1.0),
    obs("c", 0.9, 1.6, 1.0),
]


class ReconcileContractTest(unittest.TestCase):
    def test_weighted_consensus_is_frozen(self):
        result = reconcile_region(LENS, policy(LENS_WEIGHTS))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.accepted = False

    def test_fields(self):
        result = reconcile_region(LENS, policy(LENS_WEIGHTS, 4))
        self.assertIsInstance(result, WeightedConsensus)
        self.assertEqual(result.total_weight, 6)
        self.assertEqual(result.support_weight, 6)
        self.assertIsInstance(result.rejected, tuple)
        self.assertEqual(result.rejected, ())
        self.assertIs(result.accepted, True)

    def test_field_equality(self):
        self.assertEqual(
            reconcile_region(LENS, policy(LENS_WEIGHTS, 4)),
            WeightedConsensus(
                total_weight=6, support_weight=6, rejected=(), accepted=True
            ),
        )
        self.assertNotEqual(
            reconcile_region(LENS, policy(LENS_WEIGHTS, 4)),
            WeightedConsensus(
                total_weight=6, support_weight=5, rejected=("a",), accepted=True
            ),
        )

    def test_rejected_ids_are_strings(self):
        result = reconcile_region(TRIPLE, policy({"a": 1, "b": 1, "c": 1}))
        for ident in result.rejected:
            self.assertIsInstance(ident, str)

    def test_result_is_repeatable(self):
        first = reconcile_region(TRIPLE, policy({"a": 1, "b": 1, "c": 1}))
        second = reconcile_region(TRIPLE, policy({"a": 1, "b": 1, "c": 1}))
        self.assertEqual(first, second)


class ReconcileGeometryTest(unittest.TestCase):
    def test_common_point_rejects_nobody(self):
        result = reconcile_region(LENS, policy(LENS_WEIGHTS, 6))
        self.assertEqual(
            result,
            WeightedConsensus(
                total_weight=6, support_weight=6, rejected=(), accepted=True
            ),
        )

    def test_disjoint_pair_keeps_heavier_disk(self):
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 5.0, 0.0, 1.0)]
        result = reconcile_region(observations, policy({"a": 1, "b": 2}))
        self.assertEqual(result.total_weight, 3)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("a",))

    def test_equal_weight_tie_keeps_lexicographically_later_disk(self):
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 5.0, 0.0, 1.0)]
        result = reconcile_region(observations, policy({"a": 1, "b": 1}))
        # Keeping either disk reaches weight 1; ("a",) < ("b",) as tuples,
        # so b is kept and a is rejected.
        self.assertEqual(result.support_weight, 1)
        self.assertEqual(result.rejected, ("a",))

    def test_tie_break_does_not_prefer_fewer_exclusions(self):
        # a and c overlap, b is far away; keeping {a, c} or keeping {b}
        # both reach weight 2. ("a", "c") < ("b",) as tuples, so the
        # two-exclusion solution wins over the one-exclusion solution.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 100.0, 0.0, 1.0),
            obs("c", 0.5, 0.0, 1.0),
        ]
        result = reconcile_region(observations, policy({"a": 1, "b": 2, "c": 1}))
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("a", "c"))

    def test_pairwise_overlap_without_common_point_drops_lightest(self):
        result = reconcile_region(TRIPLE, policy({"a": 1, "b": 1, "c": 1}))
        # Any two disks share a point (weight 2); the rejected tuples are
        # ("a",), ("b",) and ("c",), and ("a",) compares smallest.
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("a",))

    def test_weight_beats_cardinality(self):
        # The heavy disk a pairs with either light disk; the all-light
        # pair {b, c} reaches only weight 2 and loses despite the
        # lexicographically smaller rejected tuple ("a",).
        result = reconcile_region(TRIPLE, policy({"a": 5, "b": 1, "c": 1}))
        self.assertEqual(result.support_weight, 6)
        self.assertEqual(result.rejected, ("b",))

    def test_tangent_disks_are_kept_together(self):
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 6.0, 0.0, 3.0),
            obs("c", 3.0, 5.0, 5.0),
        ]
        # a and b touch at (3, 0), which lies exactly on c's boundary.
        result = reconcile_region(observations, policy({"a": 1, "b": 1, "c": 1}, 3))
        self.assertEqual(result.rejected, ())
        self.assertEqual(result.support_weight, 3)

    def test_shared_boundary_point_with_zero_radius_disk(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 3.0, 4.0, 0.0),
        ]
        # a and b meet at (3, ±4); c is the zero-radius disk at (3, 4).
        result = reconcile_region(observations, policy({"a": 1, "b": 1, "c": 1}, 3))
        self.assertEqual(result.rejected, ())

    def test_zero_radius_disks_at_same_point_are_kept_together(self):
        observations = [obs("a", 1.0, 1.0, 0.0), obs("b", 1.0, 1.0, 0.0)]
        result = reconcile_region(observations, policy({"a": 1, "b": 1}, 2))
        self.assertEqual(result.rejected, ())
        self.assertEqual(result.support_weight, 2)

    def test_zero_radius_disks_at_distinct_points_conflict(self):
        observations = [obs("a", 0.0, 0.0, 0.0), obs("b", 1.0, 0.0, 0.0)]
        result = reconcile_region(observations, policy({"a": 1, "b": 1}))
        self.assertEqual(result.rejected, ("a",))

    def test_coincident_disks_are_kept_together(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 0.0, 0.0, 5.0),
            obs("c", 6.0, 0.0, 5.0),
        ]
        result = reconcile_region(observations, policy({"a": 1, "b": 1, "c": 1}, 3))
        self.assertEqual(result.rejected, ())

    def test_contained_disk_is_kept(self):
        observations = [
            obs("a", 0.0, 0.0, 10.0),
            obs("b", 1.0, 1.0, 1.0),
            obs("c", -1.0, -1.0, 2.0),
        ]
        result = reconcile_region(observations, policy({"a": 1, "b": 2, "c": 3}, 6))
        self.assertEqual(result.rejected, ())

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0, accepted=False),
            obs("b", 6.0, 0.0, 5.0, accepted=False),
            obs("c", 3.0, 0.0, 10.0, accepted=False),
        ]
        result = reconcile_region(observations, policy(LENS_WEIGHTS, 6))
        self.assertEqual(result.rejected, ())
        self.assertIs(result.accepted, True)

    def test_sample_count_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0, sample_count=1),
            obs("b", 6.0, 0.0, 5.0, sample_count=7),
            obs("c", 3.0, 0.0, 10.0, sample_count=1000),
        ]
        self.assertEqual(
            reconcile_region(observations, policy(LENS_WEIGHTS, 6)),
            reconcile_region(LENS, policy(LENS_WEIGHTS, 6)),
        )

    def test_tolerance_extends_every_radius(self):
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 3.0, 0.0, 1.0)]
        self.assertEqual(
            reconcile_region(observations, policy({"a": 1, "b": 1})).rejected,
            ("a",),
        )
        # Radii become 1.5 and 1.5: the disks touch at (1.5, 0).
        result = reconcile_region(
            observations, policy({"a": 1, "b": 1}, 2), tolerance=0.5
        )
        self.assertEqual(result.rejected, ())
        self.assertIs(result.accepted, True)

    def test_no_extra_slack_beyond_tolerance(self):
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 3.0, 0.0, 1.0)]
        # A real gap of 2e-12 remains: it must not be smoothed over.
        result = reconcile_region(
            observations, policy({"a": 1, "b": 1}), tolerance=0.499999999999
        )
        self.assertEqual(result.rejected, ("a",))

    def test_huge_scale_not_misjudged_by_overflow(self):
        # The squared distance and squared radius sum both overflow to
        # inf in plain float arithmetic; the true relation decides.
        reaching = [
            obs("a", 0.0, 0.0, 6e307),
            obs("b", 1e308, 0.0, 6e307),
        ]
        result = reconcile_region(reaching, policy({"a": 1, "b": 1}, 2))
        self.assertEqual(result.rejected, ())
        far_apart = [
            obs("a", 0.0, 0.0, 4e307),
            obs("b", 1e308, 0.0, 4e307),
        ]
        result = reconcile_region(far_apart, policy({"a": 1, "b": 1}))
        self.assertEqual(result.rejected, ("a",))

    def test_tiny_scale_not_misjudged_by_underflow(self):
        # The squared distance and squared radius sum both underflow to
        # 0.0 in plain float arithmetic; the true relation decides.
        touching = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 2e-300, 0.0, 1e-300),
        ]
        result = reconcile_region(touching, policy({"a": 1, "b": 1}, 2))
        self.assertEqual(result.rejected, ())
        far_apart = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 3e-300, 0.0, 1e-300),
        ]
        result = reconcile_region(far_apart, policy({"a": 1, "b": 1}))
        self.assertEqual(result.rejected, ("a",))

    def test_integer_inputs_match_float_inputs(self):
        integers = [
            obs("a", 0, 0, 1),
            obs("b", 1.8, 0, 1),
            obs("c", 0.9, 1.6, 1),
        ]
        weights = {"a": 1, "b": 1, "c": 1}
        self.assertEqual(
            reconcile_region(integers, policy(weights)),
            reconcile_region(TRIPLE, policy(weights)),
        )
        self.assertEqual(
            reconcile_region(integers, policy(weights), tolerance=1),
            reconcile_region(TRIPLE, policy(weights), tolerance=1.0),
        )


class ReconcileThresholdTest(unittest.TestCase):
    def test_threshold_does_not_change_the_optimal_set(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 100.0, 0.0, 1.0),
            obs("c", 0.5, 0.0, 1.0),
        ]
        weights = {"a": 1, "b": 2, "c": 1}
        low = reconcile_region(observations, policy(weights, 1))
        high = reconcile_region(observations, policy(weights, 4))
        self.assertEqual(low.rejected, high.rejected)
        self.assertEqual(low.support_weight, high.support_weight)
        self.assertEqual(low.total_weight, high.total_weight)

    def test_accepted_only_reflects_threshold(self):
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 5.0, 0.0, 1.0)]
        weights = {"a": 1, "b": 2}
        accepted = reconcile_region(observations, policy(weights, 2))
        self.assertIs(accepted.accepted, True)
        self.assertEqual(accepted.support_weight, 2)
        rejected = reconcile_region(observations, policy(weights, 3))
        self.assertIs(rejected.accepted, False)
        self.assertEqual(rejected.support_weight, 2)
        self.assertEqual(rejected.rejected, ("a",))

    def test_unreachable_threshold_still_returns_optimal_set(self):
        result = reconcile_region(TRIPLE, policy({"a": 1, "b": 1, "c": 1}, 3))
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("a",))
        self.assertIs(result.accepted, False)

    def test_full_weight_threshold_passes_when_all_disks_meet(self):
        result = reconcile_region(LENS, policy(LENS_WEIGHTS, 6))
        self.assertIs(result.accepted, True)


class ReconcileOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        base = TRIPLE + [obs("d", 1.2, 1.5, 1.0), obs("e", 0.9, -1.6, 1.0)]
        weights = {"a": 3, "b": 1, "c": 2, "d": 1, "e": 2}
        expected = reconcile_region(base, policy(weights, 4))
        for permuted in itertools.permutations(base):
            self.assertEqual(reconcile_region(list(permuted), policy(weights, 4)), expected)

    def test_weight_mapping_order_is_irrelevant(self):
        forward = reconcile_region(LENS, policy({"a": 1, "b": 2, "c": 3}, 4))
        reversed_weights = dict(reversed(list(LENS_WEIGHTS.items())))
        backward = reconcile_region(LENS, policy(reversed_weights, 4))
        self.assertEqual(forward, backward)

    def test_generator_input(self):
        result = reconcile_region(iter(LENS), policy(LENS_WEIGHTS, 4))
        self.assertEqual(result, reconcile_region(LENS, policy(LENS_WEIGHTS, 4)))

    def test_inputs_not_mutated(self):
        observations = list(LENS)
        snapshot = list(observations)
        weights = dict(LENS_WEIGHTS)
        consensus_policy = policy(weights, 4)
        reconcile_region(observations, consensus_policy)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])
        self.assertEqual(dict(consensus_policy.weights), weights)


class ReconcileValidationTest(unittest.TestCase):
    def test_empty_observations(self):
        with self.assertRaises(ValueError):
            reconcile_region([], policy({"a": 1}))
        with self.assertRaises(ValueError):
            reconcile_region(iter([]), policy({"a": 1}))

    def test_single_observation(self):
        result = reconcile_region([obs("a", 0.0, 0.0, 1.0)], policy({"a": 3}, 3))
        self.assertEqual(
            result,
            WeightedConsensus(
                total_weight=3, support_weight=3, rejected=(), accepted=True
            ),
        )

    def test_two_observations(self):
        pair = [obs("a", 0.0, 0.0, 1.0), obs("b", 1.0, 0.0, 1.0)]
        result = reconcile_region(pair, policy({"a": 1, "b": 1}, 2))
        self.assertEqual(result.rejected, ())
        far = [obs("a", 0.0, 0.0, 1.0), obs("b", 5.0, 0.0, 1.0)]
        result = reconcile_region(far, policy({"a": 1, "b": 1}))
        self.assertEqual(result.rejected, ("a",))

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                reconcile_region(bad, policy({"a": 1}))

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + LENS[1:]
            with self.assertRaises(ValueError, msg=bad):
                reconcile_region(observations, policy(LENS_WEIGHTS))

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
        ]
        with self.assertRaises(ValueError):
            reconcile_region(observations, policy({"a": 1}))

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(LENS[0], id=bad)
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=bad):
                reconcile_region(observations, policy(LENS_WEIGHTS))

    def test_invalid_coordinates(self):
        for field, value in (
            ("x", True),
            ("x", False),
            ("x", math.nan),
            ("x", math.inf),
            ("x", -math.inf),
            ("x", "1"),
            ("x", None),
            ("y", True),
            ("y", math.nan),
            ("y", math.inf),
        ):
            bad_obs = dataclasses.replace(LENS[0], **{field: value})
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=(field, value)):
                reconcile_region(observations, policy(LENS_WEIGHTS))

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(LENS[0], decision=decision(value))
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=value):
                reconcile_region(observations, policy(LENS_WEIGHTS))

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(LENS[0], decision=object())
        observations = [bad_obs] + LENS[1:]
        with self.assertRaises(ValueError):
            reconcile_region(observations, policy(LENS_WEIGHTS))

    def test_invalid_tolerance(self):
        for bad in (
            True,
            False,
            -0.1,
            -1,
            math.nan,
            math.inf,
            -math.inf,
            "0.5",
            None,
        ):
            with self.assertRaises(ValueError, msg=bad):
                reconcile_region(LENS, policy(LENS_WEIGHTS), tolerance=bad)

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            reconcile_region(LENS, policy(LENS_WEIGHTS)),
            reconcile_region(LENS, policy(LENS_WEIGHTS), tolerance=0.0),
        )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            reconcile_region(LENS, policy(LENS_WEIGHTS), 0.5)

    def test_policy_wrong_type(self):
        for bad in (None, 123, "p", {"a": 1, "b": 2, "c": 3}, object()):
            with self.assertRaises(ValueError, msg=bad):
                reconcile_region(LENS, bad)

    def test_weight_ids_must_match_observation_ids(self):
        for weights in (
            {"a": 1, "b": 2},
            {"a": 1, "b": 2, "c": 3, "d": 4},
            {"a": 1, "b": 2, "x": 3},
        ):
            with self.assertRaises(ValueError, msg=weights):
                reconcile_region(LENS, policy(weights))

    def test_invalid_trailing_element_rejected_despite_early_conflict(self):
        # The first two disks already conflict, but the invalid trailing
        # observation must still be rejected rather than ignored.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 5.0, 0.0, 1.0),
            obs("c", 0.0, 0.0, -1.0),
        ]
        with self.assertRaises(ValueError):
            reconcile_region(observations, policy({"a": 1, "b": 1, "c": 1}))


if __name__ == "__main__":
    unittest.main()
