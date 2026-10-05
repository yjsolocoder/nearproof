import dataclasses
import itertools
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
        decision=decision(
            upper_bound, accepted=accepted, sample_count=sample_count
        ),
    )


# Two disjoint unit disks at the origin and at (4, 0).
DISJOINT = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 4.0, 0.0, 1.0),
]

# Two overlapping radius-5 disks plus a third disk that contains their
# lens-shaped intersection: all three share a common point.
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
    obs("c", 3.0, 0.0, 10.0),
]

# Every pair overlaps but no point lies in all three disks.
TRIPLE = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 1.8, 0.0, 1.0),
    obs("c", 0.9, 1.6, 1.0),
]


class ReconcileContractTest(unittest.TestCase):
    def test_exported(self):
        import nearproof

        self.assertIn("reconcile_region", nearproof.__all__)

    def test_weighted_consensus_is_frozen(self):
        result = reconcile_region(LENS, ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 1))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.accepted = False

    def test_fields(self):
        result = reconcile_region(LENS, ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3))
        self.assertIsInstance(result, WeightedConsensus)
        self.assertIsInstance(result.total_weight, int)
        self.assertIsInstance(result.support_weight, int)
        self.assertIsInstance(result.rejected, tuple)
        self.assertIs(result.accepted, True)

    def test_field_equality(self):
        self.assertEqual(
            reconcile_region(LENS, ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)),
            WeightedConsensus(
                total_weight=3, support_weight=3, rejected=(), accepted=True
            ),
        )

    def test_common_point_keeps_everything(self):
        result = reconcile_region(LENS, ConsensusPolicy({"a": 2, "b": 3, "c": 5}, 7))
        self.assertEqual(result.total_weight, 10)
        self.assertEqual(result.support_weight, 10)
        self.assertEqual(result.rejected, ())
        self.assertIs(result.accepted, True)

    def test_heaviest_disk_wins(self):
        policy = ConsensusPolicy({"a": 1, "b": 5}, 3)
        result = reconcile_region(DISJOINT, policy)
        self.assertEqual(result.total_weight, 6)
        self.assertEqual(result.support_weight, 5)
        self.assertEqual(result.rejected, ("a",))
        self.assertIs(result.accepted, True)

    def test_below_threshold_still_returns_optimum(self):
        policy = ConsensusPolicy({"a": 1, "b": 5}, 6)
        result = reconcile_region(DISJOINT, policy)
        self.assertEqual(result.support_weight, 5)
        self.assertEqual(result.rejected, ("a",))
        self.assertIs(result.accepted, False)

    def test_threshold_does_not_change_optimum(self):
        for threshold in (1, 2, 3, 4, 5, 6):
            policy = ConsensusPolicy({"a": 1, "b": 5}, threshold)
            result = reconcile_region(DISJOINT, policy)
            self.assertEqual(result.support_weight, 5)
            self.assertEqual(result.rejected, ("a",))
            self.assertIs(result.accepted, threshold <= 5)

    def test_no_early_return_at_threshold(self):
        # The first threshold-reaching subset found must not stop the
        # search: keeping b and c (weight 6) beats keeping only the
        # heavy c (weight 5) even though c alone already reaches 3.
        disks = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 4.0, 0.0, 2.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 5}, 3)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.support_weight, 6)
        self.assertEqual(result.rejected, ("a",))
        self.assertIs(result.accepted, True)

    def test_equal_weight_tie_breaks_on_rejected_tuple(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        result = reconcile_region(DISJOINT, policy)
        self.assertEqual(result.support_weight, 1)
        # ("a",) < ("b",): the lexicographically smallest rejected
        # tuple wins, so the "a" disk is the one excluded.
        self.assertEqual(result.rejected, ("a",))

    def test_no_fewest_exclusions_rule(self):
        # Keeping the heavy c (weight 3) beats keeping the compatible
        # pair a, b (weight 2) even though that excludes two disks
        # instead of one.
        disks = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 1.0, 0.0, 1.0),
            obs("c", 10.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 3}, 1)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.support_weight, 3)
        self.assertEqual(result.rejected, ("a", "b"))

    def test_triple_without_common_point(self):
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        result = reconcile_region(TRIPLE, policy)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("a",))
        self.assertIs(result.accepted, True)

    def test_triple_heavy_disk_is_kept(self):
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 5}, 2)
        result = reconcile_region(TRIPLE, policy)
        # Every pair intersects, so the optimum keeps the heavy c plus
        # one more disk; ("a",) < ("b",) settles which one is excluded.
        self.assertEqual(result.support_weight, 6)
        self.assertEqual(result.rejected, ("a",))

    def test_decision_accepted_and_sample_count_ignored(self):
        disks = [
            obs("a", 0.0, 0.0, 1.0, accepted=False, sample_count=0),
            obs("b", 0.5, 0.0, 1.0, accepted=False, sample_count=99),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ())

    def test_single_observation(self):
        policy = ConsensusPolicy({"only": 4}, 4)
        result = reconcile_region([obs("only", 1.0, 2.0, 0.0)], policy)
        self.assertEqual(
            result,
            WeightedConsensus(
                total_weight=4, support_weight=4, rejected=(), accepted=True
            ),
        )

    def test_two_observations(self):
        policy = ConsensusPolicy({"a": 2, "b": 1}, 2)
        result = reconcile_region(DISJOINT, policy)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("b",))

    def test_one_shot_iterator(self):
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)
        result = reconcile_region(iter(LENS), policy)
        self.assertEqual(result.rejected, ())
        self.assertEqual(result.support_weight, 3)

    def test_tolerance_enlarges_disks(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        gap = reconcile_region(DISJOINT, policy)
        self.assertEqual(gap.support_weight, 1)
        bridged = reconcile_region(DISJOINT, policy, tolerance=1.0)
        self.assertEqual(bridged.support_weight, 2)
        self.assertEqual(bridged.rejected, ())

    def test_tolerance_default_is_zero(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            reconcile_region(DISJOINT, policy),
            reconcile_region(DISJOINT, policy, tolerance=0.0),
        )

    def test_tangent_disks_share_a_point(self):
        disks = [obs("a", 0.0, 0.0, 1.0), obs("b", 2.0, 0.0, 1.0)]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ())

    def test_contained_disk(self):
        disks = [obs("a", 0.0, 0.0, 10.0), obs("b", 1.0, 1.0, 1.0)]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.rejected, ())

    def test_coincident_disks(self):
        disks = [obs("a", 1.0, 1.0, 2.0), obs("b", 1.0, 1.0, 2.0)]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.rejected, ())

    def test_zero_radius(self):
        disks = [
            obs("a", 0.0, 0.0, 0.0),
            obs("b", 0.0, 0.0, 1.0),
            obs("c", 5.0, 5.0, 0.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("c",))

    def test_huge_finite_values(self):
        disks = [
            obs("a", 1e308, 1e308, 1e308),
            obs("b", -1e308, -1e308, 1e308),
            obs("c", 1e308, 1e308, 1e307),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        result = reconcile_region(disks, policy)
        # a and c share a common point; b is too far from both.
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("b",))

    def test_tiny_finite_values(self):
        disks = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1e-300, 0.0, 1e-300),
            obs("c", 1.0, 0.0, 1e-300),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.support_weight, 2)
        self.assertEqual(result.rejected, ("c",))

    def test_order_independence(self):
        disks = TRIPLE + [obs("d", 0.9, 0.5, 0.5)]
        weights = {"a": 3, "b": 1, "c": 2, "d": 4}
        expected = reconcile_region(disks, ConsensusPolicy(weights, 5))
        for permuted in itertools.permutations(disks):
            for weight_order in itertools.permutations(weights.items()):
                policy = ConsensusPolicy(dict(weight_order), 5)
                self.assertEqual(reconcile_region(permuted, policy), expected)

    def test_does_not_mutate_inputs(self):
        disks = list(TRIPLE)
        snapshot = list(disks)
        weights = {"a": 1, "b": 1, "c": 1}
        policy = ConsensusPolicy(weights, 2)
        reconcile_region(disks, policy)
        self.assertEqual(disks, snapshot)
        self.assertEqual(dict(policy.weights), weights)

    def test_rejected_sorted_lexicographically(self):
        disks = [
            obs("z", 0.0, 0.0, 1.0),
            obs("aa", 100.0, 0.0, 1.0),
            obs("b", 200.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"z": 5, "aa": 1, "b": 1}, 1)
        result = reconcile_region(disks, policy)
        self.assertEqual(result.rejected, ("aa", "b"))


class ReconcileValidationTest(unittest.TestCase):
    def test_empty_input(self):
        with self.assertRaises(ValueError):
            reconcile_region([], ConsensusPolicy({"a": 1}, 1))

    def test_non_iterable_input(self):
        with self.assertRaises(ValueError):
            reconcile_region(None, ConsensusPolicy({"a": 1}, 1))
        with self.assertRaises(ValueError):
            reconcile_region(42, ConsensusPolicy({"a": 1}, 1))

    def test_non_observation_element(self):
        with self.assertRaises(ValueError):
            reconcile_region(
                [obs("a", 0.0, 0.0, 1.0), "nope"],
                ConsensusPolicy({"a": 1}, 1),
            )

    def test_trailing_invalid_observation_not_ignored(self):
        # The first two disks already contradict each other, but the
        # invalid trailing element must still be rejected.
        disks = DISJOINT + [obs("c", 0.0, 0.0, -1.0)]
        with self.assertRaises(ValueError):
            reconcile_region(disks, ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 1))

    def test_duplicate_id(self):
        disks = [obs("a", 0.0, 0.0, 1.0), obs("a", 1.0, 0.0, 1.0)]
        with self.assertRaises(ValueError):
            reconcile_region(disks, ConsensusPolicy({"a": 1}, 1))

    def test_empty_id(self):
        with self.assertRaises(ValueError):
            reconcile_region(
                [obs("", 0.0, 0.0, 1.0)], ConsensusPolicy({"a": 1}, 1)
            )

    def test_non_string_id(self):
        with self.assertRaises(ValueError):
            reconcile_region(
                [obs(1, 0.0, 0.0, 1.0)], ConsensusPolicy({"a": 1}, 1)
            )

    def test_wrong_policy_type(self):
        with self.assertRaises(ValueError):
            reconcile_region(LENS, {"a": 1, "b": 1, "c": 1})
        with self.assertRaises(ValueError):
            reconcile_region(LENS, None)

    def test_weight_ids_must_match_observation_ids(self):
        with self.assertRaises(ValueError):
            reconcile_region(LENS, ConsensusPolicy({"a": 1, "b": 1, "d": 1}, 1))
        with self.assertRaises(ValueError):
            reconcile_region(LENS, ConsensusPolicy({"a": 1, "b": 1}, 1))

    def test_invalid_coordinates(self):
        for bad in (float("nan"), float("inf"), -float("inf"), True, "0"):
            with self.assertRaises(ValueError):
                reconcile_region(
                    [obs("a", bad, 0.0, 1.0)], ConsensusPolicy({"a": 1}, 1)
                )
            with self.assertRaises(ValueError):
                reconcile_region(
                    [obs("a", 0.0, bad, 1.0)], ConsensusPolicy({"a": 1}, 1)
                )

    def test_invalid_upper_bound(self):
        for bad in (-1.0, float("nan"), float("inf"), True, "1"):
            with self.assertRaises(ValueError):
                reconcile_region(
                    [obs("a", 0.0, 0.0, bad)], ConsensusPolicy({"a": 1}, 1)
                )

    def test_invalid_decision_type(self):
        observation = Observation(
            id="a", x=0.0, y=0.0, decision=object()
        )
        with self.assertRaises(ValueError):
            reconcile_region([observation], ConsensusPolicy({"a": 1}, 1))

    def test_invalid_tolerance(self):
        policy = ConsensusPolicy({"a": 1}, 1)
        for bad in (-1.0, float("nan"), float("inf"), True, "0"):
            with self.assertRaises(ValueError):
                reconcile_region([obs("a", 0.0, 0.0, 1.0)], policy, tolerance=bad)

    def test_tolerance_keyword_only(self):
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(TypeError):
            reconcile_region([obs("a", 0.0, 0.0, 1.0)], policy, 1.0)


if __name__ == "__main__":
    unittest.main()
