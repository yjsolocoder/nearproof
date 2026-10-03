"""Contract regression across the two public locate entries.

These tests pin the shared contract of :func:`nearproof.locate` and
:func:`nearproof.locate_weighted` after their duplicated validation and
observation handling were unified: unit-weight tally correspondence,
iterator/order equivalence, frozen read-only inputs, and identical
ValueError enforcement for every shared rule, plus the count-vs-weight
differences that deliberately distinguish the two entries.
"""

import dataclasses
import math
import unittest

from nearproof import (
    Consensus,
    ConsensusPolicy,
    Observation,
    RangeDecision,
    WeightedConsensus,
    locate,
    locate_weighted,
)


def decision(upper_bound, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True):
    return Observation(
        id=ident, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


TRIANGLE = [
    obs("a", 3.0, 0.0, 5.0),
    obs("b", 0.0, 4.0, 5.0),
    obs("c", 0.0, 0.0, 0.0),
]

UNIT_POLICY = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)

POINTS = [
    (0.0, 0.0),
    (3.0, 4.0),
    (10.0, 10.0),
    (-3.0, -4.0),
    (5.0, 0.0),
]


class UnitWeightCorrespondenceTest(unittest.TestCase):
    """With unit weights the weighted tally mirrors the head count exactly."""

    def assert_entries_correspond(self, observations, point, quorum, tolerance=0.0):
        plain = locate(
            observations, point, quorum=quorum, tolerance=tolerance
        )
        weighted = locate_weighted(
            observations,
            point,
            ConsensusPolicy(
                {ident: 1 for ident in ("a", "b", "c")}, quorum
            ),
            tolerance=tolerance,
        )
        self.assertEqual(plain.total, weighted.total_weight)
        self.assertEqual(plain.support, weighted.support_weight)
        self.assertEqual(plain.rejected, weighted.rejected)
        self.assertIs(plain.accepted, weighted.accepted)
        self.assertIsInstance(weighted, WeightedConsensus)
        self.assertIsInstance(plain, Consensus)

    def test_unit_weights_match_across_points_and_quora(self):
        for point in POINTS:
            for quorum in (1, 2, 3):
                with self.subTest(point=point, quorum=quorum):
                    self.assert_entries_correspond(TRIANGLE, point, quorum)

    def test_unit_weights_match_with_tolerance(self):
        for point in ((10.5, 0.0), (-10.5, 0.0)):
            for tolerance in (0.0, 0.5, 2.0):
                with self.subTest(point=point, tolerance=tolerance):
                    self.assert_entries_correspond(
                        TRIANGLE, point, 2, tolerance=tolerance
                    )

    def test_unit_weights_match_in_overflow_regime(self):
        observations = [
            obs("a", -1.5e308, 0.0, 1e308),
            obs("b", -1e308, 0.0, 1e308),
            obs("c", 1e308, 0.0, 1e308),
        ]
        for point, covering in (
            ((1.5e308, 0.0), 1),   # only c's radius-2e308 disk reaches
            ((-1.5e308, 0.0), 2),  # a and b reach, c does not
            ((0.0, 0.0), 3),       # all three radius-2e308 disks cover
        ):
            with self.subTest(point=point):
                self.assert_entries_correspond(
                    observations, point, covering, tolerance=1e308
                )

    def test_negative_coordinates_accepted_by_both(self):
        observations = [
            obs("a", -3.0, -4.0, 5.0),
            obs("b", -6.0, -8.0, 10.0),
            obs("c", 0.0, 0.0, 0.0),
        ]
        self.assert_entries_correspond(observations, (0.0, 0.0), 3)

    def test_accepted_flag_ignored_by_both(self):
        observations = [
            obs("a", 3.0, 0.0, 5.0, accepted=False),
            obs("b", 0.0, 4.0, 5.0, accepted=False),
            obs("c", 0.0, 0.0, 0.0, accepted=False),
        ]
        self.assert_entries_correspond(observations, (0.0, 0.0), 3)


class EntryDifferencesTest(unittest.TestCase):
    def test_single_observation_weighted_only(self):
        solo = [obs("solo", 0.0, 0.0, 0.0)]
        result = locate_weighted(
            solo, (0.0, 0.0), ConsensusPolicy({"solo": 1}, 1)
        )
        self.assertEqual(result, WeightedConsensus(1, 1, (), True))
        # The count-based entry keeps its three-observation minimum.
        with self.assertRaises(ValueError):
            locate(solo, (0.0, 0.0))
        with self.assertRaises(ValueError):
            locate([], (0.0, 0.0))

    def test_two_observations_weighted_allowed(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 10.0, 0.0, 1.0),
        ]
        result = locate_weighted(
            observations,
            (0.0, 0.0),
            ConsensusPolicy({"a": 1, "b": 1}, 1),
        )
        self.assertEqual(result, WeightedConsensus(2, 1, ("b",), True))
        with self.assertRaises(ValueError):
            locate(observations, (0.0, 0.0))

    def test_weights_change_the_verdict_vs_head_count(self):
        # (3, 4): a and b cover, c does not. A head count of two accepts,
        # but weights 1+2=3 fall short of threshold 5.
        plain = locate(TRIANGLE, (3.0, 4.0), quorum=2)
        weighted = locate_weighted(
            TRIANGLE, (3.0, 4.0), ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 5)
        )
        self.assertTrue(plain.accepted)
        self.assertFalse(weighted.accepted)
        self.assertEqual(plain.support, 2)
        self.assertEqual(weighted.support_weight, 3)
        self.assertEqual(plain.rejected, weighted.rejected)

    def test_same_geometry_different_weights_differ_in_outcome(self):
        made_low = locate_weighted(
            TRIANGLE, (3.0, 4.0), ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 3)
        )
        made_high = locate_weighted(
            TRIANGLE, (3.0, 4.0), ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 5)
        )
        self.assertIs(made_low.accepted, True)
        self.assertIs(made_high.accepted, False)
        self.assertEqual(made_low.rejected, made_high.rejected)

    def test_single_weighted_observation_outside_disk_rejects(self):
        result = locate_weighted(
            [obs("solo", 10.0, 0.0, 1.0)],
            (0.0, 0.0),
            ConsensusPolicy({"solo": 1}, 1),
        )
        self.assertEqual(result, WeightedConsensus(1, 0, ("solo",), False))


class OrderAndIteratorTest(unittest.TestCase):
    def test_permutations_and_iterators_agree(self):
        import itertools

        point = (3.0, 4.0)
        reference = locate(TRIANGLE, point)
        for permutation in itertools.permutations(TRIANGLE):
            ordered = list(permutation)
            self.assertEqual(locate(ordered, point), reference)
            self.assertEqual(locate(iter(ordered), point), reference)
        weighted_reference = locate_weighted(TRIANGLE, point, UNIT_POLICY)
        for permutation in itertools.permutations(TRIANGLE):
            ordered = list(permutation)
            self.assertEqual(
                locate_weighted(iter(ordered), point, UNIT_POLICY),
                weighted_reference,
            )

    def test_oneshot_iterator_is_consumed_once(self):
        consumed = list(TRIANGLE)
        single_pass = iter(consumed)
        result = locate(single_pass, (0.0, 0.0))
        self.assertEqual(result.total, 3)
        with self.assertRaises(StopIteration):
            next(single_pass)

    def test_generator_expression_accepted(self):
        plain = locate((observation for observation in TRIANGLE), (0.0, 0.0))
        weighted = locate_weighted(
            (observation for observation in TRIANGLE), (0.0, 0.0), UNIT_POLICY
        )
        self.assertTrue(plain.accepted)
        self.assertTrue(weighted.accepted)


class SharedValidationParityTest(unittest.TestCase):
    """Every shared rule must raise ValueError through both public entries."""

    def weighted(self, observations, point=(0.0, 0.0), policy=UNIT_POLICY, **kwargs):
        return locate_weighted(observations, point, policy, **kwargs)

    def plain(self, observations, point=(0.0, 0.0), **kwargs):
        return locate(observations, point, **kwargs)

    def assert_both_reject(self, observations, point=(0.0, 0.0), **kwargs):
        with self.assertRaises(ValueError):
            self.plain(observations, point, **kwargs)
        with self.assertRaises(ValueError):
            self.weighted(observations, point, **kwargs)

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.subTest(bad=bad):
                self.assert_both_reject(bad)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            with self.subTest(bad=bad):
                self.assert_both_reject([bad] + TRIANGLE[1:])

    def test_empty_and_duplicate_ids(self):
        empty_id = dataclasses.replace(TRIANGLE[0], id="")
        self.assert_both_reject([empty_id] + TRIANGLE[1:])
        duplicate = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
            obs("b", 2.0, 0.0, 1.0),
        ]
        with self.assertRaises(ValueError):
            self.plain(duplicate)
        with self.assertRaises(ValueError):
            self.weighted(
                duplicate, policy=ConsensusPolicy({"a": 1, "b": 1}, 1)
            )

    def test_wrong_decision_type(self):
        bad_obs = dataclasses.replace(TRIANGLE[0], decision=object())
        self.assert_both_reject([bad_obs] + TRIANGLE[1:])

    def test_illegal_coordinates(self):
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
            ("y", -math.inf),
        ):
            with self.subTest(field=field, value=value):
                bad_obs = dataclasses.replace(TRIANGLE[0], **{field: value})
                self.assert_both_reject([bad_obs] + TRIANGLE[1:])

    def test_illegal_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            with self.subTest(value=value):
                bad_obs = dataclasses.replace(TRIANGLE[0], decision=decision(value))
                self.assert_both_reject([bad_obs] + TRIANGLE[1:])

    def test_illegal_point(self):
        for bad in (
            (0.0,),
            (0.0, 0.0, 0.0),
            [0.0, 0.0],
            (True, 0.0),
            (0.0, False),
            (math.nan, 0.0),
            (0.0, math.inf),
            ("0", 0.0),
            None,
            0.0,
            (),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate(TRIANGLE, bad)
                with self.assertRaises(ValueError):
                    locate_weighted(TRIANGLE, bad, UNIT_POLICY)

    def test_illegal_tolerance(self):
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
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate(TRIANGLE, (0.0, 0.0), tolerance=bad)
                with self.assertRaises(ValueError):
                    locate_weighted(TRIANGLE, (0.0, 0.0), UNIT_POLICY, tolerance=bad)

    def test_plain_specific_count_and_quorum_rules(self):
        for count in (0, 1, 2):
            with self.assertRaises(ValueError):
                locate(TRIANGLE[:count], (0.0, 0.0))
        for bad in (0, -1, True, False, 1.0, 2.5, "3", None, math.nan):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate(TRIANGLE, (0.0, 0.0), quorum=bad)
        with self.assertRaises(ValueError):
            locate(TRIANGLE, (0.0, 0.0), quorum=4)

    def test_weighted_specific_policy_rules(self):
        for bad in (None, 7, {"a": 1, "b": 1, "c": 1}, object(), True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate_weighted(TRIANGLE, (0.0, 0.0), bad)
        mismatches = [
            ConsensusPolicy({"a": 1, "b": 1}, 2),
            ConsensusPolicy({"a": 1, "b": 1, "c": 1, "d": 1}, 4),
            ConsensusPolicy({"a": 1, "b": 1, "x": 1}, 3),
        ]
        for mismatched in mismatches:
            with self.assertRaises(ValueError):
                locate_weighted(TRIANGLE, (0.0, 0.0), mismatched)

    def test_keyword_only_parameters(self):
        with self.assertRaises(TypeError):
            locate(TRIANGLE, (0.0, 0.0), 3, 0.0)
        with self.assertRaises(TypeError):
            locate_weighted(TRIANGLE, (0.0, 0.0), UNIT_POLICY, 0.0)


class ImmutabilityTest(unittest.TestCase):
    def test_success_and_failure_do_not_mutate_inputs(self):
        observations = list(TRIANGLE)
        weights = {"a": 1, "b": 2, "c": 4}
        locate(observations, (0.0, 0.0))
        locate(observations, (3.0, 4.0), quorum=3)
        locate_weighted(
            observations, (0.0, 0.0), ConsensusPolicy(weights, 5)
        )
        self.assertEqual(observations, TRIANGLE)
        self.assertEqual(weights, {"a": 1, "b": 2, "c": 4})
        # Failing calls likewise leave inputs untouched.
        with self.assertRaises(ValueError):
            locate(observations, (0.0,), quorum=1)
        with self.assertRaises(ValueError):
            locate_weighted(
                observations, (0.0, 0.0), ConsensusPolicy({"a": 1}, 1)
            )
        self.assertEqual(observations, TRIANGLE)
        self.assertEqual(weights, {"a": 1, "b": 2, "c": 4})

    def test_policy_holds_read_only_copy(self):
        source = {"a": 1, "b": 2}
        policy = ConsensusPolicy(source, 2)
        source["c"] = 4
        source["a"] = 99
        self.assertEqual(dict(policy.weights), {"a": 1, "b": 2})
        with self.assertRaises(TypeError):
            policy.weights["c"] = 4
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.threshold = 1

    def test_results_remain_frozen(self):
        plain = locate(TRIANGLE, (0.0, 0.0))
        weighted = locate_weighted(TRIANGLE, (0.0, 0.0), UNIT_POLICY)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plain.accepted = False
        with self.assertRaises(dataclasses.FrozenInstanceError):
            weighted.accepted = False
        self.assertIsInstance(plain.rejected, tuple)
        self.assertIsInstance(weighted.rejected, tuple)

    def test_failed_validation_does_not_poison_later_calls(self):
        # A sequence of failures followed by a success must behave as if
        # the failures never happened: no shared validator state.
        for bad_point in ((0.0,), None):
            with self.assertRaises(ValueError):
                locate(TRIANGLE, bad_point)
            with self.assertRaises(ValueError):
                locate_weighted(TRIANGLE, bad_point, UNIT_POLICY)
        with self.assertRaises(ValueError):
            locate(123, (0.0, 0.0))
        with self.assertRaises(ValueError):
            locate_weighted(TRIANGLE, (0.0, 0.0), object())
        self.assertTrue(locate(TRIANGLE, (0.0, 0.0)).accepted)
        self.assertTrue(
            locate_weighted(TRIANGLE, (0.0, 0.0), UNIT_POLICY).accepted
        )

    def test_observation_instances_shared_across_calls_unaffected(self):
        observations = list(TRIANGLE)
        locate(observations, (10.0, 10.0))
        locate_weighted(observations, (10.0, 10.0), UNIT_POLICY)
        locate(observations, (0.0, 0.0))
        locate_weighted(observations, (0.0, 0.0), UNIT_POLICY)
        self.assertEqual(observations, TRIANGLE)


if __name__ == "__main__":
    unittest.main()
