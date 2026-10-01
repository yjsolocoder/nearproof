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

WEIGHTS = {"a": 1, "b": 2, "c": 4}


def policy(weights=None, threshold=5):
    return ConsensusPolicy(WEIGHTS if weights is None else weights, threshold)


class WeightedConsensusContractTest(unittest.TestCase):
    def test_policy_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy().threshold = 1
        with self.assertRaises(TypeError):
            policy().weights["d"] = 8

    def test_result_is_frozen(self):
        result = locate_weighted(TRIANGLE, (0.0, 0.0), policy())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.accepted = False

    def test_fields(self):
        result = locate_weighted(TRIANGLE, (0.0, 0.0), policy(threshold=1))
        self.assertIsInstance(result, WeightedConsensus)
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 7)
        self.assertEqual(result.rejected, ())
        self.assertIs(result.accepted, True)
        self.assertIsInstance(result.rejected, tuple)

    def test_policy_equality_and_hash(self):
        self.assertEqual(policy(threshold=3), ConsensusPolicy(dict(WEIGHTS), 3))
        self.assertEqual(
            hash(policy(threshold=3)), hash(ConsensusPolicy(dict(WEIGHTS), 3))
        )
        self.assertNotEqual(
            policy(threshold=3), ConsensusPolicy(dict(WEIGHTS), 4)
        )
        self.assertNotEqual(policy(threshold=3), object())
        self.assertEqual(
            policy(threshold=3),
            ConsensusPolicy({"c": 4, "b": 2, "a": 1}, 3),
        )

    def test_policy_copies_weights(self):
        source = dict(WEIGHTS)
        made = ConsensusPolicy(source, 5)
        source["d"] = 8
        source["a"] = 99
        self.assertEqual(dict(made.weights), WEIGHTS)


class WeightedGeometryTest(unittest.TestCase):
    def test_all_disks_cover_point(self):
        result = locate_weighted(TRIANGLE, (0.0, 0.0), policy())
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 7)
        self.assertEqual(result.rejected, ())
        self.assertTrue(result.accepted)

    def test_weights_differ_from_count_quorum(self):
        # (3, 4): a and b cover (weights 1+2), c (weight 4) does not.
        # Count quorum of 2 would accept; weight threshold 5 must not.
        result = locate_weighted(TRIANGLE, (3.0, 4.0), policy(threshold=5))
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 3)
        self.assertEqual(result.rejected, ("c",))
        self.assertFalse(result.accepted)
        self.assertTrue(
            locate_weighted(TRIANGLE, (3.0, 4.0), policy(threshold=3)).accepted
        )
        self.assertTrue(
            locate(TRIANGLE, (3.0, 4.0), quorum=2).accepted
        )

    def test_threshold_exactly_met_accepts(self):
        result = locate_weighted(TRIANGLE, (3.0, 4.0), policy(threshold=3))
        self.assertEqual(result.support_weight, 3)
        self.assertIs(result.accepted, True)

    def test_no_support(self):
        result = locate_weighted(TRIANGLE, (10.0, 10.0), policy())
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 0)
        self.assertEqual(result.rejected, ("a", "b", "c"))
        self.assertFalse(result.accepted)

    def test_boundary_counts_as_support(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 5.0),
            obs("c", 0.0, 0.0, 0.0),
        ]
        result = locate_weighted(observations, (0.0, 0.0), policy())
        self.assertEqual(result.support_weight, 7)
        self.assertEqual(result.rejected, ())
        self.assertTrue(result.accepted)

    def test_just_outside_boundary_rejected(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        result = locate_weighted(
            observations, (10.0 + 1e-12, 0.0), policy()
        )
        self.assertEqual(result.rejected, ("a",))
        self.assertEqual(result.support_weight, 6)

    def test_tolerance_extends_radius(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        without = locate_weighted(observations, (10.5, 0.0), policy())
        self.assertEqual(without.rejected, ("a",))
        self.assertEqual(without.support_weight, 6)
        with_tol = locate_weighted(
            observations, (10.5, 0.0), policy(), tolerance=0.5
        )
        self.assertEqual(with_tol.support_weight, 7)
        self.assertEqual(with_tol.rejected, ())
        edge = locate_weighted(
            observations, (10.5 + 1e-12, 0.0), policy(), tolerance=0.5
        )
        self.assertEqual(edge.rejected, ("a",))

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            locate_weighted(TRIANGLE, (3.0, 4.0), policy()),
            locate_weighted(TRIANGLE, (3.0, 4.0), policy(), tolerance=0.0),
        )

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 3.0, 0.0, 5.0, accepted=False),
            obs("b", 0.0, 4.0, 5.0, accepted=False),
            obs("c", 0.0, 0.0, 0.0, accepted=True),
        ]
        result = locate_weighted(observations, (0.0, 0.0), policy())
        self.assertEqual(result.support_weight, 7)
        self.assertTrue(result.accepted)

    def test_integer_coordinates_and_bounds(self):
        observations = [
            obs("a", 0, 0, 0),
            obs("b", 3, 4, 5),
            obs("c", 6, 8, 10),
        ]
        result = locate_weighted(observations, (0, 0), policy())
        self.assertEqual(result.support_weight, 7)

    def test_single_weighted_observation_allowed(self):
        # Unlike locate (min 3), the weighted path has no count minimum.
        result = locate_weighted(
            [obs("solo", 0.0, 0.0, 0.0)],
            (0.0, 0.0),
            ConsensusPolicy({"solo": 1}, 1),
        )
        self.assertEqual(result, WeightedConsensus(1, 1, (), True))


class WeightedOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        made = policy(threshold=3)
        first = locate_weighted(TRIANGLE, (3.0, 4.0), made)
        shuffled = [TRIANGLE[2], TRIANGLE[0], TRIANGLE[1]]
        shuffled_weights = {"c": 4, "a": 1, "b": 2}
        second = locate_weighted(
            shuffled, (3.0, 4.0), ConsensusPolicy(shuffled_weights, 3)
        )
        self.assertEqual(first, second)
        self.assertEqual(second.rejected, ("c",))

    def test_rejected_always_lexicographic(self):
        observations = [
            obs("zebra", 100.0, 100.0, 0.0),
            obs("alpha", 0.0, 0.0, 0.0),
            obs("mid", -100.0, -100.0, 0.0),
        ]
        weights = {"zebra": 5, "alpha": 9, "mid": 1}
        result = locate_weighted(
            observations, (50.0, 50.0), ConsensusPolicy(weights, 1)
        )
        self.assertEqual(result.rejected, ("alpha", "mid", "zebra"))
        self.assertEqual(
            locate_weighted(
                list(reversed(observations)),
                (50.0, 50.0),
                ConsensusPolicy(dict(reversed(list(weights.items()))), 1),
            ).rejected,
            ("alpha", "mid", "zebra"),
        )

    def test_generator_input(self):
        result = locate_weighted(iter(TRIANGLE), (0.0, 0.0), policy())
        self.assertEqual(result.total_weight, 7)
        self.assertTrue(result.accepted)


class ConsensusPolicyValidationTest(unittest.TestCase):
    def test_bad_weights_container(self):
        for bad in (None, 123, 5.0, "x", [("a", 1)], object(), True):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy(bad, 1)

    def test_bad_weight_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy({bad: 1}, 1)

    def test_bad_weight_value(self):
        for bad in (0, -1, True, False, 1.0, 2.5, "1", None, math.nan):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy({"a": bad}, 1)

    def test_duplicate_weight_ids_in_custom_mapping(self):
        from collections.abc import Mapping as MappingABC

        class DupMap(MappingABC):
            def __init__(self, items):
                self._items = items

            def __getitem__(self, key):
                for k, v in self._items:
                    if k == key:
                        return v
                raise KeyError(key)

            def __iter__(self):
                return iter(k for k, _ in self._items)

            def __len__(self):
                return len(self._items)

        with self.assertRaises(ValueError):
            ConsensusPolicy(DupMap([("a", 1), ("a", 2)]), 1)

    def test_bad_threshold(self):
        for bad in (0, -1, True, False, 1.0, 2.5, "3", None, math.nan):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy({"a": 1, "b": 2}, bad)

    def test_threshold_larger_than_total(self):
        with self.assertRaises(ValueError):
            ConsensusPolicy({"a": 1, "b": 2}, 4)
        self.assertTrue(ConsensusPolicy({"a": 1, "b": 2}, 3).threshold == 3)


class LocateWeightedValidationTest(unittest.TestCase):
    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(bad, (0.0, 0.0), policy())

    def test_non_policy(self):
        for bad in (None, 7, WEIGHTS, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(TRIANGLE, (0.0, 0.0), bad)

    def test_weight_ids_must_match_observations(self):
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE, (0.0, 0.0), ConsensusPolicy({"a": 1, "b": 2}, 2)
            )
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE,
                (0.0, 0.0),
                ConsensusPolicy({"a": 1, "b": 2, "c": 4, "d": 8}, 7),
            )
        # Same cardinality but different ids also mismatches.
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE,
                (0.0, 0.0),
                ConsensusPolicy({"a": 1, "b": 2, "x": 4}, 3),
            )

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted([bad] + TRIANGLE[1:], (0.0, 0.0), policy())

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
            obs("b", 2.0, 0.0, 1.0),
        ]
        with self.assertRaises(ValueError):
            locate_weighted(
                observations, (0.0, 0.0), ConsensusPolicy({"a": 1, "b": 2}, 1)
            )

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(TRIANGLE[0], id=bad)
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(
                    [bad_obs] + TRIANGLE[1:],
                    (0.0, 0.0),
                    ConsensusPolicy(
                        {bad: 1, "b": 2, "c": 4}
                        if isinstance(bad, str)
                        else {"b": 2, "c": 4},
                        1,
                    ),
                )

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
            bad_obs = dataclasses.replace(TRIANGLE[0], **{field: value})
            with self.assertRaises(ValueError, msg=(field, value)):
                locate_weighted([bad_obs] + TRIANGLE[1:], (0.0, 0.0), policy())

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                TRIANGLE[0], decision=decision(value)
            )
            with self.assertRaises(ValueError, msg=value):
                locate_weighted([bad_obs] + TRIANGLE[1:], (0.0, 0.0), policy())

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(TRIANGLE[0], decision=object())
        with self.assertRaises(ValueError):
            locate_weighted([bad_obs] + TRIANGLE[1:], (0.0, 0.0), policy())

    def test_invalid_point(self):
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
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(TRIANGLE, bad, policy())

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
                locate_weighted(TRIANGLE, (0.0, 0.0), policy(), tolerance=bad)

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_weighted(TRIANGLE, (0.0, 0.0), policy(), 0.0)

    def test_no_partial_results_mutate_inputs(self):
        observations = list(TRIANGLE)
        weights = dict(WEIGHTS)
        locate_weighted(observations, (0.0, 0.0), ConsensusPolicy(weights, 5))
        self.assertEqual(observations, TRIANGLE)
        self.assertEqual(weights, WEIGHTS)


if __name__ == "__main__":
    unittest.main()
