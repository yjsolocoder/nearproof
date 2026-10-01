import dataclasses
import math
import unittest

from nearproof import (
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


# Three verifiers at the corners of a 3-4-5 triangle around the origin.
TRIANGLE = [
    obs("a", 3.0, 0.0, 5.0),
    obs("b", 0.0, 4.0, 5.0),
    obs("c", 0.0, 0.0, 0.0),
]

WEIGHTS = {"a": 1, "b": 2, "c": 4}


def policy(weights=WEIGHTS, *, threshold=4):
    return ConsensusPolicy(weights, threshold)


class WeightedConsensusContractTest(unittest.TestCase):
    def test_policy_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy().threshold = 1
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy().weights = {}

    def test_result_is_frozen(self):
        result = locate_weighted(TRIANGLE, (0.0, 0.0), policy())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.accepted = False

    def test_fields(self):
        result = locate_weighted(TRIANGLE, (3.0, 4.0), policy())
        self.assertIsInstance(result, WeightedConsensus)
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 3)
        self.assertEqual(result.rejected, ("c",))
        self.assertIs(result.accepted, False)
        self.assertIsInstance(result.rejected, tuple)
        self.assertIsInstance(result.total_weight, int)
        self.assertIsInstance(result.support_weight, int)

    def test_single_observation_is_allowed(self):
        # Unlike locate, there is no three-observation minimum.
        one = [obs("solo", 0.0, 0.0, 1.0)]
        result = locate_weighted(one, (0.5, 0.0), ConsensusPolicy({"solo": 9}, 1))
        self.assertEqual(result.total_weight, 9)
        self.assertEqual(result.support_weight, 9)
        self.assertEqual(result.rejected, ())
        self.assertTrue(result.accepted)


class WeightedTallyTest(unittest.TestCase):
    def test_weights_tallied_not_heads(self):
        # Point (3, 4): a and b cover it (distances 4, 5 vs radii 5),
        # c's radius-0 disk does not. Heads are 2 vs 1, weights 3 vs 4.
        result = locate_weighted(TRIANGLE, (3.0, 4.0), policy())
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 3)
        self.assertEqual(result.rejected, ("c",))
        # threshold 4 (weight of the single dissenter) rejects ...
        self.assertFalse(result.accepted)
        # ... but threshold 3 accepts on the minority-by-heads supporters.
        self.assertTrue(
            locate_weighted(TRIANGLE, (3.0, 4.0), policy(threshold=3)).accepted
        )

    def test_threshold_boundary_is_inclusive(self):
        # a+b carry weight 3: accepted exactly at threshold 3.
        at = locate_weighted(TRIANGLE, (3.0, 4.0), policy(threshold=3))
        self.assertEqual(at.support_weight, 3)
        self.assertTrue(at.accepted)

    def test_all_support_meets_total_threshold(self):
        result = locate_weighted(TRIANGLE, (0.0, 0.0), policy(threshold=7))
        self.assertEqual(result.support_weight, 7)
        self.assertEqual(result.rejected, ())
        self.assertTrue(result.accepted)

    def test_one_dissenter_fails_total_threshold(self):
        result = locate_weighted(TRIANGLE, (3.0, 4.0), policy(threshold=7))
        self.assertEqual(result.support_weight, 3)
        self.assertFalse(result.accepted)

    def test_no_support(self):
        result = locate_weighted(TRIANGLE, (10.0, 10.0), policy(threshold=1))
        self.assertEqual(result.total_weight, 7)
        self.assertEqual(result.support_weight, 0)
        self.assertEqual(result.rejected, ("a", "b", "c"))
        self.assertFalse(result.accepted)

    def test_heavy_supporter_outvotes_many_light_rejecters(self):
        observations = [
            obs("light1", 100.0, 0.0, 1.0),
            obs("light2", 0.0, 100.0, 1.0),
            obs("heavy", 0.0, 0.0, 1.0),
        ]
        weights = {"light1": 1, "light2": 1, "heavy": 5}
        result = locate_weighted(
            observations, (0.0, 0.0), ConsensusPolicy(weights, 5)
        )
        self.assertEqual(result.support_weight, 5)
        self.assertEqual(result.rejected, ("light1", "light2"))
        self.assertTrue(result.accepted)

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 3.0, 0.0, 5.0, accepted=False),
            obs("b", 0.0, 4.0, 5.0, accepted=False),
            obs("c", 0.0, 0.0, 0.0, accepted=True),
        ]
        result = locate_weighted(observations, (0.0, 0.0), policy(threshold=7))
        self.assertEqual(result.support_weight, 7)
        self.assertTrue(result.accepted)

    def test_integer_coordinates_and_bounds(self):
        observations = [
            obs("a", 0, 0, 0),
            obs("b", 3, 4, 5),
            obs("c", 6, 8, 10),
        ]
        result = locate_weighted(
            observations, (0, 0), ConsensusPolicy({"a": 2, "b": 3, "c": 5}, 1)
        )
        self.assertEqual(result.support_weight, 10)


class WeightedGeometryTest(unittest.TestCase):
    def test_boundary_counts_as_support(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 5.0),
            obs("c", 0.0, 0.0, 0.0),
        ]
        result = locate_weighted(
            observations, (0.0, 0.0), ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)
        )
        self.assertEqual(result.support_weight, 3)
        self.assertEqual(result.rejected, ())
        self.assertTrue(result.accepted)

    def test_just_outside_boundary_rejected(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        weights = {"a": 1, "b": 2, "c": 4}
        result = locate_weighted(
            observations, (10.0 + 1e-12, 0.0), ConsensusPolicy(weights, 7)
        )
        self.assertEqual(result.rejected, ("a",))
        self.assertEqual(result.support_weight, 6)
        self.assertFalse(result.accepted)

    def test_tolerance_extends_radius_with_closed_edge(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        weights = {"a": 1, "b": 2, "c": 4}
        without = locate_weighted(
            observations, (10.5, 0.0), ConsensusPolicy(weights, 1)
        )
        self.assertEqual(without.rejected, ("a",))
        self.assertEqual(without.support_weight, 6)
        with_tol = locate_weighted(
            observations, (10.5, 0.0), ConsensusPolicy(weights, 1), tolerance=0.5
        )
        self.assertEqual(with_tol.support_weight, 7)
        self.assertEqual(with_tol.rejected, ())
        edge = locate_weighted(
            observations,
            (10.5 + 1e-12, 0.0),
            ConsensusPolicy(weights, 1),
            tolerance=0.5,
        )
        self.assertEqual(edge.rejected, ("a",))

    def test_zero_tolerance_is_default(self):
        pol = policy()
        self.assertEqual(
            locate_weighted(TRIANGLE, (3.0, 4.0), pol),
            locate_weighted(TRIANGLE, (3.0, 4.0), pol, tolerance=0.0),
        )


class WeightedOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        pol = policy()
        point = (3.0, 4.0)
        first = locate_weighted(TRIANGLE, point, pol)
        shuffled = [TRIANGLE[2], TRIANGLE[0], TRIANGLE[1]]
        second = locate_weighted(shuffled, point, pol)
        self.assertEqual(first, second)
        self.assertEqual(second.rejected, ("c",))

    def test_weight_insertion_order_irrelevant(self):
        point = (3.0, 4.0)
        a = locate_weighted(TRIANGLE, point, ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 4))
        b = locate_weighted(TRIANGLE, point, ConsensusPolicy({"c": 4, "b": 2, "a": 1}, 4))
        self.assertEqual(a, b)

    def test_rejected_always_lexicographic(self):
        observations = [
            obs("zebra", 100.0, 100.0, 0.0),
            obs("alpha", 0.0, 0.0, 0.0),
            obs("mid", -100.0, -100.0, 0.0),
        ]
        weights = {"zebra": 3, "alpha": 1, "mid": 2}
        pol = ConsensusPolicy(weights, 1)
        result = locate_weighted(observations, (50.0, 50.0), pol)
        self.assertEqual(result.rejected, ("alpha", "mid", "zebra"))
        self.assertEqual(
            locate_weighted(list(reversed(observations)), (50.0, 50.0), pol).rejected,
            ("alpha", "mid", "zebra"),
        )

    def test_generator_input(self):
        result = locate_weighted(iter(TRIANGLE), (0.0, 0.0), policy())
        self.assertEqual(result.total_weight, 7)
        self.assertTrue(result.accepted)


class WeightedPurityTest(unittest.TestCase):
    def test_inputs_not_mutated(self):
        weights = {"a": 1, "b": 2, "c": 4}
        pol = ConsensusPolicy(weights, 4)
        observations = [
            obs("a", 3.0, 0.0, 5.0),
            obs("b", 0.0, 4.0, 5.0),
            obs("c", 0.0, 0.0, 0.0),
        ]
        locate_weighted(observations, (3.0, 4.0), pol)
        self.assertEqual(weights, {"a": 1, "b": 2, "c": 4})
        self.assertEqual(dict(pol.weights), {"a": 1, "b": 2, "c": 4})
        self.assertEqual(
            [o.id for o in observations], ["a", "b", "c"]
        )

    def test_policy_copies_weights_mapping(self):
        source = {"a": 1, "b": 2, "c": 4}
        pol = ConsensusPolicy(source, 4)
        source["a"] = 999
        source["d"] = 5
        del source["b"]
        self.assertEqual(dict(pol.weights), {"a": 1, "b": 2, "c": 4})
        # The frozen copy still works with the original observation set.
        result = locate_weighted(TRIANGLE, (3.0, 4.0), pol)
        self.assertEqual(result.support_weight, 3)


class PolicyValidationTest(unittest.TestCase):
    def test_weights_not_a_mapping(self):
        for bad in (None, 123, [("a", 1)], (("a", 1),), {("a",): 1}, "x"):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy(bad, 1)

    def test_empty_weights(self):
        with self.assertRaises(ValueError):
            ConsensusPolicy({}, 1)

    def test_invalid_weight_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy({"a": 1, bad: 2}, 1)

    def test_non_positive_integer_weight(self):
        for bad in (0, -1, 1.0, 2.5, True, False, "1", None, math.nan, math.inf):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy({"a": 1, "b": bad}, 1)

    def test_invalid_threshold(self):
        weights = {"a": 1, "b": 2}
        for bad in (0, -1, True, False, 1.0, 2.5, "3", None, math.nan):
            with self.assertRaises(ValueError, msg=bad):
                ConsensusPolicy(weights, bad)

    def test_threshold_above_total_weight(self):
        with self.assertRaises(ValueError):
            ConsensusPolicy({"a": 1, "b": 2}, 4)
        # Exactly the total weight is still legal.
        pol = ConsensusPolicy({"a": 1, "b": 2}, 3)
        self.assertEqual(pol.threshold, 3)


class LocateWeightedValidationTest(unittest.TestCase):
    def test_policy_wrong_type(self):
        for bad in (None, 1, {"a": 1}, object(), WEIGHTS, "policy"):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(TRIANGLE, (0.0, 0.0), bad)

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(bad, (0.0, 0.0), policy())

    def test_empty_observations(self):
        # No observations against a non-empty (valid) policy: id sets differ.
        with self.assertRaises(ValueError):
            locate_weighted([], (0.0, 0.0), policy())

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
                observations,
                (0.0, 0.0),
                ConsensusPolicy({"a": 1, "b": 2}, 1),
            )

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(TRIANGLE[0], id=bad)
            observations = [bad_obs] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(observations, (0.0, 0.0), policy())

    def test_observation_id_missing_from_policy(self):
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE,
                (0.0, 0.0),
                ConsensusPolicy({"a": 1, "b": 2, "d": 4}, 1),
            )

    def test_policy_has_extra_weight_id(self):
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE,
                (0.0, 0.0),
                ConsensusPolicy({"a": 1, "b": 2, "c": 4, "d": 8}, 1),
            )

    def test_policy_id_set_must_match_exactly(self):
        # Same cardinality, different id.
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE,
                (0.0, 0.0),
                ConsensusPolicy({"a": 1, "b": 2, "x": 4}, 1),
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
            observations = [bad_obs] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=(field, value)):
                locate_weighted(observations, (0.0, 0.0), policy())

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(TRIANGLE[0], decision=decision(value))
            observations = [bad_obs] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=value):
                locate_weighted(observations, (0.0, 0.0), policy())

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(TRIANGLE[0], decision=object())
        observations = [bad_obs] + TRIANGLE[1:]
        with self.assertRaises(ValueError):
            locate_weighted(observations, (0.0, 0.0), policy())

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

    def test_legitimate_threshold_splits_accepted_from_rejected(self):
        # threshold == total weight: any rejection flips accepted.
        all_cover = locate_weighted(
            TRIANGLE, (0.0, 0.0), ConsensusPolicy(WEIGHTS, 7)
        )
        self.assertTrue(all_cover.accepted)
        one_misses = locate_weighted(
            TRIANGLE, (3.0, 4.0), ConsensusPolicy(WEIGHTS, 7)
        )
        self.assertFalse(one_misses.accepted)


class UnchangedLocateFamilyTest(unittest.TestCase):
    def test_locate_still_counts_heads(self):
        # locate keeps its quorum semantics: 2 of 3 heads with quorum 2
        # accepts even though their combined weight would be 3 < 4.
        result = locate(TRIANGLE, (3.0, 4.0), quorum=2)
        self.assertEqual(result.support, 2)
        self.assertTrue(result.accepted)
        self.assertFalse(hasattr(result, "total_weight"))
        self.assertFalse(hasattr(result, "support_weight"))


if __name__ == "__main__":
    unittest.main()
