import dataclasses
import math
import unittest

from nearproof import (
    ConsensusPolicy,
    Observation,
    RangeDecision,
    RegionDecision,
    locate_region,
    locate_weighted_region,
)


def decision(upper_bound, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True):
    return Observation(
        id=ident, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


# Two disjoint unit disks at the origin and at (4, 0), weight 1 each:
# threshold 1 gives the union (bounds (-1, -1, 5, 1), witness (-1, 0)),
# threshold 2 gives the empty region.
DISJOINT = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 4.0, 0.0, 1.0),
]
DISJOINT_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 1)

# Same lens geometry as the locate_region tests: extremes from b's
# leftmost point (1, 0), a's rightmost point (5, 0) and the two
# circle-meeting points (3, ±4) once the threshold demands every disk.
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
    obs("c", 3.0, 0.0, 10.0),
]
LENS_POLICY = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)


class WeightedRegionContractTest(unittest.TestCase):
    def test_region_decision_is_frozen(self):
        region = locate_weighted_region(DISJOINT, DISJOINT_POLICY)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            region.feasible = False

    def test_fields(self):
        region = locate_weighted_region(DISJOINT, DISJOINT_POLICY)
        self.assertIsInstance(region, RegionDecision)
        self.assertIs(region.feasible, True)
        self.assertIsInstance(region.bounds, tuple)
        self.assertEqual(len(region.bounds), 4)
        self.assertIsInstance(region.witness, tuple)
        self.assertEqual(len(region.witness), 2)
        for value in region.bounds + region.witness:
            self.assertIsInstance(value, float)
            self.assertTrue(math.isfinite(value))
            self.assertNotIsInstance(value, bool)

    def test_empty_region_fields(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        region = locate_weighted_region(DISJOINT, policy)
        self.assertIs(region.feasible, False)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_no_minimum_observation_count(self):
        policy = ConsensusPolicy({"only": 2}, 2)
        region = locate_weighted_region(
            [obs("only", 1.0, 2.0, 3.0)], policy
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-2.0, -1.0, 4.0, 5.0))
        self.assertEqual(region.witness, (-2.0, 2.0))

    def test_single_observation_policy_mismatch_rejected(self):
        policy = ConsensusPolicy({"only": 1, "ghost": 1}, 2)
        with self.assertRaises(ValueError):
            locate_weighted_region([obs("only", 0.0, 0.0, 1.0)], policy)


class WeightedRegionGeometryTest(unittest.TestCase):
    def test_disjoint_disks_union(self):
        region = locate_weighted_region(DISJOINT, DISJOINT_POLICY)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-1.0, -1.0, 5.0, 1.0))
        self.assertEqual(region.witness, (-1.0, 0.0))

    def test_disjoint_disks_threshold_two_is_empty(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        region = locate_weighted_region(DISJOINT, policy)
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_threshold_at_total_weight_matches_locate_region(self):
        weighted = locate_weighted_region(LENS, LENS_POLICY)
        plain = locate_region(LENS)
        self.assertTrue(weighted.feasible)
        self.assertEqual(weighted, plain)

    def test_weighted_threshold_picks_heavier_side(self):
        # Two disjoint disks; only b's weight reaches the threshold.
        policy = ConsensusPolicy({"a": 1, "b": 2}, 2)
        region = locate_weighted_region(DISJOINT, policy)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (3.0, -1.0, 5.0, 1.0))
        self.assertEqual(region.witness, (3.0, 0.0))

    def test_separated_regions_from_partial_overlaps(self):
        # a and c are tangent at (1, 0), b and c at (3, 0); with weight 2
        # required the feasible region is exactly those two points.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 2.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 1.0, delta=1e-9)
        self.assertAlmostEqual(min_y, 0.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 3.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 0.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, 1.0, delta=1e-9)
        self.assertAlmostEqual(wy, 0.0, delta=1e-9)

    def test_witness_is_leftmost_then_lowest(self):
        # Two unit disks stacked vertically at x = 0: the leftmost slice
        # holds both (-1, 0) and (-1, 4); the lower one wins.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 0.0, 4.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-1.0, -1.0, 1.0, 5.0))
        self.assertEqual(region.witness, (-1.0, 0.0))

    def test_tangent_disks_degenerate_to_single_point(self):
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 3.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 3.0, delta=1e-9)
        self.assertAlmostEqual(min_y, 0.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 0.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, 3.0, delta=1e-9)
        self.assertAlmostEqual(wy, 0.0, delta=1e-9)

    def test_zero_radius_disk_pins_region(self):
        observations = [
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 2.0, 2.0, 2.0),
            obs("c", 1.0, 1.0, 0.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (1.0, 1.0, 1.0, 1.0))
        self.assertEqual(region.witness, (1.0, 1.0))

    def test_zero_radius_disk_alone(self):
        policy = ConsensusPolicy({"pin": 1}, 1)
        region = locate_weighted_region(
            [obs("pin", 3.0, -2.0, 0.0)], policy
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (3.0, -2.0, 3.0, -2.0))
        self.assertEqual(region.witness, (3.0, -2.0))

    def test_concentric_disks_use_smallest(self):
        observations = [
            obs("a", 1.0, 1.0, 10.0),
            obs("b", 1.0, 1.0, 3.0),
            obs("c", 1.0, 1.0, 20.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-2.0, -2.0, 4.0, 4.0))
        self.assertEqual(region.witness, (-2.0, 1.0))

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0, accepted=False),
            obs("b", 4.0, 0.0, 1.0, accepted=False),
        ]
        region = locate_weighted_region(observations, DISJOINT_POLICY)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-1.0, -1.0, 5.0, 1.0))

    def test_tolerance_extends_every_radius(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertFalse(locate_weighted_region(DISJOINT, policy).feasible)
        # Radii become 2: the disks touch at (2, 0).
        region = locate_weighted_region(DISJOINT, policy, tolerance=1.0)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 2.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 2.0, delta=1e-9)
        self.assertAlmostEqual(min_y, 0.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 0.0, delta=1e-9)

    def test_integer_inputs_match_float_inputs(self):
        integers = [obs("a", 0, 0, 1), obs("b", 4, 0, 1)]
        self.assertEqual(
            locate_weighted_region(integers, DISJOINT_POLICY),
            locate_weighted_region(DISJOINT, DISJOINT_POLICY),
        )
        self.assertEqual(
            locate_weighted_region(integers, DISJOINT_POLICY, tolerance=1),
            locate_weighted_region(DISJOINT, DISJOINT_POLICY, tolerance=1.0),
        )


class WeightedRegionOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_observations_give_identical_result(self):
        first = locate_weighted_region(LENS, LENS_POLICY)
        shuffled = [LENS[2], LENS[0], LENS[1]]
        self.assertEqual(first, locate_weighted_region(shuffled, LENS_POLICY))

    def test_weight_mapping_order_is_irrelevant(self):
        forward = ConsensusPolicy({"a": 1, "b": 2, "c": 3}, 4)
        backward = ConsensusPolicy({"c": 3, "b": 2, "a": 1}, 4)
        self.assertEqual(
            locate_weighted_region(LENS, forward),
            locate_weighted_region(LENS, backward),
        )

    def test_generator_input(self):
        region = locate_weighted_region(iter(LENS), LENS_POLICY)
        self.assertTrue(region.feasible)
        self.assertEqual(region, locate_weighted_region(LENS, LENS_POLICY))

    def test_inputs_not_mutated(self):
        observations = list(LENS)
        snapshot = list(observations)
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        weights_snapshot = dict(policy.weights)
        locate_weighted_region(observations, policy)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])
        self.assertEqual(dict(policy.weights), weights_snapshot)


class WeightedRegionValidationTest(unittest.TestCase):
    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region(bad, DISJOINT_POLICY)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region(observations, DISJOINT_POLICY)

    def test_empty_observations_rejected(self):
        with self.assertRaises(ValueError):
            locate_weighted_region([], DISJOINT_POLICY)

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_region(observations, policy)

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(DISJOINT[0], id=bad)
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region(observations, DISJOINT_POLICY)

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
            bad_obs = dataclasses.replace(DISJOINT[0], **{field: value})
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=(field, value)):
                locate_weighted_region(observations, DISJOINT_POLICY)

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                DISJOINT[0], decision=decision(value)
            )
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=value):
                locate_weighted_region(observations, DISJOINT_POLICY)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(DISJOINT[0], decision=object())
        observations = [bad_obs] + DISJOINT[1:]
        with self.assertRaises(ValueError):
            locate_weighted_region(observations, DISJOINT_POLICY)

    def test_non_policy_rejected(self):
        for bad in (None, 123, "policy", object(), {"a": 1, "b": 1}, (("a", 1),)):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region(DISJOINT, bad)

    def test_policy_ids_must_match_observation_ids(self):
        for weights in ({"a": 1}, {"a": 1, "b": 1, "c": 1}, {"a": 1, "z": 1}):
            policy = ConsensusPolicy(weights, 1)
            with self.assertRaises(ValueError, msg=weights):
                locate_weighted_region(DISJOINT, policy)

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
                locate_weighted_region(DISJOINT, DISJOINT_POLICY, tolerance=bad)

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            locate_weighted_region(DISJOINT, DISJOINT_POLICY),
            locate_weighted_region(DISJOINT, DISJOINT_POLICY, tolerance=0.0),
        )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_weighted_region(DISJOINT, DISJOINT_POLICY, 0.5)


class WeightedRegionOverflowTest(unittest.TestCase):
    def test_huge_feasible_disk_raises_instead_of_overflowing(self):
        # The true rightmost bound is 2e308, beyond the finite float range.
        policy = ConsensusPolicy({"huge": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_region(
                [obs("huge", 1e308, 0.0, 1e308)], policy
            )

    def test_huge_negative_side_raises(self):
        policy = ConsensusPolicy({"huge": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_region(
                [obs("huge", -1e308, 0.0, 1e308)], policy
            )

    def test_huge_disk_below_threshold_is_empty_not_an_error(self):
        # The huge disk sits far from the small one, so no point reaches
        # the combined weight; the overflow-prone coordinates must not be
        # misread as a feasible or as an overflowing region.
        observations = [
            obs("huge", 1e308, 0.0, 1e307),
            obs("small", 0.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"huge": 1, "small": 1}, 2)
        region = locate_weighted_region(observations, policy)
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_huge_tangent_disks_have_finite_degenerate_region(self):
        # The disks meet only at the origin; the region is that one point.
        observations = [
            obs("left", -1e308, 0.0, 1e308),
            obs("right", 1e308, 0.0, 1e308),
        ]
        policy = ConsensusPolicy({"left": 1, "right": 1}, 2)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 0.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 0.0, delta=1e-9)
        self.assertAlmostEqual(min_y, 0.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 0.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, 0.0, delta=1e-9)
        self.assertAlmostEqual(wy, 0.0, delta=1e-9)

    def test_huge_finite_region_scales_back_exactly(self):
        observations = [
            obs("a", 1e307, 1e307, 2e307),
            obs("b", 1e307, 1e307, 2e307),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        region = locate_weighted_region(observations, policy)
        self.assertTrue(region.feasible)
        self.assertEqual(
            region.bounds, (-1e307, -1e307, 3e307, 3e307)
        )
        self.assertEqual(region.witness, (-1e307, 1e307))

    def test_tiny_geometry_not_swamped_by_slack(self):
        # The feasibility slack is relative to the geometry scale, so
        # disks far below 1e-12 still get exact bounds and witness.
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1e-300, 0.0, 1e-300),
        ]
        union = locate_weighted_region(
            observations, ConsensusPolicy({"a": 1, "b": 1}, 1)
        )
        self.assertTrue(union.feasible)
        self.assertEqual(union.bounds, (-1e-300, -1e-300, 2e-300, 1e-300))
        self.assertEqual(union.witness, (-1e-300, 0.0))
        lens = locate_weighted_region(
            observations, ConsensusPolicy({"a": 1, "b": 1}, 2)
        )
        self.assertTrue(lens.feasible)
        min_x, min_y, max_x, max_y = lens.bounds
        self.assertAlmostEqual(min_x, 0.0, delta=1e-309)
        self.assertAlmostEqual(max_x, 1e-300, delta=1e-309)
        self.assertAlmostEqual(min_y, -math.sqrt(3) / 2 * 1e-300, delta=1e-309)
        self.assertAlmostEqual(max_y, math.sqrt(3) / 2 * 1e-300, delta=1e-309)
        self.assertEqual(lens.witness, (0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
