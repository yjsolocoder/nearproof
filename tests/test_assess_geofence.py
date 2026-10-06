import dataclasses
import math
import unittest

from nearproof import (
    ConsensusPolicy,
    Observation,
    RangeDecision,
    assess_geofence,
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


# Two disjoint unit disks at the origin and at (4, 0), weight 1 each:
# threshold 1 gives the union of the two disks, threshold 2 is empty.
DISJOINT = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 4.0, 0.0, 1.0),
]
DISJOINT_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 1)

# Two disks whose intersection lens has extremes x in [1, 5], y in [-4, 4]
# with circle-meeting points (3, +-4).
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
]
LENS_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 2)


class GeofenceContractTest(unittest.TestCase):
    def test_result_is_str(self):
        for bounds in ((-2.0, -2.0, 6.0, 2.0), (1.5, -0.5, 2.5, 0.5)):
            result = assess_geofence(DISJOINT, DISJOINT_POLICY, bounds)
            self.assertIsInstance(result, str)
            self.assertIn(result, ("empty", "inside", "outside", "mixed"))

    def test_empty_region(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = assess_geofence(DISJOINT, policy, (-10.0, -10.0, 10.0, 10.0))
        self.assertEqual(result, "empty")

    def test_no_minimum_observation_count(self):
        policy = ConsensusPolicy({"only": 2}, 2)
        result = assess_geofence(
            [obs("only", 1.0, 2.0, 3.0)], policy, (-3.0, -2.0, 5.0, 6.0)
        )
        self.assertEqual(result, "inside")

    def test_accepted_flag_and_sample_count_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0, accepted=False, sample_count=99),
            obs("b", 4.0, 0.0, 1.0, accepted=False, sample_count=7),
        ]
        bounds = (-2.0, -2.0, 6.0, 2.0)
        self.assertEqual(
            assess_geofence(observations, DISJOINT_POLICY, bounds),
            assess_geofence(DISJOINT, DISJOINT_POLICY, bounds),
        )


class GeofenceGeometryTest(unittest.TestCase):
    def test_inside(self):
        result = assess_geofence(DISJOINT, DISJOINT_POLICY, (-2.0, -2.0, 6.0, 2.0))
        self.assertEqual(result, "inside")

    def test_outside(self):
        result = assess_geofence(DISJOINT, DISJOINT_POLICY, (10.0, 10.0, 12.0, 12.0))
        self.assertEqual(result, "outside")

    def test_mixed(self):
        # The fence covers disk a but not disk b.
        result = assess_geofence(DISJOINT, DISJOINT_POLICY, (-2.0, -2.0, 2.0, 2.0))
        self.assertEqual(result, "mixed")

    def test_fence_in_gap_of_bounding_box_is_outside(self):
        # The fence sits inside the region's bounding box but entirely in
        # the gap between the two disks: the gap is not a feasible position.
        result = assess_geofence(DISJOINT, DISJOINT_POLICY, (1.5, -0.5, 2.5, 0.5))
        self.assertEqual(result, "outside")

    def test_fence_overlapping_gap_and_one_disk_is_mixed(self):
        result = assess_geofence(DISJOINT, DISJOINT_POLICY, (-0.5, -0.5, 2.5, 0.5))
        self.assertEqual(result, "mixed")

    def test_boundary_touch_counts_as_inside(self):
        # The unit disk inscribed in the fence: every extreme point lies
        # exactly on the fence boundary.
        result = assess_geofence(
            [obs("a", 0.0, 0.0, 1.0)],
            ConsensusPolicy({"a": 1}, 1),
            (-1.0, -1.0, 1.0, 1.0),
        )
        self.assertEqual(result, "inside")

    def test_lens_inscribed_in_fence_is_inside(self):
        # The lens touches every side of its own bounding box.
        result = assess_geofence(LENS, LENS_POLICY, (1.0, -4.0, 5.0, 4.0))
        self.assertEqual(result, "inside")

    def test_lens_fence_shaved_by_one_ulp_is_mixed(self):
        shaved = math.nextafter(5.0, 0.0)
        result = assess_geofence(LENS, LENS_POLICY, (1.0, -4.0, shaved, 4.0))
        self.assertEqual(result, "mixed")

    def test_single_feasible_point_on_fence_boundary(self):
        # Tangent disks: the feasible set is exactly the point (3, 0).
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_geofence(observations, policy, (3.0, 0.0, 5.0, 5.0)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (4.0, 0.0, 5.0, 5.0)),
            "outside",
        )

    def test_degenerate_fence_point(self):
        policy = ConsensusPolicy({"a": 1}, 1)
        self.assertEqual(
            assess_geofence([obs("a", 0.0, 0.0, 1.0)], policy, (0.5, 0.0, 0.5, 0.0)),
            "mixed",
        )
        self.assertEqual(
            assess_geofence([obs("a", 0.0, 0.0, 1.0)], policy, (5.0, 5.0, 5.0, 5.0)),
            "outside",
        )

    def test_degenerate_fence_segment(self):
        # A zero-width fence segment crossing the disk.
        result = assess_geofence(
            [obs("a", 0.0, 0.0, 2.0)],
            ConsensusPolicy({"a": 1}, 1),
            (0.0, -5.0, 0.0, 5.0),
        )
        self.assertEqual(result, "mixed")
        # A zero-width segment inside the disk does not contain it.
        result = assess_geofence(
            [obs("a", 0.0, 0.0, 2.0)],
            ConsensusPolicy({"a": 1}, 1),
            (0.0, -1.0, 0.0, 1.0),
        )
        self.assertEqual(result, "mixed")

    def test_zero_radius_disk(self):
        policy = ConsensusPolicy({"pin": 1}, 1)
        observation = [obs("pin", 3.0, -2.0, 0.0)]
        self.assertEqual(
            assess_geofence(observation, policy, (3.0, -2.0, 3.0, -2.0)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observation, policy, (0.0, 0.0, 1.0, 1.0)),
            "outside",
        )

    def test_tolerance_extends_every_radius(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = (1.0, -1.0, 3.0, 1.0)
        self.assertEqual(assess_geofence(DISJOINT, policy, fence), "empty")
        # Radii become 2: the disks touch at (2, 0), inside the fence.
        self.assertEqual(
            assess_geofence(DISJOINT, policy, fence, tolerance=1.0),
            "inside",
        )
        self.assertEqual(
            assess_geofence(DISJOINT, policy, fence, tolerance=0.5),
            "empty",
        )

    def test_tolerance_does_not_blur_fence_boundary(self):
        # Radius 2 disk inscribed in the fence only via tolerance.
        result = assess_geofence(
            [obs("a", 0.0, 0.0, 1.0)],
            ConsensusPolicy({"a": 1}, 1),
            (-2.0, -2.0, 2.0, 2.0),
            tolerance=1.0,
        )
        self.assertEqual(result, "inside")
        # One ulp less tolerance: the disk stays strictly inside.
        slack = math.nextafter(1.0, 0.0)
        result = assess_geofence(
            [obs("a", 0.0, 0.0, 1.0)],
            ConsensusPolicy({"a": 1}, 1),
            (-2.0, -2.0, 2.0, 2.0),
            tolerance=slack,
        )
        self.assertEqual(result, "inside")

    def test_weighted_threshold_picks_heavier_side(self):
        # Only b's weight reaches the threshold: the feasible set is b's
        # disk alone, which the fence contains while a's disk is ignored.
        policy = ConsensusPolicy({"a": 1, "b": 2}, 2)
        result = assess_geofence(DISJOINT, policy, (2.0, -2.0, 6.0, 2.0))
        self.assertEqual(result, "inside")

    def test_one_region_inside_one_outside(self):
        observations = [
            obs("near", 0.0, 0.0, 1.0),
            obs("far", 10.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"near": 1, "far": 1}, 1)
        result = assess_geofence(observations, policy, (-2.0, -2.0, 2.0, 2.0))
        self.assertEqual(result, "mixed")

    def test_integer_inputs_match_float_inputs(self):
        integers = [obs("a", 0, 0, 1), obs("b", 4, 0, 1)]
        for bounds in (
            (-2, -2, 6, 2),
            (1, 0, 3, 0),
            (2, -1, 3, 1),
        ):
            self.assertEqual(
                assess_geofence(integers, DISJOINT_POLICY, bounds, tolerance=0),
                assess_geofence(
                    DISJOINT,
                    DISJOINT_POLICY,
                    tuple(float(v) for v in bounds),
                    tolerance=0.0,
                ),
            )


class GeofenceOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_observations_give_identical_result(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 3.0, 0.0, 10.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        bounds = (0.0, -4.0, 6.0, 4.0)
        first = assess_geofence(observations, policy, bounds)
        shuffled = [observations[2], observations[0], observations[1]]
        self.assertEqual(first, assess_geofence(shuffled, policy, bounds))

    def test_weight_mapping_order_is_irrelevant(self):
        forward = ConsensusPolicy({"a": 1, "b": 2}, 2)
        backward = ConsensusPolicy({"b": 2, "a": 1}, 2)
        bounds = (2.0, -2.0, 6.0, 2.0)
        self.assertEqual(
            assess_geofence(DISJOINT, forward, bounds),
            assess_geofence(DISJOINT, backward, bounds),
        )

    def test_generator_input(self):
        result = assess_geofence(
            iter(DISJOINT), DISJOINT_POLICY, (-2.0, -2.0, 6.0, 2.0)
        )
        self.assertEqual(result, "inside")

    def test_inputs_not_mutated(self):
        observations = list(DISJOINT)
        snapshot = list(observations)
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        weights_snapshot = dict(policy.weights)
        bounds = (-2.0, -2.0, 6.0, 2.0)
        assess_geofence(observations, policy, bounds)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])
        self.assertEqual(dict(policy.weights), weights_snapshot)
        self.assertEqual(bounds, (-2.0, -2.0, 6.0, 2.0))


class GeofenceValidationTest(unittest.TestCase):
    BOUNDS = (-2.0, -2.0, 6.0, 2.0)

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(bad, DISJOINT_POLICY, self.BOUNDS)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(observations, DISJOINT_POLICY, self.BOUNDS)

    def test_empty_observations_rejected(self):
        with self.assertRaises(ValueError):
            assess_geofence([], DISJOINT_POLICY, self.BOUNDS)

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            assess_geofence(observations, policy, self.BOUNDS)

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(DISJOINT[0], id=bad)
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(observations, DISJOINT_POLICY, self.BOUNDS)

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
                assess_geofence(observations, DISJOINT_POLICY, self.BOUNDS)

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(DISJOINT[0], decision=decision(value))
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=value):
                assess_geofence(observations, DISJOINT_POLICY, self.BOUNDS)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(DISJOINT[0], decision=object())
        observations = [bad_obs] + DISJOINT[1:]
        with self.assertRaises(ValueError):
            assess_geofence(observations, DISJOINT_POLICY, self.BOUNDS)

    def test_trailing_invalid_observation_not_masked(self):
        # The first observation alone already determines the "inside"
        # classification; the invalid trailing element must still raise.
        bad_obs = dataclasses.replace(DISJOINT[1], x=math.nan)
        observations = [DISJOINT[0], bad_obs]
        with self.assertRaises(ValueError):
            assess_geofence(observations, DISJOINT_POLICY, self.BOUNDS)

    def test_non_policy_rejected(self):
        for bad in (None, 123, "policy", object(), {"a": 1, "b": 1}, (("a", 1),)):
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(DISJOINT, bad, self.BOUNDS)

    def test_policy_ids_must_match_observation_ids(self):
        for weights in ({"a": 1}, {"a": 1, "b": 1, "c": 1}, {"a": 1, "z": 1}):
            policy = ConsensusPolicy(weights, 1)
            with self.assertRaises(ValueError, msg=weights):
                assess_geofence(DISJOINT, policy, self.BOUNDS)

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
                assess_geofence(
                    DISJOINT, DISJOINT_POLICY, self.BOUNDS, tolerance=bad
                )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            assess_geofence(DISJOINT, DISJOINT_POLICY, self.BOUNDS, 0.5)

    def test_invalid_bounds_type(self):
        for bad in (
            None,
            123,
            "bounds",
            object(),
            [-2.0, -2.0, 6.0, 2.0],
            (-2.0, -2.0, 6.0),
            (-2.0, -2.0, 6.0, 2.0, 0.0),
            (),
        ):
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(DISJOINT, DISJOINT_POLICY, bad)

    def test_invalid_bounds_elements(self):
        for bad_element in (True, False, math.nan, math.inf, -math.inf, "1", None):
            bounds = (-2.0, -2.0, 6.0, bad_element)
            with self.assertRaises(ValueError, msg=bad_element):
                assess_geofence(DISJOINT, DISJOINT_POLICY, bounds)
            bounds = (bad_element, -2.0, 6.0, 2.0)
            with self.assertRaises(ValueError, msg=bad_element):
                assess_geofence(DISJOINT, DISJOINT_POLICY, bounds)

    def test_inverted_bounds_rejected(self):
        for bounds in (
            (6.0, -2.0, -2.0, 2.0),
            (-2.0, 2.0, 6.0, -2.0),
            (1.0, 0.0, 0.0, 0.0),
            (0.0, 1.0, 0.0, 0.0),
        ):
            with self.assertRaises(ValueError, msg=bounds):
                assess_geofence(DISJOINT, DISJOINT_POLICY, bounds)

    def test_degenerate_bounds_accepted(self):
        # Zero width, zero height, or both are valid fences.
        for bounds in ((0.0, -1.0, 0.0, 1.0), (-1.0, 0.0, 1.0, 0.0), (0.0, 0.0, 0.0, 0.0)):
            result = assess_geofence(DISJOINT, DISJOINT_POLICY, bounds)
            self.assertIn(result, ("empty", "inside", "outside", "mixed"))


class GeofenceExactnessTest(unittest.TestCase):
    def test_huge_tangent_disks(self):
        # The disks meet only at the origin: the feasible set is {(0, 0)}.
        observations = [
            obs("left", -1e308, 0.0, 1e308),
            obs("right", 1e308, 0.0, 1e308),
        ]
        policy = ConsensusPolicy({"left": 1, "right": 1}, 2)
        self.assertEqual(
            assess_geofence(observations, policy, (-1.0, -1.0, 1.0, 1.0)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (1.0, -1.0, 1e308, 1.0)),
            "outside",
        )

    def test_huge_disjoint_disks_stay_empty(self):
        observations = [
            obs("huge", 1e308, 0.0, 1e307),
            obs("small", 0.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"huge": 1, "small": 1}, 2)
        result = assess_geofence(
            observations, policy, (-1e308, -1e308, 1e308, 1e308)
        )
        self.assertEqual(result, "empty")

    def test_huge_disk_inside_huge_fence(self):
        observations = [obs("huge", 1e307, 1e307, 2e307)]
        policy = ConsensusPolicy({"huge": 1}, 1)
        self.assertEqual(
            assess_geofence(observations, policy, (-2e307, -2e307, 4e307, 4e307)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (0.0, 0.0, 4e307, 4e307)),
            "mixed",
        )

    def test_huge_fence_boundary_not_blurred(self):
        # The represented value of 1e307 + 2e307 exceeds the represented
        # 3e307 by one ulp, so the disk pokes exactly that far out of the
        # fence: exact geometry reports "mixed", never a blurred "inside".
        observations = [obs("huge", 1e307, 1e307, 2e307)]
        policy = ConsensusPolicy({"huge": 1}, 1)
        self.assertEqual(
            assess_geofence(observations, policy, (-1e307, -1e307, 3e307, 3e307)),
            "mixed",
        )

    def test_tiny_geometry_not_swamped(self):
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1e-300, 0.0, 1e-300),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_geofence(
                observations, policy, (-1e-300, -1e-300, 2e-300, 1e-300)
            ),
            "inside",
        )
        # The lens spans x in [0, 1e-300]: a fence starting halfway holds
        # only part of it.
        self.assertEqual(
            assess_geofence(
                observations, policy, (0.5e-300, -1e-300, 2e-300, 1e-300)
            ),
            "mixed",
        )
        self.assertEqual(
            assess_geofence(
                observations, policy, (2e-300, -1e-300, 3e-300, 1e-300)
            ),
            "outside",
        )


if __name__ == "__main__":
    unittest.main()
