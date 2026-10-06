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
# threshold 1 gives the two-disk union, threshold 2 the empty set.
DISJOINT = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 4.0, 0.0, 1.0),
]
DISJOINT_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 1)

# One unit disk at the origin.
UNIT = [obs("a", 0.0, 0.0, 1.0)]
UNIT_POLICY = ConsensusPolicy({"a": 1}, 1)


class GeofenceResultTest(unittest.TestCase):
    def test_result_is_plain_string(self):
        result = assess_geofence(UNIT, UNIT_POLICY, (-2.0, -2.0, 2.0, 2.0))
        self.assertIsInstance(result, str)
        self.assertEqual(result, "inside")

    def test_inside_when_region_within_fence(self):
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (-2.0, -2.0, 2.0, 2.0)),
            "inside",
        )

    def test_outside_when_region_misses_fence(self):
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (2.0, -2.0, 4.0, 2.0)),
            "outside",
        )

    def test_mixed_when_region_straddles_fence(self):
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (0.5, -0.5, 2.0, 2.0)),
            "mixed",
        )

    def test_empty_region_reports_empty(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        for fence in (
            (-10.0, -10.0, 10.0, 10.0),
            (1.5, -0.5, 2.5, 0.5),
            (0.0, 0.0, 0.0, 0.0),
        ):
            self.assertEqual(
                assess_geofence(DISJOINT, policy, fence), "empty", msg=fence
            )

    def test_boundary_touch_counts_as_inside(self):
        # Two tangent disks with threshold 2: the region is the single
        # tangent point (3, 0), which lies on the fence's left edge.
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_geofence(observations, policy, (3.0, -1.0, 5.0, 1.0)),
            "inside",
        )
        # A fence strictly past the tangent point misses the region.
        self.assertEqual(
            assess_geofence(observations, policy, (3.1, -1.0, 5.0, 1.0)),
            "outside",
        )

    def test_extended_region_touching_fence_is_mixed(self):
        # The unit disk touches the fence's left edge at (1, 0) but
        # extends beyond it, so both sides have feasible points.
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (1.0, -2.0, 3.0, 2.0)),
            "mixed",
        )

    def test_fence_corner_touch_counts_as_inside(self):
        # A zero-radius disk pinned at the fence's corner.
        pin = [obs("pin", 1.0, 0.0, 0.0)]
        policy = ConsensusPolicy({"pin": 1}, 1)
        self.assertEqual(
            assess_geofence(pin, policy, (1.0, 0.0, 3.0, 2.0)), "inside"
        )

    def test_degenerate_point_fence_outside(self):
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (2.0, 0.0, 2.0, 0.0)),
            "outside",
        )

    def test_degenerate_segment_fence(self):
        # A horizontal segment through the disk: the disk extends above
        # and below it, so both sides of the fence have feasible points.
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (-2.0, 0.0, 2.0, 0.0)),
            "mixed",
        )
        # A zero-radius disk pinned on the segment is entirely inside.
        pin = [obs("pin", 1.0, 0.0, 0.0)]
        policy = ConsensusPolicy({"pin": 1}, 1)
        self.assertEqual(
            assess_geofence(pin, policy, (-2.0, 0.0, 2.0, 0.0)), "inside"
        )

    def test_disjoint_disks_fence_in_gap_is_outside(self):
        # The fence sits fully inside the region's bounding box but in
        # the gap between the two disks: no feasible point lies in it.
        self.assertEqual(
            assess_geofence(DISJOINT, DISJOINT_POLICY, (1.5, -0.5, 2.5, 0.5)),
            "outside",
        )

    def test_disjoint_disks_one_inside_one_outside_is_mixed(self):
        # The fence covers disk a only; disk b is strictly outside.
        self.assertEqual(
            assess_geofence(DISJOINT, DISJOINT_POLICY, (-2.0, -2.0, 1.5, 2.0)),
            "mixed",
        )

    def test_disjoint_disks_both_inside(self):
        self.assertEqual(
            assess_geofence(DISJOINT, DISJOINT_POLICY, (-2.0, -2.0, 6.0, 2.0)),
            "inside",
        )

    def test_disjoint_disks_both_outside(self):
        self.assertEqual(
            assess_geofence(DISJOINT, DISJOINT_POLICY, (6.0, 3.0, 8.0, 5.0)),
            "outside",
        )

    def test_lens_region_from_threshold(self):
        # Two radius-5 disks six units apart; threshold 2 gives the lens
        # with extremes x in [1, 5] and y in [-4, 4].
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_geofence(observations, policy, (1.0, -4.0, 5.0, 4.0)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (2.0, -4.0, 5.0, 4.0)),
            "mixed",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (6.0, 0.0, 9.0, 1.0)),
            "outside",
        )

    def test_weighted_threshold_picks_heavier_side(self):
        # Only disk b's weight reaches the threshold.
        policy = ConsensusPolicy({"a": 1, "b": 2}, 2)
        self.assertEqual(
            assess_geofence(DISJOINT, policy, (-2.0, -2.0, 1.5, 2.0)),
            "outside",
        )
        self.assertEqual(
            assess_geofence(DISJOINT, policy, (3.0, -1.0, 5.0, 1.0)),
            "inside",
        )

    def test_accepted_flag_and_sample_count_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0, accepted=False, sample_count=0),
            obs("b", 4.0, 0.0, 1.0, accepted=False, sample_count=99),
        ]
        self.assertEqual(
            assess_geofence(observations, DISJOINT_POLICY, (-2.0, -2.0, 6.0, 2.0)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, DISJOINT_POLICY, (1.5, -0.5, 2.5, 0.5)),
            "outside",
        )

    def test_tolerance_extends_disks_into_fence(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = (2.0, 0.0, 2.0, 0.0)
        # Without tolerance the disks are disjoint (empty region); with
        # tolerance 1 both radii become 2 and they touch at (2, 0).
        self.assertEqual(assess_geofence(DISJOINT, policy, fence), "empty")
        self.assertEqual(
            assess_geofence(DISJOINT, policy, fence, tolerance=1.0), "inside"
        )

    def test_tolerance_does_not_blur_fence_boundary(self):
        # With tolerance 1 both radii become 2 and the disks touch
        # exactly at (2, 0): a fence through that point has a feasible
        # point inside, a fence one step further right does not.
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_geofence(DISJOINT, policy, (2.0, -1.0, 2.0, 1.0), tolerance=1.0),
            "inside",
        )
        self.assertEqual(
            assess_geofence(DISJOINT, policy, (2.1, -1.0, 3.0, 1.0), tolerance=1.0),
            "outside",
        )

    def test_integer_inputs_match_float_inputs(self):
        integers = [obs("a", 0, 0, 1), obs("b", 4, 0, 1)]
        for fence in ((-2, -2, 6, 2), (1, 0, 3, 0), (5, 0, 6, 0)):
            self.assertEqual(
                assess_geofence(integers, DISJOINT_POLICY, fence, tolerance=1),
                assess_geofence(DISJOINT, DISJOINT_POLICY, fence, tolerance=1.0),
            )


class GeofenceOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_observations_give_identical_result(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 3.0, 0.0, 10.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        fence = (1.0, -4.0, 5.0, 4.0)
        first = assess_geofence(observations, policy, fence)
        shuffled = [observations[2], observations[0], observations[1]]
        self.assertEqual(first, assess_geofence(shuffled, policy, fence))

    def test_weight_mapping_order_is_irrelevant(self):
        forward = ConsensusPolicy({"a": 1, "b": 2}, 2)
        backward = ConsensusPolicy({"b": 2, "a": 1}, 2)
        fence = (0.0, -2.0, 4.0, 2.0)
        self.assertEqual(
            assess_geofence(DISJOINT, forward, fence),
            assess_geofence(DISJOINT, backward, fence),
        )

    def test_generator_input(self):
        self.assertEqual(
            assess_geofence(iter(DISJOINT), DISJOINT_POLICY, (-2.0, -2.0, 6.0, 2.0)),
            "inside",
        )

    def test_inputs_not_mutated(self):
        observations = list(DISJOINT)
        snapshot = list(observations)
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        weights_snapshot = dict(policy.weights)
        fence = (-2.0, -2.0, 6.0, 2.0)
        assess_geofence(observations, policy, fence)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])
        self.assertEqual(dict(policy.weights), weights_snapshot)


class GeofenceValidationTest(unittest.TestCase):
    FENCE = (-2.0, -2.0, 2.0, 2.0)

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(bad, DISJOINT_POLICY, self.FENCE)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(observations, DISJOINT_POLICY, self.FENCE)

    def test_empty_observations_rejected(self):
        with self.assertRaises(ValueError):
            assess_geofence([], DISJOINT_POLICY, self.FENCE)

    def test_trailing_invalid_observation_not_masked(self):
        # The first two observations alone already determine an "inside"
        # result; the invalid trailing element must still be rejected.
        observations = DISJOINT + [obs("a", 0.0, 0.0, 1.0)]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        with self.assertRaises(ValueError):
            assess_geofence(observations, policy, (-2.0, -2.0, 6.0, 2.0))

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            assess_geofence(observations, policy, self.FENCE)

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(DISJOINT[0], id=bad)
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(observations, DISJOINT_POLICY, self.FENCE)

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
                assess_geofence(observations, DISJOINT_POLICY, self.FENCE)

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(DISJOINT[0], decision=decision(value))
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=value):
                assess_geofence(observations, DISJOINT_POLICY, self.FENCE)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(DISJOINT[0], decision=object())
        observations = [bad_obs] + DISJOINT[1:]
        with self.assertRaises(ValueError):
            assess_geofence(observations, DISJOINT_POLICY, self.FENCE)

    def test_non_policy_rejected(self):
        for bad in (None, 123, "policy", object(), {"a": 1, "b": 1}, (("a", 1),)):
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(DISJOINT, bad, self.FENCE)

    def test_policy_ids_must_match_observation_ids(self):
        for weights in ({"a": 1}, {"a": 1, "b": 1, "c": 1}, {"a": 1, "z": 1}):
            policy = ConsensusPolicy(weights, 1)
            with self.assertRaises(ValueError, msg=weights):
                assess_geofence(DISJOINT, policy, self.FENCE)

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
                assess_geofence(DISJOINT, DISJOINT_POLICY, self.FENCE, tolerance=bad)

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            assess_geofence(DISJOINT, DISJOINT_POLICY, self.FENCE, 0.5)

    def test_invalid_bounds_shape(self):
        for bad in (
            None,
            123,
            "bounds",
            object(),
            [0.0, 0.0, 1.0, 1.0],
            (0.0, 0.0, 1.0),
            (0.0, 0.0, 1.0, 1.0, 1.0),
            (),
        ):
            with self.assertRaises(ValueError, msg=bad):
                assess_geofence(DISJOINT, DISJOINT_POLICY, bad)

    def test_invalid_bounds_values(self):
        for value in (True, False, math.nan, math.inf, -math.inf, "1", None):
            fence = (0.0, 0.0, 1.0, 1.0)
            for index in range(4):
                bad = fence[:index] + (value,) + fence[index + 1 :]
                with self.assertRaises(ValueError, msg=(index, value)):
                    assess_geofence(DISJOINT, DISJOINT_POLICY, bad)

    def test_reversed_bounds_rejected(self):
        for fence in (
            (2.0, 0.0, 1.0, 1.0),
            (0.0, 2.0, 1.0, 1.0),
            (1.0, 1.0, 0.0, 0.0),
        ):
            with self.assertRaises(ValueError, msg=fence):
                assess_geofence(DISJOINT, DISJOINT_POLICY, fence)

    def test_degenerate_bounds_accepted(self):
        # Equal min/max on one or both axes is a valid segment or point.
        pin = [obs("pin", 0.0, 0.0, 0.0)]
        policy = ConsensusPolicy({"pin": 1}, 1)
        self.assertEqual(
            assess_geofence(pin, policy, (0.0, 0.0, 0.0, 0.0)), "inside"
        )
        # The unit disk covers the point fence but extends beyond it.
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (0.0, 0.0, 0.0, 0.0)), "mixed"
        )
        self.assertEqual(
            assess_geofence(UNIT, UNIT_POLICY, (0.0, -2.0, 0.0, 2.0)), "mixed"
        )


class GeofenceExactnessTest(unittest.TestCase):
    def test_huge_tangent_disks_classified_exactly(self):
        # The disks meet only at the origin; the region is that point.
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
            assess_geofence(observations, policy, (0.0, -1.0, 1.0, 1.0)),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (1e307, -1.0, 1e308, 1.0)),
            "outside",
        )

    def test_huge_radius_sum_does_not_overflow(self):
        # bound + tolerance overflows the float range; the exact radius
        # is 2e308, so the far fence point at 1.5e308 is covered (and
        # the disk still extends beyond the fence).
        observations = [obs("huge", 0.0, 0.0, 1e308)]
        policy = ConsensusPolicy({"huge": 1}, 1)
        fence = (1.5e308, 0.0, 1.5e308, 0.0)
        self.assertEqual(
            assess_geofence(observations, policy, fence, tolerance=1e308),
            "mixed",
        )
        # Without tolerance the radius is 1e308 and the same fence point
        # lies strictly beyond it — the overflowed radius must not be
        # read as infinite.
        self.assertEqual(
            assess_geofence(observations, policy, fence), "outside"
        )

    def test_huge_disk_far_from_small_fence(self):
        observations = [
            obs("huge", 1e308, 0.0, 1e307),
            obs("small", 0.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"huge": 1, "small": 1}, 1)
        self.assertEqual(
            assess_geofence(observations, policy, (-2.0, -2.0, 2.0, 2.0)),
            "mixed",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (2.0, 2.0, 3.0, 3.0)),
            "outside",
        )

    def test_tiny_geometry_not_swamped(self):
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1e-300, 0.0, 1e-300),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        # The lens spans x in [0, 1e-300].
        self.assertEqual(
            assess_geofence(
                observations, policy, (-1e-300, -1e-300, 2e-300, 1e-300)
            ),
            "inside",
        )
        self.assertEqual(
            assess_geofence(observations, policy, (2e-300, 0.0, 3e-300, 1e-300)),
            "outside",
        )
        self.assertEqual(
            assess_geofence(
                observations, policy, (0.5e-300, -1e-300, 2e-300, 1e-300)
            ),
            "mixed",
        )

    def test_exact_boundary_not_rounded(self):
        # A zero-radius disk pinned at an irrational-looking coordinate:
        # the fence point at the exact same float is inside, the fence
        # point one ulp further right is strictly outside.
        x = math.sqrt(2.0)
        pin = [obs("pin", x, 0.0, 0.0)]
        policy = ConsensusPolicy({"pin": 1}, 1)
        self.assertEqual(
            assess_geofence(pin, policy, (x, 0.0, x, 0.0)), "inside"
        )
        self.assertEqual(
            assess_geofence(
                pin, policy, (math.nextafter(x, math.inf), 0.0, 2.0, 0.0)
            ),
            "outside",
        )


if __name__ == "__main__":
    unittest.main()
