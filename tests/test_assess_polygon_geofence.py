import dataclasses
import math
import unittest

from nearproof import (
    ConsensusPolicy,
    Observation,
    RangeDecision,
    assess_geofence,
    assess_polygon_geofence,
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

# Counterclockwise square over x in [-2, 6], y in [-2, 2]: contains both
# disjoint unit disks.
SQUARE = ((-2.0, -2.0), (6.0, -2.0), (6.0, 2.0), (-2.0, 2.0))

# Counterclockwise triangle containing the lens (extremes x in [1, 5],
# y in [-4, 4]) including its boundary arcs.
LENS_TRIANGLE = ((-2.0, -6.0), (8.0, -6.0), (3.0, 7.0))


class PolygonGeofenceContractTest(unittest.TestCase):
    def test_result_is_str(self):
        for vertices in (SQUARE, LENS_TRIANGLE):
            result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)
            self.assertIsInstance(result, str)
            self.assertIn(result, ("empty", "inside", "outside", "mixed"))

    def test_empty_region(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = assess_polygon_geofence(DISJOINT, policy, SQUARE)
        self.assertEqual(result, "empty")

    def test_no_minimum_observation_count(self):
        policy = ConsensusPolicy({"only": 2}, 2)
        fence = ((-3.0, -2.0), (5.0, -2.0), (5.0, 6.0), (-3.0, 6.0))
        result = assess_polygon_geofence(
            [obs("only", 1.0, 2.0, 3.0)], policy, fence
        )
        self.assertEqual(result, "inside")

    def test_accepted_flag_and_sample_count_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0, accepted=False, sample_count=99),
            obs("b", 4.0, 0.0, 1.0, accepted=False, sample_count=7),
        ]
        self.assertEqual(
            assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE),
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE),
        )


class PolygonGeofenceGeometryTest(unittest.TestCase):
    def test_inside(self):
        result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE)
        self.assertEqual(result, "inside")

    def test_inside_triangle(self):
        result = assess_polygon_geofence(LENS, LENS_POLICY, LENS_TRIANGLE)
        self.assertEqual(result, "inside")

    def test_outside(self):
        far = ((10.0, 10.0), (12.0, 10.0), (11.0, 12.0))
        result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, far)
        self.assertEqual(result, "outside")

    def test_mixed(self):
        # The fence covers disk a but not disk b.
        fence = ((-2.0, -2.0), (2.0, -2.0), (2.0, 2.0), (-2.0, 2.0))
        result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, fence)
        self.assertEqual(result, "mixed")

    def test_fence_in_gap_of_bounding_box_is_outside(self):
        # The fence sits inside the region's bounding box but entirely in
        # the gap between the two disks: the gap is not a feasible position.
        gap = ((1.5, -0.5), (2.5, -0.5), (2.5, 0.5), (1.5, 0.5))
        result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, gap)
        self.assertEqual(result, "outside")

    def test_fence_between_separated_regions_is_outside(self):
        # A diamond fence in the gap between two separated feasible
        # regions, touching neither.
        observations = [
            obs("near", 0.0, 0.0, 1.0),
            obs("far", 10.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"near": 1, "far": 1}, 1)
        diamond = ((4.5, 0.0), (5.0, 0.5), (5.5, 0.0), (5.0, -0.5))
        result = assess_polygon_geofence(observations, policy, diamond)
        self.assertEqual(result, "outside")

    def test_slanted_edge_cutting_disk_is_mixed(self):
        # A triangle whose hypotenuse cuts disk a in half.
        fence = ((-2.0, -2.0), (2.0, -2.0), (-2.0, 2.0))
        result = assess_polygon_geofence(
            [obs("a", 0.0, 0.0, 1.0)], ConsensusPolicy({"a": 1}, 1), fence
        )
        self.assertEqual(result, "mixed")

    def test_slanted_edge_just_clear_of_disk_is_inside(self):
        # The hypotenuse x + y = 2 stays at distance sqrt(2) > 1 from the
        # origin: the whole unit disk is inside.
        fence = ((-2.0, -2.0), (4.0, -2.0), (-2.0, 4.0))
        result = assess_polygon_geofence(
            [obs("a", 0.0, 0.0, 1.0)], ConsensusPolicy({"a": 1}, 1), fence
        )
        self.assertEqual(result, "inside")

    def test_slanted_edge_tangent_to_disk_is_inside(self):
        # The fence's left edge x = -1 is exactly tangent to the unit
        # disk at (-1, 0): the fence includes its boundary.
        fence = ((-1.0, -2.0), (3.0, -2.0), (-1.0, 3.0))
        result = assess_polygon_geofence(
            [obs("a", 0.0, 0.0, 1.0)], ConsensusPolicy({"a": 1}, 1), fence
        )
        self.assertEqual(result, "inside")

    def test_single_feasible_point_on_fence_vertex(self):
        # Tangent disks: the feasible set is exactly the point (3, 0),
        # which is a vertex of the fence.
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = ((3.0, 0.0), (6.0, 4.0), (0.0, 4.0))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, fence),
            "inside",
        )

    def test_single_feasible_point_on_fence_edge(self):
        # The same tangent point (3, 0) lying on a fence edge.
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = ((0.0, 0.0), (6.0, 0.0), (3.0, 4.0))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, fence),
            "inside",
        )

    def test_single_feasible_point_outside_fence(self):
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = ((4.0, 0.0), (7.0, 4.0), (1.0, 4.0))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, fence),
            "outside",
        )

    def test_lens_fence_shaved_by_one_ulp_is_mixed(self):
        # The lens rightmost point is (5, 0); a fence vertex one ulp to
        # the left of x = 5 cuts it off.
        shaved = math.nextafter(5.0, 0.0)
        fence = ((1.0, -4.0), (shaved, -4.0), (shaved, 4.0), (1.0, 4.0))
        result = assess_polygon_geofence(LENS, LENS_POLICY, fence)
        self.assertEqual(result, "mixed")

    def test_lens_fence_at_exact_extreme_is_inside(self):
        fence = ((1.0, -4.0), (5.0, -4.0), (5.0, 4.0), (1.0, 4.0))
        result = assess_polygon_geofence(LENS, LENS_POLICY, fence)
        self.assertEqual(result, "inside")

    def test_zero_radius_disk(self):
        policy = ConsensusPolicy({"pin": 1}, 1)
        observation = [obs("pin", 3.0, -2.0, 0.0)]
        self.assertEqual(
            assess_polygon_geofence(observation, policy, SQUARE),
            "inside",
        )
        far = ((10.0, 10.0), (12.0, 10.0), (11.0, 12.0))
        self.assertEqual(
            assess_polygon_geofence(observation, policy, far),
            "outside",
        )

    def test_tolerance_extends_every_radius(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = ((1.0, -1.0), (3.0, -1.0), (3.0, 1.0), (1.0, 1.0))
        self.assertEqual(assess_polygon_geofence(DISJOINT, policy, fence), "empty")
        # Radii become 2: the disks touch at (2, 0), inside the fence.
        self.assertEqual(
            assess_polygon_geofence(DISJOINT, policy, fence, tolerance=1.0),
            "inside",
        )
        self.assertEqual(
            assess_polygon_geofence(DISJOINT, policy, fence, tolerance=0.5),
            "empty",
        )

    def test_tolerance_does_not_blur_fence_boundary(self):
        # Radius 2 disk inscribed in the fence only via tolerance.
        fence = ((-2.0, -2.0), (2.0, -2.0), (2.0, 2.0), (-2.0, 2.0))
        result = assess_polygon_geofence(
            [obs("a", 0.0, 0.0, 1.0)],
            ConsensusPolicy({"a": 1}, 1),
            fence,
            tolerance=1.0,
        )
        self.assertEqual(result, "inside")
        # One ulp less tolerance: the disk stays strictly inside.
        slack = math.nextafter(1.0, 0.0)
        result = assess_polygon_geofence(
            [obs("a", 0.0, 0.0, 1.0)],
            ConsensusPolicy({"a": 1}, 1),
            fence,
            tolerance=slack,
        )
        self.assertEqual(result, "inside")

    def test_weighted_threshold_picks_heavier_side(self):
        # Only b's weight reaches the threshold: the feasible set is b's
        # disk alone, which the fence contains while a's disk is ignored.
        policy = ConsensusPolicy({"a": 1, "b": 2}, 2)
        fence = ((2.0, -2.0), (6.0, -2.0), (6.0, 2.0), (2.0, 2.0))
        result = assess_polygon_geofence(DISJOINT, policy, fence)
        self.assertEqual(result, "inside")

    def test_one_region_inside_one_outside(self):
        observations = [
            obs("near", 0.0, 0.0, 1.0),
            obs("far", 10.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"near": 1, "far": 1}, 1)
        fence = ((-2.0, -2.0), (2.0, -2.0), (2.0, 2.0), (-2.0, 2.0))
        result = assess_polygon_geofence(observations, policy, fence)
        self.assertEqual(result, "mixed")

    def test_integer_inputs_match_float_inputs(self):
        integers = [obs("a", 0, 0, 1), obs("b", 4, 0, 1)]
        int_vertices = ((-2, -2), (6, -2), (6, 2), (-2, 2))
        self.assertEqual(
            assess_polygon_geofence(integers, DISJOINT_POLICY, int_vertices),
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE),
        )

    def test_huge_coordinates_not_overflowed(self):
        # Tangent disks whose only feasible point is (1e308, 0).
        observations = [
            obs("a", 0.0, 0.0, 1e308),
            obs("b", 1.5e308, 0.0, 5e307),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        inside = ((1e308, 0.0), (1.5e308, 1e308), (5e307, 1e308))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, inside),
            "inside",
        )
        away = ((1.5e308, 0.0), (1.5e308, 1e308), (1e308, 1e308))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, away),
            "outside",
        )

    def test_tiny_coordinates_not_underflowed(self):
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1e-300, 0.0, 1e-300),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        # The lens spans x in [0, 1e-300]; a fence starting halfway holds
        # only part of it.
        half = ((0.5e-300, -1e-300), (2e-300, -1e-300), (2e-300, 1e-300), (0.5e-300, 1e-300))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, half),
            "mixed",
        )
        whole = ((-1e-300, -1e-300), (2e-300, -1e-300), (2e-300, 1e-300), (-1e-300, 1e-300))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, whole),
            "inside",
        )

    def test_matches_rectangular_geofence(self):
        # An axis-aligned rectangle given as a polygon must classify
        # exactly like assess_geofence on the matching bounds.
        rectangles = [
            (-2.0, -2.0, 6.0, 2.0),
            (1.5, -0.5, 2.5, 0.5),
            (-0.5, -0.5, 2.5, 0.5),
            (10.0, 10.0, 12.0, 12.0),
            (1.0, -4.0, 5.0, 4.0),
        ]
        for observations, policy in (
            (DISJOINT, DISJOINT_POLICY),
            (LENS, LENS_POLICY),
        ):
            for bounds in rectangles:
                min_x, min_y, max_x, max_y = bounds
                vertices = (
                    (min_x, min_y),
                    (max_x, min_y),
                    (max_x, max_y),
                    (min_x, max_y),
                )
                self.assertEqual(
                    assess_polygon_geofence(observations, policy, vertices),
                    assess_geofence(observations, policy, bounds),
                    msg=(observations, bounds),
                )


class PolygonGeofenceOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_observations_give_identical_result(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 3.0, 0.0, 10.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
        fence = ((0.0, -4.0), (6.0, -4.0), (6.0, 4.0), (0.0, 4.0))
        first = assess_polygon_geofence(observations, policy, fence)
        shuffled = [observations[2], observations[0], observations[1]]
        self.assertEqual(first, assess_polygon_geofence(shuffled, policy, fence))

    def test_weight_mapping_order_is_irrelevant(self):
        forward = ConsensusPolicy({"a": 1, "b": 2}, 2)
        backward = ConsensusPolicy({"b": 2, "a": 1}, 2)
        fence = ((2.0, -2.0), (6.0, -2.0), (6.0, 2.0), (2.0, 2.0))
        self.assertEqual(
            assess_polygon_geofence(DISJOINT, forward, fence),
            assess_polygon_geofence(DISJOINT, backward, fence),
        )

    def test_vertex_rotation_is_irrelevant(self):
        for start in range(len(SQUARE)):
            rotated = SQUARE[start:] + SQUARE[:start]
            self.assertEqual(
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, rotated),
                "inside",
            )

    def test_winding_direction_is_irrelevant(self):
        reversed_square = tuple(reversed(SQUARE))
        self.assertEqual(
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, reversed_square),
            "inside",
        )
        reversed_triangle = tuple(reversed(LENS_TRIANGLE))
        self.assertEqual(
            assess_polygon_geofence(LENS, LENS_POLICY, reversed_triangle),
            "inside",
        )

    def test_clockwise_fence(self):
        clockwise = ((-2.0, -2.0), (-2.0, 2.0), (6.0, 2.0), (6.0, -2.0))
        result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, clockwise)
        self.assertEqual(result, "inside")

    def test_generator_input(self):
        result = assess_polygon_geofence(
            iter(DISJOINT), DISJOINT_POLICY, iter(SQUARE)
        )
        self.assertEqual(result, "inside")

    def test_inputs_not_mutated(self):
        observations = list(DISJOINT)
        snapshot = list(observations)
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        weights_snapshot = dict(policy.weights)
        vertices = list(SQUARE)
        vertices_snapshot = list(vertices)
        assess_polygon_geofence(observations, policy, vertices)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])
        self.assertEqual(dict(policy.weights), weights_snapshot)
        self.assertEqual(vertices, vertices_snapshot)


class PolygonGeofenceValidationTest(unittest.TestCase):
    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(bad, DISJOINT_POLICY, SQUARE)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

    def test_empty_observations_rejected(self):
        with self.assertRaises(ValueError):
            assess_polygon_geofence([], DISJOINT_POLICY, SQUARE)

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            assess_polygon_geofence(observations, policy, SQUARE)

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(DISJOINT[0], id=bad)
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

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
                assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                DISJOINT[0], decision=decision(value)
            )
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=value):
                assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(DISJOINT[0], decision=object())
        observations = [bad_obs] + DISJOINT[1:]
        with self.assertRaises(ValueError):
            assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

    def test_non_policy_rejected(self):
        for bad in (None, 123, "policy", object(), {"a": 1, "b": 1}):
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, bad, SQUARE)

    def test_policy_ids_must_match_observation_ids(self):
        for weights in ({"a": 1}, {"a": 1, "b": 1, "c": 1}, {"a": 1, "z": 1}):
            policy = ConsensusPolicy(weights, 1)
            with self.assertRaises(ValueError, msg=weights):
                assess_polygon_geofence(DISJOINT, policy, SQUARE)

    def test_invalid_tolerance(self):
        for bad in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "0.5", None):
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(
                    DISJOINT, DISJOINT_POLICY, SQUARE, tolerance=bad
                )

    def test_non_iterable_vertices(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, bad)

    def test_non_tuple_vertex(self):
        for bad in ([0.0, 0.0], "ab", 5, None, True, object()):
            vertices = [bad] + list(SQUARE[1:])
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_vertex_wrong_length(self):
        for bad in ((1.0,), (1.0, 2.0, 3.0), ()):
            vertices = [bad] + list(SQUARE[1:])
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_vertex_non_finite_or_bool(self):
        for bad in (True, False, math.nan, math.inf, -math.inf, "1", None):
            vertices = [(bad, 0.0)] + list(SQUARE[1:])
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)
            vertices = [(0.0, bad)] + list(SQUARE[1:])
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_too_few_vertices(self):
        for vertices in ((), ((0.0, 0.0),), ((0.0, 0.0), (1.0, 1.0))):
            with self.assertRaises(ValueError, msg=vertices):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_duplicate_vertices_rejected(self):
        vertices = ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 0.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_closing_vertex_repeat_rejected(self):
        # The first vertex must not be repeated at the end.
        vertices = SQUARE + (SQUARE[0],)
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_int_float_equal_vertices_are_duplicates(self):
        vertices = ((0, 0), (4.0, 0.0), (4.0, 4.0), (0.0, 0.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_consecutive_collinear_vertices_rejected(self):
        vertices = ((0.0, 0.0), (1.0, 0.0), (2.0, 0.0), (0.0, 2.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_fully_collinear_vertices_rejected(self):
        vertices = ((0.0, 0.0), (1.0, 0.0), (2.0, 0.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_concave_vertices_rejected(self):
        # A dart: the vertex (2, 1) is reflex.
        vertices = ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (2.0, 1.0), (0.0, 4.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_self_intersecting_bowtie_rejected(self):
        vertices = ((0.0, 0.0), (4.0, 4.0), (4.0, 0.0), (0.0, 4.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_self_intersecting_star_rejected(self):
        # A pentagram turns the same way at every vertex, so only the
        # edge-crossing check can reject it.
        points = [
            (
                math.cos(math.radians(90 + 72 * k)),
                math.sin(math.radians(90 + 72 * k)),
            )
            for k in range(5)
        ]
        star = tuple(points[(2 * k) % 5] for k in range(5))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, star)

    def test_all_inputs_validated_before_classification(self):
        # The first observation alone already makes the region empty
        # against any fence, but the invalid trailing observation must
        # still be rejected.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            "not-an-observation",
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        with self.assertRaises(ValueError):
            assess_polygon_geofence(observations, policy, SQUARE)

    def test_vertices_validated_even_when_region_empty(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        with self.assertRaises(ValueError):
            assess_polygon_geofence(
                DISJOINT, policy, ((0.0, 0.0), (1.0, 0.0))
            )


if __name__ == "__main__":
    unittest.main()
