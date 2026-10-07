import dataclasses
import math
import unittest

from nearproof import (
    ConsensusPolicy,
    Observation,
    RangeDecision,
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

# Counterclockwise unit square and its clockwise twin.
SQUARE = ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 4.0))
SQUARE_CW = SQUARE[::-1]

# Diamond with rational inradius 12/5 = 2.4 (edges 4x + 3y = +-12).
DIAMOND = ((3.0, 0.0), (0.0, 4.0), (-3.0, 0.0), (0.0, -4.0))


class PolygonGeofenceContractTest(unittest.TestCase):
    def test_result_is_str(self):
        for vertices in (SQUARE, DIAMOND):
            result = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)
            self.assertIsInstance(result, str)
            self.assertIn(result, ("empty", "inside", "outside", "mixed"))

    def test_empty_region(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        result = assess_polygon_geofence(DISJOINT, policy, SQUARE)
        self.assertEqual(result, "empty")

    def test_no_minimum_observation_count(self):
        policy = ConsensusPolicy({"only": 2}, 2)
        result = assess_polygon_geofence(
            [obs("only", 1.0, 2.0, 1.0)], policy, SQUARE
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
        result = assess_polygon_geofence(
            DISJOINT, DISJOINT_POLICY, ((-2.0, -2.0), (6.0, -2.0), (6.0, 2.0), (-2.0, 2.0))
        )
        self.assertEqual(result, "inside")

    def test_outside(self):
        result = assess_polygon_geofence(
            DISJOINT,
            DISJOINT_POLICY,
            ((10.0, 10.0), (12.0, 10.0), (12.0, 12.0), (10.0, 12.0)),
        )
        self.assertEqual(result, "outside")

    def test_mixed(self):
        # The fence covers disk a but not disk b.
        result = assess_polygon_geofence(
            DISJOINT, DISJOINT_POLICY, ((-2.0, -2.0), (2.0, -2.0), (2.0, 2.0), (-2.0, 2.0))
        )
        self.assertEqual(result, "mixed")

    def test_fence_in_gap_of_bounding_box_is_outside(self):
        # The fence sits inside the region's bounding box but entirely in
        # the gap between the two disks: the gap is not a feasible position.
        result = assess_polygon_geofence(
            DISJOINT,
            DISJOINT_POLICY,
            ((1.5, -0.5), (2.5, -0.5), (2.5, 0.5), (1.5, 0.5)),
        )
        self.assertEqual(result, "outside")

    def test_fence_between_separated_regions_is_outside(self):
        # A triangle fence in the gap between two separated feasible
        # regions, touching neither.
        observations = [
            obs("near", 0.0, 0.0, 1.0),
            obs("far", 10.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"near": 1, "far": 1}, 1)
        fence = ((4.0, -0.5), (6.0, -0.5), (5.0, 0.5))
        self.assertEqual(assess_polygon_geofence(observations, policy, fence), "outside")

    def test_one_region_inside_one_outside(self):
        observations = [
            obs("near", 0.0, 0.0, 1.0),
            obs("far", 10.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"near": 1, "far": 1}, 1)
        self.assertEqual(
            assess_polygon_geofence(observations, policy, SQUARE),
            "mixed",
        )

    def test_triangle_fence(self):
        triangle = ((0.0, 0.0), (6.0, 0.0), (0.0, 6.0))
        policy = ConsensusPolicy({"a": 1}, 1)
        self.assertEqual(
            assess_polygon_geofence([obs("a", 1.0, 1.0, 0.5)], policy, triangle),
            "inside",
        )
        # The disk straddles the hypotenuse x + y = 6.
        self.assertEqual(
            assess_polygon_geofence([obs("a", 3.0, 3.0, 1.0)], policy, triangle),
            "mixed",
        )

    def test_slanted_edge_normal_extreme(self):
        # Every axis-extreme of the disk lies inside the triangle, yet the
        # disk pokes past the hypotenuse x + y = 10 (distance sqrt(2)).
        triangle = ((0.0, 0.0), (10.0, 0.0), (0.0, 10.0))
        policy = ConsensusPolicy({"a": 1}, 1)
        self.assertEqual(
            assess_polygon_geofence([obs("a", 4.0, 4.0, 1.5)], policy, triangle),
            "mixed",
        )
        self.assertEqual(
            assess_polygon_geofence([obs("a", 4.0, 4.0, 1.4)], policy, triangle),
            "inside",
        )

    def test_inscribed_disk_on_slanted_edges_is_inside(self):
        # The radius-2.4 disk is tangent to all four diamond edges.
        result = assess_polygon_geofence(
            [obs("a", 0.0, 0.0, 2.4)], ConsensusPolicy({"a": 1}, 1), DIAMOND
        )
        self.assertEqual(result, "inside")

    def test_single_feasible_point_on_fence_boundary(self):
        # Tangent disks: the feasible set is exactly the point (3, 0),
        # which is a vertex of the fence.
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_polygon_geofence(
                observations, policy, ((3.0, 0.0), (8.0, 0.0), (3.0, 5.0))
            ),
            "inside",
        )
        self.assertEqual(
            assess_polygon_geofence(
                observations, policy, ((4.0, 0.0), (8.0, 0.0), (4.0, 5.0))
            ),
            "outside",
        )

    def test_single_feasible_point_on_slanted_edge(self):
        # The unique feasible point (3, 0) lies in the interior of the
        # slanted edge from (1, -2) to (5, 2).
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = ((1.0, -2.0), (5.0, 2.0), (1.0, 6.0))
        self.assertEqual(assess_polygon_geofence(observations, policy, fence), "inside")

    def test_zero_radius_disk(self):
        policy = ConsensusPolicy({"pin": 1}, 1)
        observation = [obs("pin", 3.0, -2.0, 0.0)]
        self.assertEqual(
            assess_polygon_geofence(
                observation, policy, ((3.0, -2.0), (5.0, -2.0), (3.0, 0.0))
            ),
            "inside",
        )
        self.assertEqual(
            assess_polygon_geofence(
                observation, policy, ((0.0, 0.0), (1.0, 0.0), (0.0, 1.0))
            ),
            "outside",
        )

    def test_tolerance_extends_every_radius(self):
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        fence = ((0.0, -1.0), (4.0, -1.0), (4.0, 1.0), (0.0, 1.0))
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
        # Radius 2.4 disk inscribed in the diamond only via tolerance.
        policy = ConsensusPolicy({"a": 1}, 1)
        self.assertEqual(
            assess_polygon_geofence(
                [obs("a", 0.0, 0.0, 1.4)], policy, DIAMOND, tolerance=1.0
            ),
            "inside",
        )
        # One ulp more tolerance: the disk pokes out of the fence.
        slack = math.nextafter(1.0, math.inf)
        self.assertEqual(
            assess_polygon_geofence(
                [obs("a", 0.0, 0.0, 1.4)], policy, DIAMOND, tolerance=slack
            ),
            "mixed",
        )

    def test_weighted_threshold_picks_heavier_side(self):
        # Only b's weight reaches the threshold: the feasible set is b's
        # disk alone, which the fence contains while a's disk is ignored.
        policy = ConsensusPolicy({"a": 1, "b": 2}, 2)
        fence = ((2.0, -2.0), (6.0, -2.0), (6.0, 2.0), (2.0, 2.0))
        self.assertEqual(
            assess_polygon_geofence(DISJOINT, policy, fence), "inside"
        )

    def test_integer_inputs_match_float_inputs(self):
        integers = [obs("a", 0, 0, 1), obs("b", 4, 0, 1)]
        vertices_int = ((-2, -2), (6, -2), (6, 2), (-2, 2))
        vertices_float = tuple(
            (float(x), float(y)) for x, y in vertices_int
        )
        self.assertEqual(
            assess_polygon_geofence(
                integers, DISJOINT_POLICY, vertices_int, tolerance=0
            ),
            assess_polygon_geofence(
                DISJOINT, DISJOINT_POLICY, vertices_float, tolerance=0.0
            ),
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

    def test_winding_direction_is_irrelevant(self):
        result_ccw = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE)
        result_cw = assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE_CW)
        self.assertEqual(result_ccw, result_cw)

    def test_starting_vertex_is_irrelevant(self):
        rotated = SQUARE[1:] + SQUARE[:1]
        self.assertEqual(
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE),
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, rotated),
        )

    def test_generator_input(self):
        result = assess_polygon_geofence(
            iter(DISJOINT), DISJOINT_POLICY, iter(SQUARE)
        )
        self.assertIsInstance(result, str)

    def test_inputs_not_mutated(self):
        observations = list(DISJOINT)
        snapshot = list(observations)
        policy = ConsensusPolicy({"a": 1, "b": 1}, 1)
        weights_snapshot = dict(policy.weights)
        vertices = [vertex for vertex in SQUARE]
        assess_polygon_geofence(observations, policy, vertices)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])
        self.assertEqual(dict(policy.weights), weights_snapshot)
        self.assertEqual(vertices, list(SQUARE))


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
            ("x", math.nan),
            ("x", math.inf),
            ("y", False),
            ("y", math.nan),
            ("y", -math.inf),
        ):
            bad_obs = dataclasses.replace(DISJOINT[0], **{field: value})
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=(field, value)):
                assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

    def test_invalid_upper_bound(self):
        for value in (True, -0.1, -1, math.nan, math.inf, "1", None):
            bad_obs = dataclasses.replace(DISJOINT[0], decision=decision(value))
            observations = [bad_obs] + DISJOINT[1:]
            with self.assertRaises(ValueError, msg=value):
                assess_polygon_geofence(observations, DISJOINT_POLICY, SQUARE)

    def test_trailing_invalid_observation_not_masked(self):
        # The first observation alone already determines the "inside"
        # classification; the invalid trailing element must still raise.
        bad_obs = dataclasses.replace(DISJOINT[1], x=math.nan)
        observations = [DISJOINT[0], bad_obs]
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
        for bad in (True, False, -0.1, -1, math.nan, math.inf, "0.5", None):
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(
                    DISJOINT, DISJOINT_POLICY, SQUARE, tolerance=bad
                )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, SQUARE, 0.5)

    def test_non_iterable_vertices(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, bad)

    def test_too_few_vertices(self):
        for vertices in ((), ((0.0, 0.0),), ((0.0, 0.0), (1.0, 0.0))):
            with self.assertRaises(ValueError, msg=vertices):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_vertex_not_a_pair_tuple(self):
        for bad_vertex in (
            [0.0, 0.0],
            (0.0,),
            (0.0, 0.0, 0.0),
            "ab",
            None,
            0.0,
        ):
            vertices = (bad_vertex, (1.0, 0.0), (0.0, 1.0))
            with self.assertRaises(ValueError, msg=bad_vertex):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_invalid_vertex_coordinates(self):
        for bad_element in (True, False, math.nan, math.inf, -math.inf, "1", None):
            vertices = ((0.0, 0.0), (1.0, 0.0), (0.0, bad_element))
            with self.assertRaises(ValueError, msg=bad_element):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_duplicate_vertices_rejected(self):
        for vertices in (
            ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 4.0), (0.0, 0.0)),
            ((0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 0.0)),
            ((0, 0), (1, 0), (0, 1), (1.0, 0.0)),
        ):
            with self.assertRaises(ValueError, msg=vertices):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_consecutive_collinear_rejected(self):
        for vertices in (
            ((0.0, 0.0), (2.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 4.0)),
            ((0.0, 0.0), (1.0, 0.0), (2.0, 0.0)),
            # The collinear triple wraps around the end of the list.
            ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 4.0), (0.0, 2.0)),
        ):
            with self.assertRaises(ValueError, msg=vertices):
                assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_concave_rejected(self):
        vertices = ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (2.0, 1.0), (0.0, 4.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, vertices)

    def test_self_intersecting_rejected(self):
        bowtie = ((0.0, 0.0), (2.0, 2.0), (2.0, 0.0), (0.0, 2.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, bowtie)
        # A pentagram turns the same way at every vertex yet self-intersects.
        pentagram = tuple(
            (math.cos(math.pi / 2 + 4 * math.pi * k / 5),
             math.sin(math.pi / 2 + 4 * math.pi * k / 5))
            for k in range(5)
        )
        with self.assertRaises(ValueError):
            assess_polygon_geofence(DISJOINT, DISJOINT_POLICY, pentagram)

    def test_trailing_invalid_vertex_not_masked(self):
        # The single observation already determines the "inside"
        # classification; the invalid trailing vertex must still raise.
        observations = [obs("a", 2.0, 2.0, 0.5)]
        policy = ConsensusPolicy({"a": 1}, 1)
        vertices = ((0.0, 0.0), (4.0, 0.0), (4.0, 4.0), (0.0, 4.0), (math.inf, 0.0))
        with self.assertRaises(ValueError):
            assess_polygon_geofence(observations, policy, vertices)

    def test_valid_fences_accepted(self):
        hexagon = tuple(
            (math.cos(math.pi * k / 3), math.sin(math.pi * k / 3))
            for k in range(6)
        )
        policy = ConsensusPolicy({"a": 1}, 1)
        for vertices in (SQUARE, SQUARE_CW, DIAMOND, hexagon):
            result = assess_polygon_geofence(
                [obs("a", 0.0, 0.0, 0.5)], policy, vertices
            )
            self.assertIn(result, ("empty", "inside", "outside", "mixed"))


class PolygonGeofenceExactnessTest(unittest.TestCase):
    def test_huge_tangent_disks(self):
        # The disks meet only at the origin: the feasible set is {(0, 0)}.
        observations = [
            obs("left", -1e308, 0.0, 1e308),
            obs("right", 1e308, 0.0, 1e308),
        ]
        policy = ConsensusPolicy({"left": 1, "right": 1}, 2)
        self.assertEqual(
            assess_polygon_geofence(
                observations, policy, ((-1.0, -1.0), (1.0, -1.0), (1.0, 1.0), (-1.0, 1.0))
            ),
            "inside",
        )
        self.assertEqual(
            assess_polygon_geofence(
                observations,
                policy,
                ((1.0, -1.0), (1e308, -1.0), (1e308, 1.0), (1.0, 1.0)),
            ),
            "outside",
        )

    def test_huge_disjoint_disks_stay_empty(self):
        observations = [
            obs("huge", 1e308, 0.0, 1e307),
            obs("small", 0.0, 0.0, 1.0),
        ]
        policy = ConsensusPolicy({"huge": 1, "small": 1}, 2)
        fence = ((-1e308, -1e308), (1e308, -1e308), (1e308, 1e308), (-1e308, 1e308))
        self.assertEqual(assess_polygon_geofence(observations, policy, fence), "empty")

    def test_huge_disk_inside_huge_fence(self):
        observations = [obs("huge", 1e307, 1e307, 2e307)]
        policy = ConsensusPolicy({"huge": 1}, 1)
        self.assertEqual(
            assess_polygon_geofence(
                observations,
                policy,
                ((-2e307, -2e307), (4e307, -2e307), (4e307, 4e307), (-2e307, 4e307)),
            ),
            "inside",
        )

    def test_huge_fence_boundary_not_blurred(self):
        # The represented value of 1e307 + 2e307 exceeds the represented
        # 3e307 by one ulp, so the disk pokes exactly that far out of the
        # fence: exact geometry reports "mixed", never a blurred "inside".
        observations = [obs("huge", 1e307, 1e307, 2e307)]
        policy = ConsensusPolicy({"huge": 1}, 1)
        fence = ((-1e307, -1e307), (3e307, -1e307), (3e307, 3e307), (-1e307, 3e307))
        self.assertEqual(
            assess_polygon_geofence(observations, policy, fence), "mixed"
        )

    def test_tiny_geometry_not_swamped(self):
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1e-300, 0.0, 1e-300),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            assess_polygon_geofence(
                observations,
                policy,
                ((-1e-300, -1e-300), (2e-300, -1e-300), (2e-300, 1e-300), (-1e-300, 1e-300)),
            ),
            "inside",
        )
        self.assertEqual(
            assess_polygon_geofence(
                observations,
                policy,
                ((0.5e-300, -1e-300), (2e-300, -1e-300), (2e-300, 1e-300), (0.5e-300, 1e-300)),
            ),
            "mixed",
        )
        self.assertEqual(
            assess_polygon_geofence(
                observations,
                policy,
                ((2e-300, -1e-300), (3e-300, -1e-300), (3e-300, 1e-300), (2e-300, 1e-300)),
            ),
            "outside",
        )

    def test_one_ulp_past_slanted_edge_is_mixed(self):
        # The radius-2.4 disk is inscribed in the diamond; one ulp more
        # radius makes it poke through all four slanted edges.
        policy_inside = ConsensusPolicy({"a": 1}, 1)
        self.assertEqual(
            assess_polygon_geofence(
                [obs("a", 0.0, 0.0, 2.4)], policy_inside, DIAMOND
            ),
            "inside",
        )
        bigger = math.nextafter(2.4, math.inf)
        self.assertEqual(
            assess_polygon_geofence(
                [obs("a", 0.0, 0.0, bigger)], policy_inside, DIAMOND
            ),
            "mixed",
        )

    def test_vertex_shaved_by_one_ulp_is_mixed(self):
        # Shaving one diamond vertex by one ulp lowers the inradius below
        # the disk radius: exact geometry reports "mixed".
        shaved = math.nextafter(3.0, 0.0)
        fence = ((shaved, 0.0), (0.0, 4.0), (-3.0, 0.0), (0.0, -4.0))
        self.assertEqual(
            assess_polygon_geofence(
                [obs("a", 0.0, 0.0, 2.4)], ConsensusPolicy({"a": 1}, 1), fence
            ),
            "mixed",
        )


if __name__ == "__main__":
    unittest.main()
