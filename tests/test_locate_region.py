import dataclasses
import math
import unittest

from nearproof import (
    Observation,
    RangeDecision,
    RegionDecision,
    locate_region,
)


def decision(upper_bound, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True):
    return Observation(
        id=ident, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


# Two overlapping radius-5 disks plus a wide third disk containing their
# lens: intersection bounds (3, -3) .. (5, 3), leftmost point (3, 0).
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 8.0, 0.0, 5.0),
    obs("c", 4.0, 0.0, 10.0),
]


class RegionContractTest(unittest.TestCase):
    def test_region_decision_is_frozen(self):
        region = locate_region(LENS)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            region.feasible = False

    def test_fields(self):
        region = locate_region(LENS)
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

    def test_infeasible_fields(self):
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 1.0),
                obs("b", 10.0, 0.0, 1.0),
                obs("c", 5.0, 20.0, 1.0),
            ]
        )
        self.assertIs(region.feasible, False)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)


class LocateRegionGeometryTest(unittest.TestCase):
    def assertClose(self, actual, expected):
        self.assertAlmostEqual(actual, expected, delta=1e-9)

    def test_lens_bounds_and_witness(self):
        region = locate_region(LENS)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        # Left edge is b's own leftmost point (3, 0), right edge a's
        # rightmost (5, 0), top/bottom the two circle vertices (4, +/-3).
        self.assertClose(min_x, 3.0)
        self.assertClose(min_y, -3.0)
        self.assertClose(max_x, 5.0)
        self.assertClose(max_y, 3.0)
        wx, wy = region.witness
        self.assertClose(wx, 3.0)
        self.assertClose(wy, 0.0)

    def test_single_disk_dominates(self):
        # a's disk lies inside both others, so the region is a's disk.
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 2.0),
                obs("b", 1.0, 0.0, 5.0),
                obs("c", 0.0, 1.0, 5.0),
            ]
        )
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertClose(min_x, -2.0)
        self.assertClose(min_y, -2.0)
        self.assertClose(max_x, 2.0)
        self.assertClose(max_y, 2.0)
        wx, wy = region.witness
        self.assertClose(wx, -2.0)
        self.assertClose(wy, 0.0)

    def test_tangent_disks_degenerate_to_point(self):
        # a and b are externally tangent at (3, 0); c is a zero-radius
        # point disk sitting exactly on the tangent point.
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 3.0),
                obs("b", 7.0, 0.0, 4.0),
                obs("c", 3.0, 0.0, 0.0),
            ]
        )
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertClose(min_x, 3.0)
        self.assertClose(min_y, 0.0)
        self.assertClose(max_x, 3.0)
        self.assertClose(max_y, 0.0)
        wx, wy = region.witness
        self.assertClose(wx, 3.0)
        self.assertClose(wy, 0.0)

    def test_three_disks_meet_at_single_point(self):
        # Every pair of radius-2.5 circles passes through (1.5, 2) and the
        # three share nothing else.
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 2.5),
                obs("b", 3.0, 0.0, 2.5),
                obs("c", 1.5, 4.5, 2.5),
            ]
        )
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertClose(min_x, 1.5)
        self.assertClose(min_y, 2.0)
        self.assertClose(max_x, 1.5)
        self.assertClose(max_y, 2.0)
        wx, wy = region.witness
        self.assertClose(wx, 1.5)
        self.assertClose(wy, 2.0)

    def test_disjoint_disks_are_infeasible_not_exception(self):
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 1.0),
                obs("b", 10.0, 0.0, 1.0),
                obs("c", 5.0, 20.0, 1.0),
            ]
        )
        self.assertEqual(region, RegionDecision(False, None, None))

    def test_pairwise_overlap_but_empty_triple_intersection(self):
        # Every pair of disks intersects, yet no point lies in all three.
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 2.5),
                obs("b", 3.0, 0.0, 2.5),
                obs("c", 1.5, 4.6, 2.5),
            ]
        )
        self.assertIs(region.feasible, False)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_zero_radius_point_disk_outside_is_infeasible(self):
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 3.0),
                obs("b", 7.0, 0.0, 4.0),
                obs("c", 3.1, 0.0, 0.0),
            ]
        )
        self.assertIs(region.feasible, False)

    def test_tolerance_widens_every_radius(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 3.0, 0.0, 1.0),
            obs("c", 1.5, 5.0, 10.0),
        ]
        # Radii 1 and 1 leave a unit gap between a and b: no common point.
        self.assertIs(locate_region(observations).feasible, False)
        # Radii 1.5 and 1.5 are tangent at (1.5, 0), inside c's wide disk.
        tangent = locate_region(observations, tolerance=0.5)
        self.assertTrue(tangent.feasible)
        min_x, min_y, max_x, max_y = tangent.bounds
        self.assertClose(min_x, 1.5)
        self.assertClose(min_y, 0.0)
        self.assertClose(max_x, 1.5)
        self.assertClose(max_y, 0.0)
        wx, wy = tangent.witness
        self.assertClose(wx, 1.5)
        self.assertClose(wy, 0.0)
        # Radii 2 and 2 overlap in a lens with vertices (1.5, +/-sqrt(1.75)).
        wide = locate_region(observations, tolerance=1.0)
        self.assertTrue(wide.feasible)
        min_x, min_y, max_x, max_y = wide.bounds
        self.assertClose(min_x, 1.0)
        self.assertClose(min_y, -math.sqrt(1.75))
        self.assertClose(max_x, 2.0)
        self.assertClose(max_y, math.sqrt(1.75))
        wx, wy = wide.witness
        self.assertClose(wx, 1.0)
        self.assertClose(wy, 0.0)

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0, accepted=False),
            obs("b", 8.0, 0.0, 5.0, accepted=False),
            obs("c", 4.0, 0.0, 10.0, accepted=False),
        ]
        region = locate_region(observations)
        self.assertTrue(region.feasible)
        self.assertAlmostEqual(region.bounds[0], 3.0, delta=1e-9)

    def test_integer_inputs_match_float_inputs(self):
        integral = [
            obs("a", 0, 0, 5),
            obs("b", 8, 0, 5),
            obs("c", 4, 0, 10),
        ]
        self.assertEqual(locate_region(integral), locate_region(LENS))
        self.assertEqual(
            locate_region(integral, tolerance=1),
            locate_region(LENS, tolerance=1.0),
        )

    def test_four_observations(self):
        region = locate_region(
            LENS
            + [obs("d", 4.0, 0.0, 2.0)]
        )
        # d's disk clips the lens on the left and right, but its own top
        # (4, 2) and bottom (4, -2) lie inside every other disk, so they
        # become the region's vertical extrema.
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertClose(min_x, 3.0)
        self.assertClose(min_y, -2.0)
        self.assertClose(max_x, 5.0)
        self.assertClose(max_y, 2.0)
        wx, wy = region.witness
        self.assertClose(wx, 3.0)
        self.assertClose(wy, 0.0)


class LocateRegionOrderTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        first = locate_region(LENS)
        shuffled = [LENS[2], LENS[0], LENS[1]]
        self.assertEqual(first, locate_region(shuffled))

    def test_generator_input(self):
        region = locate_region(iter(LENS))
        self.assertTrue(region.feasible)
        self.assertAlmostEqual(region.bounds[0], 3.0, delta=1e-9)

    def test_inputs_not_mutated(self):
        observations = list(LENS)
        snapshot = list(observations)
        locate_region(observations, tolerance=0.25)
        self.assertEqual(observations, snapshot)

    def test_pure_computation_repeats_identically(self):
        self.assertEqual(locate_region(LENS), locate_region(LENS))


class LocateRegionValidationTest(unittest.TestCase):
    def test_too_few_observations(self):
        for count in (0, 1, 2):
            with self.assertRaises(ValueError, msg=count):
                locate_region(LENS[:count])

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_region(bad)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + LENS[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate_region(observations)

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("a", 1.0, 0.0, 5.0),
            obs("b", 2.0, 0.0, 5.0),
        ]
        with self.assertRaises(ValueError):
            locate_region(observations)

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(LENS[0], id=bad)
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate_region(observations)

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
                locate_region(observations)

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                LENS[0], decision=decision(value)
            )
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=value):
                locate_region(observations)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(LENS[0], decision=object())
        observations = [bad_obs] + LENS[1:]
        with self.assertRaises(ValueError):
            locate_region(observations)

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
                locate_region(LENS, tolerance=bad)

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            locate_region(LENS),
            locate_region(LENS, tolerance=0.0),
        )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_region(LENS, 0.5)


if __name__ == "__main__":
    unittest.main()
