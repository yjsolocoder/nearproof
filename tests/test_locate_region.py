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


# Two overlapping radius-5 disks plus a third disk that contains their
# lens-shaped intersection: extremes come from b's leftmost point (1, 0),
# a's rightmost point (5, 0) and the two circle-meeting points (3, ±4).
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
    obs("c", 3.0, 0.0, 10.0),
]

# a and b are externally tangent at (3, 0); c swallows both.
TANGENT = [
    obs("a", 0.0, 0.0, 3.0),
    obs("b", 10.0, 0.0, 7.0),
    obs("c", 0.0, 0.0, 100.0),
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

    def test_empty_region_fields(self):
        region = locate_region(
            [
                obs("a", 0.0, 0.0, 1.0),
                obs("b", 10.0, 0.0, 1.0),
                obs("c", 20.0, 0.0, 1.0),
            ]
        )
        self.assertIs(region.feasible, False)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)


class RegionGeometryTest(unittest.TestCase):
    def test_lens_bounds_and_witness(self):
        region = locate_region(LENS)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 1.0, delta=1e-9)
        self.assertAlmostEqual(min_y, -4.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 5.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 4.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, 1.0, delta=1e-9)
        self.assertAlmostEqual(wy, 0.0, delta=1e-9)

    def test_witness_lies_in_every_disk(self):
        region = locate_region(LENS)
        wx, wy = region.witness
        for observation in LENS:
            distance = math.hypot(wx - observation.x, wy - observation.y)
            self.assertLessEqual(
                distance, observation.decision.upper_bound + 1e-9
            )

    def test_tangent_disks_degenerate_to_single_point(self):
        region = locate_region(TANGENT)
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
        region = locate_region(observations)
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (1.0, 1.0, 1.0, 1.0))
        self.assertEqual(region.witness, (1.0, 1.0))

    def test_zero_radius_disk_outside_others_is_infeasible(self):
        observations = [
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 2.0, 2.0, 2.0),
            obs("c", 100.0, 100.0, 0.0),
        ]
        region = locate_region(observations)
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_pairwise_overlap_without_one(self):
        # Each pair of disks overlaps but no point lies in all three.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 1.8, 0.0, 1.0),
            obs("c", 0.9, 1.6, 1.0),
        ]
        region = locate_region(observations)
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_empty_intersection_is_not_an_exception(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 3.0, 0.0, 1.0),
            obs("c", 1.5, 0.0, 0.4),
        ]
        region = locate_region(observations)
        self.assertFalse(region.feasible)

    def test_tolerance_extends_every_radius(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 3.0, 0.0, 1.0),
            obs("c", 1.5, 0.0, 0.4),
        ]
        self.assertFalse(locate_region(observations).feasible)
        # Radii become 1.5, 1.5, 0.9: a and b touch at (1.5, 0), c's center.
        region = locate_region(observations, tolerance=0.5)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 1.5, delta=1e-9)
        self.assertAlmostEqual(max_x, 1.5, delta=1e-9)
        self.assertAlmostEqual(min_y, 0.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 0.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, 1.5, delta=1e-9)
        self.assertAlmostEqual(wy, 0.0, delta=1e-9)

    def test_shared_extremum_from_multiple_disks(self):
        # Three copies of the same circle: every extreme is jointly
        # determined by all three disks.
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 0.0, 0.0, 5.0),
            obs("c", 0.0, 0.0, 5.0),
        ]
        region = locate_region(observations)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, -5.0, delta=1e-9)
        self.assertAlmostEqual(min_y, -5.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 5.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 5.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, -5.0, delta=1e-9)
        self.assertAlmostEqual(wy, 0.0, delta=1e-9)

    def test_concentric_disks_use_smallest(self):
        observations = [
            obs("a", 1.0, 1.0, 10.0),
            obs("b", 1.0, 1.0, 3.0),
            obs("c", 1.0, 1.0, 20.0),
        ]
        region = locate_region(observations)
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, -2.0, delta=1e-9)
        self.assertAlmostEqual(min_y, -2.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 4.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 4.0, delta=1e-9)
        wx, wy = region.witness
        self.assertAlmostEqual(wx, -2.0, delta=1e-9)
        self.assertAlmostEqual(wy, 1.0, delta=1e-9)

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0, accepted=False),
            obs("b", 6.0, 0.0, 5.0, accepted=False),
            obs("c", 3.0, 0.0, 10.0, accepted=False),
        ]
        region = locate_region(observations)
        self.assertTrue(region.feasible)
        self.assertAlmostEqual(region.bounds[0], 1.0, delta=1e-9)

    def test_integer_inputs_match_float_inputs(self):
        integers = [
            obs("a", 0, 0, 5),
            obs("b", 6, 0, 5),
            obs("c", 3, 0, 10),
        ]
        self.assertEqual(locate_region(integers), locate_region(LENS))
        self.assertEqual(
            locate_region(integers, tolerance=1),
            locate_region(LENS, tolerance=1.0),
        )


class RegionOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        first = locate_region(LENS)
        shuffled = [LENS[2], LENS[0], LENS[1]]
        self.assertEqual(first, locate_region(shuffled))

    def test_generator_input(self):
        region = locate_region(iter(LENS))
        self.assertTrue(region.feasible)
        self.assertEqual(region, locate_region(LENS))

    def test_inputs_not_mutated(self):
        observations = list(LENS)
        snapshot = list(observations)
        locate_region(observations)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])


class RegionValidationTest(unittest.TestCase):
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
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
            obs("b", 2.0, 0.0, 1.0),
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
