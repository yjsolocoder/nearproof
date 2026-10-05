import dataclasses
import itertools
import math
import unittest

from nearproof import (
    Observation,
    RangeDecision,
    RegionConflict,
    diagnose_region,
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
# lens-shaped intersection.
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
    obs("c", 3.0, 0.0, 10.0),
]

# Every pair overlaps but no point lies in all three disks.
TRIPLE = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 1.8, 0.0, 1.0),
    obs("c", 0.9, 1.6, 1.0),
]


class ConflictContractTest(unittest.TestCase):
    def test_region_conflict_is_frozen(self):
        result = diagnose_region(LENS)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.feasible = False

    def test_fields(self):
        result = diagnose_region(LENS)
        self.assertIsInstance(result, RegionConflict)
        self.assertIs(result.feasible, True)
        self.assertIsInstance(result.conflict, tuple)
        self.assertEqual(result.conflict, ())

    def test_field_equality(self):
        self.assertEqual(
            diagnose_region(TRIPLE),
            RegionConflict(feasible=False, conflict=("a", "b", "c")),
        )
        self.assertNotEqual(
            diagnose_region(LENS),
            RegionConflict(feasible=False, conflict=("a", "b")),
        )

    def test_conflict_ids_are_strings(self):
        result = diagnose_region(TRIPLE)
        self.assertIs(result.feasible, False)
        for ident in result.conflict:
            self.assertIsInstance(ident, str)


class ConflictGeometryTest(unittest.TestCase):
    def test_feasible_set_has_empty_conflict(self):
        self.assertEqual(
            diagnose_region(LENS), RegionConflict(feasible=True, conflict=())
        )

    def test_disjoint_pair_gives_two_ids(self):
        result = diagnose_region(
            [
                obs("a", 0.0, 0.0, 1.0),
                obs("b", 3.0, 0.0, 1.0),
                obs("c", 1.5, 0.0, 0.4),
            ]
        )
        self.assertIs(result.feasible, False)
        self.assertEqual(result.conflict, ("a", "b"))

    def test_pairwise_overlap_without_common_point_gives_three_ids(self):
        result = diagnose_region(TRIPLE)
        self.assertIs(result.feasible, False)
        self.assertEqual(result.conflict, ("a", "b", "c"))

    def test_returned_triple_pairs_intersect_but_triple_does_not(self):
        result = diagnose_region(TRIPLE)
        subset = [o for o in TRIPLE if o.id in result.conflict]
        for first, second in itertools.combinations(subset, 2):
            distance = math.hypot(first.x - second.x, first.y - second.y)
            reach = (
                first.decision.upper_bound + second.decision.upper_bound
            )
            self.assertLessEqual(distance, reach)
        self.assertEqual(diagnose_region(subset), result)

    def test_pair_conflict_beats_triple_conflict(self):
        # TRIPLE conflicts only as a triple; the extra far-away disk adds
        # disjoint pairs, which are the smaller conflict sets.
        result = diagnose_region(TRIPLE + [obs("e", 100.0, 100.0, 1.0)])
        self.assertEqual(result.conflict, ("a", "e"))

    def test_lexicographically_smallest_pair_wins(self):
        observations = [
            obs("c", 10.0, 0.0, 1.0),
            obs("a", 5.0, 0.0, 1.0),
            obs("b", 0.0, 0.0, 1.0),
        ]
        # (a, b), (a, c) and (b, c) are all disjoint pairs.
        self.assertEqual(diagnose_region(observations).conflict, ("a", "b"))

    def test_lexicographically_smallest_triple_wins(self):
        # Every pair intersects; (a, b, c) and (a, b, d) both lack a
        # common point, and (a, b, c) sorts first.
        observations = [
            obs("d", 1.2, 1.5, 1.0),
            obs("c", 0.9, 1.6, 1.0),
            obs("b", 1.8, 0.0, 1.0),
            obs("a", 0.0, 0.0, 1.0),
        ]
        self.assertEqual(diagnose_region(observations).conflict, ("a", "b", "c"))

    def test_tangent_disks_are_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 6.0, 0.0, 3.0),
            obs("c", 3.0, 5.0, 5.0),
        ]
        # a and b touch at (3, 0), which lies exactly on c's boundary.
        self.assertEqual(
            diagnose_region(observations),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_shared_boundary_point_is_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 3.0, 4.0, 0.0),
        ]
        # a and b meet at (3, ±4); c is the zero-radius disk at (3, 4).
        self.assertEqual(
            diagnose_region(observations),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_zero_radius_disk_outside_others_conflicts(self):
        observations = [
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 2.0, 2.0, 2.0),
            obs("c", 100.0, 100.0, 0.0),
        ]
        result = diagnose_region(observations)
        self.assertIs(result.feasible, False)
        self.assertEqual(result.conflict, ("a", "c"))

    def test_zero_radius_disks_at_same_point_are_feasible(self):
        observations = [obs("a", 1.0, 1.0, 0.0), obs("b", 1.0, 1.0, 0.0)]
        self.assertEqual(
            diagnose_region(observations),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_coincident_disks_are_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 0.0, 0.0, 5.0),
        ]
        self.assertEqual(
            diagnose_region(observations),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_contained_disk_is_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 10.0),
            obs("b", 1.0, 1.0, 1.0),
            obs("c", -1.0, -1.0, 2.0),
        ]
        self.assertEqual(
            diagnose_region(observations),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0, accepted=False),
            obs("b", 6.0, 0.0, 5.0, accepted=False),
            obs("c", 3.0, 0.0, 10.0, accepted=False),
        ]
        self.assertEqual(
            diagnose_region(observations),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_tolerance_extends_every_radius(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 3.0, 0.0, 1.0),
            obs("c", 1.5, 0.0, 0.4),
        ]
        self.assertIs(diagnose_region(observations).feasible, False)
        # Radii become 1.5, 1.5, 0.9: a and b touch at (1.5, 0), c's center.
        self.assertEqual(
            diagnose_region(observations, tolerance=0.5),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_no_extra_slack_beyond_tolerance(self):
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 3.0, 0.0, 1.0)]
        # A real gap of 2e-12 remains: it must not be smoothed over.
        self.assertIs(
            diagnose_region(observations, tolerance=0.499999999999).feasible,
            False,
        )

    def test_huge_scale_not_misjudged_by_overflow(self):
        # The squared distance and squared radius sum both overflow to
        # inf in plain float arithmetic; the true relation decides.
        far_apart = [
            obs("a", 0.0, 0.0, 4e307),
            obs("b", 1e308, 0.0, 4e307),
        ]
        self.assertEqual(
            diagnose_region(far_apart),
            RegionConflict(feasible=False, conflict=("a", "b")),
        )
        reaching = [
            obs("a", 0.0, 0.0, 6e307),
            obs("b", 1e308, 0.0, 6e307),
        ]
        self.assertEqual(
            diagnose_region(reaching),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_tiny_scale_not_misjudged_by_underflow(self):
        # The squared distance and squared radius sum both underflow to
        # 0.0 in plain float arithmetic; the true relation decides.
        far_apart = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 3e-300, 0.0, 1e-300),
        ]
        self.assertEqual(
            diagnose_region(far_apart),
            RegionConflict(feasible=False, conflict=("a", "b")),
        )
        touching = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 2e-300, 0.0, 1e-300),
        ]
        self.assertEqual(
            diagnose_region(touching),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_integer_inputs_match_float_inputs(self):
        integers = [
            obs("a", 0, 0, 1),
            obs("b", 1.8, 0, 1),
            obs("c", 0.9, 1.6, 1),
        ]
        self.assertEqual(diagnose_region(integers), diagnose_region(TRIPLE))
        self.assertEqual(
            diagnose_region(integers, tolerance=1),
            diagnose_region(TRIPLE, tolerance=1.0),
        )


class ConflictOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        base = TRIPLE + [obs("d", 1.2, 1.5, 1.0)]
        expected = diagnose_region(base)
        for permuted in itertools.permutations(base):
            self.assertEqual(diagnose_region(list(permuted)), expected)

    def test_generator_input(self):
        result = diagnose_region(iter(TRIPLE))
        self.assertEqual(result, diagnose_region(TRIPLE))

    def test_conflict_subset_can_be_fed_back(self):
        base = TRIPLE + [obs("d", 1.2, 1.5, 1.0)]
        result = diagnose_region(base)
        subset = [o for o in base if o.id in result.conflict]
        self.assertEqual(diagnose_region(iter(subset)), result)

    def test_inputs_not_mutated(self):
        observations = list(TRIPLE)
        snapshot = list(observations)
        diagnose_region(observations)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])


class ConflictValidationTest(unittest.TestCase):
    def test_empty_observations(self):
        with self.assertRaises(ValueError):
            diagnose_region([])

    def test_single_observation_is_feasible(self):
        self.assertEqual(
            diagnose_region([obs("a", 0.0, 0.0, 1.0)]),
            RegionConflict(feasible=True, conflict=()),
        )

    def test_two_observations(self):
        pair = [obs("a", 0.0, 0.0, 1.0), obs("b", 1.0, 0.0, 1.0)]
        self.assertEqual(
            diagnose_region(pair), RegionConflict(feasible=True, conflict=())
        )
        far = [obs("a", 0.0, 0.0, 1.0), obs("b", 5.0, 0.0, 1.0)]
        self.assertEqual(
            diagnose_region(far),
            RegionConflict(feasible=False, conflict=("a", "b")),
        )

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                diagnose_region(bad)

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + LENS[1:]
            with self.assertRaises(ValueError, msg=bad):
                diagnose_region(observations)

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
        ]
        with self.assertRaises(ValueError):
            diagnose_region(observations)

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(LENS[0], id=bad)
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=bad):
                diagnose_region(observations)

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
                diagnose_region(observations)

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                LENS[0], decision=decision(value)
            )
            observations = [bad_obs] + LENS[1:]
            with self.assertRaises(ValueError, msg=value):
                diagnose_region(observations)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(LENS[0], decision=object())
        observations = [bad_obs] + LENS[1:]
        with self.assertRaises(ValueError):
            diagnose_region(observations)

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
                diagnose_region(LENS, tolerance=bad)

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            diagnose_region(LENS),
            diagnose_region(LENS, tolerance=0.0),
        )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            diagnose_region(LENS, 0.5)

    def test_invalid_trailing_element_rejected_despite_early_conflict(self):
        # The first two disks already conflict, but the invalid trailing
        # observation must still be rejected rather than ignored.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 5.0, 0.0, 1.0),
            obs("c", 0.0, 0.0, -1.0),
        ]
        with self.assertRaises(ValueError):
            diagnose_region(observations)


if __name__ == "__main__":
    unittest.main()
