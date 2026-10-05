import dataclasses
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


# Three disks whose lens-shaped intersection is non-empty.
LENS = [
    obs("a", 0.0, 0.0, 5.0),
    obs("b", 6.0, 0.0, 5.0),
    obs("c", 3.0, 0.0, 10.0),
]

# Each pair of disks overlaps but no point lies in all three.
TRIPLE_GAP = [
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
        self.assertEqual(diagnose_region(LENS), RegionConflict(True, ()))
        self.assertEqual(
            diagnose_region(TRIPLE_GAP), RegionConflict(False, ("a", "b", "c"))
        )
        self.assertNotEqual(RegionConflict(True, ()), RegionConflict(False, ()))

    def test_conflict_ids_are_strings(self):
        result = diagnose_region(TRIPLE_GAP)
        self.assertIs(result.feasible, False)
        for ident in result.conflict:
            self.assertIsInstance(ident, str)


class ConflictGeometryTest(unittest.TestCase):
    def test_single_observation_is_always_feasible(self):
        self.assertEqual(diagnose_region([obs("a", 1.0, 2.0, 0.0)]), RegionConflict(True, ()))

    def test_two_meeting_disks_are_feasible(self):
        observations = [obs("a", 0.0, 0.0, 2.0), obs("b", 3.0, 0.0, 2.0)]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_two_disjoint_disks_give_pair(self):
        observations = [obs("b", 10.0, 0.0, 1.0), obs("a", 0.0, 0.0, 1.0)]
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "b"))
        )

    def test_tangent_disks_are_feasible(self):
        # Closed disks: the single shared boundary point (3, 0) counts.
        observations = [
            obs("a", 0.0, 0.0, 3.0),
            obs("b", 10.0, 0.0, 7.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_contained_disk_is_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 10.0),
            obs("b", 1.0, 1.0, 2.0),
            obs("c", 0.0, 0.0, 20.0),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_coincident_disks_are_feasible(self):
        observations = [
            obs("a", 1.0, 1.0, 5.0),
            obs("b", 1.0, 1.0, 5.0),
            obs("c", 1.0, 1.0, 5.0),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_zero_radius_disk_on_shared_boundary_is_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 2.0, 2.0, 2.0),
            obs("c", 1.0, 1.0, 0.0),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_zero_radius_disk_outside_others_conflicts_with_each(self):
        observations = [
            obs("c", 100.0, 100.0, 0.0),
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 2.0, 2.0, 2.0),
        ]
        # c is disjoint from both a and b; ("a", "c") sorts first.
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "c"))
        )

    def test_pairwise_overlap_without_common_point_gives_triple(self):
        result = diagnose_region(TRIPLE_GAP)
        self.assertEqual(result, RegionConflict(False, ("a", "b", "c")))

    def test_returned_triple_meets_pairwise_but_not_jointly(self):
        result = diagnose_region(TRIPLE_GAP)
        by_id = {observation.id: observation for observation in TRIPLE_GAP}
        subset = [by_id[ident] for ident in result.conflict]
        for first in range(len(subset)):
            for second in range(first + 1, len(subset)):
                pair = [subset[first], subset[second]]
                self.assertTrue(diagnose_region(pair).feasible)
        self.assertFalse(diagnose_region(subset).feasible)

    def test_disjoint_pair_beats_infeasible_triple(self):
        # A disjoint pair plus a pairwise-meeting but jointly infeasible
        # triple (a, b, c): the minimum conflict has size 2, and ("a", "x")
        # is the lexicographically smallest disjoint pair here.
        observations = TRIPLE_GAP + [
            obs("x", 100.0, 0.0, 1.0),
            obs("y", 110.0, 0.0, 1.0),
        ]
        result = diagnose_region(observations)
        self.assertEqual(result, RegionConflict(False, ("a", "x")))
        self.assertEqual(len(result.conflict), 2)

    def test_lexicographically_smallest_pair_wins(self):
        # Every pair here is disjoint; ("a", "b") is the smallest tuple.
        observations = [
            obs("c", 5.0, 0.0, 1.0),
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 10.0, 0.0, 1.0),
        ]
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "b"))
        )

    def test_lexicographically_smallest_triple_wins(self):
        # Every pair of disks meets and every one of the four triples is
        # jointly infeasible; ("a", "b", "c") sorts first.
        observations = [
            obs("d", 0.0, 0.0, 1.0),
            obs("a", 0.9, 0.54, 0.06),
            obs("c", 1.8, 0.0, 1.0),
            obs("b", 0.9, 1.6, 1.0),
        ]
        result = diagnose_region(observations)
        self.assertEqual(result, RegionConflict(False, ("a", "b", "c")))

    def test_conflict_subset_recheck_reproduces_verdict(self):
        observations = TRIPLE_GAP + [obs("z", 0.9, 0.5, 0.2)]
        result = diagnose_region(observations)
        self.assertFalse(result.feasible)
        by_id = {observation.id: observation for observation in observations}
        subset = [by_id[ident] for ident in result.conflict]
        self.assertEqual(diagnose_region(subset), result)

    def test_accepted_decision_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0, accepted=False),
            obs("b", 6.0, 0.0, 5.0, accepted=False),
            obs("c", 3.0, 0.0, 10.0, accepted=False),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_integer_inputs_match_float_inputs(self):
        integers = [
            obs("a", 0, 0, 5),
            obs("b", 6, 0, 5),
            obs("c", 3, 0, 10),
        ]
        self.assertEqual(diagnose_region(integers), diagnose_region(LENS))


class ConflictToleranceTest(unittest.TestCase):
    def test_tolerance_only_enlarges_disks(self):
        # A genuine 0.1 gap: no slack beyond tolerance may bridge it.
        observations = [obs("a", 0.0, 0.0, 1.0), obs("b", 2.1, 0.0, 1.0)]
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "b"))
        )
        self.assertEqual(
            diagnose_region(observations, tolerance=0.049),
            RegionConflict(False, ("a", "b")),
        )
        # Radii become exactly 1.05: tangent at (1.05, 0), feasible.
        self.assertEqual(
            diagnose_region(observations, tolerance=0.05),
            RegionConflict(True, ()),
        )

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            diagnose_region(TRIPLE_GAP),
            diagnose_region(TRIPLE_GAP, tolerance=0.0),
        )

    def test_tolerance_is_keyword_only(self):
        with self.assertRaises(TypeError):
            diagnose_region(LENS, 0.5)


class ConflictScaleTest(unittest.TestCase):
    def test_huge_scale_tangent_disks_are_feasible(self):
        observations = [
            obs("a", -1e308, 0.0, 1e308),
            obs("b", 1e308, 0.0, 1e308),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_huge_scale_disjoint_disks_conflict(self):
        observations = [
            obs("a", -1e308, 0.0, 0.5e308),
            obs("b", 1e308, 0.0, 0.5e308),
        ]
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "b"))
        )

    def test_huge_scale_triple_gap(self):
        observations = [
            obs("a", 0.0, 0.0, 0.9e308),
            obs("b", 1.62e308, 0.0, 0.9e308),
            obs("c", 0.81e308, 1.44e308, 0.9e308),
        ]
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "b", "c"))
        )

    def test_tiny_scale_triple_gap(self):
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1.8e-300, 0.0, 1e-300),
            obs("c", 0.9e-300, 1.6e-300, 1e-300),
        ]
        self.assertEqual(
            diagnose_region(observations), RegionConflict(False, ("a", "b", "c"))
        )

    def test_tiny_scale_meeting_disks_are_feasible(self):
        observations = [
            obs("a", 0.0, 0.0, 1e-300),
            obs("b", 1.5e-300, 0.0, 1e-300),
        ]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))

    def test_all_zero_radii_at_one_point(self):
        observations = [obs("a", 0.0, 0.0, 0.0), obs("b", 0.0, 0.0, 0.0)]
        self.assertEqual(diagnose_region(observations), RegionConflict(True, ()))


class ConflictOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        first = diagnose_region(TRIPLE_GAP)
        shuffled = [TRIPLE_GAP[2], TRIPLE_GAP[0], TRIPLE_GAP[1]]
        self.assertEqual(first, diagnose_region(shuffled))

    def test_generator_input(self):
        self.assertEqual(diagnose_region(iter(TRIPLE_GAP)), diagnose_region(TRIPLE_GAP))

    def test_inputs_not_mutated(self):
        observations = list(TRIPLE_GAP)
        snapshot = list(observations)
        diagnose_region(observations)
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])


class ConflictValidationTest(unittest.TestCase):
    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError):
            diagnose_region([])

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

    def test_invalid_element_after_conflict_still_rejected(self):
        # The first two observations already conflict, but the invalid
        # third element must still be rejected rather than returning a
        # partial verdict.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 10.0, 0.0, 1.0),
            "not-an-observation",
        ]
        with self.assertRaises(ValueError):
            diagnose_region(observations)
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 10.0, 0.0, 1.0),
            obs("b", 20.0, 0.0, 1.0),
        ]
        with self.assertRaises(ValueError):
            diagnose_region(observations)


if __name__ == "__main__":
    unittest.main()
