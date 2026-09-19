import dataclasses
import math
import unittest

from nearproof import (
    Consensus,
    Observation,
    RangeDecision,
    locate,
)


def decision(upper_bound, *, accepted=False):
    return RangeDecision(
        sample_count=5, upper_bound=upper_bound, accepted=accepted
    )


def observation(obs_id, x, y, upper_bound, *, accepted=False):
    return Observation(
        id=obs_id, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


# Three unit disks centred at (0, 0), (1, 0) and (0, 1); the origin region
# is covered by all three, while (2, 2) is outside every disk.
THREE = [
    observation("a", 0.0, 0.0, 1.0),
    observation("b", 1.0, 0.0, 1.0),
    observation("c", 0.0, 1.0, 1.0),
]


class ConsensusContractTest(unittest.TestCase):
    def test_is_frozen(self):
        consensus = locate(THREE, (0.0, 0.0))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            consensus.accepted = False

    def test_fields(self):
        consensus = locate(THREE, (0.0, 0.0))
        self.assertIsInstance(consensus, Consensus)
        self.assertEqual(consensus.total, 3)
        self.assertEqual(consensus.support, 3)
        self.assertEqual(consensus.rejected, ())
        self.assertIs(consensus.accepted, True)

    def test_rejected_is_tuple_of_strings(self):
        consensus = locate(THREE, (2.0, 2.0))
        self.assertIsInstance(consensus.rejected, tuple)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        self.assertTrue(all(isinstance(value, str) for value in consensus.rejected))


class LocateGeometryTest(unittest.TestCase):
    def test_disk_intersection_supports_point(self):
        # (0.5, 0.5) lies within all three unit disks.
        consensus = locate(THREE, (0.5, 0.5))
        self.assertEqual((consensus.total, consensus.support), (3, 3))
        self.assertEqual(consensus.rejected, ())
        self.assertTrue(consensus.accepted)

    def test_partial_intersection_counts_support(self):
        # (1.0, 1.0) is within disks b and c (distance 1), not a (sqrt 2).
        consensus = locate(THREE, (1.0, 1.0))
        self.assertEqual(consensus.support, 2)
        self.assertEqual(consensus.rejected, ("a",))
        self.assertFalse(consensus.accepted)
        # A quorum of 2 accepts the same point.
        self.assertTrue(locate(THREE, (1.0, 1.0), quorum=2).accepted)

    def test_closed_boundary_counts_as_support(self):
        # Exactly one unit away from every centre -> on the boundary.
        consensus = locate(THREE, (1.0, 0.0))
        self.assertEqual(consensus.support, 2)  # b at the centre, a on edge
        # The c disk reaches exactly to (0, 1); (0, 1) itself is on a's edge.
        consensus = locate(THREE, (0.0, 1.0))
        self.assertEqual(consensus.support, 2)

    def test_contradictory_disks_return_rejection_not_error(self):
        # One zero-radius disk contradicts the others at the covered point.
        observations = [
            observation("a", 0.0, 0.0, 1.0),
            observation("b", 1.0, 0.0, 1.0),
            observation("zero", 0.5, 0.0, 0.0),
        ]
        consensus = locate(observations, (0.0, 0.0))
        self.assertEqual(consensus.total, 3)
        self.assertEqual(consensus.support, 2)
        self.assertEqual(consensus.rejected, ("zero",))
        self.assertFalse(consensus.accepted)

    def test_no_disk_covers_point(self):
        consensus = locate(THREE, (10.0, 10.0))
        self.assertEqual(consensus.support, 0)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        self.assertFalse(consensus.accepted)

    def test_tolerance_extends_disks(self):
        # (2, 0): disk b reaches distance 1 exactly, a reaches 2.
        consensus = locate(THREE, (2.0, 0.0))
        self.assertEqual(consensus.support, 1)
        widened = locate(THREE, (2.0, 0.0), tolerance=1.0)
        self.assertEqual(widened.support, 2)  # a and b now cover
        self.assertEqual(widened.rejected, ("c",))

    def test_tolerance_boundary_is_closed(self):
        # Distance to a is exactly 2 = bound 1 + tolerance 1.
        consensus = locate(THREE, (2.0, 0.0), tolerance=1.0)
        self.assertNotIn("a", consensus.rejected)

    def test_integer_coordinates_and_bounds(self):
        observations = [
            observation("a", 0, 0, 2),
            observation("b", 2, 0, 2),
            observation("c", 0, 2, 2),
        ]
        consensus = locate(observations, (1, 1))
        self.assertTrue(consensus.accepted)
        self.assertEqual(consensus.support, 3)


class LocateOrderTest(unittest.TestCase):
    def test_result_independent_of_order(self):
        point = (1.0, 1.0)
        first = locate(THREE, point)
        shuffled = [THREE[2], THREE[0], THREE[1]]
        second = locate(shuffled, point)
        self.assertEqual(first, second)
        self.assertEqual(second.rejected, ("a",))

    def test_rejected_sorted_lexicographically(self):
        observations = [
            observation("zebra", 10.0, 10.0, 0.0),
            observation("alpha", 10.0, 10.0, 0.0),
            observation("mid", 0.0, 0.0, 1.0),
        ]
        consensus = locate(observations, (0.0, 0.0))
        self.assertEqual(consensus.rejected, ("alpha", "zebra"))


class LocateAcceptedFlagTest(unittest.TestCase):
    def setUp(self):
        self.five = [
            observation("a", 0.0, 0.0, 1.0),
            observation("b", 1.0, 0.0, 1.0),
            observation("c", 0.0, 1.0, 1.0),
            observation("d", 1.0, 1.0, 1.0),
            observation("e", 5.0, 5.0, 0.1),
        ]

    def test_default_quorum_three(self):
        consensus = locate(self.five, (0.5, 0.5))
        self.assertEqual(consensus.support, 4)
        self.assertTrue(consensus.accepted)

    def test_quorum_not_met(self):
        consensus = locate(self.five, (0.5, 0.5), quorum=5)
        self.assertEqual(consensus.support, 4)
        self.assertFalse(consensus.accepted)

    def test_decision_accepted_flag_ignored(self):
        # Every per-verifier decision claims rejected, yet the disks cover.
        observations = [
            observation("a", 0.0, 0.0, 1.0, accepted=False),
            observation("b", 1.0, 0.0, 1.0, accepted=False),
            observation("c", 0.0, 1.0, 1.0, accepted=False),
        ]
        consensus = locate(observations, (0.0, 0.0))
        self.assertTrue(consensus.accepted)


class LocateValidationTest(unittest.TestCase):
    def test_fewer_than_three_observations(self):
        for count in (0, 1, 2):
            with self.assertRaises(ValueError, msg=count):
                locate(THREE[:count], (0.0, 0.0))

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), THREE[0]):
            with self.assertRaises(ValueError, msg=bad):
                locate(bad, (0.0, 0.0))

    def test_generator_iterable_allowed(self):
        consensus = locate(iter(THREE), (0.0, 0.0))
        self.assertEqual(consensus.total, 3)

    def test_duplicate_id(self):
        observations = [THREE[0]] + [
            dataclasses.replace(obs, id="a") for obs in THREE[1:]
        ]
        with self.assertRaises(ValueError):
            locate(observations, (0.0, 0.0))

    def test_empty_or_non_string_id(self):
        for bad_id in ("", 1, None, b"a", object()):
            observations = [
                dataclasses.replace(THREE[0], id=bad_id)
            ] + THREE[1:]
            with self.assertRaises(ValueError, msg=bad_id):
                locate(observations, (0.0, 0.0))

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(5, 1.0, True)):
            observations = [bad] + THREE[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate(observations, (0.0, 0.0))

    def test_invalid_coordinates(self):
        for bad in (True, False, math.nan, math.inf, -math.inf, "1", None, 1 + 2j):
            observations = [
                dataclasses.replace(THREE[0], x=bad)
            ] + THREE[1:]
            with self.assertRaises(ValueError, msg=("x", bad)):
                locate(observations, (0.0, 0.0))
            observations = [
                dataclasses.replace(THREE[0], y=bad)
            ] + THREE[1:]
            with self.assertRaises(ValueError, msg=("y", bad)):
                locate(observations, (0.0, 0.0))

    def test_invalid_upper_bound(self):
        for bad in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            observations = [
                Observation("a", 0.0, 0.0, decision(bad))
            ] + THREE[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate(observations, (0.0, 0.0))

    def test_zero_upper_bound_allowed(self):
        observations = [
            observation("a", 0.0, 0.0, 0.0),
            observation("b", 0.0, 0.0, 1.0),
            observation("c", 1.0, 0.0, 1.0),
        ]
        consensus = locate(observations, (0.0, 0.0))
        self.assertEqual(consensus.support, 3)

    def test_invalid_decision_type(self):
        for bad in (None, 5, object(), (1.0,)):
            observations = [
                Observation("a", 0.0, 0.0, bad)
            ] + THREE[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate(observations, (0.0, 0.0))

    def test_point_must_be_tuple_of_two(self):
        for bad in (
            [0.0, 0.0],
            (0.0,),
            (0.0, 0.0, 0.0),
            (0.0,),
            None,
            5,
            "(0,0)",
        ):
            with self.assertRaises(ValueError, msg=bad):
                locate(THREE, bad)

    def test_point_coordinate_validation(self):
        for bad in (True, False, math.nan, math.inf, -math.inf, "0", None, 1j):
            with self.assertRaises(ValueError, msg=bad):
                locate(THREE, (bad, 0.0))
            with self.assertRaises(ValueError, msg=bad):
                locate(THREE, (0.0, bad))

    def test_quorum_validation(self):
        for bad in (0, -1, 4, 100, True, False, 1.0, 2.5, "3", None):
            with self.assertRaises(ValueError, msg=bad):
                locate(THREE, (0.0, 0.0), quorum=bad)

    def test_quorum_equal_to_count_allowed(self):
        consensus = locate(THREE, (0.0, 0.0), quorum=3)
        self.assertTrue(consensus.accepted)

    def test_tolerance_validation(self):
        for bad in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "0", None):
            with self.assertRaises(ValueError, msg=bad):
                locate(THREE, (0.0, 0.0), tolerance=bad)

    def test_zero_tolerance_allowed(self):
        consensus = locate(THREE, (0.0, 0.0), tolerance=0)
        self.assertEqual(consensus.support, 3)


if __name__ == "__main__":
    unittest.main()
