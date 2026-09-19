import dataclasses
import math
import unittest

from nearproof import (
    Consensus,
    Observation,
    RangeDecision,
    locate,
)


def decision(upper_bound, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True):
    return Observation(
        id=ident, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


# Three verifiers at the corners of a 3-4-5 triangle around the origin.
TRIANGLE = [
    obs("a", 3.0, 0.0, 5.0),
    obs("b", 0.0, 4.0, 5.0),
    obs("c", 0.0, 0.0, 0.0),
]


class ConsensusContractTest(unittest.TestCase):
    def test_observation_is_frozen(self):
        observation = obs("a", 0.0, 0.0, 1.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.x = 1.0

    def test_consensus_is_frozen(self):
        consensus = locate(TRIANGLE, (0.0, 0.0))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            consensus.accepted = False

    def test_fields(self):
        consensus = locate(TRIANGLE, (0.0, 0.0))
        self.assertIsInstance(consensus, Consensus)
        self.assertEqual(consensus.total, 3)
        self.assertEqual(consensus.support, 3)
        self.assertEqual(consensus.rejected, ())
        self.assertIs(consensus.accepted, True)
        self.assertIsInstance(consensus.rejected, tuple)


class LocateGeometryTest(unittest.TestCase):
    def test_disks_intersect_at_origin(self):
        # Distances 3, 4, 0 against radii 5, 5, 0: every disk covers it.
        consensus = locate(TRIANGLE, (0.0, 0.0))
        self.assertEqual(consensus.support, 3)
        self.assertEqual(consensus.rejected, ())
        self.assertTrue(consensus.accepted)

    def test_point_outside_some_disks_is_rejection_not_exception(self):
        # Point (3, 4): distance 4, 5, 5 against radii 5, 5, 0; c's radius-0
        # disk contradicts the other two, which still cover it. Contradiction
        # surfaces as a rejected id, not an exception.
        consensus = locate(TRIANGLE, (3.0, 4.0))
        self.assertEqual(consensus.total, 3)
        self.assertEqual(consensus.support, 2)
        self.assertEqual(consensus.rejected, ("c",))
        self.assertFalse(consensus.accepted)
        self.assertTrue(locate(TRIANGLE, (3.0, 4.0), quorum=2).accepted)

    def test_below_quorum_not_accepted(self):
        consensus = locate(TRIANGLE, (10.0, 10.0))
        self.assertEqual(consensus.support, 0)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        self.assertFalse(consensus.accepted)

    def test_boundary_counts_as_support(self):
        # (0, 0) lies exactly on a's and b's radius-5 boundaries (distance
        # 5.0 from both); the closed disk keeps boundary points as support.
        boundary = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 5.0),
            obs("c", 0.0, 0.0, 0.0),
        ]
        consensus = locate(boundary, (0.0, 0.0))
        self.assertEqual(consensus.support, 3)
        self.assertEqual(consensus.rejected, ())
        self.assertTrue(consensus.accepted)

    def test_just_outside_boundary_rejected(self):
        boundary = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        # 5 + 1e-12 from a's center: just beyond the closed disk.
        consensus = locate(boundary, (10.0 + 1e-12, 0.0))
        self.assertEqual(consensus.rejected, ("a",))
        self.assertEqual(consensus.support, 2)

    def test_tolerance_extends_radius(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        without = locate(observations, (10.5, 0.0))
        self.assertEqual(without.rejected, ("a",))
        with_tol = locate(observations, (10.5, 0.0), tolerance=0.5)
        self.assertEqual(with_tol.support, 3)
        self.assertEqual(with_tol.rejected, ())
        # The tolerance boundary is likewise closed; 1e-12 past it rejects.
        edge = locate(observations, (10.5 + 1e-12, 0.0), tolerance=0.5)
        self.assertEqual(edge.rejected, ("a",))

    def test_accepted_decision_flag_ignored(self):
        # a and b claim accepted=False but their bounds still cover the
        # origin; consensus must rely solely on upper_bound.
        observations = [
            obs("a", 3.0, 0.0, 5.0, accepted=False),
            obs("b", 0.0, 4.0, 5.0, accepted=False),
            obs("c", 0.0, 0.0, 0.0, accepted=True),
        ]
        consensus = locate(observations, (0.0, 0.0))
        self.assertEqual(consensus.support, 3)
        self.assertTrue(consensus.accepted)

    def test_custom_quorum(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 10.0, 0.0, 1.0),
            obs("c", 20.0, 0.0, 1.0),
            obs("d", 30.0, 0.0, 1.0),
        ]
        consensus = locate(observations, (0.0, 0.0), quorum=1)
        self.assertEqual(consensus.support, 1)
        self.assertEqual(consensus.rejected, ("b", "c", "d"))
        self.assertTrue(consensus.accepted)
        self.assertFalse(locate(observations, (0.0, 0.0)).accepted)

    def test_integer_coordinates_and_bounds(self):
        observations = [
            obs("a", 0, 0, 0),
            obs("b", 3, 4, 5),
            obs("c", 6, 8, 10),
        ]
        consensus = locate(observations, (0, 0))
        self.assertEqual(consensus.support, 3)


class LocateOrderIndependenceTest(unittest.TestCase):
    def test_shuffled_input_gives_identical_result(self):
        point = (3.0, 4.0)
        first = locate(TRIANGLE, point)
        shuffled = [TRIANGLE[2], TRIANGLE[0], TRIANGLE[1]]
        second = locate(shuffled, point)
        self.assertEqual(first, second)
        self.assertEqual(second.rejected, ("c",))

    def test_rejected_always_lexicographic(self):
        observations = [
            obs("zebra", 100.0, 100.0, 0.0),
            obs("alpha", 0.0, 0.0, 0.0),
            obs("mid", -100.0, -100.0, 0.0),
        ]
        consensus = locate(observations, (50.0, 50.0))
        self.assertEqual(consensus.rejected, ("alpha", "mid", "zebra"))
        reversed_input = list(reversed(observations))
        self.assertEqual(
            locate(reversed_input, (50.0, 50.0)).rejected,
            ("alpha", "mid", "zebra"),
        )

    def test_generator_input(self):
        consensus = locate(iter(TRIANGLE), (0.0, 0.0))
        self.assertEqual(consensus.total, 3)
        self.assertTrue(consensus.accepted)


class LocateValidationTest(unittest.TestCase):
    def test_too_few_observations(self):
        for count in (0, 1, 2):
            with self.assertRaises(ValueError, msg=count):
                locate(TRIANGLE[:count], (0.0, 0.0))

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate(bad, (0.0, 0.0))

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            observations = [bad] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate(observations, (0.0, 0.0))

    def test_duplicate_ids_rejected(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("a", 1.0, 0.0, 1.0),
            obs("b", 2.0, 0.0, 1.0),
        ]
        with self.assertRaises(ValueError):
            locate(observations, (0.0, 0.0))

    def test_invalid_id(self):
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(TRIANGLE[0], id=bad)
            observations = [bad_obs] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=bad):
                locate(observations, (0.0, 0.0))

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
            bad_obs = dataclasses.replace(TRIANGLE[0], **{field: value})
            observations = [bad_obs] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=(field, value)):
                locate(observations, (0.0, 0.0))

    def test_invalid_upper_bound(self):
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                TRIANGLE[0], decision=decision(value)
            )
            observations = [bad_obs] + TRIANGLE[1:]
            with self.assertRaises(ValueError, msg=value):
                locate(observations, (0.0, 0.0))

    def test_zero_upper_bound_allowed(self):
        consensus = locate(TRIANGLE, (0.0, 0.0))
        self.assertEqual(consensus.support, 3)

    def test_decision_wrong_type(self):
        bad_obs = dataclasses.replace(TRIANGLE[0], decision=object())
        observations = [bad_obs] + TRIANGLE[1:]
        with self.assertRaises(ValueError):
            locate(observations, (0.0, 0.0))

    def test_invalid_point(self):
        for bad in (
            (0.0,),
            (0.0, 0.0, 0.0),
            [0.0, 0.0],
            (True, 0.0),
            (0.0, False),
            (math.nan, 0.0),
            (0.0, math.inf),
            ("0", 0.0),
            None,
            0.0,
            (),
        ):
            with self.assertRaises(ValueError, msg=bad):
                locate(TRIANGLE, bad)

    def test_invalid_quorum(self):
        for bad in (0, -1, True, False, 1.0, 2.5, "3", None, math.nan):
            with self.assertRaises(ValueError, msg=bad):
                locate(TRIANGLE, (0.0, 0.0), quorum=bad)

    def test_quorum_larger_than_count(self):
        with self.assertRaises(ValueError):
            locate(TRIANGLE, (0.0, 0.0), quorum=4)
        four = TRIANGLE + [obs("d", 1.0, 1.0, 9.0)]
        self.assertTrue(locate(four, (0.0, 0.0), quorum=4).accepted)

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
                locate(TRIANGLE, (0.0, 0.0), tolerance=bad)

    def test_zero_tolerance_is_default(self):
        self.assertEqual(
            locate(TRIANGLE, (3.0, 4.0)),
            locate(TRIANGLE, (3.0, 4.0), tolerance=0.0),
        )

    def test_quorum_and_tolerance_are_keyword_only(self):
        with self.assertRaises(TypeError):
            locate(TRIANGLE, (0.0, 0.0), 3, 0.0)


if __name__ == "__main__":
    unittest.main()
