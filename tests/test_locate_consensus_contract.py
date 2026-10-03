"""Regression tests for the shared locate/locate_weighted contract.

The two entry points delegate their input validation and observation
handling to common private helpers; these tests pin the observable
contract through the public functions only, so the refactor cannot
silently change it.
"""

import dataclasses
import math
import unittest
from types import MappingProxyType

from nearproof import (
    Consensus,
    ConsensusPolicy,
    Observation,
    RangeDecision,
    WeightedConsensus,
    locate,
    locate_weighted,
)


def decision(upper_bound, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True):
    return Observation(
        id=ident, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


TRIANGLE = [
    obs("a", 3.0, 0.0, 5.0),
    obs("b", 0.0, 4.0, 5.0),
    obs("c", 0.0, 0.0, 0.0),
]

UNIT_WEIGHTS = {"a": 1, "b": 1, "c": 1}


def unit_policy(threshold):
    return ConsensusPolicy(dict(UNIT_WEIGHTS), threshold)


class UnitWeightCorrespondenceTest(unittest.TestCase):
    """With unit weights, locate_weighted must mirror locate field by field."""

    def check_correspondence(self, observations, point, quorum, **kwargs):
        plain = locate(observations, point, quorum=quorum, **kwargs)
        weighted = locate_weighted(
            observations, point, unit_policy(quorum), **kwargs
        )
        self.assertEqual(weighted.total_weight, plain.total)
        self.assertEqual(weighted.support_weight, plain.support)
        self.assertEqual(weighted.rejected, plain.rejected)
        self.assertIs(weighted.accepted, plain.accepted)
        return plain, weighted

    def test_all_cover(self):
        plain, _ = self.check_correspondence(TRIANGLE, (0.0, 0.0), 3)
        self.assertEqual(plain, Consensus(3, 3, (), True))

    def test_partial_cover(self):
        for quorum in (1, 2, 3):
            plain, weighted = self.check_correspondence(
                TRIANGLE, (3.0, 4.0), quorum
            )
            self.assertEqual(plain.rejected, ("c",))
            self.assertIs(plain.accepted, quorum <= 2)
            self.assertIs(weighted.accepted, quorum <= 2)

    def test_none_cover(self):
        plain, _ = self.check_correspondence(TRIANGLE, (10.0, 10.0), 1)
        self.assertEqual(plain, Consensus(3, 0, ("a", "b", "c"), False))

    def test_tolerance_and_boundary(self):
        observations = [
            obs("a", 5.0, 0.0, 5.0),
            obs("b", 0.0, 5.0, 100.0),
            obs("c", 0.0, 0.0, 100.0),
        ]
        for quorum in (1, 2, 3):
            self.check_correspondence(
                observations, (10.5, 0.0), quorum, tolerance=0.5
            )
            self.check_correspondence(observations, (10.5, 0.0), quorum)

    def test_overflowing_inputs_correspond(self):
        observations = [obs(ident, -1.5e308, 0.0, 1e308) for ident in "abc"]
        plain, weighted = self.check_correspondence(
            observations, (1.5e308, 0.0), 2, tolerance=1e308
        )
        self.assertEqual(plain.support, 0)
        self.assertFalse(weighted.accepted)
        boundary = [obs(ident, -1e308, 0.0, 1e308) for ident in "abc"]
        plain, weighted = self.check_correspondence(
            boundary, (1e308, 0.0), 3, tolerance=1e308
        )
        self.assertEqual(plain.support, 3)
        self.assertTrue(weighted.accepted)


class WeightedSpecificsTest(unittest.TestCase):
    def test_single_observation_allowed(self):
        result = locate_weighted(
            [obs("solo", 0.0, 0.0, 0.0)],
            (0.0, 0.0),
            ConsensusPolicy({"solo": 1}, 1),
        )
        self.assertEqual(result, WeightedConsensus(1, 1, (), True))
        # The plain entry still demands at least three observations.
        with self.assertRaises(ValueError):
            locate([obs("solo", 0.0, 0.0, 0.0)], (0.0, 0.0))

    def test_weights_change_the_conclusion(self):
        # (3, 4): a and b cover, c does not. Uniform weights accept at
        # threshold 2; concentrating weight on the rejected id does not.
        self.assertTrue(
            locate_weighted(
                TRIANGLE, (3.0, 4.0), ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 2)
            ).accepted
        )
        heavy = locate_weighted(
            TRIANGLE, (3.0, 4.0), ConsensusPolicy({"a": 1, "b": 1, "c": 5}, 3)
        )
        self.assertEqual(heavy.support_weight, 2)
        self.assertEqual(heavy.total_weight, 7)
        self.assertFalse(heavy.accepted)
        # ...while the same threshold accepts when the covering ids carry
        # the weight.
        self.assertTrue(
            locate_weighted(
                TRIANGLE, (3.0, 4.0), ConsensusPolicy({"a": 4, "b": 4, "c": 1}, 3)
            ).accepted
        )


class InputHandlingTest(unittest.TestCase):
    def test_one_shot_iterator_matches_list(self):
        point = (3.0, 4.0)
        expected = locate(TRIANGLE, point)
        self.assertEqual(locate(iter(TRIANGLE), point), expected)
        self.assertEqual(
            locate_weighted(iter(TRIANGLE), point, unit_policy(2)),
            locate_weighted(TRIANGLE, point, unit_policy(2)),
        )

    def test_shuffled_input_gives_equal_results(self):
        shuffled = [TRIANGLE[2], TRIANGLE[0], TRIANGLE[1]]
        self.assertEqual(locate(shuffled, (3.0, 4.0)), locate(TRIANGLE, (3.0, 4.0)))
        self.assertEqual(
            locate_weighted(shuffled, (3.0, 4.0), unit_policy(2)),
            locate_weighted(TRIANGLE, (3.0, 4.0), unit_policy(2)),
        )

    def test_success_does_not_mutate_inputs(self):
        observations = list(TRIANGLE)
        weights = dict(UNIT_WEIGHTS)
        made = ConsensusPolicy(weights, 2)
        locate(observations, (0.0, 0.0))
        locate_weighted(observations, (0.0, 0.0), made)
        self.assertEqual(observations, TRIANGLE)
        self.assertEqual(weights, UNIT_WEIGHTS)
        self.assertEqual(dict(made.weights), UNIT_WEIGHTS)
        self.assertEqual(made.threshold, 2)

    def test_failure_does_not_mutate_inputs(self):
        observations = list(TRIANGLE)
        weights = dict(UNIT_WEIGHTS)
        made = ConsensusPolicy(weights, 2)
        bad_calls = (
            lambda: locate(observations, (0.0, 0.0), quorum=0),
            lambda: locate(observations, (0.0, 0.0), tolerance=-1.0),
            lambda: locate(observations, (math.nan, 0.0)),
            lambda: locate(observations + [obs("a", 9.0, 9.0, 1.0)], (0.0, 0.0)),
            lambda: locate_weighted(observations, (0.0, 0.0), made, tolerance=True),
            lambda: locate_weighted(observations, [0.0, 0.0], made),
            lambda: locate_weighted(
                observations, (0.0, 0.0), ConsensusPolicy({"a": 1, "b": 2}, 1)
            ),
            lambda: locate_weighted(
                observations + [obs("a", 9.0, 9.0, 1.0)], (0.0, 0.0), made
            ),
        )
        for call in bad_calls:
            with self.assertRaises(ValueError, msg=call):
                call()
        self.assertEqual(observations, TRIANGLE)
        self.assertEqual(weights, UNIT_WEIGHTS)
        self.assertEqual(dict(made.weights), UNIT_WEIGHTS)
        self.assertEqual(made.threshold, 2)

    def test_policy_weights_are_a_read_only_copy(self):
        weights = dict(UNIT_WEIGHTS)
        made = ConsensusPolicy(weights, 2)
        weights["d"] = 8
        weights["a"] = 99
        self.assertIsInstance(made.weights, MappingProxyType)
        self.assertEqual(dict(made.weights), UNIT_WEIGHTS)
        with self.assertRaises(TypeError):
            made.weights["d"] = 8
        with self.assertRaises(dataclasses.FrozenInstanceError):
            made.threshold = 1


class SharedValidationTest(unittest.TestCase):
    """Both entries raise ValueError for the same contract violations."""

    def check_both_raise(self, observations, point, **kwargs):
        kwargs.setdefault("quorum", 1)
        with self.assertRaises(ValueError):
            locate(observations, point, **kwargs)
        weighted_kwargs = dict(kwargs)
        weighted_kwargs.pop("quorum")
        with self.assertRaises(ValueError):
            locate_weighted(
                observations, point, unit_policy(1), **weighted_kwargs
            )

    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            self.check_both_raise(bad, (0.0, 0.0))

    def test_non_observation_element(self):
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            self.check_both_raise([bad] + TRIANGLE[1:], (0.0, 0.0))

    def test_empty_and_duplicate_ids(self):
        self.check_both_raise(
            [obs("", 0.0, 0.0, 1.0)] + TRIANGLE[1:], (0.0, 0.0)
        )
        self.check_both_raise(
            [obs("a", 0.0, 0.0, 1.0), obs("a", 1.0, 0.0, 1.0), TRIANGLE[2]],
            (0.0, 0.0),
        )

    def test_wrong_decision_type(self):
        self.check_both_raise(
            [dataclasses.replace(TRIANGLE[0], decision=object())] + TRIANGLE[1:],
            (0.0, 0.0),
        )

    def test_invalid_coordinates(self):
        for field, value in (
            ("x", True),
            ("x", math.nan),
            ("x", math.inf),
            ("x", "1"),
            ("y", False),
            ("y", -math.inf),
            ("y", None),
        ):
            bad_obs = dataclasses.replace(TRIANGLE[0], **{field: value})
            self.check_both_raise([bad_obs] + TRIANGLE[1:], (0.0, 0.0))

    def test_negative_coordinates_allowed(self):
        observations = [
            obs("a", -3.0, 0.0, 5.0),
            obs("b", 0.0, -4.0, 5.0),
            obs("c", 0.0, 0.0, 0.0),
        ]
        consensus = locate(observations, (0.0, 0.0))
        self.assertEqual(consensus.support, 3)
        weighted = locate_weighted(observations, (0.0, 0.0), unit_policy(3))
        self.assertEqual(weighted.support_weight, 3)

    def test_invalid_upper_bound(self):
        for value in (True, -0.1, -1, math.nan, math.inf, "1", None):
            bad_obs = dataclasses.replace(TRIANGLE[0], decision=decision(value))
            self.check_both_raise([bad_obs] + TRIANGLE[1:], (0.0, 0.0))

    def test_invalid_point(self):
        for bad in (
            (0.0,),
            (0.0, 0.0, 0.0),
            [0.0, 0.0],
            (True, 0.0),
            (math.nan, 0.0),
            (0.0, math.inf),
            None,
            (),
        ):
            self.check_both_raise(TRIANGLE, bad)

    def test_invalid_tolerance(self):
        for bad in (True, False, -0.1, math.nan, math.inf, "0.5", None):
            self.check_both_raise(TRIANGLE, (0.0, 0.0), tolerance=bad)

    def test_quorum_and_policy_violations(self):
        for bad in (0, -1, True, 1.0, "3", None, math.nan):
            with self.assertRaises(ValueError, msg=bad):
                locate(TRIANGLE, (0.0, 0.0), quorum=bad)
        with self.assertRaises(ValueError):
            locate(TRIANGLE, (0.0, 0.0), quorum=4)
        for bad in (None, 7, UNIT_WEIGHTS, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted(TRIANGLE, (0.0, 0.0), bad)
        with self.assertRaises(ValueError):
            locate_weighted(
                TRIANGLE, (0.0, 0.0), ConsensusPolicy({"a": 1, "b": 2, "x": 4}, 3)
            )

    def test_keyword_only_and_defaults_preserved(self):
        with self.assertRaises(TypeError):
            locate(TRIANGLE, (0.0, 0.0), 3, 0.0)
        with self.assertRaises(TypeError):
            locate_weighted(TRIANGLE, (0.0, 0.0), unit_policy(3), 0.0)
        self.assertEqual(
            locate(TRIANGLE, (3.0, 4.0)),
            locate(TRIANGLE, (3.0, 4.0), quorum=3, tolerance=0.0),
        )
        self.assertEqual(
            locate_weighted(TRIANGLE, (3.0, 4.0), unit_policy(2)),
            locate_weighted(TRIANGLE, (3.0, 4.0), unit_policy(2), tolerance=0.0),
        )

    def test_result_types_stay_frozen(self):
        consensus = locate(TRIANGLE, (0.0, 0.0))
        self.assertIsInstance(consensus, Consensus)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            consensus.accepted = False
        weighted = locate_weighted(TRIANGLE, (0.0, 0.0), unit_policy(1))
        self.assertIsInstance(weighted, WeightedConsensus)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            weighted.accepted = False


if __name__ == "__main__":
    unittest.main()
