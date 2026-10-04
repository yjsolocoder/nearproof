import dataclasses
import math
import unittest

from nearproof import (
    ConsensusPolicy,
    Observation,
    RangeDecision,
    RegionDecision,
    locate_region,
    locate_weighted,
    locate_weighted_region,
)


def decision(upper_bound, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def obs(ident, x, y, upper_bound, *, accepted=True):
    return Observation(
        id=ident, x=x, y=y, decision=decision(upper_bound, accepted=accepted)
    )


def policy(weights, threshold):
    return ConsensusPolicy(weights, threshold)


# Two disjoint unit disks centered at (0, 0) and (4, 0).
DISJOINT = [
    obs("a", 0.0, 0.0, 1.0),
    obs("b", 4.0, 0.0, 1.0),
]

# Three disks: a and b overlap in a lens, c is far away from both.
LENS_PLUS_ISLAND = [
    obs("a", 0.0, 0.0, 2.0),
    obs("b", 3.0, 0.0, 2.0),
    obs("c", 20.0, 0.0, 1.0),
]

# Two overlapping pairs far apart: {a, b} and {c, d}.
TWO_LENSES = [
    obs("a", 0.0, 0.0, 2.0),
    obs("b", 3.0, 0.0, 2.0),
    obs("c", 20.0, 0.0, 2.0),
    obs("d", 23.0, 0.0, 2.0),
]

# a and b are externally tangent at (3, 0).
TANGENT = [
    obs("a", 0.0, 0.0, 3.0),
    obs("b", 10.0, 0.0, 7.0),
]


class WeightedRegionContractTest(unittest.TestCase):
    def test_returns_frozen_region_decision(self):
        region = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 1)
        )
        self.assertIsInstance(region, RegionDecision)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            region.feasible = False

    def test_fields_when_feasible(self):
        region = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 1)
        )
        self.assertIs(region.feasible, True)
        self.assertIsInstance(region.bounds, tuple)
        self.assertEqual(len(region.bounds), 4)
        self.assertIsInstance(region.witness, tuple)
        self.assertEqual(len(region.witness), 2)
        for value in region.bounds + region.witness:
            self.assertIsInstance(value, float)
            self.assertNotIsInstance(value, bool)
            self.assertTrue(math.isfinite(value))

    def test_fields_when_empty(self):
        region = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 2)
        )
        self.assertIs(region.feasible, False)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_no_minimum_observation_count(self):
        # A single observation is enough when the policy matches it.
        region = locate_weighted_region(
            [obs("a", 1.0, 2.0, 3.0)], policy({"a": 1}, 1)
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-2.0, -1.0, 4.0, 5.0))
        self.assertEqual(region.witness, (-2.0, 2.0))


class WeightedRegionGeometryTest(unittest.TestCase):
    def test_disjoint_unit_disks_threshold_one(self):
        region = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 1)
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-1.0, -1.0, 5.0, 1.0))
        self.assertEqual(region.witness, (-1.0, 0.0))

    def test_disjoint_unit_disks_threshold_two_is_empty(self):
        region = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 2)
        )
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_witness_is_feasible_unlike_box_center(self):
        region = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 1)
        )
        wx, wy = region.witness
        # The witness itself must be covered by at least threshold weight.
        self.assertEqual(
            locate_weighted(
                DISJOINT, (wx, wy), policy({"a": 1, "b": 1}, 1)
            ).accepted,
            True,
        )
        # The bounding-box center (2, 0) sits in the gap and is infeasible:
        # it must never be offered as the witness.
        self.assertFalse(
            locate_weighted(
                DISJOINT, (2.0, 0.0), policy({"a": 1, "b": 1}, 1)
            ).accepted
        )

    def test_two_separated_lens_components(self):
        weights = {"a": 1, "b": 1, "c": 1, "d": 1}
        region = locate_weighted_region(TWO_LENSES, policy(weights, 2))
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, 1.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 22.0, delta=1e-9)
        half = math.sqrt(1.75)
        self.assertAlmostEqual(min_y, -half, delta=1e-9)
        self.assertAlmostEqual(max_y, half, delta=1e-9)
        self.assertAlmostEqual(region.witness[0], 1.0, delta=1e-9)
        self.assertAlmostEqual(region.witness[1], 0.0, delta=1e-9)
        # The middle of the spanning box lies in neither lens.
        self.assertFalse(
            locate_weighted(
                TWO_LENSES, (11.5, 0.0), policy(weights, 2)
            ).accepted
        )

    def test_different_supporting_combinations_in_one_region(self):
        # Threshold 1: the a/b lens and the separate c disk are both in;
        # each whole a/b disk is feasible on its own as well, so the box
        # spans their full +-2 vertical extent and c's far-away extremes.
        weights = {"a": 1, "b": 1, "c": 1}
        region = locate_weighted_region(
            LENS_PLUS_ISLAND, policy(weights, 1)
        )
        self.assertTrue(region.feasible)
        min_x, min_y, max_x, max_y = region.bounds
        self.assertAlmostEqual(min_x, -2.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 21.0, delta=1e-9)
        self.assertAlmostEqual(min_y, -2.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 2.0, delta=1e-9)
        # At threshold 2 only the a/b lens survives; c pairs with nobody.
        region_two = locate_weighted_region(
            LENS_PLUS_ISLAND, policy(weights, 2)
        )
        self.assertTrue(region_two.feasible)
        self.assertAlmostEqual(region_two.bounds[0], 1.0, delta=1e-9)
        self.assertAlmostEqual(region_two.bounds[2], 2.0, delta=1e-9)

    def test_tangent_disks_union_vs_contact_point(self):
        weights = {"a": 1, "b": 1}
        union = locate_weighted_region(TANGENT, policy(weights, 1))
        self.assertTrue(union.feasible)
        for got, expected in zip(union.bounds, (-3.0, -7.0, 17.0, 7.0)):
            self.assertAlmostEqual(got, expected, delta=1e-9)
        self.assertAlmostEqual(union.witness[0], -3.0, delta=1e-9)
        self.assertAlmostEqual(union.witness[1], 0.0, delta=1e-9)
        contact = locate_weighted_region(TANGENT, policy(weights, 2))
        self.assertTrue(contact.feasible)
        for got, expected in zip(contact.bounds, (3.0, 0.0, 3.0, 0.0)):
            self.assertAlmostEqual(got, expected, delta=1e-9)
        self.assertAlmostEqual(contact.witness[0], 3.0, delta=1e-9)
        self.assertAlmostEqual(contact.witness[1], 0.0, delta=1e-9)

    def test_concentric_disks_threshold_one_is_outer_disk(self):
        observations = [
            obs("a", 1.0, 1.0, 10.0),
            obs("b", 1.0, 1.0, 3.0),
        ]
        region = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 1)
        )
        self.assertTrue(region.feasible)
        for got, expected in zip(region.bounds, (-9.0, -9.0, 11.0, 11.0)):
            self.assertAlmostEqual(got, expected, delta=1e-9)
        self.assertAlmostEqual(region.witness[0], -9.0, delta=1e-9)
        self.assertAlmostEqual(region.witness[1], 1.0, delta=1e-9)

    def test_concentric_disks_threshold_total_is_inner_disk(self):
        observations = [
            obs("a", 1.0, 1.0, 10.0),
            obs("b", 1.0, 1.0, 3.0),
        ]
        region = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 2)
        )
        self.assertTrue(region.feasible)
        for got, expected in zip(region.bounds, (-2.0, -2.0, 4.0, 4.0)):
            self.assertAlmostEqual(got, expected, delta=1e-9)
        self.assertAlmostEqual(region.witness[0], -2.0, delta=1e-9)
        self.assertAlmostEqual(region.witness[1], 1.0, delta=1e-9)

    def test_zero_radius_disks_as_separate_components(self):
        observations = [
            obs("a", 1.0, 1.0, 0.0),
            obs("b", 5.0, 5.0, 0.0),
        ]
        region = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 1)
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (1.0, 1.0, 5.0, 5.0))
        self.assertEqual(region.witness, (1.0, 1.0))
        empty = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 2)
        )
        self.assertFalse(empty.feasible)

    def test_zero_radius_disk_pins_total_weight_region(self):
        observations = [
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 2.0, 2.0, 2.0),
            obs("c", 1.0, 1.0, 0.0),
        ]
        weights = {"a": 1, "b": 1, "c": 1}
        region = locate_weighted_region(observations, policy(weights, 3))
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (1.0, 1.0, 1.0, 1.0))
        self.assertEqual(region.witness, (1.0, 1.0))

    def test_threshold_total_matches_full_intersection(self):
        observations = [
            obs("a", 0.0, 0.0, 5.0),
            obs("b", 6.0, 0.0, 5.0),
            obs("c", 3.0, 0.0, 10.0),
        ]
        weighted = locate_weighted_region(
            observations, policy({"a": 2, "b": 3, "c": 5}, 10)
        )
        reference = locate_region(observations)
        self.assertEqual(weighted.feasible, reference.feasible)
        for got, expected in zip(weighted.bounds, reference.bounds):
            self.assertAlmostEqual(got, expected, delta=1e-9)
        for got, expected in zip(weighted.witness, reference.witness):
            self.assertAlmostEqual(got, expected, delta=1e-9)

    def test_threshold_total_with_empty_intersection(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 3.0, 0.0, 1.0),
            obs("c", 1.5, 0.0, 0.4),
        ]
        weights = {"a": 1, "b": 1, "c": 1}
        region = locate_weighted_region(observations, policy(weights, 3))
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_weights_not_observation_counts(self):
        # b and c together (weights 3 + 1 = 4) reach threshold 4 only in
        # the overlap of their two disks; a alone (weight 5) qualifies
        # throughout its own distant disk. A plain count quorum of one
        # would also admit isolated b and c points, which weight 4 must
        # not: the region is exactly a's disk union the b/c lens.
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 5.0, 0.0, 1.0),
        ]
        weights = {"a": 5, "b": 3, "c": 1}
        region = locate_weighted_region(observations, policy(weights, 5))
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-1.0, -1.0, 1.0, 1.0))
        self.assertEqual(region.witness, (-1.0, 0.0))
        region_four = locate_weighted_region(
            observations, policy(weights, 4)
        )
        self.assertTrue(region_four.feasible)
        min_x, min_y, max_x, max_y = region_four.bounds
        self.assertAlmostEqual(min_x, -1.0, delta=1e-9)
        self.assertAlmostEqual(max_x, 5.0, delta=1e-9)
        # a's disk contributes the larger vertical extent (+-1) even
        # though the b/c lens reaches only +-sqrt(3/4).
        self.assertAlmostEqual(min_y, -1.0, delta=1e-9)
        self.assertAlmostEqual(max_y, 1.0, delta=1e-9)
        # The b/c lens covers both centers; points on only one of the two
        # disks (weight 3 or 1) stay infeasible under weight 4.
        self.assertTrue(
            locate_weighted(
                observations, (4.0, 0.0), policy(weights, 4)
            ).accepted
        )
        self.assertFalse(
            locate_weighted(
                observations, (3.0, 0.0), policy(weights, 4)
            ).accepted
        )
        self.assertFalse(
            locate_weighted(
                observations, (6.0, 0.0), policy(weights, 4)
            ).accepted
        )

    def test_boundary_counts_as_support(self):
        # Disks meet at exactly one boundary point: (2, 0) is on both.
        observations = [
            obs("a", 0.0, 0.0, 2.0),
            obs("b", 4.0, 0.0, 2.0),
        ]
        region = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 2)
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (2.0, 0.0, 2.0, 0.0))
        self.assertEqual(region.witness, (2.0, 0.0))

    def test_witness_tie_breaks_toward_smallest_y(self):
        # Two stacked disjoint disks share the same minimum x = -1.
        observations = [
            obs("a", 0.0, 3.0, 1.0),
            obs("b", 0.0, -3.0, 1.0),
        ]
        region = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 1)
        )
        self.assertEqual(region.witness, (-1.0, -3.0))

    def test_accepted_flag_ignored(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0, accepted=False),
            obs("b", 4.0, 0.0, 1.0, accepted=False),
        ]
        region = locate_weighted_region(
            observations, policy({"a": 1, "b": 1}, 1)
        )
        self.assertEqual(region.bounds, (-1.0, -1.0, 5.0, 1.0))

    def test_tolerance_extends_every_radius(self):
        observations = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 3.0, 0.0, 1.0),
        ]
        weights = {"a": 1, "b": 1}
        self.assertFalse(
            locate_weighted_region(observations, policy(weights, 2)).feasible
        )
        # Radii become 1.5: the disks touch at (1.5, 0).
        region = locate_weighted_region(
            observations, policy(weights, 2), tolerance=0.5
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (1.5, 0.0, 1.5, 0.0))
        self.assertEqual(region.witness, (1.5, 0.0))

    def test_integer_inputs_match_float_inputs(self):
        integers = [
            obs("a", 0, 0, 1),
            obs("b", 4, 0, 1),
        ]
        floats = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
        ]
        self.assertEqual(
            locate_weighted_region(integers, policy({"a": 1, "b": 1}, 1)),
            locate_weighted_region(floats, policy({"a": 1, "b": 1}, 1)),
        )
        self.assertEqual(
            locate_weighted_region(
                integers, policy({"a": 1, "b": 1}, 1), tolerance=1
            ),
            locate_weighted_region(
                floats, policy({"a": 1, "b": 1}, 1), tolerance=1.0
            ),
        )


class WeightedRegionOrderTest(unittest.TestCase):
    def test_shuffled_observations_identical(self):
        weights = {"a": 1, "b": 1, "c": 1, "d": 1}
        first = locate_weighted_region(TWO_LENSES, policy(weights, 2))
        shuffled = [TWO_LENSES[3], TWO_LENSES[1], TWO_LENSES[0], TWO_LENSES[2]]
        self.assertEqual(
            first, locate_weighted_region(shuffled, policy(weights, 2))
        )

    def test_weight_mapping_order_ignored(self):
        first = locate_weighted_region(
            DISJOINT, policy({"a": 1, "b": 1}, 1)
        )
        reordered = locate_weighted_region(
            DISJOINT, policy({"b": 1, "a": 1}, 1)
        )
        self.assertEqual(first, reordered)

    def test_one_shot_iterator_input(self):
        weights = {"a": 1, "b": 1}
        from_list = locate_weighted_region(DISJOINT, policy(weights, 1))
        from_iter = locate_weighted_region(iter(DISJOINT), policy(weights, 1))
        self.assertEqual(from_list, from_iter)

    def test_inputs_not_mutated(self):
        observations = list(reversed(DISJOINT))
        snapshot = list(observations)
        locate_weighted_region(
            observations, policy({"b": 1, "a": 1}, 1)
        )
        self.assertEqual(observations, snapshot)
        self.assertIs(observations[0], snapshot[0])


class WeightedRegionValidationTest(unittest.TestCase):
    WEIGHTS = {"a": 1, "b": 1, "c": 1}

    def _region(self, observations, weights=None, threshold=1, **kwargs):
        chosen = self.WEIGHTS if weights is None else weights
        return locate_weighted_region(
            observations, policy(chosen, threshold), **kwargs
        )

    def test_empty_observations_cannot_match_policy(self):
        with self.assertRaises(ValueError):
            locate_weighted_region([], policy({"a": 1}, 1))

    def test_non_iterable_observations(self):
        pol = policy({"a": 1, "b": 1}, 1)
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region(bad, pol)

    def test_non_observation_element(self):
        pol = policy({"a": 1, "b": 1}, 1)
        for bad in ("x", 123, None, object(), b"raw", RangeDecision(1, 1.0, True)):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region([bad, obs("b", 4.0, 0.0, 1.0)], pol)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            self._region(
                [
                    obs("a", 0.0, 0.0, 1.0),
                    obs("a", 1.0, 0.0, 1.0),
                    obs("b", 2.0, 0.0, 1.0),
                ],
                {"a": 1, "b": 1},
            )

    def test_invalid_id(self):
        pol = policy({"a": 1, "b": 1, "c": 1}, 1)
        good = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 8.0, 0.0, 1.0),
        ]
        for bad in ("", b"a", 1, None, True, object()):
            bad_obs = dataclasses.replace(good[0], id=bad)
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region([bad_obs] + good[1:], pol)

    def test_invalid_coordinates(self):
        good = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 8.0, 0.0, 1.0),
        ]
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
            bad_obs = dataclasses.replace(good[0], **{field: value})
            with self.assertRaises(ValueError, msg=(field, value)):
                locate_weighted_region(
                    [bad_obs] + good[1:], policy(self.WEIGHTS, 1)
                )

    def test_invalid_upper_bound(self):
        good = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 8.0, 0.0, 1.0),
        ]
        for value in (True, False, -0.1, -1, math.nan, math.inf, -math.inf, "1", None):
            bad_obs = dataclasses.replace(
                good[0], decision=decision(value)
            )
            with self.assertRaises(ValueError, msg=value):
                locate_weighted_region(
                    [bad_obs] + good[1:], policy(self.WEIGHTS, 1)
                )

    def test_decision_wrong_type(self):
        good = [
            obs("a", 0.0, 0.0, 1.0),
            obs("b", 4.0, 0.0, 1.0),
            obs("c", 8.0, 0.0, 1.0),
        ]
        bad_obs = dataclasses.replace(good[0], decision=object())
        with self.assertRaises(ValueError):
            locate_weighted_region(
                [bad_obs] + good[1:], policy(self.WEIGHTS, 1)
            )

    def test_policy_wrong_type(self):
        observations = [obs("a", 0.0, 0.0, 1.0)]
        for bad in (None, "policy", object(), {"a": 1}, 1, RangeDecision(1, 1.0, True)):
            with self.assertRaises(ValueError, msg=bad):
                locate_weighted_region(observations, bad)

    def test_policy_missing_observation_id(self):
        with self.assertRaises(ValueError):
            locate_weighted_region(
                DISJOINT, policy({"a": 1}, 1)
            )

    def test_policy_has_extra_id(self):
        with self.assertRaises(ValueError):
            locate_weighted_region(
                DISJOINT, policy({"a": 1, "b": 1, "c": 1}, 1)
            )

    def test_invalid_tolerance(self):
        pol = policy({"a": 1, "b": 1}, 1)
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
                locate_weighted_region(DISJOINT, pol, tolerance=bad)

    def test_zero_tolerance_is_default(self):
        pol = policy({"a": 1, "b": 1}, 2)
        self.assertEqual(
            locate_weighted_region(DISJOINT, pol),
            locate_weighted_region(DISJOINT, pol, tolerance=0.0),
        )

    def test_tolerance_is_keyword_only(self):
        pol = policy({"a": 1, "b": 1}, 1)
        with self.assertRaises(TypeError):
            locate_weighted_region(DISJOINT, pol, 0.5)


class WeightedRegionOverflowTest(unittest.TestCase):
    def test_true_boundary_beyond_float_range_raises(self):
        # Right extreme 2e308 exceeds the finite float range; the region is
        # non-empty, so this must be ValueError, not an empty/false result.
        observations = [obs("a", 1e308, 0.0, 1e308)]
        with self.assertRaises(ValueError):
            locate_weighted_region(observations, policy({"a": 1}, 1))

    def test_union_extreme_beyond_float_range_raises(self):
        observations = [
            obs("a", 0.9e308, 0.0, 0.9e308),
            obs("b", -0.9e308, 0.0, 0.9e308),
        ]
        weights = {"a": 1, "b": 1}
        with self.assertRaises(ValueError):
            locate_weighted_region(observations, policy(weights, 1))

    def test_huge_but_representable_region_succeeds(self):
        observations = [
            obs("a", 1e200, 0.0, 1e200),
            obs("b", -1e200, 0.0, 1e200),
        ]
        weights = {"a": 1, "b": 1}
        region = locate_weighted_region(observations, policy(weights, 1))
        self.assertTrue(region.feasible)
        self.assertEqual(
            region.bounds, (-2e200, -1e200, 2e200, 1e200)
        )
        self.assertEqual(region.witness, (-2e200, 0.0))

    def test_huge_disjoint_disks_still_reported_empty(self):
        observations = [
            obs("a", 1e307, 0.0, 1.0),
            obs("b", -1e307, 0.0, 1.0),
        ]
        weights = {"a": 1, "b": 1}
        region = locate_weighted_region(observations, policy(weights, 2))
        self.assertFalse(region.feasible)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)
        union = locate_weighted_region(observations, policy(weights, 1))
        self.assertTrue(union.feasible)
        self.assertAlmostEqual(union.bounds[0], -1e307 - 1.0, delta=1e-9)
        self.assertAlmostEqual(union.bounds[2], 1e307 + 1.0, delta=1e-9)


if __name__ == "__main__":
    unittest.main()
