"""Tests for assess_attested_geofence.

The entry authenticates a batch of AttestedObservation records under the
exact locate_attested rules (MAC, freshness, whole-batch time span and
both revocation sources) and then classifies the verified records with
assess_geofence's exact geometry.
"""

import math
import unittest
from unittest import mock

from nearproof import (
    AttestedObservation,
    ConsensusPolicy,
    Observation,
    RangeDecision,
    assess_attested_geofence,
    assess_geofence,
    attest_observation,
    make_observation_crl,
    revoke_observation,
)

KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
ROOT = b"\x72" * 32
KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def attest(ident, x, y, upper_bound=5.0, *, key=None, issued_at=100.0, **kwargs):
    return attest_observation(
        ident, x, y, decision(upper_bound, **kwargs), issued_at,
        key or KEYS[ident],
    )


def project(records):
    return [
        Observation(id=r.id, x=r.x, y=r.y, decision=r.decision) for r in records
    ]


# Two disjoint unit disks at the origin and at (4, 0): threshold 1 gives
# the union, threshold 2 the empty region.
DISJOINT = [
    attest("a", 0.0, 0.0, 1.0),
    attest("b", 4.0, 0.0, 1.0),
]
UNION_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 1)
BOTH_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 2)

# Two disks whose intersection lens has circle-meeting points (3, +-4).
LENS = [
    attest("a", 0.0, 0.0, 5.0),
    attest("b", 6.0, 0.0, 5.0),
]
LENS_POLICY = ConsensusPolicy({"a": 1, "b": 1}, 2)


class GeometryEquivalenceTest(unittest.TestCase):
    def test_matches_plain_geofence(self):
        cases = [
            (DISJOINT, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), 0.0),
            (DISJOINT, UNION_POLICY, (10.0, 10.0, 12.0, 12.0), 0.0),
            (DISJOINT, UNION_POLICY, (-2.0, -2.0, 2.0, 2.0), 0.0),
            (DISJOINT, BOTH_POLICY, (-10.0, -10.0, 10.0, 10.0), 0.0),
            (DISJOINT, UNION_POLICY, (1.5, -0.5, 2.5, 0.5), 0.0),
            (LENS, LENS_POLICY, (1.0, -4.0, 5.0, 4.0), 0.0),
            (DISJOINT, UNION_POLICY, (-3.0, -3.0, 7.0, 3.0), 1.25),
        ]
        for records, policy, bounds, tolerance in cases:
            with self.subTest(bounds=bounds, tolerance=tolerance):
                expected = assess_geofence(
                    project(records), policy, bounds, tolerance=tolerance
                )
                actual = assess_attested_geofence(
                    records, policy, bounds, KEYS, tolerance=tolerance
                )
                self.assertEqual(actual, expected)

    def test_returns_one_of_the_four_strings(self):
        result = assess_attested_geofence(
            DISJOINT, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS
        )
        self.assertIsInstance(result, str)
        self.assertIn(result, ("empty", "inside", "outside", "mixed"))

    def test_empty(self):
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, BOTH_POLICY, (-10.0, -10.0, 10.0, 10.0), KEYS
            ),
            "empty",
        )

    def test_inside(self):
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS
            ),
            "inside",
        )

    def test_outside(self):
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, (10.0, 10.0, 12.0, 12.0), KEYS
            ),
            "outside",
        )

    def test_mixed(self):
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, (-2.0, -2.0, 2.0, 2.0), KEYS
            ),
            "mixed",
        )

    def test_single_observation_allowed(self):
        record = attest_observation(
            "only", 1.0, 2.0, decision(3.0), 0.0, b"\x09" * 32
        )
        policy = ConsensusPolicy({"only": 2}, 2)
        self.assertEqual(
            assess_attested_geofence(
                [record], policy, (-3.0, -2.0, 5.0, 6.0), {"only": b"\x09" * 32}
            ),
            "inside",
        )
        self.assertEqual(
            assess_attested_geofence(
                [record], policy, (10.0, 10.0, 12.0, 12.0), {"only": b"\x09" * 32}
            ),
            "outside",
        )

    def test_accepted_flag_and_sample_count_ignored(self):
        records = [
            attest("a", 0.0, 0.0, 1.0, accepted=False, sample_count=99),
            attest("b", 4.0, 0.0, 1.0, accepted=False, sample_count=7),
        ]
        bounds = (-2.0, -2.0, 6.0, 2.0)
        self.assertEqual(
            assess_attested_geofence(records, UNION_POLICY, bounds, KEYS),
            "inside",
        )

    def test_tolerance_only_enlarges_disks(self):
        # Radius-1 disks at (0, 0) and (4, 0) do not meet; tolerance 1
        # makes them externally tangent at (2, 0).
        bounds = (1.5, -0.5, 2.5, 0.5)
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, BOTH_POLICY, bounds, KEYS, tolerance=1.0
            ),
            # The single feasible point (2, 0) lies in the fence.
            "inside",
        )
        # A fence a hair away from the tangent point stays disjoint.
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, BOTH_POLICY, (2.5, 0.5, 3.0, 1.0), KEYS, tolerance=1.0
            ),
            "outside",
        )

    def test_bounding_box_gap_is_not_feasible(self):
        # The fence sits inside the bounding box but in the gap between
        # the two disks: it must report outside, not inside.
        self.assertEqual(
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, (1.5, -0.5, 2.5, 0.5), KEYS
            ),
            "outside",
        )

    def test_degenerate_point_bounds_meets_full_disk_as_mixed(self):
        # The feasible set is the whole disk; only one of its points is
        # the fence, so feasible points exist both sides of the boundary.
        plain = [Observation(id="a", x=0.0, y=0.0, decision=decision(1.0))]
        point = (1.0, 0.0, 1.0, 0.0)
        self.assertEqual(
            assess_attested_geofence(
                [attest("a", 0.0, 0.0, 1.0, issued_at=0.0, key=KEY_A)],
                ConsensusPolicy({"a": 1}, 1),
                point,
                {"a": KEY_A},
            ),
            assess_geofence(plain, ConsensusPolicy({"a": 1}, 1), point),
        )
        self.assertEqual(
            assess_attested_geofence(
                [attest("a", 0.0, 0.0, 1.0, issued_at=0.0, key=KEY_A)],
                ConsensusPolicy({"a": 1}, 1),
                point,
                {"a": KEY_A},
            ),
            "mixed",
        )

    def test_degenerate_point_fence_around_point_feasible_set_is_inside(self):
        # Two radius-2 disks externally tangent at (2, 0): the feasible
        # set is exactly that point, which the point fence contains.
        records = [
            attest("a", 0.0, 0.0, 2.0, issued_at=0.0, key=KEY_A),
            attest("b", 4.0, 0.0, 2.0, issued_at=0.0, key=KEY_B),
        ]
        self.assertEqual(
            assess_attested_geofence(
                records, BOTH_POLICY, (2.0, 0.0, 2.0, 0.0), KEYS
            ),
            "inside",
        )

    def test_degenerate_line_segment_bounds(self):
        # The segment through the disk center is covered but the disk
        # extends beyond it, so the feasible set is mixed against the
        # segment fence; a segment away from the disk is outside.
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=0.0, key=KEY_A)]
        policy = ConsensusPolicy({"a": 1}, 1)
        self.assertEqual(
            assess_attested_geofence(
                records, policy, (-1.0, 0.0, 1.0, 0.0), {"a": KEY_A}
            ),
            "mixed",
        )
        self.assertEqual(
            assess_attested_geofence(
                records, policy, (3.0, 0.0, 5.0, 0.0), {"a": KEY_A}
            ),
            "outside",
        )

    def test_lens_tangency_matches_plain_entry(self):
        shaved = math.nextafter(5.0, 0.0)
        self.assertEqual(
            assess_attested_geofence(
                LENS, LENS_POLICY, (1.0, -4.0, shaved, 4.0), KEYS
            ),
            assess_geofence(
                project(LENS), LENS_POLICY, (1.0, -4.0, shaved, 4.0)
            ),
        )

    def test_huge_and_tiny_finite_values_match_plain_entry(self):
        huge = 1.0e200
        tiny = 1.0e-200
        records = [
            attest_observation(
                "a", 0.0, 0.0, decision(huge), 0.0, KEY_A
            ),
            attest_observation(
                "b", 2.0 * huge, 0.0, decision(huge), 0.0, KEY_B
            ),
        ]
        policy = ConsensusPolicy({"a": 1, "b": 1}, 2)
        # Externally tangent at (huge, 0) without tolerance.
        for bounds in (
            (huge - 1.0, -1.0, huge + 1.0, 1.0),
            (3.0 * huge, 0.0, 4.0 * huge, 1.0),
        ):
            with self.subTest(bounds=bounds):
                self.assertEqual(
                    assess_attested_geofence(records, policy, bounds, KEYS),
                    assess_geofence(project(records), policy, bounds),
                )
        small_records = [
            attest_observation(
                "a", 0.0, 0.0, decision(tiny), 0.0, KEY_A
            ),
            attest_observation(
                "b", 2.0 * tiny, 0.0, decision(tiny), 0.0, KEY_B
            ),
        ]
        tangent = (tiny, 0.0, tiny, 0.0)
        self.assertEqual(
            assess_attested_geofence(small_records, policy, tangent, KEYS),
            assess_geofence(project(small_records), policy, tangent),
        )


class InputShapeTest(unittest.TestCase):
    def test_generator_consumed_once(self):
        gen = (record for record in DISJOINT)
        self.assertEqual(
            assess_attested_geofence(gen, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS),
            assess_geofence(project(DISJOINT), UNION_POLICY, (-2.0, -2.0, 6.0, 2.0)),
        )

    def test_objects_and_bytes_mix(self):
        mixed = [DISJOINT[0], DISJOINT[1].to_bytes()]
        self.assertEqual(
            assess_attested_geofence(
                mixed, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS
            ),
            "inside",
        )

    def test_single_bytes_item(self):
        record = DISJOINT[0]
        self.assertEqual(
            assess_attested_geofence(
                [record.to_bytes()],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
            ),
            "inside",
        )

    def test_shuffled_input_is_identical(self):
        bounds = (-2.0, -2.0, 2.0, 2.0)
        self.assertEqual(
            assess_attested_geofence(DISJOINT, UNION_POLICY, bounds, KEYS),
            assess_attested_geofence(
                [DISJOINT[1], DISJOINT[0]], UNION_POLICY, bounds, KEYS
            ),
        )

    def test_shuffled_keys_is_identical(self):
        bounds = (-2.0, -2.0, 6.0, 2.0)
        reversed_keys = {"b": KEY_B, "a": KEY_A}
        self.assertEqual(
            assess_attested_geofence(DISJOINT, UNION_POLICY, bounds, KEYS),
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, bounds, reversed_keys
            ),
        )

    def test_inputs_not_mutated(self):
        mixed = [DISJOINT[0], DISJOINT[1].to_bytes()]
        before = [mixed[0], bytes(mixed[1])]
        assess_attested_geofence(
            mixed, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS
        )
        self.assertEqual(mixed[0], before[0])
        self.assertEqual(mixed[1], before[1])

    def test_options_are_keyword_only(self):
        with self.assertRaises(TypeError):
            assess_attested_geofence(  # type: ignore[misc]
                DISJOINT, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS, 0.0
            )

    def test_unknown_keyword_rejected(self):
        with self.assertRaises(TypeError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                (-2.0, -2.0, 6.0, 2.0),
                KEYS,
                quorum=1,  # type: ignore[call-arg]
            )

    def test_non_iterable_observations(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                42, UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS
            )

    def test_empty_observations_rejected(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [], UNION_POLICY, (-2.0, -2.0, 6.0, 2.0), KEYS
            )


class ContractViolationTest(unittest.TestCase):
    BOUNDS = (-2.0, -2.0, 6.0, 2.0)

    def test_bad_keys(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(DISJOINT, UNION_POLICY, self.BOUNDS, {})
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                {"a": b"", "b": KEY_B},
            )

    def test_unknown_observation_id(self):
        record = attest_observation(
            "x", 0.0, 0.0, decision(1.0), 0.0, b"\x01" * 32
        )
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [DISJOINT[0], record],
                ConsensusPolicy({"a": 1, "x": 1}, 1),
                self.BOUNDS,
                KEYS,
            )

    def test_duplicate_observation_id(self):
        duplicate = attest("a", 4.0, 0.0, 1.0)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [DISJOINT[0], duplicate],
                ConsensusPolicy({"a": 1}, 1),
                self.BOUNDS,
                KEYS,
            )

    def test_wrong_key(self):
        record = attest("a", 0.0, 0.0, 1.0, key=b"\x01" * 32)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [record], ConsensusPolicy({"a": 1}, 1), self.BOUNDS, KEYS
            )

    def test_tampered_encoding(self):
        blob = bytearray(DISJOINT[0].to_bytes())
        blob[-2] = ord("0") if chr(blob[-2]) != "0" else ord("1")
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [bytes(blob)],
                ConsensusPolicy({"a": 1}, 1),
                self.BOUNDS,
                KEYS,
            )

    def test_non_canonical_encoding(self):
        blob = b" " + DISJOINT[0].to_bytes()
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [blob], ConsensusPolicy({"a": 1}, 1), self.BOUNDS, KEYS
            )

    def test_wrong_record_type(self):
        revocation = revoke_observation("a", 0.0, KEY_A)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [DISJOINT[0], revocation], UNION_POLICY, self.BOUNDS, KEYS
            )

    def test_policy_must_be_consensus_policy(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(DISJOINT, object(), self.BOUNDS, KEYS)

    def test_policy_extra_id_rejected(self):
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 1)
        with self.assertRaises(ValueError):
            assess_attested_geofence(DISJOINT, policy, self.BOUNDS, KEYS)

    def test_policy_missing_id_rejected(self):
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            assess_attested_geofence(DISJOINT, policy, self.BOUNDS, KEYS)

    def test_invalid_tolerance(self):
        for bad in (True, -0.1, float("nan"), float("inf"), "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_attested_geofence(
                        DISJOINT, UNION_POLICY, self.BOUNDS, KEYS,
                        tolerance=bad,
                    )

    def test_bounds_must_be_a_four_tuple(self):
        for bad in (
            [-2.0, -2.0, 6.0, 2.0],
            (-2.0, -2.0, 6.0),
            (-2.0, -2.0, 6.0, 2.0, 0.0),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_attested_geofence(
                        DISJOINT, UNION_POLICY, bad, KEYS
                    )

    def test_bounds_values_must_be_finite_non_bool_numbers(self):
        for bad in (
            (True, -2.0, 6.0, 2.0),
            (-2.0, "0", 6.0, 2.0),
            (float("nan"), -2.0, 6.0, 2.0),
            (-2.0, -2.0, float("inf"), 2.0),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_attested_geofence(
                        DISJOINT, UNION_POLICY, bad, KEYS
                    )

    def test_bounds_must_be_ordered(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, (6.0, -2.0, -2.0, 2.0), KEYS
            )
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, (-2.0, 2.0, 6.0, -2.0), KEYS
            )

    def test_authentication_runs_before_geometry(self):
        # Even a trailing observation the geometry would never need must
        # authenticate.
        bad = DISJOINT[1].to_bytes() + b" "
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [DISJOINT[0], bad], UNION_POLICY, self.BOUNDS, KEYS
            )

    def test_trailing_material_checked_when_result_already_outside(self):
        # The fence only ever covers disk a; the bad trailing record (b)
        # must still be rejected instead of silently dropped.
        bad = DISJOINT[1].to_bytes() + b" "
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [DISJOINT[0], bad],
                UNION_POLICY,
                (-2.0, -2.0, 2.0, 2.0),
                KEYS,
            )


class FreshnessTest(unittest.TestCase):
    BOUNDS = (-2.0, -2.0, 6.0, 2.0)

    def test_closed_age_interval(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        policy = ConsensusPolicy({"a": 1}, 1)
        assess_attested_geofence(
            records, policy, (-1.0, -1.0, 1.0, 1.0), KEYS,
            now=100.0, max_age=0.0,
        )
        assess_attested_geofence(
            records, policy, (-1.0, -1.0, 1.0, 1.0), KEYS,
            now=110.0, max_age=10.0,
        )

    def test_stale_record_rejected(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                records,
                ConsensusPolicy({"a": 1}, 1),
                self.BOUNDS,
                KEYS,
                now=110.0 + 1e-9,
                max_age=10.0,
            )

    def test_future_record_rejected(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                records,
                ConsensusPolicy({"a": 1}, 1),
                self.BOUNDS,
                KEYS,
                now=99.0,
                max_age=10.0,
            )

    def test_bad_now(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        for bad in (True, "100", float("inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_attested_geofence(
                        records,
                        ConsensusPolicy({"a": 1}, 1),
                        self.BOUNDS,
                        KEYS,
                        now=bad,
                        max_age=10.0,
                    )

    def test_bad_max_age(self):
        for bad in (True, -1.0, float("nan"), float("inf"), "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_attested_geofence(
                        DISJOINT, UNION_POLICY, self.BOUNDS, KEYS,
                        max_age=bad,
                    )

    def test_clock_read_once_for_freshness(self):
        with mock.patch(
            "nearproof.time.time", return_value=100.0
        ) as clock:
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, self.BOUNDS, KEYS, max_age=1000.0
            )
            self.assertEqual(clock.call_count, 1)

    def test_no_clock_read_without_checks(self):
        with mock.patch("nearproof.time.time") as clock:
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, self.BOUNDS, KEYS
            )
            self.assertFalse(clock.called)


class SpanTest(unittest.TestCase):
    BOUNDS = (-20.0, -20.0, 120.0, 120.0)

    def test_span_includes_non_contributing_observations(self):
        # Threshold needs only a, but c's late issuance still counts.
        records = [
            attest("a", 0.0, 0.0, 1.0, issued_at=0.0),
            attest("b", 4.0, 0.0, 1.0, issued_at=0.0),
            attest("c", 100.0, 100.0, 0.1, issued_at=50.0),
        ]
        policy = ConsensusPolicy({"a": 10, "b": 1, "c": 1}, 10)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                records, policy, self.BOUNDS, KEYS, max_skew=10.0
            )

    def test_span_at_limit_is_accepted(self):
        records = [
            attest("a", 0.0, 0.0, 1.0, issued_at=0.0),
            attest("b", 4.0, 0.0, 1.0, issued_at=10.0),
        ]
        assess_attested_geofence(
            records, UNION_POLICY, self.BOUNDS, KEYS, max_skew=10.0
        )

    def test_span_only_reads_no_clock(self):
        with mock.patch("nearproof.time.time") as clock:
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, self.BOUNDS, KEYS, max_skew=1000.0
            )
            self.assertFalse(clock.called)

    def test_bad_max_skew(self):
        for bad in (True, -0.1, float("nan"), float("inf"), "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    assess_attested_geofence(
                        DISJOINT, UNION_POLICY, self.BOUNDS, KEYS,
                        max_skew=bad,
                    )

    def test_huge_integer_max_skew_rejected(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT, UNION_POLICY, self.BOUNDS, KEYS,
                max_skew=10 ** 400,
            )


class RevocationTest(unittest.TestCase):
    BOUNDS = (-2.0, -2.0, 6.0, 2.0)

    def test_observation_at_revocation_time_rejected(self):
        revocation = revoke_observation("a", 100.0, KEY_A)
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
                revocations=[revocation],
                now=100.0,
            )

    def test_observation_strictly_after_revocation_kept(self):
        revocation = revoke_observation("a", 100.0, KEY_A)
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0 + 1e-9)
        result = assess_attested_geofence(
            [record],
            ConsensusPolicy({"a": 1}, 1),
            (-1.0, -1.0, 1.0, 1.0),
            KEYS,
            revocations=[revocation],
            now=200.0,
        )
        self.assertEqual(result, "inside")

    def test_revocation_bytes_mix(self):
        revocation = revoke_observation("a", 100.0, KEY_A)
        record = attest("a", 0.0, 0.0, 1.0, issued_at=50.0)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
                revocations=[revocation.to_bytes()],
                now=100.0,
            )

    def test_future_revocation_rejected(self):
        revocation = revoke_observation("a", 200.0, KEY_A)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
                revocations=[revocation],
                now=150.0,
            )

    def test_unknown_revocation_id_rejected(self):
        revocation = revoke_observation("z", 0.0, b"\x5a" * 32)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocations=[revocation],
                now=100.0,
            )

    def test_duplicate_revocation_id_rejected(self):
        revocations = [
            revoke_observation("a", 0.0, KEY_A),
            revoke_observation("a", 10.0, KEY_A),
        ]
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocations=revocations,
                now=100.0,
            )

    def test_tampered_revocation_rejected(self):
        blob = bytearray(revoke_observation("a", 0.0, KEY_A).to_bytes())
        blob[-2] = ord("0") if chr(blob[-2]) != "0" else ord("1")
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocations=[bytes(blob)],
                now=100.0,
            )

    def test_wrong_revocation_type_rejected(self):
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocations=[42],
                now=100.0,
            )

    def test_trailing_revocation_checked_when_geometry_settled(self):
        # A bad revocation (unknown id) after valid observations must
        # still surface, even though the geometry alone would be inside.
        bad = revoke_observation("z", 0.0, b"\x5a" * 32)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocations=[bad],
                now=100.0,
            )

    def test_revocation_iterable_consumed(self):
        revoked = [revoke_observation("a", 60.0, KEY_A)]
        record = attest("a", 0.0, 0.0, 1.0, issued_at=50.0)

        def gen():
            yield from revoked

        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
                revocations=gen(),
                now=100.0,
            )

    def test_default_now_reads_clock_at_most_once(self):
        records = [attest("b", 4.0, 0.0, 1.0, issued_at=50.0)]
        with mock.patch(
            "nearproof.time.time", return_value=100.0
        ) as clock:
            assess_attested_geofence(
                records,
                ConsensusPolicy({"b": 1}, 1),
                (3.0, -1.0, 5.0, 1.0),
                KEYS,
                revocations=[revoke_observation("b", 0.0, KEY_B)],
            )
            self.assertEqual(clock.call_count, 1)


class SnapshotTest(unittest.TestCase):
    BOUNDS = (-2.0, -2.0, 6.0, 2.0)

    def crl(self, entries, *, sequence=1, issued_at=90.0):
        return make_observation_crl(entries, sequence, issued_at, ROOT)

    def test_snapshot_requires_explicit_now(self):
        snapshot = self.crl([revoke_observation("a", 0.0, KEY_A)])
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
            )

    def test_snapshot_does_not_read_clock(self):
        snapshot = self.crl([])
        with mock.patch("nearproof.time.time") as clock:
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )
            self.assertFalse(clock.called)

    def test_root_must_be_bytes(self):
        snapshot = self.crl([])
        with self.assertRaises(TypeError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=bytearray(ROOT),
                now=100.0,
            )

    def test_empty_root_rejected(self):
        snapshot = self.crl([])
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=b"",
                now=100.0,
            )

    def test_snapshot_hit_rejects(self):
        snapshot = self.crl([revoke_observation("a", 100.0, KEY_A)])
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )

    def test_snapshot_bytes_form(self):
        snapshot = self.crl(
            [revoke_observation("a", 100.0, KEY_A)]
        ).to_bytes()
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0 + 1e-9)
        result = assess_attested_geofence(
            [record],
            ConsensusPolicy({"a": 1}, 1),
            (-1.0, -1.0, 1.0, 1.0),
            KEYS,
            revocation_list=snapshot,
            root=ROOT,
            now=100.0,
        )
        self.assertEqual(result, "inside")

    def test_both_sources_require_later_than_each_revocation(self):
        per_call = [revoke_observation("a", 80.0, KEY_A)]
        snapshot = self.crl([revoke_observation("a", 90.0, KEY_A)])
        record = attest("a", 0.0, 0.0, 1.0, issued_at=85.0)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                (-1.0, -1.0, 1.0, 1.0),
                KEYS,
                revocations=per_call,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )
        fresh = attest("a", 0.0, 0.0, 1.0, issued_at=90.0 + 1e-9)
        result = assess_attested_geofence(
            [fresh],
            ConsensusPolicy({"a": 1}, 1),
            (-1.0, -1.0, 1.0, 1.0),
            KEYS,
            revocations=per_call,
            revocation_list=snapshot,
            root=ROOT,
            now=100.0,
        )
        self.assertEqual(result, "inside")

    def test_sequence_below_min_rejected(self):
        snapshot = self.crl([], sequence=3)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
                min=4,
            )

    def test_future_snapshot_rejected(self):
        snapshot = self.crl([], issued_at=110.0)
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )

    def test_tampered_snapshot_rejected(self):
        blob = bytearray(self.crl([]).to_bytes())
        blob[-2] = ord("0") if chr(blob[-2]) != "0" else ord("1")
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=bytes(blob),
                root=ROOT,
                now=100.0,
            )

    def test_snapshot_entry_unknown_to_keys_rejected(self):
        entry = revoke_observation("z", 0.0, b"\x5a" * 32)
        snapshot = self.crl([entry])
        with self.assertRaises(ValueError):
            assess_attested_geofence(
                DISJOINT,
                UNION_POLICY,
                self.BOUNDS,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )


if __name__ == "__main__":
    unittest.main()
