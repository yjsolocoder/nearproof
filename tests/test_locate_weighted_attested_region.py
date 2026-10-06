"""Tests for locate_weighted_attested_region.

The entry authenticates a batch of AttestedObservation records under the
exact locate_attested rules (MAC, freshness, whole-batch time span and
both revocation sources) and then feeds the verified records to
locate_weighted_region unchanged.
"""

import dataclasses
import math
import unittest
from unittest import mock

from nearproof import (
    AttestedObservation,
    ConsensusPolicy,
    Observation,
    RangeDecision,
    RegionDecision,
    attest_observation,
    locate_weighted_attested_region,
    locate_weighted_region,
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

# Three disks: a and b form a lens inside c.
LENS = [
    attest("a", 0.0, 0.0, 5.0),
    attest("b", 6.0, 0.0, 5.0),
    attest("c", 3.0, 0.0, 10.0),
]
LENS_POLICY = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 3)


class GeometryEquivalenceTest(unittest.TestCase):
    def test_matches_plain_weighted_region(self):
        for records, policy, tolerance in (
            (DISJOINT, UNION_POLICY, 0.0),
            (DISJOINT, BOTH_POLICY, 0.0),
            (LENS, LENS_POLICY, 0.0),
            (LENS, ConsensusPolicy({"a": 2, "b": 1, "c": 1}, 3), 0.75),
            (DISJOINT, UNION_POLICY, 2),
        ):
            expected = locate_weighted_region(
                project(records), policy, tolerance=tolerance
            )
            actual = locate_weighted_attested_region(
                records, policy, KEYS, tolerance=tolerance
            )
            self.assertEqual(actual, expected)

    def test_disconnected_region_returns_overall_box(self):
        region = locate_weighted_attested_region(
            DISJOINT, UNION_POLICY, KEYS
        )
        self.assertIsInstance(region, RegionDecision)
        self.assertTrue(region.feasible)
        # Bounds span both disks even though the middle gap is infeasible.
        self.assertEqual(region.bounds, (-1.0, -1.0, 5.0, 1.0))
        self.assertEqual(region.witness, (-1.0, 0.0))

    def test_infeasible_region(self):
        region = locate_weighted_attested_region(DISJOINT, BOTH_POLICY, KEYS)
        self.assertIs(region.feasible, False)
        self.assertIsNone(region.bounds)
        self.assertIsNone(region.witness)

    def test_result_is_frozen(self):
        region = locate_weighted_attested_region(DISJOINT, UNION_POLICY, KEYS)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            region.feasible = False

    def test_accepted_flag_ignored(self):
        records = [
            attest("a", 0.0, 0.0, 1.0, accepted=False),
            attest("b", 4.0, 0.0, 1.0, accepted=False),
        ]
        region = locate_weighted_attested_region(
            records, UNION_POLICY, KEYS
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-1.0, -1.0, 5.0, 1.0))

    def test_single_verifier_allowed(self):
        policy = ConsensusPolicy({"only": 4}, 4)
        record = attest_observation(
            "only", 1.0, 2.0, decision(3.0), 0.0, b"\x09" * 32
        )
        region = locate_weighted_attested_region(
            [record], policy, {"only": b"\x09" * 32}
        )
        self.assertTrue(region.feasible)
        self.assertEqual(region.bounds, (-2.0, -1.0, 4.0, 5.0))
        self.assertEqual(region.witness, (-2.0, 2.0))

    def test_tolerance_extends_disks(self):
        records = [
            attest("a", 0.0, 0.0, 1.0),
            attest("b", 4.0, 0.0, 1.0),
        ]
        without = locate_weighted_attested_region(
            records, BOTH_POLICY, KEYS, tolerance=0.0
        )
        self.assertFalse(without.feasible)
        with_tolerance = locate_weighted_attested_region(
            records, BOTH_POLICY, KEYS, tolerance=1.0
        )
        # Radius 2 disks are externally tangent at (2, 0).
        self.assertTrue(with_tolerance.feasible)
        self.assertEqual(with_tolerance.bounds, (2.0, 0.0, 2.0, 0.0))
        self.assertEqual(with_tolerance.witness, (2.0, 0.0))


class InputShapeTest(unittest.TestCase):
    def test_generator_consumed_once(self):
        gen = (record for record in DISJOINT)
        region = locate_weighted_attested_region(gen, UNION_POLICY, KEYS)
        self.assertEqual(
            region, locate_weighted_region(project(DISJOINT), UNION_POLICY)
        )

    def test_objects_and_bytes_mix(self):
        mixed = [DISJOINT[0], DISJOINT[1].to_bytes()]
        region = locate_weighted_attested_region(mixed, UNION_POLICY, KEYS)
        self.assertEqual(
            region, locate_weighted_region(project(DISJOINT), UNION_POLICY)
        )

    def test_shuffled_input_is_identical(self):
        shuffled = [DISJOINT[1], DISJOINT[0]]
        self.assertEqual(
            locate_weighted_attested_region(DISJOINT, UNION_POLICY, KEYS),
            locate_weighted_attested_region(shuffled, UNION_POLICY, KEYS),
        )

    def test_shuffled_keys_is_identical(self):
        reversed_keys = {"b": KEY_B, "a": KEY_A}
        self.assertEqual(
            locate_weighted_attested_region(DISJOINT, UNION_POLICY, KEYS),
            locate_weighted_attested_region(
                DISJOINT, UNION_POLICY, reversed_keys
            ),
        )

    def test_inputs_not_mutated(self):
        mixed = [DISJOINT[0], DISJOINT[1].to_bytes()]
        before = [mixed[0], bytes(mixed[1])]
        locate_weighted_attested_region(mixed, UNION_POLICY, KEYS)
        self.assertEqual(mixed[0], before[0])
        self.assertEqual(mixed[1], before[1])

    def test_no_point_or_quorum_parameters(self):
        with self.assertRaises(TypeError):
            locate_weighted_attested_region(  # type: ignore[misc]
                DISJOINT, (0.0, 0.0), UNION_POLICY, KEYS
            )
        with self.assertRaises(TypeError):
            locate_weighted_attested_region(
                DISJOINT, UNION_POLICY, KEYS, quorum=1
            )

    def test_options_are_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_weighted_attested_region(  # type: ignore[misc]
                DISJOINT, UNION_POLICY, KEYS, 0.0
            )

    def test_non_iterable_observations(self):
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(42, UNION_POLICY, KEYS)


class ContractViolationTest(unittest.TestCase):
    def test_bad_keys(self):
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(DISJOINT, UNION_POLICY, {})
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT, UNION_POLICY, {"a": b"", "b": KEY_B}
            )

    def test_unknown_observation_id(self):
        record = attest_observation(
            "x", 0.0, 0.0, decision(1.0), 0.0, b"\x01" * 32
        )
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [DISJOINT[0], record],
                ConsensusPolicy({"a": 1, "x": 1}, 1),
                KEYS,
            )

    def test_duplicate_observation_id(self):
        duplicate = attest("a", 4.0, 0.0, 1.0)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [DISJOINT[0], duplicate],
                ConsensusPolicy({"a": 1}, 1),
                KEYS,
            )

    def test_wrong_key(self):
        record = attest("a", 0.0, 0.0, 1.0, key=b"\x01" * 32)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [record], ConsensusPolicy({"a": 1}, 1), KEYS
            )

    def test_tampered_encoding(self):
        blob = bytearray(DISJOINT[0].to_bytes())
        # Flip the last hex nibble of the MAC (just before the closing
        # brace): still valid canonical-shaped JSON, but a wrong MAC.
        blob[-2] = ord("0") if chr(blob[-2]) != "0" else ord("1")
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [bytes(blob)], ConsensusPolicy({"a": 1}, 1), KEYS
            )

    def test_non_canonical_encoding(self):
        blob = b" " + DISJOINT[0].to_bytes()
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [blob], ConsensusPolicy({"a": 1}, 1), KEYS
            )

    def test_wrong_record_type(self):
        revocation = revoke_observation("a", 0.0, KEY_A)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [DISJOINT[0], revocation], UNION_POLICY, KEYS
            )

    def test_policy_must_be_consensus_policy(self):
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(DISJOINT, object(), KEYS)

    def test_policy_extra_id_rejected(self):
        policy = ConsensusPolicy({"a": 1, "b": 1, "c": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(DISJOINT, policy, KEYS)

    def test_policy_missing_id_rejected(self):
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(DISJOINT, policy, KEYS)

    def test_invalid_tolerance(self):
        for bad in (True, -0.1, float("nan"), float("inf"), "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate_weighted_attested_region(
                        DISJOINT, UNION_POLICY, KEYS, tolerance=bad
                    )

    def test_authentication_runs_before_region_judgement(self):
        # Even an observation the region would never need (its disk is
        # disjoint from the threshold-reaching set) must authenticate.
        bad = DISJOINT[1].to_bytes() + b" "
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [DISJOINT[0], bad], UNION_POLICY, KEYS
            )


class FreshnessTest(unittest.TestCase):
    def test_closed_age_interval(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        policy = ConsensusPolicy({"a": 1}, 1)
        # issued exactly max_age ago and issued now are both accepted.
        locate_weighted_attested_region(
            records, policy, KEYS, now=100.0, max_age=0.0
        )
        locate_weighted_attested_region(
            records, policy, KEYS, now=110.0, max_age=10.0
        )

    def test_stale_record_rejected(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                records, policy, KEYS, now=110.0 + 1e-9, max_age=10.0
            )

    def test_future_record_rejected(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        policy = ConsensusPolicy({"a": 1}, 1)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                records, policy, KEYS, now=99.0, max_age=10.0
            )

    def test_bad_now(self):
        records = [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)]
        policy = ConsensusPolicy({"a": 1}, 1)
        for bad in (True, "100", float("inf")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate_weighted_attested_region(
                        records, policy, KEYS, now=bad, max_age=10.0
                    )

    def test_bad_max_age(self):
        for bad in (True, -1.0, float("nan"), float("inf"), "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate_weighted_attested_region(
                        DISJOINT, UNION_POLICY, KEYS, max_age=bad
                    )

    def test_clock_read_once_for_freshness(self):
        with mock.patch(
            "nearproof.time.time", return_value=100.0
        ) as clock:
            locate_weighted_attested_region(
                DISJOINT, UNION_POLICY, KEYS, max_age=1000.0
            )
            self.assertEqual(clock.call_count, 1)

    def test_no_clock_read_without_checks(self):
        with mock.patch("nearproof.time.time") as clock:
            locate_weighted_attested_region(DISJOINT, UNION_POLICY, KEYS)
            self.assertFalse(clock.called)


class SpanTest(unittest.TestCase):
    def test_span_includes_non_contributing_observations(self):
        # Threshold needs only a, but c's late issuance still counts.
        records = [
            attest("a", 0.0, 0.0, 1.0, issued_at=0.0),
            attest("b", 4.0, 0.0, 1.0, issued_at=0.0),
            attest("c", 100.0, 100.0, 0.1, issued_at=50.0),
        ]
        policy = ConsensusPolicy({"a": 10, "b": 1, "c": 1}, 10)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                records, policy, KEYS, max_skew=10.0
            )

    def test_span_at_limit_is_accepted(self):
        records = [
            attest("a", 0.0, 0.0, 1.0, issued_at=0.0),
            attest("b", 4.0, 0.0, 1.0, issued_at=10.0),
        ]
        locate_weighted_attested_region(
            records, UNION_POLICY, KEYS, max_skew=10.0
        )

    def test_span_only_reads_no_clock(self):
        with mock.patch("nearproof.time.time") as clock:
            locate_weighted_attested_region(
                DISJOINT, UNION_POLICY, KEYS, max_skew=1000.0
            )
            self.assertFalse(clock.called)

    def test_bad_max_skew(self):
        for bad in (True, -0.1, float("nan"), float("inf"), "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    locate_weighted_attested_region(
                        DISJOINT, UNION_POLICY, KEYS, max_skew=bad
                    )

    def test_huge_integer_max_skew_rejected(self):
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT, UNION_POLICY, KEYS, max_skew=10 ** 400
            )


class RevocationTest(unittest.TestCase):
    def test_observation_at_revocation_time_rejected(self):
        revocation = revoke_observation("a", 100.0, KEY_A)
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                KEYS,
                revocations=[revocation],
                now=100.0,
            )

    def test_observation_strictly_after_revocation_kept(self):
        revocation = revoke_observation("a", 100.0, KEY_A)
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0 + 1e-9)
        region = locate_weighted_attested_region(
            [record],
            ConsensusPolicy({"a": 1}, 1),
            KEYS,
            revocations=[revocation],
            now=200.0,
        )
        self.assertTrue(region.feasible)

    def test_revocation_bytes_mix(self):
        revocation = revoke_observation("a", 100.0, KEY_A)
        record = attest("a", 0.0, 0.0, 1.0, issued_at=50.0)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                KEYS,
                revocations=[revocation.to_bytes()],
                now=100.0,
            )

    def test_future_revocation_rejected(self):
        revocation = revoke_observation("a", 200.0, KEY_A)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [attest("a", 0.0, 0.0, 1.0, issued_at=100.0)],
                ConsensusPolicy({"a": 1}, 1),
                KEYS,
                revocations=[revocation],
                now=150.0,
            )

    def test_unknown_revocation_id_rejected(self):
        revocation = revoke_observation("z", 0.0, b"\x5a" * 32)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
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
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocations=revocations,
                now=100.0,
            )

    def test_tampered_revocation_rejected(self):
        blob = bytearray(revoke_observation("a", 0.0, KEY_A).to_bytes())
        blob[-2] = ord("0") if chr(blob[-2]) != "0" else ord("1")
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocations=[bytes(blob)],
                now=100.0,
            )

    def test_wrong_revocation_type_rejected(self):
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocations=[42],
                now=100.0,
            )


class SnapshotTest(unittest.TestCase):
    def crl(self, entries, *, sequence=1, issued_at=90.0):
        return make_observation_crl(entries, sequence, issued_at, ROOT)

    def test_snapshot_requires_explicit_now(self):
        snapshot = self.crl([revoke_observation("a", 0.0, KEY_A)])
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
            )

    def test_snapshot_does_not_read_clock(self):
        snapshot = self.crl([])
        with mock.patch("nearproof.time.time") as clock:
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )
            self.assertFalse(clock.called)

    def test_root_must_be_bytes(self):
        snapshot = self.crl([])
        with self.assertRaises(TypeError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=bytearray(ROOT),
                now=100.0,
            )

    def test_empty_root_rejected(self):
        snapshot = self.crl([])
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=b"",
                now=100.0,
            )

    def test_snapshot_hit_rejects(self):
        snapshot = self.crl([revoke_observation("a", 100.0, KEY_A)])
        record = attest("a", 0.0, 0.0, 1.0, issued_at=100.0)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [record],
                ConsensusPolicy({"a": 1}, 1),
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
        region = locate_weighted_attested_region(
            [record],
            ConsensusPolicy({"a": 1}, 1),
            KEYS,
            revocation_list=snapshot,
            root=ROOT,
            now=100.0,
        )
        self.assertTrue(region.feasible)

    def test_both_sources_require_later_than_each_revocation(self):
        # Per-call revocation at 80, snapshot entry at 90: issuance 85 is
        # after the per-call hit but before the snapshot's.
        per_call = [revoke_observation("a", 80.0, KEY_A)]
        snapshot = self.crl([revoke_observation("a", 90.0, KEY_A)])
        record = attest("a", 0.0, 0.0, 1.0, issued_at=85.0)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                [record],
                ConsensusPolicy({"a": 1}, 1),
                KEYS,
                revocations=per_call,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )
        fresh = attest("a", 0.0, 0.0, 1.0, issued_at=90.0 + 1e-9)
        region = locate_weighted_attested_region(
            [fresh],
            ConsensusPolicy({"a": 1}, 1),
            KEYS,
            revocations=per_call,
            revocation_list=snapshot,
            root=ROOT,
            now=100.0,
        )
        self.assertTrue(region.feasible)

    def test_sequence_below_min_rejected(self):
        snapshot = self.crl([], sequence=3)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
                min=4,
            )

    def test_future_snapshot_rejected(self):
        snapshot = self.crl([], issued_at=110.0)
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )

    def test_tampered_snapshot_rejected(self):
        blob = bytearray(self.crl([]).to_bytes())
        # Flip a nibble inside the list MAC (last hex nibble sits just
        # before the closing brace).
        blob[-2] = ord("0") if chr(blob[-2]) != "0" else ord("1")
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=bytes(blob),
                root=ROOT,
                now=100.0,
            )

    def test_snapshot_entry_unknown_to_keys_rejected(self):
        entry = revoke_observation("z", 0.0, b"\x5a" * 32)
        snapshot = self.crl([entry])
        with self.assertRaises(ValueError):
            locate_weighted_attested_region(
                DISJOINT,
                UNION_POLICY,
                KEYS,
                revocation_list=snapshot,
                root=ROOT,
                now=100.0,
            )


if __name__ == "__main__":
    unittest.main()
