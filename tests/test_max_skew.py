"""Tests for the keyword-only ``max_skew`` batch time-span option shared by
``locate_attested`` and ``locate_bound_attested``.

The span is ``max(issued_at) - min(issued_at)`` over *every* record of the
batch; it is compared against ``max_skew`` only after all the existing
per-record checks pass, uses signed timestamps only and never reads the
clock. Passing the span check is independent of the geometric consensus.
"""

import dataclasses
import math
import unittest
from unittest import mock

from nearproof import (
    Consensus,
    RangeDecision,
    attest_observation,
    attest_observation_for_point,
    locate_attested,
    locate_bound_attested,
    make_observation_crl,
    revoke_observation,
)

KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
KEY_D = b"\xdd" * 32
KEY_Z = b"\x7a" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C, "d": KEY_D, "z": KEY_Z}
ROOT = b"\x72" * 32

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def attest(ident, x, y, upper_bound=5.0, *, key=None, issued_at=0.0, **kwargs):
    return attest_observation(
        ident, x, y, decision(upper_bound, **kwargs), issued_at, key or KEYS[ident]
    )


def attest_bound(ident, x, y, upper_bound=5.0, *, key=None, issued_at=0.0,
                 point=POINT, context=CONTEXT, **kwargs):
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound, **kwargs), point, context,
        issued_at, key or KEYS[ident],
    )


def call_plain(observations, **kwargs):
    return locate_attested(observations, POINT, KEYS, **kwargs)


def call_bound(observations, **kwargs):
    return locate_bound_attested(observations, POINT, CONTEXT, KEYS, **kwargs)


ENTRIES = (
    ("plain", call_plain, attest),
    ("bound", call_bound, attest_bound),
)


# Records at issued_at 10, 12 and 15: span 5. The three verifiers form a
# 3-4-5 triangle around the origin and all cover it.
def staggered(make, **kwargs):
    return [
        make("a", 3.0, 0.0, 5.0, issued_at=10, **kwargs),
        make("b", 0.0, 4.0, 5.0, issued_at=12, **kwargs),
        make("c", 0.0, 0.0, 0.0, issued_at=15, **kwargs),
    ]


class MaxSkewSpanTest(unittest.TestCase):
    def test_spec_example_within_limit_passes(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                consensus = call(staggered(make), max_skew=5)
                self.assertEqual(
                    consensus,
                    Consensus(total=3, support=3, rejected=(), accepted=True),
                )

    def test_spec_example_over_limit_raises(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(ValueError):
                    call(staggered(make), max_skew=4)

    def test_boundary_is_closed(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                # Span is exactly 5: equality passes.
                self.assertTrue(call(staggered(make), max_skew=5.0).accepted)
                # A float limit infinitesimally below the span rejects.
                tight = math.nextafter(5.0, 0.0)
                with self.assertRaises(ValueError):
                    call(staggered(make), max_skew=tight)

    def test_integer_times_and_integer_limit(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                self.assertTrue(call(staggered(make), max_skew=5).accepted)
                with self.assertRaises(ValueError):
                    call(staggered(make), max_skew=4)

    def test_zero_requires_identical_times(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                same = [
                    make("a", 3.0, 0.0, 5.0, issued_at=7),
                    make("b", 0.0, 4.0, 5.0, issued_at=7.0),
                    make("c", 0.0, 0.0, 0.0, issued_at=7),
                ]
                self.assertTrue(call(same, max_skew=0).accepted)
                self.assertTrue(call(same, max_skew=0.0).accepted)
                # Any difference, however small, violates a zero limit.
                almost = same[:2] + [
                    make("c", 0.0, 0.0, 0.0, issued_at=7.0 + 1e-12)
                ]
                with self.assertRaises(ValueError):
                    call(almost, max_skew=0)

    def test_span_covers_non_supporting_records(self):
        # z is a legitimate record whose disk does not cover the origin and
        # whose earlier issued_at widens the span to 15 (105 - 90).
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = staggered(make)
                # Move the three supporters forward so they span 5 among
                # themselves; z stays far earlier.
                items = [
                    make("a", 3.0, 0.0, 5.0, issued_at=100),
                    make("b", 0.0, 4.0, 5.0, issued_at=102),
                    make("c", 0.0, 0.0, 0.0, issued_at=105),
                    make("z", 1000.0, 1000.0, 1.0, issued_at=90),
                ]
                with self.assertRaises(ValueError):
                    call(items, max_skew=5)
                # Without the span check z merely shows up rejected; a check
                # limited to supporters would have accepted this batch.
                consensus = call(items)
                self.assertEqual(consensus.rejected, ("z",))
                self.assertTrue(consensus.accepted)

    def test_no_satisfying_subset_is_chosen(self):
        # a/b/c all fit within a 5-second window; d is an older legitimate
        # record. The whole batch must be rejected: no subset is selected.
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = [
                    make("a", 3.0, 0.0, 5.0, issued_at=100),
                    make("b", 0.0, 4.0, 5.0, issued_at=102),
                    make("c", 0.0, 0.0, 0.0, issued_at=105),
                    make("d", 50.0, 0.0, 1.0, issued_at=0),
                ]
                with self.assertRaises(ValueError):
                    call(items, max_skew=5)
                # A window wide enough for the whole batch proceeds normally;
                # d is geometrically rejected but the result, not an error.
                consensus = call(items, max_skew=200)
                self.assertEqual(consensus.rejected, ("d",))
                self.assertTrue(consensus.accepted)


class MaxSkewVersusGeometryTest(unittest.TestCase):
    def test_passing_skew_still_reports_failed_consensus(self):
        # The span check passes, but the disks miss the queried point.
        plain = locate_attested(
            staggered(attest), (100.0, 100.0), KEYS, max_skew=5
        )
        self.assertEqual(plain.support, 0)
        self.assertEqual(plain.rejected, ("a", "b", "c"))
        self.assertFalse(plain.accepted)
        # Bound records are point-bound to the query coordinate itself; their
        # verifier coordinates can still be far enough that the disks miss.
        far_point = (100.0, 100.0)
        far = [
            attest_bound("a", 1000.0, 1000.0, 1.0, issued_at=10, point=far_point),
            attest_bound("b", 1010.0, 1010.0, 1.0, issued_at=12, point=far_point),
            attest_bound("c", 1020.0, 1020.0, 1.0, issued_at=15, point=far_point),
        ]
        bound = locate_bound_attested(
            far, far_point, CONTEXT, KEYS, max_skew=5
        )
        self.assertEqual(bound.support, 0)
        self.assertFalse(bound.accepted)

    def test_skew_raises_before_quorum_shortage_is_returned(self):
        # quorum=5 can never be met by three records; with an excessive span
        # the span error still raises before locate judges the quorum.
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaisesRegex(ValueError, "skew"):
                    call(staggered(make), quorum=5, max_skew=4)


class MaxSkewContractTest(unittest.TestCase):
    def test_invalid_values_raise_value_error(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = staggered(make)
                for bad in (
                    True,
                    False,
                    "5",
                    b"5",
                    -1,
                    -1.0,
                    -0.001,
                    math.nan,
                    math.inf,
                    -math.inf,
                    [5.0],
                    (5.0,),
                    None,
                ):
                    if bad is None:
                        continue
                    with self.subTest(bad=bad):
                        with self.assertRaises(ValueError):
                            call(items, max_skew=bad)

    def test_integer_too_large_for_float_raises_value_error(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(ValueError):
                    call(staggered(make), max_skew=10 ** 400)

    def test_none_disables_the_check(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                # A span of 5 would fail under max_skew=4, but None disables.
                consensus = call(staggered(make), max_skew=None)
                self.assertTrue(consensus.accepted)

    def test_keyword_only_positionally_raises_type_error(self):
        plain = staggered(attest)
        bound = staggered(attest_bound)
        # observations, point, keys, quorum, tolerance, now, max_age, max_skew
        with self.assertRaises(TypeError):
            locate_attested(plain, POINT, KEYS, 3, 0.0, None, None, 5.0)
        # observations, point, context, keys, quorum, tolerance, now,
        # max_age, max_skew
        with self.assertRaises(TypeError):
            locate_bound_attested(
                bound, POINT, CONTEXT, KEYS, 3, 0.0, None, None, 5.0
            )

    def test_validated_before_observations_are_materialized(self):
        # A bad max_skew is a contract error on its own, even when the
        # observation argument itself would fail the iterable contract.
        with self.assertRaisesRegex(ValueError, "max_skew must be"):
            locate_attested(None, POINT, KEYS, max_skew=-1.0)
        with self.assertRaisesRegex(ValueError, "max_skew must be"):
            locate_bound_attested(None, POINT, CONTEXT, KEYS, max_skew=math.nan)

    def test_validation_order_keys_max_age_skew(self):
        items = staggered(attest)
        with self.assertRaisesRegex(ValueError, "keys must be a non-empty mapping"):
            locate_attested(items, POINT, {}, max_age=-1.0, max_skew=-1.0)
        with self.assertRaisesRegex(ValueError, "max_age must be"):
            locate_attested(items, POINT, KEYS, max_age=-1.0, max_skew=-1.0)
        items_bound = staggered(attest_bound)
        with self.assertRaisesRegex(ValueError, "max_age must be"):
            locate_bound_attested(
                items_bound, POINT, CONTEXT, KEYS, max_age="x", max_skew=-1.0
            )


class MaxSkewClockTest(unittest.TestCase):
    def test_skew_alone_never_reads_clock(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with mock.patch("nearproof.time.time") as clock:
                    self.assertTrue(
                        call(staggered(make), max_skew=5).accepted
                    )
                    clock.assert_not_called()

    def test_skew_alone_ignores_now(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                # now is neither validated nor used without a time-based check.
                self.assertTrue(
                    call(staggered(make), now="ignored", max_skew=5).accepted
                )

    def test_skew_with_max_age_reads_clock_once(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with mock.patch(
                    "nearproof.time.time", return_value=120.0
                ) as clock:
                    self.assertTrue(
                        call(
                            staggered(make),
                            max_age=200.0,
                            max_skew=5,
                        ).accepted
                    )
                    self.assertEqual(clock.call_count, 1)

    def test_skew_does_not_relax_max_age(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                # All within a 5-second window but older than max_age.
                with self.assertRaises(ValueError):
                    call(staggered(make), now=100.0, max_age=80.0, max_skew=5)
                # Fresh enough but spread too wide.
                items = [
                    make("a", 3.0, 0.0, 5.0, issued_at=90),
                    make("b", 0.0, 4.0, 5.0, issued_at=92),
                    make("c", 0.0, 0.0, 0.0, issued_at=100),
                ]
                with self.assertRaises(ValueError):
                    call(items, now=100.0, max_age=20.0, max_skew=5)


class MaxSkewCombinedRevocationTest(unittest.TestCase):
    def test_revocation_still_hits_with_skew_enabled(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(ValueError):
                    call(
                        staggered(make),
                        now=100.0,
                        max_skew=5,
                        revocations=[revoke_observation("a", 50.0, KEY_A)],
                    )

    def test_skew_and_snapshot_and_revocations_together(self):
        snapshot = make_observation_crl([], sequence=1, issued_at=0.0, root=ROOT)
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = [
                    make("a", 3.0, 0.0, 5.0, issued_at=100),
                    make("b", 0.0, 4.0, 5.0, issued_at=102),
                    make("c", 0.0, 0.0, 0.0, issued_at=105),
                ]
                consensus = call(
                    items,
                    now=110.0,
                    max_age=20.0,
                    max_skew=5,
                    revocations=[revoke_observation("z", 5.0, KEY_Z)],
                    revocation_list=snapshot,
                    root=ROOT,
                )
                self.assertTrue(consensus.accepted)
                # The same bundle still fails once the span is too wide.
                with self.assertRaises(ValueError):
                    call(
                        items,
                        now=110.0,
                        max_age=20.0,
                        max_skew=4,
                        revocations=[revoke_observation("z", 5.0, KEY_Z)],
                        revocation_list=snapshot,
                        root=ROOT,
                    )

    def test_snapshot_root_type_error_kept(self):
        snapshot = make_observation_crl([], sequence=1, issued_at=0.0, root=ROOT)
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(TypeError):
                    call(
                        staggered(make),
                        max_skew=5,
                        revocation_list=snapshot,
                        root="root",
                        now=10.0,
                    )


class MaxSkewCompatibilityTest(unittest.TestCase):
    def test_omitted_and_none_match_legacy_result(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = staggered(make)
                omitted = call(items)
                explicit_none = call(items, max_skew=None)
                self.assertEqual(omitted, explicit_none)
                self.assertEqual(
                    omitted,
                    Consensus(total=3, support=3, rejected=(), accepted=True),
                )

    def test_order_and_representation_independent(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = staggered(make)
                reversed_items = list(reversed(items))
                mixed = [items[0].to_bytes(), items[2], items[1].to_bytes()]
                baseline = call(items, max_skew=5)
                self.assertEqual(call(reversed_items, max_skew=5), baseline)
                self.assertEqual(call(mixed, max_skew=5), baseline)
                # One-shot iterator.
                self.assertEqual(
                    call(iter(items), max_skew=5), baseline
                )

    def test_inputs_and_records_unchanged(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                items = staggered(make)
                snapshots = [dataclasses.replace(item) for item in items]
                blobs = [item.to_bytes() for item in items]
                call(list(items), max_skew=5)
                self.assertEqual(items, snapshots)
                self.assertEqual([item.to_bytes() for item in items], blobs)

    def test_empty_and_short_batches_still_raise(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(ValueError):
                    call([], max_skew=5)
                with self.assertRaises(ValueError):
                    call(staggered(make)[:2], max_skew=5)

    def test_bad_quorum_and_tolerance_still_raise(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(ValueError):
                    call(staggered(make), quorum=4, max_skew=5)
                with self.assertRaises(ValueError):
                    call(staggered(make), tolerance=-1.0, max_skew=5)

    def test_existing_record_checks_still_raise_with_skew_enabled(self):
        for name, call, make in ENTRIES:
            with self.subTest(entry=name):
                # Unknown id: a structurally valid, MAC'd record signed under a
                # key that has no matching id in KEYS.
                unknown_key = b"\x71" * 32
                items = staggered(make)
                items[0] = make(
                    "q", 3.0, 0.0, 5.0, issued_at=10, key=unknown_key
                )
                with self.assertRaises(ValueError):
                    call(items, max_skew=5)
                # Duplicate id.
                items = staggered(make)
                items.append(items[0])
                with self.assertRaises(ValueError):
                    call(items, max_skew=5)
                # Tampered after signing.
                items = staggered(make)
                items[1] = dataclasses.replace(items[1], x=9.0)
                with self.assertRaises(ValueError):
                    call(items, max_skew=5)

    def test_bound_binding_mismatch_still_raises_with_skew(self):
        items = [
            attest_bound("a", 3.0, 0.0, 5.0, issued_at=10, point=(1.0, 0.0)),
            attest_bound("b", 0.0, 4.0, 5.0, issued_at=12),
            attest_bound("c", 0.0, 0.0, 0.0, issued_at=15),
        ]
        with self.assertRaises(ValueError):
            call_bound(items, max_skew=5)
        items = [
            attest_bound("a", 3.0, 0.0, 5.0, issued_at=10, context="other"),
            attest_bound("b", 0.0, 4.0, 5.0, issued_at=12),
            attest_bound("c", 0.0, 0.0, 0.0, issued_at=15),
        ]
        with self.assertRaises(ValueError):
            call_bound(items, max_skew=5)


if __name__ == "__main__":
    unittest.main()
