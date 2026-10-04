"""Regression tests for the shared verification flow of locate_attested
and locate_bound_attested.

Both public entries must judge freshness and revocation identically, read
the clock at most once per call, keep their own record types and (for the
bound entry) point/context binding semantics, and preserve the exact
validation order and exception types of the pre-refactor baseline.
"""

import dataclasses
import math
import unittest
from unittest import mock

from nearproof import (
    AttestedObservation,
    BoundAttestedObservation,
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


# Three verifiers at the corners of a 3-4-5 triangle around the origin.
def triangle(**kwargs):
    return [
        attest("a", 3.0, 0.0, 5.0, **kwargs),
        attest("b", 0.0, 4.0, 5.0, **kwargs),
        attest("c", 0.0, 0.0, 0.0, **kwargs),
    ]


def triangle_bound(**kwargs):
    return [
        attest_bound("a", 3.0, 0.0, 5.0, **kwargs),
        attest_bound("b", 0.0, 4.0, 5.0, **kwargs),
        attest_bound("c", 0.0, 0.0, 0.0, **kwargs),
    ]


def crl(entries, *, sequence=1, issued_at=0.0, root=ROOT):
    return make_observation_crl(entries, sequence, issued_at, root)


def call_plain(observations, **kwargs):
    return locate_attested(observations, POINT, KEYS, **kwargs)


def call_bound(observations, **kwargs):
    return locate_bound_attested(observations, POINT, CONTEXT, KEYS, **kwargs)


ENTRIES = (
    ("plain", call_plain, triangle),
    ("bound", call_bound, triangle_bound),
)


class SuccessAndRejectionTest(unittest.TestCase):
    """Existing success and refusal scenarios, kept identical for both
    entries after the refactor."""

    def test_success_both_entries(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                consensus = call(records())
                self.assertIsInstance(consensus, Consensus)
                self.assertEqual(
                    consensus, Consensus(total=3, support=3, rejected=(), accepted=True)
                )

    def test_mixed_records_and_bytes(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                items = records()
                mixed = [items[0], items[1].to_bytes(), items[2]]
                consensus = call(mixed)
                self.assertEqual(consensus.support, 3)
                self.assertTrue(consensus.accepted)

    def test_one_shot_iterator(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                consensus = call(item for item in records())
                self.assertEqual(consensus.support, 3)
                self.assertTrue(consensus.accepted)

    def test_quorum_not_reached_returns_accepted_false(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                make = attest if name == "plain" else attest_bound
                # Input order is deliberately not sorted: the rejected tuple
                # must come back lexicographically sorted anyway.
                items = records()[:2] + [
                    make("d", 10.0, 10.0, 1.0),
                    make("c", 10.0, 10.0, 1.0),
                ]
                consensus = call(items)
                self.assertEqual(consensus.total, 4)
                self.assertEqual(consensus.support, 2)
                self.assertEqual(consensus.rejected, ("c", "d"))
                self.assertFalse(consensus.accepted)
                # A lower quorum accepts the very same observations.
                consensus = call(items, quorum=2)
                self.assertTrue(consensus.accepted)
                self.assertEqual(consensus.rejected, ("c", "d"))

    def test_geometry_boundary_is_closed(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                make = attest if name == "plain" else attest_bound
                # Every distance exactly equals its upper bound.
                items = [
                    make("a", 3.0, 0.0, 3.0),
                    make("b", 0.0, 4.0, 4.0),
                    make("c", 0.0, 0.0, 0.0),
                ]
                consensus = call(items)
                self.assertEqual(consensus.support, 3)
                self.assertTrue(consensus.accepted)
                # A hair inside the bound rejects, and tolerance reopens
                # exactly the same boundary.
                just_inside = math.nextafter(3.0, 0.0)
                items[0] = make("a", 3.0, 0.0, just_inside)
                consensus = call(items)
                self.assertEqual(consensus.rejected, ("a",))
                self.assertFalse(consensus.accepted)
                slack = 3.0 - just_inside
                consensus = call(items, tolerance=slack)
                self.assertEqual(consensus.support, 3)
                self.assertTrue(consensus.accepted)

    def test_wrong_key_tamper_duplicate_unknown_rejected(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                items = records()
                # Signed under the wrong key.
                items[0] = (attest if name == "plain" else attest_bound)(
                    "a", 3.0, 0.0, 5.0, key=KEY_B
                )
                with self.assertRaises(ValueError):
                    call(items)
                # Tampered after signing.
                items = records()
                items[1] = dataclasses.replace(items[1], x=9.0)
                with self.assertRaises(ValueError):
                    call(items)
                # Duplicated id.
                items = records()
                items.append(items[0])
                with self.assertRaises(ValueError):
                    call(items)
                # Unknown id.
                items = records()
                items[2] = dataclasses.replace(items[2], id="q")
                with self.assertRaises(ValueError):
                    call(items)

    def test_wrong_record_type_and_non_canonical_bytes(self):
        other = {
            "plain": triangle_bound,
            "bound": triangle,
        }
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                # The other entry's record type is not accepted here.
                with self.assertRaises(ValueError):
                    call(other[name]())
                # Bytes that do not parse as the canonical record encoding.
                items = records()
                items[0] = b"\x00\x01\x02"
                with self.assertRaises(ValueError):
                    call(items)
                # A non-record, non-bytes element.
                with self.assertRaises(ValueError):
                    call([42, 42, 42])

    def test_keys_contract(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                for bad_keys in ({}, None, [], {"a": ""}, {"": KEY_A}, {"a": b""}):
                    with self.assertRaises(ValueError, msg=repr(bad_keys)):
                        locate_attested(records(), POINT, bad_keys)
                with self.assertRaises(ValueError):
                    locate_bound_attested(records(), POINT, CONTEXT, {})

    def test_root_contract_only_with_snapshot(self):
        snapshot = crl([], sequence=1, issued_at=0.0)
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                # Non-bytes root is a TypeError, empty root a ValueError.
                with self.assertRaises(TypeError):
                    call(records(), revocation_list=snapshot, root="root", now=10.0)
                with self.assertRaises(ValueError):
                    call(records(), revocation_list=snapshot, root=b"", now=10.0)
                # Without a snapshot, root and min are ignored entirely.
                consensus = call(records(), root="not-bytes", min="junk")
                self.assertTrue(consensus.accepted)

    def test_call_does_not_mutate_inputs(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                items = records()
                items_copy = list(items)
                keys = dict(KEYS)
                revocations = [revoke_observation("z", 5.0, KEY_Z)]
                snapshot = crl([], sequence=1, issued_at=0.0)
                consensus = call(
                    items,
                    revocations=revocations,
                    revocation_list=snapshot,
                    root=ROOT,
                    now=10.0,
                )
                self.assertTrue(consensus.accepted)
                self.assertEqual(items, items_copy)
                self.assertEqual(keys, KEYS)
                self.assertEqual(len(revocations), 1)


class FreshnessContractTest(unittest.TestCase):
    """Identical freshness judgement for both entries."""

    def test_closed_interval(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                items = records(issued_at=100.0)
                # Both ends of the closed interval are accepted.
                self.assertTrue(call(items, now=120.0, max_age=20.0).accepted)
                self.assertTrue(call(items, now=100.0, max_age=0.0).accepted)
                # Stale past the bound, or dated in the future: ValueError.
                with self.assertRaises(ValueError):
                    call(records(issued_at=100.0), now=121.0, max_age=20.0)
                with self.assertRaises(ValueError):
                    call(records(issued_at=100.0), now=99.0, max_age=20.0)

    def test_max_age_and_now_contract(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                for bad in (True, -1.0, math.inf, math.nan, "20"):
                    with self.assertRaises(ValueError, msg=repr(bad)):
                        call(records(), max_age=bad)
                for bad in (True, "100", math.inf, math.nan):
                    with self.assertRaises(ValueError, msg=repr(bad)):
                        call(records(), now=bad, max_age=10.0)
                # Without any check enabled, now is not even validated.
                self.assertTrue(call(records(), now="ignored").accepted)


class ClockReadCountTest(unittest.TestCase):
    """The clock is read at most once per call, and only when a check
    actually needs the current time."""

    def test_no_check_never_reads_clock(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                with mock.patch("nearproof.time.time") as clock:
                    self.assertTrue(call(records()).accepted)
                    clock.assert_not_called()

    def test_single_read_per_call(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                with mock.patch(
                    "nearproof.time.time", return_value=1000.0
                ) as clock:
                    self.assertTrue(
                        call(records(issued_at=990.0), max_age=20.0).accepted
                    )
                    self.assertEqual(clock.call_count, 1)
                with mock.patch(
                    "nearproof.time.time", return_value=1000.0
                ) as clock:
                    revocations = [revoke_observation("z", 5.0, KEY_Z)]
                    self.assertTrue(call(records(), revocations=revocations).accepted)
                    self.assertEqual(clock.call_count, 1)
                # Freshness and revocation together still read once.
                with mock.patch(
                    "nearproof.time.time", return_value=1000.0
                ) as clock:
                    revocations = [revoke_observation("z", 5.0, KEY_Z)]
                    self.assertTrue(
                        call(
                            records(issued_at=990.0),
                            max_age=20.0,
                            revocations=revocations,
                        ).accepted
                    )
                    self.assertEqual(clock.call_count, 1)

    def test_explicit_now_never_reads_clock(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                with mock.patch("nearproof.time.time") as clock:
                    self.assertTrue(
                        call(records(issued_at=90.0), now=100.0, max_age=20.0).accepted
                    )
                    clock.assert_not_called()

    def test_snapshot_requires_explicit_now_and_never_reads_clock(self):
        snapshot = crl([], sequence=1, issued_at=5.0)
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                with mock.patch("nearproof.time.time") as clock:
                    with self.assertRaises(ValueError):
                        call(records(), revocation_list=snapshot, root=ROOT)
                    clock.assert_not_called()
                with mock.patch("nearproof.time.time") as clock:
                    self.assertTrue(
                        call(
                            records(),
                            revocation_list=snapshot,
                            root=ROOT,
                            now=10.0,
                        ).accepted
                    )
                    clock.assert_not_called()
                # An invalid explicit now raises; there is no clock fallback.
                with mock.patch("nearproof.time.time") as clock:
                    for bad in (True, "10", math.inf, math.nan):
                        with self.assertRaises(ValueError, msg=repr(bad)):
                            call(
                                records(),
                                revocation_list=snapshot,
                                root=ROOT,
                                now=bad,
                            )
                    clock.assert_not_called()


class JointRevocationTest(unittest.TestCase):
    """The per-call revocations and the signed snapshot are judged jointly
    and identically by both entries."""

    def test_same_id_in_both_sources_latest_wins(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                for first, second in ((50.0, 80.0), (80.0, 50.0)):
                    revocations = [revoke_observation("a", first, KEY_A)]
                    snapshot = crl(
                        [revoke_observation("a", second, KEY_A)],
                        sequence=1,
                        issued_at=90.0,
                    )
                    kwargs = dict(
                        revocations=revocations,
                        revocation_list=snapshot,
                        root=ROOT,
                        now=100.0,
                    )
                    # Between the two revocation times: revoked by the later.
                    with self.assertRaises(ValueError):
                        call(records(issued_at=60.0), **kwargs)
                    # Exactly at the later revocation time: still revoked.
                    with self.assertRaises(ValueError):
                        call(records(issued_at=80.0), **kwargs)
                    # Strictly after both: the observation participates.
                    consensus = call(records(issued_at=81.0), **kwargs)
                    self.assertTrue(consensus.accepted)
                    self.assertEqual(consensus.support, 3)

    def test_either_source_alone_revokes(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                with self.assertRaises(ValueError):
                    call(
                        records(issued_at=10.0),
                        revocations=[revoke_observation("a", 50.0, KEY_A)],
                        now=100.0,
                    )
                snapshot = crl(
                    [revoke_observation("a", 50.0, KEY_A)],
                    sequence=1,
                    issued_at=90.0,
                )
                with self.assertRaises(ValueError):
                    call(
                        records(issued_at=10.0),
                        revocation_list=snapshot,
                        root=ROOT,
                        now=100.0,
                    )

    def test_unrelated_revocations_still_authenticated(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                # A tampered revocation for an id no observation uses.
                forged = revoke_observation("z", 5.0, KEY_A)
                with self.assertRaises(ValueError):
                    call(records(), revocations=[forged], now=100.0)
                # A future-dated revocation for an unrelated id.
                future = revoke_observation("z", 500.0, KEY_Z)
                with self.assertRaises(ValueError):
                    call(records(), revocations=[future], now=100.0)
                # An unknown revocation id.
                stranger = revoke_observation("q", 5.0, b"\x71" * 32)
                with self.assertRaises(ValueError):
                    call(records(), revocations=[stranger], now=100.0)
                # A duplicated revocation id inside the per-call source.
                with self.assertRaises(ValueError):
                    call(
                        records(),
                        revocations=[future, revoke_observation("z", 6.0, KEY_Z)],
                        now=1000.0,
                    )

    def test_snapshot_authentication_and_freshness(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                # Wrong root key.
                snapshot = crl([], sequence=1, issued_at=0.0)
                with self.assertRaises(ValueError):
                    call(
                        records(),
                        revocation_list=snapshot,
                        root=b"\x73" * 32,
                        now=10.0,
                    )
                # An entry id unknown to keys.
                snapshot = crl(
                    [revoke_observation("q", 5.0, b"\x71" * 32)],
                    sequence=1,
                    issued_at=0.0,
                )
                with self.assertRaises(ValueError):
                    call(records(), revocation_list=snapshot, root=ROOT, now=10.0)
                # A future-dated revocation inside the snapshot.
                snapshot = crl(
                    [revoke_observation("z", 500.0, KEY_Z)],
                    sequence=1,
                    issued_at=0.0,
                )
                with self.assertRaises(ValueError):
                    call(records(), revocation_list=snapshot, root=ROOT, now=10.0)
                # A future-dated snapshot.
                snapshot = crl([], sequence=1, issued_at=500.0)
                with self.assertRaises(ValueError):
                    call(records(), revocation_list=snapshot, root=ROOT, now=10.0)
                # A sequence below the floor; exactly at the floor passes.
                snapshot = crl([], sequence=1, issued_at=0.0)
                with self.assertRaises(ValueError):
                    call(
                        records(),
                        revocation_list=snapshot,
                        root=ROOT,
                        now=10.0,
                        min=2,
                    )
                self.assertTrue(
                    call(
                        records(),
                        revocation_list=snapshot,
                        root=ROOT,
                        now=10.0,
                        min=1,
                    ).accepted
                )

    def test_snapshot_and_revocations_accept_canonical_bytes(self):
        for name, call, records in ENTRIES:
            with self.subTest(entry=name):
                snapshot = crl([], sequence=1, issued_at=0.0)
                revocations = [revoke_observation("z", 5.0, KEY_Z).to_bytes()]
                consensus = call(
                    records(),
                    revocations=revocations,
                    revocation_list=snapshot.to_bytes(),
                    root=ROOT,
                    now=10.0,
                )
                self.assertTrue(consensus.accepted)


class BindingDifferenceTest(unittest.TestCase):
    """The bound entry verifies the record signature first, then the
    point/context binding; the plain entry adds no binding requirement."""

    def test_bound_rejects_mismatched_point_or_context(self):
        for items in (
            triangle_bound(point=(1.0, 0.0)),
            triangle_bound(context="other"),
        ):
            with self.assertRaises(ValueError) as caught:
                call_bound(items)
            self.assertIn("not bound to the queried point and context",
                          str(caught.exception))
        # A record signed for the queried point and context passes.
        self.assertTrue(call_bound(triangle_bound()).accepted)

    def test_signature_verified_before_binding(self):
        items = triangle_bound(point=(1.0, 1.0))
        # Tampered after signing AND bound elsewhere: the MAC error wins.
        items[0] = dataclasses.replace(items[0], x=9.0)
        with self.assertRaises(ValueError) as caught:
            call_bound(items)
        self.assertIn("mac does not match", str(caught.exception))

    def test_plain_entry_has_no_binding_requirement(self):
        # The plain entry knows nothing of points or contexts on records;
        # the same query shape simply runs the consensus.
        consensus = call_plain(triangle())
        self.assertTrue(consensus.accepted)
        # And each entry rejects the other's record type.
        with self.assertRaises(ValueError):
            call_plain(triangle_bound())
        with self.assertRaises(ValueError):
            call_bound(triangle())

    def test_bound_point_and_context_contract(self):
        for bad_point in ((0.0,), (0.0, 0.0, 0.0), [0.0, 0.0], (0.0, math.nan),
                          (True, 0.0), "origin"):
            with self.assertRaises(ValueError, msg=repr(bad_point)):
                locate_bound_attested(triangle_bound(), bad_point, CONTEXT, KEYS)
        for bad_context in ("", 7, None):
            with self.assertRaises(ValueError, msg=repr(bad_context)):
                locate_bound_attested(triangle_bound(), POINT, bad_context, KEYS)

    def test_shared_validation_order_preserved(self):
        # keys are validated before max_age, max_age before now, and now
        # before the bound entry's point/context contract.
        with self.assertRaisesRegex(ValueError, "keys must be a non-empty mapping"):
            locate_bound_attested(
                triangle_bound(), "bad-point", "", {}, max_age=-1.0
            )
        with self.assertRaisesRegex(ValueError, "max_age must be"):
            locate_bound_attested(
                triangle_bound(), "bad-point", "", KEYS, max_age=-1.0
            )
        with self.assertRaisesRegex(ValueError, "now must be a finite number"):
            locate_bound_attested(
                triangle_bound(), "bad-point", "", KEYS, now="x", max_age=1.0
            )
        with self.assertRaisesRegex(ValueError, "point must be a tuple"):
            locate_bound_attested(
                triangle_bound(), "bad-point", "", KEYS, now=1.0, max_age=1.0
            )
        with self.assertRaisesRegex(ValueError, "context must be a non-empty"):
            locate_bound_attested(
                triangle_bound(), POINT, "", KEYS, now=1.0, max_age=1.0
            )


if __name__ == "__main__":
    unittest.main()
