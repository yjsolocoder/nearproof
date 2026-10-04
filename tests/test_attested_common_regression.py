"""Regression tests for the shared verification flow of the attested entries.

``locate_attested`` and ``locate_bound_attested`` share one verification
pipeline (keys, freshness, revocations, signed snapshot); these tests pin
down that both entries judge identical conditions identically, that the two
revocation sources combine, that the clock is read exactly as documented,
and that the point/context binding is the only difference between them.
"""

import json
import time
import unittest
from unittest import mock

import nearproof
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

ROOT = b"\x09" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
KEY_D = b"\xdd" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def revocation(ident, revoked_at=100.0, *, key=None):
    return revoke_observation(ident, revoked_at, key or KEYS[ident])


def observation(ident, issued_at=10.0, *, key=None):
    x, y = POSITIONS[ident]
    return attest_observation(
        ident, x, y, decision(), issued_at, key or KEYS[ident]
    )


def bound_observation(ident, issued_at=10.0, *, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(), point, context, issued_at, KEYS[ident]
    )


def triangle(issued_at=10.0):
    return [observation(ident, issued_at) for ident in ("a", "b", "c")]


def bound_triangle(issued_at=10.0, **kwargs):
    return [bound_observation(ident, issued_at, **kwargs) for ident in ("a", "b", "c")]


def crl(entries=("a",), sequence=7, issued_at=120.0, *, root=ROOT, revoked_at=100.0):
    return make_observation_crl(
        [revocation(ident, revoked_at) for ident in entries],
        sequence,
        issued_at,
        root,
    )


def locate_both(issued_at=10.0, **kwargs):
    """Run both entries over equivalent records and return both results."""
    plain = locate_attested(triangle(issued_at), POINT, KEYS, **kwargs)
    bound = locate_bound_attested(
        bound_triangle(issued_at), POINT, CONTEXT, KEYS, **kwargs
    )
    return plain, bound


def assert_same_consensus(test_case, plain, bound):
    test_case.assertIsInstance(plain, Consensus)
    test_case.assertIsInstance(bound, Consensus)
    for field in ("total", "support", "rejected", "accepted"):
        test_case.assertEqual(getattr(plain, field), getattr(bound, field), field)


class EntryParityTest(unittest.TestCase):
    """Identical freshness/revocation conditions, identical judgements."""

    def test_success_results_match(self):
        plain, bound = locate_both()
        assert_same_consensus(self, plain, bound)
        self.assertEqual((plain.total, plain.support), (3, 3))
        self.assertEqual(plain.rejected, ())
        self.assertTrue(plain.accepted)

    def test_quorum_miss_is_a_result_not_an_error(self):
        far = (100.0, 100.0)
        plain = locate_attested(triangle(), far, KEYS)
        bound = locate_bound_attested(bound_triangle(point=far), far, CONTEXT, KEYS)
        assert_same_consensus(self, plain, bound)
        self.assertEqual(plain.support, 0)
        self.assertEqual(plain.rejected, ("a", "b", "c"))
        self.assertFalse(plain.accepted)

    def test_freshness_boundary_is_closed_for_both(self):
        for issued_at, now, max_age in ((100.0, 120.0, 20.0), (100.0, 100.0, 0.0)):
            with self.subTest(issued_at=issued_at, now=now, max_age=max_age):
                plain, bound = locate_both(issued_at, now=now, max_age=max_age)
                self.assertEqual(plain.support, 3)
                self.assertEqual(bound.support, 3)

    def test_stale_and_future_records_rejected_by_both(self):
        for kwargs in (
            {"now": 121.0, "max_age": 20.0},
            {"now": 99.0, "max_age": 20.0},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    locate_attested(triangle(100.0), POINT, KEYS, **kwargs)
                with self.assertRaises(ValueError):
                    locate_bound_attested(
                        bound_triangle(100.0), POINT, CONTEXT, KEYS, **kwargs
                    )

    def test_revocation_equality_and_strictly_later(self):
        revocations = [revocation("a", 100.0)]
        # issued_at == revoked_at is a breach for both entries.
        with self.assertRaises(ValueError):
            locate_attested(
                [observation("a", 100.0), observation("b"), observation("c")],
                POINT, KEYS, revocations=revocations, now=130.0,
            )
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [bound_observation("a", 100.0), bound_observation("b"),
                 bound_observation("c")],
                POINT, CONTEXT, KEYS, revocations=revocations, now=130.0,
            )
        # Issued strictly after the revocation: kept by both entries.
        plain = locate_attested(
            [observation("a", 101.0), observation("b"), observation("c")],
            POINT, KEYS, revocations=revocations, now=130.0,
        )
        bound = locate_bound_attested(
            [bound_observation("a", 101.0), bound_observation("b"),
             bound_observation("c")],
            POINT, CONTEXT, KEYS, revocations=revocations, now=130.0,
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)

    def test_future_revocation_rejected_by_both(self):
        revocations = [revocation("a", 200.0)]
        with self.assertRaises(ValueError):
            locate_attested(triangle(), POINT, KEYS,
                            revocations=revocations, now=130.0)
        with self.assertRaises(ValueError):
            locate_bound_attested(bound_triangle(), POINT, CONTEXT, KEYS,
                                  revocations=revocations, now=130.0)

    def test_snapshot_failures_match(self):
        record = crl(("a",))
        for kwargs in (
            {"revocation_list": record, "root": ROOT},               # now missing
            {"revocation_list": record, "root": ROOT, "now": 130.0, "min": 8},
            {"revocation_list": record, "root": b"\x08" * 32, "now": 130.0},
            {"revocation_list": record, "root": ROOT, "now": 119.0},  # future list
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    locate_attested(triangle(101.0), POINT, KEYS, **kwargs)
                with self.assertRaises(ValueError):
                    locate_bound_attested(
                        bound_triangle(101.0), POINT, CONTEXT, KEYS, **kwargs
                    )

    def test_snapshot_success_matches(self):
        record = crl(("a",), revoked_at=100.0)
        kwargs = {"revocation_list": record, "root": ROOT, "now": 130.0}
        plain = locate_attested(
            [observation("a", 101.0), observation("b"), observation("c")],
            POINT, KEYS, **kwargs,
        )
        bound = locate_bound_attested(
            [bound_observation("a", 101.0), bound_observation("b"),
             bound_observation("c")],
            POINT, CONTEXT, KEYS, **kwargs,
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)

    def test_record_types_are_not_interchangeable(self):
        with self.assertRaises(ValueError):
            locate_attested(bound_triangle(), POINT, KEYS)
        with self.assertRaises(ValueError):
            locate_bound_attested(triangle(), POINT, CONTEXT, KEYS)

    def test_tampering_and_wrong_key_rejected_by_both(self):
        blob = observation("a").to_bytes().replace(b'"x":3.0', b'"x":99.0')
        with self.assertRaises(ValueError):
            locate_attested([blob, observation("b"), observation("c")], POINT, KEYS)
        bound_blob = bound_observation("a").to_bytes().replace(b'"x":3.0', b'"x":99.0')
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [bound_blob, bound_observation("b"), bound_observation("c")],
                POINT, CONTEXT, KEYS,
            )
        bad_keys = dict(KEYS, b=KEY_C)
        with self.assertRaises(ValueError):
            locate_attested(triangle(), POINT, bad_keys)
        with self.assertRaises(ValueError):
            locate_bound_attested(bound_triangle(), POINT, CONTEXT, bad_keys)

    def test_noncanonical_bytes_rejected_by_both(self):
        for record in (observation("a"), bound_observation("a")):
            blob = record.to_bytes()
            pretty = json.dumps(json.loads(blob), indent=2).encode()
            with self.subTest(type=type(record).__name__):
                if type(record).__name__.startswith("Bound"):
                    with self.assertRaises(ValueError):
                        locate_bound_attested(
                            [pretty, bound_observation("b"), bound_observation("c")],
                            POINT, CONTEXT, KEYS,
                        )
                else:
                    with self.assertRaises(ValueError):
                        locate_attested(
                            [pretty, observation("b"), observation("c")], POINT, KEYS
                        )

    def test_duplicate_and_unknown_ids_rejected_by_both(self):
        with self.assertRaises(ValueError):
            locate_attested(triangle() + [observation("a")], POINT, KEYS)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                bound_triangle() + [bound_observation("a")], POINT, CONTEXT, KEYS
            )
        with self.assertRaises(ValueError):
            locate_attested(triangle(), POINT, {"a": KEY_A, "b": KEY_B})
        with self.assertRaises(ValueError):
            locate_bound_attested(
                bound_triangle(), POINT, CONTEXT, {"a": KEY_A, "b": KEY_B}
            )


class JointRevocationSourcesTest(unittest.TestCase):
    """Per-call revocations and the signed snapshot are judged jointly."""

    def test_same_id_in_both_sources_must_postdate_each(self):
        record = crl(("a",), revoked_at=100.0)
        single = revocation("a", 150.0)
        kwargs = {
            "revocations": [single],
            "revocation_list": record,
            "root": ROOT,
            "now": 200.0,
        }
        # Equality with either source's revoked_at is a breach.
        for issued_at in (100.0, 150.0):
            with self.subTest(issued_at=issued_at):
                with self.assertRaises(ValueError):
                    locate_attested(
                        [observation("a", issued_at), observation("b"),
                         observation("c")],
                        POINT, KEYS, **kwargs,
                    )
                with self.assertRaises(ValueError):
                    locate_bound_attested(
                        [bound_observation("a", issued_at), bound_observation("b"),
                         bound_observation("c")],
                        POINT, CONTEXT, KEYS, **kwargs,
                    )
        # Strictly later than both: the observation participates again.
        plain = locate_attested(
            [observation("a", 151.0), observation("b"), observation("c")],
            POINT, KEYS, **kwargs,
        )
        bound = locate_bound_attested(
            [bound_observation("a", 151.0), bound_observation("b"),
             bound_observation("c")],
            POINT, CONTEXT, KEYS, **kwargs,
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)

    def test_each_source_catches_its_own_id(self):
        record = crl(("a",), revoked_at=100.0)
        single = revocation("c", 5.0)
        kwargs = {
            "revocations": [single],
            "revocation_list": record,
            "root": ROOT,
            "now": 130.0,
        }
        # c's observation predates the per-call revocation; a's postdates the
        # snapshot entry. Both entries must catch c.
        with self.assertRaises(ValueError):
            locate_attested(
                [observation("a", 101.0), observation("b"), observation("c", 4.0)],
                POINT, KEYS, **kwargs,
            )
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [bound_observation("a", 101.0), bound_observation("b"),
                 bound_observation("c", 4.0)],
                POINT, CONTEXT, KEYS, **kwargs,
            )

    def test_unrelated_revocation_still_authenticated_and_dated(self):
        keys = {**KEYS, "d": KEY_D}
        record = crl(("a",), revoked_at=100.0)
        base = {
            "revocation_list": record,
            "root": ROOT,
            "now": 130.0,
        }
        # A tampered revocation for an id with no observation still fails.
        tampered = revoke_observation("d", 50.0, KEY_D)
        tampered = type(tampered)(
            tampered.version, tampered.id, 60.0, tampered.mac
        )
        with self.assertRaises(ValueError):
            locate_attested(
                [observation("a", 101.0), observation("b"), observation("c")],
                POINT, keys, revocations=[tampered], **base,
            )
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [bound_observation("a", 101.0), bound_observation("b"),
                 bound_observation("c")],
                POINT, CONTEXT, keys, revocations=[tampered], **base,
            )
        # A future-dated unrelated revocation fails too.
        future = revoke_observation("d", 999.0, KEY_D)
        with self.assertRaises(ValueError):
            locate_attested(
                [observation("a", 101.0), observation("b"), observation("c")],
                POINT, keys, revocations=[future], **base,
            )
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [bound_observation("a", 101.0), bound_observation("b"),
                 bound_observation("c")],
                POINT, CONTEXT, keys, revocations=[future], **base,
            )
        # A genuine unrelated revocation is simply ignored by the geometry.
        genuine = revoke_observation("d", 50.0, KEY_D)
        plain = locate_attested(
            [observation("a", 101.0), observation("b"), observation("c")],
            POINT, keys, revocations=[genuine], **base,
        )
        bound = locate_bound_attested(
            [bound_observation("a", 101.0), bound_observation("b"),
             bound_observation("c")],
            POINT, CONTEXT, keys, revocations=[genuine], **base,
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)

    def test_unrelated_snapshot_entries_still_audited(self):
        keys = {**KEYS, "d": KEY_D}
        # Unknown-to-keys snapshot entry id is rejected even with no matching
        # observation.
        record = make_observation_crl(
            [revocation("a"), revoke_observation("z", 100.0, b"\xee" * 32)],
            7, 120.0, ROOT,
        )
        with self.assertRaises(ValueError):
            locate_attested(triangle(101.0), POINT, keys,
                            revocation_list=record, root=ROOT, now=130.0)
        with self.assertRaises(ValueError):
            locate_bound_attested(bound_triangle(101.0), POINT, CONTEXT, keys,
                                  revocation_list=record, root=ROOT, now=130.0)
        # A genuine entry for an unobserved id does not hit the geometry.
        record = make_observation_crl(
            [revocation("a"), revoke_observation("d", 100.0, KEY_D)],
            7, 120.0, ROOT,
        )
        plain = locate_attested(
            [observation("a", 101.0), observation("b"), observation("c")],
            POINT, keys, revocation_list=record, root=ROOT, now=130.0,
        )
        bound = locate_bound_attested(
            [bound_observation("a", 101.0), bound_observation("b"),
             bound_observation("c")],
            POINT, CONTEXT, keys, revocation_list=record, root=ROOT, now=130.0,
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)


class ClockReadCountTest(unittest.TestCase):
    """The clock is read at most once per call, and only when needed."""

    def count_reads(self, thunk):
        reads = 0
        real_time = time.time

        def counting():
            nonlocal reads
            reads += 1
            return real_time()

        with mock.patch.object(nearproof.time, "time", counting):
            outcome = thunk()
        return reads, outcome

    def test_no_freshness_no_revocation_never_reads_clock(self):
        # Records are stamped before the patched region so only the locate
        # calls themselves can touch the clock.
        plain_records = triangle(time.time())
        bound_records = bound_triangle(time.time())
        reads, (plain, bound) = self.count_reads(
            lambda: (
                locate_attested(plain_records, POINT, KEYS),
                locate_bound_attested(bound_records, POINT, CONTEXT, KEYS),
            )
        )
        self.assertEqual(reads, 0)
        assert_same_consensus(self, plain, bound)
        # root and min are ignored without a snapshot: still no clock read.
        reads, _ = self.count_reads(
            lambda: locate_attested(triangle(), POINT, KEYS,
                                    root="not-bytes", min="junk")
        )
        self.assertEqual(reads, 0)

    def test_max_age_without_now_reads_clock_exactly_once(self):
        plain_records = triangle(time.time())
        bound_records = bound_triangle(time.time())

        def run():
            plain = locate_attested(plain_records, POINT, KEYS, max_age=60.0)
            bound = locate_bound_attested(
                bound_records, POINT, CONTEXT, KEYS, max_age=60.0
            )
            return plain, bound

        # Each call reads the clock exactly once: two calls, two reads.
        reads, (plain, bound) = self.count_reads(run)
        self.assertEqual(reads, 2)
        self.assertTrue(plain.accepted)
        self.assertTrue(bound.accepted)

    def test_revocations_without_now_read_clock_exactly_once(self):
        revocations = [revocation("a", 5.0)]

        def run():
            plain = locate_attested(triangle(), POINT, KEYS,
                                    revocations=revocations)
            bound = locate_bound_attested(bound_triangle(), POINT, CONTEXT, KEYS,
                                          revocations=revocations)
            return plain, bound

        reads, _ = self.count_reads(run)
        self.assertEqual(reads, 2)

    def test_max_age_and_revocations_together_read_clock_once(self):
        records = triangle(time.time())
        revocations = [revocation("a", 5.0)]
        reads, _ = self.count_reads(
            lambda: locate_attested(records, POINT, KEYS,
                                    max_age=60.0, revocations=revocations)
        )
        self.assertEqual(reads, 1)

    def test_explicit_now_reads_no_clock(self):
        revocations = [revocation("a", 5.0)]
        reads, _ = self.count_reads(
            lambda: locate_both(10.0, now=130.0, max_age=200.0,
                                revocations=revocations)
        )
        self.assertEqual(reads, 0)

    def test_snapshot_requires_explicit_now_and_never_reads_clock(self):
        record = crl(("a",))

        def missing_now():
            with self.assertRaises(ValueError):
                locate_attested(triangle(101.0), POINT, KEYS,
                                revocation_list=record, root=ROOT)
            with self.assertRaises(ValueError):
                locate_bound_attested(bound_triangle(101.0), POINT, CONTEXT, KEYS,
                                      revocation_list=record, root=ROOT)

        reads, _ = self.count_reads(missing_now)
        self.assertEqual(reads, 0)

        def explicit_now():
            plain = locate_attested(
                [observation("a", 101.0), observation("b"), observation("c")],
                POINT, KEYS, revocation_list=record, root=ROOT, now=130.0,
            )
            bound = locate_bound_attested(
                [bound_observation("a", 101.0), bound_observation("b"),
                 bound_observation("c")],
                POINT, CONTEXT, KEYS, revocation_list=record, root=ROOT, now=130.0,
            )
            return plain, bound

        reads, (plain, bound) = self.count_reads(explicit_now)
        self.assertEqual(reads, 0)
        assert_same_consensus(self, plain, bound)

    def test_invalid_explicit_now_raises_without_clock(self):
        for bad in (True, "now", float("inf"), float("nan")):
            with self.subTest(now=bad):
                reads, _ = self.count_reads(
                    lambda: self.assertRaises(
                        ValueError,
                        locate_attested, triangle(), POINT, KEYS,
                        now=bad, max_age=10.0,
                    )
                )
                self.assertEqual(reads, 0)


class BindingDifferenceTest(unittest.TestCase):
    """The point/context binding is the only difference between the entries."""

    def test_bound_entry_rejects_other_point_or_context(self):
        for kwargs in (
            {"point": (1.0, 0.0)},
            {"context": "room-8"},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    locate_bound_attested(
                        bound_triangle(**kwargs), POINT, CONTEXT, KEYS
                    )

    def test_mac_is_checked_before_the_binding(self):
        record = bound_observation("a", context="room-8")
        blob = record.to_bytes().replace(b'"x":3.0', b'"x":99.0')
        # Tampered MAC and wrong context: the MAC failure must win.
        with self.assertRaisesRegex(ValueError, "mac does not match"):
            locate_bound_attested(
                [blob, bound_observation("b"), bound_observation("c")],
                POINT, CONTEXT, KEYS,
            )
        with self.assertRaisesRegex(ValueError, "not bound to the queried"):
            locate_bound_attested(
                [record, bound_observation("b"), bound_observation("c")],
                POINT, CONTEXT, KEYS,
            )

    def test_plain_entry_has_no_binding_requirement(self):
        # The plain entry neither accepts bound records nor enforces any
        # point/context on its own records.
        with self.assertRaises(ValueError):
            locate_attested(bound_triangle(), POINT, KEYS)
        consensus = locate_attested(triangle(), POINT, KEYS)
        self.assertTrue(consensus.accepted)

    def test_bound_entry_rejects_plain_records(self):
        with self.assertRaises(ValueError):
            locate_bound_attested(triangle(), POINT, CONTEXT, KEYS)


class InputShapeTest(unittest.TestCase):
    """Mixed objects/bytes, one-shot iterators, and no input mutation."""

    def test_mixed_objects_and_bytes(self):
        records = triangle()
        mixed = [records[0].to_bytes(), records[1], records[2].to_bytes()]
        plain = locate_attested(mixed, POINT, KEYS)
        bound_records = bound_triangle()
        mixed_bound = [
            bound_records[0].to_bytes(), bound_records[1],
            bound_records[2].to_bytes(),
        ]
        bound = locate_bound_attested(mixed_bound, POINT, CONTEXT, KEYS)
        assert_same_consensus(self, plain, bound)
        self.assertEqual(plain.support, 3)

    def test_one_shot_iterators(self):
        plain = locate_attested(iter(triangle()), POINT, KEYS)
        bound = locate_bound_attested(
            (record for record in bound_triangle()), POINT, CONTEXT, KEYS
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)
        # Revocations may be one-shot too.
        revocations = [revocation("a", 5.0)]
        plain = locate_attested(
            iter(triangle()), POINT, KEYS,
            revocations=iter(revocations), now=130.0,
        )
        bound = locate_bound_attested(
            iter(bound_triangle()), POINT, CONTEXT, KEYS,
            revocations=iter(revocations), now=130.0,
        )
        assert_same_consensus(self, plain, bound)
        self.assertTrue(plain.accepted)

    def test_inputs_are_not_mutated(self):
        records = triangle()
        records_copy = list(records)
        bound_records = bound_triangle()
        bound_copy = list(bound_records)
        keys = dict(KEYS)
        revocations = [revocation("a", 5.0)]
        revocations_copy = list(revocations)
        snapshot = crl(("a",), revoked_at=1.0)
        locate_attested(
            records, POINT, keys, revocations=revocations,
            revocation_list=snapshot, root=ROOT, now=130.0, max_age=200.0,
        )
        locate_bound_attested(
            bound_records, POINT, CONTEXT, keys, revocations=revocations,
            revocation_list=snapshot, root=ROOT, now=130.0, max_age=200.0,
        )
        self.assertEqual(records, records_copy)
        self.assertEqual(bound_records, bound_copy)
        self.assertEqual(keys, KEYS)
        self.assertEqual(revocations, revocations_copy)

    def test_root_shape_matches_for_both(self):
        record = crl(("a",))
        with self.assertRaises(TypeError):
            locate_attested(triangle(101.0), POINT, KEYS,
                            revocation_list=record, root="root", now=130.0)
        with self.assertRaises(TypeError):
            locate_bound_attested(bound_triangle(101.0), POINT, CONTEXT, KEYS,
                                  revocation_list=record, root="root", now=130.0)
        with self.assertRaises(ValueError):
            locate_attested(triangle(101.0), POINT, KEYS,
                            revocation_list=record, root=b"", now=130.0)
        with self.assertRaises(ValueError):
            locate_bound_attested(bound_triangle(101.0), POINT, CONTEXT, KEYS,
                                  revocation_list=record, root=b"", now=130.0)

    def test_snapshot_bytes_and_object_forms_agree(self):
        record = crl(("a",), revoked_at=100.0)
        observations = [observation("a", 101.0), observation("b"), observation("c")]
        as_object = locate_attested(
            observations, POINT, KEYS,
            revocation_list=record, root=ROOT, now=130.0,
        )
        as_bytes = locate_attested(
            observations, POINT, KEYS,
            revocation_list=record.to_bytes(), root=ROOT, now=130.0,
        )
        assert_same_consensus(self, as_object, as_bytes)


if __name__ == "__main__":
    unittest.main()
