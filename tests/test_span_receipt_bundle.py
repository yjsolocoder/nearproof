import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeAuditor,
    RangeFrontier,
    RangeReceipt,
    RangeReceiptBatch,
    SpanReceiptBundle,
    _range_frontier_mac,
    _range_receipt_mac,
    _span_receipt_bundle_content_bytes,
    _span_receipt_bundle_signature,
    audit_span_receipt_bundle,
    seal_range_receipt_batch,
    seal_span_receipt_bundle,
)
from test_range_auditor_audit_batch import (
    CFRONTIER_1,
    CHAIN,
    KEY,
    OTHER_KEY,
    RANGE_1,
    RANGE_FROM_CP,
    RDIGEST_1,
    RECEIPT_R1,
    RECEIPT_RCP,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    range_frontier_for,
)

# "" -> RFRONTIER_1, RFRONTIER_1 -> RFRONTIER_2 and the whole journey
# "" -> RFRONTIER_2.
BUNDLE_1 = seal_span_receipt_bundle([RECEIPT_R1], KEY)
BUNDLE_2 = seal_span_receipt_bundle(
    [RECEIPT_RCP], KEY, start=RFRONTIER_1
)
BUNDLE_FULL = seal_span_receipt_bundle(
    [RECEIPT_R1, RECEIPT_RCP], KEY
)


def bundle_for(start, receipts, end, key=KEY):
    """A bundle with the NPBJ35 signature recomputed over the first
    four fields."""
    placeholder = SpanReceiptBundle(1, start, receipts, end, ZERO)
    return dataclasses.replace(
        placeholder,
        signature=_span_receipt_bundle_signature(key, placeholder),
    )


class SpanReceiptBundleFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        bundle = SpanReceiptBundle(
            1,
            b"",
            (RECEIPT_R1.to_bytes(),),
            RFRONTIER_1.to_bytes(),
            BUNDLE_1.signature,
        )
        self.assertEqual(bundle, BUNDLE_1)
        self.assertEqual(hash(bundle), hash(BUNDLE_1))
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.receipts, (RECEIPT_R1.to_bytes(),))
        self.assertEqual(bundle.end, RFRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BUNDLE_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BUNDLE_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, start=bad)
        # Malformed bytes are value errors: the start is empty or a
        # canonical range frontier.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BUNDLE_1, start=b"")

    def test_receipts_contract(self):
        for bad in (1, "1", None, [RECEIPT_R1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, receipts=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BUNDLE_1, receipts=())
        for bad in (1, "1", None, bytearray(RECEIPT_R1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, receipts=(bad,))
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, receipts=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty range frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, signature=bad)


class SpanReceiptBundleEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'["' + RECEIPT_R1.to_bytes().hex().encode() + b'"],'
            b'"' + RFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + BUNDLE_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(BUNDLE_1.to_bytes(), expected)

    def test_round_trip(self):
        for bundle in (BUNDLE_1, BUNDLE_2, BUNDLE_FULL):
            blob = bundle.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(SpanReceiptBundle.from_bytes(blob), bundle)
            self.assertEqual(
                SpanReceiptBundle.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = BUNDLE_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanReceiptBundle.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanReceiptBundle.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            [RECEIPT_R1.to_bytes().hex()],
            RFRONTIER_1.to_bytes().hex(),
            BUNDLE_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, "ab"),
            (2, [1]),
            (3, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = BUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanReceiptBundle.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            BUNDLE_1.signature.hex().encode(),
            BUNDLE_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanReceiptBundle.from_bytes(upper)
        with self.assertRaises(ValueError):
            SpanReceiptBundle.from_bytes(blob.replace(b"[1,", b"[2,", 1))
        with self.assertRaises(ValueError):
            SpanReceiptBundle.from_bytes(blob + b" ")

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            [RECEIPT_R1.to_bytes().hex()],
            RFRONTIER_1.to_bytes().hex(),
            BUNDLE_1.signature.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (2, []),
            (2, ["junk"]),
            (3, ""),
            (3, "junk"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                SpanReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the bundle signature nor any nested MAC is checked at
        # parse time.
        tampered = dataclasses.replace(BUNDLE_1, signature=ZERO)
        parsed = SpanReceiptBundle.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_signature_scheme(self):
        expected_signature = hmac.new(
            KEY,
            b"NPBJ35" + _span_receipt_bundle_content_bytes(BUNDLE_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BUNDLE_1.signature, expected_signature)


class SealSpanReceiptBundleTest(unittest.TestCase):
    def test_seals_chain_from_empty_ledger(self):
        bundle = seal_span_receipt_bundle(
            [RECEIPT_R1, RECEIPT_RCP], KEY
        )
        self.assertEqual(bundle, BUNDLE_FULL)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(
            bundle.receipts,
            (RECEIPT_R1.to_bytes(), RECEIPT_RCP.to_bytes()),
        )
        self.assertEqual(bundle.end, RFRONTIER_2.to_bytes())

    def test_seals_single_receipt(self):
        bundle = seal_span_receipt_bundle([RECEIPT_R1], KEY)
        self.assertEqual(bundle, BUNDLE_1)
        self.assertEqual(bundle.end, RFRONTIER_1.to_bytes())

    def test_seals_from_supplied_frontier_object_and_bytes(self):
        for start in (RFRONTIER_1, RFRONTIER_1.to_bytes()):
            bundle = seal_span_receipt_bundle(
                [RECEIPT_RCP], KEY, start=start
            )
            self.assertEqual(bundle, BUNDLE_2)
            self.assertEqual(bundle.start, RFRONTIER_1.to_bytes())
            self.assertEqual(bundle.end, RFRONTIER_2.to_bytes())

    def test_accepts_canonical_receipt_bytes(self):
        bundle = seal_span_receipt_bundle(
            [RECEIPT_R1.to_bytes(), RECEIPT_RCP.to_bytes()], KEY
        )
        self.assertEqual(bundle, BUNDLE_FULL)

    def test_accepts_any_non_empty_iterable(self):
        receipts = [pair[0] for pair in CHAIN]
        self.assertEqual(
            seal_span_receipt_bundle(list(receipts), KEY), BUNDLE_FULL
        )
        self.assertEqual(
            seal_span_receipt_bundle(tuple(receipts), KEY), BUNDLE_FULL
        )
        self.assertEqual(
            seal_span_receipt_bundle(
                (receipt for receipt in receipts), KEY
            ),
            BUNDLE_FULL,
        )

    def test_start_must_be_keyword_only(self):
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle([RECEIPT_R1], KEY, RFRONTIER_1)

    def test_sealing_touches_no_auditor_state(self):
        auditor = RangeAuditor(KEY)
        seal_span_receipt_bundle([RECEIPT_R1], KEY)
        self.assertIsNone(auditor.state)

    def test_type_contract(self):
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle(1, KEY)
        for bad in (1, "x", None, [RECEIPT_R1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_receipt_bundle([bad], KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_receipt_bundle([RECEIPT_R1], bad)
        for bad in (1, "x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_receipt_bundle([RECEIPT_R1], KEY, start=bad)

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([], KEY)
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([RECEIPT_R1], b"")
        # Malformed receipt bytes are value errors.
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([b"junk"], KEY)
        # A non-canonical or MAC-bad checkpoint is a value error.
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_RCP], KEY, start=b"junk"
            )

    def test_broken_chain_rejected(self):
        # The same receipt twice audits its own signature but the second
        # start does not continue from the first frontier end.
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_R1, RECEIPT_R1], KEY
            )

    def test_wrong_first_start_rejected(self):
        # The first receipt starts at b"" but a non-empty start was
        # supplied.
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_R1], KEY, start=RFRONTIER_1
            )

    def test_tampered_receipt_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [dataclasses.replace(RECEIPT_R1, mac=ZERO)], KEY
            )

    def test_sequence_overflow_rejected(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_R1], KEY, start=maxed
            )


class AuditSpanReceiptBundleTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_FULL, KEY), RFRONTIER_2
        )
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_1, KEY), RFRONTIER_1
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_FULL.to_bytes(), KEY),
            RFRONTIER_2,
        )

    def test_is_a_pure_check_touching_no_auditor(self):
        auditor = RangeAuditor(KEY)
        audit_span_receipt_bundle(BUNDLE_FULL, KEY)
        self.assertIsNone(auditor.state)

    def test_type_contract(self):
        for bad in (1, "x", None, [BUNDLE_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_receipt_bundle(bad, KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_receipt_bundle(BUNDLE_FULL, bad)

    def test_value_contract(self):
        for bad in (b"junk", b"[1]", BUNDLE_FULL.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_receipt_bundle(bad, KEY)
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(BUNDLE_FULL, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(BUNDLE_FULL, OTHER_KEY)

    def test_signature_mismatch_rejected(self):
        forged = dataclasses.replace(BUNDLE_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(forged, KEY)

    def test_re_signature_over_tampered_start_rejected(self):
        placeholder = SpanReceiptBundle(
            1,
            RFRONTIER_1.to_bytes(),
            BUNDLE_FULL.receipts,
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder,
            signature=_span_receipt_bundle_signature(KEY, placeholder),
        )
        # The carried chain begins at b"", so replaying it from the
        # declared non-empty start breaks the first link.
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(signed, KEY)

    def test_tampered_start_frontier_rejected(self):
        bad_start = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        placeholder = SpanReceiptBundle(
            1,
            bad_start.to_bytes(),
            BUNDLE_2.receipts,
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder,
            signature=_span_receipt_bundle_signature(KEY, placeholder),
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(signed, KEY)

    def test_tampered_end_frontier_rejected(self):
        bad_end = dataclasses.replace(RFRONTIER_2, mac=ZERO)
        placeholder = SpanReceiptBundle(
            1,
            b"",
            BUNDLE_FULL.receipts,
            bad_end.to_bytes(),
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder,
            signature=_span_receipt_bundle_signature(KEY, placeholder),
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(signed, KEY)

    def test_tampered_carried_receipt_rejected(self):
        broken_receipts = (
            dataclasses.replace(RECEIPT_R1, mac=ZERO).to_bytes(),
            RECEIPT_RCP.to_bytes(),
        )
        signed = bundle_for(
            b"", broken_receipts, RFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(signed, KEY)

    def test_broken_link_inside_bundle_rejected(self):
        # The second receipt restarts at the empty string while the
        # first ends at RFRONTIER_1: its signature verifies but the
        # replayed chain breaks.
        broken_receipts = (
            RECEIPT_R1.to_bytes(),
            dataclasses.replace(RECEIPT_RCP, start=b"").to_bytes(),
        )
        signed = bundle_for(
            b"", broken_receipts, RFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(signed, KEY)

    def test_end_must_match_replayed_chain(self):
        signed = bundle_for(
            b"", BUNDLE_FULL.receipts, RFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(signed, KEY)

    def test_replied_journey_end_is_declared_end(self):
        final = audit_span_receipt_bundle(BUNDLE_FULL, KEY)
        self.assertEqual(final.to_bytes(), BUNDLE_FULL.end)
        self.assertEqual(final.sequence, 2)


class RangeAuditorAuditBundleSuccessTest(unittest.TestCase):
    def test_returns_self_and_advances_to_declared_end(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_FULL), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(
            auditor.audit_bundle(BUNDLE_FULL.to_bytes()), auditor
        )
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_single_receipt_bundle(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_chained_bundles_start_at_current_checkpoint(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertIs(auditor.audit_bundle(BUNDLE_2), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_matches_single_and_batch_booking(self):
        via_bundle = RangeAuditor(KEY)
        via_bundle.audit_bundle(BUNDLE_1)
        via_bundle.audit_bundle(BUNDLE_2)
        via_singles = RangeAuditor(KEY)
        via_singles.audit(RECEIPT_R1, RANGE_1)
        via_singles.audit(RECEIPT_RCP, RANGE_FROM_CP)
        via_batch = RangeAuditor(KEY)
        via_batch.audit_batch(CHAIN)
        self.assertEqual(via_bundle.state, via_singles.state)
        self.assertEqual(via_bundle.state, via_batch.state)

    def test_mixed_with_old_entry_points(self):
        rbatch_1 = seal_range_receipt_batch(
            [(RECEIPT_R1, RANGE_1)], KEY
        )
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(rbatch_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_restart_from_checkpoint_then_bundle(self):
        first = RangeAuditor(KEY)
        first.audit_bundle(BUNDLE_1)
        restored = RangeAuditor(
            KEY, checkpoint=first.state.to_bytes()
        )
        restored.audit_bundle(BUNDLE_2)
        self.assertEqual(restored.state, RFRONTIER_2)


class RangeAuditorAuditBundleStartTest(unittest.TestCase):
    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_same_bundle_replayed_rejected(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL.to_bytes())
        self.assertIs(auditor.state, before)

    def test_old_fork_rejected(self):
        # A structurally valid bundle starting at a different frontier
        # than the current one is an old fork.
        fork_frontier = range_frontier_for(
            1, CFRONTIER_1.to_bytes(), b"\x02" * 32
        )
        signed = bundle_for(
            fork_frontier.to_bytes(),
            BUNDLE_2.receipts,
            RFRONTIER_2.to_bytes(),
        )
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(signed)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_broken_link_inside_bundle_rejected(self):
        broken_receipts = (
            RECEIPT_R1.to_bytes(),
            dataclasses.replace(RECEIPT_RCP, start=b"").to_bytes(),
        )
        signed = bundle_for(
            b"", broken_receipts, RFRONTIER_2.to_bytes()
        )
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(signed)
        self.assertIsNone(auditor.state)


class RangeAuditorAuditBundleTypeContractTest(unittest.TestCase):
    def test_wrong_kind_is_type_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_or_non_canonical_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (
            b"junk",
            b"[1,2,3]",
            b"",
            BUNDLE_FULL.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_failed_call_leaves_auditor_usable(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_bundle(42)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)


class RangeAuditorAuditBundleVerificationTest(unittest.TestCase):
    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).audit_bundle(BUNDLE_FULL)

    def test_signature_mismatch_rejected(self):
        forged = dataclasses.replace(BUNDLE_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(forged)

    def test_tampered_start_frontier_rejected(self):
        bad_start = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        placeholder = SpanReceiptBundle(
            1,
            bad_start.to_bytes(),
            BUNDLE_2.receipts,
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder,
            signature=_span_receipt_bundle_signature(KEY, placeholder),
        )
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(signed)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_tampered_end_frontier_rejected(self):
        bad_end = dataclasses.replace(RFRONTIER_2, mac=ZERO)
        placeholder = SpanReceiptBundle(
            1, b"", BUNDLE_FULL.receipts, bad_end.to_bytes(), ZERO
        )
        signed = dataclasses.replace(
            placeholder,
            signature=_span_receipt_bundle_signature(KEY, placeholder),
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(signed)

    def test_tampered_carried_receipt_rejected(self):
        broken_receipts = (
            dataclasses.replace(RECEIPT_R1, mac=ZERO).to_bytes(),
            RECEIPT_RCP.to_bytes(),
        )
        signed = bundle_for(
            b"", broken_receipts, RFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(signed)

    def test_end_must_match_replayed_chain(self):
        signed = bundle_for(
            BUNDLE_FULL.start,
            BUNDLE_FULL.receipts,
            RFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(signed)


class RangeAuditorAuditBundleAtomicityTest(unittest.TestCase):
    def test_failure_changes_nothing_from_empty(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_failure_keeps_prior_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.state, before)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_sequence_overflow_rejected_without_state_change(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        items = (RECEIPT_R1.to_bytes(),)
        signed = bundle_for(
            maxed.to_bytes(), items, RFRONTIER_2.to_bytes()
        )
        auditor = RangeAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(signed)
        self.assertIs(auditor.state, before)


class RangeAuditorAuditBundleLinearizationTest(unittest.TestCase):
    def test_bundle_batch_and_single_competing_calls_linearize(self):
        rbatch_full = seal_range_receipt_batch(CHAIN, KEY)
        auditor = RangeAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(4)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_bundle(BUNDLE_FULL),
                    "bundle",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_batch_record(rbatch_full),
                    "record",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(CHAIN), "batch"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_R1, RANGE_1),
                    "one",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 3)
        winner = successes[0]
        if winner == "one":
            self.assertEqual(auditor.state, RFRONTIER_1)
        else:
            self.assertEqual(auditor.state, RFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
