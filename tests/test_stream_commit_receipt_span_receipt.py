import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptBundleReceiptAuditor,
    StreamCommitReceiptSpanReceipt,
    _stream_commit_receipt_span_receipt_content_bytes,
    _stream_commit_receipt_span_receipt_mac,
    audit_stream_commit_receipt_span_receipt,
    seal_stream_commit_receipt_span,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_stream_commit_receipt_bundle import BUNDLE_1, BUNDLE_2
from test_stream_commit_receipt_bundle_receipt import RECEIPT_1, RECEIPT_2
from test_stream_commit_receipt_bundle_receipt_frontier import (
    RDIGEST_1,
    RFRONTIER_1,
    RFRONTIER_2,
    bundle_receipt_frontier_for,
)
from test_stream_commit_receipt_frontier import CFRONTIER_2
from test_stream_commit_receipt_span import (
    SPAN_1,
    SPAN_2,
    SPAN_FULL,
    SPAN_SOLO,
    span_for,
)


def _commit(*spans, key=KEY):
    """Book ``spans`` in order on a fresh auditor, returning the
    commit receipts."""
    auditor = StreamCommitReceiptBundleReceiptAuditor(key)
    return [auditor.commit_span(span) for span in spans]


# The receipts signed out by commit_span for the empty-ledger span, its
# continuation, the whole chain in one packing and the competing fork.
SPAN_RECEIPT_1, SPAN_RECEIPT_2 = _commit(SPAN_1, SPAN_2)
SPAN_RECEIPT_FULL = _commit(SPAN_FULL)[0]
SPAN_RECEIPT_SOLO = _commit(SPAN_SOLO)[0]


def span_receipt_for(start, span_digest, end, key=KEY):
    """A span receipt with the NPBJ32 mac recomputed over the first
    four fields."""
    placeholder = StreamCommitReceiptSpanReceipt(
        1, start, span_digest, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_commit_receipt_span_receipt_mac(key, placeholder),
    )


class StreamCommitReceiptSpanReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = StreamCommitReceiptSpanReceipt(
            1,
            b"",
            hashlib.sha256(SPAN_1.to_bytes()).digest(),
            RFRONTIER_1.to_bytes(),
            SPAN_RECEIPT_1.mac,
        )
        self.assertEqual(receipt, SPAN_RECEIPT_1)
        self.assertEqual(hash(receipt), hash(SPAN_RECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.span_digest,
            hashlib.sha256(SPAN_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, RFRONTIER_1.to_bytes())

    def test_fields_of_chain_and_continuation(self):
        self.assertEqual(SPAN_RECEIPT_2.start, RFRONTIER_1.to_bytes())
        self.assertEqual(SPAN_RECEIPT_2.end, RFRONTIER_2.to_bytes())
        self.assertEqual(
            SPAN_RECEIPT_2.span_digest,
            hashlib.sha256(SPAN_2.to_bytes()).digest(),
        )
        self.assertEqual(SPAN_RECEIPT_FULL.start, b"")
        self.assertEqual(SPAN_RECEIPT_FULL.end, RFRONTIER_2.to_bytes())
        self.assertEqual(
            SPAN_RECEIPT_FULL.span_digest,
            hashlib.sha256(SPAN_FULL.to_bytes()).digest(),
        )

    def test_span_digest_binds_only_that_span(self):
        # Same start, same key, different packed intervals: the digests
        # differ, and each equals the hash of its own span only.
        self.assertNotEqual(
            SPAN_RECEIPT_1.span_digest, SPAN_RECEIPT_SOLO.span_digest
        )
        self.assertNotEqual(
            SPAN_RECEIPT_1.span_digest, SPAN_RECEIPT_FULL.span_digest
        )
        self.assertEqual(
            SPAN_RECEIPT_1.span_digest,
            hashlib.sha256(SPAN_1.to_bytes()).digest(),
        )
        self.assertEqual(
            SPAN_RECEIPT_SOLO.span_digest,
            hashlib.sha256(SPAN_SOLO.to_bytes()).digest(),
        )

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            SPAN_RECEIPT_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(SPAN_RECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, start=bad)
        # Malformed bytes are value errors: the start is empty or a
        # canonical bundle-receipt frontier.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, start=bad)
        # b"" (the empty ledger) and a canonical frontier both pass.
        dataclasses.replace(SPAN_RECEIPT_1, start=b"")
        dataclasses.replace(SPAN_RECEIPT_1, start=RFRONTIER_1.to_bytes())

    def test_span_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, span_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, span_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty bundle-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, end=bad)

    def test_mac_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, mac=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_RECEIPT_1, mac=bad)


class StreamCommitReceiptSpanReceiptEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'"' + SPAN_RECEIPT_1.span_digest.hex().encode() + b'",'
            b'"' + RFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + SPAN_RECEIPT_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(SPAN_RECEIPT_1.to_bytes(), expected)

    def test_round_trip(self):
        for receipt in (
            SPAN_RECEIPT_1,
            SPAN_RECEIPT_2,
            SPAN_RECEIPT_FULL,
            SPAN_RECEIPT_SOLO,
        ):
            blob = receipt.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptSpanReceipt.from_bytes(blob), receipt
            )
            self.assertEqual(
                StreamCommitReceiptSpanReceipt.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = SPAN_RECEIPT_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptSpanReceipt.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptSpanReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            SPAN_RECEIPT_1.span_digest.hex(),
            RFRONTIER_1.to_bytes().hex(),
            SPAN_RECEIPT_1.mac.hex(),
        ]
        # A non-integer version and non-string hex fields are
        # field-shape (type) errors.
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, None),
            (3, 1.0),
            (4, b"x"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                StreamCommitReceiptSpanReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = SPAN_RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpanReceipt.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            SPAN_RECEIPT_1.mac.hex().encode(),
            SPAN_RECEIPT_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpanReceipt.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpanReceipt.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            SPAN_RECEIPT_1.span_digest.hex(),
            RFRONTIER_1.to_bytes().hex(),
            SPAN_RECEIPT_1.mac.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (2, "00"),
            (2, "junk"),
            (3, ""),
            (3, "junk"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                StreamCommitReceiptSpanReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the receipt signature nor any nested frontier MAC is
        # checked at parse time.
        tampered = dataclasses.replace(SPAN_RECEIPT_1, mac=ZERO)
        parsed = StreamCommitReceiptSpanReceipt.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_mac_scheme(self):
        expected_mac = hmac.new(
            KEY,
            b"NPBJ32"
            + _stream_commit_receipt_span_receipt_content_bytes(
                SPAN_RECEIPT_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(SPAN_RECEIPT_1.mac, expected_mac)
        self.assertEqual(len(SPAN_RECEIPT_1.mac), 32)


class StreamCommitReceiptSpanReceiptCommitSpanTest(unittest.TestCase):
    def test_commit_span_returns_receipt_and_advances(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_1)
        self.assertIsInstance(receipt, StreamCommitReceiptSpanReceipt)
        self.assertEqual(receipt, SPAN_RECEIPT_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)

    def test_receipt_carries_span_endpoints_and_digest(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_FULL)
        self.assertEqual(receipt.start, SPAN_FULL.start)
        self.assertEqual(receipt.end, SPAN_FULL.end)
        self.assertEqual(
            receipt.span_digest,
            hashlib.sha256(SPAN_FULL.to_bytes()).digest(),
        )
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_chain_continues_with_second_span(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        receipt = auditor.commit_span(SPAN_2)
        self.assertEqual(receipt, SPAN_RECEIPT_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_1.to_bytes())
        self.assertEqual(receipt, SPAN_RECEIPT_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_restart_from_checkpoint_continues(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            receipt = restored.commit_span(SPAN_2)
            self.assertEqual(receipt, SPAN_RECEIPT_2)
            self.assertEqual(restored.checkpoint, RFRONTIER_2)

    def test_matches_audit_span_booking(self):
        # commit_span books exactly like audit_span and only adds the
        # receipt.
        via_commit = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_commit.commit_span(SPAN_FULL)
        via_audit = StreamCommitReceiptBundleReceiptAuditor(KEY)
        self.assertIs(via_audit.audit_span(SPAN_FULL), via_audit)
        self.assertEqual(via_commit.checkpoint, via_audit.checkpoint)

    def test_first_span_must_start_empty(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_span_rejected_no_receipt(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1)
        self.assertIs(auditor.checkpoint, before)

    def test_old_fork_rejected_no_receipt(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_fork_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_SOLO)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_span_rejected_leaves_state(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(dataclasses.replace(SPAN_2, mac=ZERO))
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_key_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [SPAN_1], (SPAN_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_span(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_span(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1.to_bytes().replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failed_commit_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_2)
        self.assertIsNone(auditor.checkpoint)
        receipt = auditor.commit_span(SPAN_1)
        self.assertEqual(receipt, SPAN_RECEIPT_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_shares_lock_with_single_receipt_audit(self):
        # A span committed onto the empty ledger lands exactly where
        # the one-at-a-time audit does, and subsequent single audits
        # continue from it; replays are rejected either way.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        via_single = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_single.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, via_single.checkpoint)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_2)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_2.to_bytes(), RDIGEST_1
        )
        auditor = StreamCommitReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(
                seal_stream_commit_receipt_span(
                    [(RECEIPT_2, BUNDLE_2)], KEY, start=maxed
                )
            )
        self.assertIs(auditor.checkpoint, before)

    def test_competing_commit_spans_linearize(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        wins, losses = [], []

        def run(span, tag):
            try:
                wins.append((tag, auditor.commit_span(span)))
            except ValueError:
                losses.append(tag)

        threads = [
            threading.Thread(target=run, args=(SPAN_1, "a")),
            threading.Thread(target=run, args=(SPAN_SOLO, "b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(losses), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        # The winner's receipt attests exactly the span that booked.
        tag, receipt = wins[0]
        span = SPAN_1 if tag == "a" else SPAN_SOLO
        self.assertEqual(
            receipt.span_digest,
            hashlib.sha256(span.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, auditor.checkpoint.to_bytes())

    def test_commit_span_linearizes_with_audit(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        outcomes = []

        def run_commit():
            try:
                auditor.commit_span(SPAN_1)
                outcomes.append("commit")
            except ValueError:
                outcomes.append("commit-lost")

        def run_audit():
            try:
                auditor.audit(RECEIPT_1, BUNDLE_1)
                outcomes.append("audit")
            except ValueError:
                outcomes.append("audit-lost")

        threads = [
            threading.Thread(target=run_commit),
            threading.Thread(target=run_audit),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Exactly one of the two books the first sequence slot; both
        # paths lead the ledger to the same frontier.
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(
            sum(tag.endswith("lost") for tag in outcomes), 1
        )
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)


class AuditStreamCommitReceiptSpanReceiptTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1, SPAN_1, KEY
            ),
            RFRONTIER_1,
        )
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_2, SPAN_2, KEY
            ),
            RFRONTIER_2,
        )
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_FULL, SPAN_FULL, KEY
            ),
            RFRONTIER_2,
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_2.to_bytes(), SPAN_2.to_bytes(), KEY
            ),
            RFRONTIER_2,
        )

    def test_receipt_argument_type_contract(self):
        for bad in (1, "x", None, [SPAN_RECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span_receipt(bad, SPAN_1, KEY)

    def test_span_argument_type_contract(self):
        for bad in (1, "x", None, [SPAN_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span_receipt(
                    SPAN_RECEIPT_1, bad, KEY
                )

    def test_malformed_bytes_are_value_errors(self):
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=("receipt", repr(bad))):
                audit_stream_commit_receipt_span_receipt(bad, SPAN_1, KEY)
            with self.assertRaises(ValueError, msg=("span", repr(bad))):
                audit_stream_commit_receipt_span_receipt(
                    SPAN_RECEIPT_1, bad, KEY
                )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1.to_bytes().replace(b",", b", "), SPAN_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1, SPAN_1.to_bytes().replace(b",", b", "), KEY
            )

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span_receipt(
                    SPAN_RECEIPT_1, SPAN_1, bad
                )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1, SPAN_1, b""
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1, SPAN_1, OTHER_KEY
            )

    def test_tampered_receipt_mac_rejected(self):
        tampered = dataclasses.replace(SPAN_RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                tampered, SPAN_1, KEY
            )

    def test_span_digest_mismatch_rejected(self):
        # An honestly signed receipt whose carried digest is not the
        # hash of the presented span.
        forged = span_receipt_for(
            SPAN_RECEIPT_1.start, ZERO, SPAN_RECEIPT_1.end
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(forged, SPAN_1, KEY)

    def test_receipt_binds_only_its_own_span(self):
        # The receipt for SPAN_1 does not attest any other span, even
        # one starting from the same empty ledger.
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1, SPAN_SOLO, KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SPAN_RECEIPT_1, SPAN_FULL, KEY
            )

    def test_start_mismatch_rejected(self):
        forged = span_receipt_for(
            RFRONTIER_1.to_bytes(),
            SPAN_RECEIPT_1.span_digest,
            SPAN_RECEIPT_1.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(forged, SPAN_1, KEY)

    def test_end_mismatch_rejected(self):
        forged = span_receipt_for(
            SPAN_RECEIPT_1.start,
            SPAN_RECEIPT_1.span_digest,
            RFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(forged, SPAN_1, KEY)

    def test_whole_span_replayed(self):
        # The receipt honestly attests a span whose wrapper MAC is
        # valid but whose carried chain does not reach its end: the
        # full replay inside the audit must reject it.
        broken_span = span_for(
            SPAN_1.start, SPAN_1.items, RFRONTIER_2.to_bytes()
        )
        receipt = span_receipt_for(
            broken_span.start,
            hashlib.sha256(broken_span.to_bytes()).digest(),
            broken_span.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                receipt, broken_span, KEY
            )

    def test_tampered_carried_receipt_rejected(self):
        broken_receipt = dataclasses.replace(RECEIPT_1, mac=ZERO)
        broken_span = span_for(
            SPAN_1.start,
            ((broken_receipt.to_bytes(), BUNDLE_1.to_bytes()),),
            SPAN_1.end,
        )
        receipt = span_receipt_for(
            broken_span.start,
            hashlib.sha256(broken_span.to_bytes()).digest(),
            broken_span.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                receipt, broken_span, KEY
            )

    def test_touches_no_auditor_state(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        audit_stream_commit_receipt_span_receipt(
            SPAN_RECEIPT_1, SPAN_1, KEY
        )
        self.assertIsNone(auditor.checkpoint)


class StreamCommitReceiptSpanReceiptParameterNamingTest(unittest.TestCase):
    def test_audit_params_named_receipt_span_key(self):
        signature = inspect.signature(
            audit_stream_commit_receipt_span_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "span", "key"]
        )

    def test_commit_span_param_named_x(self):
        signature = inspect.signature(
            StreamCommitReceiptBundleReceiptAuditor.commit_span
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_entry_still_verifies(self):
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                receipt=SPAN_RECEIPT_1, span=SPAN_1, key=KEY
            ),
            RFRONTIER_1,
        )


if __name__ == "__main__":
    unittest.main()
