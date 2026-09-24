import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptBundleReceiptAuditor,
    StreamCommitReceiptSpan,
    _stream_commit_receipt_span_content_bytes,
    _stream_commit_receipt_span_mac,
    audit_stream_commit_receipt_span,
    seal_stream_commit_receipt_span,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_stream_commit_receipt_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    BUNDLE_SOLO,
)
from test_stream_commit_receipt_bundle_receipt import (
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
    RECEIPT_SOLO,
)
from test_stream_commit_receipt_bundle_receipt_frontier import (
    RDIGEST_1,
    RFRONTIER_1,
    RFRONTIER_2,
    RFRONTIER_FULL,
    bundle_receipt_frontier_for,
)
from test_stream_commit_receipt_frontier import CFRONTIER_1, CFRONTIER_2


# "" -> RFRONTIER_1, RFRONTIER_1 -> RFRONTIER_2, the whole chain in one
# packing and a fork competing with SPAN_1 for the first sequence slot.
SPAN_1 = seal_stream_commit_receipt_span(
    [(RECEIPT_1, BUNDLE_1)], KEY
)
SPAN_2 = seal_stream_commit_receipt_span(
    [(RECEIPT_2, BUNDLE_2)], KEY, start=RFRONTIER_1
)
SPAN_FULL = seal_stream_commit_receipt_span(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
)
SPAN_SOLO = seal_stream_commit_receipt_span(
    [(RECEIPT_SOLO, BUNDLE_SOLO)], KEY
)


def span_for(start, items, end, key=KEY):
    """A span with the NPBJ31 mac recomputed over the first four
    fields."""
    placeholder = StreamCommitReceiptSpan(1, start, items, end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_stream_commit_receipt_span_mac(key, placeholder)
    )


class StreamCommitReceiptSpanFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        span = StreamCommitReceiptSpan(
            1,
            b"",
            (
                (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
            ),
            RFRONTIER_1.to_bytes(),
            SPAN_1.mac,
        )
        self.assertEqual(span, SPAN_1)
        self.assertEqual(hash(span), hash(SPAN_1))
        self.assertEqual(span.version, 1)
        self.assertEqual(span.start, b"")
        self.assertEqual(
            span.items, ((RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),)
        )
        self.assertEqual(span.end, RFRONTIER_1.to_bytes())

    def test_fields_of_chain_and_continuation(self):
        self.assertEqual(SPAN_FULL.start, b"")
        self.assertEqual(
            SPAN_FULL.items,
            (
                (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
                (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
            ),
        )
        self.assertEqual(SPAN_FULL.end, RFRONTIER_2.to_bytes())
        self.assertEqual(SPAN_2.start, RFRONTIER_1.to_bytes())
        self.assertEqual(
            SPAN_2.items, ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),)
        )
        self.assertEqual(SPAN_2.end, RFRONTIER_2.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            SPAN_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(SPAN_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, start=bad)
        # Malformed bytes are value errors: the start is empty or a
        # canonical bundle-receipt frontier.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, start=bad)
        # b"" (the empty ledger) and a canonical frontier both pass.
        dataclasses.replace(SPAN_1, start=b"")
        dataclasses.replace(SPAN_1, start=RFRONTIER_1.to_bytes())

    def test_items_container_contract(self):
        for bad in (1, "1", None, [SPAN_1.items[0]], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, items=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(SPAN_1, items=())

    def test_items_pair_contract(self):
        # Non-tuple pair members are type errors; wrong arity is a value
        # error.
        for bad_pair in (
            1,
            "x",
            None,
            [RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()],
        ):
            with self.assertRaises(TypeError, msg=repr(bad_pair)):
                dataclasses.replace(SPAN_1, items=(bad_pair,))
        for bad_pair in (
            (),
            (RECEIPT_1.to_bytes(),),
            (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), 1),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_pair)):
                dataclasses.replace(SPAN_1, items=(bad_pair,))

    def test_items_member_type_contract(self):
        for bad_receipt in (1, None, bytearray(RECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad_receipt)):
                dataclasses.replace(
                    SPAN_1,
                    items=((bad_receipt, BUNDLE_1.to_bytes()),),
                )
        for bad_bundle in (1, None, bytearray(BUNDLE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad_bundle)):
                dataclasses.replace(
                    SPAN_1,
                    items=((RECEIPT_1.to_bytes(), bad_bundle),),
                )

    def test_items_must_be_canonical_inner_encodings(self):
        # Well-typed but malformed or non-canonical inner bytes are
        # value errors.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=("receipt", repr(bad))):
                dataclasses.replace(
                    SPAN_1, items=((bad, BUNDLE_1.to_bytes()),)
                )
            with self.assertRaises(ValueError, msg=("bundle", repr(bad))):
                dataclasses.replace(
                    SPAN_1, items=((RECEIPT_1.to_bytes(), bad),)
                )

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty bundle-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, end=bad)

    def test_mac_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, mac=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, mac=bad)


class StreamCommitReceiptSpanEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",[['
            b'"' + RECEIPT_1.to_bytes().hex().encode() + b'",'
            b'"' + BUNDLE_1.to_bytes().hex().encode() + b'"]],'
            b'"' + RFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + SPAN_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(SPAN_1.to_bytes(), expected)

    def test_round_trip(self):
        for span in (SPAN_1, SPAN_2, SPAN_FULL, SPAN_SOLO):
            blob = span.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptSpan.from_bytes(blob), span
            )
            self.assertEqual(
                StreamCommitReceiptSpan.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = SPAN_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptSpan.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptSpan.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            [
                [
                    RECEIPT_1.to_bytes().hex(),
                    BUNDLE_1.to_bytes().hex(),
                ]
            ],
            RFRONTIER_1.to_bytes().hex(),
            SPAN_1.mac.hex(),
        ]
        # A non-integer version, a non-array items field and a non-array
        # pair are all field-shape (type) errors.
        for index, bad_value in ((0, "1"), (2, 1), (2, {})):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                StreamCommitReceiptSpan.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )
        broken_items = list(good)
        broken_items[2] = [1]
        with self.assertRaises(TypeError):
            StreamCommitReceiptSpan.from_bytes(
                json.dumps(broken_items, separators=(",", ":")).encode()
            )
        # A pair of the wrong arity is a value error.
        broken_items[2] = [["aa"]]
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(
                json.dumps(broken_items, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = SPAN_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            SPAN_1.mac.hex().encode(), SPAN_1.mac.hex().upper().encode()
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            [
                [
                    RECEIPT_1.to_bytes().hex(),
                    BUNDLE_1.to_bytes().hex(),
                ]
            ],
            RFRONTIER_1.to_bytes().hex(),
            SPAN_1.mac.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (3, ""),
            (3, "junk"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                StreamCommitReceiptSpan.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )
        # An empty items array is a value error (the span must pack at
        # least one pair).
        broken = list(good)
        broken[2] = []
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(
                json.dumps(broken, separators=(",", ":")).encode()
            )
        # A non-canonical inner receipt encoding is rejected.
        broken = list(good)
        broken[2] = [
            [RECEIPT_1.to_bytes().replace(b",", b", ").hex(),
             BUNDLE_1.to_bytes().hex()]
        ]
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(
                json.dumps(broken, separators=(",", ":")).encode()
            )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the span MAC nor any nested receipt, bundle or
        # frontier MAC is checked at parse time.
        tampered = dataclasses.replace(SPAN_1, mac=ZERO)
        parsed = StreamCommitReceiptSpan.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_mac_scheme(self):
        expected_mac = hmac.new(
            KEY,
            b"NPBJ31" + _stream_commit_receipt_span_content_bytes(SPAN_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(SPAN_1.mac, expected_mac)
        self.assertEqual(len(SPAN_1.mac), 32)


class SealStreamCommitReceiptSpanTest(unittest.TestCase):
    def test_seal_empty_start_and_continuation(self):
        self.assertEqual(SPAN_1.start, b"")
        self.assertEqual(SPAN_1.end, RFRONTIER_1.to_bytes())
        self.assertEqual(SPAN_2.start, RFRONTIER_1.to_bytes())
        self.assertEqual(SPAN_2.end, RFRONTIER_2.to_bytes())
        self.assertEqual(SPAN_FULL.end, RFRONTIER_2.to_bytes())

    def test_seal_accepts_objects_or_canonical_bytes(self):
        from_bytes = seal_stream_commit_receipt_span(
            [(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())], KEY
        )
        self.assertEqual(from_bytes, SPAN_1)
        chained = seal_stream_commit_receipt_span(
            [(RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes())],
            KEY,
            start=RFRONTIER_1.to_bytes(),
        )
        self.assertEqual(chained, SPAN_2)

    def test_seal_with_frontier_object_and_bytes_start(self):
        self.assertEqual(
            seal_stream_commit_receipt_span(
                [(RECEIPT_2, BUNDLE_2)], KEY, start=RFRONTIER_1
            ),
            SPAN_2,
        )

    def test_seal_rejects_empty_sequence(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([], KEY)

    def test_seal_rejects_non_iterable(self):
        for bad in (7, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span(bad, KEY)

    def test_seal_rejects_wrong_pair_shapes(self):
        # A non-unpackable member is a type error; wrong arity is a value
        # error.
        with self.assertRaises(TypeError):
            seal_stream_commit_receipt_span([7], KEY)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([(RECEIPT_1,)], KEY)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_1, BUNDLE_1, 1)], KEY
            )

    def test_seal_rejects_wrong_pair_member_types(self):
        for bad in (7, "x", None):
            with self.assertRaises(TypeError, msg=("receipt", repr(bad))):
                seal_stream_commit_receipt_span([(bad, BUNDLE_1)], KEY)
            with self.assertRaises(TypeError, msg=("bundle", repr(bad))):
                seal_stream_commit_receipt_span([(RECEIPT_1, bad)], KEY)

    def test_seal_rejects_malformed_member_bytes(self):
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=("receipt", repr(bad))):
                seal_stream_commit_receipt_span([(bad, BUNDLE_1)], KEY)
            with self.assertRaises(ValueError, msg=("bundle", repr(bad))):
                seal_stream_commit_receipt_span([(RECEIPT_1, bad)], KEY)

    def test_seal_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span(
                    [(RECEIPT_1, BUNDLE_1)], bad
                )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([(RECEIPT_1, BUNDLE_1)], b"")

    def test_seal_start_type_contract(self):
        for bad in (1, "x", object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span(
                    [(RECEIPT_1, BUNDLE_1)], KEY, start=bad
                )

    def test_seal_rejects_wrong_key(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_1, BUNDLE_1)], OTHER_KEY
            )

    def test_seal_rejects_broken_chain(self):
        # The continuation receipt cannot seal from the empty ledger and
        # the genesis receipt cannot follow RFRONTIER_1.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_2, BUNDLE_2)], KEY
            )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_1, BUNDLE_1)], KEY, start=RFRONTIER_1
            )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_2, BUNDLE_2), (RECEIPT_1, BUNDLE_1)], KEY
            )

    def test_seal_rejects_receipt_bundle_mismatch(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_2, BUNDLE_1)], KEY
            )

    def test_seal_rejects_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_2.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(RECEIPT_2, BUNDLE_2)], KEY, start=maxed
            )

    def test_seal_touches_no_auditor_state(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        seal_stream_commit_receipt_span(
            [(RECEIPT_1, BUNDLE_1)], KEY
        )
        self.assertIsNone(auditor.checkpoint)


class AuditStreamCommitReceiptSpanTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_1, KEY), RFRONTIER_1
        )
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_2, KEY), RFRONTIER_2
        )
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_FULL, KEY), RFRONTIER_2
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_2.to_bytes(), KEY),
            RFRONTIER_2,
        )

    def test_wrong_argument_type(self):
        for bad in (1, "x", None, [SPAN_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span(bad, KEY)

    def test_malformed_or_non_canonical_bytes_is_value_error(self):
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_stream_commit_receipt_span(bad, KEY)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(
                SPAN_1.to_bytes().replace(b",", b", "), KEY
            )

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span(SPAN_1, bad)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(SPAN_1, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(SPAN_1, OTHER_KEY)

    def test_tampered_span_mac_rejected(self):
        tampered = dataclasses.replace(SPAN_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(tampered, KEY)

    def test_tampered_carried_receipt_rejected(self):
        # The span wrapper is re-MAC'd honestly but the carried
        # receipt's NPBJ28 MAC is wrong: the inner layer must fail.
        broken_receipt = dataclasses.replace(RECEIPT_1, mac=ZERO)
        tampered = span_for(
            SPAN_1.start,
            ((broken_receipt.to_bytes(), BUNDLE_1.to_bytes()),),
            SPAN_1.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(tampered, KEY)

    def test_swapped_bundle_rejected(self):
        tampered = span_for(
            SPAN_1.start,
            ((RECEIPT_1.to_bytes(), BUNDLE_2.to_bytes()),),
            SPAN_1.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(tampered, KEY)

    def test_forged_end_rejected(self):
        # A syntactically valid, properly MAC'd end frontier that the
        # carried chain does not actually reach.
        forged = span_for(
            SPAN_1.start, SPAN_1.items, RFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(forged, KEY)

    def test_broken_start_linkage_rejected(self):
        # Chain sealed against the empty ledger but carrying the
        # continuation receipt with a non-empty start.
        broken = span_for(
            b"",
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            RFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(broken, KEY)

    def test_tampered_endpoint_frontier_rejected(self):
        # The nested end frontier's own NPBJ29 layer is recomputed.
        bad_end = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        tampered = span_for(SPAN_1.start, SPAN_1.items, bad_end.to_bytes())
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(tampered, KEY)


class StreamCommitReceiptSpanAuditorAuditSpanTest(unittest.TestCase):
    def test_audit_span_returns_self_and_advances(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_span(SPAN_1), auditor)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, CFRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, RDIGEST_1)

    def test_whole_chain_books_in_one_step(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_FULL)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_chain_continues_with_second_span(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        auditor.audit_span(SPAN_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_FULL.to_bytes())
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_restart_from_checkpoint_continues(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit_span(SPAN_2)
            self.assertEqual(restored.checkpoint, RFRONTIER_2)

    def test_first_span_must_start_empty(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_span_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1)
        self.assertIs(auditor.checkpoint, before)

    def test_old_fork_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_fork_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_SOLO)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_span_rejected_leaves_state(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_span(dataclasses.replace(SPAN_2, mac=ZERO))
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_key_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [SPAN_1], (SPAN_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_span(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_span(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1.to_bytes().replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_span(SPAN_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_shares_lock_with_single_receipt_audit(self):
        # A span booked onto the empty ledger lands exactly where the
        # one-at-a-time audit does, and subsequent single audits
        # continue from it; replays are rejected either way.
        via_span = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_span.audit_span(SPAN_1)
        via_single = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_single.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(via_span.checkpoint, via_single.checkpoint)
        via_span.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_span.checkpoint, RFRONTIER_2)
        with self.assertRaises(ValueError):
            via_span.audit_span(SPAN_2)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_2.to_bytes(), RDIGEST_1
        )
        auditor = StreamCommitReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_span(
                seal_stream_commit_receipt_span(
                    [(RECEIPT_2, BUNDLE_2)], KEY, start=maxed
                )
            )
        self.assertIs(auditor.checkpoint, before)

    def test_competing_spans_linearize(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        wins, losses = [], []

        def run(span, tag):
            try:
                auditor.audit_span(span)
                wins.append(tag)
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

    def test_accepted_span_is_never_lost(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_SOLO)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)


class StreamCommitReceiptSpanParameterNamingTest(unittest.TestCase):
    def test_seal_params_named_items_key_start(self):
        signature = inspect.signature(seal_stream_commit_receipt_span)
        self.assertEqual(list(signature.parameters), ["items", "key", "start"])
        self.assertTrue(
            signature.parameters["start"].kind
            == inspect.Parameter.KEYWORD_ONLY
        )

    def test_audit_params_named_x_and_key(self):
        signature = inspect.signature(audit_stream_commit_receipt_span)
        self.assertEqual(list(signature.parameters), ["x", "key"])

    def test_auditor_method_param_named_x(self):
        signature = inspect.signature(
            StreamCommitReceiptBundleReceiptAuditor.audit_span
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_entry_still_verifies(self):
        self.assertEqual(
            audit_stream_commit_receipt_span(x=SPAN_1, key=KEY),
            RFRONTIER_1,
        )


if __name__ == "__main__":
    unittest.main()
