import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptAuditor,
    StreamCommitReceiptFrontier,
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
from test_stream_receipt_batch_commit_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    CRECEIPT_FULL,
    SBATCH_1,
    SBATCH_2,
    SBATCH_FULL,
)
from test_stream_commit_receipt_frontier import (
    CDIGEST_1,
    CFRONTIER_1,
    CFRONTIER_2,
    CFRONTIER_FULL,
    commit_frontier_for,
)
from test_stream_receipt_frontier import (
    SFRONTIER_1,
    SFRONTIER_2,
)
from test_stream_commit_receipt_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
)


PAIR_1 = (CRECEIPT_1, SBATCH_1)
PAIR_2 = (CRECEIPT_2, SBATCH_2)

# "" -> CFRONTIER_1, CFRONTIER_1 -> CFRONTIER_2 and "" -> CFRONTIER_2.
SPAN_1 = seal_stream_commit_receipt_span([PAIR_1], KEY)
SPAN_2 = seal_stream_commit_receipt_span(
    [PAIR_2], KEY, start=CFRONTIER_1
)
SPAN_FULL = seal_stream_commit_receipt_span(
    [PAIR_1, PAIR_2], KEY
)
# One commit straight to SFRONTIER_2: a fork competing with SPAN_1.
SPAN_SOLO = seal_stream_commit_receipt_span([(CRECEIPT_FULL, SBATCH_FULL)], KEY)


def span_for(start, items, end, key=KEY):
    """A span with the NPBJ31 mac recomputed over the first four
    fields."""
    placeholder = StreamCommitReceiptSpan(1, start, items, end, ZERO)
    return dataclasses.replace(
        placeholder,
        mac=_stream_commit_receipt_span_mac(key, placeholder),
    )


class StreamCommitReceiptSpanFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        span = StreamCommitReceiptSpan(
            1,
            b"",
            ((CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),),
            CFRONTIER_1.to_bytes(),
            SPAN_1.mac,
        )
        self.assertEqual(span, SPAN_1)
        self.assertEqual(hash(span), hash(SPAN_1))
        self.assertEqual(span.version, 1)
        self.assertEqual(span.start, b"")
        self.assertEqual(
            span.items,
            ((CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),),
        )
        self.assertEqual(span.end, CFRONTIER_1.to_bytes())

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
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, start=bad)
        dataclasses.replace(SPAN_1, start=b"")

    def test_items_contract(self):
        for bad in (1, "1", None, [SPAN_1.items[0]]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, items=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(SPAN_1, items=())
        for bad in (1, "1", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, items=(bad,))
        # A pair with a non-bytes member is a type error.
        for bad in (1, "1", None, bytearray(CRECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(
                    SPAN_1, items=((bad, SBATCH_1.to_bytes()),)
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(
                    SPAN_1, items=((CRECEIPT_1.to_bytes(), bad),)
                )
        # A pair with malformed bytes members is a value error.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(
                    SPAN_1, items=((bad, SBATCH_1.to_bytes()),)
                )
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(
                    SPAN_1, items=((CRECEIPT_1.to_bytes(), bad),)
                )
        # Wrong pair arity.
        with self.assertRaises(ValueError):
            dataclasses.replace(
                SPAN_1,
                items=((CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes(), b""),),
            )

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SPAN_1, end=bad)
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
            b'[1,"",'
            b'[["' + CRECEIPT_1.to_bytes().hex().encode()
            + b'","' + SBATCH_1.to_bytes().hex().encode() + b'"]],'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
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
                StreamCommitReceiptSpan.from_bytes(blob).to_bytes(),
                blob,
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
                    CRECEIPT_1.to_bytes().hex(),
                    SBATCH_1.to_bytes().hex(),
                ]
            ],
            CFRONTIER_1.to_bytes().hex(),
            SPAN_1.mac.hex(),
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
                StreamCommitReceiptSpan.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = SPAN_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpan.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            SPAN_1.mac.hex().encode(),
            SPAN_1.mac.hex().upper().encode(),
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
                    CRECEIPT_1.to_bytes().hex(),
                    SBATCH_1.to_bytes().hex(),
                ]
            ],
            CFRONTIER_1.to_bytes().hex(),
            SPAN_1.mac.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (2, []),
            (2, [["junk", SBATCH_1.to_bytes().hex()]]),
            (2, [[CRECEIPT_1.to_bytes().hex(), "junk"]]),
            (2, [[]]),
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

    def test_from_bytes_does_not_verify_mac(self):
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


class SealStreamCommitReceiptSpanTest(unittest.TestCase):
    def test_seals_chain_from_empty_ledger(self):
        span = seal_stream_commit_receipt_span(
            [PAIR_1, PAIR_2], KEY
        )
        self.assertEqual(span, SPAN_FULL)
        self.assertEqual(span.start, b"")
        self.assertEqual(
            span.items,
            (
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
                (CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),
            ),
        )
        self.assertEqual(span.end, CFRONTIER_2.to_bytes())

    def test_seals_single_pair(self):
        span = seal_stream_commit_receipt_span([PAIR_1], KEY)
        self.assertEqual(span, SPAN_1)
        self.assertEqual(span.end, CFRONTIER_1.to_bytes())

    def test_seals_from_supplied_frontier_object_and_bytes(self):
        for start in (CFRONTIER_1, CFRONTIER_1.to_bytes()):
            span = seal_stream_commit_receipt_span(
                [PAIR_2], KEY, start=start
            )
            self.assertEqual(span, SPAN_2)
            self.assertEqual(span.start, CFRONTIER_1.to_bytes())
            self.assertEqual(span.end, CFRONTIER_2.to_bytes())

    def test_accepts_canonical_pair_bytes(self):
        span = seal_stream_commit_receipt_span(
            [
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
                (CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),
            ],
            KEY,
        )
        self.assertEqual(span, SPAN_FULL)

    def test_sealing_touches_no_auditor_state(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        seal_stream_commit_receipt_span([PAIR_1], KEY)
        self.assertIsNone(auditor.state)

    def test_type_contract(self):
        with self.assertRaises(TypeError):
            seal_stream_commit_receipt_span(1, KEY)
        for bad in (1, "x", None, [CRECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span([(bad, SBATCH_1)], KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span([(CRECEIPT_1, bad)], KEY)
        with self.assertRaises(TypeError):
            seal_stream_commit_receipt_span([1], KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span([PAIR_1], bad)
        for bad in (1, "x", [CFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_span(
                    [PAIR_2], KEY, start=bad
                )

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([], KEY)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([PAIR_1], b"")
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(b"junk", SBATCH_1)], KEY
            )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(CRECEIPT_1, b"junk")], KEY
            )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [PAIR_2], KEY, start=b"junk"
            )

    def test_broken_chain_rejected(self):
        # The continuation pair cannot start from the empty ledger.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([PAIR_2], KEY)
        # A receipt cannot follow itself.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [PAIR_1, PAIR_1], KEY
            )

    def test_receipt_batch_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(CRECEIPT_1, SBATCH_2)], KEY
            )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(CRECEIPT_2, SBATCH_1)], KEY
            )

    def test_tampered_receipt_rejected(self):
        tampered = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [(tampered, SBATCH_1)], KEY
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span([PAIR_1], OTHER_KEY)

    def test_tampered_start_frontier_rejected(self):
        tampered = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [PAIR_2], KEY, start=tampered
            )

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_span(
                [PAIR_2], KEY, start=maxed
            )


class AuditStreamCommitReceiptSpanTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_1, KEY), CFRONTIER_1
        )
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_FULL, KEY), CFRONTIER_2
        )
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_2, KEY), CFRONTIER_2
        )
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_SOLO, KEY),
            CFRONTIER_FULL,
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_stream_commit_receipt_span(SPAN_FULL.to_bytes(), KEY),
            CFRONTIER_2,
        )

    def test_touches_no_auditor_state(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        audit_stream_commit_receipt_span(SPAN_FULL, KEY)
        self.assertIsNone(auditor.state)

    def test_type_contract(self):
        for bad in (1, "x", None, [SPAN_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span(bad, KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span(SPAN_1, bad)

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(b"junk", KEY)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(SPAN_1, b"")
        blob = SPAN_1.to_bytes()
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(
                blob.replace(b",", b", "), KEY
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(SPAN_1, OTHER_KEY)

    def test_tampered_span_mac(self):
        tampered = dataclasses.replace(SPAN_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(tampered, KEY)

    def test_tampered_start_frontier_mac(self):
        tampered_start = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        span = span_for(
            tampered_start.to_bytes(),
            ((CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_tampered_end_frontier_mac(self):
        tampered_end = dataclasses.replace(CFRONTIER_2, mac=ZERO)
        span = span_for(
            b"",
            (
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
                (CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),
            ),
            tampered_end.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        span = span_for(
            b"",
            ((tampered.to_bytes(), SBATCH_1.to_bytes()),),
            CFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_tampered_batch_mac(self):
        from nearproof import _stream_receipt_batch_mac

        forged_batch = dataclasses.replace(
            SBATCH_1,
            mac=_stream_receipt_batch_mac(OTHER_KEY, SBATCH_1),
        )
        span = span_for(
            b"",
            ((CRECEIPT_1.to_bytes(), forged_batch.to_bytes()),),
            CFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_receipt_batch_mismatch(self):
        span = span_for(
            b"",
            ((CRECEIPT_1.to_bytes(), SBATCH_2.to_bytes()),),
            CFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_broken_chain(self):
        # The first receipt must link to the span start.
        span = span_for(
            b"",
            ((CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)
        # Each receipt must link to the previous receipt's end.
        span = span_for(
            b"",
            (
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
            ),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_forged_end(self):
        # Valid MACs everywhere, but the replayed chain lands at
        # CFRONTIER_1 while the span claims CFRONTIER_2.
        span = span_for(
            b"",
            ((CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        span = span_for(
            maxed.to_bytes(),
            ((CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span(span, KEY)


class StreamCommitReceiptAuditorAuditSpanTest(unittest.TestCase):
    def test_commits_whole_span_from_empty(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit_span(SPAN_1), auditor)
        self.assertEqual(auditor.state, CFRONTIER_1)
        self.assertEqual(auditor.state.to_bytes(), SPAN_1.end)

    def test_commits_full_chain_in_one_step(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_span(SPAN_FULL)
        self.assertEqual(auditor.state, CFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit_span(SPAN_FULL.to_bytes()), auditor)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_continues_from_non_empty_frontier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        auditor.audit_span(SPAN_2)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_restarted_auditor_continues_from_span_start(self):
        first = StreamCommitReceiptAuditor(KEY)
        first.audit_span(SPAN_1)
        restored = StreamCommitReceiptAuditor(
            KEY, checkpoint=first.checkpoint.to_bytes()
        )
        restored.audit_span(SPAN_2)
        self.assertEqual(restored.state, CFRONTIER_2)

    def test_mixes_with_single_audit_and_bundle(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        auditor.audit_span(SPAN_2)
        self.assertEqual(auditor.state, CFRONTIER_2)
        auditor2 = StreamCommitReceiptAuditor(KEY)
        auditor2.audit_span(SPAN_1)
        auditor2.audit(CRECEIPT_2, SBATCH_2)
        self.assertEqual(auditor2.state, CFRONTIER_2)
        auditor3 = StreamCommitReceiptAuditor(KEY)
        auditor3.audit_bundle(BUNDLE_1)
        auditor3.audit_span(SPAN_2)
        self.assertEqual(auditor3.state, CFRONTIER_2)
        auditor4 = StreamCommitReceiptAuditor(KEY)
        auditor4.audit_span(SPAN_1)
        auditor4.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor4.state, CFRONTIER_2)

    def test_agrees_with_standalone_verifier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_span(SPAN_FULL)
        self.assertEqual(
            auditor.state,
            audit_stream_commit_receipt_span(SPAN_FULL, KEY),
        )

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (1, "x", None, [SPAN_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_span(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_span(bad)
        self.assertIsNone(auditor.state)

    def test_empty_ledger_requires_empty_start(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_2)
        self.assertIsNone(auditor.state)

    def test_non_empty_ledger_requires_current_frontier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_span(SPAN_1)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_FULL)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_same_span_replay_is_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_span(SPAN_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_FULL)
        self.assertIs(auditor.state, before)

    def test_fork_from_other_start_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_span(SPAN_SOLO)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_2)
        self.assertEqual(auditor.state, CFRONTIER_FULL)
        self.assertEqual(auditor.state.sequence, 1)

    def test_tampered_span_mac(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        tampered = dataclasses.replace(SPAN_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_span(tampered)
        self.assertIsNone(auditor.state)

    def test_wrong_key(self):
        auditor = StreamCommitReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_1)
        self.assertIsNone(auditor.state)

    def test_tampered_end_frontier_mac(self):
        tampered_end = dataclasses.replace(CFRONTIER_2, mac=ZERO)
        span = span_for(
            b"",
            (
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
                (CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),
            ),
            tampered_end.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(span)
        self.assertIsNone(auditor.state)

    def test_forged_end(self):
        span = span_for(
            b"",
            ((CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),),
            CFRONTIER_2.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(span)
        self.assertIsNone(auditor.state)

    def test_failure_after_first_pair_is_atomic(self):
        span = span_for(
            b"",
            (
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
                (CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes()),
            ),
            CFRONTIER_2.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(span)
        self.assertIsNone(auditor.state)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        span = span_for(
            maxed.to_bytes(),
            ((CRECEIPT_2.to_bytes(), SBATCH_2.to_bytes()),),
            CFRONTIER_2.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_span(span)
        self.assertIs(auditor.state, before)

    def test_failed_span_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_span(SPAN_2)
        self.assertIsNone(auditor.state)
        auditor.audit_span(SPAN_1)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_competing_spans_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        commits, failures = [], []

        def run(span):
            try:
                auditor.audit_span(span)
                commits.append(span)
            except ValueError:
                failures.append(span)

        threads = [
            threading.Thread(target=run, args=(SPAN_1,)),
            threading.Thread(target=run, args=(SPAN_SOLO,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertIn(
            auditor.state.end,
            (SFRONTIER_1.to_bytes(), SFRONTIER_2.to_bytes()),
        )

    def test_span_and_single_audit_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        commits, failures = [], []

        def run_span():
            try:
                auditor.audit_span(SPAN_1)
                commits.append("span")
            except ValueError:
                failures.append("span")

        def run_single():
            try:
                auditor.audit(CRECEIPT_1, SBATCH_1)
                commits.append("single")
            except ValueError:
                failures.append("single")

        threads = [
            threading.Thread(target=run_span),
            threading.Thread(target=run_single),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_span_and_bundle_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        commits, failures = [], []

        def run_span():
            try:
                auditor.audit_span(SPAN_FULL)
                commits.append("span")
            except ValueError:
                failures.append("span")

        def run_bundle():
            try:
                auditor.audit_bundle(BUNDLE_FULL)
                commits.append("bundle")
            except ValueError:
                failures.append("bundle")

        threads = [
            threading.Thread(target=run_span),
            threading.Thread(target=run_bundle),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state, CFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
