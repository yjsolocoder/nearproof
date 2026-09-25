import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptAuditor,
    SpanBundleReceiptBatch,
    SpanBundleReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX,
    _span_bundle_receipt_batch_content_bytes,
    _span_bundle_receipt_batch_signature,
    _span_bundle_receipt_frontier_signature,
    _span_bundle_receipt_signature,
    audit_span_bundle_receipt_batch,
    seal_span_bundle_receipt_batch,
)
from test_range_auditor_audit_batch import (
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RDIGEST_1,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    range_frontier_for,
)
from test_span_bundle_receipt import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
)


# A one-receipt batch from the empty ledger to PFRONTIER_1, its
# continuation from PFRONTIER_1 to PFRONTIER_2, and the whole segment in
# one batch.
BATCH_1 = seal_span_bundle_receipt_batch([RECEIPT_1], KEY)
BATCH_2 = seal_span_bundle_receipt_batch(
    [RECEIPT_2], KEY, start=PFRONTIER_1
)
BATCH_FULL = seal_span_bundle_receipt_batch(
    [RECEIPT_1, RECEIPT_2], KEY
)


def batch_for(start, receipts, end, key=KEY):
    """A batch with the NPBJ38 signature recomputed over the first four
    fields; ``receipts`` is already a tuple of canonical receipt
    bytes."""
    placeholder = SpanBundleReceiptBatch(1, start, receipts, end, ZERO)
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_signature(key, placeholder),
    )


def resign_receipt(receipt, key=KEY):
    return dataclasses.replace(
        receipt,
        signature=_span_bundle_receipt_signature(key, receipt),
    )


class SpanBundleReceiptBatchFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(SpanBundleReceiptBatch)
            ],
            ["version", "start", "receipts", "end", "signature"],
        )
        self.assertNotIn("key", BATCH_FULL.__dict__)
        self.assertNotIn("mac", BATCH_FULL.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        batch = SpanBundleReceiptBatch(
            1,
            BATCH_1.start,
            BATCH_1.receipts,
            BATCH_1.end,
            BATCH_1.signature,
        )
        self.assertEqual(batch, BATCH_1)
        self.assertEqual(hash(batch), hash(BATCH_1))
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, b"")
        self.assertEqual(batch.end, PFRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BATCH_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BATCH_1, start=b"")

    def test_receipts_contract(self):
        for bad in (1, "x", None, [RECEIPT_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, receipts=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_1, receipts=())
        for bad in (1, "x", None, bytearray(RECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, receipts=(bad,))
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, receipts=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty span bundle receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, signature=bad)


class SpanBundleReceiptBatchEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = BATCH_FULL.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], b"".hex())
        self.assertEqual(
            outer[2],
            [RECEIPT_1.to_bytes().hex(), RECEIPT_2.to_bytes().hex()],
        )
        self.assertEqual(outer[3], PFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], BATCH_FULL.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for batch in (BATCH_1, BATCH_2, BATCH_FULL):
            raw = batch.to_bytes()
            parsed = SpanBundleReceiptBatch.from_bytes(raw)
            self.assertEqual(parsed, batch)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signatures(self):
        # A structurally valid batch with an all-zero signature parses;
        # signatures are checked only by audit_span_bundle_receipt_batch.
        unsigned = dataclasses.replace(BATCH_1, signature=ZERO)
        parsed = SpanBundleReceiptBatch.from_bytes(unsigned.to_bytes())
        self.assertEqual(parsed, unsigned)
        # A carried receipt with an all-zero signature still parses.
        unsigned_receipts = (
            dataclasses.replace(RECEIPT_1, signature=ZERO).to_bytes(),
        )
        unsigned_batch = dataclasses.replace(
            BATCH_1, receipts=unsigned_receipts
        )
        parsed = SpanBundleReceiptBatch.from_bytes(
            unsigned_batch.to_bytes()
        )
        self.assertEqual(parsed, unsigned_batch)

    def test_non_canonical_spelling_rejected(self):
        raw = BATCH_1.to_bytes()
        for bad in (
            b"",
            b"junk",
            b"[1,2,3]",
            raw + b" ",
            raw.replace(b",", b", ", 1),
            b" " + raw,
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatch.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatch.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [BATCH_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatch.from_bytes(bad)

    def test_batch_carries_only_receipts(self):
        # The encoding embeds the receipt bodies but no journey bundle.
        raw = BATCH_FULL.to_bytes()
        # The SpanReceiptBundle bytes do not appear in the batch.
        self.assertNotIn(BUNDLE_FULL.to_bytes(), raw)


class SpanBundleReceiptBatchSignatureTest(unittest.TestCase):
    def test_signature_is_npbj38_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX
            + _span_bundle_receipt_batch_content_bytes(BATCH_FULL),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BATCH_FULL.signature, expected)
        self.assertEqual(len(BATCH_FULL.signature), 32)
        joined = json.dumps(
            [
                BATCH_FULL.version,
                BATCH_FULL.start.hex(),
                [receipt.hex() for receipt in BATCH_FULL.receipts],
                BATCH_FULL.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(
                KEY,
                _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX + joined,
                hashlib.sha256,
            ).digest(),
            BATCH_FULL.signature,
        )

    def test_new_domain_label_distinct_from_frontier(self):
        # A signature under the NPBJ37 frontier label is not the batch
        # signature.
        wrong = hmac.new(
            KEY,
            b"NPBJ37"
            + _span_bundle_receipt_batch_content_bytes(BATCH_FULL),
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(wrong, BATCH_FULL.signature)


class SealSpanBundleReceiptBatchTest(unittest.TestCase):
    def test_seals_full_segment_and_advances_to_end(self):
        self.assertEqual(BATCH_FULL.start, b"")
        self.assertEqual(
            BATCH_FULL.receipts,
            (RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()),
        )
        self.assertEqual(BATCH_FULL.end, PFRONTIER_2.to_bytes())
        self.assertEqual(
            BATCH_FULL.signature,
            _span_bundle_receipt_batch_signature(KEY, BATCH_FULL),
        )

    def test_seals_from_checkpoint(self):
        self.assertEqual(BATCH_2.start, PFRONTIER_1.to_bytes())
        self.assertEqual(BATCH_2.receipts, (RECEIPT_2.to_bytes(),))
        self.assertEqual(BATCH_2.end, PFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            seal_span_bundle_receipt_batch(
                [RECEIPT_1.to_bytes()], KEY
            ),
            BATCH_1,
        )
        self.assertEqual(
            seal_span_bundle_receipt_batch(
                [RECEIPT_2.to_bytes()],
                KEY,
                start=PFRONTIER_1.to_bytes(),
            ),
            BATCH_2,
        )

    def test_start_is_keyword_only(self):
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1], KEY, PFRONTIER_1
            )

    def test_seal_touches_no_ledger_state(self):
        # Sealing needs no SpanBundleReceiptAuditor state and re-sealing
        # the first segment works regardless of any unrelated ledger.
        self.assertEqual(
            seal_span_bundle_receipt_batch([RECEIPT_1], KEY), BATCH_1
        )

    def test_empty_sequence_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([], KEY)

    def test_non_iterable_is_type_error(self):
        for bad in (42, RECEIPT_1, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch(bad, KEY)

    def test_broken_chain_rejected(self):
        # RECEIPT_2 starts at RFRONTIER_1; it cannot lead an empty chain.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([RECEIPT_2], KEY)
        # Reordering breaks the second link.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_2, RECEIPT_1], KEY
            )
        # Repeating the same receipt cannot extend the frontier twice.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1, RECEIPT_1], KEY
            )

    def test_wrong_start_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_2], KEY, start=PFRONTIER_2
            )

    def test_bad_receipt_signature_rejected(self):
        forged = dataclasses.replace(RECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([forged], KEY)

    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1], OTHER_KEY
            )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([RECEIPT_1], b"")

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch([RECEIPT_1], bad)

    def test_wrong_receipt_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch([bad], KEY)

    def test_non_canonical_receipt_bytes_are_value_error(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1.to_bytes() + b" "], KEY
            )

    def test_matches_single_receipt_advances(self):
        via_batch = audit_span_bundle_receipt_batch(BATCH_FULL, KEY)
        ledger = SpanBundleReceiptAuditor(KEY)
        ledger.audit(RECEIPT_1, BUNDLE_1)
        ledger.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch, ledger.checkpoint)


class AuditSpanBundleReceiptBatchSuccessTest(unittest.TestCase):
    def test_returns_final_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_FULL, KEY),
            PFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_1, KEY),
            PFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_2, KEY),
            PFRONTIER_2,
        )

    def test_accepts_object_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_FULL.to_bytes(), KEY),
            PFRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        advanced = SpanBundleReceiptAuditor(KEY)
        advanced.audit_batch(BATCH_FULL)
        # Re-verifying the first batch works independently of any local
        # ledger state.
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_1, KEY), PFRONTIER_1
        )
        self.assertEqual(advanced.checkpoint, PFRONTIER_2)

    def test_round_trip_then_verify(self):
        transported = SpanBundleReceiptBatch.from_bytes(
            BATCH_FULL.to_bytes()
        )
        self.assertEqual(transported, BATCH_FULL)
        self.assertEqual(
            audit_span_bundle_receipt_batch(transported, KEY),
            PFRONTIER_2,
        )


class AuditSpanBundleReceiptBatchViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(BATCH_FULL, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(BATCH_FULL, b"")

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch(BATCH_FULL, bad)

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [BATCH_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch(bad, KEY)

    def test_non_canonical_bytes_are_value_error(self):
        for bad in (
            BATCH_FULL.to_bytes() + b" ",
            b"junk",
            BATCH_FULL.to_bytes() + b"\n",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch(bad, KEY)

    def test_tampered_batch_signature_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(
                dataclasses.replace(BATCH_FULL, signature=ZERO), KEY
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            b"NPBJ37"
            + _span_bundle_receipt_batch_content_bytes(BATCH_FULL),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(
                dataclasses.replace(BATCH_FULL, signature=wrong), KEY
            )

    def test_tampered_carried_receipt_rejected(self):
        # A carried receipt with a zeroed signature fails even when the
        # outer batch signature is honestly recomputed over the changed
        # body.
        forged_receipts = (
            RECEIPT_1.to_bytes(),
            dataclasses.replace(RECEIPT_2, signature=ZERO).to_bytes(),
        )
        forged = batch_for(b"", forged_receipts, PFRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(forged, KEY)

    def test_replayed_or_reordered_body_rejected(self):
        # Re-signing a batch whose receipts do not replay to ``end``
        # fails the final-frontier comparison.
        duplicate = (RECEIPT_1.to_bytes(), RECEIPT_1.to_bytes())
        bad = batch_for(b"", duplicate, PFRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_forged_endpoint_rejected(self):
        # Honest outer signature, but a different ``end`` than the
        # replayed chain reaches.
        forged = dataclasses.replace(
            BATCH_2, end=PFRONTIER_1.to_bytes()
        )
        forged = dataclasses.replace(
            forged,
            signature=_span_bundle_receipt_batch_signature(KEY, forged),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(forged, KEY)

    def test_start_frontier_signature_must_verify(self):
        # A batch whose start frontier carries a bad NPBJ37 signature is
        # rejected at the envelope before replay.
        bad_start_frontier = dataclasses.replace(
            PFRONTIER_1, signature=ZERO
        )
        bad = dataclasses.replace(
            BATCH_2, start=bad_start_frontier.to_bytes()
        )
        bad = dataclasses.replace(
            bad,
            signature=_span_bundle_receipt_batch_signature(KEY, bad),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)


class AuditorAuditBatchSuccessTest(unittest.TestCase):
    def test_books_segment_and_returns_self(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_batch(BATCH_FULL), auditor)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_FULL.to_bytes())
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_chained_batches_and_restart(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)
        restored = SpanBundleReceiptAuditor(
            KEY, checkpoint=PFRONTIER_1.to_bytes()
        )
        restored.audit_batch(BATCH_2)
        self.assertEqual(restored.checkpoint, PFRONTIER_2)

    def test_single_and_batch_share_ledger(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_checkpoint_matches_single_receipt_ledger(self):
        via_batch = SpanBundleReceiptAuditor(KEY)
        via_batch.audit_batch(BATCH_FULL)
        via_singles = SpanBundleReceiptAuditor(KEY)
        via_singles.audit(RECEIPT_1, BUNDLE_1)
        via_singles.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch.checkpoint, via_singles.checkpoint)


class AuditorAuditBatchFailureTest(unittest.TestCase):
    def test_same_batch_replay_rejected_without_rollback(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1)
        self.assertIs(auditor.checkpoint, before)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_empty_ledger_rejects_non_empty_start(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_old_fork_rejected(self):
        # RECEIPT_FULL is a competing first receipt (empty straight to
        # RFRONTIER_2); a batch over it cannot extend a ledger already at
        # PFRONTIER_1.
        fork = seal_span_bundle_receipt_batch([RECEIPT_FULL], KEY)
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(fork)
        self.assertIs(auditor.checkpoint, before)

    def test_broken_link_rejected(self):
        # A batch from the empty ledger presented to a ledger already at
        # PFRONTIER_1 fails the start linkage.
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(OTHER_KEY).audit_batch(BATCH_FULL)

    def test_failed_audit_leaves_checkpoint_and_stays_usable(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_batch(42)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_batch(BATCH_FULL)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_failed_continuation_keeps_checkpoint(self):
        # An honestly outer-signed batch whose declared end does not
        # match the replayed chain fails after replay; the live
        # checkpoint is untouched.
        bad_end = dataclasses.replace(
            BATCH_2, end=PFRONTIER_1.to_bytes()
        )
        bad_end = dataclasses.replace(
            bad_end,
            signature=_span_bundle_receipt_batch_signature(KEY, bad_end),
        )
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad_end)
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_kind_is_type_error(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)


class AuditorAuditBatchOverflowTest(unittest.TestCase):
    def test_overflow_rejected_without_state_change(self):
        # A span-bundle-receipt frontier pinned at u64 max cannot accept
        # one more receipt through a batch.
        max_range = range_frontier_for(
            U64_MAX,
            CFRONTIER_1.to_bytes(),
            RDIGEST_1,
        )
        placeholder = SpanBundleReceiptFrontier(
            1, U64_MAX, max_range.to_bytes(), ZERO, ZERO
        )
        maxed = dataclasses.replace(
            placeholder,
            signature=_span_bundle_receipt_frontier_signature(
                KEY, placeholder
            ),
        )
        continuation = dataclasses.replace(
            RECEIPT_1, start=maxed.end
        )
        continuation = resign_receipt(continuation)
        # The declared end never gets compared: the first replay step
        # overflows the u64 sequence first.
        overflow = batch_for(
            maxed.to_bytes(),
            (continuation.to_bytes(),),
            maxed.to_bytes(),
        )
        auditor = SpanBundleReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(overflow)
        self.assertIs(auditor.checkpoint, before)


class AuditorAuditBatchLinearizationTest(unittest.TestCase):
    def test_single_and_batch_compete_on_one_lock(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(3)

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
                    lambda: auditor.audit_batch(BATCH_FULL),
                    "full",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(BATCH_1), "one"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_1, BUNDLE_1),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        # The frontier never went backwards: a BATCH_2 continuation
        # links cleanly from whichever single step won.
        if successes[0] != "full":
            auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_two_competing_full_batches_one_wins(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                auditor.audit_batch(BATCH_FULL)
                outcomes.append("ok")
            except ValueError:
                outcomes.append("replay")

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ok", "replay"])
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
