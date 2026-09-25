import dataclasses
import hashlib
import hmac
import inspect
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
    audit_span_bundle_receipt_batch,
    seal_span_bundle_receipt_batch,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
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
    BDIGEST_1,
    BDIGEST_2,
    PFRONTIER_1,
    PFRONTIER_2,
    PFRONTIER_FULL,
    bundle_receipt_frontier_for,
)

BATCH_1 = seal_span_bundle_receipt_batch([RECEIPT_1], KEY)
BATCH_2 = seal_span_bundle_receipt_batch(
    [RECEIPT_2], KEY, start=PFRONTIER_1
)
BATCH_CHAIN = seal_span_bundle_receipt_batch([RECEIPT_1, RECEIPT_2], KEY)
BATCH_FULL = seal_span_bundle_receipt_batch([RECEIPT_FULL], KEY)


def batch_for(receipts, end, start=b"", key=KEY):
    """A batch over the canonical ``receipts`` bytes with the declared
    ``start``/``end`` and the NPBJ38 signature recomputed over the first
    four fields — honest or not, the batch itself is always signed."""
    placeholder = SpanBundleReceiptBatch(
        1, start, tuple(receipts), end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_signature(key, placeholder),
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
        self.assertNotIn("key", BATCH_CHAIN.__dict__)
        self.assertNotIn("mac", BATCH_CHAIN.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        batch = SpanBundleReceiptBatch(
            1,
            b"",
            (RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()),
            PFRONTIER_2.to_bytes(),
            BATCH_CHAIN.signature,
        )
        self.assertEqual(batch, BATCH_CHAIN)
        self.assertEqual(hash(batch), hash(BATCH_CHAIN))
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, b"")
        self.assertEqual(
            batch.receipts,
            (RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()),
        )
        self.assertEqual(batch.end, PFRONTIER_2.to_bytes())

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
        # Malformed bytes and the wrong frontier layer are value errors.
        for bad in (b"junk", b"[1,2,3]", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BATCH_1, start=b"")

    def test_receipts_contract(self):
        for bad in (1, "1", None, [RECEIPT_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, receipts=bad)
        # An empty tuple is a value error: the chain is non-empty.
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_1, receipts=())
        for bad in (1, "1", None, bytearray(RECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, receipts=(bad,))
        for bad in (b"", b"junk", b"[1,2,3]", BUNDLE_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, receipts=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, end=bad)
        # Empty, malformed and wrong-layer frontier bytes are value
        # errors: the end is a non-empty receipt ledger frontier.
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
        raw = BATCH_CHAIN.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], "")
        self.assertEqual(
            outer[2],
            [RECEIPT_1.to_bytes().hex(), RECEIPT_2.to_bytes().hex()],
        )
        self.assertEqual(outer[3], PFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], BATCH_CHAIN.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for batch in (BATCH_1, BATCH_2, BATCH_CHAIN, BATCH_FULL):
            raw = batch.to_bytes()
            parsed = SpanBundleReceiptBatch.from_bytes(raw)
            self.assertEqual(parsed, batch)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signature(self):
        # A structurally valid batch with an all-zero signature parses;
        # signatures are checked only by the audit entry points.
        unsigned = dataclasses.replace(BATCH_1, signature=ZERO)
        parsed = SpanBundleReceiptBatch.from_bytes(unsigned.to_bytes())
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = BATCH_1.to_bytes()
        variants = (
            b"",
            b"junk",
            b"[1,2,3]",
            raw + b" ",
            raw.replace(b",", b", ", 1),
            b" " + raw,
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatch.from_bytes(bad)
        upper = raw.replace(
            BATCH_1.signature.hex().encode(),
            BATCH_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatch.from_bytes(upper)

    def test_wrong_json_shape_rejected(self):
        cases = (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
            b'["1","",[],"",""]',
            b'[1,"",[],"' + PFRONTIER_1.to_bytes().hex().encode()
            + b'","' + ZERO.hex().encode() + b'"]',
        )
        for bad in cases:
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatch.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [BATCH_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatch.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            [RECEIPT_1.to_bytes().hex()],
            PFRONTIER_1.to_bytes().hex(),
            BATCH_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, 1), (2, ""), (3, 1), (4, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanBundleReceiptBatch.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_signature_is_npbj38_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX
            + _span_bundle_receipt_batch_content_bytes(BATCH_CHAIN),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BATCH_CHAIN.signature, expected)
        self.assertEqual(len(BATCH_CHAIN.signature), 32)
        # The prefix and the compact encoding are concatenated directly,
        # with no delimiter or length prefix between them.
        joined = json.dumps(
            [
                BATCH_CHAIN.version,
                BATCH_CHAIN.start.hex(),
                [receipt.hex() for receipt in BATCH_CHAIN.receipts],
                BATCH_CHAIN.end.hex(),
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
            BATCH_CHAIN.signature,
        )


class SealSpanBundleReceiptBatchTest(unittest.TestCase):
    def test_seals_chain_from_empty_ledger(self):
        batch = seal_span_bundle_receipt_batch(
            [RECEIPT_1, RECEIPT_2], KEY
        )
        self.assertEqual(batch, BATCH_CHAIN)
        self.assertEqual(batch.start, b"")
        self.assertEqual(
            batch.receipts,
            (RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()),
        )
        self.assertEqual(batch.end, PFRONTIER_2.to_bytes())

    def test_seals_single_receipt(self):
        batch = seal_span_bundle_receipt_batch([RECEIPT_1], KEY)
        self.assertEqual(batch.start, b"")
        self.assertEqual(batch.end, PFRONTIER_1.to_bytes())

    def test_seals_from_keyword_only_start(self):
        batch = seal_span_bundle_receipt_batch(
            [RECEIPT_2], KEY, start=PFRONTIER_1
        )
        self.assertEqual(batch, BATCH_2)
        self.assertEqual(batch.start, PFRONTIER_1.to_bytes())
        self.assertEqual(batch.end, PFRONTIER_2.to_bytes())
        # Canonical frontier bytes are accepted too.
        self.assertEqual(
            seal_span_bundle_receipt_batch(
                [RECEIPT_2], KEY, start=PFRONTIER_1.to_bytes()
            ),
            BATCH_2,
        )

    def test_start_is_keyword_only(self):
        signature = inspect.signature(seal_span_bundle_receipt_batch)
        self.assertEqual(
            list(signature.parameters), ["receipts", "key", "start"]
        )
        self.assertEqual(
            signature.parameters["start"].kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_2], KEY, PFRONTIER_1
            )

    def test_accepts_canonical_receipt_bytes(self):
        batch = seal_span_bundle_receipt_batch(
            [RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()], KEY
        )
        self.assertEqual(batch, BATCH_CHAIN)

    def test_sealing_touches_no_auditor_state(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        seal_span_bundle_receipt_batch([RECEIPT_1, RECEIPT_2], KEY)
        self.assertIsNone(auditor.checkpoint)

    def test_empty_sequence_rejected(self):
        for empty in ((), [], iter(())):
            with self.assertRaises(ValueError, msg=repr(empty)):
                seal_span_bundle_receipt_batch(empty, KEY)

    def test_key_contract(self):
        for bad in (1, "k", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch([RECEIPT_1], bad)
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([RECEIPT_1], b"")

    def test_non_iterable_receipts_is_type_error(self):
        for bad in (1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch(bad, KEY)

    def test_wrong_receipt_kind_is_type_error(self):
        for bad in (1, "x", None, object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch([bad], KEY)

    def test_wrong_start_kind_is_type_error(self):
        for bad in (1, "x", [PFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch(
                    [RECEIPT_2], KEY, start=bad
                )

    def test_broken_chain_rejected(self):
        # RECEIPT_2 starts at RFRONTIER_1 and cannot open a batch from
        # the empty ledger.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([RECEIPT_2], KEY)
        # Two receipts that do not link.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1, RECEIPT_1], KEY
            )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1, RECEIPT_2], KEY, start=PFRONTIER_1
            )

    def test_unsigned_or_forged_receipt_rejected(self):
        forged = dataclasses.replace(RECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([forged], KEY)
        wrong_key_receipt = dataclasses.replace(
            RECEIPT_1,
            signature=hmac.new(
                OTHER_KEY,
                _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX
                + RECEIPT_1.to_bytes(),
                hashlib.sha256,
            ).digest(),
        )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([wrong_key_receipt], KEY)

    def test_malformed_receipt_bytes_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch([b"junk"], KEY)
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_1.to_bytes() + b" "], KEY
            )

    def test_start_frontier_signature_verified(self):
        tampered = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_2], KEY, start=tampered
            )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_2], OTHER_KEY, start=PFRONTIER_1
            )

    def test_sequence_overflow_rejected(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, RFRONTIER_1.to_bytes(), BDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch(
                [RECEIPT_2], KEY, start=maxed
            )


class AuditSpanBundleReceiptBatchTest(unittest.TestCase):
    def test_returns_final_frontier(self):
        final = audit_span_bundle_receipt_batch(BATCH_CHAIN, KEY)
        self.assertEqual(final, PFRONTIER_2)
        self.assertEqual(
            final.signature,
            _span_bundle_receipt_frontier_signature(KEY, final),
        )
        self.assertIsInstance(final, SpanBundleReceiptFrontier)

    def test_accepts_object_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_1, KEY), PFRONTIER_1
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_1.to_bytes(), KEY),
            PFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_2, KEY), PFRONTIER_2
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_FULL, KEY),
            PFRONTIER_FULL,
        )

    def test_round_trip_then_verify(self):
        transported = SpanBundleReceiptBatch.from_bytes(
            BATCH_CHAIN.to_bytes()
        )
        self.assertEqual(transported, BATCH_CHAIN)
        self.assertEqual(
            audit_span_bundle_receipt_batch(transported, KEY),
            PFRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        # Auditing a batch from the empty ledger consults no ledger
        # state and mutates nothing.
        self.assertEqual(
            audit_span_bundle_receipt_batch(BATCH_CHAIN, KEY),
            PFRONTIER_2,
        )
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_key_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(BATCH_CHAIN, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(BATCH_CHAIN, b"")

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch(BATCH_CHAIN, bad)

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [BATCH_CHAIN], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch(bad, KEY)

    def test_non_canonical_bytes_are_value_errors(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(
                BATCH_CHAIN.to_bytes() + b" ", KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(b"junk", KEY)

    def test_tampered_batch_signature_rejected(self):
        bad = dataclasses.replace(BATCH_CHAIN, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_signature_must_use_npbj38_domain(self):
        wrong_domain = hmac.new(
            KEY,
            b"NPBJ37"
            + _span_bundle_receipt_batch_content_bytes(BATCH_CHAIN),
            hashlib.sha256,
        ).digest()
        bad = dataclasses.replace(BATCH_CHAIN, signature=wrong_domain)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_tampered_endpoint_frontier_rejected(self):
        # Re-sign the batch over an endpoint frontier whose own NPBJ37
        # layer no longer verifies.
        bad_end = dataclasses.replace(PFRONTIER_2, signature=ZERO)
        bad = batch_for(
            [RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()],
            end=bad_end.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)
        bad_start = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        bad = batch_for(
            [RECEIPT_2.to_bytes()],
            start=bad_start.to_bytes(),
            end=PFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_tampered_carried_receipt_rejected(self):
        forged = dataclasses.replace(RECEIPT_1, signature=ZERO)
        bad = batch_for(
            [forged.to_bytes(), RECEIPT_2.to_bytes()],
            end=PFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_broken_carried_chain_rejected(self):
        # The first carried receipt does not link to the empty start.
        bad = batch_for(
            [RECEIPT_2.to_bytes()], end=PFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)
        # A mid-chain break: the second receipt does not continue the
        # first.
        bad = batch_for(
            [RECEIPT_1.to_bytes(), RECEIPT_1.to_bytes()],
            end=PFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_end_mismatch_rejected(self):
        # An honestly signed batch whose declared end is not the
        # replayed frontier.
        bad = batch_for(
            [RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()],
            end=PFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)
        bad = batch_for(
            [RECEIPT_1.to_bytes()], end=PFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch(bad, KEY)

    def test_carries_receipts_only_no_bundle(self):
        # The batch binds the receipt bodies only: the committed bundles
        # are not carried and not needed to audit the batch.
        self.assertEqual(
            BATCH_CHAIN.receipts,
            (RECEIPT_1.to_bytes(), RECEIPT_2.to_bytes()),
        )
        self.assertNotIn(
            BUNDLE_1.to_bytes().hex(), BATCH_CHAIN.to_bytes().decode()
        )


class SpanBundleReceiptAuditorAuditBatchTest(unittest.TestCase):
    def test_audit_batch_returns_self_and_advances(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_batch(BATCH_CHAIN), auditor)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_audit_batch_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1.to_bytes())
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)

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

    def test_matches_single_receipt_entry_point(self):
        via_batch = SpanBundleReceiptAuditor(KEY)
        via_batch.audit_batch(BATCH_CHAIN)
        via_singles = SpanBundleReceiptAuditor(KEY)
        via_singles.audit(RECEIPT_1, BUNDLE_1)
        via_singles.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch.checkpoint, via_singles.checkpoint)

    def test_mixed_single_and_batch_entries(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_empty_ledger_accepts_only_empty_start(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_same_batch_replayed_rejected_without_state_change(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_CHAIN)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_CHAIN)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_CHAIN.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_old_fork_rejected(self):
        # Commit the whole-chain batch straight to PFRONTIER_FULL; the
        # genesis batch and the continuation batch are then both old
        # forks whose start does not match the checkpoint.
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIs(auditor.checkpoint, before)

    def test_broken_chain_rejected_without_state_change(self):
        bad = batch_for(
            [RECEIPT_1.to_bytes(), RECEIPT_1.to_bytes()],
            end=PFRONTIER_2.to_bytes(),
        )
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_batch_signature_rejected(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                dataclasses.replace(BATCH_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_carried_receipt_rejected(self):
        forged = dataclasses.replace(RECEIPT_1, signature=ZERO)
        bad = batch_for(
            [forged.to_bytes()], end=PFRONTIER_1.to_bytes()
        )
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_end_mismatch_rejected_without_state_change(self):
        bad = batch_for(
            [RECEIPT_1.to_bytes()], end=PFRONTIER_2.to_bytes()
        )
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = SpanBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_1], (BATCH_1,), object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_batch(bad)
        blob = BATCH_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit_batch(blob.replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_sequence_overflow_rejected_without_state_change(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, RFRONTIER_1.to_bytes(), BDIGEST_1
        )
        end = bundle_receipt_frontier_for(
            U64_MAX, RFRONTIER_2.to_bytes(), BDIGEST_2
        )
        bad = batch_for(
            [RECEIPT_2.to_bytes()],
            start=maxed.to_bytes(),
            end=end.to_bytes(),
        )
        auditor = SpanBundleReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad)
        self.assertIs(auditor.checkpoint, before)

    def test_failed_batch_leaves_auditor_usable(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_batch(42)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_batch(BATCH_CHAIN)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_audit_and_audit_batch_compete_on_one_lock(self):
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
                args=(lambda: auditor.audit_batch(BATCH_CHAIN), "batch"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_FULL, BUNDLE_FULL),
                    "single",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(BATCH_FULL), "full"),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(
            auditor.checkpoint.end, RFRONTIER_2.to_bytes()
        )

    def test_two_competing_batches_one_wins(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                auditor.audit_batch(BATCH_CHAIN)
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
