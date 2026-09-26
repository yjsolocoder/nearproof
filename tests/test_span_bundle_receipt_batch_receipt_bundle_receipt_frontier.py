import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptBatchReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundleReceiptFrontier,
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_content_bytes,
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_next_digest,
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_signature,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_span_bundle_receipt_batch_receipt_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_12,
    BUNDLE_FULL,
)
from test_span_bundle_receipt_batch_receipt_bundle_receipt import (
    BRECEIPT_1,
    BRECEIPT_2,
    BRECEIPT_12,
    BRECEIPT_FULL,
)
from test_span_bundle_receipt_batch_receipt_frontier import (
    DIGEST_1,
    FRONTIER_1,
    FRONTIER_2,
    FRONTIER_FULL,
    commit_frontier_for,
)
from test_span_bundle_receipt_frontier import PFRONTIER_1


def bundle_receipt_ledger_frontier_for(sequence, end, digest, key=KEY):
    """An NPBJ43-signed bundle-receipt ledger frontier over the given
    fields."""
    placeholder = SpanBundleReceiptBatchReceiptBundleReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_bundle_receipt_frontier_signature(
            key, placeholder
        ),
    )


# One bundle receipt starting empty and ending at FRONTIER_1.
QDIGEST_1 = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_next_digest(
        ZERO, 1, BRECEIPT_1.to_bytes()
    )
)
# Continuation receipt from FRONTIER_1 to FRONTIER_2.
QDIGEST_2 = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_next_digest(
        QDIGEST_1, 2, BRECEIPT_2.to_bytes()
    )
)
# The two-commit segment in one bundle receipt: a fork competing with
# BRECEIPT_1 for the first sequence slot.
QDIGEST_12 = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_next_digest(
        ZERO, 1, BRECEIPT_12.to_bytes()
    )
)
# A single receipt straight to FRONTIER_FULL: another first-slot fork.
QDIGEST_FULL = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_next_digest(
        ZERO, 1, BRECEIPT_FULL.to_bytes()
    )
)
QFRONTIER_1 = bundle_receipt_ledger_frontier_for(
    1, FRONTIER_1.to_bytes(), QDIGEST_1
)
QFRONTIER_2 = bundle_receipt_ledger_frontier_for(
    2, FRONTIER_2.to_bytes(), QDIGEST_2
)
QFRONTIER_12 = bundle_receipt_ledger_frontier_for(
    1, FRONTIER_2.to_bytes(), QDIGEST_12
)
QFRONTIER_FULL = bundle_receipt_ledger_frontier_for(
    1, FRONTIER_FULL.to_bytes(), QDIGEST_FULL
)


class BundleReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptBundleReceiptFrontier
                )
            ],
            ["version", "sequence", "end", "digest", "signature"],
        )
        self.assertNotIn("key", QFRONTIER_1.__dict__)
        self.assertNotIn("mac", QFRONTIER_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = SpanBundleReceiptBatchReceiptBundleReceiptFrontier(
            1,
            1,
            FRONTIER_1.to_bytes(),
            QDIGEST_1,
            QFRONTIER_1.signature,
        )
        self.assertEqual(frontier, QFRONTIER_1)
        self.assertEqual(hash(frontier), hash(QFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, FRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, QDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            QFRONTIER_1.signature = ZERO

    def test_no_alias_attributes(self):
        self.assertEqual(
            sorted(field.name for field in dataclasses.fields(QFRONTIER_1)),
            ["digest", "end", "sequence", "signature", "version"],
        )

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(QFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(QFRONTIER_1, sequence=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QFRONTIER_1, end=bad)
        # Empty, malformed and wrong-layer frontier bytes are value
        # errors: the end is a non-empty batch-receipt ledger frontier.
        for bad in (
            b"",
            b"junk",
            b"[1,2,3]",
            PFRONTIER_1.to_bytes(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(QFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "1", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(QFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(QFRONTIER_1, **{name: bad})


class BundleReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + FRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + QDIGEST_1.hex().encode() + b'",'
            b'"' + QFRONTIER_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(QFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (QFRONTIER_1, QFRONTIER_2, QFRONTIER_FULL):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                    blob
                ),
                frontier,
            )
            self.assertEqual(
                SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                    blob
                ).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = QFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                    bad
                )

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                    bad
                )

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            FRONTIER_1.to_bytes().hex(),
            QDIGEST_1.hex(),
            QFRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = QFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            QFRONTIER_1.signature.hex().encode(),
            QFRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                upper
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            1,
            FRONTIER_1.to_bytes().hex(),
            QDIGEST_1.hex(),
            QFRONTIER_1.signature.hex(),
        ]
        for index, bad_value in (
            (2, ""),
            (2, "junk"),
            (3, "00"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the frontier signature nor the nested endpoint
        # signatures are checked at parse time.
        tampered = dataclasses.replace(QFRONTIER_1, signature=ZERO)
        parsed = (
            SpanBundleReceiptBatchReceiptBundleReceiptFrontier.from_bytes(
                tampered.to_bytes()
            )
        )
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_signature_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ44"
            + ZERO
            + (1).to_bytes(8, "big")
            + BRECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(QDIGEST_1, expected_digest)
        expected_signature = hmac.new(
            KEY,
            b"NPBJ43"
            + _span_bundle_receipt_batch_receipt_bundle_receipt_frontier_content_bytes(
                QFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(QFRONTIER_1.signature, expected_signature)


class BundleReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(b"")

    def test_empty_checkpoint_is_empty_ledger(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            QFRONTIER_1,
            QFRONTIER_1.to_bytes(),
        ):
            auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [QFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(QFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_endpoint_frontier_signature_verified(self):
        # The nested batch-receipt ledger frontier's own NPBJ40 layer is
        # recomputed on load; re-sign the outer layer so only it fails.
        bad_end = dataclasses.replace(FRONTIER_1, signature=ZERO)
        tampered = bundle_receipt_ledger_frontier_for(
            1, bad_end.to_bytes(), QDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_deep_nested_signature_verified(self):
        # A failure one more layer down is rejected just the same: the
        # endpoint check replays every signature layer of the
        # batch-receipt ledger frontier, including the NPBJ37 signature
        # of the receipt ledger frontier nested in its end.
        bad_ledger_end = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        bad_end = commit_frontier_for(
            1, bad_ledger_end.to_bytes(), DIGEST_1
        )
        tampered = bundle_receipt_ledger_frontier_for(
            1, bad_end.to_bytes(), QDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                OTHER_KEY, checkpoint=QFRONTIER_1
            )

    def test_checkpoint_is_read_only_and_has_no_state_alias(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
            KEY, checkpoint=QFRONTIER_1
        )
        with self.assertRaises(AttributeError):
            auditor.checkpoint = QFRONTIER_1
        # The ledger exports through checkpoint only; no state alias is
        # provided.
        self.assertFalse(hasattr(auditor, "state"))


class BundleReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit(BRECEIPT_1, BUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, FRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, QDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        auditor.audit(BRECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, FRONTIER_2.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, QDIGEST_2)

    def test_full_segment_commits_in_one_audit(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_12, BUNDLE_12)
        self.assertEqual(auditor.checkpoint, QFRONTIER_12)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, FRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        auditor.audit(BRECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)

    def test_restart_from_checkpoint_continues_with_next_receipt(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(BRECEIPT_2, BUNDLE_2)
            self.assertEqual(restored.checkpoint, QFRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        # A receipt continuing from FRONTIER_1 cannot be the first
        # receipt of a fresh ledger.
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_last_receipt_rejected(self):
        # Same sequence, same digest: a straight replay is rejected.
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)

    def test_low_sequence_and_old_fork_rejected(self):
        # Commit the two-commit segment straight to FRONTIER_2; the
        # genesis receipt and the continuation receipt are then both old
        # receipts whose start does not link to the current end.
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_12, BUNDLE_12)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_different_digest_fork_rejected(self):
        # From the empty ledger BRECEIPT_1, BRECEIPT_12 and
        # BRECEIPT_FULL all occupy sequence slot one with an empty
        # start; once one is accepted the same-sequence forks' empty
        # starts no longer link.
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_12, BUNDLE_12)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_FULL, BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_receipt_bundle_mismatch_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, BUNDLE_12)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, BUNDLE_2)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_12, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_receipt_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(BRECEIPT_1, signature=ZERO), BUNDLE_1
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_bundle_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                BRECEIPT_1, dataclasses.replace(BUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
            OTHER_KEY
        )
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        for bad in (
            1,
            "x",
            None,
            [BRECEIPT_1],
            (BRECEIPT_1,),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(BRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(BRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        blob = BRECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(blob.replace(b",", b", "), BUNDLE_1)
        bundle_blob = BUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, bundle_blob.replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_ledger_frontier_for(
            U64_MAX, FRONTIER_1.to_bytes(), QDIGEST_1
        )
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_receipts_linearize(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipts, failures = [], []

        def run(receipt, bundle):
            try:
                auditor.audit(receipt, bundle)
                receipts.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(target=run, args=(BRECEIPT_1, BUNDLE_1)),
            threading.Thread(target=run, args=(BRECEIPT_12, BUNDLE_12)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, receipts[0].end)

    def test_accepted_receipt_is_never_lost(self):
        # A failure arriving concurrently against an already advanced
        # ledger never rolls the frontier back.
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_12, BUNDLE_12)
        with self.assertRaises(ValueError):
            auditor.audit(BRECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)


class BundleReceiptAuditorParameterNamingTest(unittest.TestCase):
    def test_audit_params_named_receipt_and_bundle(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor.audit
        )
        self.assertEqual(
            list(signature.parameters), ["self", "receipt", "bundle"]
        )

    def test_audit_verifies_with_keyword_arguments(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit(receipt=BRECEIPT_1, bundle=BUNDLE_1), auditor
        )
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
