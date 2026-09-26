import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    RangeFrontier,
    SpanBundleReceiptBatch,
    SpanBundleReceiptBatchReceipt,
    SpanBundleReceiptBatchReceiptAuditor,
    SpanBundleReceiptBatchReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX,
    _span_bundle_receipt_batch_receipt_frontier_content_bytes,
    _span_bundle_receipt_batch_receipt_frontier_next_digest,
    _span_bundle_receipt_batch_receipt_frontier_signature,
    _span_bundle_receipt_batch_receipt_signature,
    _span_bundle_receipt_batch_signature,
    _span_bundle_receipt_frontier_signature,
    audit_span_bundle_receipt_batch_receipt,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_span_bundle_receipt import RECEIPT_1
from test_span_bundle_receipt_batch import (
    BATCH_1,
    BATCH_2,
    BATCH_FULL,
    batch_for,
)
from test_span_bundle_receipt_batch_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    CRECEIPT_FULL,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
    bundle_receipt_frontier_for,
)


def commit_frontier_for(sequence, end, digest, key=KEY):
    """An NPBJ40-signed batch-receipt frontier over the given fields."""
    placeholder = SpanBundleReceiptBatchReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=(
            _span_bundle_receipt_batch_receipt_frontier_signature(
                key, placeholder
            )
        ),
    )


# One committed batch receipt from the empty ledger to PFRONTIER_1.
DIGEST_1 = _span_bundle_receipt_batch_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_1.to_bytes()
)
# Continuation commit from PFRONTIER_1 to PFRONTIER_2.
DIGEST_2 = _span_bundle_receipt_batch_receipt_frontier_next_digest(
    DIGEST_1, 2, CRECEIPT_2.to_bytes()
)
# A competing first commit straight to PFRONTIER_2 (a fork).
DIGEST_FULL = _span_bundle_receipt_batch_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_FULL.to_bytes()
)
FRONTIER_1 = commit_frontier_for(
    1, PFRONTIER_1.to_bytes(), DIGEST_1
)
FRONTIER_2 = commit_frontier_for(
    2, PFRONTIER_2.to_bytes(), DIGEST_2
)
FRONTIER_FULL = commit_frontier_for(
    1, PFRONTIER_2.to_bytes(), DIGEST_FULL
)


class BatchReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptFrontier
                )
            ],
            ["version", "sequence", "end", "digest", "signature"],
        )
        self.assertNotIn("key", FRONTIER_1.__dict__)
        self.assertNotIn("mac", FRONTIER_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = SpanBundleReceiptBatchReceiptFrontier(
            1,
            1,
            CRECEIPT_1.end,
            DIGEST_1,
            FRONTIER_1.signature,
        )
        self.assertEqual(frontier, FRONTIER_1)
        self.assertEqual(hash(frontier), hash(FRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, PFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, DIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FRONTIER_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(FRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(FRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)
        # The end is a canonical non-empty receipt-ledger frontier:
        # empty, junk and a JSON array of the wrong shape are all value
        # errors.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "x", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(FRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(FRONTIER_1, **{name: bad})


class BatchReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + PFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + DIGEST_1.hex().encode() + b'",'
            b'"' + FRONTIER_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(FRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (FRONTIER_1, FRONTIER_2, FRONTIER_FULL):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            parsed = SpanBundleReceiptBatchReceiptFrontier.from_bytes(blob)
            self.assertEqual(parsed, frontier)
            self.assertEqual(parsed.to_bytes(), blob)

    def test_from_bytes_type_contract(self):
        blob = FRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            PFRONTIER_1.to_bytes().hex(),
            DIGEST_1.hex(),
            FRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = FRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            FRONTIER_1.signature.hex().encode(),
            FRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            1,
            PFRONTIER_1.to_bytes().hex(),
            DIGEST_1.hex(),
            FRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((2, ""), (2, "junk"), (3, "00"), (4, "00")):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the frontier signature nor the nested endpoint
        # signatures are checked at parse time.
        tampered = dataclasses.replace(FRONTIER_1, signature=ZERO)
        parsed = SpanBundleReceiptBatchReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)


class BatchReceiptFrontierSchemeTest(unittest.TestCase):
    def test_digest_chain_is_prefixed_by_nothing(self):
        # d0 is 32 zero bytes; the step is SHA256(d + u64be(n) + R),
        # every part concatenated directly with no domain tag,
        # delimiter or length prefix.
        expected = hashlib.sha256(
            ZERO + (1).to_bytes(8, "big") + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(DIGEST_1, expected)
        expected_two = hashlib.sha256(
            DIGEST_1 + (2).to_bytes(8, "big") + CRECEIPT_2.to_bytes()
        ).digest()
        self.assertEqual(DIGEST_2, expected_two)
        # No domain tag prefix: tagging the same concatenation changes
        # the digest.
        tagged = hashlib.sha256(
            b"NPBJ40"
            + ZERO
            + (1).to_bytes(8, "big")
            + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertNotEqual(tagged, DIGEST_1)
        # A replayed receipt at a different sequence hashes differently,
        # so the chain binds the sequence number.
        self.assertNotEqual(
            DIGEST_1,
            hashlib.sha256(
                ZERO + (2).to_bytes(8, "big") + CRECEIPT_1.to_bytes()
            ).digest(),
        )

    def test_signature_is_npbj40_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX
            + _span_bundle_receipt_batch_receipt_frontier_content_bytes(
                FRONTIER_2
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(FRONTIER_2.signature, expected)
        self.assertEqual(len(FRONTIER_2.signature), 32)
        joined = json.dumps(
            [
                FRONTIER_2.version,
                FRONTIER_2.sequence,
                FRONTIER_2.end.hex(),
                FRONTIER_2.digest.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(
                KEY, b"NPBJ40" + joined, hashlib.sha256
            ).digest(),
            FRONTIER_2.signature,
        )

    def test_new_domain_label_distinct_from_receipt_label(self):
        # An NPBJ39 signature over the frontier content is not the
        # frontier signature.
        wrong = hmac.new(
            KEY,
            b"NPBJ39"
            + _span_bundle_receipt_batch_receipt_frontier_content_bytes(
                FRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(wrong, FRONTIER_1.signature)


class BatchReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(b"")

    def test_empty_checkpoint_is_empty_ledger(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (FRONTIER_1, FRONTIER_1.to_bytes()):
            auditor = SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [FRONTIER_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_or_non_canonical_bytes(self):
        for bad in (
            b"junk",
            b"[1,2,3]",
            FRONTIER_1.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(FRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_endpoint_ledger_signature_verified(self):
        # The nested receipt-ledger frontier's own NPBJ37 layer is
        # recomputed on load; re-sign the outer NPBJ40 layer so only it
        # fails.
        bad_ledger = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        tampered = commit_frontier_for(
            1, bad_ledger.to_bytes(), DIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_deep_nested_layer_verified(self):
        # A failure one layer down (inside the ledger end range
        # frontier) is rejected just the same: loading replays every
        # nested signature layer.
        bad_range_end = dataclasses.replace(
            RangeFrontier.from_bytes(PFRONTIER_1.end),
            mac=ZERO,
        )
        bad_ledger = bundle_receipt_frontier_for(
            1, bad_range_end.to_bytes(), PFRONTIER_1.digest
        )
        tampered = commit_frontier_for(
            1, bad_ledger.to_bytes(), DIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                OTHER_KEY, checkpoint=FRONTIER_1
            )

    def test_checkpoint_is_read_only_and_has_no_state_alias(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=FRONTIER_1
        )
        with self.assertRaises(AttributeError):
            auditor.checkpoint = FRONTIER_1
        self.assertFalse(hasattr(auditor, "state"))


class BatchReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit(CRECEIPT_1, BATCH_1), auditor
        )
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, CRECEIPT_1.end)
        self.assertEqual(auditor.checkpoint.digest, DIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, CRECEIPT_2.end)
        self.assertEqual(auditor.checkpoint.digest, DIGEST_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1.to_bytes(), BATCH_1.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_verifies_with_keyword_arguments(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit(receipt=CRECEIPT_1, batch=BATCH_1), auditor
        )
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_restart_from_checkpoint_audits_next_commit(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        # Round-trip the frontier through its canonical bytes: the
        # observable restart contract is that the exported checkpoint
        # comes back equal and the next commit is accepted.
        blob = auditor.checkpoint.to_bytes()
        self.assertEqual(
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(blob),
            FRONTIER_1,
        )
        for checkpoint in (auditor.checkpoint, blob):
            restored = SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(CRECEIPT_2, BATCH_2)
            self.assertEqual(restored.checkpoint, FRONTIER_2)

    def test_first_commit_must_start_empty(self):
        # A continuation receipt cannot be the first commit of a fresh
        # ledger.
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_commit_rejected_without_rollback(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIs(auditor.checkpoint, before)

    def test_old_receipt_and_fork_rejected(self):
        # Accept the whole segment as one commit; the genesis receipt,
        # its continuation and a same-sequence fork are then all old
        # receipts whose start no longer links to the current end.
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)
        # And on a ledger that took the first segment, the straight-to-
        # end fork is rejected.
        forked = SpanBundleReceiptBatchReceiptAuditor(KEY)
        forked.audit(CRECEIPT_1, BATCH_1)
        with self.assertRaises(ValueError):
            forked.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertEqual(forked.checkpoint, FRONTIER_1)

    def test_broken_link_rejected(self):
        # A valid receipt/batch pair that does not continue the current
        # frontier is rejected after full stateless verification.
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=FRONTIER_2
        )
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_receipt_batch_mismatch_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_same_endpoints_other_batch_not_attested(self):
        # Another batch body with the same start and end has a different
        # digest and is not attested by the receipt.
        duplicate = (RECEIPT_1.to_bytes(), RECEIPT_1.to_bytes())
        other = batch_for(
            b"", duplicate, PFRONTIER_2.to_bytes()
        )
        self.assertEqual(other.start, BATCH_FULL.start)
        self.assertEqual(other.end, BATCH_FULL.end)
        self.assertNotEqual(other.to_bytes(), BATCH_FULL.to_bytes())
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_FULL, other)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_receipt_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(CRECEIPT_1, signature=ZERO),
                BATCH_1,
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_batch_rejected(self):
        forged = dataclasses.replace(
            BATCH_1,
            signature=_span_bundle_receipt_batch_signature(
                OTHER_KEY, BATCH_1
            ),
        )
        receipt = dataclasses.replace(
            CRECEIPT_1,
            signature=_span_bundle_receipt_batch_receipt_signature(
                KEY,
                dataclasses.replace(
                    CRECEIPT_1,
                    batch_digest=hashlib.sha256(
                        forged.to_bytes()
                    ).digest(),
                ),
            ),
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(receipt, forged)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_and_empty_key(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type_is_type_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [CRECEIPT_1], (CRECEIPT_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_and_non_canonical_bytes_is_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1.to_bytes() + b" ", BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1.to_bytes() + b" ")
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, PFRONTIER_1.to_bytes(), DIGEST_1
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        # CRECEIPT_2 honestly continues from PFRONTIER_1: the pair
        # verifies and the start links, but the u64 sequence cannot
        # advance.
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_commits_linearize(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        commits, failures = [], []
        barrier = threading.Barrier(2)

        def run(receipt, batch):
            barrier.wait()
            try:
                auditor.audit(receipt, batch)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(CRECEIPT_1, BATCH_1)
            ),
            threading.Thread(
                target=run, args=(CRECEIPT_FULL, BATCH_FULL)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, commits[0].end)
        # Whichever fork won, the ledger is consistent afterwards: the
        # continuation links only from the two-step winner.
        if commits[0] is CRECEIPT_1:
            auditor.audit(CRECEIPT_2, BATCH_2)
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, FRONTIER_FULL)

    def test_accepted_commit_is_never_lost_or_rolled_back(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)


class BatchReceiptAuditorParameterNamingTest(unittest.TestCase):
    def test_audit_params_named_receipt_and_batch(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptAuditor.audit
        )
        self.assertEqual(
            list(signature.parameters), ["self", "receipt", "batch"]
        )


class StatelessEntryPointStillWorksTest(unittest.TestCase):
    def test_stateless_audit_returns_ledger_end(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_1, KEY
            ),
            PFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL, KEY
            ),
            PFRONTIER_2,
        )


class MergedEndpointHelperTest(unittest.TestCase):
    def test_batch_endpoint_wording_preserved(self):
        with self.assertRaisesRegex(
            ValueError,
            r"span bundle receipt batch start must be the canonical"
            r" SpanBundleReceiptFrontier encoding or empty",
        ):
            SpanBundleReceiptBatch(1, b"junk", (RECEIPT_1.to_bytes(),),
                                   PFRONTIER_1.to_bytes(), ZERO)

    def test_batch_receipt_endpoint_wording_preserved(self):
        with self.assertRaisesRegex(
            ValueError,
            r"span bundle receipt batch receipt end must be the"
            r" canonical SpanBundleReceiptFrontier encoding$",
        ):
            SpanBundleReceiptBatchReceipt(
                1, b"", ZERO, b"junk", ZERO
            )


if __name__ == "__main__":
    unittest.main()
