import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptBatchReceiptAuditor,
    SpanBundleReceiptBatchReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX,
    _span_bundle_receipt_batch_receipt_frontier_content_bytes,
    _span_bundle_receipt_batch_receipt_frontier_next_digest,
    _span_bundle_receipt_batch_receipt_frontier_signature,
    _span_bundle_receipt_frontier_signature,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    RFRONTIER_1,
    U64_MAX,
    ZERO,
)
from test_span_bundle_receipt_batch import (
    BATCH_1,
    BATCH_2,
    BATCH_FULL,
)
from test_span_bundle_receipt_batch_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    CRECEIPT_FULL,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
)


def commit_frontier_for(sequence, end, digest, key=KEY):
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


# The commit-receipt digest chain starts at 32 zero bytes; each accepted
# batch receipt extends it as SHA256(d + u64be(n) + R), with no domain
# tag, separator or length prefix.
CDIGEST_1 = _span_bundle_receipt_batch_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_1.to_bytes()
)
CDIGEST_2 = _span_bundle_receipt_batch_receipt_frontier_next_digest(
    CDIGEST_1, 2, CRECEIPT_2.to_bytes()
)
CFRONTIER_1 = commit_frontier_for(
    1, PFRONTIER_1.to_bytes(), CDIGEST_1
)
CFRONTIER_2 = commit_frontier_for(
    2, PFRONTIER_2.to_bytes(), CDIGEST_2
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
        self.assertNotIn("key", CFRONTIER_1.__dict__)
        self.assertNotIn("mac", CFRONTIER_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = SpanBundleReceiptBatchReceiptFrontier(
            1,
            1,
            CRECEIPT_1.end,
            CDIGEST_1,
            CFRONTIER_1.signature,
        )
        self.assertEqual(frontier, CFRONTIER_1)
        self.assertEqual(hash(frontier), hash(CFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, CRECEIPT_1.end)
        self.assertEqual(frontier.end, PFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, CDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            CFRONTIER_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(CFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(CFRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)
        # end must be the canonical non-empty SpanBundleReceiptFrontier
        # encoding: not empty, not junk and not a range frontier.
        for bad in (b"", b"junk", b"[1,2,3]", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})


class BatchReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + CRECEIPT_1.end.hex().encode() + b'",'
            b'"' + CDIGEST_1.hex().encode() + b'",'
            b'"' + CFRONTIER_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(CFRONTIER_1.to_bytes(), expected)
        raw = CFRONTIER_1.to_bytes()
        self.assertNotIn(b" ", raw)
        self.assertEqual(
            raw, raw.decode("utf-8").lower().encode("utf-8")
        )

    def test_round_trip(self):
        for frontier in (CFRONTIER_1, CFRONTIER_2):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(blob),
                frontier,
            )
            self.assertEqual(
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                    blob
                ).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = CFRONTIER_1.to_bytes()
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
            CFRONTIER_1.end.hex(),
            CDIGEST_1.hex(),
            CFRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (1, True)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=repr((index, bad_value))):
                SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = CFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            CFRONTIER_1.signature.hex().encode(),
            CFRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_signature(self):
        tampered = dataclasses.replace(CFRONTIER_1, signature=ZERO)
        parsed = SpanBundleReceiptBatchReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_digest_chain_has_no_domain_tag(self):
        # d1 = SHA256(d0 + u64be(1) + R): the three parts concatenated
        # directly, with no prefix, delimiter or length prefix.
        expected_digest = hashlib.sha256(
            ZERO + (1).to_bytes(8, "big") + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(CDIGEST_1, expected_digest)
        tagged = hashlib.sha256(
            b"NPBJ40"
            + ZERO
            + (1).to_bytes(8, "big")
            + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertNotEqual(CDIGEST_1, tagged)

    def test_signature_is_npbj40_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX
            + _span_bundle_receipt_batch_receipt_frontier_content_bytes(
                CFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(CFRONTIER_1.signature, expected)
        self.assertEqual(len(CFRONTIER_1.signature), 32)

    def test_new_domain_label_distinct_from_receipt(self):
        # A signature under the NPBJ39 batch-receipt label is not the
        # frontier signature.
        wrong = hmac.new(
            KEY,
            b"NPBJ39"
            + _span_bundle_receipt_batch_receipt_frontier_content_bytes(
                CFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(wrong, CFRONTIER_1.signature)


class BatchReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(
            SpanBundleReceiptBatchReceiptAuditor(KEY).checkpoint
        )
        self.assertIsNone(
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (CFRONTIER_1, CFRONTIER_1.to_bytes()):
            auditor = SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [CFRONTIER_1], object(), PFRONTIER_1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=b"junk"
            )

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(CFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_receipt_frontier_signature_verified(self):
        # The end SpanBundleReceiptFrontier's own NPBJ37 layer is
        # recomputed on load.
        bad_end = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        tampered = commit_frontier_for(
            1, bad_end.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_nested_range_frontier_mac_verified(self):
        # One layer deeper: a bad NPBJ13 range-frontier MAC inside the
        # end receipt frontier is recomputed on load as well; the NPBJ37
        # layer is honestly re-signed so only that nested layer fails.
        bad_range = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        bad_end = dataclasses.replace(
            PFRONTIER_1, end=bad_range.to_bytes()
        )
        bad_end = dataclasses.replace(
            bad_end,
            signature=_span_bundle_receipt_frontier_signature(
                KEY, bad_end
            ),
        )
        tampered = commit_frontier_for(
            1, bad_end.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                OTHER_KEY, checkpoint=CFRONTIER_1
            )

    def test_checkpoint_is_read_only_and_no_alias(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=CFRONTIER_1
        )
        with self.assertRaises(AttributeError):
            auditor.checkpoint = CFRONTIER_2
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)


class BatchReceiptAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(auditor.audit(CRECEIPT_1, BATCH_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, CRECEIPT_1.end)
        self.assertEqual(auditor.checkpoint.digest, CDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, CRECEIPT_2.end)
        self.assertEqual(auditor.checkpoint.digest, CDIGEST_2)

    def test_full_segment_books_one_receipt(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, PFRONTIER_2.to_bytes())
        expected_digest = hashlib.sha256(
            ZERO + (1).to_bytes(8, "big") + CRECEIPT_FULL.to_bytes()
        ).digest()
        self.assertEqual(auditor.checkpoint.digest, expected_digest)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1.to_bytes(), BATCH_1.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_restart_from_checkpoint_continues_with_next(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        blob = auditor.checkpoint.to_bytes()
        restored = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=blob
        )
        self.assertEqual(restored.checkpoint, CFRONTIER_1)
        # Restart lets the long-term receiver continue auditing the
        # next commit receipt.
        restored.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(restored.checkpoint, CFRONTIER_2)

    def test_first_commit_must_start_empty(self):
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
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1.to_bytes(), BATCH_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_old_receipt_and_fork_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        before = auditor.checkpoint
        # An old first-segment receipt no longer links.
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        # The second segment does not link to the straight-to-end fork.
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)

    def test_broken_chain_rejected(self):
        # A full segment presented after the first segment fails the
        # start linkage (empty start vs the current frontier end).
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_commit_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(CRECEIPT_1, signature=ZERO),
                BATCH_1,
            )
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_batch_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_FULL)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (
            1,
            "x",
            None,
            [CRECEIPT_1],
            (CRECEIPT_1,),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_are_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1.to_bytes() + b" ", BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1.to_bytes() + b" ")
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(CRECEIPT_1, signature=ZERO),
                BATCH_1,
            )
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, PFRONTIER_1.to_bytes(), CDIGEST_1
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
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
        self.assertEqual(
            auditor.checkpoint.end, commits[0].end
        )
        # No commit was lost: the frontier still extends exactly one
        # honest first segment.
        self.assertIn(
            auditor.checkpoint.end,
            (CRECEIPT_1.end, CRECEIPT_FULL.end),
        )

    def test_frontier_round_trip_after_each_audit(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        blob = auditor.checkpoint.to_bytes()
        self.assertEqual(
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(blob),
            auditor.checkpoint,
        )
        auditor.audit(CRECEIPT_2, BATCH_2)
        blob = auditor.checkpoint.to_bytes()
        self.assertEqual(
            SpanBundleReceiptBatchReceiptFrontier.from_bytes(blob),
            auditor.checkpoint,
        )


if __name__ == "__main__":
    unittest.main()
