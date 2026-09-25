import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptAuditor,
    SpanBundleReceiptBatchReceipt,
    SpanBundleReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX,
    _span_bundle_receipt_batch_receipt_content_bytes,
    _span_bundle_receipt_batch_receipt_signature,
    _span_bundle_receipt_batch_signature,
    _span_bundle_receipt_frontier_signature,
    audit_span_bundle_receipt_batch_receipt,
)
from test_range_auditor_audit_batch import (
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RDIGEST_1,
    U64_MAX,
    ZERO,
    range_frontier_for,
)
from test_span_bundle_receipt import (
    BUNDLE_1,
    RECEIPT_1,
    RECEIPT_2,
)
from test_span_bundle_receipt_batch import (
    BATCH_1,
    BATCH_2,
    BATCH_FULL,
    batch_for,
    resign_receipt,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
)


def receipt_for(batch, key=KEY):
    """The receipt an honest ledger mints over ``batch``: the NPBJ39
    signature recomputed over the first four fields."""
    placeholder = SpanBundleReceiptBatchReceipt(
        1,
        batch.start,
        hashlib.sha256(batch.to_bytes()).digest(),
        batch.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_signature(
            key, placeholder
        ),
    )


CRECEIPT_1 = receipt_for(BATCH_1)
CRECEIPT_2 = receipt_for(BATCH_2)
CRECEIPT_FULL = receipt_for(BATCH_FULL)


class SpanBundleReceiptBatchReceiptFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(SpanBundleReceiptBatchReceipt)
            ],
            ["version", "start", "batch_digest", "end", "signature"],
        )
        self.assertNotIn("key", CRECEIPT_FULL.__dict__)
        self.assertNotIn("mac", CRECEIPT_FULL.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = SpanBundleReceiptBatchReceipt(
            1,
            CRECEIPT_1.start,
            CRECEIPT_1.batch_digest,
            CRECEIPT_1.end,
            CRECEIPT_1.signature,
        )
        self.assertEqual(receipt, CRECEIPT_1)
        self.assertEqual(hash(receipt), hash(CRECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.batch_digest,
            hashlib.sha256(BATCH_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, PFRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            CRECEIPT_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(CRECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(CRECEIPT_1, start=b"")

    def test_batch_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, batch_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, batch_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(PFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty span bundle receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CRECEIPT_1, signature=bad)


class SpanBundleReceiptBatchReceiptEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = CRECEIPT_FULL.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], b"".hex())
        self.assertEqual(
            outer[2], hashlib.sha256(BATCH_FULL.to_bytes()).hexdigest()
        )
        self.assertEqual(outer[3], PFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], CRECEIPT_FULL.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for receipt in (CRECEIPT_1, CRECEIPT_2, CRECEIPT_FULL):
            raw = receipt.to_bytes()
            parsed = SpanBundleReceiptBatchReceipt.from_bytes(raw)
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signatures(self):
        # A structurally valid receipt with an all-zero signature parses;
        # signatures are checked only by
        # audit_span_bundle_receipt_batch_receipt.
        unsigned = dataclasses.replace(CRECEIPT_1, signature=ZERO)
        parsed = SpanBundleReceiptBatchReceipt.from_bytes(
            unsigned.to_bytes()
        )
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = CRECEIPT_1.to_bytes()
        outer = json.loads(raw)
        for bad in (
            b"",
            b"junk",
            b"[1,2,3]",
            raw + b" ",
            raw.replace(b",", b", ", 1),
            b" " + raw,
            json.dumps(outer, indent=2).encode(),
            # Uppercase hex.
            raw.replace(outer[2].encode(), outer[2].upper().encode()),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatchReceipt.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [CRECEIPT_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt.from_bytes(bad)


class SpanBundleReceiptBatchReceiptSignatureTest(unittest.TestCase):
    def test_signature_is_npbj39_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX
            + _span_bundle_receipt_batch_receipt_content_bytes(
                CRECEIPT_FULL
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(CRECEIPT_FULL.signature, expected)
        self.assertEqual(len(CRECEIPT_FULL.signature), 32)
        joined = json.dumps(
            [
                CRECEIPT_FULL.version,
                CRECEIPT_FULL.start.hex(),
                CRECEIPT_FULL.batch_digest.hex(),
                CRECEIPT_FULL.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(
                KEY,
                _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX + joined,
                hashlib.sha256,
            ).digest(),
            CRECEIPT_FULL.signature,
        )

    def test_new_domain_label_distinct_from_batch(self):
        # A signature under the NPBJ38 batch label is not the receipt
        # signature.
        wrong = hmac.new(
            KEY,
            b"NPBJ38"
            + _span_bundle_receipt_batch_receipt_content_bytes(
                CRECEIPT_FULL
            ),
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(wrong, CRECEIPT_FULL.signature)


class AuditorCommitBatchSuccessTest(unittest.TestCase):
    def test_mints_receipt_and_advances(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipt = auditor.commit_batch(BATCH_1)
        self.assertEqual(receipt, CRECEIPT_1)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)
        receipt = auditor.commit_batch(BATCH_2)
        self.assertEqual(receipt, CRECEIPT_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipt = auditor.commit_batch(BATCH_FULL.to_bytes())
        self.assertEqual(receipt, CRECEIPT_FULL)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_receipt_fields(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipt = auditor.commit_batch(BATCH_1)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, BATCH_1.start)
        self.assertEqual(
            receipt.batch_digest,
            hashlib.sha256(BATCH_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, BATCH_1.end)
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_batch_receipt_signature(KEY, receipt),
        )

    def test_checkpoint_matches_audit_batch_ledger(self):
        via_commit = SpanBundleReceiptAuditor(KEY)
        via_commit.commit_batch(BATCH_1)
        via_commit.commit_batch(BATCH_2)
        via_audit = SpanBundleReceiptAuditor(KEY)
        via_audit.audit_batch(BATCH_FULL)
        self.assertEqual(via_commit.checkpoint, via_audit.checkpoint)

    def test_minted_receipt_round_trips_and_verifies(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipt = auditor.commit_batch(BATCH_FULL)
        transported = SpanBundleReceiptBatchReceipt.from_bytes(
            receipt.to_bytes()
        )
        self.assertEqual(transported, receipt)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                transported, BATCH_FULL, KEY
            ),
            PFRONTIER_2,
        )


class AuditorCommitBatchFailureTest(unittest.TestCase):
    def test_wrong_kind_is_type_error(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_failure_changes_no_state_and_mints_nothing(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (b"junk", BATCH_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_batch(bad)
        # A continuation whose start does not match the empty ledger.
        with self.assertRaises(ValueError):
            auditor.commit_batch(BATCH_2)
        # The whole batch under the wrong key.
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(OTHER_KEY).commit_batch(BATCH_FULL)
        self.assertIsNone(auditor.checkpoint)
        # The ledger is still usable afterwards.
        auditor.commit_batch(BATCH_FULL)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_same_batch_replay_rejected_without_rollback(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.commit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_batch(BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1)
        self.assertIs(auditor.checkpoint, before)

    def test_failed_continuation_keeps_checkpoint(self):
        # An honestly outer-signed batch whose declared end does not
        # match the replayed chain fails after replay; the live
        # checkpoint is untouched and no receipt is minted.
        bad_end = dataclasses.replace(
            BATCH_2, end=PFRONTIER_1.to_bytes()
        )
        bad_end = dataclasses.replace(
            bad_end,
            signature=_span_bundle_receipt_batch_signature(KEY, bad_end),
        )
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.commit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_batch(bad_end)
        self.assertIs(auditor.checkpoint, before)

    def test_overflow_rejected_without_state_change(self):
        # A receipt-ledger frontier pinned at u64 max cannot accept one
        # more receipt through a committed batch.
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
        continuation = resign_receipt(
            dataclasses.replace(RECEIPT_1, start=maxed.end)
        )
        overflow = batch_for(
            maxed.to_bytes(),
            (continuation.to_bytes(),),
            maxed.to_bytes(),
        )
        auditor = SpanBundleReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_batch(overflow)
        self.assertIs(auditor.checkpoint, before)


class AuditorCommitBatchLinearizationTest(unittest.TestCase):
    def test_commit_audit_and_single_compete_on_one_lock(self):
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
                args=(lambda: auditor.commit_batch(BATCH_FULL), "commit"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(BATCH_1), "batch"),
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
        if successes[0] != "commit":
            auditor.commit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_two_competing_commits_mint_exactly_one_receipt(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        minted = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                minted.append(auditor.commit_batch(BATCH_FULL))
            except ValueError:
                pass

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(minted, [CRECEIPT_FULL])
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)


class AuditSpanBundleReceiptBatchReceiptSuccessTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL, KEY
            ),
            PFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_1, KEY
            ),
            PFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_2, BATCH_2, KEY
            ),
            PFRONTIER_2,
        )

    def test_accepts_object_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL.to_bytes(), BATCH_FULL.to_bytes(), KEY
            ),
            PFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1.to_bytes(), BATCH_1, KEY
            ),
            PFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_1.to_bytes(), KEY
            ),
            PFRONTIER_1,
        )

    def test_stateless_and_touches_no_auditor(self):
        advanced = SpanBundleReceiptAuditor(KEY)
        advanced.commit_batch(BATCH_FULL)
        # Re-verifying the first segment's receipt works independently
        # of any local ledger state.
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_1, KEY
            ),
            PFRONTIER_1,
        )
        self.assertEqual(advanced.checkpoint, PFRONTIER_2)


class AuditSpanBundleReceiptBatchReceiptViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL, b""
            )

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt(
                    CRECEIPT_FULL, BATCH_FULL, bad
                )

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [CRECEIPT_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt(
                    bad, BATCH_FULL, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt(
                    CRECEIPT_FULL, bad, KEY
                )

    def test_non_canonical_bytes_are_value_error(self):
        for bad in (
            CRECEIPT_FULL.to_bytes() + b" ",
            b"junk",
            CRECEIPT_FULL.to_bytes() + b"\n",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt(
                    bad, BATCH_FULL, KEY
                )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL.to_bytes() + b" ", KEY
            )

    def test_tampered_signature_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                dataclasses.replace(CRECEIPT_FULL, signature=ZERO),
                BATCH_FULL,
                KEY,
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            b"NPBJ38"
            + _span_bundle_receipt_batch_receipt_content_bytes(
                CRECEIPT_FULL
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                dataclasses.replace(CRECEIPT_FULL, signature=wrong),
                BATCH_FULL,
                KEY,
            )

    def test_receipt_batch_mismatch_rejected(self):
        # A valid receipt for a different batch does not attest this one.
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_2, BATCH_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_2, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_FULL, KEY
            )

    def test_same_endpoints_other_batch_not_attested(self):
        # Another batch with the same start and end but a different body
        # has a different digest and is not attested by the receipt.
        duplicate = (RECEIPT_1.to_bytes(), RECEIPT_1.to_bytes())
        other = batch_for(b"", duplicate, PFRONTIER_2.to_bytes())
        self.assertEqual(other.start, BATCH_FULL.start)
        self.assertEqual(other.end, BATCH_FULL.end)
        self.assertNotEqual(other.to_bytes(), BATCH_FULL.to_bytes())
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, other, KEY
            )

    def test_tampered_digest_rejected(self):
        tampered = dataclasses.replace(CRECEIPT_1, batch_digest=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                tampered, BATCH_1, KEY
            )

    def test_forged_endpoints_rejected(self):
        # Honestly re-signed over a forged start or end: the endpoints
        # no longer equal the batch's own.
        forged_start = dataclasses.replace(
            CRECEIPT_2, start=PFRONTIER_2.to_bytes()
        )
        forged_start = dataclasses.replace(
            forged_start,
            signature=_span_bundle_receipt_batch_receipt_signature(
                KEY, forged_start
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                forged_start, BATCH_2, KEY
            )
        forged_end = dataclasses.replace(
            CRECEIPT_1, end=PFRONTIER_2.to_bytes()
        )
        forged_end = dataclasses.replace(
            forged_end,
            signature=_span_bundle_receipt_batch_receipt_signature(
                KEY, forged_end
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                forged_end, BATCH_1, KEY
            )

    def test_tampered_batch_rejected(self):
        # A batch re-signed with the wrong key fails full verification
        # even when the receipt itself is honestly minted over it.
        forged = dataclasses.replace(
            BATCH_1,
            signature=_span_bundle_receipt_batch_signature(
                OTHER_KEY, BATCH_1
            ),
        )
        receipt = receipt_for(forged)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(receipt, forged, KEY)


if __name__ == "__main__":
    unittest.main()
