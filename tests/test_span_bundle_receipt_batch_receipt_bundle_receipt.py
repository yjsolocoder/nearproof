import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptBatchReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundle,
    SpanBundleReceiptBatchReceiptBundleReceipt,
    SpanBundleReceiptBatchReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_PREFIX,
    _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes,
    _span_bundle_receipt_batch_receipt_bundle_receipt_signature,
    _span_bundle_receipt_batch_receipt_bundle_signature,
    audit_span_bundle_receipt_batch_receipt_bundle,
    audit_span_bundle_receipt_batch_receipt_bundle_receipt,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
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
from test_span_bundle_receipt_batch_receipt_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_12,
    BUNDLE_FULL,
    bundle_for,
)
from test_span_bundle_receipt_batch_receipt_frontier import (
    DIGEST_1,
    FRONTIER_1,
    FRONTIER_2,
    FRONTIER_FULL,
    commit_frontier_for,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
)


def bundle_receipt_for(bundle, key=KEY):
    """The receipt an honest ledger mints over ``bundle``: the NPBJ42
    signature recomputed over the first four fields."""
    placeholder = SpanBundleReceiptBatchReceiptBundleReceipt(
        1,
        bundle.start,
        hashlib.sha256(bundle.to_bytes()).digest(),
        bundle.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        signature=(
            _span_bundle_receipt_batch_receipt_bundle_receipt_signature(
                key, placeholder
            )
        ),
    )


BRECEIPT_1 = bundle_receipt_for(BUNDLE_1)
BRECEIPT_2 = bundle_receipt_for(BUNDLE_2)
BRECEIPT_12 = bundle_receipt_for(BUNDLE_12)
BRECEIPT_FULL = bundle_receipt_for(BUNDLE_FULL)


class BundleReceiptFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptBundleReceipt
                )
            ],
            ["version", "start", "bundle_digest", "end", "signature"],
        )
        self.assertNotIn("key", BRECEIPT_FULL.__dict__)
        self.assertNotIn("mac", BRECEIPT_FULL.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = SpanBundleReceiptBatchReceiptBundleReceipt(
            1,
            BRECEIPT_1.start,
            BRECEIPT_1.bundle_digest,
            BRECEIPT_1.end,
            BRECEIPT_1.signature,
        )
        self.assertEqual(receipt, BRECEIPT_1)
        self.assertEqual(hash(receipt), hash(BRECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, FRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BRECEIPT_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BRECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (
            1,
            "1",
            None,
            bytearray(FRONTIER_1.to_bytes()),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BRECEIPT_1, start=b"")

    def test_bundle_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, bundle_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, bundle_digest=bad)

    def test_end_contract(self):
        for bad in (
            1,
            "1",
            None,
            bytearray(FRONTIER_1.to_bytes()),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty batch-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BRECEIPT_1, signature=bad)


class BundleReceiptEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = BRECEIPT_FULL.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], b"".hex())
        self.assertEqual(
            outer[2],
            hashlib.sha256(BUNDLE_FULL.to_bytes()).hexdigest(),
        )
        self.assertEqual(outer[3], FRONTIER_FULL.to_bytes().hex())
        self.assertEqual(outer[4], BRECEIPT_FULL.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(
            raw, raw.decode("utf-8").lower().encode("utf-8")
        )

    def test_round_trip_byte_for_byte(self):
        for receipt in (BRECEIPT_1, BRECEIPT_2, BRECEIPT_12, BRECEIPT_FULL):
            raw = receipt.to_bytes()
            parsed = (
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(raw)
            )
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signatures(self):
        # A structurally valid receipt with an all-zero signature
        # parses; the signature is checked only by
        # audit_span_bundle_receipt_batch_receipt_bundle_receipt.
        unsigned = dataclasses.replace(BRECEIPT_1, signature=ZERO)
        parsed = SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(
            unsigned.to_bytes()
        )
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = BRECEIPT_1.to_bytes()
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
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(
                (TypeError, ValueError), msg=repr(bad)
            ):
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (
            1,
            "x",
            None,
            [BRECEIPT_1.to_bytes()],
            object(),
            True,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            hashlib.sha256(BUNDLE_1.to_bytes()).hexdigest(),
            FRONTIER_1.to_bytes().hex(),
            BRECEIPT_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, 1),
            (3, 1),
            (4, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(
                (TypeError, ValueError), msg=(index, bad_value)
            ):
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(
                    json.dumps(
                        broken, separators=(",", ":")
                    ).encode()
                )


class BundleReceiptSignatureTest(unittest.TestCase):
    def test_signature_is_npbj42_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_PREFIX
            + _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes(
                BRECEIPT_FULL
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BRECEIPT_FULL.signature, expected)
        self.assertEqual(len(BRECEIPT_FULL.signature), 32)
        joined = json.dumps(
            [
                BRECEIPT_FULL.version,
                BRECEIPT_FULL.start.hex(),
                BRECEIPT_FULL.bundle_digest.hex(),
                BRECEIPT_FULL.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(
                KEY,
                _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_PREFIX
                + joined,
                hashlib.sha256,
            ).digest(),
            BRECEIPT_FULL.signature,
        )

    def test_new_domain_label_distinct_from_bundle_and_frontier(self):
        # Signatures under the NPBJ40 frontier and NPBJ41 bundle labels
        # are not the bundle-receipt signature.
        for label in (b"NPBJ40", b"NPBJ41"):
            wrong = hmac.new(
                KEY,
                label
                + _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes(
                    BRECEIPT_1
                ),
                hashlib.sha256,
            ).digest()
            self.assertNotEqual(wrong, BRECEIPT_1.signature)


class AuditorAuditBundleReceiptSuccessTest(unittest.TestCase):
    def test_mints_receipt_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(receipt, BRECEIPT_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        receipt = auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertEqual(receipt, BRECEIPT_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_whole_segment_mints_one_receipt(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_12)
        self.assertEqual(receipt, BRECEIPT_12)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL.to_bytes())
        self.assertEqual(receipt, BRECEIPT_FULL)
        self.assertEqual(auditor.checkpoint, FRONTIER_FULL)

    def test_receipt_fields(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, BUNDLE_1.start)
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, BUNDLE_1.end)
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_batch_receipt_bundle_receipt_signature(
                KEY, receipt
            ),
        )

    def test_bundle_digest_binds_only_that_bundle(self):
        # The digest is the hash of exactly that bundle's canonical
        # bytes; bundles reaching related ledger points have different
        # digests.
        self.assertEqual(
            BRECEIPT_12.bundle_digest,
            hashlib.sha256(BUNDLE_12.to_bytes()).digest(),
        )
        self.assertNotEqual(
            BRECEIPT_12.bundle_digest,
            hashlib.sha256(BUNDLE_FULL.to_bytes()).digest(),
        )
        self.assertNotEqual(
            BRECEIPT_1.bundle_digest,
            BRECEIPT_12.bundle_digest,
        )

    def test_checkpoint_matches_audit_bundle_ledger(self):
        via_receipt = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_receipt.audit_bundle_receipt(BUNDLE_1)
        via_receipt.audit_bundle_receipt(BUNDLE_2)
        via_audit = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_audit.audit_bundle(BUNDLE_12)
        self.assertEqual(
            via_receipt.checkpoint, via_audit.checkpoint
        )

    def test_minted_receipt_round_trips_and_verifies(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        transported = (
            SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(
                receipt.to_bytes()
            )
        )
        self.assertEqual(transported, receipt)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                transported, BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )

    def test_restart_from_checkpoint_accepts_continuation(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        blob = auditor.checkpoint.to_bytes()
        restored = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=blob
        )
        receipt = restored.audit_bundle_receipt(BUNDLE_2)
        self.assertEqual(receipt, BRECEIPT_2)
        self.assertEqual(restored.checkpoint, FRONTIER_2)


class AuditorAuditBundleReceiptFailureTest(unittest.TestCase):
    def test_wrong_kind_is_type_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (
            1,
            "x",
            None,
            [BUNDLE_FULL],
            (BUNDLE_FULL,),
            object(),
            True,
            False,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_failure_changes_no_state_and_mints_nothing(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (b"junk", BUNDLE_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        # A continuation whose start does not match the empty ledger.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_2)
        # The whole bundle under the wrong key.
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                OTHER_KEY
            ).audit_bundle_receipt(BUNDLE_FULL)
        self.assertIsNone(auditor.checkpoint)
        # The ledger is still usable afterwards.
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertEqual(receipt, BRECEIPT_FULL)
        self.assertEqual(auditor.checkpoint, FRONTIER_FULL)

    def test_same_bundle_replay_rejected_without_rollback(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        first = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(first, BRECEIPT_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_fork_rejected_after_commit(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        before = auditor.checkpoint
        # The competing straight-to-end segment no longer links.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_forged_end_rejected_without_state_change(self):
        forged = bundle_for(
            b"",
            ((CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(forged)
        self.assertIsNone(auditor.checkpoint)
        # The ledger is still usable afterwards.
        auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_tampered_signature_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(
                dataclasses.replace(BUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_sequence_overflow_rejected_without_state_change(self):
        # A batch-receipt frontier pinned at u64 max cannot accept one
        # more commit: the carried pair links to its receipt-ledger end,
        # full verification passes, but advancing the sequence
        # overflows. The bundle is honestly NPBJ41-signed over the
        # maxed start so the failure is the overflow itself, and no
        # receipt is minted.
        maxed = commit_frontier_for(
            U64_MAX, PFRONTIER_1.to_bytes(), DIGEST_1
        )
        overflow = bundle_for(
            maxed.to_bytes(),
            ((CRECEIPT_2.to_bytes(), BATCH_2.to_bytes()),),
            maxed.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(overflow)
        self.assertIs(auditor.checkpoint, before)

    def test_failed_commit_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        receipt = auditor.audit_bundle_receipt(BUNDLE_12)
        self.assertEqual(receipt, BRECEIPT_12)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)


class AuditorAuditBundleReceiptLinearizationTest(unittest.TestCase):
    def test_two_competing_commits_mint_exactly_one_receipt(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        minted = []
        barrier = threading.Barrier(2)

        def run(bundle, receipt):
            barrier.wait()
            try:
                minted.append(auditor.audit_bundle_receipt(bundle))
            except ValueError:
                pass

        threads = [
            threading.Thread(
                target=run, args=(BUNDLE_1, BRECEIPT_1)
            ),
            threading.Thread(
                target=run, args=(BUNDLE_FULL, BRECEIPT_FULL)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(minted), 1)
        self.assertIn(minted[0], (BRECEIPT_1, BRECEIPT_FULL))
        # Whichever segment won, the minted receipt matches it and the
        # ledger is consistent afterwards.
        if minted[0] == BRECEIPT_1:
            self.assertEqual(auditor.checkpoint, FRONTIER_1)
            self.assertEqual(
                auditor.audit_bundle_receipt(BUNDLE_2), BRECEIPT_2
            )
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, FRONTIER_FULL)

    def test_bundle_receipt_competes_with_bundle_and_single(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
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
                    lambda: auditor.audit_bundle_receipt(BUNDLE_12),
                    "receipt",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_bundle(BUNDLE_FULL), "bundle"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(CRECEIPT_1, BATCH_1),
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
        if successes[0] == "receipt":
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        elif successes[0] == "bundle":
            self.assertEqual(auditor.checkpoint, FRONTIER_FULL)
        else:
            self.assertEqual(auditor.checkpoint.sequence, 1)
            # The single CRECEIPT_1 commit lands at FRONTIER_1.
            self.assertEqual(auditor.checkpoint, FRONTIER_1)


class AuditBundleReceiptStatelessSuccessTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_1, BUNDLE_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_2, BUNDLE_2, KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_12, BUNDLE_12, KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_FULL, BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )

    def test_accepts_objects_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_FULL.to_bytes(), BUNDLE_FULL.to_bytes(), KEY
            ),
            FRONTIER_FULL,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_1.to_bytes(), BUNDLE_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_1, BUNDLE_1.to_bytes(), KEY
            ),
            FRONTIER_1,
        )

    def test_stateless_and_touches_no_auditor(self):
        advanced = SpanBundleReceiptBatchReceiptAuditor(KEY)
        advanced.audit_bundle(BUNDLE_12)
        # Re-verifying the first segment's receipt works independently
        # of any local ledger state.
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_1, BUNDLE_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(advanced.checkpoint, FRONTIER_2)


class AuditBundleReceiptStatelessViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_FULL, BUNDLE_FULL, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_FULL, BUNDLE_FULL, b""
            )

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    BRECEIPT_FULL, BUNDLE_FULL, bad
                )

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (
            1,
            "x",
            None,
            [BRECEIPT_FULL],
            object(),
            True,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    bad, BUNDLE_FULL, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    BRECEIPT_FULL, bad, KEY
                )

    def test_non_canonical_bytes_are_value_error(self):
        for bad in (
            BRECEIPT_FULL.to_bytes() + b" ",
            b"junk",
            BRECEIPT_FULL.to_bytes() + b"\n",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    bad, BUNDLE_FULL, KEY
                )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_FULL, BUNDLE_FULL.to_bytes() + b" ", KEY
            )

    def test_tampered_signature_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                dataclasses.replace(BRECEIPT_FULL, signature=ZERO),
                BUNDLE_FULL,
                KEY,
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            b"NPBJ41"
            + _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes(
                BRECEIPT_FULL
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                dataclasses.replace(BRECEIPT_FULL, signature=wrong),
                BUNDLE_FULL,
                KEY,
            )

    def test_receipt_bundle_mismatch_rejected(self):
        # A valid receipt for a different bundle does not attest this
        # one.
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_2, BUNDLE_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_1, BUNDLE_2, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_1, BUNDLE_FULL, KEY
            )

    def test_same_endpoints_other_bundle_not_attested(self):
        # Another bundle with the same start (b"") and end (FRONTIER_2)
        # but a different body: one item instead of two, honestly
        # NPBJ41-signed. Its body does not replay to its declared end,
        # but the receipt check fails earlier on the bundle digest,
        # proving the receipt binds that one definite bundle.
        other = bundle_for(
            b"",
            ((CRECEIPT_2.to_bytes(), BATCH_2.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        self.assertEqual(other.start, BUNDLE_12.start)
        self.assertEqual(other.end, BUNDLE_12.end)
        self.assertNotEqual(other.to_bytes(), BUNDLE_12.to_bytes())
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                BRECEIPT_12, other, KEY
            )

    def test_tampered_digest_rejected(self):
        tampered = dataclasses.replace(
            BRECEIPT_1, bundle_digest=ZERO
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                tampered, BUNDLE_1, KEY
            )

    def test_forged_endpoints_rejected(self):
        # Honestly re-signed over a forged start or end: the endpoints
        # no longer equal the bundle's own.
        forged_start = dataclasses.replace(
            BRECEIPT_2, start=FRONTIER_2.to_bytes()
        )
        forged_start = dataclasses.replace(
            forged_start,
            signature=(
                _span_bundle_receipt_batch_receipt_bundle_receipt_signature(
                    KEY, forged_start
                )
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                forged_start, BUNDLE_2, KEY
            )
        forged_end = dataclasses.replace(
            BRECEIPT_1, end=FRONTIER_2.to_bytes()
        )
        forged_end = dataclasses.replace(
            forged_end,
            signature=(
                _span_bundle_receipt_batch_receipt_bundle_receipt_signature(
                    KEY, forged_end
                )
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                forged_end, BUNDLE_1, KEY
            )

    def test_tampered_bundle_rejected(self):
        # A bundle re-signed with the wrong key fails full verification
        # even when the receipt itself is honestly minted over it.
        forged = dataclasses.replace(
            BUNDLE_1,
            signature=_span_bundle_receipt_batch_receipt_bundle_signature(
                OTHER_KEY, BUNDLE_1
            ),
        )
        receipt = bundle_receipt_for(forged)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                receipt, forged, KEY
            )


class ParameterNamingTest(unittest.TestCase):
    def test_audit_bundle_receipt_param_named_x(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptAuditor.audit_bundle_receipt
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_stateless_audit_signature(self):
        signature = inspect.signature(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "bundle", "key"]
        )

    def test_bundle_audit_entry_unchanged(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptAuditor.audit_bundle
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])
        self.assertIsNone(
            getattr(
                SpanBundleReceiptBatchReceiptAuditor, "state", None
            )
        )


if __name__ == "__main__":
    unittest.main()
