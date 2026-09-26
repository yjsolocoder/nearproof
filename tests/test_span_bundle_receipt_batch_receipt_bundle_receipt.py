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
)


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPBJ42 signature recomputed over
    the first four fields; ``start``/``end``/``digest`` default to the
    honest values."""
    placeholder = SpanBundleReceiptBatchReceiptBundleReceipt(
        1,
        bundle.start if start is None else start,
        (
            hashlib.sha256(bundle.to_bytes()).digest()
            if digest is None
            else digest
        ),
        bundle.end if end is None else end,
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


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)
RECEIPT_12 = receipt_for(BUNDLE_12)
RECEIPT_FULL = receipt_for(BUNDLE_FULL)


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
        self.assertNotIn("key", RECEIPT_FULL.__dict__)
        self.assertNotIn("mac", RECEIPT_FULL.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = SpanBundleReceiptBatchReceiptBundleReceipt(
            1,
            RECEIPT_1.start,
            RECEIPT_1.bundle_digest,
            RECEIPT_1.end,
            RECEIPT_1.signature,
        )
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(hash(receipt), hash(RECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, FRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(RECEIPT_1, start=b"")

    def test_bundle_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty batch-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, signature=bad)


class BundleReceiptEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = RECEIPT_FULL.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], BUNDLE_FULL.start.hex())
        self.assertEqual(
            outer[2],
            hashlib.sha256(BUNDLE_FULL.to_bytes()).hexdigest(),
        )
        self.assertEqual(outer[3], BUNDLE_FULL.end.hex())
        self.assertEqual(outer[4], RECEIPT_FULL.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_12, RECEIPT_FULL):
            raw = receipt.to_bytes()
            parsed = (
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(raw)
            )
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signature(self):
        # A structurally valid receipt with an all-zero signature parses;
        # the signature is checked only by
        # audit_span_bundle_receipt_batch_receipt_bundle_receipt.
        unsigned = dataclasses.replace(RECEIPT_1, signature=ZERO)
        parsed = SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(
            unsigned.to_bytes()
        )
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = RECEIPT_1.to_bytes()
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
            raw.replace(outer[4].encode(), outer[4].upper().encode()),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(bad)

    def test_signature_is_npbj42_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_PREFIX
            + (
                _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes(
                    RECEIPT_FULL
                )
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_FULL.signature, expected)
        self.assertEqual(len(RECEIPT_FULL.signature), 32)
        # The prefix and the compact encoding are concatenated directly,
        # with no delimiter or length prefix between them.
        joined = json.dumps(
            [
                RECEIPT_FULL.version,
                RECEIPT_FULL.start.hex(),
                RECEIPT_FULL.bundle_digest.hex(),
                RECEIPT_FULL.end.hex(),
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
            RECEIPT_FULL.signature,
        )

    def test_new_domain_label_distinct_from_bundle_and_frontier(self):
        # Signatures under the NPBJ41 bundle and NPBJ40 frontier labels
        # are not the bundle-receipt signature.
        content = (
            _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes(
                RECEIPT_1
            )
        )
        for label in (b"NPBJ40", b"NPBJ41"):
            wrong = hmac.new(KEY, label + content, hashlib.sha256).digest()
            self.assertNotEqual(wrong, RECEIPT_1.signature)


class AuditBundleReceiptSuccessTest(unittest.TestCase):
    def test_returns_final_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_2, BUNDLE_2, KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_12, BUNDLE_12, KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )

    def test_accepts_objects_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_2, BUNDLE_2.to_bytes(), KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_2.to_bytes(), BUNDLE_2, KEY
            ),
            FRONTIER_2,
        )

    def test_round_trip_then_verify(self):
        produced = SpanBundleReceiptBatchReceiptAuditor(
            KEY
        ).audit_bundle_receipt(BUNDLE_FULL)
        transported = (
            SpanBundleReceiptBatchReceiptBundleReceipt.from_bytes(
                produced.to_bytes()
            )
        )
        self.assertEqual(transported, produced)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                transported, BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )

    def test_stateless_and_touches_no_auditor(self):
        # Verification needs no stateful auditor at all, and a third party
        # can verify a bundle against the same key regardless of any local
        # ledger state.
        advanced = SpanBundleReceiptBatchReceiptAuditor(KEY)
        advanced.audit_bundle(BUNDLE_FULL)
        # Re-verifying the first bundle still works — nothing consults or
        # mutates ``advanced``.
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(advanced.checkpoint, FRONTIER_FULL)
        self.assertIsInstance(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_1, KEY
            ),
            SpanBundleReceiptBatchReceiptFrontier,
        )


class BundleReceiptDigestBindingTest(unittest.TestCase):
    def test_receipt_binds_exactly_one_bundle(self):
        # A structurally valid, properly NPBJ41-signed bundle carrying the
        # same start and end fields as BUNDLE_1 but a different body is not
        # admitted by a receipt minted over BUNDLE_1, even before the
        # carried chain itself is replayed.
        other = bundle_for(
            BUNDLE_1.start,
            ((CRECEIPT_FULL.to_bytes(), BATCH_FULL.to_bytes()),),
            BUNDLE_1.end,
        )
        self.assertEqual(other.start, BUNDLE_1.start)
        self.assertEqual(other.end, BUNDLE_1.end)
        self.assertNotEqual(other.to_bytes(), BUNDLE_1.to_bytes())
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1, other, KEY
            )

    def test_receipt_over_one_bundle_rejected_for_another(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_2, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_1, KEY
            )

    def test_digest_field_equals_sha256_of_bundle(self):
        self.assertEqual(
            RECEIPT_FULL.bundle_digest,
            hashlib.sha256(BUNDLE_FULL.to_bytes()).digest(),
        )
        bad = receipt_for(BUNDLE_FULL, digest=b"\x09" * 32)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                bad, BUNDLE_FULL, KEY
            )


class AuditBundleReceiptViolationTest(unittest.TestCase):
    def test_wrong_key_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_FULL, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_FULL, b""
            )

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    RECEIPT_FULL, BUNDLE_FULL, bad
                )

    def test_wrong_argument_kinds_are_type_errors(self):
        for bad in (1, "x", None, [RECEIPT_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    bad, BUNDLE_FULL, KEY
                )
        for bad in (1, "x", None, [BUNDLE_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                    RECEIPT_FULL, bad, KEY
                )

    def test_non_canonical_bytes_are_value_errors(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL.to_bytes() + b" ", BUNDLE_FULL, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_FULL.to_bytes() + b"\n", KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                b"junk", BUNDLE_FULL, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, b"junk", KEY
            )

    def test_tampered_signature_rejected(self):
        bad = dataclasses.replace(RECEIPT_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                bad, BUNDLE_FULL, KEY
            )

    def test_tampered_bundle_body_rejected(self):
        raw = bytearray(BUNDLE_FULL.to_bytes())
        raw[-1] ^= 0x01
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_FULL, bytes(raw), KEY
            )

    def test_tampered_carried_receipt_rejected(self):
        # Re-sign a bundle whose carried receipt is forged: the receipt
        # over the original bundle is rejected on the digest mismatch,
        # and a receipt re-minted over the tampered bundle is rejected
        # once the carried chain fails full verification.
        tampered = bundle_for(
            b"",
            (
                (
                    dataclasses.replace(
                        CRECEIPT_1, signature=ZERO
                    ).to_bytes(),
                    BATCH_1.to_bytes(),
                ),
            ),
            FRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                RECEIPT_1, tampered, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                receipt_for(tampered), tampered, KEY
            )

    def test_forged_endpoint_rejected(self):
        # A receipt signed over honest content but naming a different end
        # frontier does not match the bundle's end.
        forged_end = receipt_for(BUNDLE_FULL, end=BUNDLE_1.end)
        self.assertEqual(forged_end.end, BUNDLE_1.end)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                forged_end, BUNDLE_FULL, KEY
            )
        forged_start = receipt_for(BUNDLE_2, start=b"")
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                forged_start, BUNDLE_2, KEY
            )

    def test_signature_must_use_npbj42_domain(self):
        # A signature computed under a different domain label is just a
        # wrong signature.
        wrong_domain = hmac.new(
            KEY,
            b"NPBJ41"
            + (
                _span_bundle_receipt_batch_receipt_bundle_receipt_content_bytes(
                    RECEIPT_FULL
                )
            ),
            hashlib.sha256,
        ).digest()
        bad = dataclasses.replace(RECEIPT_FULL, signature=wrong_domain)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                bad, BUNDLE_FULL, KEY
            )

    def test_unsigned_receipt_rejected(self):
        unsigned = dataclasses.replace(RECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                unsigned, BUNDLE_1, KEY
            )


class AuditorCommitBundleReceiptSuccessTest(unittest.TestCase):
    def test_mints_receipt_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertIsInstance(
            receipt, SpanBundleReceiptBatchReceiptBundleReceipt
        )
        self.assertEqual(auditor.checkpoint, FRONTIER_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_FULL.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, BUNDLE_FULL.end)
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_batch_receipt_bundle_receipt_signature(
                KEY, receipt
            ),
        )

    def test_does_not_return_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertNotIsInstance(
            auditor.audit_bundle_receipt(BUNDLE_1),
            SpanBundleReceiptBatchReceiptAuditor,
        )

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_FULL)
        self.assertEqual(receipt, RECEIPT_FULL)

    def test_chained_commits_and_restart(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertEqual(auditor.audit_bundle_receipt(BUNDLE_1), RECEIPT_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertEqual(auditor.audit_bundle_receipt(BUNDLE_2), RECEIPT_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        restored = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=FRONTIER_1.to_bytes()
        )
        self.assertEqual(
            restored.audit_bundle_receipt(BUNDLE_2), RECEIPT_2
        )
        self.assertEqual(restored.checkpoint, FRONTIER_2)

    def test_matches_other_entry_points(self):
        via_commit = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_commit.audit_bundle_receipt(BUNDLE_1)
        via_commit.audit_bundle_receipt(BUNDLE_2)
        via_singles = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_singles.audit(CRECEIPT_1, BATCH_1)
        via_singles.audit(CRECEIPT_2, BATCH_2)
        via_audit = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_audit.audit_bundle(BUNDLE_12)
        self.assertEqual(via_commit.checkpoint, via_singles.checkpoint)
        self.assertEqual(via_commit.checkpoint, via_audit.checkpoint)
        self.assertEqual(via_commit.checkpoint, FRONTIER_2)

    def test_minted_receipt_independently_verifies(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_12)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                receipt.to_bytes(), BUNDLE_12, KEY
            ),
            FRONTIER_2,
        )


class AuditorCommitBundleReceiptFailureTest(unittest.TestCase):
    def test_replay_rejected_without_receipt_or_rollback(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        first = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(first, RECEIPT_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_start_rejected(self):
        # BUNDLE_2 starts at FRONTIER_1 and cannot commit into an empty
        # auditor; nothing is minted and the checkpoint stays empty.
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                OTHER_KEY
            ).audit_bundle_receipt(BUNDLE_FULL)

    def test_bad_signature_rejected(self):
        forged = dataclasses.replace(BUNDLE_FULL, signature=ZERO)
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(forged)
        self.assertIsNone(auditor.checkpoint)

    def test_old_fork_rejected(self):
        # The competing straight-to-end segment no longer links after the
        # two-commit segment landed.
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_12)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_overflow_rejected_without_state_change(self):
        maxed = commit_frontier_for(
            U64_MAX, PFRONTIER_1.to_bytes(), DIGEST_1
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_failed_call_mints_nothing_and_keeps_auditor_usable(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_bundle_receipt(42)
        self.assertIsNone(auditor.checkpoint)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertEqual(auditor.checkpoint, FRONTIER_FULL)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt(
                receipt, BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )

    def test_wrong_kind_is_type_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.checkpoint)


class AuditorCommitBundleReceiptLinearizationTest(unittest.TestCase):
    def test_all_entry_points_compete_on_one_lock(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        successes, failures, receipts = [], [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                result = action()
                successes.append(token)
                if isinstance(
                    result, SpanBundleReceiptBatchReceiptBundleReceipt
                ):
                    receipts.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_bundle_receipt(BUNDLE_12),
                    "commit",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_bundle(BUNDLE_FULL), "audit"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(CRECEIPT_1, BATCH_1),
                    "one",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        winner = successes[0]
        # A receipt exists exactly when audit_bundle_receipt won.
        self.assertEqual(receipts, ["commit"] if winner == "commit" else [])
        if winner == "one":
            self.assertEqual(auditor.checkpoint, FRONTIER_1)
            auditor.audit_bundle(BUNDLE_2)
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        elif winner == "commit":
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, FRONTIER_FULL)

    def test_two_competing_full_commits_one_wins(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                auditor.audit_bundle_receipt(BUNDLE_FULL)
                outcomes.append("ok")
            except ValueError:
                outcomes.append("replay")

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ok", "replay"])
        self.assertEqual(auditor.checkpoint, FRONTIER_FULL)


class ParameterNamingTest(unittest.TestCase):
    def test_audit_bundle_receipt_param_named_x(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptAuditor.audit_bundle_receipt
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_stateless_param_names(self):
        signature = inspect.signature(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "bundle", "key"]
        )


if __name__ == "__main__":
    unittest.main()
