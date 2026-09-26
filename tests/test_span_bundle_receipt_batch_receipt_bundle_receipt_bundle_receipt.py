import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundleReceiptBundle,
    SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_BUNDLE_RECEIPT_PREFIX,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes,
    audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_span_bundle_receipt_batch_receipt_bundle_receipt_bundle import (
    QBUNDLE_1,
    QBUNDLE_2,
    QBUNDLE_12,
    QBUNDLE_FULL,
)
from test_span_bundle_receipt_batch_receipt_bundle_receipt_frontier import (
    QDIGEST_1,
    QFRONTIER_1,
    QFRONTIER_2,
    QFRONTIER_FULL,
    bundle_receipt_ledger_frontier_for,
)
from test_span_bundle_receipt_batch_receipt_frontier import (
    FRONTIER_1,
)


# The receipts signed out by audit_bundle_receipt for each fixed bundle.
RECEIPT_1 = (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
    .audit_bundle_receipt(QBUNDLE_1)
)
RECEIPT_12 = (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
    .audit_bundle_receipt(QBUNDLE_12)
)
RECEIPT_FULL = (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
    .audit_bundle_receipt(QBUNDLE_FULL)
)


def receipt_for(start, bundle_digest, end, key=KEY):
    """A receipt with the NPBJ46 signature recomputed over the first
    four fields."""
    placeholder = SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt(
        1, start, bundle_digest, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=hmac.new(
            key,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_BUNDLE_RECEIPT_PREFIX
            + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                placeholder
            ),
            hashlib.sha256,
        ).digest(),
    )


class ReceiptFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt
                )
            ],
            ["version", "start", "bundle_digest", "end", "signature"],
        )
        self.assertNotIn("key", RECEIPT_1.__dict__)
        self.assertNotIn("mac", RECEIPT_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt(
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
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(QBUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, QFRONTIER_1.to_bytes())

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
        for bad in (1, "1", None, bytearray(QFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(RECEIPT_1, start=b"")
        # A non-empty canonical bundle-receipt frontier is valid too.
        receipt2 = receipt_for(
            QFRONTIER_1.to_bytes(),
            RECEIPT_1.bundle_digest,
            QFRONTIER_2.to_bytes(),
        )
        self.assertEqual(receipt2.start, QFRONTIER_1.to_bytes())

    def test_bundle_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)
        for bad in (b"", ZERO[:-1], ZERO + b"\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(QFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)
        # Empty, malformed and wrong-layer frontier bytes are value
        # errors: the end is a non-empty bundle-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, signature=bad)


class ReceiptEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = RECEIPT_12.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], b"".hex())
        self.assertEqual(
            outer[2], hashlib.sha256(QBUNDLE_12.to_bytes()).hexdigest()
        )
        self.assertEqual(outer[3], QFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], RECEIPT_12.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for receipt in (RECEIPT_1, RECEIPT_12, RECEIPT_FULL):
            raw = receipt.to_bytes()
            parsed = (
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    raw
                )
            )
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signature(self):
        unsigned = dataclasses.replace(RECEIPT_1, signature=ZERO)
        parsed = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                unsigned.to_bytes()
            )
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
            raw.replace(outer[4].encode(), outer[4].upper().encode()),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    bad
                )

    def test_wrong_json_shape_rejected(self):
        for bad in (b"{}", b"[1,2,3,4]", b"[1,2,3,4,5,6]"):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    bad
                )

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    bad
                )

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            hashlib.sha256(QBUNDLE_1.to_bytes()).hexdigest(),
            QFRONTIER_1.to_bytes().hex(),
            RECEIPT_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, 1),
            (3, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(
                (TypeError, ValueError), msg=(index, bad_value)
            ):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )


class ReceiptSignatureTest(unittest.TestCase):
    def test_signature_is_npbj46_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_BUNDLE_RECEIPT_PREFIX
            + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                RECEIPT_12
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_12.signature, expected)
        self.assertEqual(len(RECEIPT_12.signature), 32)
        joined = json.dumps(
            [
                RECEIPT_12.version,
                RECEIPT_12.start.hex(),
                RECEIPT_12.bundle_digest.hex(),
                RECEIPT_12.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(KEY, b"NPBJ46" + joined, hashlib.sha256).digest(),
            RECEIPT_12.signature,
        )

    def test_new_domain_label_distinct_from_bundle_layers(self):
        for label in (b"NPBJ43", b"NPBJ44", b"NPBJ45"):
            wrong = hmac.new(
                KEY,
                label
                + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                    RECEIPT_1
                ),
                hashlib.sha256,
            ).digest()
            self.assertNotEqual(wrong, RECEIPT_1.signature)


class AuditorAuditBundleReceiptSuccessTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_1)
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        receipt2 = auditor.audit_bundle_receipt(QBUNDLE_2)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        self.assertEqual(receipt2.start, QFRONTIER_1.to_bytes())
        self.assertEqual(receipt2.end, QFRONTIER_2.to_bytes())
        self.assertEqual(
            receipt2.bundle_digest,
            hashlib.sha256(QBUNDLE_2.to_bytes()).digest(),
        )

    def test_whole_segment_in_one_commit(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_12)
        self.assertEqual(receipt, RECEIPT_12)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_1.to_bytes())
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_receipt_round_trips_and_reviews(self):
        transported = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                RECEIPT_12.to_bytes()
            )
        )
        self.assertEqual(transported, RECEIPT_12)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                transported, QBUNDLE_12, KEY
            ),
            QFRONTIER_2,
        )

    def test_same_commit_mints_equal_receipts(self):
        first = (
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
            .audit_bundle_receipt(QBUNDLE_1)
        )
        second = (
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
            .audit_bundle_receipt(QBUNDLE_1)
        )
        self.assertEqual(first, second)
        self.assertEqual(first.to_bytes(), second.to_bytes())


class AuditorAuditBundleReceiptFailureTest(unittest.TestCase):
    def test_wrong_argument_kind_is_type_error(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        for bad in (
            1,
            "x",
            None,
            [QBUNDLE_1],
            (QBUNDLE_1,),
            object(),
            True,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_are_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]", QBUNDLE_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_and_tampered_rejected_without_receipt(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                OTHER_KEY
            ).audit_bundle_receipt(QBUNDLE_1)
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(
                dataclasses.replace(QBUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_same_bundle_replay_rejected_without_rollback(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_fork_rejected_after_commit(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_sequence_overflow_rejected_without_state_change(self):
        maxed = bundle_receipt_ledger_frontier_for(
            U64_MAX, FRONTIER_1.to_bytes(), QDIGEST_1
        )

        def qbundle_for(start, items, end, key=KEY):
            from nearproof import (
                _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_signature,
            )

            placeholder = SpanBundleReceiptBatchReceiptBundleReceiptBundle(
                1, start, items, end, ZERO
            )
            return dataclasses.replace(
                placeholder,
                signature=(
                    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_signature(
                        key, placeholder
                    )
                ),
            )

        from test_span_bundle_receipt_batch_receipt_bundle_receipt import (
            BRECEIPT_2,
        )
        from test_span_bundle_receipt_batch_receipt_bundle import BUNDLE_2

        overflow = qbundle_for(
            maxed.to_bytes(),
            ((BRECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            maxed.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(overflow)
        self.assertIs(auditor.checkpoint, before)

    def test_failure_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_12)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        self.assertEqual(receipt, RECEIPT_12)


class AuditorAuditBundleReceiptLinearizationTest(unittest.TestCase):
    def test_competing_commits_linearize(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        commits, failures = [], []
        barrier = threading.Barrier(2)

        def run(bundle, token):
            barrier.wait()
            try:
                auditor.audit_bundle_receipt(bundle)
                commits.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(target=run, args=(QBUNDLE_1, "first")),
            threading.Thread(target=run, args=(QBUNDLE_FULL, "full")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        if commits[0] == "first":
            auditor.audit_bundle(QBUNDLE_2)
            self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)

    def test_receipt_and_legacy_entries_share_one_lock(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(2)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        from test_span_bundle_receipt_batch_receipt_bundle_receipt import (
            BRECEIPT_FULL,
        )
        from test_span_bundle_receipt_batch_receipt_bundle import BUNDLE_FULL

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_bundle_receipt(QBUNDLE_12),
                    "receipt",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(BRECEIPT_FULL, BUNDLE_FULL),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        if successes[0] == "receipt":
            self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)


class AuditReceiptSuccessTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        self.assertEqual(audit(RECEIPT_1, QBUNDLE_1, KEY), QFRONTIER_1)
        self.assertEqual(audit(RECEIPT_12, QBUNDLE_12, KEY), QFRONTIER_2)
        self.assertEqual(audit(RECEIPT_FULL, QBUNDLE_FULL, KEY), QFRONTIER_FULL)

    def test_accepts_objects_or_canonical_bytes(self):
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        self.assertEqual(
            audit(RECEIPT_12.to_bytes(), QBUNDLE_12.to_bytes(), KEY),
            QFRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_1)
        result = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_FULL, QBUNDLE_FULL, KEY
            )
        )
        self.assertEqual(result, QFRONTIER_FULL)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)


class AuditReceiptViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        with self.assertRaises(ValueError):
            audit(RECEIPT_12, QBUNDLE_12, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit(RECEIPT_12, QBUNDLE_12, b"")

    def test_wrong_argument_kind_is_type_error(self):
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        for bad in (1, "x", None, [RECEIPT_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit(bad, QBUNDLE_1, KEY)
        for bad in (1, "x", None, [QBUNDLE_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit(RECEIPT_1, bad, KEY)
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit(RECEIPT_1, QBUNDLE_1, bad)

    def test_non_canonical_bytes_are_value_error(self):
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        raw = RECEIPT_1.to_bytes()
        for bad in (raw + b" ", b"junk", raw + b"\n"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit(bad, QBUNDLE_1, KEY)

    def test_tampered_signature_rejected(self):
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        with self.assertRaises(ValueError):
            audit(
                dataclasses.replace(RECEIPT_1, signature=ZERO),
                QBUNDLE_1,
                KEY,
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            b"NPBJ45"
            + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                RECEIPT_1
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                dataclasses.replace(RECEIPT_1, signature=wrong),
                QBUNDLE_1,
                KEY,
            )

    def test_bundle_digest_binds_one_bundle(self):
        # The receipt for QBUNDLE_12 does not attest QBUNDLE_1 even
        # though QBUNDLE_1 is a perfectly valid bundle on its own.
        audit = (
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        with self.assertRaises(ValueError):
            audit(RECEIPT_12, QBUNDLE_1, KEY)
        with self.assertRaises(ValueError):
            audit(RECEIPT_1, QBUNDLE_12, KEY)

    def test_tampered_bundle_digest_field_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                dataclasses.replace(RECEIPT_1, bundle_digest=ZERO),
                QBUNDLE_1,
                KEY,
            )

    def test_endpoint_mismatch_rejected(self):
        # An honestly signed receipt over QBUNDLE_1's digest but the
        # continuation endpoints: byte-for-byte endpoint comparison fails.
        forged = receipt_for(
            QFRONTIER_1.to_bytes(),
            RECEIPT_1.bundle_digest,
            QFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                forged, QBUNDLE_1, KEY
            )

    def test_invalid_bundle_still_rejected(self):
        # A receipt matching a tampered bundle byte for byte does not
        # rescue the bundle's own whole-bundle verification.
        bad_bundle = dataclasses.replace(QBUNDLE_1, signature=ZERO)
        receipt = receipt_for(
            b"",
            hashlib.sha256(bad_bundle.to_bytes()).digest(),
            QFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                receipt, bad_bundle, KEY
            )


class ParameterNamingTest(unittest.TestCase):
    def test_auditor_entry_param_named_x(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor.audit_bundle_receipt
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_stateless_audit_signature(self):
        signature = inspect.signature(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "bundle", "key"]
        )


if __name__ == "__main__":
    unittest.main()
