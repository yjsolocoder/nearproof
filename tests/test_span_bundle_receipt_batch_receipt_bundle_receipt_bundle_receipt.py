import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_BUNDLE_RECEIPT_PREFIX,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_signature,
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
    qbundle_for,
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


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPBJ46 signature recomputed
    over the first four fields; ``start``/``end``/``digest`` default to
    the honest values."""
    placeholder = SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt(
        1,
        bundle.start if start is None else start,
        hashlib.sha256(bundle.to_bytes()).digest()
        if digest is None
        else digest,
        bundle.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_signature(
            key, placeholder
        ),
    )


RECEIPT_1 = receipt_for(QBUNDLE_1)
RECEIPT_2 = receipt_for(QBUNDLE_2)
RECEIPT_12 = receipt_for(QBUNDLE_12)
RECEIPT_FULL = receipt_for(QBUNDLE_FULL)


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
        for bad in (b"junk", b"[1,2,3]", FRONTIER_1.to_bytes()):
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
        self.assertEqual(outer[1], QBUNDLE_12.start.hex())
        self.assertEqual(
            outer[2],
            hashlib.sha256(QBUNDLE_12.to_bytes()).hexdigest(),
        )
        self.assertEqual(outer[3], QFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], RECEIPT_12.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_12, RECEIPT_FULL):
            raw = receipt.to_bytes()
            parsed = (
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    raw
                )
            )
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signature(self):
        # A structurally valid receipt with an all-zero signature
        # parses; the signature is checked only by
        # audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt.
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
            # Uppercase hex.
            raw.replace(
                outer[4].encode(), outer[4].upper().encode()
            ),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    bad
                )

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
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
            RECEIPT_1.start.hex(),
            RECEIPT_1.bundle_digest.hex(),
            RECEIPT_1.end.hex(),
            RECEIPT_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, 64),
            (3, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(
                TypeError, msg=(index, bad_value)
            ):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_bad_field_values(self):
        good = [
            1,
            RECEIPT_1.start.hex(),
            RECEIPT_1.bundle_digest.hex(),
            RECEIPT_1.end.hex(),
            RECEIPT_1.signature.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (2, "00"),
            (3, ""),
            (3, "junk"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(
                ValueError, msg=(index, bad_value)
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
        # The domain label and the encoding are concatenated directly
        # with no delimiter or length prefix: inserting either breaks
        # the signature.
        for separator in (b"", b"|", b"\x00", b"\x00\x00"):
            if not separator:
                continue
            wrong = hmac.new(
                KEY,
                b"NPBJ46"
                + separator
                + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                    RECEIPT_12
                ),
                hashlib.sha256,
            ).digest()
            self.assertNotEqual(wrong, RECEIPT_12.signature)

    def test_new_domain_label_distinct_from_inner_layers(self):
        # HMACs under other labels are never the NPBJ46 receipt
        # signature, even over the same first-four encoding.
        content = (
            _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                RECEIPT_1
            )
        )
        for label in (b"NPBJ42", b"NPBJ43", b"NPBJ45"):
            wrong = hmac.new(
                KEY, label + content, hashlib.sha256
            ).digest()
            self.assertNotEqual(wrong, RECEIPT_1.signature)


class AuditorAuditBundleReceiptSuccessTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_1)
        self.assertIsInstance(
            receipt,
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt,
        )
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(QBUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, QFRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_receipt_signature_verifies(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_12)
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_signature(
                KEY, receipt
            ),
        )
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_1.to_bytes())
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_continues_from_non_empty_frontier(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(QBUNDLE_1)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_2)
        self.assertEqual(receipt, RECEIPT_2)
        self.assertEqual(receipt.start, QFRONTIER_1.to_bytes())
        self.assertEqual(receipt.end, QFRONTIER_2.to_bytes())
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)

    def test_whole_segment_in_one_commit(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_FULL)
        self.assertEqual(receipt, RECEIPT_FULL)
        self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)

    def test_receipt_round_trips_and_reviews(self):
        # The observable contract: the receipt round-trips byte for
        # byte and an independent review returns the end frontier.
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_12)
        transported = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceipt.from_bytes(
                receipt.to_bytes()
            )
        )
        self.assertEqual(transported, receipt)
        self.assertEqual(transported.to_bytes(), receipt.to_bytes())
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                transported, QBUNDLE_12, KEY
            ),
            QFRONTIER_2,
        )

    def test_mixed_with_legacy_entries(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_1)
        receipt = auditor.audit_bundle_receipt(QBUNDLE_2)
        self.assertEqual(receipt, RECEIPT_2)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)


class AuditorAuditBundleReceiptFailureTest(unittest.TestCase):
    def test_replay_rejected_without_rollback_or_receipt(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        first = auditor.audit_bundle_receipt(QBUNDLE_1)
        before = auditor.checkpoint
        # The already committed bundle no longer starts at the advanced
        # frontier.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)
        # The first receipt remains the only one minted.
        self.assertEqual(first, RECEIPT_1)

    def test_old_fork_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(QBUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_bundle_rejected(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        tampered = dataclasses.replace(QBUNDLE_1, signature=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(tampered)
        self.assertIsNone(auditor.checkpoint)
        # The ledger is still usable afterwards.
        receipt = auditor.audit_bundle_receipt(QBUNDLE_1)
        self.assertEqual(receipt, RECEIPT_1)

    def test_forged_end_rejected_without_state_change(self):
        forged = qbundle_for(
            b"",
            (
                (
                    QBUNDLE_1.items[0][0],
                    QBUNDLE_1.items[0][1],
                ),
            ),
            QFRONTIER_2.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(forged)
        self.assertIsNone(auditor.checkpoint)

    def test_sequence_overflow_rejected(self):
        maxed = bundle_receipt_ledger_frontier_for(
            U64_MAX, FRONTIER_1.to_bytes(), QDIGEST_1
        )
        overflow = qbundle_for(
            maxed.to_bytes(),
            (
                (
                    QBUNDLE_2.items[0][0],
                    QBUNDLE_2.items[0][1],
                ),
            ),
            maxed.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(overflow)
        self.assertIs(auditor.checkpoint, before)

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

    def test_malformed_bytes_is_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]", QBUNDLE_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_audit_bundle_interface_unchanged(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(QBUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        # audit_bundle mints no receipt: it still returns the auditor.
        result = auditor.audit_bundle(QBUNDLE_2)
        self.assertIs(result, auditor)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)


class AuditorAuditBundleReceiptLinearizationTest(unittest.TestCase):
    def test_competing_commits_linearize_on_one_lock(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        receipts, failures = [], []
        barrier = threading.Barrier(2)

        def run(bundle, token):
            barrier.wait()
            try:
                receipts.append((token, auditor.audit_bundle_receipt(bundle)))
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run, args=(QBUNDLE_1, "first")
            ),
            threading.Thread(
                target=run, args=(QBUNDLE_FULL, "full")
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        # The one minted receipt attests exactly the committed bundle.
        token, receipt = receipts[0]
        if token == "first":
            self.assertEqual(receipt, RECEIPT_1)
            self.assertEqual(
                receipt.end, auditor.checkpoint.to_bytes()
            )
            self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        else:
            self.assertEqual(receipt, RECEIPT_FULL)
            self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)

    def test_receipt_and_plain_bundle_compete_on_one_lock(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(2)

        def run(action, token):
            barrier.wait()
            try:
                successes.append((token, action()))
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_bundle_receipt(QBUNDLE_1),
                    "receipt",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_bundle(QBUNDLE_FULL), "bundle"),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        token, _result = successes[0]
        if token == "receipt":
            self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        else:
            self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)


class AuditReceiptSuccessTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_1, QBUNDLE_1, KEY
            ),
            QFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_2, QBUNDLE_2, KEY
            ),
            QFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_12, QBUNDLE_12, KEY
            ),
            QFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_FULL, QBUNDLE_FULL, KEY
            ),
            QFRONTIER_FULL,
        )

    def test_accepts_objects_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_12.to_bytes(), QBUNDLE_12.to_bytes(), KEY
            ),
            QFRONTIER_2,
        )

    def test_pure_check_touches_no_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(QBUNDLE_1)
        # Reviewing the independent segment changes no frontier; even a
        # segment whose start does not match the auditor's checkpoint
        # reviews fine because review is stateless.
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_FULL, QBUNDLE_FULL, KEY
            ),
            QFRONTIER_FULL,
        )
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)


class AuditReceiptViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_12, QBUNDLE_12, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_12, QBUNDLE_12, b""
            )

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                    bad, QBUNDLE_1, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                    RECEIPT_1, bad, KEY
                )
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                    RECEIPT_1, QBUNDLE_1, bad
                )

    def test_non_canonical_bytes_are_value_error(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                b"junk", QBUNDLE_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_1.to_bytes().replace(b",", b", "),
                QBUNDLE_1,
                KEY,
            )

    def test_tampered_receipt_signature_rejected(self):
        tampered = dataclasses.replace(RECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                tampered, QBUNDLE_1, KEY
            )

    def test_wrong_domain_label_rejected(self):
        content = (
            _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_content_bytes(
                RECEIPT_1
            )
        )
        wrong = hmac.new(
            KEY, b"NPBJ45" + content, hashlib.sha256
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                dataclasses.replace(RECEIPT_1, signature=wrong),
                QBUNDLE_1,
                KEY,
            )

    def test_bundle_digest_binds_one_bundle(self):
        # The receipt only attests the exact bundle whose canonical
        # bytes hash to its bundle digest: another bundle over
        # overlapping endpoints is rejected.
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_1, QBUNDLE_12, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_12, QBUNDLE_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                RECEIPT_FULL, QBUNDLE_12, KEY
            )

    def test_tampered_bundle_digest_field(self):
        tampered = receipt_for(QBUNDLE_1, digest=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                tampered, QBUNDLE_1, KEY
            )

    def test_endpoint_mismatch(self):
        # Receipt signature and bundle digest both verify against
        # QBUNDLE_1, but the claimed start/end are different.
        mismatched = receipt_for(
            QBUNDLE_1,
            start=QFRONTIER_1.to_bytes(),
            end=QFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt(
                mismatched, QBUNDLE_1, KEY
            )

    def test_invalid_bundle_still_rejected(self):
        # An honestly NPBJ45-signed bundle whose forged end the
        # replayed chain does not reach, with a receipt honestly
        # attesting that bundle's own bytes and endpoints: the receipt
        # signature, digest and endpoint checks pass, but the bundle
        # itself fails whole-bundle verification.
        bad_bundle = qbundle_for(
            b"",
            (
                (
                    QBUNDLE_1.items[0][0],
                    QBUNDLE_1.items[0][1],
                ),
            ),
            QFRONTIER_2.to_bytes(),
        )
        receipt = receipt_for(bad_bundle)
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

    def test_stateless_review_signature(self):
        signature = inspect.signature(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "bundle", "key"]
        )


if __name__ == "__main__":
    unittest.main()
