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
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_BUNDLE_PREFIX,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_content_bytes,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_signature,
    audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle,
    seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle,
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
from test_span_bundle_receipt_batch_receipt_bundle_receipt_frontier import (
    QDIGEST_1,
    QDIGEST_2,
    QFRONTIER_1,
    QFRONTIER_2,
    QFRONTIER_FULL,
    bundle_receipt_ledger_frontier_for,
)
from test_span_bundle_receipt_batch_receipt_frontier import (
    FRONTIER_1,
    FRONTIER_2,
)


def qbundle_for(start, items, end, key=KEY):
    """A bundle with the NPBJ45 signature recomputed over the first four
    fields; ``items`` is already a tuple of canonical (receipt, bundle)
    byte pairs."""
    placeholder = SpanBundleReceiptBatchReceiptBundleReceiptBundle(
        1, start, items, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_signature(
            key, placeholder
        ),
    )


# One committed bundle receipt from the empty ledger, its continuation,
# the two-commit segment in one bundle and the competing one-commit
# segment straight to the same ledger end.
QBUNDLE_1 = seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
    [(BRECEIPT_1, BUNDLE_1)], KEY
)
QBUNDLE_2 = seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
    [(BRECEIPT_2, BUNDLE_2)], KEY, start=QFRONTIER_1
)
QBUNDLE_12 = seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
    [(BRECEIPT_1, BUNDLE_1), (BRECEIPT_2, BUNDLE_2)], KEY
)
QBUNDLE_FULL = (
    seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
        [(BRECEIPT_FULL, BUNDLE_FULL)], KEY
    )
)


class BundleFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptBundleReceiptBundle
                )
            ],
            ["version", "start", "items", "end", "signature"],
        )
        self.assertNotIn("key", QBUNDLE_1.__dict__)
        self.assertNotIn("mac", QBUNDLE_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        bundle = SpanBundleReceiptBatchReceiptBundleReceiptBundle(
            1,
            QBUNDLE_1.start,
            QBUNDLE_1.items,
            QBUNDLE_1.end,
            QBUNDLE_1.signature,
        )
        self.assertEqual(bundle, QBUNDLE_1)
        self.assertEqual(hash(bundle), hash(QBUNDLE_1))
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(
            bundle.items, ((BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),)
        )
        self.assertEqual(bundle.end, QFRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            QBUNDLE_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(QBUNDLE_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(QFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, start=bad)
        for bad in (b"junk", b"[1,2,3]", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(QBUNDLE_1, start=b"")

    def test_items_contract(self):
        for bad in (1, "x", None, [QBUNDLE_1.items[0]]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, items=bad)
        # Empty and mis-shaped pairs are value errors.
        for bad in (
            (),
            ((BRECEIPT_1.to_bytes(),),),
            ((BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), b"x"),),
            ((b"junk", BUNDLE_1.to_bytes()),),
            ((BRECEIPT_1.to_bytes(), b"junk"),),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, items=bad)
        # Pair members of the wrong kind are type errors.
        for bad in (
            (1, BUNDLE_1.to_bytes()),
            (BRECEIPT_1.to_bytes(), None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, items=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(QFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, end=bad)
        # Empty, malformed and wrong-layer frontier bytes are value
        # errors: the end is a non-empty bundle-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(QBUNDLE_1, signature=bad)


class BundleEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = QBUNDLE_12.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], b"".hex())
        self.assertEqual(
            outer[2],
            [
                [BRECEIPT_1.to_bytes().hex(), BUNDLE_1.to_bytes().hex()],
                [BRECEIPT_2.to_bytes().hex(), BUNDLE_2.to_bytes().hex()],
            ],
        )
        self.assertEqual(outer[3], QFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], QBUNDLE_12.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for bundle in (QBUNDLE_1, QBUNDLE_2, QBUNDLE_12, QBUNDLE_FULL):
            raw = bundle.to_bytes()
            parsed = (
                SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                    raw
                )
            )
            self.assertEqual(parsed, bundle)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signatures(self):
        # A structurally valid bundle with an all-zero signature parses;
        # signatures are checked only by
        # audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle.
        unsigned = dataclasses.replace(QBUNDLE_1, signature=ZERO)
        parsed = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                unsigned.to_bytes()
            )
        )
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = QBUNDLE_1.to_bytes()
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
                SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                    bad
                )

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                    bad
                )

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [QBUNDLE_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                    bad
                )

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            [[BRECEIPT_1.to_bytes().hex(), BUNDLE_1.to_bytes().hex()]],
            QFRONTIER_1.to_bytes().hex(),
            QBUNDLE_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, "x"),
            (2, [[1, BUNDLE_1.to_bytes().hex()]]),
            (2, [[BRECEIPT_1.to_bytes().hex()]]),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(
                (TypeError, ValueError), msg=(index, bad_value)
            ):
                SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )


class BundleSignatureTest(unittest.TestCase):
    def test_signature_is_npbj45_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_RECEIPT_BUNDLE_PREFIX
            + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_content_bytes(
                QBUNDLE_12
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(QBUNDLE_12.signature, expected)
        self.assertEqual(len(QBUNDLE_12.signature), 32)
        joined = json.dumps(
            [
                QBUNDLE_12.version,
                QBUNDLE_12.start.hex(),
                [
                    [receipt.hex(), sealed.hex()]
                    for receipt, sealed in QBUNDLE_12.items
                ],
                QBUNDLE_12.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(KEY, b"NPBJ45" + joined, hashlib.sha256).digest(),
            QBUNDLE_12.signature,
        )

    def test_new_domain_label_distinct_from_receipt_and_frontier(self):
        # Signatures under the NPBJ42 receipt, NPBJ43 frontier and
        # NPBJ44 digest labels are not the bundle signature.
        for label in (b"NPBJ42", b"NPBJ43", b"NPBJ44"):
            wrong = hmac.new(
                KEY,
                label
                + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_content_bytes(
                    QBUNDLE_1
                ),
                hashlib.sha256,
            ).digest()
            self.assertNotEqual(wrong, QBUNDLE_1.signature)


class SealBundleSuccessTest(unittest.TestCase):
    def test_seals_genesis_segment(self):
        bundle = (
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_1, BUNDLE_1)], KEY
            )
        )
        self.assertEqual(bundle, QBUNDLE_1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.end, QFRONTIER_1.to_bytes())

    def test_seals_continuation_with_keyword_start(self):
        for start in (QFRONTIER_1, QFRONTIER_1.to_bytes()):
            bundle = seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_2, BUNDLE_2)], KEY, start=start
            )
            self.assertEqual(bundle, QBUNDLE_2)
            self.assertEqual(bundle.start, QFRONTIER_1.to_bytes())
            self.assertEqual(bundle.end, QFRONTIER_2.to_bytes())

    def test_seals_multi_item_segment(self):
        bundle = (
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_1, BUNDLE_1), (BRECEIPT_2, BUNDLE_2)], KEY
            )
        )
        self.assertEqual(bundle, QBUNDLE_12)
        self.assertEqual(
            bundle.items,
            (
                (BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
                (BRECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
            ),
        )

    def test_accepts_objects_or_canonical_bytes(self):
        bundle = (
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [
                    (BRECEIPT_1.to_bytes(), BUNDLE_1),
                    (BRECEIPT_2, BUNDLE_2.to_bytes()),
                ],
                KEY,
            )
        )
        self.assertEqual(bundle, QBUNDLE_12)

    def test_sealed_bundle_round_trips_and_audits(self):
        transported = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundle.from_bytes(
                QBUNDLE_12.to_bytes()
            )
        )
        self.assertEqual(transported, QBUNDLE_12)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                transported, KEY
            ),
            QFRONTIER_2,
        )

    def test_sealing_touches_no_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
            [(BRECEIPT_2, BUNDLE_2)], KEY, start=QFRONTIER_1
        )
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)


class SealBundleFailureTest(unittest.TestCase):
    def test_empty_sequence_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [], KEY
            )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                (), KEY
            )

    def test_non_iterable_and_wrong_member_kind_is_type_error(self):
        for bad in (1, None, object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    bad, KEY
                )
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [BRECEIPT_1], KEY
            )
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(1, BUNDLE_1)], KEY
            )
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_1, "x")], KEY
            )

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_1, BUNDLE_1)], b""
            )
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    [(BRECEIPT_1, BUNDLE_1)], bad
                )

    def test_start_is_keyword_only_and_checked(self):
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_2, BUNDLE_2)], KEY, QFRONTIER_1
            )
        for bad in (1, "x", [QFRONTIER_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    [(BRECEIPT_2, BUNDLE_2)], KEY, start=bad
                )
        for bad in (b"junk", QFRONTIER_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    [(BRECEIPT_2, BUNDLE_2)], KEY, start=bad
                )

    def test_broken_chain_rejected(self):
        # The continuation cannot start from the empty ledger...
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_2, BUNDLE_2)], KEY
            )
        # ...and the genesis cannot follow it.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_2, BUNDLE_2), (BRECEIPT_1, BUNDLE_1)],
                KEY,
                start=QFRONTIER_1,
            )
        # A start frontier the chain does not link to.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_1, BUNDLE_1)], KEY, start=QFRONTIER_1
            )

    def test_failed_receipt_verification_rejected(self):
        # A receipt/bundle pair that does not attest each other.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_2, BUNDLE_1)], KEY
            )
        # A pair signed under the wrong key.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_1, BUNDLE_1)], OTHER_KEY
            )

    def test_sequence_overflow_rejected(self):
        maxed = bundle_receipt_ledger_frontier_for(
            U64_MAX, FRONTIER_1.to_bytes(), QDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                [(BRECEIPT_2, BUNDLE_2)], KEY, start=maxed
            )


class AuditBundleSuccessTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_1, KEY
            ),
            QFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_2, KEY
            ),
            QFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_12, KEY
            ),
            QFRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_FULL, KEY
            ),
            QFRONTIER_FULL,
        )

    def test_accepts_object_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_12.to_bytes(), KEY
            ),
            QFRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_FULL, KEY
            ),
            QFRONTIER_FULL,
        )
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)


class AuditBundleViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_12, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                QBUNDLE_12, b""
            )

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [QBUNDLE_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    bad, KEY
                )
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    QBUNDLE_1, bad
                )

    def test_non_canonical_bytes_are_value_error(self):
        for bad in (
            QBUNDLE_1.to_bytes() + b" ",
            b"junk",
            QBUNDLE_1.to_bytes() + b"\n",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                    bad, KEY
                )

    def test_tampered_signature_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                dataclasses.replace(QBUNDLE_1, signature=ZERO), KEY
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            b"NPBJ43"
            + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_content_bytes(
                QBUNDLE_1
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                dataclasses.replace(QBUNDLE_1, signature=wrong), KEY
            )

    def test_tampered_items_rejected(self):
        # Honestly re-signed over swapped pairs: the chain no longer
        # links.
        swapped = qbundle_for(
            b"",
            (
                (BRECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
                (BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
            ),
            QFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                swapped, KEY
            )
        # Honestly re-signed over a mismatched pair.
        mismatched = qbundle_for(
            b"",
            ((BRECEIPT_1.to_bytes(), BUNDLE_2.to_bytes()),),
            QFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                mismatched, KEY
            )

    def test_forged_end_rejected(self):
        # Honestly re-signed over a forged end: the replayed frontier
        # does not reach it.
        forged = qbundle_for(
            b"",
            ((BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),),
            QFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                forged, KEY
            )

    def test_forged_start_rejected(self):
        # Honestly re-signed over a start the chain does not begin at.
        forged = qbundle_for(
            QFRONTIER_1.to_bytes(),
            ((BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),),
            QFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                forged, KEY
            )

    def test_tampered_endpoint_frontier_rejected(self):
        # The end frontier's own NPBJ43 layer is forged under another
        # key; the bundle itself is honestly re-signed over it.
        bad_end = bundle_receipt_ledger_frontier_for(
            2, FRONTIER_2.to_bytes(), QDIGEST_2, key=OTHER_KEY
        )
        forged = qbundle_for(
            b"",
            (
                (BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
                (BRECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
            ),
            bad_end.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle(
                forged, KEY
            )


class AuditorAuditBundleSuccessTest(unittest.TestCase):
    def test_returns_self_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(QBUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)
        self.assertIs(auditor.audit_bundle(QBUNDLE_2), auditor)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)

    def test_whole_segment_in_one_bundle(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_12)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_matches_per_receipt_ledger(self):
        via_bundle = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        via_bundle.audit_bundle(QBUNDLE_12)
        via_audit = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        via_audit.audit(BRECEIPT_1, BUNDLE_1)
        via_audit.audit(BRECEIPT_2, BUNDLE_2)
        self.assertEqual(via_bundle.checkpoint, via_audit.checkpoint)

    def test_mixed_bundle_and_single_commits(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit(BRECEIPT_1, BUNDLE_1)
        auditor.audit_bundle(QBUNDLE_2)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        other = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        other.audit_bundle(QBUNDLE_1)
        other.audit(BRECEIPT_2, BUNDLE_2)
        self.assertEqual(other.checkpoint, QFRONTIER_2)

    def test_restart_from_checkpoint_accepts_continuation(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_1)
        blob = auditor.checkpoint.to_bytes()
        for checkpoint in (auditor.checkpoint, blob):
            restored = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit_bundle(QBUNDLE_2)
            self.assertEqual(restored.checkpoint, QFRONTIER_2)


class AuditorAuditBundleFailureTest(unittest.TestCase):
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
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_are_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]", QBUNDLE_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_and_tampered_rejected(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
                OTHER_KEY
            ).audit_bundle(QBUNDLE_1)
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                dataclasses.replace(QBUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_first_bundle_must_start_empty(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(QBUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_same_bundle_replay_rejected_without_rollback(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle(QBUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(QBUNDLE_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_fork_rejected_after_commit(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        auditor.audit_bundle(QBUNDLE_1)
        before = auditor.checkpoint
        # The competing straight-to-end segment no longer links.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(QBUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)
        # And the two-commit bundle is rejected after the one-commit
        # full segment landed.
        other = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        other.audit_bundle(QBUNDLE_FULL)
        with self.assertRaises(ValueError):
            other.audit_bundle(QBUNDLE_12)
        self.assertEqual(other.checkpoint, QFRONTIER_FULL)

    def test_forged_end_rejected_without_state_change(self):
        forged = qbundle_for(
            b"",
            ((BRECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),),
            QFRONTIER_2.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(forged)
        self.assertIsNone(auditor.checkpoint)
        # The ledger is still usable afterwards.
        auditor.audit_bundle(QBUNDLE_1)
        self.assertEqual(auditor.checkpoint, QFRONTIER_1)

    def test_sequence_overflow_rejected_without_state_change(self):
        # A bundle-receipt frontier pinned at u64 max cannot accept one
        # more commit: the carried pair links to its ledger end, full
        # verification passes, but advancing the sequence overflows. The
        # bundle is honestly NPBJ45-signed over the maxed start so the
        # failure is the overflow itself.
        maxed = bundle_receipt_ledger_frontier_for(
            U64_MAX, FRONTIER_1.to_bytes(), QDIGEST_1
        )
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
            auditor.audit_bundle(overflow)
        self.assertIs(auditor.checkpoint, before)

    def test_failed_bundle_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(QBUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_bundle(QBUNDLE_12)
        self.assertEqual(auditor.checkpoint, QFRONTIER_2)


class AuditorAuditBundleLinearizationTest(unittest.TestCase):
    def test_competing_bundles_linearize(self):
        auditor = SpanBundleReceiptBatchReceiptBundleReceiptAuditor(KEY)
        commits, failures = [], []
        barrier = threading.Barrier(2)

        def run(bundle, token):
            barrier.wait()
            try:
                auditor.audit_bundle(bundle)
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
        # Whichever segment won, the ledger is consistent afterwards.
        if commits[0] == "first":
            auditor.audit_bundle(QBUNDLE_2)
            self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)

    def test_bundle_and_single_compete_on_one_lock(self):
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

        threads = [
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_bundle(QBUNDLE_12), "bundle"),
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
        if successes[0] == "bundle":
            self.assertEqual(auditor.checkpoint, QFRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, QFRONTIER_FULL)


class ParameterNamingTest(unittest.TestCase):
    def test_seal_signature(self):
        signature = inspect.signature(
            seal_span_bundle_receipt_batch_receipt_bundle_receipt_bundle
        )
        params = list(signature.parameters.values())
        self.assertEqual(
            [param.name for param in params], ["items", "key", "start"]
        )
        self.assertEqual(
            params[2].kind, inspect.Parameter.KEYWORD_ONLY
        )
        self.assertIsNone(params[2].default)

    def test_audit_bundle_param_named_x(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptBundleReceiptAuditor.audit_bundle
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_stateless_audit_signature(self):
        signature = inspect.signature(
            audit_span_bundle_receipt_batch_receipt_bundle_receipt_bundle
        )
        self.assertEqual(list(signature.parameters), ["x", "key"])


if __name__ == "__main__":
    unittest.main()
