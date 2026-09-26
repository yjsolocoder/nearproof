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
    SpanBundleReceiptBatchReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_PREFIX,
    _span_bundle_receipt_batch_receipt_bundle_content_bytes,
    _span_bundle_receipt_batch_receipt_bundle_signature,
    _span_bundle_receipt_batch_receipt_frontier_signature,
    audit_span_bundle_receipt_batch_receipt_bundle,
    seal_span_bundle_receipt_batch_receipt_bundle,
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
from test_span_bundle_receipt_batch_receipt_frontier import (
    DIGEST_1,
    DIGEST_2,
    FRONTIER_1,
    FRONTIER_2,
    FRONTIER_FULL,
    commit_frontier_for,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
)


def bundle_for(start, items, end, key=KEY):
    """A bundle with the NPBJ41 signature recomputed over the first four
    fields; ``items`` is already a tuple of canonical (receipt, batch)
    byte pairs."""
    placeholder = SpanBundleReceiptBatchReceiptBundle(
        1, start, items, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_bundle_signature(
            key, placeholder
        ),
    )


# One committed batch receipt from the empty ledger, its continuation,
# the two-commit segment in one bundle and the competing one-commit
# segment straight to the same ledger end.
BUNDLE_1 = seal_span_bundle_receipt_batch_receipt_bundle(
    [(CRECEIPT_1, BATCH_1)], KEY
)
BUNDLE_2 = seal_span_bundle_receipt_batch_receipt_bundle(
    [(CRECEIPT_2, BATCH_2)], KEY, start=FRONTIER_1
)
BUNDLE_12 = seal_span_bundle_receipt_batch_receipt_bundle(
    [(CRECEIPT_1, BATCH_1), (CRECEIPT_2, BATCH_2)], KEY
)
BUNDLE_FULL = seal_span_bundle_receipt_batch_receipt_bundle(
    [(CRECEIPT_FULL, BATCH_FULL)], KEY
)


class BundleFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptBundle
                )
            ],
            ["version", "start", "items", "end", "signature"],
        )
        self.assertNotIn("key", BUNDLE_1.__dict__)
        self.assertNotIn("mac", BUNDLE_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        bundle = SpanBundleReceiptBatchReceiptBundle(
            1,
            BUNDLE_1.start,
            BUNDLE_1.items,
            BUNDLE_1.end,
            BUNDLE_1.signature,
        )
        self.assertEqual(bundle, BUNDLE_1)
        self.assertEqual(hash(bundle), hash(BUNDLE_1))
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(
            bundle.items, ((CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),)
        )
        self.assertEqual(bundle.end, FRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BUNDLE_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BUNDLE_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BUNDLE_1, start=b"")

    def test_items_contract(self):
        for bad in (1, "x", None, [BUNDLE_1.items[0]]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, items=bad)
        # Empty and mis-shaped pairs are value errors.
        for bad in (
            (),
            ((CRECEIPT_1.to_bytes(),),),
            ((CRECEIPT_1.to_bytes(), BATCH_1.to_bytes(), b"x"),),
            ((b"junk", BATCH_1.to_bytes()),),
            ((CRECEIPT_1.to_bytes(), b"junk"),),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, items=bad)
        # Pair members of the wrong kind are type errors.
        for bad in (
            (1, BATCH_1.to_bytes()),
            (CRECEIPT_1.to_bytes(), None),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, items=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty batch-receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, signature=bad)


class BundleEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = BUNDLE_12.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], b"".hex())
        self.assertEqual(
            outer[2],
            [
                [CRECEIPT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()],
                [CRECEIPT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()],
            ],
        )
        self.assertEqual(outer[3], FRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], BUNDLE_12.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for bundle in (BUNDLE_1, BUNDLE_2, BUNDLE_12, BUNDLE_FULL):
            raw = bundle.to_bytes()
            parsed = SpanBundleReceiptBatchReceiptBundle.from_bytes(raw)
            self.assertEqual(parsed, bundle)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signatures(self):
        # A structurally valid bundle with an all-zero signature parses;
        # signatures are checked only by
        # audit_span_bundle_receipt_batch_receipt_bundle.
        unsigned = dataclasses.replace(BUNDLE_1, signature=ZERO)
        parsed = SpanBundleReceiptBatchReceiptBundle.from_bytes(
            unsigned.to_bytes()
        )
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = BUNDLE_1.to_bytes()
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
                SpanBundleReceiptBatchReceiptBundle.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundle.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [BUNDLE_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundle.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            [[CRECEIPT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()]],
            FRONTIER_1.to_bytes().hex(),
            BUNDLE_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, "x"),
            (2, [[1, BATCH_1.to_bytes().hex()]]),
            (2, [[CRECEIPT_1.to_bytes().hex()]]),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(
                (TypeError, ValueError), msg=(index, bad_value)
            ):
                SpanBundleReceiptBatchReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )


class BundleSignatureTest(unittest.TestCase):
    def test_signature_is_npbj41_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_BUNDLE_PREFIX
            + _span_bundle_receipt_batch_receipt_bundle_content_bytes(
                BUNDLE_12
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BUNDLE_12.signature, expected)
        self.assertEqual(len(BUNDLE_12.signature), 32)
        joined = json.dumps(
            [
                BUNDLE_12.version,
                BUNDLE_12.start.hex(),
                [
                    [receipt.hex(), batch.hex()]
                    for receipt, batch in BUNDLE_12.items
                ],
                BUNDLE_12.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(KEY, b"NPBJ41" + joined, hashlib.sha256).digest(),
            BUNDLE_12.signature,
        )

    def test_new_domain_label_distinct_from_receipt_and_frontier(self):
        # Signatures under the NPBJ39 receipt and NPBJ40 frontier labels
        # are not the bundle signature.
        for label in (b"NPBJ39", b"NPBJ40"):
            wrong = hmac.new(
                KEY,
                label
                + _span_bundle_receipt_batch_receipt_bundle_content_bytes(
                    BUNDLE_1
                ),
                hashlib.sha256,
            ).digest()
            self.assertNotEqual(wrong, BUNDLE_1.signature)


class SealBundleSuccessTest(unittest.TestCase):
    def test_seals_genesis_segment(self):
        bundle = seal_span_bundle_receipt_batch_receipt_bundle(
            [(CRECEIPT_1, BATCH_1)], KEY
        )
        self.assertEqual(bundle, BUNDLE_1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.end, FRONTIER_1.to_bytes())

    def test_seals_continuation_with_keyword_start(self):
        for start in (FRONTIER_1, FRONTIER_1.to_bytes()):
            bundle = seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_2, BATCH_2)], KEY, start=start
            )
            self.assertEqual(bundle, BUNDLE_2)
            self.assertEqual(bundle.start, FRONTIER_1.to_bytes())
            self.assertEqual(bundle.end, FRONTIER_2.to_bytes())

    def test_seals_multi_item_segment(self):
        bundle = seal_span_bundle_receipt_batch_receipt_bundle(
            [(CRECEIPT_1, BATCH_1), (CRECEIPT_2, BATCH_2)], KEY
        )
        self.assertEqual(bundle, BUNDLE_12)
        self.assertEqual(
            bundle.items,
            (
                (CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),
                (CRECEIPT_2.to_bytes(), BATCH_2.to_bytes()),
            ),
        )

    def test_accepts_objects_or_canonical_bytes(self):
        bundle = seal_span_bundle_receipt_batch_receipt_bundle(
            [
                (CRECEIPT_1.to_bytes(), BATCH_1),
                (CRECEIPT_2, BATCH_2.to_bytes()),
            ],
            KEY,
        )
        self.assertEqual(bundle, BUNDLE_12)

    def test_sealed_bundle_round_trips_and_audits(self):
        transported = SpanBundleReceiptBatchReceiptBundle.from_bytes(
            BUNDLE_12.to_bytes()
        )
        self.assertEqual(transported, BUNDLE_12)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(
                transported, KEY
            ),
            FRONTIER_2,
        )

    def test_sealing_touches_no_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        seal_span_bundle_receipt_batch_receipt_bundle(
            [(CRECEIPT_2, BATCH_2)], KEY, start=FRONTIER_1
        )
        self.assertEqual(auditor.checkpoint, FRONTIER_1)


class SealBundleFailureTest(unittest.TestCase):
    def test_empty_sequence_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle([], KEY)
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle((), KEY)

    def test_non_iterable_and_wrong_member_kind_is_type_error(self):
        for bad in (1, None, object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle(bad, KEY)
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [CRECEIPT_1], KEY
            )
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(1, BATCH_1)], KEY
            )
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_1, "x")], KEY
            )

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_1, BATCH_1)], b""
            )
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle(
                    [(CRECEIPT_1, BATCH_1)], bad
                )

    def test_start_is_keyword_only_and_checked(self):
        with self.assertRaises(TypeError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_2, BATCH_2)], KEY, FRONTIER_1
            )
        for bad in (1, "x", [FRONTIER_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle(
                    [(CRECEIPT_2, BATCH_2)], KEY, start=bad
                )
        for bad in (b"junk", FRONTIER_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                seal_span_bundle_receipt_batch_receipt_bundle(
                    [(CRECEIPT_2, BATCH_2)], KEY, start=bad
                )

    def test_broken_chain_rejected(self):
        # The continuation cannot start from the empty ledger...
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_2, BATCH_2)], KEY
            )
        # ...and the genesis cannot follow it.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_2, BATCH_2), (CRECEIPT_1, BATCH_1)],
                KEY,
                start=FRONTIER_1,
            )
        # A start frontier the chain does not link to.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_1, BATCH_1)], KEY, start=FRONTIER_1
            )

    def test_failed_receipt_verification_rejected(self):
        # A receipt/batch pair that does not attest each other.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_2, BATCH_1)], KEY
            )
        # A pair signed under the wrong key.
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_1, BATCH_1)], OTHER_KEY
            )

    def test_sequence_overflow_rejected(self):
        maxed = commit_frontier_for(
            U64_MAX, PFRONTIER_1.to_bytes(), DIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_span_bundle_receipt_batch_receipt_bundle(
                [(CRECEIPT_2, BATCH_2)], KEY, start=maxed
            )


class AuditBundleSuccessTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(BUNDLE_1, KEY),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(BUNDLE_2, KEY),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(
                BUNDLE_12, KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(
                BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )

    def test_accepts_object_or_canonical_bytes(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(
                BUNDLE_12.to_bytes(), KEY
            ),
            FRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt_bundle(
                BUNDLE_FULL, KEY
            ),
            FRONTIER_FULL,
        )
        self.assertEqual(auditor.checkpoint, FRONTIER_1)


class AuditBundleViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(
                BUNDLE_12, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(BUNDLE_12, b"")

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [BUNDLE_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle(bad, KEY)
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle(
                    BUNDLE_1, bad
                )

    def test_non_canonical_bytes_are_value_error(self):
        for bad in (
            BUNDLE_1.to_bytes() + b" ",
            b"junk",
            BUNDLE_1.to_bytes() + b"\n",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt_bundle(bad, KEY)

    def test_tampered_signature_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(
                dataclasses.replace(BUNDLE_1, signature=ZERO), KEY
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            b"NPBJ40"
            + _span_bundle_receipt_batch_receipt_bundle_content_bytes(
                BUNDLE_1
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(
                dataclasses.replace(BUNDLE_1, signature=wrong), KEY
            )

    def test_tampered_items_rejected(self):
        # Honestly re-signed over swapped pairs: the chain no longer
        # links.
        swapped = bundle_for(
            b"",
            (
                (CRECEIPT_2.to_bytes(), BATCH_2.to_bytes()),
                (CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),
            ),
            FRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(swapped, KEY)
        # Honestly re-signed over a mismatched pair.
        mismatched = bundle_for(
            b"",
            ((CRECEIPT_1.to_bytes(), BATCH_2.to_bytes()),),
            FRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(mismatched, KEY)

    def test_forged_end_rejected(self):
        # Honestly re-signed over a forged end: the replayed frontier
        # does not reach it.
        forged = bundle_for(
            b"",
            ((CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(forged, KEY)

    def test_forged_start_rejected(self):
        # Honestly re-signed over a start the chain does not begin at.
        forged = bundle_for(
            FRONTIER_1.to_bytes(),
            ((CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(forged, KEY)

    def test_tampered_endpoint_frontier_rejected(self):
        # The end frontier's own NPBJ40 layer is forged under another
        # key; the bundle itself is honestly re-signed over it.
        bad_end = commit_frontier_for(
            2, PFRONTIER_2.to_bytes(), DIGEST_2, key=OTHER_KEY
        )
        forged = bundle_for(
            b"",
            (
                (CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),
                (CRECEIPT_2.to_bytes(), BATCH_2.to_bytes()),
            ),
            bad_end.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt_bundle(forged, KEY)


class AuditorAuditBundleSuccessTest(unittest.TestCase):
    def test_returns_self_and_advances(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertIs(auditor.audit_bundle(BUNDLE_2), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_whole_segment_in_one_bundle(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_12)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_matches_per_receipt_ledger(self):
        via_bundle = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_bundle.audit_bundle(BUNDLE_12)
        via_audit = SpanBundleReceiptBatchReceiptAuditor(KEY)
        via_audit.audit(CRECEIPT_1, BATCH_1)
        via_audit.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(via_bundle.checkpoint, via_audit.checkpoint)

    def test_mixed_bundle_and_single_commits(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        other = SpanBundleReceiptBatchReceiptAuditor(KEY)
        other.audit_bundle(BUNDLE_1)
        other.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(other.checkpoint, FRONTIER_2)

    def test_restart_from_checkpoint_accepts_continuation(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        blob = auditor.checkpoint.to_bytes()
        for checkpoint in (auditor.checkpoint, blob):
            restored = SpanBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit_bundle(BUNDLE_2)
            self.assertEqual(restored.checkpoint, FRONTIER_2)


class AuditorAuditBundleFailureTest(unittest.TestCase):
    def test_wrong_argument_kind_is_type_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], (BUNDLE_1,), object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_are_value_error(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]", BUNDLE_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_and_tampered_rejected(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptAuditor(
                OTHER_KEY
            ).audit_bundle(BUNDLE_1)
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                dataclasses.replace(BUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_first_bundle_must_start_empty(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_same_bundle_replay_rejected_without_rollback(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_fork_rejected_after_commit(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        before = auditor.checkpoint
        # The competing straight-to-end segment no longer links.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)
        # And the two-commit bundle is rejected after the one-commit
        # full segment landed.
        other = SpanBundleReceiptBatchReceiptAuditor(KEY)
        other.audit_bundle(BUNDLE_FULL)
        with self.assertRaises(ValueError):
            other.audit_bundle(BUNDLE_12)
        self.assertEqual(other.checkpoint, FRONTIER_FULL)

    def test_forged_end_rejected_without_state_change(self):
        forged = bundle_for(
            b"",
            ((CRECEIPT_1.to_bytes(), BATCH_1.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(forged)
        self.assertIsNone(auditor.checkpoint)
        # The ledger is still usable afterwards.
        auditor.audit_bundle(BUNDLE_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_sequence_overflow_rejected_without_state_change(self):
        maxed = commit_frontier_for(
            U64_MAX, PFRONTIER_1.to_bytes(), DIGEST_1
        )
        auditor = SpanBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_failed_bundle_then_recovers(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_bundle(BUNDLE_12)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)


class AuditorAuditBundleLinearizationTest(unittest.TestCase):
    def test_competing_bundles_linearize(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
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
            threading.Thread(target=run, args=(BUNDLE_1, "first")),
            threading.Thread(target=run, args=(BUNDLE_FULL, "full")),
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
            auditor.audit_bundle(BUNDLE_2)
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, FRONTIER_FULL)

    def test_bundle_and_single_compete_on_one_lock(self):
        auditor = SpanBundleReceiptBatchReceiptAuditor(KEY)
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
                args=(lambda: auditor.audit_bundle(BUNDLE_12), "bundle"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(CRECEIPT_FULL, BATCH_FULL),
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
            self.assertEqual(auditor.checkpoint, FRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, FRONTIER_FULL)


class ParameterNamingTest(unittest.TestCase):
    def test_seal_signature(self):
        signature = inspect.signature(
            seal_span_bundle_receipt_batch_receipt_bundle
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
            SpanBundleReceiptBatchReceiptAuditor.audit_bundle
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])


if __name__ == "__main__":
    unittest.main()
