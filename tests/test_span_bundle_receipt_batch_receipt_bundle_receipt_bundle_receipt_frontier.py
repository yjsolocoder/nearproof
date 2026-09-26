import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor,
    SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_content_bytes,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_next_digest,
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_signature,
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
from test_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt import (
    RECEIPT_1,
    RECEIPT_12,
    RECEIPT_FULL,
)
from test_span_bundle_receipt_batch_receipt_bundle_receipt_frontier import (
    QDIGEST_1,
    QFRONTIER_1,
    QFRONTIER_2,
    QFRONTIER_FULL,
    bundle_receipt_ledger_frontier_for,
)
from test_span_bundle_receipt_batch_receipt_frontier import (
    DIGEST_1,
    FRONTIER_1,
    commit_frontier_for,
)
from test_span_bundle_receipt_frontier import PFRONTIER_1


# The commit receipt over the continuation bundle QBUNDLE_2, signed out
# by the bundle-receipt ledger auditor restored from QFRONTIER_1.
RECEIPT_2 = (
    SpanBundleReceiptBatchReceiptBundleReceiptAuditor(
        KEY, checkpoint=QFRONTIER_1
    ).audit_bundle_receipt(QBUNDLE_2)
)


def bundle_commit_receipt_ledger_frontier_for(
    sequence, end, digest, key=KEY
):
    """An NPBJ47-signed bundle-commit-receipt ledger frontier over the
    given fields."""
    placeholder = (
        SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier(
            1, sequence, end, digest, ZERO
        )
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_signature(
            key, placeholder
        ),
    )


# One commit receipt starting empty and ending at QFRONTIER_1.
RDIGEST_1 = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_next_digest(
        ZERO, 1, RECEIPT_1.to_bytes()
    )
)
# Continuation receipt from QFRONTIER_1 to QFRONTIER_2.
RDIGEST_2 = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_next_digest(
        RDIGEST_1, 2, RECEIPT_2.to_bytes()
    )
)
# The two-commit segment in one commit receipt: a fork competing with
# RECEIPT_1 for the first sequence slot.
RDIGEST_12 = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_next_digest(
        ZERO, 1, RECEIPT_12.to_bytes()
    )
)
# A single receipt straight to QFRONTIER_FULL: another first-slot fork.
RDIGEST_FULL = (
    _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_next_digest(
        ZERO, 1, RECEIPT_FULL.to_bytes()
    )
)
RFRONTIER_1 = bundle_commit_receipt_ledger_frontier_for(
    1, QFRONTIER_1.to_bytes(), RDIGEST_1
)
RFRONTIER_2 = bundle_commit_receipt_ledger_frontier_for(
    2, QFRONTIER_2.to_bytes(), RDIGEST_2
)
RFRONTIER_12 = bundle_commit_receipt_ledger_frontier_for(
    1, QFRONTIER_2.to_bytes(), RDIGEST_12
)
RFRONTIER_FULL = bundle_commit_receipt_ledger_frontier_for(
    1, QFRONTIER_FULL.to_bytes(), RDIGEST_FULL
)


class BundleCommitReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier
                )
            ],
            ["version", "sequence", "end", "digest", "signature"],
        )
        self.assertNotIn("key", RFRONTIER_1.__dict__)
        self.assertNotIn("mac", RFRONTIER_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier(
                1,
                1,
                QFRONTIER_1.to_bytes(),
                RDIGEST_1,
                RFRONTIER_1.signature,
            )
        )
        self.assertEqual(frontier, RFRONTIER_1)
        self.assertEqual(hash(frontier), hash(RFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, QFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, RDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RFRONTIER_1.signature = ZERO

    def test_no_alias_attributes(self):
        self.assertEqual(
            sorted(field.name for field in dataclasses.fields(RFRONTIER_1)),
            ["digest", "end", "sequence", "signature", "version"],
        )

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, sequence=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(QFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, end=bad)
        # Empty, malformed and wrong-layer frontier bytes are value
        # errors: the end is a non-empty bundle-receipt ledger frontier.
        for bad in (
            b"",
            b"junk",
            b"[1,2,3]",
            FRONTIER_1.to_bytes(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "1", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(RFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(RFRONTIER_1, **{name: bad})


class BundleCommitReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + QFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + RDIGEST_1.hex().encode() + b'",'
            b'"' + RFRONTIER_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(RFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (RFRONTIER_1, RFRONTIER_2, RFRONTIER_FULL):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                    blob
                ),
                frontier,
            )
            self.assertEqual(
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                    blob
                ).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = RFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
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
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                    bad
                )

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            QFRONTIER_1.to_bytes().hex(),
            RDIGEST_1.hex(),
            RFRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            RFRONTIER_1.signature.hex().encode(),
            RFRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                upper
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            1,
            QFRONTIER_1.to_bytes().hex(),
            RDIGEST_1.hex(),
            RFRONTIER_1.signature.hex(),
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
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the frontier signature nor the nested endpoint
        # signatures are checked at parse time.
        tampered = dataclasses.replace(RFRONTIER_1, signature=ZERO)
        parsed = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptFrontier.from_bytes(
                tampered.to_bytes()
            )
        )
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_signature_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ48"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(RDIGEST_1, expected_digest)
        expected_signature = hmac.new(
            KEY,
            b"NPBJ47"
            + _span_bundle_receipt_batch_receipt_bundle_receipt_bundle_receipt_frontier_content_bytes(
                RFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RFRONTIER_1.signature, expected_signature)


class BundleCommitReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                    bad
                )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                b""
            )

    def test_empty_checkpoint_is_empty_ledger(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            RFRONTIER_1,
            RFRONTIER_1.to_bytes(),
        ):
            auditor = SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [RFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(RFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_endpoint_frontier_signature_verified(self):
        # The nested bundle-receipt ledger frontier's own NPBJ43 layer
        # is recomputed on load; re-sign the outer layer so only it
        # fails.
        bad_end = dataclasses.replace(QFRONTIER_1, signature=ZERO)
        tampered = bundle_commit_receipt_ledger_frontier_for(
            1, bad_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_deep_nested_signature_verified(self):
        # A failure one more layer down is rejected just the same: the
        # endpoint check replays every signature layer of the
        # bundle-receipt ledger frontier, including the NPBJ40 signature
        # of the batch-receipt ledger frontier nested in its end.
        bad_ledger_end = dataclasses.replace(FRONTIER_1, signature=ZERO)
        bad_end = bundle_receipt_ledger_frontier_for(
            1, bad_ledger_end.to_bytes(), QDIGEST_1
        )
        tampered = bundle_commit_receipt_ledger_frontier_for(
            1, bad_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_deeper_nested_signature_verified(self):
        # And one layer deeper still: the NPBJ37 signature of the
        # receipt ledger frontier nested in the batch-receipt ledger
        # frontier's end is recomputed too.
        bad_ledger_end = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        bad_commit_end = commit_frontier_for(
            1, bad_ledger_end.to_bytes(), DIGEST_1
        )
        bad_end = bundle_receipt_ledger_frontier_for(
            1, bad_commit_end.to_bytes(), QDIGEST_1
        )
        tampered = bundle_commit_receipt_ledger_frontier_for(
            1, bad_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                OTHER_KEY, checkpoint=RFRONTIER_1
            )

    def test_checkpoint_is_read_only_and_has_no_state_alias(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=RFRONTIER_1
            )
        )
        with self.assertRaises(AttributeError):
            auditor.checkpoint = RFRONTIER_1
        # The ledger exports through checkpoint only; no state alias is
        # provided.
        self.assertFalse(hasattr(auditor, "state"))


class BundleCommitReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        self.assertIs(auditor.audit(RECEIPT_1, QBUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, QFRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, RDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_1, QBUNDLE_1)
        auditor.audit(RECEIPT_2, QBUNDLE_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, QFRONTIER_2.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, RDIGEST_2)

    def test_full_segment_commits_in_one_audit(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_12, QBUNDLE_12)
        self.assertEqual(auditor.checkpoint, RFRONTIER_12)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, QFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_1.to_bytes(), QBUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)
        auditor.audit(RECEIPT_2, QBUNDLE_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_restart_from_checkpoint_continues_with_next_receipt(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_1, QBUNDLE_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(RECEIPT_2, QBUNDLE_2)
            self.assertEqual(restored.checkpoint, RFRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        # A receipt continuing from QFRONTIER_1 cannot be the first
        # receipt of a fresh ledger.
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, QBUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_last_receipt_rejected(self):
        # Same sequence, same digest: a straight replay is rejected.
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_1, QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, QBUNDLE_1)
        self.assertIs(auditor.checkpoint, before)

    def test_low_sequence_and_old_fork_rejected(self):
        # Commit the two-commit segment straight to QFRONTIER_2; the
        # genesis receipt and the continuation receipt are then both old
        # receipts whose start does not link to the current end.
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_12, QBUNDLE_12)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, QBUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, QBUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_different_digest_fork_rejected(self):
        # From the empty ledger RECEIPT_1, RECEIPT_12 and RECEIPT_FULL
        # all occupy sequence slot one with an empty start; once one is
        # accepted the same-sequence forks' empty starts no longer link.
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_1, QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_12, QBUNDLE_12)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, QBUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_receipt_bundle_mismatch_rejected(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, QBUNDLE_12)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, QBUNDLE_2)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_12, QBUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_receipt_rejected(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_1, signature=ZERO), QBUNDLE_1
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_bundle_rejected(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit(
                RECEIPT_1, dataclasses.replace(QBUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                OTHER_KEY
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, QBUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        for bad in (
            1,
            "x",
            None,
            [RECEIPT_1],
            (RECEIPT_1,),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, QBUNDLE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, QBUNDLE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(blob.replace(b",", b", "), QBUNDLE_1)
        bundle_blob = QBUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, bundle_blob.replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, QBUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(RECEIPT_1, QBUNDLE_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = bundle_commit_receipt_ledger_frontier_for(
            U64_MAX, QFRONTIER_1.to_bytes(), RDIGEST_1
        )
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY, checkpoint=maxed
            )
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, QBUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_receipts_linearize(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        receipts, failures = [], []

        def run(receipt, bundle):
            try:
                auditor.audit(receipt, bundle)
                receipts.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(target=run, args=(RECEIPT_1, QBUNDLE_1)),
            threading.Thread(target=run, args=(RECEIPT_12, QBUNDLE_12)),
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
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        auditor.audit(RECEIPT_1, QBUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_12, QBUNDLE_12)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, QBUNDLE_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)


class BundleCommitReceiptAuditorParameterNamingTest(unittest.TestCase):
    def test_audit_params_named_receipt_and_bundle(self):
        signature = inspect.signature(
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor.audit
        )
        self.assertEqual(
            list(signature.parameters), ["self", "receipt", "bundle"]
        )

    def test_audit_verifies_with_keyword_arguments(self):
        auditor = (
            SpanBundleReceiptBatchReceiptBundleReceiptBundleReceiptAuditor(
                KEY
            )
        )
        self.assertIs(
            auditor.audit(receipt=RECEIPT_1, bundle=QBUNDLE_1), auditor
        )
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
