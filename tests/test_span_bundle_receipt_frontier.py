import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptAuditor,
    SpanBundleReceiptFrontier,
    _span_bundle_receipt_frontier_content_bytes,
    _span_bundle_receipt_frontier_next_digest,
    _span_bundle_receipt_frontier_signature,
)
from test_range_auditor_audit_batch import (
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RDIGEST_1,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    range_frontier_for,
)
from test_span_bundle_receipt import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
)


def bundle_receipt_frontier_for(sequence, end, digest, key=KEY):
    placeholder = SpanBundleReceiptFrontier(1, sequence, end, digest, ZERO)
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_frontier_signature(
            key, placeholder
        ),
    )


# One receipt starting empty and ending at RFRONTIER_1.
BDIGEST_1 = _span_bundle_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_1.to_bytes()
)
# Continuation receipt from RFRONTIER_1 to RFRONTIER_2.
BDIGEST_2 = _span_bundle_receipt_frontier_next_digest(
    BDIGEST_1, 2, RECEIPT_2.to_bytes()
)
# A single receipt straight to RFRONTIER_2: a fork competing with
# RECEIPT_1 for the first sequence slot.
BDIGEST_FULL = _span_bundle_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_FULL.to_bytes()
)
PFRONTIER_1 = bundle_receipt_frontier_for(
    1, RFRONTIER_1.to_bytes(), BDIGEST_1
)
PFRONTIER_2 = bundle_receipt_frontier_for(
    2, RFRONTIER_2.to_bytes(), BDIGEST_2
)
PFRONTIER_FULL = bundle_receipt_frontier_for(
    1, RFRONTIER_2.to_bytes(), BDIGEST_FULL
)


class SpanBundleReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = SpanBundleReceiptFrontier(
            1,
            1,
            RFRONTIER_1.to_bytes(),
            BDIGEST_1,
            PFRONTIER_1.signature,
        )
        self.assertEqual(frontier, PFRONTIER_1)
        self.assertEqual(hash(frontier), hash(PFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, RFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, BDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            PFRONTIER_1.signature = ZERO

    def test_no_alias_attributes(self):
        self.assertEqual(
            sorted(
                field.name for field in dataclasses.fields(PFRONTIER_1)
            ),
            ["digest", "end", "sequence", "signature", "version"],
        )
        self.assertNotIn("key", PFRONTIER_1.__dict__)

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(PFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(PFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(PFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(PFRONTIER_1, sequence=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(PFRONTIER_1, end=bad)
        # Empty, malformed and wrong-layer frontier bytes are value
        # errors: the end is a non-empty range frontier.
        for bad in (
            b"",
            b"junk",
            b"[1,2,3]",
            CFRONTIER_1.to_bytes(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(PFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "1", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(PFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(PFRONTIER_1, **{name: bad})


class SpanBundleReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + RFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + BDIGEST_1.hex().encode() + b'",'
            b'"' + PFRONTIER_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(PFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (PFRONTIER_1, PFRONTIER_2, PFRONTIER_FULL):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                SpanBundleReceiptFrontier.from_bytes(blob), frontier
            )
            self.assertEqual(
                SpanBundleReceiptFrontier.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = PFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            RFRONTIER_1.to_bytes().hex(),
            BDIGEST_1.hex(),
            PFRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = PFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanBundleReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            PFRONTIER_1.signature.hex().encode(),
            PFRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            SpanBundleReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            1,
            RFRONTIER_1.to_bytes().hex(),
            BDIGEST_1.hex(),
            PFRONTIER_1.signature.hex(),
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
                SpanBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the frontier signature nor the nested endpoint MACs
        # are checked at parse time.
        tampered = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        parsed = SpanBundleReceiptFrontier.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_signature_schemes(self):
        # The digest chain concatenates the previous digest, the fixed
        # 8-byte big-endian sequence and the canonical receipt bytes
        # directly, with no domain tag or length prefix.
        expected_digest = hashlib.sha256(
            ZERO + (1).to_bytes(8, "big") + RECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(BDIGEST_1, expected_digest)
        expected_signature = hmac.new(
            KEY,
            b"NPBJ37"
            + _span_bundle_receipt_frontier_content_bytes(PFRONTIER_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(PFRONTIER_1.signature, expected_signature)


class SpanBundleReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(b"")

    def test_empty_checkpoint_is_empty_ledger(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            SpanBundleReceiptAuditor(KEY, checkpoint=None).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            PFRONTIER_1,
            PFRONTIER_1.to_bytes(),
        ):
            auditor = SpanBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, PFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [PFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(PFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(KEY, checkpoint=tampered.to_bytes())

    def test_checkpoint_endpoint_range_frontier_mac_verified(self):
        # The nested range frontier's own NPBJ13 layer is recomputed on
        # load; re-sign the outer layer so only it fails.
        bad_end = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        tampered = bundle_receipt_frontier_for(
            1, bad_end.to_bytes(), BDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_deep_nested_mac_verified(self):
        # A failure one more layer down is rejected just the same: the
        # endpoint check replays every MAC layer of the range frontier,
        # including the layers of the commit frontier nested in its end.
        bad_commit_end = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        bad_end = range_frontier_for(
            1, bad_commit_end.to_bytes(), RDIGEST_1
        )
        tampered = bundle_receipt_frontier_for(
            1, bad_end.to_bytes(), BDIGEST_1
        )
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(OTHER_KEY, checkpoint=PFRONTIER_1)

    def test_checkpoint_is_read_only_and_has_no_state_alias(self):
        auditor = SpanBundleReceiptAuditor(KEY, checkpoint=PFRONTIER_1)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = PFRONTIER_1
        # The ledger exports through checkpoint only; no state alias is
        # provided.
        self.assertFalse(hasattr(auditor, "state"))


class SpanBundleReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_1, BUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, RFRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, BDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, RFRONTIER_2.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, BDIGEST_2)

    def test_full_bundle_commits_in_one_audit(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertEqual(auditor.checkpoint, PFRONTIER_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, RFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_restart_from_checkpoint_continues_with_next_receipt(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = SpanBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(RECEIPT_2, BUNDLE_2)
            self.assertEqual(restored.checkpoint, PFRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        # A receipt continuing from RFRONTIER_1 cannot be the first
        # receipt of a fresh ledger.
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_last_receipt_rejected(self):
        # Same sequence, same digest: a straight replay is rejected.
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)

    def test_low_sequence_and_old_fork_rejected(self):
        # Commit the whole-chain bundle straight to RFRONTIER_2; the
        # genesis receipt and the continuation receipt are then both old
        # low-sequence receipts whose start does not link to the current
        # end.
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_different_digest_fork_rejected(self):
        # From the empty ledger RECEIPT_1 and RECEIPT_FULL both occupy
        # sequence slot one with an empty start; once one is accepted
        # the same-sequence fork's empty start no longer links.
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_receipt_bundle_mismatch_rejected(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_2)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_FULL)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_receipt_rejected(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_1, signature=ZERO), BUNDLE_1
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_bundle_rejected(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                RECEIPT_1, dataclasses.replace(BUNDLE_1, signature=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = SpanBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (
            1,
            "x",
            None,
            [RECEIPT_1],
            (RECEIPT_1,),
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(blob.replace(b",", b", "), BUNDLE_1)
        bundle_blob = BUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, bundle_blob.replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, RFRONTIER_1.to_bytes(), BDIGEST_1
        )
        auditor = SpanBundleReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_receipts_linearize(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipts, failures = [], []

        def run(receipt, bundle):
            try:
                auditor.audit(receipt, bundle)
                receipts.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(target=run, args=(RECEIPT_1, BUNDLE_1)),
            threading.Thread(
                target=run, args=(RECEIPT_FULL, BUNDLE_FULL)
            ),
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
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)


class SpanBundleReceiptAuditorParameterNamingTest(unittest.TestCase):
    def test_audit_params_named_receipt_and_bundle(self):
        signature = inspect.signature(SpanBundleReceiptAuditor.audit)
        self.assertEqual(
            list(signature.parameters), ["self", "receipt", "bundle"]
        )

    def test_audit_verifies_with_keyword_arguments(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit(receipt=RECEIPT_1, bundle=BUNDLE_1), auditor
        )
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
