import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListBundleReceiptAuditor,
    EvidenceRevocationListBundleReceiptBatchReceipt,
    EvidenceRevocationListBundleReceiptBatchReceiptAuditor,
    EvidenceRevocationListBundleReceiptBatchReceiptFrontier,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX,
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_content_bytes,
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest,
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_signature,
    _evidence_revocation_list_bundle_receipt_batch_receipt_signature,
    _evidence_revocation_list_bundle_receipt_batch_signature,
    audit_evidence_revocation_list_bundle_receipt_batch_receipt,
)
from test_evidence_revocation_list_bundle import KEY, OTHER_KEY
from test_evidence_revocation_list_bundle_receipt_frontier import (
    BUNDLE_1,
    BUNDLE_2,
    DIGEST_1,
    FRONTIER_1,
    FRONTIER_2,
    RECEIPT_1,
    RECEIPT_2,
    STATE_1,
    U64_MAX,
    ZERO,
    frontier_for_sequence,
)
from test_evidence_revocation_list_bundle_receipt_batch import (
    BATCH_1,
    BATCH_2,
    BATCH_FULL,
    batch_for,
)
from test_evidence_revocation_list_bundle_receipt_batch_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    CRECEIPT_FULL,
)


def commit_frontier_for(sequence, end, digest, key=KEY):
    """An NPEBR7-signed batch-receipt frontier over the given fields."""
    placeholder = EvidenceRevocationListBundleReceiptBatchReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=(
            _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_signature(
                key, placeholder
            )
        ),
    )


# One audited batch receipt from the empty ledger to FRONTIER_1.
CDIGEST_1 = _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_1.to_bytes()
)
# Continuation from FRONTIER_1 to FRONTIER_2.
CDIGEST_2 = _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest(
    CDIGEST_1, 2, CRECEIPT_2.to_bytes()
)
# A competing first receipt straight to FRONTIER_2 (a fork).
CDIGEST_FULL = _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_FULL.to_bytes()
)
CFRONTIER_1 = commit_frontier_for(
    1, FRONTIER_1.to_bytes(), CDIGEST_1
)
CFRONTIER_2 = commit_frontier_for(
    2, FRONTIER_2.to_bytes(), CDIGEST_2
)
CFRONTIER_FULL = commit_frontier_for(
    1, FRONTIER_2.to_bytes(), CDIGEST_FULL
)


class BatchReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    EvidenceRevocationListBundleReceiptBatchReceiptFrontier
                )
            ],
            ["version", "sequence", "end", "digest", "signature"],
        )
        self.assertNotIn("key", CFRONTIER_1.__dict__)
        self.assertNotIn("mac", CFRONTIER_1.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = EvidenceRevocationListBundleReceiptBatchReceiptFrontier(
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
        self.assertEqual(frontier.end, FRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, CDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            CFRONTIER_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, version=bad)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, version=bad)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(CFRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)
        # The end is the canonical non-empty receipt-ledger frontier:
        # empty, junk and a JSON array of the wrong shape are all value
        # errors.
        for bad in (b"", b"junk", b"[1,2,3]", CRECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "x", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})


class BatchReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'{"version":1,"sequence":1,'
            b'"end":"' + FRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"digest":"' + CDIGEST_1.hex().encode() + b'",'
            b'"signature":"' + CFRONTIER_1.signature.hex().encode() + b'"}'
        )
        self.assertEqual(CFRONTIER_1.to_bytes(), expected)
        # Compact: no whitespace, lowercase hex only.
        raw = CFRONTIER_1.to_bytes()
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for frontier in (CFRONTIER_1, CFRONTIER_2, CFRONTIER_FULL):
            blob = frontier.to_bytes()
            parsed = (
                EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                    blob
                )
            )
            self.assertEqual(parsed, frontier)
            self.assertEqual(parsed.to_bytes(), blob)

    def test_from_bytes_type_contract(self):
        blob = CFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                    bad
                )

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"[]",
            b"{}",
            b"[1,2,3,4,5]",
            b'{"version":1,"sequence":1,"end":"","digest":"","signature":""}',
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                    bad
                )

    def test_from_bytes_rejects_key_disorder(self):
        obj = json.loads(CFRONTIER_1.to_bytes())

        def encode(keys):
            return json.dumps(
                {key: obj.get(key, 0) for key in keys},
                separators=(",", ":"),
            ).encode()

        fields = ["version", "sequence", "end", "digest", "signature"]
        for bad_keys in (
            fields[:-1],  # missing key
            fields + ["extra"],  # extra key
            list(reversed(fields)),  # out-of-order keys
            ["version", "version", "end", "digest", "signature"],
        ):
            with self.assertRaises(ValueError, msg=repr(bad_keys)):
                EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                    encode(bad_keys)
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = CFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            CFRONTIER_1.signature.hex().encode(),
            CFRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                upper
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b'"version":1', b'"version":2', 1)
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                blob.replace(b'"sequence":1', b'"sequence":1.0', 1)
            )
        # Trailing/leading whitespace breaks the byte-for-byte check.
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                blob + b" "
            )

    def test_from_bytes_does_not_verify_signatures(self):
        # Neither the frontier signature nor any nested signature is
        # checked at parse time.
        tampered = dataclasses.replace(CFRONTIER_1, signature=ZERO)
        parsed = EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)


class BatchReceiptFrontierSchemeTest(unittest.TestCase):
    def test_digest_chain_is_npebr6_direct_concatenation(self):
        # d0 is 32 zero bytes; the step is
        # SHA256(b"NPEBR6" + d + u64be(n) + R), every part concatenated
        # directly with no delimiter or length prefix.
        expected = hashlib.sha256(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX
            + ZERO
            + (1).to_bytes(8, "big")
            + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(CDIGEST_1, expected)
        expected_two = hashlib.sha256(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX
            + CDIGEST_1
            + (2).to_bytes(8, "big")
            + CRECEIPT_2.to_bytes()
        ).digest()
        self.assertEqual(CDIGEST_2, expected_two)
        # Dropping the NPEBR6 tag changes the digest.
        untagged = hashlib.sha256(
            ZERO + (1).to_bytes(8, "big") + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertNotEqual(untagged, CDIGEST_1)
        # A replayed receipt at a different sequence hashes differently,
        # so the chain binds the sequence number.
        self.assertNotEqual(
            CDIGEST_1,
            hashlib.sha256(
                _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX
                + ZERO
                + (2).to_bytes(8, "big")
                + CRECEIPT_1.to_bytes()
            ).digest(),
        )

    def test_signature_is_npebr7_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX
            + _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_content_bytes(
                CFRONTIER_2
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(CFRONTIER_2.signature, expected)
        self.assertEqual(len(CFRONTIER_2.signature), 32)
        joined = json.dumps(
            {
                "version": CFRONTIER_2.version,
                "sequence": CFRONTIER_2.sequence,
                "end": CFRONTIER_2.end.hex(),
                "digest": CFRONTIER_2.digest.hex(),
            },
            separators=(",", ":"),
        ).encode()
        signature_prefix = (
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX
        )
        self.assertEqual(
            hmac.new(
                KEY,
                signature_prefix + joined,
                hashlib.sha256,
            ).digest(),
            CFRONTIER_2.signature,
        )

    def test_new_domain_label_distinct_from_receipt_label(self):
        # An NPEBR5 signature over the frontier content is not the
        # frontier signature.
        wrong = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX
            + _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_content_bytes(
                CFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(wrong, CFRONTIER_1.signature)


class BatchReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(b"")

    def test_empty_checkpoint_is_empty_ledger(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (CFRONTIER_1, CFRONTIER_1.to_bytes()):
            auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [CFRONTIER_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_or_non_canonical_bytes(self):
        for bad in (
            b"junk",
            b"[1,2,3]",
            CFRONTIER_1.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(CFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_endpoint_ledger_mac_verified(self):
        # The nested receipt-ledger frontier's own NPEBR3 layer is
        # recomputed on load; re-sign the outer NPEBR7 layer so only it
        # fails.
        bad_ledger = dataclasses.replace(FRONTIER_1, mac=ZERO)
        tampered = commit_frontier_for(
            1, bad_ledger.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_endpoint_state_mac_verified(self):
        # A failure one layer down (the NPES1 MAC of the ledger end
        # state) is rejected just the same.
        bad_state = dataclasses.replace(STATE_1, mac=ZERO)
        bad_ledger = frontier_for_sequence(
            1, bad_state.to_bytes(), DIGEST_1
        )
        tampered = commit_frontier_for(
            1, bad_ledger.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                OTHER_KEY, checkpoint=CFRONTIER_1
            )

    def test_checkpoint_is_read_only_and_has_no_alias(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=CFRONTIER_1
        )
        with self.assertRaises(AttributeError):
            auditor.checkpoint = CFRONTIER_1
        self.assertFalse(hasattr(auditor, "state"))
        self.assertFalse(hasattr(auditor, "frontier"))


class BatchReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(auditor.audit(CRECEIPT_1, BATCH_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, CRECEIPT_1.end)
        self.assertEqual(auditor.checkpoint.digest, CDIGEST_1)
        self.assertEqual(
            auditor.checkpoint.signature, CFRONTIER_1.signature
        )

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, CRECEIPT_2.end)
        self.assertEqual(auditor.checkpoint.digest, CDIGEST_2)

    def test_accepts_canonical_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1.to_bytes(), BATCH_1.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_verifies_with_keyword_arguments(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit(receipt=CRECEIPT_1, batch=BATCH_1), auditor
        )
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_restart_from_checkpoint_audits_next_receipt(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        # Round-trip the frontier through its canonical bytes: the
        # observable restart contract is that the exported checkpoint
        # comes back equal and the next receipt is accepted.
        blob = auditor.checkpoint.to_bytes()
        self.assertEqual(
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                blob
            ),
            CFRONTIER_1,
        )
        for checkpoint in (auditor.checkpoint, blob):
            restored = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(CRECEIPT_2, BATCH_2)
            self.assertEqual(restored.checkpoint, CFRONTIER_2)

    def test_restart_after_full_segment(self):
        # Commit the whole segment in one receipt, export, restart and
        # confirm the restored ledger refuses replays and equals the
        # straight-line ledger's view of the fork frontier.
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        blob = auditor.checkpoint.to_bytes()
        restored = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=blob
        )
        self.assertEqual(restored.checkpoint, auditor.checkpoint)
        self.assertEqual(restored.checkpoint, CFRONTIER_FULL)
        with self.assertRaises(ValueError):
            restored.audit(CRECEIPT_FULL, BATCH_FULL)

    def test_first_receipt_must_start_empty(self):
        # A continuation receipt cannot be the first receipt of a fresh
        # ledger.
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_receipt_rejected_without_rollback(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIs(auditor.checkpoint, before)

    def test_old_receipt_and_fork_rejected(self):
        # Accept the whole segment as one receipt; the genesis receipt,
        # its continuation and a same-sequence straight-to-end receipt
        # are then all old receipts whose start no longer links.
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)
        # And on a ledger that took the first segment, the straight-to-
        # end fork is rejected.
        forked = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        forked.audit(CRECEIPT_1, BATCH_1)
        with self.assertRaises(ValueError):
            forked.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertEqual(forked.checkpoint, CFRONTIER_1)

    def test_broken_link_rejected(self):
        # A valid receipt/batch pair that does not continue the current
        # frontier is rejected after full stateless verification.
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=CFRONTIER_2
        )
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_receipt_batch_mismatch_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_same_endpoints_other_batch_not_attested(self):
        # Another batch body with the same start and end as BATCH_FULL
        # but a different carried chain is not attested by the full
        # segment's receipt.
        other = batch_for(
            b"",
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        self.assertEqual(other.start, BATCH_FULL.start)
        self.assertEqual(other.end, BATCH_FULL.end)
        self.assertNotEqual(other.to_bytes(), BATCH_FULL.to_bytes())
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_FULL, other)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_receipt_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(CRECEIPT_1, signature=ZERO),
                BATCH_1,
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_batch_rejected(self):
        # A batch re-signed with the wrong key fails full verification
        # even when the receipt itself is honestly minted over it.
        forged = dataclasses.replace(
            BATCH_1,
            signature=_evidence_revocation_list_bundle_receipt_batch_signature(
                OTHER_KEY, BATCH_1
            ),
        )
        placeholder = EvidenceRevocationListBundleReceiptBatchReceipt(
            1,
            forged.start,
            hashlib.sha256(forged.to_bytes()).digest(),
            forged.end,
            ZERO,
        )
        receipt = dataclasses.replace(
            placeholder,
            signature=(
                _evidence_revocation_list_bundle_receipt_batch_receipt_signature(
                    KEY, placeholder
                )
            ),
        )
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(receipt, forged)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_and_empty_key(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            OTHER_KEY
        )
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type_is_type_error(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [CRECEIPT_1], (CRECEIPT_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_and_non_canonical_bytes_is_value_error(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1.to_bytes() + b" ", BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1.to_bytes() + b" ")
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, FRONTIER_1.to_bytes(), CDIGEST_1
        )
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        # CRECEIPT_2 honestly continues from FRONTIER_1: the pair
        # verifies and the start links, but the u64 sequence cannot
        # advance.
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_commits_linearize(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
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
        self.assertEqual(auditor.checkpoint.end, commits[0].end)
        # Whichever fork won, the ledger is consistent afterwards: the
        # continuation links only from the two-step winner.
        if commits[0] is CRECEIPT_1:
            auditor.audit(CRECEIPT_2, BATCH_2)
            self.assertEqual(auditor.checkpoint, CFRONTIER_2)
        else:
            self.assertEqual(auditor.checkpoint, CFRONTIER_FULL)

    def test_accepted_receipt_is_never_lost_or_rolled_back(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)


class BatchReceiptAuditorParameterNamingTest(unittest.TestCase):
    def test_audit_params_named_receipt_and_batch(self):
        signature = inspect.signature(
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor.audit
        )
        self.assertEqual(
            list(signature.parameters), ["self", "receipt", "batch"]
        )


class StatelessAndLedgerEntryPointsStillWorkTest(unittest.TestCase):
    def test_stateless_audit_returns_ledger_end(self):
        # The existing stateless review of a batch receipt is unchanged.
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch_receipt(
                CRECEIPT_1, BATCH_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL, KEY
            ),
            FRONTIER_2,
        )

    def test_existing_single_receipt_ledger_unchanged(self):
        # The pre-existing per-receipt auditor still runs independently
        # of the new batch-receipt ledger.
        ledger = EvidenceRevocationListBundleReceiptAuditor(KEY)
        ledger.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(ledger.checkpoint, FRONTIER_1)


if __name__ == "__main__":
    unittest.main()
