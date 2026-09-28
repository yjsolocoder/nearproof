import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListBundleReceiptBatchReceiptAuditor,
    EvidenceRevocationListBundleReceiptBatchReceiptFrontier,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX,
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_content_bytes,
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest,
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_signature,
    audit_evidence_revocation_list_bundle_receipt_batch_receipt,
)
from test_evidence_revocation_list_bundle import KEY, OTHER_KEY
from test_evidence_revocation_list_bundle_receipt_frontier import (
    FRONTIER_1,
    FRONTIER_2,
    U64_MAX,
    ZERO,
)
from test_evidence_revocation_list_bundle_receipt_batch import (
    BATCH_1,
    BATCH_2,
    BATCH_FULL,
)
from test_evidence_revocation_list_bundle_receipt_batch_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    CRECEIPT_FULL,
)

# The commit-frontier digest chain runs over the canonical batch-receipt
# bytes, starting from 32 zero bytes.
CDIGEST_1 = (
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest(
        ZERO, 1, CRECEIPT_1.to_bytes()
    )
)
CDIGEST_2 = (
    _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_next_digest(
        CDIGEST_1, 2, CRECEIPT_2.to_bytes()
    )
)


def cfrontier_for_sequence(sequence, end, digest, key=KEY):
    """A batch-receipt commit frontier with the NPEBR7 signature
    recomputed over the first four fields."""
    placeholder = (
        EvidenceRevocationListBundleReceiptBatchReceiptFrontier(
            1, sequence, end, digest, ZERO
        )
    )
    return dataclasses.replace(
        placeholder,
        signature=(
            _evidence_revocation_list_bundle_receipt_batch_receipt_frontier_signature(
                key, placeholder
            )
        ),
    )


CFRONTIER_1 = cfrontier_for_sequence(
    1, FRONTIER_1.to_bytes(), CDIGEST_1
)
CFRONTIER_2 = cfrontier_for_sequence(
    2, FRONTIER_2.to_bytes(), CDIGEST_2
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
        frontier = (
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier(
                1,
                1,
                FRONTIER_1.to_bytes(),
                CDIGEST_1,
                CFRONTIER_1.signature,
            )
        )
        self.assertEqual(frontier, CFRONTIER_1)
        self.assertEqual(hash(frontier), hash(CFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, FRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, CDIGEST_1)
        self.assertEqual(frontier.signature, CFRONTIER_1.signature)

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
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(
                CFRONTIER_1, sequence=U64_MAX
            ).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)
        # end must be the canonical non-empty receipt-ledger frontier.
        for bad in (b"", b"junk", b"[1,2,3]", CRECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})


class BatchReceiptFrontierEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = CFRONTIER_1.to_bytes()
        expected = (
            b'{"version":1,"sequence":1,'
            b'"end":"' + FRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"digest":"' + CDIGEST_1.hex().encode() + b'",'
            b'"signature":"' + CFRONTIER_1.signature.hex().encode()
            + b'"}'
        )
        self.assertEqual(raw, expected)
        self.assertNotIn(b" ", raw)
        self.assertEqual(
            raw, raw.decode("utf-8").lower().encode("utf-8")
        )

    def test_round_trip_byte_for_byte(self):
        for frontier in (CFRONTIER_1, CFRONTIER_2):
            blob = frontier.to_bytes()
            parsed = (
                EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                    blob
                )
            )
            self.assertEqual(parsed, frontier)
            self.assertEqual(parsed.to_bytes(), blob)

    def test_parse_does_not_verify_signature(self):
        # A structurally valid frontier with an all-zero signature
        # parses; signatures are checked only by the auditor.
        unsigned = dataclasses.replace(CFRONTIER_1, signature=ZERO)
        parsed = (
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                unsigned.to_bytes()
            )
        )
        self.assertEqual(parsed, unsigned)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [CFRONTIER_1.to_bytes()], object(), True):
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
            b"[1,1,2,3,4]",
            b'{"version":1,"sequence":1,"end":"","digest":"",'
            b'"signature":""}',
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
        spaced = blob.replace(b",", b", ")
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptFrontier.from_bytes(
                spaced
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


class BatchReceiptFrontierSignatureTest(unittest.TestCase):
    def test_digest_chain_step_is_npebr6(self):
        expected = hashlib.sha256(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX
            + ZERO
            + (1).to_bytes(8, "big")
            + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(CDIGEST_1, expected)
        self.assertEqual(len(CDIGEST_1), 32)

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
        self.assertEqual(
            hmac.new(
                KEY,
                _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_RECEIPT_FRONTIER_SIGNATURE_PREFIX
                + joined,
                hashlib.sha256,
            ).digest(),
            CFRONTIER_2.signature,
        )

    def test_new_domain_label_distinct_from_batch_receipt(self):
        # A signature under the NPEBR5 batch-receipt label is not the
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


class AuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_no_state_alias(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        self.assertFalse(hasattr(auditor, "state"))

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

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=b"junk"
            )

    def test_checkpoint_frontier_signature_verified(self):
        tampered = dataclasses.replace(CFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_frontier_macs_verified(self):
        # Both MAC layers of the end receipt-ledger frontier (its own
        # NPEBR3 mac and the NPES1 state mac) are recomputed on load.
        bad_ledger = dataclasses.replace(FRONTIER_1, mac=ZERO)
        tampered = cfrontier_for_sequence(
            1, bad_ledger.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
                OTHER_KEY, checkpoint=CFRONTIER_1
            )


class AuditSuccessTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        self.assertIs(auditor.audit(CRECEIPT_1, BATCH_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, FRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, CDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, FRONTIER_2.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, CDIGEST_2)

    def test_whole_segment_in_one_commit(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, FRONTIER_2.to_bytes())

    def test_accepts_object_or_canonical_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1.to_bytes(), BATCH_1.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        auditor.audit(CRECEIPT_2.to_bytes(), BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_checkpoint_end_matches_stateless_audit(self):
        # The frontier end is exactly what the stateless receipt audit
        # returns for the attested batch.
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertEqual(
            auditor.checkpoint.end,
            audit_evidence_revocation_list_bundle_receipt_batch_receipt(
                CRECEIPT_FULL, BATCH_FULL, KEY
            ).to_bytes(),
        )


class AuditRestartTest(unittest.TestCase):
    def test_restart_from_checkpoint_continues_audit(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        blob = auditor.checkpoint.to_bytes()
        restored = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=blob
        )
        self.assertEqual(restored.checkpoint, CFRONTIER_1)
        restored.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(restored.checkpoint, CFRONTIER_2)

    def test_restart_then_replay_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        restored = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=auditor.checkpoint
        )
        with self.assertRaises(ValueError):
            restored.audit(CRECEIPT_1, BATCH_1)
        self.assertEqual(restored.checkpoint, CFRONTIER_1)


class AuditRejectionTest(unittest.TestCase):
    def test_first_receipt_must_start_empty(self):
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

    def test_old_fork_rejected_without_rollback(self):
        # The whole-segment commit also starts empty; after CRECEIPT_1
        # landed it no longer links to the advanced frontier.
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_FULL, BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_receipt_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        tampered = dataclasses.replace(CRECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered, BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_batch_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_FULL)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            OTHER_KEY
        )
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_kind_is_type_error(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [CRECEIPT_1], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_are_value_error(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        for bad in (b"junk", CRECEIPT_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1.to_bytes() + b"\n")
        self.assertIsNone(auditor.checkpoint)

    def test_failure_leaves_ledger_usable(self):
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        auditor.audit(CRECEIPT_1, BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, BATCH_1)
        auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_sequence_overflow(self):
        maxed = cfrontier_for_sequence(
            U64_MAX, FRONTIER_1.to_bytes(), CDIGEST_1
        )
        auditor = EvidenceRevocationListBundleReceiptBatchReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)


class AuditLinearizationTest(unittest.TestCase):
    def test_competing_commits_linearize_without_loss(self):
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
        self.assertEqual(
            auditor.checkpoint.end, commits[0].end
        )
        # Whichever fork won, the ledger never rolled back and a clean
        # continuation stays possible from the winning end.
        if commits[0] is CRECEIPT_1:
            auditor.audit(CRECEIPT_2, BATCH_2)
            self.assertEqual(auditor.checkpoint, CFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
