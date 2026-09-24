import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptBundleReceiptAuditor,
    StreamCommitReceiptBundleReceiptFrontier,
    _stream_commit_receipt_bundle_receipt_frontier_content_bytes,
    _stream_commit_receipt_bundle_receipt_frontier_next_digest,
    _stream_commit_receipt_bundle_receipt_frontier_signature,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_stream_commit_receipt_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
)
from test_stream_commit_receipt_bundle_receipt import (
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
)
from test_stream_commit_receipt_frontier import (
    CDIGEST_1,
    CFRONTIER_1,
    CFRONTIER_2,
    commit_frontier_for,
)
from test_stream_receipt_frontier import (
    SFRONTIER_1,
    stream_frontier_for,
)


def bundle_receipt_frontier_for(sequence, end, digest, key=KEY):
    placeholder = StreamCommitReceiptBundleReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=(
            _stream_commit_receipt_bundle_receipt_frontier_signature(
                key, placeholder
            )
        ),
    )


# One bundle receipt starting empty and ending at CFRONTIER_1.
BRDIGEST_1 = _stream_commit_receipt_bundle_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_1.to_bytes()
)
# Continuation receipt from CFRONTIER_1 to CFRONTIER_2.
BRDIGEST_2 = _stream_commit_receipt_bundle_receipt_frontier_next_digest(
    BRDIGEST_1, 2, RECEIPT_2.to_bytes()
)
BRFRONTIER_1 = bundle_receipt_frontier_for(
    1, CFRONTIER_1.to_bytes(), BRDIGEST_1
)
BRFRONTIER_2 = bundle_receipt_frontier_for(
    2, CFRONTIER_2.to_bytes(), BRDIGEST_2
)


class StreamCommitReceiptBundleReceiptFrontierFieldContractTest(
    unittest.TestCase
):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = StreamCommitReceiptBundleReceiptFrontier(
            1,
            1,
            CFRONTIER_1.to_bytes(),
            BRDIGEST_1,
            BRFRONTIER_1.signature,
        )
        self.assertEqual(frontier, BRFRONTIER_1)
        self.assertEqual(hash(frontier), hash(BRFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, CFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, BRDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BRFRONTIER_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BRFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BRFRONTIER_1, sequence=bad)

    def test_end_contract(self):
        for bad in (
            1,
            "1",
            None,
            bytearray(CFRONTIER_1.to_bytes()),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BRFRONTIER_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty commit frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BRFRONTIER_1, end=bad)

    def test_digest_and_signature_contract(self):
        for name in ("digest", "signature"):
            for bad in (1, "1", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(BRFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(BRFRONTIER_1, **{name: bad})


class StreamCommitReceiptBundleReceiptFrontierEncodingTest(
    unittest.TestCase
):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + BRDIGEST_1.hex().encode() + b'",'
            b'"' + BRFRONTIER_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(BRFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (BRFRONTIER_1, BRFRONTIER_2):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(blob),
                frontier,
            )
            self.assertEqual(
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                    blob
                ).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = BRFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            CFRONTIER_1.to_bytes().hex(),
            BRDIGEST_1.hex(),
            BRFRONTIER_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError):
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = BRFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            BRFRONTIER_1.signature.hex().encode(),
            BRFRONTIER_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the frontier signature nor any nested MAC is checked
        # at parse time.
        tampered = dataclasses.replace(BRFRONTIER_1, signature=ZERO)
        parsed = StreamCommitReceiptBundleReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_signature_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ30"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(BRDIGEST_1, expected_digest)
        expected_signature = hmac.new(
            KEY,
            b"NPBJ29"
            + _stream_commit_receipt_bundle_receipt_frontier_content_bytes(
                BRFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BRFRONTIER_1.signature, expected_signature)


class StreamCommitReceiptBundleReceiptAuditorConstructionTest(
    unittest.TestCase
):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(
            StreamCommitReceiptBundleReceiptAuditor(KEY).checkpoint
        )
        self.assertIsNone(
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            BRFRONTIER_1,
            BRFRONTIER_1.to_bytes(),
        ):
            auditor = StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, BRFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [BRFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=b"junk"
            )

    def test_checkpoint_own_frontier_signature_verified(self):
        tampered = dataclasses.replace(BRFRONTIER_1, signature=ZERO)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_commit_frontier_mac_verified(self):
        # The nested commit frontier's own NPBJ25 layer is recomputed on
        # load; re-sign the outer layer so only the nested one fails.
        bad_end = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        tampered = bundle_receipt_frontier_for(
            1, bad_end.to_bytes(), BRDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_deep_nested_mac_verified(self):
        # The NPBJ21 layer two levels down (inside the end commit
        # frontier's stream-receipt frontier) is recomputed too.
        bad_nested = dataclasses.replace(SFRONTIER_1, mac=ZERO)
        bad_commit_end = commit_frontier_for(
            1, bad_nested.to_bytes(), CDIGEST_1
        )
        tampered = bundle_receipt_frontier_for(
            1, bad_commit_end.to_bytes(), BRDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                OTHER_KEY, checkpoint=BRFRONTIER_1
            )

    def test_checkpoint_is_read_only(self):
        with self.assertRaises(AttributeError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY
            ).checkpoint = BRFRONTIER_1


class StreamCommitReceiptBundleReceiptAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_1, BUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, BRFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(
            auditor.checkpoint.end, CFRONTIER_1.to_bytes()
        )
        self.assertEqual(auditor.checkpoint.digest, BRDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, BRFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(
            auditor.checkpoint.end, CFRONTIER_2.to_bytes()
        )
        self.assertEqual(auditor.checkpoint.digest, BRDIGEST_2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, BRFRONTIER_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, BRFRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        blob = auditor.checkpoint.to_bytes()
        restored = StreamCommitReceiptBundleReceiptAuditor(
            KEY, checkpoint=blob
        )
        restored.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(restored.checkpoint, BRFRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        # A receipt continuing from CFRONTIER_1 cannot be the first
        # receipt of a fresh ledger.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_receipt_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)

    def test_low_sequence_and_old_fork_rejected(self):
        # Commit the both-receipts bundle straight to CFRONTIER_2; the
        # genesis receipt and the continuation receipt are then both old
        # receipts whose start does not link to the current end.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_different_digest_rejected(self):
        # A second receipt over the same empty start but a different
        # bundle is a fork at sequence one: after the honest first
        # receipt its start no longer links, and presenting the fork
        # first still rejects the honest receipt afterwards.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_receipt_bundle_pair_mismatch_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_receipt_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_1, mac=ZERO), BUNDLE_1
            )
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_bundle_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                RECEIPT_1, dataclasses.replace(BUNDLE_1, mac=ZERO)
            )
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
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
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(blob.replace(b",", b", "), BUNDLE_1)
        bundle_blob = BUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, bundle_blob.replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, BRFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), BRDIGEST_1
        )
        auditor = StreamCommitReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_receipts_linearize(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        commits, failures = [], []

        def run(receipt, bundle):
            try:
                auditor.audit(receipt, bundle)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(RECEIPT_1, BUNDLE_1)
            ),
            threading.Thread(
                target=run, args=(RECEIPT_1, BUNDLE_1)
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
            auditor.checkpoint.end, CFRONTIER_1.to_bytes()
        )


if __name__ == "__main__":
    unittest.main()
