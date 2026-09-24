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
    _stream_commit_receipt_bundle_receipt_frontier_mac,
    _stream_commit_receipt_bundle_receipt_frontier_next_digest,
    audit_stream_commit_receipt_bundle_receipt,
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
    BUNDLE_SOLO,
)
from test_stream_commit_receipt_bundle_receipt import (
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
    RECEIPT_SOLO,
)
from test_stream_commit_receipt_frontier import (
    CDIGEST_1,
    CFRONTIER_1,
    CFRONTIER_2,
    CFRONTIER_FULL,
    commit_frontier_for,
)
from test_stream_receipt_frontier import (
    SDIGEST_1,
    SFRONTIER_1,
    stream_frontier_for,
)


def bundle_receipt_frontier_for(sequence, end, digest, key=KEY):
    placeholder = StreamCommitReceiptBundleReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_commit_receipt_bundle_receipt_frontier_mac(
            key, placeholder
        ),
    )


# One bundle receipt starting empty and ending at CFRONTIER_1.
RDIGEST_1 = _stream_commit_receipt_bundle_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_1.to_bytes()
)
# Continuation receipt from CFRONTIER_1 to CFRONTIER_2.
RDIGEST_2 = _stream_commit_receipt_bundle_receipt_frontier_next_digest(
    RDIGEST_1, 2, RECEIPT_2.to_bytes()
)
# A single receipt straight to CFRONTIER_2: a fork competing with
# RECEIPT_1 for the first sequence slot.
RDIGEST_FULL = _stream_commit_receipt_bundle_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_FULL.to_bytes()
)
RFRONTIER_1 = bundle_receipt_frontier_for(
    1, CFRONTIER_1.to_bytes(), RDIGEST_1
)
RFRONTIER_2 = bundle_receipt_frontier_for(
    2, CFRONTIER_2.to_bytes(), RDIGEST_2
)
RFRONTIER_FULL = bundle_receipt_frontier_for(
    1, CFRONTIER_2.to_bytes(), RDIGEST_FULL
)


class StreamCommitReceiptBundleReceiptFrontierFieldContractTest(
    unittest.TestCase
):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = StreamCommitReceiptBundleReceiptFrontier(
            1,
            1,
            CFRONTIER_1.to_bytes(),
            RDIGEST_1,
            RFRONTIER_1.mac,
        )
        self.assertEqual(frontier, RFRONTIER_1)
        self.assertEqual(hash(frontier), hash(RFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, CFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, RDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RFRONTIER_1.mac = ZERO

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
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty batch-commit ledger frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "1", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(RFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(RFRONTIER_1, **{name: bad})


class StreamCommitReceiptBundleReceiptFrontierEncodingTest(
    unittest.TestCase
):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + RDIGEST_1.hex().encode() + b'",'
            b'"' + RFRONTIER_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(RFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (RFRONTIER_1, RFRONTIER_2, RFRONTIER_FULL):
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
        blob = RFRONTIER_1.to_bytes()
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
            RDIGEST_1.hex(),
            RFRONTIER_1.mac.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            RFRONTIER_1.mac.hex().encode(),
            RFRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            1,
            CFRONTIER_1.to_bytes().hex(),
            RDIGEST_1.hex(),
            RFRONTIER_1.mac.hex(),
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
                StreamCommitReceiptBundleReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the frontier MAC nor the nested endpoint MACs are
        # checked at parse time.
        tampered = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        parsed = StreamCommitReceiptBundleReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_mac_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ30"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(RDIGEST_1, expected_digest)
        expected_mac = hmac.new(
            KEY,
            b"NPBJ29"
            + _stream_commit_receipt_bundle_receipt_frontier_content_bytes(
                RFRONTIER_1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RFRONTIER_1.mac, expected_mac)


class StreamCommitReceiptBundleReceiptAuditorConstructionTest(
    unittest.TestCase
):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(b"")

    def test_empty_checkpoint_is_empty_ledger(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            RFRONTIER_1,
            RFRONTIER_1.to_bytes(),
        ):
            auditor = StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [RFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_own_frontier_mac_verified(self):
        tampered = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_endpoint_commit_frontier_mac_verified(self):
        # The nested batch-commit ledger frontier's own NPBJ25 layer is
        # recomputed on load; re-MAC the outer layer so only it fails.
        bad_end = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        tampered = bundle_receipt_frontier_for(
            1, bad_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_endpoint_nested_stream_frontier_mac_verified(self):
        # The NPBJ21 layer one more level down (the endpoint's own end
        # stream-receipt frontier) is recomputed on load too.
        bad_stream_end = dataclasses.replace(SFRONTIER_1, mac=ZERO)
        bad_commit_end = commit_frontier_for(
            1, bad_stream_end.to_bytes(), CDIGEST_1
        )
        tampered = bundle_receipt_frontier_for(
            1, bad_commit_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_deep_nested_mac_verified(self):
        # A failure deep inside the endpoint's nested layers is rejected
        # just the same: the endpoint double-layer check replays every
        # MAC layer of the batch-commit ledger frontier.
        from test_range_batch_receipt_frontier import BFRONTIER_1

        bad_nested = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        bad_stream_end = stream_frontier_for(
            1, bad_nested.to_bytes(), SDIGEST_1
        )
        bad_commit_end = commit_frontier_for(
            1, bad_stream_end.to_bytes(), CDIGEST_1
        )
        tampered = bundle_receipt_frontier_for(
            1, bad_commit_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceiptAuditor(
                OTHER_KEY, checkpoint=RFRONTIER_1
            )

    def test_checkpoint_is_read_only_and_has_no_state_alias(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(
            KEY, checkpoint=RFRONTIER_1
        )
        with self.assertRaises(AttributeError):
            auditor.checkpoint = RFRONTIER_1
        # The ledger exports through checkpoint only; no state alias is
        # provided.
        self.assertFalse(hasattr(auditor, "state"))


class StreamCommitReceiptBundleReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit(RECEIPT_1, BUNDLE_1), auditor
        )
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(
            auditor.checkpoint.end, CFRONTIER_1.to_bytes()
        )
        self.assertEqual(auditor.checkpoint.digest, RDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(
            auditor.checkpoint.end, CFRONTIER_2.to_bytes()
        )
        self.assertEqual(auditor.checkpoint.digest, RDIGEST_2)

    def test_full_bundle_commits_in_one_audit(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertEqual(auditor.checkpoint, RFRONTIER_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(
            auditor.checkpoint.end, CFRONTIER_2.to_bytes()
        )

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_restart_from_checkpoint_continues_with_next_receipt(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(RECEIPT_2, BUNDLE_2)
            self.assertEqual(restored.checkpoint, RFRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        # A receipt continuing from CFRONTIER_1 cannot be the first
        # receipt of a fresh ledger.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_last_receipt_rejected(self):
        # Same sequence, same digest: a straight replay is rejected.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)

    def test_low_sequence_and_old_fork_rejected(self):
        # Commit the both-bundles chain straight to CFRONTIER_2; the
        # genesis receipt and the continuation receipt are then both old
        # low-sequence receipts whose start does not link to the current
        # end.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_different_digest_fork_rejected(self):
        # From the empty ledger RECEIPT_1 and RECEIPT_FULL both occupy
        # sequence slot one with an empty start; once one is accepted the
        # same-sequence fork's empty start no longer links, and a fresh
        # ledger rejects presenting the loser after the winner too.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_SOLO, BUNDLE_SOLO)
        self.assertIs(auditor.checkpoint, before)

    def test_receipt_bundle_mismatch_rejected(self):
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
        for bad in (b"", b"junk", b"[1,2,3]"):
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
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
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
        receipts, failures = [], []

        def run(receipt, bundle):
            try:
                auditor.audit(receipt, bundle)
                receipts.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(RECEIPT_1, BUNDLE_1)
            ),
            threading.Thread(
                target=run, args=(RECEIPT_SOLO, BUNDLE_SOLO)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(
            auditor.checkpoint.end, receipts[0].end
        )

    def test_accepted_receipt_is_never_lost(self):
        # A failure arriving concurrently against an already advanced
        # ledger never rolls the frontier back.
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_SOLO, BUNDLE_SOLO)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)


class StatelessEntryParameterNamingTest(unittest.TestCase):
    def test_entry_params_named_receipt_and_bundle(self):
        import inspect

        signature = inspect.signature(
            audit_stream_commit_receipt_bundle_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "bundle", "key"]
        )

    def test_entry_still_verifies(self):
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                receipt=RECEIPT_1, bundle=BUNDLE_1, key=KEY
            ),
            CFRONTIER_1,
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_2, BUNDLE_2, KEY
            ),
            CFRONTIER_2,
        )


if __name__ == "__main__":
    unittest.main()
