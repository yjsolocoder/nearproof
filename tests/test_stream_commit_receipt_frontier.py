import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptAuditor,
    StreamCommitReceiptFrontier,
    StreamReceiptFrontier,
    _stream_commit_receipt_frontier_content_bytes,
    _stream_commit_receipt_frontier_mac,
    _stream_commit_receipt_frontier_next_digest,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_range_batch_receipt_frontier import (
    BFRONTIER_1,
)
from test_stream_receipt_batch_commit_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    CRECEIPT_FULL,
    SBATCH_1,
    SBATCH_2,
    SBATCH_FULL,
)
from test_stream_receipt_frontier import (
    SDIGEST_1,
    SFRONTIER_1,
    SFRONTIER_2,
    stream_frontier_for,
)


def commit_frontier_for(sequence, end, digest, key=KEY):
    placeholder = StreamCommitReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_commit_receipt_frontier_mac(key, placeholder),
    )


# One batch commit starting empty and ending at SFRONTIER_1.
CDIGEST_1 = _stream_commit_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_1.to_bytes()
)
# Continuation batch commit from SFRONTIER_1 to SFRONTIER_2.
CDIGEST_2 = _stream_commit_receipt_frontier_next_digest(
    CDIGEST_1, 2, CRECEIPT_2.to_bytes()
)
# A single batch sealing both items: one commit straight to SFRONTIER_2.
CDIGEST_FULL = _stream_commit_receipt_frontier_next_digest(
    ZERO, 1, CRECEIPT_FULL.to_bytes()
)
CFRONTIER_1 = commit_frontier_for(
    1, SFRONTIER_1.to_bytes(), CDIGEST_1
)
CFRONTIER_2 = commit_frontier_for(
    2, SFRONTIER_2.to_bytes(), CDIGEST_2
)
CFRONTIER_FULL = commit_frontier_for(
    1, SFRONTIER_2.to_bytes(), CDIGEST_FULL
)


class StreamCommitReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = StreamCommitReceiptFrontier(
            1,
            1,
            SFRONTIER_1.to_bytes(),
            CDIGEST_1,
            CFRONTIER_1.mac,
        )
        self.assertEqual(frontier, CFRONTIER_1)
        self.assertEqual(hash(frontier), hash(CFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, SFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, CDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            CFRONTIER_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(CFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1, 10 ** 30):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, sequence=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(SFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty stream receipt frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CFRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "1", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})
            for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    dataclasses.replace(CFRONTIER_1, **{name: bad})


class StreamCommitReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + SFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + CDIGEST_1.hex().encode() + b'",'
            b'"' + CFRONTIER_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(CFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (CFRONTIER_1, CFRONTIER_2, CFRONTIER_FULL):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptFrontier.from_bytes(blob), frontier
            )
            self.assertEqual(
                StreamCommitReceiptFrontier.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = CFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            SFRONTIER_1.to_bytes().hex(),
            CDIGEST_1.hex(),
            CFRONTIER_1.mac.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError):
                StreamCommitReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = CFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            CFRONTIER_1.mac.hex().encode(),
            CFRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the commit frontier MAC nor the nested end MACs are
        # checked at parse time.
        tampered = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        parsed = StreamCommitReceiptFrontier.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_mac_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ26"
            + ZERO
            + (1).to_bytes(8, "big")
            + CRECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(CDIGEST_1, expected_digest)
        expected_mac = hmac.new(
            KEY,
            b"NPBJ25"
            + _stream_commit_receipt_frontier_content_bytes(CFRONTIER_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(CFRONTIER_1.mac, expected_mac)


class StreamCommitReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(StreamCommitReceiptAuditor(KEY).state)
        self.assertIsNone(
            StreamCommitReceiptAuditor(KEY, checkpoint=None).state
        )
        self.assertIsNone(StreamCommitReceiptAuditor(KEY).checkpoint)

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            CFRONTIER_1,
            CFRONTIER_1.to_bytes(),
        ):
            auditor = StreamCommitReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.state, CFRONTIER_1)
            self.assertEqual(auditor.checkpoint, CFRONTIER_1)
            self.assertIs(auditor.state, auditor.checkpoint)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [CFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(KEY, checkpoint=b"junk")

    def test_checkpoint_own_frontier_mac_verified(self):
        tampered = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_stream_frontier_mac_verified(self):
        # The nested stream receipt frontier's own NPBJ21 layer is
        # recomputed on load; re-MAC the outer layer so only it fails.
        bad_end = dataclasses.replace(SFRONTIER_1, mac=ZERO)
        tampered = commit_frontier_for(
            1, bad_end.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_deep_nested_mac_verified(self):
        # The NPBJ17 layer two levels down (inside the end stream
        # frontier's range-batch receipt frontier) is recomputed too.
        bad_nested = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        bad_stream_end = stream_frontier_for(
            1, bad_nested.to_bytes(), SDIGEST_1
        )
        tampered = commit_frontier_for(
            1, bad_stream_end.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            StreamCommitReceiptAuditor(
                OTHER_KEY, checkpoint=CFRONTIER_1
            )

    def test_state_is_read_only(self):
        with self.assertRaises(AttributeError):
            StreamCommitReceiptAuditor(KEY).state = CFRONTIER_1
        with self.assertRaises(AttributeError):
            StreamCommitReceiptAuditor(KEY).checkpoint = CFRONTIER_1


class StreamCommitReceiptAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit(CRECEIPT_1, SBATCH_1), auditor)
        self.assertEqual(auditor.state, CFRONTIER_1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, SFRONTIER_1.to_bytes())
        self.assertEqual(auditor.state.digest, CDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        auditor.audit(CRECEIPT_2, SBATCH_2)
        self.assertEqual(auditor.state, CFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.end, SFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state.digest, CDIGEST_2)

    def test_full_batch_commits_in_one_audit(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, SBATCH_FULL)
        self.assertEqual(auditor.state, CFRONTIER_FULL)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, SFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1.to_bytes(), SBATCH_1.to_bytes())
        self.assertEqual(auditor.state, CFRONTIER_1)
        auditor.audit(CRECEIPT_2, SBATCH_2)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        for checkpoint in (
            auditor.state,
            auditor.checkpoint.to_bytes(),
        ):
            restored = StreamCommitReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            restored.audit(CRECEIPT_2, SBATCH_2)
            self.assertEqual(restored.state, CFRONTIER_2)

    def test_first_commit_must_start_empty(self):
        # A batch continuing from SFRONTIER_1 cannot be the first commit
        # of a fresh ledger.
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, SBATCH_2)
        self.assertIsNone(auditor.state)

    def test_replayed_last_commit_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, SBATCH_1)
        self.assertIs(auditor.state, before)

    def test_old_receipt_and_old_fork_rejected(self):
        # Commit the both-items batch straight to SFRONTIER_2; the
        # genesis receipt and the continuation receipt are then both old
        # forks whose start does not link to the current end.
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_FULL, SBATCH_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, SBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, SBATCH_2)
        self.assertIs(auditor.state, before)

    def test_receipt_batch_pair_mismatch_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, SBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, SBATCH_2)
        self.assertIs(auditor.state, before)

    def test_tampered_receipt_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(CRECEIPT_1, mac=ZERO), SBATCH_1
            )
        self.assertIsNone(auditor.state)

    def test_wrong_key_rejected(self):
        auditor = StreamCommitReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, SBATCH_1)
        self.assertIsNone(auditor.state)

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (1, "x", None, [CRECEIPT_1], (CRECEIPT_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, SBATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, SBATCH_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(CRECEIPT_1, bad)
        self.assertIsNone(auditor.state)

    def test_non_canonical_bytes_is_value_error(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        blob = CRECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(blob.replace(b",", b", "), SBATCH_1)
        batch_blob = SBATCH_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_1, batch_blob.replace(b",", b", "))
        self.assertIsNone(auditor.state)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, SBATCH_2)
        self.assertIsNone(auditor.state)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        auditor = StreamCommitReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(CRECEIPT_2, SBATCH_2)
        self.assertIs(auditor.state, before)

    def test_competing_commits_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        commits, failures = [], []

        def run(receipt, batch):
            try:
                auditor.audit(receipt, batch)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(CRECEIPT_1, SBATCH_1)
            ),
            threading.Thread(
                target=run, args=(CRECEIPT_1, SBATCH_1)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, SFRONTIER_1.to_bytes())


if __name__ == "__main__":
    unittest.main()
