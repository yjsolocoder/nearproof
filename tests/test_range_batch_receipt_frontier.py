import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitMapHistoryJournalReceiptFrontier,
    RangeBatchReceiptAuditor,
    RangeBatchReceiptFrontier,
    _range_batch_receipt_frontier_content_bytes,
    _range_batch_receipt_frontier_mac,
    _range_batch_receipt_frontier_next_digest,
)
from test_range_auditor_audit_batch import (
    CDIGEST_1,
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RDIGEST_1,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    commit_frontier_for,
    range_frontier_for,
)
from test_range_batch_receipt import (
    RBATCH_1,
    RBATCH_2,
    RBATCH_FULL,
    RECEIPT_B1,
    RECEIPT_B2,
    RECEIPT_BFULL,
)


def batch_frontier_for(sequence, end, digest, key=KEY):
    placeholder = RangeBatchReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_range_batch_receipt_frontier_mac(key, placeholder),
    )


BDIGEST_1 = _range_batch_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_B1.to_bytes()
)
BDIGEST_2 = _range_batch_receipt_frontier_next_digest(
    BDIGEST_1, 2, RECEIPT_B2.to_bytes()
)
BFRONTIER_1 = batch_frontier_for(
    1, RFRONTIER_1.to_bytes(), BDIGEST_1
)
BFRONTIER_2 = batch_frontier_for(
    2, RFRONTIER_2.to_bytes(), BDIGEST_2
)


class BatchReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = RangeBatchReceiptFrontier(
            1, 1, RBATCH_1.end, BDIGEST_1, BFRONTIER_1.mac
        )
        self.assertEqual(frontier, BFRONTIER_1)
        self.assertEqual(hash(frontier), hash(BFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, RBATCH_1.end)
        self.assertEqual(frontier.digest, BDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BFRONTIER_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BFRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(BFRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(RBATCH_1.end)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BFRONTIER_1, end=bad)
        # end must be the canonical non-empty RangeFrontier encoding:
        # not empty, not junk and not a commit frontier.
        for bad in (b"", b"junk", CFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BFRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(BFRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(BFRONTIER_1, **{name: bad})


class BatchReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + RBATCH_1.end.hex().encode() + b'",'
            b'"' + BDIGEST_1.hex().encode() + b'",'
            b'"' + BFRONTIER_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(BFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (BFRONTIER_1, BFRONTIER_2):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                RangeBatchReceiptFrontier.from_bytes(blob), frontier
            )
            self.assertEqual(
                RangeBatchReceiptFrontier.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = BFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            BFRONTIER_1.end.hex(),
            BDIGEST_1.hex(),
            BFRONTIER_1.mac.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1")):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError):
                RangeBatchReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = BFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            RangeBatchReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            BFRONTIER_1.mac.hex().encode(),
            BFRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            RangeBatchReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            RangeBatchReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        parsed = RangeBatchReceiptFrontier.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_mac_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ18"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_B1.to_bytes()
        ).digest()
        self.assertEqual(BDIGEST_1, expected_digest)
        expected_mac = hmac.new(
            KEY,
            b"NPBJ17"
            + _range_batch_receipt_frontier_content_bytes(BFRONTIER_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BFRONTIER_1.mac, expected_mac)


class BatchReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(RangeBatchReceiptAuditor(KEY).state)
        self.assertIsNone(
            RangeBatchReceiptAuditor(KEY, checkpoint=None).state
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (BFRONTIER_1, BFRONTIER_1.to_bytes()):
            auditor = RangeBatchReceiptAuditor(KEY, checkpoint=checkpoint)
            self.assertEqual(auditor.state, BFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [BFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=b"junk")

    def test_checkpoint_own_frontier_mac_verified(self):
        tampered = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_range_frontier_mac_verified(self):
        # The end range frontier's own NPBJ13 layer is recomputed on
        # load.
        bad_end = dataclasses.replace(
            range_frontier_for(1, CFRONTIER_1.to_bytes(), RDIGEST_1),
            mac=ZERO,
        )
        tampered = batch_frontier_for(
            1, bad_end.to_bytes(), BDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_commit_frontier_mac_verified(self):
        # The nested commit frontier's NPBJ9 layer is recomputed on
        # load: re-MAC every outer layer so only that layer fails.
        bad_commit = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        bad_range = range_frontier_for(
            1, bad_commit.to_bytes(), RDIGEST_1
        )
        tampered = batch_frontier_for(
            1, bad_range.to_bytes(), BDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_receipt_frontier_mac_verified(self):
        # The NPBJ5 layer inside the nested commit frontier's end is
        # recomputed on load as well.
        bad_receipt_frontier = dataclasses.replace(
            BitMapHistoryJournalReceiptFrontier.from_bytes(CFRONTIER_1.end),
            mac=ZERO,
        )
        bad_commit = commit_frontier_for(
            1, bad_receipt_frontier.to_bytes(), CDIGEST_1
        )
        bad_range = range_frontier_for(
            1, bad_commit.to_bytes(), RDIGEST_1
        )
        tampered = batch_frontier_for(
            1, bad_range.to_bytes(), BDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(OTHER_KEY, checkpoint=BFRONTIER_1)

    def test_state_is_read_only(self):
        with self.assertRaises(AttributeError):
            RangeBatchReceiptAuditor(KEY).state = BFRONTIER_1


class BatchReceiptAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_B1, RBATCH_1), auditor)
        self.assertEqual(auditor.state, BFRONTIER_1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, RBATCH_1.end)
        self.assertEqual(auditor.state.digest, BDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertEqual(auditor.state, BFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.end, RBATCH_2.end)
        self.assertEqual(auditor.state.digest, BDIGEST_2)

    def test_full_batch_commits_in_one_audit(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_BFULL, RBATCH_FULL)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, RBATCH_FULL.end)

    def test_accepts_canonical_bytes(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes())
        self.assertEqual(auditor.state, BFRONTIER_1)
        auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertEqual(auditor.state, BFRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        blob = auditor.state.to_bytes()
        restored = RangeBatchReceiptAuditor(KEY, checkpoint=blob)
        restored.audit(RECEIPT_B2, RBATCH_2)
        self.assertEqual(restored.state, BFRONTIER_2)

    def test_first_commit_must_start_empty(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertIsNone(auditor.state)

    def test_replayed_commit_rejected(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertIs(auditor.state, before)

    def test_tampered_commit_rejected(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_B1, mac=ZERO), RBATCH_1
            )
        self.assertIsNone(auditor.state)

    def test_wrong_batch_rejected(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_B1, RBATCH_FULL)
        self.assertIsNone(auditor.state)

    def test_wrong_argument_type(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_B1], (RECEIPT_B1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, RBATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_B1, bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, RBATCH_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_B1, bad)
        self.assertIsNone(auditor.state)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_B1, mac=ZERO), RBATCH_1
            )
        self.assertIsNone(auditor.state)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertEqual(auditor.state, BFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = batch_frontier_for(
            U64_MAX, RFRONTIER_1.to_bytes(), BDIGEST_1
        )
        auditor = RangeBatchReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertIs(auditor.state, before)

    def test_competing_commits_linearize(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        commits, failures = [], []

        def run(receipt, batch):
            try:
                auditor.audit(receipt, batch)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(RECEIPT_B1, RBATCH_1)
            ),
            threading.Thread(
                target=run, args=(RECEIPT_BFULL, RBATCH_FULL)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, commits[0].end)


if __name__ == "__main__":
    unittest.main()
