import dataclasses
import hashlib
import json
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptAuditor,
    BitMapUpdate,
    CommitRange,
    CommitRangeAuditor,
    JournalBatchReceipt,
    JournalBatchReceiptFrontier,
    _bit_map_history_journal_batch_receipt_frontier_mac,
    _bit_map_history_journal_batch_receipt_frontier_next_digest,
    _bit_map_history_journal_batch_receipt_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _commit_range_body_bytes,
    _commit_range_mac,
    seal_map_history,
    seal_map_history_journal_bundle,
    seal_map_history_journal_receipt_batch,
    seal_range,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2

SID_A = b"\x0a" * 32
SID_B = b"\x0b" * 32
HASH_1 = b"\x01" * 32
HASH_2 = b"\x02" * 32
HASH_3 = b"\x03" * 32
ZERO = b"\x00" * 32
U64_MAX = 0xFFFFFFFFFFFFFFFF


def map_for(entries, key=KEY):
    ordered = tuple(sorted(entries))
    return BitMap(1, ordered, _bit_map_mac(key, _bit_map_payload(ordered)))


def update_for(before, after, key=KEY):
    placeholder = BitMapUpdate(1, before, after, ZERO)
    mac = _bit_map_update_mac(key, _bit_map_update_payload(placeholder))
    return BitMapUpdate(1, before, after, mac)


MAP_1 = map_for(((SID_A, 1, HASH_1),))
MAP_2 = map_for(((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)))
MAP_3 = map_for(((SID_A, 3, HASH_3), (SID_B, 2, HASH_2)))

UPDATE_1 = update_for(b"", MAP_1.to_bytes())
UPDATE_2 = update_for(MAP_1.to_bytes(), MAP_2.to_bytes())
UPDATE_3 = update_for(MAP_2.to_bytes(), MAP_3.to_bytes())

EVIDENCE_1 = seal_map_history([UPDATE_1, UPDATE_2], KEY)
EVIDENCE_2 = seal_map_history([UPDATE_3], KEY, checkpoint=MAP_2)


def audited_state(*evidences, key=KEY):
    auditor = BitMapHistoryJournalAuditor(key)
    for evidence in evidences:
        auditor.audit(evidence)
    return auditor.state


STATE_1 = audited_state(EVIDENCE_1)

BUNDLE_1 = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
BUNDLE_2 = seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=STATE_1)


def receipt_for(bundle, key=KEY):
    placeholder = BitMapHistoryJournalReceipt(
        1,
        bundle.start,
        hashlib.sha256(bundle.to_bytes()).digest(),
        bundle.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_receipt_mac(key, placeholder)
    )


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)

BATCH_1 = seal_map_history_journal_receipt_batch([(RECEIPT_1, BUNDLE_1)], KEY)
FRONTIER_1 = BitMapHistoryJournalReceiptAuditor(KEY).audit_batch(
    BATCH_1
).checkpoint
BATCH_2 = seal_map_history_journal_receipt_batch(
    [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=FRONTIER_1
)


def commit_for(batch, key=KEY):
    placeholder = JournalBatchReceipt(
        1,
        batch.start,
        hashlib.sha256(batch.to_bytes()).digest(),
        batch.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        mac=_bit_map_history_journal_batch_receipt_mac(key, placeholder),
    )


COMMIT_1 = commit_for(BATCH_1)
COMMIT_2 = commit_for(BATCH_2)


def commit_frontier_for(sequence, end, digest, key=KEY):
    placeholder = JournalBatchReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_bit_map_history_journal_batch_receipt_frontier_mac(
            key, placeholder
        ),
    )


CDIGEST_1 = _bit_map_history_journal_batch_receipt_frontier_next_digest(
    ZERO, 1, COMMIT_1.to_bytes()
)
CDIGEST_2 = _bit_map_history_journal_batch_receipt_frontier_next_digest(
    CDIGEST_1, 2, COMMIT_2.to_bytes()
)
CFRONTIER_1 = commit_frontier_for(1, BATCH_1.end, CDIGEST_1)
CFRONTIER_2 = commit_frontier_for(2, BATCH_2.end, CDIGEST_2)

RANGE_1 = seal_range([(COMMIT_1, BATCH_1)], KEY)
RANGE_2 = seal_range([(COMMIT_1, BATCH_1), (COMMIT_2, BATCH_2)], KEY)
RANGE_FROM_CP = seal_range(
    [(COMMIT_2, BATCH_2)], KEY, checkpoint=CFRONTIER_1
)


class CommitRangeAuditorAdvanceTest(unittest.TestCase):
    def test_returns_self_and_advances(self):
        auditor = CommitRangeAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIs(auditor.audit(RANGE_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        self.assertIs(auditor.audit(RANGE_FROM_CP), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_multi_commit_range_advances_in_one_audit(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_2.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_restart_from_checkpoint_bytes_then_continue(self):
        first = CommitRangeAuditor(KEY)
        first.audit(RANGE_1)
        restored = CommitRangeAuditor(
            KEY, checkpoint=first.checkpoint.to_bytes()
        )
        self.assertEqual(restored.checkpoint, CFRONTIER_1)
        restored.audit(RANGE_FROM_CP)
        self.assertEqual(restored.checkpoint, CFRONTIER_2)

    def test_restart_from_checkpoint_object_then_continue(self):
        restored = CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1)
        restored.audit(RANGE_FROM_CP)
        self.assertEqual(restored.checkpoint, CFRONTIER_2)

    def test_checkpoint_property_is_frozen(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            auditor.checkpoint.sequence = 9


class CommitRangeAuditorGateTest(unittest.TestCase):
    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = CommitRangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        self.assertIsNone(auditor.checkpoint)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_old_range_rejected_after_advance(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_2)
        before = auditor.checkpoint
        # RANGE_FROM_CP starts at the older CFRONTIER_1 checkpoint.
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        self.assertIs(auditor.checkpoint, before)

    def test_same_endpoint_replay_rejected(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_1)
        auditor.audit(RANGE_FROM_CP)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        self.assertIs(auditor.checkpoint, before)

    def test_range_from_other_checkpoint_rejected(self):
        # A MAC-valid frontier at the same sequence but a different digest is
        # a fork the start gate must reject byte for byte.
        forked = commit_frontier_for(1, BATCH_1.end, b"\x01" * 32)
        auditor = CommitRangeAuditor(KEY, checkpoint=forked)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        self.assertEqual(auditor.checkpoint, forked)

    def test_gate_failure_leaves_auditor_reusable(self):
        auditor = CommitRangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        auditor.audit(RANGE_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)


class CommitRangeAuditorVerificationTest(unittest.TestCase):
    def test_wrong_key_rejected(self):
        auditor = CommitRangeAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_range_mac_rejected(self):
        auditor = CommitRangeAuditor(KEY)
        tampered = CommitRange(1, RANGE_1.body, ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        with self.assertRaises(ValueError):
            auditor.audit(tampered.to_bytes())
        self.assertIsNone(auditor.checkpoint)

    def test_end_not_matching_replay_rejected(self):
        start, items, _ = json.loads(RANGE_2.body.decode("utf-8"))
        # Only the first commit is carried but E claims the two-commit end.
        bad_body = json.dumps(
            [start, items[:1], CFRONTIER_2.to_bytes().hex()],
            separators=(",", ":"),
        ).encode()
        record = CommitRange(
            1, bad_body, _commit_range_mac(KEY, bad_body)
        )
        auditor = CommitRangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(record)
        self.assertIsNone(auditor.checkpoint)

    def test_carried_checkpoint_bad_mac_rejected(self):
        bad_checkpoint = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        start, items, end = json.loads(RANGE_FROM_CP.body.decode("utf-8"))
        bad_body = _commit_range_body_bytes(
            bad_checkpoint.to_bytes(),
            tuple(
                (bytes.fromhex(r), bytes.fromhex(b)) for r, b in items
            ),
            bytes.fromhex(end),
        )
        record = CommitRange(
            1, bad_body, _commit_range_mac(KEY, bad_body)
        )
        auditor = CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1)
        with self.assertRaises(ValueError):
            auditor.audit(record)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_sequence_overflow_rejected_without_state_change(self):
        # A MAC-valid checkpoint at u64 max, ending where COMMIT_2 starts:
        # replaying even one commit must fail the overflow gate.
        maxed = commit_frontier_for(U64_MAX, BATCH_1.end, ZERO)
        start, items, end = json.loads(RANGE_FROM_CP.body.decode("utf-8"))
        overflow_body = _commit_range_body_bytes(
            maxed.to_bytes(),
            tuple(
                (bytes.fromhex(r), bytes.fromhex(b)) for r, b in items
            ),
            bytes.fromhex(end),
        )
        record = CommitRange(
            1, overflow_body, _commit_range_mac(KEY, overflow_body)
        )
        auditor = CommitRangeAuditor(KEY, checkpoint=maxed)
        with self.assertRaises(ValueError):
            auditor.audit(record)
        self.assertEqual(auditor.checkpoint, maxed)


class CommitRangeAuditorKeyContractTest(unittest.TestCase):
    def test_key_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, bytearray(KEY), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRangeAuditor(bad)

    def test_empty_key_is_value_error(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(b"")


class CommitRangeAuditorCheckpointContractTest(unittest.TestCase):
    def test_checkpoint_wrong_kind_is_type_error(self):
        for bad in (1, "x", [CFRONTIER_1], (CFRONTIER_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_bad_mac_is_value_error(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(
                KEY, checkpoint=dataclasses.replace(CFRONTIER_1, mac=ZERO)
            )
        with self.assertRaises(ValueError):
            CommitRangeAuditor(
                KEY,
                checkpoint=dataclasses.replace(
                    CFRONTIER_1, mac=ZERO
                ).to_bytes(),
            )

    def test_checkpoint_wrong_key_is_value_error(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(OTHER_KEY, checkpoint=CFRONTIER_1)


class CommitRangeAuditorArgumentContractTest(unittest.TestCase):
    def test_x_wrong_kind_is_type_error(self):
        auditor = CommitRangeAuditor(KEY)
        for bad in (1, "x", None, [RANGE_1], (RANGE_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_x_malformed_bytes_is_value_error(self):
        auditor = CommitRangeAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_x_non_canonical_bytes_is_value_error(self):
        auditor = CommitRangeAuditor(KEY)
        blob = RANGE_1.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(blob.replace(b",", b", "))


class CommitRangeAuditorLinearizationTest(unittest.TestCase):
    def test_concurrent_audits_linearize_under_one_lock(self):
        # RANGE_1 (one commit) and RANGE_2 (two commits) both start empty;
        # whichever acquires the lock first commits, the other must fail the
        # start gate rather than overwrite or extend the winner's frontier.
        for _ in range(20):
            auditor = CommitRangeAuditor(KEY)
            commits = []
            failures = []

            def run(record, token):
                try:
                    auditor.audit(record)
                    commits.append(token)
                except ValueError:
                    failures.append(token)

            threads = [
                threading.Thread(target=run, args=(RANGE_1, "one")),
                threading.Thread(target=run, args=(RANGE_2, "two")),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(commits), 1)
            self.assertEqual(len(failures), 1)
            winner = commits[0]
            if winner == "one":
                self.assertEqual(auditor.checkpoint, CFRONTIER_1)
            else:
                self.assertEqual(auditor.checkpoint, CFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
