import dataclasses
import hashlib
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptAuditor,
    BitMapHistoryJournalReceiptFrontier,
    BitMapHistoryJournalState,
    BitMapUpdate,
    CommitRange,
    CommitRangeAuditor,
    JournalBatchReceipt,
    JournalBatchReceiptFrontier,
    _bit_map_history_journal_batch_receipt_frontier_mac,
    _bit_map_history_journal_batch_receipt_frontier_next_digest,
    _bit_map_history_journal_batch_receipt_mac,
    _bit_map_history_journal_mac,
    _bit_map_history_journal_receipt_frontier_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
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


class CommitRangeAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, None, "k", bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRangeAuditor(bad)
        with self.assertRaises(ValueError):
            CommitRangeAuditor(b"")

    def test_empty_checkpoint(self):
        auditor = CommitRangeAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        self.assertEqual(
            CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1).checkpoint,
            CFRONTIER_1,
        )
        self.assertEqual(
            CommitRangeAuditor(
                KEY, checkpoint=CFRONTIER_1.to_bytes()
            ).checkpoint,
            CFRONTIER_1,
        )

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", bytearray(CFRONTIER_1.to_bytes()), []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"", b"not-json", b"[]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_commit_frontier_mac_verified(self):
        tampered = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY, checkpoint=tampered.to_bytes())

    def test_checkpoint_end_receipt_frontier_mac_verified(self):
        # The NPBJ5 layer of the end receipt frontier is recomputed on load.
        bad_end = dataclasses.replace(
            BitMapHistoryJournalReceiptFrontier.from_bytes(CFRONTIER_1.end),
            mac=ZERO,
        )
        tampered = commit_frontier_for(1, bad_end.to_bytes(), CDIGEST_1)
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_state_mac_verified(self):
        # The NPBJ1 layer of the end journal state is recomputed on load.
        end_frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
            CFRONTIER_1.end
        )
        bad_state = dataclasses.replace(
            BitMapHistoryJournalState.from_bytes(end_frontier.end), mac=ZERO
        )
        bad_frontier = dataclasses.replace(
            end_frontier, end=bad_state.to_bytes()
        )
        bad_frontier = dataclasses.replace(
            bad_frontier,
            mac=_bit_map_history_journal_receipt_frontier_mac(
                KEY, bad_frontier
            ),
        )
        tampered = commit_frontier_for(
            1, bad_frontier.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_table_mac_verified(self):
        # The NPBL1 layer of the end checkpoint table is recomputed on load.
        end_frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
            CFRONTIER_1.end
        )
        state = BitMapHistoryJournalState.from_bytes(end_frontier.end)
        bad_map = dataclasses.replace(
            BitMap.from_bytes(state.checkpoint), mac=ZERO
        )
        bad_state = dataclasses.replace(
            state, checkpoint=bad_map.to_bytes()
        )
        bad_state = dataclasses.replace(
            bad_state, mac=_bit_map_history_journal_mac(KEY, bad_state)
        )
        bad_frontier = dataclasses.replace(
            end_frontier, end=bad_state.to_bytes()
        )
        bad_frontier = dataclasses.replace(
            bad_frontier,
            mac=_bit_map_history_journal_receipt_frontier_mac(
                KEY, bad_frontier
            ),
        )
        tampered = commit_frontier_for(
            1, bad_frontier.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(OTHER_KEY, checkpoint=CFRONTIER_1)

    def test_checkpoint_is_frozen_export(self):
        auditor = CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            auditor.checkpoint.sequence = 9


class CommitRangeAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = CommitRangeAuditor(KEY)
        self.assertIs(auditor.audit(RANGE_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        auditor.audit(RANGE_FROM_CP)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = CommitRangeAuditor(KEY)
        self.assertIs(auditor.audit(RANGE_1.to_bytes()), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_multi_commit_range_from_empty(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_restart_from_checkpoint(self):
        first = CommitRangeAuditor(KEY)
        first.audit(RANGE_1)
        restarted = CommitRangeAuditor(
            KEY, checkpoint=first.checkpoint.to_bytes()
        )
        restarted.audit(RANGE_FROM_CP)
        self.assertEqual(restarted.checkpoint, CFRONTIER_2)

    def test_empty_state_requires_empty_start(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY).audit(RANGE_FROM_CP)
        # The failed audit leaves no checkpoint behind.
        self.assertIsNone(CommitRangeAuditor(KEY).checkpoint)

    def test_checkpointed_state_rejects_empty_start(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1).audit(RANGE_1)

    def test_same_end_replay_rejected(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_1)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_old_range_rejected(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_2)
        # RANGE_1 starts empty, so it fails the start gate before the
        # sequence gate even matters.
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_same_end_replay_from_checkpoint_rejected(self):
        # From CFRONTIER_1 the continuation ends at sequence 2; delivering
        # it again is a same-end replay refused by the strict-advance gate.
        auditor = CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1)
        auditor.audit(RANGE_FROM_CP)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_start_must_equal_current_checkpoint(self):
        # A range starting from a different, independently valid
        # checkpoint (same sequence, different end) is a fork and rejected.
        other_digest = _bit_map_history_journal_batch_receipt_frontier_next_digest(
            ZERO, 1, COMMIT_2.to_bytes()
        )
        other_frontier = commit_frontier_for(
            1, BATCH_1.end, other_digest
        )
        forked = seal_range(
            [(COMMIT_2, BATCH_2)], KEY, checkpoint=other_frontier
        )
        auditor = CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1)
        with self.assertRaises(ValueError):
            auditor.audit(forked)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_x_type_contract(self):
        auditor = CommitRangeAuditor(KEY)
        for bad in (1, None, "x", [], bytearray(RANGE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = CommitRangeAuditor(KEY)
        for bad in (b"", b"not-json", b"[1,\"\",\"\"]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_range_mac_rejected(self):
        tampered = dataclasses.replace(RANGE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY).audit(tampered)

    def test_tampered_body_rejected(self):
        tampered = CommitRange(
            1, RANGE_1.body, RANGE_1.mac
        )
        body = bytearray(tampered.body)
        body[-2] ^= 0x01
        with self.assertRaises(ValueError):
            CommitRangeAuditor(KEY).audit(bytes(body))

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(OTHER_KEY).audit(RANGE_1)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = CommitRangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RANGE_FROM_CP)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(RANGE_1)
        tampered = dataclasses.replace(RANGE_FROM_CP, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        auditor.audit(RANGE_FROM_CP)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_failure_returns_no_partial_result(self):
        # A range whose NPBJ11 MAC and carried commits verify but whose E
        # does not match the replayed chain is rejected after the replay;
        # the checkpoint must still be untouched.
        import json

        document = json.loads(RANGE_1.body.decode("utf-8"))
        end = JournalBatchReceiptFrontier.from_bytes(
            bytes.fromhex(document[2])
        )
        wrong_end = dataclasses.replace(end, digest=ZERO, mac=ZERO)
        document[2] = wrong_end.to_bytes().hex()
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        tampered = CommitRange(1, body, _commit_range_mac(KEY, body))
        auditor = CommitRangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        self.assertIsNone(auditor.checkpoint)

    def test_sequence_overflow_rejected(self):
        # A checkpoint at u64 max cannot be continued: a range starting
        # there replays one commit and the advance would overflow u64. The
        # range itself is rebuilt from RANGE_FROM_CP with a saturated start
        # and re-MAC'd, so it is only the overflow gate that fails.
        import json

        saturated = commit_frontier_for(U64_MAX, BATCH_1.end, CDIGEST_1)
        document = json.loads(RANGE_FROM_CP.body.decode("utf-8"))
        document[0] = saturated.to_bytes().hex()
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        overflow_range = CommitRange(
            1, body, _commit_range_mac(KEY, body)
        )
        auditor = CommitRangeAuditor(KEY, checkpoint=saturated)
        with self.assertRaises(ValueError):
            auditor.audit(overflow_range)
        self.assertEqual(auditor.checkpoint, saturated)


class CommitRangeAuditorConcurrencyTest(unittest.TestCase):
    def test_concurrent_audits_linearize_to_one_chain(self):
        auditor = CommitRangeAuditor(KEY)
        errors = []

        def worker(record):
            try:
                auditor.audit(record)
            except ValueError:
                # Exactly one audit at each frontier position can win;
                # replays and losing starts are rejected.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        # Phase 1: five identical empty-start ranges race; exactly one wins.
        first_barrier = threading.Barrier(5)

        def first_stage():
            first_barrier.wait()
            worker(RANGE_1)

        threads = [threading.Thread(target=first_stage) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

        # Phase 2: five continuations race from the new checkpoint; one wins.
        second_barrier = threading.Barrier(5)

        def second_stage():
            second_barrier.wait()
            worker(RANGE_FROM_CP)

        threads = [threading.Thread(target=second_stage) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_advance_wins_against_rejected_rollback(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.audit(RANGE_1)
        start = threading.Barrier(2)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    auditor.audit(RANGE_1)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            auditor.audit(RANGE_FROM_CP)
            outcomes.append("advanced")

        threads = [
            threading.Thread(target=rollback),
            threading.Thread(target=advance),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
