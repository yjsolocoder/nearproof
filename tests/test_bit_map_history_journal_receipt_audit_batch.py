import dataclasses
import hashlib
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptAuditor,
    BitMapHistoryJournalReceiptBatch,
    BitMapHistoryJournalReceiptFrontier,
    BitMapUpdate,
    _bit_map_history_journal_receipt_batch_mac,
    _bit_map_history_journal_receipt_frontier_mac,
    _bit_map_history_journal_receipt_frontier_next_digest,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    seal_map_history,
    seal_map_history_journal_bundle,
    seal_map_history_journal_receipt_batch,
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
STATE_2 = audited_state(EVIDENCE_1, EVIDENCE_2)

BUNDLE_1 = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
BUNDLE_2 = seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=STATE_1)
BUNDLE_FULL = seal_map_history_journal_bundle([EVIDENCE_1, EVIDENCE_2], KEY)


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
RECEIPT_FULL = receipt_for(BUNDLE_FULL)

BATCH_1 = seal_map_history_journal_receipt_batch([(RECEIPT_1, BUNDLE_1)], KEY)
FRONTIER_1 = BitMapHistoryJournalReceiptFrontier.from_bytes(BATCH_1.end)
BATCH_2 = seal_map_history_journal_receipt_batch(
    [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=FRONTIER_1
)
BATCH_FULL = seal_map_history_journal_receipt_batch(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
)


def reseal(batch, key=KEY):
    return dataclasses.replace(
        batch, mac=_bit_map_history_journal_receipt_batch_mac(key, batch)
    )


class AuditBatchCommitTest(unittest.TestCase):
    def test_returns_self_and_advances_to_batch_end(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        self.assertIs(auditor.audit_batch(BATCH_FULL), auditor)
        self.assertEqual(auditor.checkpoint.to_bytes(), BATCH_FULL.end)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, STATE_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        one = BitMapHistoryJournalReceiptAuditor(KEY).audit_batch(BATCH_FULL)
        two = BitMapHistoryJournalReceiptAuditor(KEY).audit_batch(
            BATCH_FULL.to_bytes()
        )
        self.assertEqual(one.checkpoint, two.checkpoint)

    def test_chained_batches_start_at_current_checkpoint(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertIs(auditor.audit_batch(BATCH_2), auditor)
        self.assertEqual(auditor.checkpoint.to_bytes(), BATCH_2.end)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_matches_single_receipt_audits(self):
        via_batch = BitMapHistoryJournalReceiptAuditor(KEY)
        via_batch.audit_batch(BATCH_FULL)
        via_singles = BitMapHistoryJournalReceiptAuditor(KEY)
        via_singles.audit(RECEIPT_1, BUNDLE_1)
        via_singles.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch.checkpoint, via_singles.checkpoint)

    def test_mixed_single_and_batch_share_frontier(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, STATE_2.to_bytes())


class AuditBatchStartTest(unittest.TestCase):
    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_FULL)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_replayed_batch_rejected_on_start(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_FULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_restart_from_checkpoint_then_batch(self):
        first = BitMapHistoryJournalReceiptAuditor(KEY)
        first.audit_batch(BATCH_1)
        restored = BitMapHistoryJournalReceiptAuditor(
            KEY, checkpoint=first.checkpoint.to_bytes()
        )
        restored.audit_batch(BATCH_2)
        self.assertEqual(restored.checkpoint.sequence, 2)
        self.assertEqual(restored.checkpoint.end, STATE_2.to_bytes())


class AuditBatchTypeContractTest(unittest.TestCase):
    def test_wrong_argument_kind_is_type_error(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_FULL], (BATCH_FULL,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        for bad in (
            b"junk",
            b"[1,2,3]",
            b"[1," + BATCH_FULL.start.hex().encode() + b"]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)


class AuditBatchMacTest(unittest.TestCase):
    def test_batch_mac_mismatch_rejected(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(dataclasses.replace(BATCH_FULL, mac=ZERO))
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(OTHER_KEY).audit_batch(
                BATCH_FULL
            )

    def test_tampered_end_frontier_mac_rejected(self):
        frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
            BATCH_FULL.end
        )
        bad = dataclasses.replace(
            BATCH_FULL, end=dataclasses.replace(frontier, mac=ZERO).to_bytes()
        )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY).audit_batch(reseal(bad))

    def test_tampered_start_frontier_mac_rejected(self):
        frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
            BATCH_2.start
        )
        bad = dataclasses.replace(
            BATCH_2,
            start=dataclasses.replace(frontier, mac=ZERO).to_bytes(),
        )
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(reseal(bad))
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_reordered_items_rejected(self):
        bad = dataclasses.replace(
            BATCH_FULL, items=(BATCH_FULL.items[1], BATCH_FULL.items[0])
        )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY).audit_batch(reseal(bad))

    def test_end_not_matching_replay_rejected(self):
        bad = dataclasses.replace(BATCH_FULL, end=BATCH_1.end)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY).audit_batch(reseal(bad))


class AuditBatchAtomicityTest(unittest.TestCase):
    def test_failure_mid_batch_changes_nothing(self):
        # Tamper the second carried receipt MAC and re-seal the batch: the
        # first item would replay, but the batch must commit atomically.
        receipt, bundle = BATCH_FULL.items[1]
        bad_receipt = dataclasses.replace(
            BitMapHistoryJournalReceipt.from_bytes(receipt), mac=ZERO
        ).to_bytes()
        bad = dataclasses.replace(
            BATCH_FULL, items=(BATCH_FULL.items[0], (bad_receipt, bundle))
        )
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(reseal(bad))
        self.assertIsNone(auditor.checkpoint)
        # The auditor is still usable for a correct batch afterwards.
        auditor.audit_batch(BATCH_FULL)
        self.assertEqual(auditor.checkpoint.to_bytes(), BATCH_FULL.end)

    def test_failed_batch_keeps_prior_frontier(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                dataclasses.replace(BATCH_2, mac=ZERO)
            )
        self.assertIs(auditor.checkpoint, before)

    def test_sequence_overflow_rejected_without_state_change(self):
        chain_digest = _bit_map_history_journal_receipt_frontier_next_digest(
            ZERO, 1, RECEIPT_1.to_bytes()
        )
        placeholder = BitMapHistoryJournalReceiptFrontier(
            1, U64_MAX, STATE_1.to_bytes(), chain_digest, ZERO
        )
        maxed = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_receipt_frontier_mac(
                KEY, placeholder
            ),
        )
        end_placeholder = BitMapHistoryJournalReceiptFrontier(
            1, 0, STATE_2.to_bytes(), ZERO, ZERO
        )
        end = dataclasses.replace(
            end_placeholder,
            mac=_bit_map_history_journal_receipt_frontier_mac(
                KEY, end_placeholder
            ),
        )
        batch = BitMapHistoryJournalReceiptBatch(
            1,
            maxed.to_bytes(),
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            end.to_bytes(),
            ZERO,
        )
        auditor = BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(reseal(batch))
        self.assertIs(auditor.checkpoint, before)


class AuditBatchLinearizationTest(unittest.TestCase):
    def test_batch_and_single_competing_commits_linearize(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        commits = []
        failures = []

        def run(action, token):
            try:
                action()
                commits.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(BATCH_FULL), "batch"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit(RECEIPT_FULL, BUNDLE_FULL), "one"),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.end, STATE_2.to_bytes())
        winner = commits[0]
        if winner == "batch":
            self.assertEqual(auditor.checkpoint.sequence, 2)
        else:
            self.assertEqual(auditor.checkpoint.sequence, 1)


if __name__ == "__main__":
    unittest.main()
