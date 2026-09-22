import dataclasses
import threading
import unittest

from nearproof import (
    RangeAuditor,
    RangeReceiptBatch,
    _range_receipt_batch_mac,
    seal_range_receipt_batch,
)
from test_range_auditor_audit_batch import (
    CHAIN,
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RANGE_1,
    RANGE_FROM_CP,
    RDIGEST_1,
    RECEIPT_R1,
    RECEIPT_RCP,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    range_frontier_for,
)

RBATCH_1 = seal_range_receipt_batch([(RECEIPT_R1, RANGE_1)], KEY)
RBATCH_2 = seal_range_receipt_batch(
    [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint=RFRONTIER_1
)
RBATCH_FULL = seal_range_receipt_batch(CHAIN, KEY)


class AuditBatchRecordSuccessTest(unittest.TestCase):
    def test_returns_self_and_advances_to_declared_end(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit_batch_record(RBATCH_FULL), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(
            auditor.audit_batch_record(RBATCH_FULL.to_bytes()), auditor
        )
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_single_item_batch(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_chained_records_start_at_current_state(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertIs(auditor.audit_batch_record(RBATCH_2), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_matches_audit_and_audit_batch(self):
        via_record = RangeAuditor(KEY)
        via_record.audit_batch_record(RBATCH_1)
        via_record.audit_batch_record(RBATCH_2)
        via_singles = RangeAuditor(KEY)
        via_singles.audit(RECEIPT_R1, RANGE_1)
        via_singles.audit(RECEIPT_RCP, RANGE_FROM_CP)
        via_batch = RangeAuditor(KEY)
        via_batch.audit_batch(CHAIN)
        self.assertEqual(via_record.state, via_singles.state)
        self.assertEqual(via_record.state, via_batch.state)

    def test_mixed_with_old_entry_points(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        auditor.audit_batch_record(RBATCH_2)
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(((RECEIPT_R1, RANGE_1),))
        auditor.audit_batch_record(RBATCH_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_restart_from_checkpoint_then_record(self):
        first = RangeAuditor(KEY)
        first.audit_batch_record(RBATCH_1)
        restored = RangeAuditor(
            KEY, checkpoint=first.state.to_bytes()
        )
        restored.audit_batch_record(RBATCH_2)
        self.assertEqual(restored.state, RFRONTIER_2)


class AuditBatchRecordStartTest(unittest.TestCase):
    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(RBATCH_2)
        self.assertIsNone(auditor.state)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(RBATCH_FULL)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_same_batch_replayed_rejected(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(RBATCH_FULL)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(RBATCH_FULL.to_bytes())
        self.assertIs(auditor.state, before)

    def test_old_fork_rejected(self):
        # A structurally valid batch starting at a different frontier
        # than the current one is an old fork.
        fork_frontier = range_frontier_for(
            1, CFRONTIER_1.to_bytes(), b"\x02" * 32
        )
        placeholder = RangeReceiptBatch(
            1,
            fork_frontier.to_bytes(),
            RBATCH_2.items,
            RBATCH_2.end,
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(signed)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_broken_link_inside_batch_rejected(self):
        # The second carried receipt starts at the empty string while the
        # first ends elsewhere: it audits on its own merits but breaks the
        # replayed chain.
        forged_items = (
            (RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),
            (
                dataclasses.replace(RECEIPT_RCP, start=b"").to_bytes(),
                RANGE_FROM_CP.to_bytes(),
            ),
        )
        placeholder = RangeReceiptBatch(
            1, b"", forged_items, RFRONTIER_2.to_bytes(), ZERO
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(signed)
        self.assertIsNone(auditor.state)


class AuditBatchRecordTypeContractTest(unittest.TestCase):
    def test_wrong_kind_is_type_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [RBATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch_record(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_or_non_canonical_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        variants = (
            b"junk",
            b"[1,2,3]",
            b"",
            RBATCH_FULL.to_bytes() + b" ",
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_batch_record(bad)
        self.assertIsNone(auditor.state)

    def test_failed_call_leaves_auditor_usable(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_batch_record(42)
        auditor.audit_batch_record(RBATCH_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)


class AuditBatchRecordVerificationTest(unittest.TestCase):
    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).audit_batch_record(RBATCH_FULL)

    def test_batch_mac_mismatch_rejected(self):
        forged = dataclasses.replace(RBATCH_FULL, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_batch_record(forged)

    def test_tampered_start_frontier_rejected(self):
        bad_start = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        placeholder = RangeReceiptBatch(
            1,
            bad_start.to_bytes(),
            RBATCH_2.items,
            RBATCH_2.end,
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(signed)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_tampered_end_frontier_rejected(self):
        bad_end = dataclasses.replace(RFRONTIER_2, mac=ZERO)
        placeholder = RangeReceiptBatch(
            1, b"", RBATCH_FULL.items, bad_end.to_bytes(), ZERO
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_batch_record(signed)

    def test_tampered_carried_receipt_rejected(self):
        broken_items = (
            (
                dataclasses.replace(RECEIPT_R1, mac=ZERO).to_bytes(),
                RANGE_1.to_bytes(),
            ),
            (RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),
        )
        placeholder = RangeReceiptBatch(
            1, b"", broken_items, RFRONTIER_2.to_bytes(), ZERO
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_batch_record(signed)

    def test_end_must_match_replayed_chain(self):
        placeholder = RangeReceiptBatch(
            1,
            RBATCH_FULL.start,
            RBATCH_FULL.items,
            RFRONTIER_1.to_bytes(),
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_batch_record(signed)


class AuditBatchRecordAtomicityTest(unittest.TestCase):
    def test_failure_changes_nothing_from_empty(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(RBATCH_2)
        self.assertIsNone(auditor.state)
        auditor.audit_batch_record(RBATCH_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_failure_keeps_prior_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(RBATCH_FULL)
        self.assertIs(auditor.state, before)
        auditor.audit_batch_record(RBATCH_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_sequence_overflow_rejected_without_state_change(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        items = ((RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),)
        placeholder = RangeReceiptBatch(
            1, maxed.to_bytes(), items, RFRONTIER_2.to_bytes(), ZERO
        )
        overflow = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        auditor = RangeAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_batch_record(overflow)
        self.assertIs(auditor.state, before)


class AuditBatchRecordLinearizationTest(unittest.TestCase):
    def test_record_batch_and_single_competing_calls_linearize(self):
        auditor = RangeAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_batch_record(RBATCH_FULL),
                    "record",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(CHAIN), "batch"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_R1, RANGE_1),
                    "one",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        winner = successes[0]
        if winner == "one":
            self.assertEqual(auditor.state, RFRONTIER_1)
        else:
            self.assertEqual(auditor.state, RFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
