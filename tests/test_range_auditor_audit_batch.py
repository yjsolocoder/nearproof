import dataclasses
import hashlib
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptAuditor,
    BitMapUpdate,
    CommitRange,
    JournalBatchReceipt,
    JournalBatchReceiptFrontier,
    RangeAuditor,
    RangeFrontier,
    RangeReceipt,
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
    _range_frontier_mac,
    _range_frontier_next_digest,
    _range_receipt_mac,
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
RANGE_FROM_CP = seal_range(
    [(COMMIT_2, BATCH_2)], KEY, checkpoint=CFRONTIER_1
)


def range_receipt_for(record, start, end, key=KEY):
    placeholder = RangeReceipt(
        1,
        start,
        hashlib.sha256(record.to_bytes()).digest(),
        end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_range_receipt_mac(key, placeholder)
    )


RECEIPT_R1 = range_receipt_for(RANGE_1, b"", CFRONTIER_1.to_bytes())
RECEIPT_RCP = range_receipt_for(
    RANGE_FROM_CP, CFRONTIER_1.to_bytes(), CFRONTIER_2.to_bytes()
)

CHAIN = ((RECEIPT_R1, RANGE_1), (RECEIPT_RCP, RANGE_FROM_CP))


def range_frontier_for(sequence, end, digest, key=KEY):
    placeholder = RangeFrontier(1, sequence, end, digest, ZERO)
    return dataclasses.replace(
        placeholder, mac=_range_frontier_mac(key, placeholder)
    )


RDIGEST_1 = _range_frontier_next_digest(ZERO, 1, RECEIPT_R1.to_bytes())
RDIGEST_2 = _range_frontier_next_digest(
    RDIGEST_1, 2, RECEIPT_RCP.to_bytes()
)
RFRONTIER_1 = range_frontier_for(
    1, CFRONTIER_1.to_bytes(), RDIGEST_1
)
RFRONTIER_2 = range_frontier_for(
    2, CFRONTIER_2.to_bytes(), RDIGEST_2
)


class AuditBatchCommitTest(unittest.TestCase):
    def test_returns_self_and_advances_to_chain_end(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit_batch(CHAIN), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.end, CFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state.digest, RDIGEST_2)
        self.assertEqual(
            auditor.state.mac, _range_frontier_mac(KEY, auditor.state)
        )

    def test_single_item_batch(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(
            auditor.audit_batch(((RECEIPT_R1, RANGE_1),)), auditor
        )
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(
            (
                (RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),
                (RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),
            )
        )
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_accepts_any_non_empty_iterable(self):
        via_list = RangeAuditor(KEY).audit_batch(list(CHAIN))
        via_tuple = RangeAuditor(KEY).audit_batch(CHAIN)
        via_generator = RangeAuditor(KEY).audit_batch(
            (pair for pair in CHAIN)
        )
        self.assertEqual(via_list.state, RFRONTIER_2)
        self.assertEqual(via_tuple.state, RFRONTIER_2)
        self.assertEqual(via_generator.state, RFRONTIER_2)

    def test_chained_batches_start_at_current_state(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(((RECEIPT_R1, RANGE_1),))
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertIs(
            auditor.audit_batch(((RECEIPT_RCP, RANGE_FROM_CP),)),
            auditor,
        )
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_matches_single_receipt_audits(self):
        via_batch = RangeAuditor(KEY)
        via_batch.audit_batch(CHAIN)
        via_singles = RangeAuditor(KEY)
        via_singles.audit(RECEIPT_R1, RANGE_1)
        via_singles.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(via_batch.state, via_singles.state)

    def test_mixed_single_and_batch_share_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        auditor.audit_batch(((RECEIPT_RCP, RANGE_FROM_CP),))
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(((RECEIPT_R1, RANGE_1),))
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_restart_from_checkpoint_then_batch(self):
        first = RangeAuditor(KEY)
        first.audit_batch(((RECEIPT_R1, RANGE_1),))
        restored = RangeAuditor(
            KEY, checkpoint=first.state.to_bytes()
        )
        restored.audit_batch(((RECEIPT_RCP, RANGE_FROM_CP),))
        self.assertEqual(restored.state, RFRONTIER_2)


class AuditBatchStartTest(unittest.TestCase):
    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(((RECEIPT_RCP, RANGE_FROM_CP),))
        self.assertIsNone(auditor.state)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(((RECEIPT_R1, RANGE_1),))
        with self.assertRaises(ValueError):
            auditor.audit_batch(CHAIN)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_replayed_batch_rejected_on_start(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(CHAIN)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_batch(CHAIN)
        self.assertIs(auditor.state, before)

    def test_broken_link_inside_batch_rejected(self):
        # The second receipt starts at the empty string while the first
        # ends elsewhere: it audits on its own merits but breaks the
        # batch chain.
        forged = range_receipt_for(
            RANGE_FROM_CP, b"", CFRONTIER_2.to_bytes()
        )
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                (
                    (RECEIPT_R1, RANGE_1),
                    (forged, RANGE_FROM_CP),
                )
            )
        self.assertIsNone(auditor.state)


class AuditBatchTypeContractTest(unittest.TestCase):
    def test_non_iterable_argument_is_type_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_item_must_be_exactly_a_two_element_tuple(self):
        auditor = RangeAuditor(KEY)
        good = (RECEIPT_R1, RANGE_1)
        for bad in (
            RECEIPT_R1,
            [RECEIPT_R1, RANGE_1],
            (RECEIPT_R1,),
            (RECEIPT_R1, RANGE_1, 0),
            "ab",
            42,
            None,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch([bad])
            # A failure on the second item must be a TypeError too.
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch([good, bad])
        self.assertIsNone(auditor.state)

    def test_wrong_pair_member_kind_is_type_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_R1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch([(bad, RANGE_1)])
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch([(RECEIPT_R1, bad)])
        self.assertIsNone(auditor.state)

    def test_empty_batch_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for empty in ([], (), iter(())):
            with self.assertRaises(ValueError, msg=repr(empty)):
                auditor.audit_batch(empty)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_batch([(bad, RANGE_1)])
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_batch([(RECEIPT_R1, bad)])
        self.assertIsNone(auditor.state)


class AuditBatchVerificationTest(unittest.TestCase):
    def test_tampered_receipt_rejected(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                (
                    (RECEIPT_R1, RANGE_1),
                    (dataclasses.replace(RECEIPT_RCP, mac=ZERO),
                     RANGE_FROM_CP),
                )
            )
        self.assertIsNone(auditor.state)

    def test_tampered_range_rejected(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                (
                    (RECEIPT_R1, RANGE_1),
                    (RECEIPT_RCP,
                     dataclasses.replace(RANGE_FROM_CP, mac=ZERO)),
                )
            )
        self.assertIsNone(auditor.state)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).audit_batch(CHAIN)


class AuditBatchAtomicityTest(unittest.TestCase):
    def test_failure_mid_batch_changes_nothing(self):
        # The first pair audits, the second replays the same receipt and
        # therefore breaks the chain: the whole batch must be rejected
        # without advancing the frontier even by one step.
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                (
                    (RECEIPT_R1, RANGE_1),
                    (RECEIPT_R1, RANGE_1),
                )
            )
        self.assertIsNone(auditor.state)
        # The auditor is still usable for a correct batch afterwards.
        auditor.audit_batch(CHAIN)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_failed_batch_keeps_prior_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_batch(
                ((dataclasses.replace(RECEIPT_RCP, mac=ZERO),
                  RANGE_FROM_CP),)
            )
        self.assertIs(auditor.state, before)
        auditor.audit_batch(((RECEIPT_RCP, RANGE_FROM_CP),))
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_sequence_overflow_rejected_without_state_change(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        auditor = RangeAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_batch(((RECEIPT_RCP, RANGE_FROM_CP),))
        self.assertIs(auditor.state, before)


class AuditBatchLinearizationTest(unittest.TestCase):
    def test_batch_and_single_competing_audits_linearize(self):
        auditor = RangeAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(2)

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
        self.assertEqual(len(failures), 1)
        winner = successes[0]
        if winner == "batch":
            self.assertEqual(auditor.state, RFRONTIER_2)
        else:
            self.assertEqual(auditor.state, RFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
