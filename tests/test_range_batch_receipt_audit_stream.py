import threading
import unittest

from nearproof import (
    RangeBatchReceiptAuditor,
    seal_stream,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    RFRONTIER_1,
    U64_MAX,
)
from test_range_batch_receipt import (
    RBATCH_1,
    RBATCH_2,
    RECEIPT_B1,
    RECEIPT_B2,
)
from test_range_batch_receipt_frontier import (
    BDIGEST_1,
    BFRONTIER_1,
    BFRONTIER_2,
    batch_frontier_for,
)
from test_receipt_stream import (
    PAIR_1,
    PAIRS_12,
    STREAM_12,
    _rebuild,
    stream_for,
)


CONTINUATION_2 = seal_stream(
    ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),),
    KEY,
    checkpoint=BFRONTIER_1.to_bytes(),
)


class AuditStreamMethodTest(unittest.TestCase):
    def test_audit_stream_returns_self_and_commits_whole_chain(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        result = auditor.audit_stream(STREAM_12)
        self.assertIs(result, auditor)
        self.assertEqual(auditor.state, BFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.to_bytes(), STREAM_12.end)

    def test_audit_stream_accepts_canonical_bytes(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit_stream(STREAM_12.to_bytes())
        self.assertEqual(auditor.state, BFRONTIER_2)

    def test_audit_stream_single_commit(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        stream = stream_for(b"", PAIR_1, BFRONTIER_1.to_bytes())
        auditor.audit_stream(stream)
        self.assertEqual(auditor.state, BFRONTIER_1)

    def test_audit_stream_continues_from_audited_frontier(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertEqual(auditor.state, BFRONTIER_1)
        auditor.audit_stream(CONTINUATION_2)
        self.assertEqual(auditor.state, BFRONTIER_2)

    def test_audit_stream_continues_from_checkpoint_auditor(self):
        auditor = RangeBatchReceiptAuditor(
            KEY, checkpoint=BFRONTIER_1.to_bytes()
        )
        auditor.audit_stream(CONTINUATION_2)
        self.assertEqual(auditor.state, BFRONTIER_2)

    def test_audit_stream_start_must_be_empty_on_empty_auditor(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(CONTINUATION_2)
        self.assertIsNone(auditor.state)

    def test_audit_stream_start_must_match_current_state(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        before = auditor.state
        # A stream sealed from the empty frontier cannot join a
        # non-empty auditor.
        with self.assertRaises(ValueError):
            auditor.audit_stream(STREAM_12)
        self.assertIs(auditor.state, before)

    def test_audit_stream_replay_rejected_without_state_change(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit_stream(STREAM_12)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_stream(STREAM_12)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.audit_stream(STREAM_12.to_bytes())
        self.assertIs(auditor.state, before)

    def test_audit_stream_wrong_key(self):
        auditor = RangeBatchReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(STREAM_12)
        self.assertIsNone(auditor.state)

    def test_audit_stream_tampered_mac(self):
        record = stream_for(
            STREAM_12.start,
            STREAM_12.items,
            STREAM_12.end,
            key=OTHER_KEY,
        )
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(record)
        self.assertIsNone(auditor.state)

    def test_audit_stream_tampered_body_with_valid_mac_fails_replay(self):
        record = _rebuild(STREAM_12, items=tuple(reversed(PAIRS_12)))
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(record)
        self.assertIsNone(auditor.state)

    def test_audit_stream_wrong_end_with_valid_mac_fails(self):
        record = _rebuild(STREAM_12, end=BFRONTIER_1.to_bytes())
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(record)
        self.assertIsNone(auditor.state)

    def test_audit_stream_wrong_pairing_fails_mid_chain(self):
        # The second receipt is paired with the wrong batch: the stream
        # MAC is valid, but the carried audit must fail.
        broken = (
            PAIRS_12[0],
            (RECEIPT_B2.to_bytes(), RBATCH_1.to_bytes()),
        )
        record = stream_for(
            b"", broken, BFRONTIER_2.to_bytes()
        )
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(record)
        self.assertIsNone(auditor.state)

    def test_audit_stream_broken_chain_from_non_empty_state_is_atomic(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        # B2 audits from BFRONTIER_1, then B1 cannot join its end: the
        # NPBJ18/start replay breaks inside the stream.
        broken = (
            (RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),
            (RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes()),
        )
        record = stream_for(
            BFRONTIER_1.to_bytes(),
            broken,
            BFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            auditor.audit_stream(record)
        # All or nothing: the auditor stands exactly at BFRONTIER_1...
        self.assertEqual(auditor.state, BFRONTIER_1)
        # ...and a valid continuation still commits.
        auditor.audit_stream(CONTINUATION_2)
        self.assertEqual(auditor.state, BFRONTIER_2)

    def test_audit_stream_failure_then_single_audit_recovers(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_stream(CONTINUATION_2)
        self.assertIsNone(auditor.state)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertEqual(auditor.state, BFRONTIER_1)

    def test_audit_stream_sequence_overflow(self):
        maxed = batch_frontier_for(
            U64_MAX, RFRONTIER_1.to_bytes(), BDIGEST_1
        )
        auditor = RangeBatchReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        # RECEIPT_B2 legitimately starts at RFRONTIER_1 (= maxed.end),
        # so only the u64 sequence increment can fail. The declared end
        # is never reached.
        record = stream_for(
            maxed.to_bytes(),
            ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),),
            BFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            auditor.audit_stream(record)
        self.assertIs(auditor.state, before)

    def test_audit_stream_x_type_contract(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        for bad in (None, 1, "x", [], object(), bytearray(STREAM_12.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_stream(bad)
        self.assertIsNone(auditor.state)

    def test_audit_stream_malformed_bytes_is_value_error(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        for bad in (
            b"not json",
            b"[1,[],[],[],\"\"]",
            STREAM_12.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_stream(bad)
        self.assertIsNone(auditor.state)

    def test_state_remains_read_only(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(AttributeError):
            auditor.state = BFRONTIER_1

    def test_audit_and_audit_stream_share_the_lock(self):
        auditor = RangeBatchReceiptAuditor(KEY)
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
                args=(lambda: auditor.audit_stream(STREAM_12), "stream"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_B1, RBATCH_1),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Both actions start from the empty frontier; exactly one wins.
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        if successes[0] == "stream":
            self.assertEqual(auditor.state, BFRONTIER_2)
        else:
            self.assertEqual(auditor.state, BFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
