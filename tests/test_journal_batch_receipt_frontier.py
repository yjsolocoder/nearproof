import dataclasses
import hashlib
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptFrontier,
    BitMapUpdate,
    JournalBatchReceipt,
    JournalBatchReceiptAuditor,
    JournalBatchReceiptFrontier,
    _bit_map_history_journal_batch_receipt_mac,
    _bit_map_history_journal_mac,
    _bit_map_history_journal_receipt_frontier_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _journal_batch_receipt_frontier_mac,
    _journal_batch_receipt_frontier_next_digest,
    audit_map_history_journal_receipt_batch,
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
RECEIPT_FRONTIER_1 = audit_map_history_journal_receipt_batch(BATCH_1, KEY)
BATCH_2 = seal_map_history_journal_receipt_batch(
    [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=RECEIPT_FRONTIER_1
)
BATCH_FULL = seal_map_history_journal_receipt_batch(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
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
COMMIT_FULL = commit_for(BATCH_FULL)


def frontier_for(sequence, end, digest, key=KEY):
    placeholder = JournalBatchReceiptFrontier(1, sequence, end, digest, ZERO)
    return dataclasses.replace(
        placeholder,
        mac=_journal_batch_receipt_frontier_mac(key, placeholder),
    )


DIGEST_1 = _journal_batch_receipt_frontier_next_digest(
    ZERO, 1, COMMIT_1.to_bytes()
)
DIGEST_2 = _journal_batch_receipt_frontier_next_digest(
    DIGEST_1, 2, COMMIT_2.to_bytes()
)
FRONTIER_1 = frontier_for(1, COMMIT_1.end, DIGEST_1)
FRONTIER_2 = frontier_for(2, COMMIT_2.end, DIGEST_2)


class FrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = JournalBatchReceiptFrontier(
            1, 1, COMMIT_1.end, DIGEST_1, FRONTIER_1.mac
        )
        self.assertEqual(frontier, FRONTIER_1)
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, COMMIT_1.end)
        self.assertEqual(frontier.digest, DIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FRONTIER_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(FRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(FRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(COMMIT_1.end)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)
        # end must be non-empty canonical receipt-frontier bytes.
        for bad in (b"", b"junk", STATE_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(FRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(FRONTIER_1, **{name: bad})


class FrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + COMMIT_1.end.hex().encode() + b'",'
            b'"' + DIGEST_1.hex().encode() + b'",'
            b'"' + FRONTIER_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(FRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (FRONTIER_1, FRONTIER_2):
            blob = frontier.to_bytes()
            self.assertEqual(
                JournalBatchReceiptFrontier.from_bytes(blob), frontier
            )
            self.assertEqual(
                JournalBatchReceiptFrontier.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        for bad in (1, "x", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                JournalBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"junk", b"{}", b"[1,2,3]", b"[1,2,3,4,5,6]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                JournalBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = FRONTIER_1.to_bytes()
        spaced = blob.replace(b",", b", ")
        with self.assertRaises(ValueError):
            JournalBatchReceiptFrontier.from_bytes(spaced)
        upper = blob.replace(
            FRONTIER_1.mac.hex().encode(),
            FRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            JournalBatchReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            JournalBatchReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(FRONTIER_1, mac=ZERO)
        parsed = JournalBatchReceiptFrontier.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)


class AuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                JournalBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        self.assertIsNone(auditor.state)
        self.assertIsNone(
            JournalBatchReceiptAuditor(KEY, checkpoint=None).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (FRONTIER_1, FRONTIER_1.to_bytes()):
            auditor = JournalBatchReceiptAuditor(KEY, checkpoint=checkpoint)
            self.assertEqual(auditor.checkpoint, FRONTIER_1)
            self.assertEqual(auditor.state, FRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [FRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                JournalBatchReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(KEY, checkpoint=b"junk")

    def test_checkpoint_frontier_mac_verified(self):
        # The frontier's own NPBJ9 layer is recomputed on load.
        tampered = dataclasses.replace(FRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(KEY, checkpoint=tampered.to_bytes())

    def test_checkpoint_end_frontier_mac_verified(self):
        # The end receipt frontier's own NPBJ5 layer is recomputed on load.
        bad_inner = dataclasses.replace(RECEIPT_FRONTIER_1, mac=ZERO)
        tampered = frontier_for(1, bad_inner.to_bytes(), DIGEST_1)
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_state_mac_verified(self):
        # The end state's own NPBJ1 layer is recomputed on load.
        bad_state = dataclasses.replace(STATE_1, mac=ZERO)
        bad_inner = dataclasses.replace(
            RECEIPT_FRONTIER_1, end=bad_state.to_bytes()
        )
        bad_inner = dataclasses.replace(
            bad_inner,
            mac=_bit_map_history_journal_receipt_frontier_mac(KEY, bad_inner),
        )
        tampered = frontier_for(1, bad_inner.to_bytes(), DIGEST_1)
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_table_mac_verified(self):
        # The embedded checkpoint table's NPBL1 layer is recomputed on load.
        bad_map = dataclasses.replace(MAP_2, mac=ZERO)
        bad_state = dataclasses.replace(
            STATE_1, checkpoint=bad_map.to_bytes()
        )
        bad_state = dataclasses.replace(
            bad_state, mac=_bit_map_history_journal_mac(KEY, bad_state)
        )
        bad_inner = dataclasses.replace(
            RECEIPT_FRONTIER_1, end=bad_state.to_bytes()
        )
        bad_inner = dataclasses.replace(
            bad_inner,
            mac=_bit_map_history_journal_receipt_frontier_mac(KEY, bad_inner),
        )
        tampered = frontier_for(1, bad_inner.to_bytes(), DIGEST_1)
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            JournalBatchReceiptAuditor(OTHER_KEY, checkpoint=FRONTIER_1)


class AuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        self.assertIs(auditor.audit(COMMIT_1, BATCH_1), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, COMMIT_1.end)
        self.assertEqual(auditor.checkpoint.digest, DIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        auditor.audit(COMMIT_1, BATCH_1)
        auditor.audit(COMMIT_2, BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, COMMIT_2.end)
        self.assertEqual(auditor.checkpoint.digest, DIGEST_2)

    def test_full_batch_receipt(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        auditor.audit(COMMIT_FULL, BATCH_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, COMMIT_FULL.end)

    def test_accepts_canonical_bytes(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        auditor.audit(COMMIT_1.to_bytes(), BATCH_1.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit(COMMIT_2.to_bytes(), BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        auditor.audit(COMMIT_1, BATCH_1)
        blob = auditor.checkpoint.to_bytes()
        restored = JournalBatchReceiptAuditor(KEY, checkpoint=blob)
        restored.audit(COMMIT_2, BATCH_2)
        self.assertEqual(restored.checkpoint, FRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(COMMIT_2, BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_receipt_rejected(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        auditor.audit(COMMIT_1, BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(COMMIT_1, BATCH_1)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_receipt_rejected(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        tampered = dataclasses.replace(COMMIT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered, BATCH_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_batch_rejected(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(COMMIT_1, BATCH_FULL)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        for bad in (1, "x", None, [COMMIT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BATCH_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(COMMIT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_sequence_overflow(self):
        maxed = frontier_for(U64_MAX, COMMIT_1.end, DIGEST_1)
        auditor = JournalBatchReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(COMMIT_2, BATCH_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_commits_linearize(self):
        auditor = JournalBatchReceiptAuditor(KEY)
        commits = []
        failures = []

        def run(receipt, batch):
            try:
                auditor.audit(receipt, batch)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(target=run, args=(COMMIT_1, BATCH_1)),
            threading.Thread(target=run, args=(COMMIT_FULL, BATCH_FULL)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        committed = commits[0]
        self.assertEqual(auditor.checkpoint.end, committed.end)


if __name__ == "__main__":
    unittest.main()
