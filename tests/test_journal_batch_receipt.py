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
    BitMapHistoryJournalReceiptBatch,
    BitMapHistoryJournalReceiptFrontier,
    BitMapUpdate,
    JournalBatchReceipt,
    _bit_map_history_journal_batch_receipt_mac,
    _bit_map_history_journal_receipt_batch_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    audit_commit,
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
FRONTIER_1 = audit_map_history_journal_receipt_batch(BATCH_1, KEY)
BATCH_2 = seal_map_history_journal_receipt_batch(
    [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=FRONTIER_1
)
BATCH_FULL = seal_map_history_journal_receipt_batch(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
)


def batch_receipt_for(batch, key=KEY):
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


COMMIT_FULL = batch_receipt_for(BATCH_FULL)
COMMIT_1 = batch_receipt_for(BATCH_1)
COMMIT_2 = batch_receipt_for(BATCH_2)


class CommitReceiptFieldContractTest(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(COMMIT_FULL.version, 1)
        self.assertEqual(COMMIT_FULL.start, b"")
        self.assertEqual(
            COMMIT_FULL.batch_digest,
            hashlib.sha256(BATCH_FULL.to_bytes()).digest(),
        )
        self.assertEqual(COMMIT_FULL.end, BATCH_FULL.end)
        self.assertEqual(len(COMMIT_FULL.batch_digest), 32)
        self.assertEqual(len(COMMIT_FULL.mac), 32)
        self.assertEqual(COMMIT_2.start, FRONTIER_1.to_bytes())

    def test_positional_construction_and_equality(self):
        clone = JournalBatchReceipt(
            1,
            COMMIT_FULL.start,
            COMMIT_FULL.batch_digest,
            COMMIT_FULL.end,
            COMMIT_FULL.mac,
        )
        self.assertEqual(clone, COMMIT_FULL)
        self.assertEqual(hash(clone), hash(COMMIT_FULL))

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            COMMIT_FULL.version = 2

    def test_version_contract(self):
        with self.assertRaises(TypeError):
            JournalBatchReceipt(
                "1", b"", COMMIT_FULL.batch_digest, COMMIT_FULL.end, ZERO
            )
        with self.assertRaises(ValueError):
            JournalBatchReceipt(
                2, b"", COMMIT_FULL.batch_digest, COMMIT_FULL.end, ZERO
            )

    def test_start_contract(self):
        with self.assertRaises(TypeError):
            JournalBatchReceipt(
                1, 0, COMMIT_FULL.batch_digest, COMMIT_FULL.end, ZERO
            )
        with self.assertRaises(ValueError):
            JournalBatchReceipt(
                1, b"junk", COMMIT_FULL.batch_digest, COMMIT_FULL.end, ZERO
            )

    def test_batch_digest_contract(self):
        with self.assertRaises(TypeError):
            JournalBatchReceipt(1, b"", "d", COMMIT_FULL.end, ZERO)
        with self.assertRaises(ValueError):
            JournalBatchReceipt(
                1, b"", b"\x00" * 31, COMMIT_FULL.end, ZERO
            )

    def test_end_contract(self):
        with self.assertRaises(TypeError):
            JournalBatchReceipt(1, b"", COMMIT_FULL.batch_digest, 0, ZERO)
        with self.assertRaises(ValueError):
            JournalBatchReceipt(1, b"", COMMIT_FULL.batch_digest, b"", ZERO)

    def test_mac_contract(self):
        with self.assertRaises(TypeError):
            JournalBatchReceipt(
                1, b"", COMMIT_FULL.batch_digest, COMMIT_FULL.end, "mac"
            )
        with self.assertRaises(ValueError):
            JournalBatchReceipt(
                1, b"", COMMIT_FULL.batch_digest, COMMIT_FULL.end, b"\x00"
            )


class CommitReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for receipt in (COMMIT_1, COMMIT_2, COMMIT_FULL):
            encoded = receipt.to_bytes()
            self.assertIsInstance(encoded, bytes)
            self.assertEqual(JournalBatchReceipt.from_bytes(encoded), receipt)

    def test_encoding_shape(self):
        decoded = json.loads(COMMIT_FULL.to_bytes())
        self.assertEqual(decoded[0], 1)
        self.assertEqual(decoded[1], "")
        self.assertEqual(
            decoded[2],
            hashlib.sha256(BATCH_FULL.to_bytes()).hexdigest(),
        )
        self.assertEqual(decoded[3], BATCH_FULL.end.hex())
        self.assertEqual(decoded[4], COMMIT_FULL.mac.hex())
        self.assertEqual(
            COMMIT_FULL.to_bytes(),
            json.dumps(decoded, separators=(",", ":")).encode("utf-8"),
        )

    def test_from_bytes_type_contract(self):
        with self.assertRaises(TypeError):
            JournalBatchReceipt.from_bytes("x")
        with self.assertRaises(ValueError):
            JournalBatchReceipt.from_bytes(b"not json")
        with self.assertRaises(ValueError):
            JournalBatchReceipt.from_bytes(b"[1,2,3]")

    def test_from_bytes_rejects_non_canonical(self):
        with self.assertRaises(ValueError):
            JournalBatchReceipt.from_bytes(
                COMMIT_FULL.to_bytes().replace(b",", b", ", 1)
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[0] = 2
        with self.assertRaises(ValueError):
            JournalBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[1] = "AB"
        with self.assertRaises(ValueError):
            JournalBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_verifies_no_mac(self):
        # A receipt MAC'd with another key still parses: from_bytes checks
        # the field contract only, never any MAC.
        foreign = batch_receipt_for(BATCH_FULL, key=OTHER_KEY)
        parsed = JournalBatchReceipt.from_bytes(foreign.to_bytes())
        self.assertEqual(parsed, foreign)


class AuditorCommitTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        receipt = auditor.commit(BATCH_FULL)
        self.assertIsInstance(receipt, JournalBatchReceipt)
        self.assertEqual(receipt, COMMIT_FULL)
        self.assertEqual(auditor.checkpoint.to_bytes(), BATCH_FULL.end)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_commit_accepts_canonical_bytes(self):
        receipt = BitMapHistoryJournalReceiptAuditor(KEY).commit(
            BATCH_FULL.to_bytes()
        )
        self.assertEqual(receipt, COMMIT_FULL)

    def test_chained_commits(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        first = auditor.commit(BATCH_1)
        self.assertEqual(first, COMMIT_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        second = auditor.commit(BATCH_2)
        self.assertEqual(second, COMMIT_2)
        self.assertEqual(auditor.checkpoint.to_bytes(), BATCH_2.end)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_commit_matches_audit_batch_frontier(self):
        committed = BitMapHistoryJournalReceiptAuditor(KEY)
        committed.commit(BATCH_FULL)
        batched = BitMapHistoryJournalReceiptAuditor(KEY)
        batched.audit_batch(BATCH_FULL)
        self.assertEqual(committed.checkpoint, batched.checkpoint)

    def test_commit_type_contract(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_FULL], (BATCH_FULL,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_commit_malformed_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_failed_commit_does_not_advance(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit(dataclasses.replace(BATCH_FULL, mac=ZERO))
        self.assertIsNone(auditor.checkpoint)
        # The auditor still commits a correct batch afterwards.
        receipt = auditor.commit(BATCH_FULL)
        self.assertEqual(receipt, COMMIT_FULL)
        self.assertEqual(auditor.checkpoint.to_bytes(), BATCH_FULL.end)

    def test_failed_chained_commit_keeps_prior_frontier(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.commit(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit(dataclasses.replace(BATCH_2, mac=ZERO))
        self.assertIs(auditor.checkpoint, before)

    def test_replayed_commit_rejected_on_start(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.commit(BATCH_1)
        with self.assertRaises(ValueError):
            auditor.commit(BATCH_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_commit_shares_lock_with_audit_and_audit_batch(self):
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
                args=(lambda: auditor.commit(BATCH_FULL), "commit"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_1, BUNDLE_1)
                    and auditor.audit(RECEIPT_2, BUNDLE_2),
                    "audits",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(
            auditor.checkpoint.end,
            BitMapHistoryJournalReceiptFrontier.from_bytes(
                BATCH_FULL.end
            ).end,
        )


class AuditCommitTest(unittest.TestCase):
    def test_audit_commit_returns_end_frontier(self):
        frontier = audit_commit(COMMIT_FULL, BATCH_FULL, KEY)
        self.assertIsInstance(frontier, BitMapHistoryJournalReceiptFrontier)
        self.assertEqual(frontier.to_bytes(), BATCH_FULL.end)

    def test_audit_commit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_commit(
                COMMIT_FULL.to_bytes(), BATCH_FULL.to_bytes(), KEY
            ),
            audit_commit(COMMIT_FULL, BATCH_FULL, KEY),
        )

    def test_audit_commit_verifies_chained_batches(self):
        self.assertEqual(
            audit_commit(COMMIT_1, BATCH_1, KEY).to_bytes(), BATCH_1.end
        )
        self.assertEqual(
            audit_commit(COMMIT_2, BATCH_2, KEY).to_bytes(), BATCH_2.end
        )

    def test_audit_commit_type_contract(self):
        with self.assertRaises(TypeError):
            audit_commit(42, BATCH_FULL, KEY)
        with self.assertRaises(TypeError):
            audit_commit(COMMIT_FULL, 42, KEY)
        with self.assertRaises(TypeError):
            audit_commit(COMMIT_FULL, BATCH_FULL, "k")

    def test_audit_commit_key_contract(self):
        with self.assertRaises(ValueError):
            audit_commit(COMMIT_FULL, BATCH_FULL, b"")
        with self.assertRaises(ValueError):
            audit_commit(COMMIT_FULL, BATCH_FULL, OTHER_KEY)

    def test_audit_commit_rejects_bad_mac(self):
        with self.assertRaises(ValueError):
            audit_commit(
                dataclasses.replace(COMMIT_FULL, mac=ZERO), BATCH_FULL, KEY
            )

    def test_audit_commit_rejects_bad_digest(self):
        with self.assertRaises(ValueError):
            audit_commit(
                dataclasses.replace(COMMIT_FULL, batch_digest=ZERO),
                BATCH_FULL,
                KEY,
            )

    def test_audit_commit_rejects_endpoint_mismatch(self):
        # A receipt over BATCH_1 cannot attest the two-receipt full batch.
        with self.assertRaises(ValueError):
            audit_commit(COMMIT_1, BATCH_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_commit(COMMIT_FULL, BATCH_1, KEY)

    def test_audit_commit_rejects_tampered_batch(self):
        resealed = dataclasses.replace(
            BATCH_FULL,
            mac=_bit_map_history_journal_receipt_batch_mac(KEY, BATCH_FULL),
        )
        # Re-sealing an unchanged batch is still valid...
        self.assertEqual(
            audit_commit(COMMIT_FULL, resealed, KEY).to_bytes(), BATCH_FULL.end
        )
        # ...but swapping the end and re-sealing the batch alone breaks the
        # carried-chain replay and the digest check.
        with self.assertRaises(ValueError):
            audit_commit(COMMIT_FULL, dataclasses.replace(BATCH_FULL, mac=ZERO), KEY)


if __name__ == "__main__":
    unittest.main()
