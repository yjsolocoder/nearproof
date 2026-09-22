import dataclasses
import hashlib
import hmac
import json
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
    _range_receipt_mac,
    audit_range,
    audit_receipt,
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

RANGE_DIGEST_1 = hashlib.sha256(RANGE_1.to_bytes()).digest()
RANGE_DIGEST_2 = hashlib.sha256(RANGE_2.to_bytes()).digest()
RANGE_DIGEST_FROM_CP = hashlib.sha256(RANGE_FROM_CP.to_bytes()).digest()


def range_receipt_for(start, digest, end, key=KEY):
    placeholder = RangeReceipt(1, start, digest, end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_range_receipt_mac(key, placeholder)
    )


RRECEIPT_1 = range_receipt_for(b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes())
RRECEIPT_2 = range_receipt_for(b"", RANGE_DIGEST_2, CFRONTIER_2.to_bytes())
RRECEIPT_FROM_CP = range_receipt_for(
    CFRONTIER_1.to_bytes(), RANGE_DIGEST_FROM_CP, CFRONTIER_2.to_bytes()
)


class RangeReceiptContractTest(unittest.TestCase):
    def test_valid_construction(self):
        receipt = RangeReceipt(
            1, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO
        )
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.digest, RANGE_DIGEST_1)
        self.assertEqual(receipt.end, CFRONTIER_1.to_bytes())
        self.assertEqual(receipt.mac, ZERO)

    def test_positional_construction_and_equality(self):
        left = RangeReceipt(1, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO)
        right = RangeReceipt(1, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO)
        self.assertEqual(left, right)
        self.assertNotEqual(left, RRECEIPT_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RRECEIPT_1.mac = ZERO

    def test_stores_no_key_material(self):
        for value in dataclasses.astuple(RRECEIPT_1):
            if isinstance(value, bytes):
                self.assertNotIn(KEY, value)

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    bad, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            RangeReceipt(2, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO)

    def test_start_contract(self):
        for bad in (1, None, "x", bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    1, bad, RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"x", b"[]", RANGE_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(
                    1, bad, RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO
                )

    def test_digest_contract(self):
        for bad in (1, None, "x", bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", bad, CFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"", ZERO[:31], ZERO + b"\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(1, b"", bad, CFRONTIER_1.to_bytes(), ZERO)

    def test_end_contract(self):
        for bad in (1, None, "x", bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(1, b"", RANGE_DIGEST_1, bad, ZERO)
        for bad in (b"", b"x", RANGE_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(1, b"", RANGE_DIGEST_1, bad, ZERO)

    def test_mac_contract(self):
        for bad in (1, None, "x", bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), bad
                )
        for bad in (b"", ZERO[:31], ZERO + b"\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), bad
                )


class RangeReceiptEncodingTest(unittest.TestCase):
    def test_canonical_encoding(self):
        expected = (
            b'[1,"","'
            + RANGE_DIGEST_1.hex().encode("ascii")
            + b'","'
            + CFRONTIER_1.to_bytes().hex().encode("ascii")
            + b'","'
            + RRECEIPT_1.mac.hex().encode("ascii")
            + b'"]'
        )
        self.assertEqual(RRECEIPT_1.to_bytes(), expected)

    def test_round_trip(self):
        for receipt in (RRECEIPT_1, RRECEIPT_2, RRECEIPT_FROM_CP):
            self.assertEqual(
                RangeReceipt.from_bytes(receipt.to_bytes()), receipt
            )

    def test_from_bytes_type_contract(self):
        for bad in (1, None, "x", [], bytearray(RRECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt.from_bytes(bad)

    def test_from_bytes_malformed(self):
        for bad in (b"", b"not-json", b"{}", b"[1]", b"[1,2,3,4]", b"[1,2,3,4,5,6]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt.from_bytes(bad)

    def test_from_bytes_field_type_errors(self):
        document = json.loads(RRECEIPT_1.to_bytes().decode("utf-8"))

        def encoded(*fields):
            return json.dumps(list(fields), separators=(",", ":")).encode(
                "utf-8"
            )

        with self.assertRaises(TypeError):
            RangeReceipt.from_bytes(encoded("1", *document[1:]))
        with self.assertRaises(TypeError):
            RangeReceipt.from_bytes(encoded(1, 7, *document[2:]))
        with self.assertRaises(ValueError):
            RangeReceipt.from_bytes(encoded(2, *document[1:]))

    def test_from_bytes_rejects_non_canonical(self):
        canonical = RRECEIPT_1.to_bytes()
        # Whitespace anywhere breaks the byte-for-byte re-encoding check.
        spaced = canonical.replace(b',"', b', "', 1)
        with self.assertRaises(ValueError):
            RangeReceipt.from_bytes(spaced)
        # Uppercase hex is not the canonical spelling.
        document = json.loads(canonical.decode("utf-8"))
        document[2] = document[2].upper()
        with self.assertRaises(ValueError):
            RangeReceipt.from_bytes(
                json.dumps(document, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_does_not_verify_mac(self):
        # A receipt with a zero MAC parses fine; verification is
        # audit_receipt's job.
        forged = RangeReceipt(1, b"", RANGE_DIGEST_1, CFRONTIER_1.to_bytes(), ZERO)
        self.assertEqual(
            RangeReceipt.from_bytes(forged.to_bytes()), forged
        )


class RangeReceiptMacTest(unittest.TestCase):
    def test_digest_is_sha256_of_range_bytes(self):
        self.assertEqual(
            RRECEIPT_1.digest, hashlib.sha256(RANGE_1.to_bytes()).digest()
        )

    def test_mac_is_hmac_over_prefixed_content(self):
        content = json.dumps(
            [
                1,
                RRECEIPT_1.start.hex(),
                RRECEIPT_1.digest.hex(),
                RRECEIPT_1.end.hex(),
            ],
            separators=(",", ":"),
        ).encode("utf-8")
        expected = hmac.new(
            KEY, b"NPBJ12" + content, hashlib.sha256
        ).digest()
        self.assertEqual(RRECEIPT_1.mac, expected)
        self.assertEqual(_range_receipt_mac(KEY, RRECEIPT_1), expected)

    def test_mac_depends_on_key(self):
        self.assertNotEqual(
            _range_receipt_mac(KEY, RRECEIPT_1),
            _range_receipt_mac(OTHER_KEY, RRECEIPT_1),
        )


class CommitRangeAuditorCommitTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = CommitRangeAuditor(KEY)
        receipt = auditor.commit(RANGE_1)
        self.assertEqual(receipt, RRECEIPT_1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.digest, RANGE_DIGEST_1)
        self.assertEqual(receipt.end, CFRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_commit_accepts_canonical_bytes(self):
        auditor = CommitRangeAuditor(KEY)
        receipt = auditor.commit(RANGE_1.to_bytes())
        self.assertEqual(receipt, RRECEIPT_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_commit_chains_from_checkpoint(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.commit(RANGE_1)
        receipt = auditor.commit(RANGE_FROM_CP)
        self.assertEqual(receipt, RRECEIPT_FROM_CP)
        self.assertEqual(receipt.start, CFRONTIER_1.to_bytes())
        self.assertEqual(receipt.end, CFRONTIER_2.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_commit_multi_commit_range(self):
        auditor = CommitRangeAuditor(KEY)
        receipt = auditor.commit(RANGE_2)
        self.assertEqual(receipt, RRECEIPT_2)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_commit_receipt_verifies(self):
        auditor = CommitRangeAuditor(KEY)
        receipt = auditor.commit(RANGE_1)
        self.assertEqual(audit_receipt(receipt, RANGE_1, KEY), CFRONTIER_1)

    def test_failed_commit_changes_nothing_and_yields_no_receipt(self):
        auditor = CommitRangeAuditor(KEY)
        # A range that does not start at the current checkpoint.
        with self.assertRaises(ValueError):
            auditor.commit(RANGE_FROM_CP)
        self.assertIsNone(auditor.checkpoint)
        # A tampered range.
        tampered = dataclasses.replace(RANGE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.commit(tampered)
        self.assertIsNone(auditor.checkpoint)
        # The auditor still recovers afterwards.
        self.assertEqual(auditor.commit(RANGE_1), RRECEIPT_1)

    def test_commit_replay_rejected(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.commit(RANGE_1)
        with self.assertRaises(ValueError):
            auditor.commit(RANGE_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_commit_type_contract(self):
        auditor = CommitRangeAuditor(KEY)
        for bad in (1, None, "x", [], bytearray(RANGE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_commit_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(OTHER_KEY).commit(RANGE_1)

    def test_commit_concurrent_linearizes(self):
        # Five threads race to commit the same range: exactly one wins,
        # the rest fail the start/sequence gates, and every produced
        # receipt is identical.
        auditor = CommitRangeAuditor(KEY)
        barrier = threading.Barrier(5)
        receipts = []
        failures = []

        def stage():
            barrier.wait()
            try:
                receipts.append(auditor.commit(RANGE_1))
            except ValueError:
                failures.append(True)

        threads = [threading.Thread(target=stage) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 4)
        self.assertEqual(receipts[0], RRECEIPT_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_audit_interface_unchanged(self):
        # The old audit path still advances without producing a receipt.
        auditor = CommitRangeAuditor(KEY)
        self.assertIs(auditor.audit(RANGE_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)


class AuditReceiptTest(unittest.TestCase):
    def test_accepts_objects_and_canonical_bytes(self):
        self.assertEqual(
            audit_receipt(RRECEIPT_1, RANGE_1, KEY), CFRONTIER_1
        )
        self.assertEqual(
            audit_receipt(
                RRECEIPT_1.to_bytes(), RANGE_1.to_bytes(), KEY
            ),
            CFRONTIER_1,
        )
        self.assertEqual(
            audit_receipt(RRECEIPT_FROM_CP, RANGE_FROM_CP, KEY),
            CFRONTIER_2,
        )

    def test_returned_frontier_matches_audit_range(self):
        self.assertEqual(
            audit_receipt(RRECEIPT_2, RANGE_2, KEY),
            audit_range(RANGE_2, KEY),
        )

    def test_type_contract(self):
        for bad in (1, None, "x", [], bytearray(RRECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_receipt(bad, RANGE_1, KEY)
        for bad in (1, None, "x", [], bytearray(RANGE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_receipt(RRECEIPT_1, bad, KEY)
        for bad in (1, None, "k", bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_receipt(RRECEIPT_1, RANGE_1, bad)

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_receipt(RRECEIPT_1, RANGE_1, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_receipt(RRECEIPT_1, RANGE_1, OTHER_KEY)

    def test_tampered_mac_rejected(self):
        tampered = dataclasses.replace(RRECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_tampered_digest_rejected(self):
        tampered = range_receipt_for(
            b"", hashlib.sha256(b"other").digest(), CFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_tampered_start_rejected(self):
        tampered = range_receipt_for(
            CFRONTIER_1.to_bytes(), RANGE_DIGEST_1, CFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_tampered_end_rejected(self):
        tampered = range_receipt_for(
            b"", RANGE_DIGEST_1, CFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_receipt_range_mismatch_rejected(self):
        # RRECEIPT_1 attests RANGE_1, not the longer RANGE_2.
        with self.assertRaises(ValueError):
            audit_receipt(RRECEIPT_1, RANGE_2, KEY)
        with self.assertRaises(ValueError):
            audit_receipt(RRECEIPT_2, RANGE_1, KEY)

    def test_malformed_bytes_are_value_errors(self):
        for bad in (b"", b"not-json", b"[1,2,3,4,5]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_receipt(bad, RANGE_1, KEY)
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_receipt(RRECEIPT_1, bad, KEY)


if __name__ == "__main__":
    unittest.main()
