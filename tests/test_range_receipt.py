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


class RangeReceiptFieldTest(unittest.TestCase):
    def test_version_contract(self):
        for bad in (1.0, True, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    bad, b"", ZERO, CFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            RangeReceipt(2, b"", ZERO, CFRONTIER_1.to_bytes(), ZERO)

    def test_start_contract(self):
        for bad in (1, "x", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    1, bad, ZERO, CFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"not-json", b"[]", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(
                    1, bad, ZERO, CFRONTIER_1.to_bytes(), ZERO
                )

    def test_digest_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", bad, CFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", bad, CFRONTIER_1.to_bytes(), ZERO
                )

    def test_end_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(1, b"", ZERO, bad, ZERO)
        for bad in (b"", b"not-json", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(1, b"", ZERO, bad, ZERO)

    def test_mac_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", ZERO, CFRONTIER_1.to_bytes(), bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt(
                    1, b"", ZERO, CFRONTIER_1.to_bytes(), bad
                )

    def test_positional_construction_and_field_equality(self):
        left = RangeReceipt(1, b"", ZERO, CFRONTIER_1.to_bytes(), ZERO)
        right = RangeReceipt(1, b"", ZERO, CFRONTIER_1.to_bytes(), ZERO)
        self.assertEqual(left, right)
        self.assertEqual(
            dataclasses.replace(left, digest=b"\x01" * 32), left.__class__(
                1, b"", b"\x01" * 32, CFRONTIER_1.to_bytes(), ZERO
            )
        )
        self.assertNotEqual(
            left, dataclasses.replace(left, digest=b"\x01" * 32)
        )

    def test_frozen_and_no_key_material(self):
        receipt = RECEIPT_R1
        with self.assertRaises(dataclasses.FrozenInstanceError):
            receipt.mac = ZERO
        for field in dataclasses.fields(receipt):
            self.assertNotEqual(getattr(receipt, field.name), KEY)
        self.assertNotIn(KEY, receipt.to_bytes())


class RangeReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for receipt in (RECEIPT_R1, RECEIPT_RCP):
            self.assertEqual(
                RangeReceipt.from_bytes(receipt.to_bytes()), receipt
            )

    def test_encoding_shape(self):
        document = json.loads(RECEIPT_R1.to_bytes().decode("utf-8"))
        self.assertEqual(
            document,
            [
                1,
                "",
                hashlib.sha256(RANGE_1.to_bytes()).hexdigest(),
                CFRONTIER_1.to_bytes().hex(),
                RECEIPT_R1.mac.hex(),
            ],
        )
        self.assertEqual(
            RECEIPT_R1.to_bytes(),
            json.dumps(document, separators=(",", ":")).encode("utf-8"),
        )

    def test_from_bytes_type_contract(self):
        for bad in (1, None, "[]", bytearray(RECEIPT_R1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeReceipt.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (b"", b"not-json", b"{}", b"[1,2,3]", b"[1,2,3,4,5,6]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        document = json.loads(RECEIPT_R1.to_bytes().decode("utf-8"))
        for index, bad in ((0, "1"), (1, 1), (2, 1), (3, 1), (4, 1)):
            tampered = list(document)
            tampered[index] = bad
            with self.assertRaises(TypeError, msg=repr(tampered)):
                RangeReceipt.from_bytes(
                    json.dumps(tampered, separators=(",", ":")).encode(
                        "utf-8"
                    )
                )

    def test_from_bytes_rejects_non_canonical(self):
        document = json.loads(RECEIPT_R1.to_bytes().decode("utf-8"))
        # Pretty-printed JSON parses but is not the canonical encoding.
        with self.assertRaises(ValueError):
            RangeReceipt.from_bytes(json.dumps(document).encode("utf-8"))
        # Uppercase hex is not canonical.
        tampered = list(document)
        tampered[4] = tampered[4].upper()
        with self.assertRaises(ValueError):
            RangeReceipt.from_bytes(
                json.dumps(tampered, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_does_not_verify_mac(self):
        # A zero-MAC receipt with a valid shape parses fine; verification
        # is audit_receipt's job.
        forged = RangeReceipt(1, b"", ZERO, CFRONTIER_1.to_bytes(), ZERO)
        self.assertEqual(
            RangeReceipt.from_bytes(forged.to_bytes()), forged
        )


class CommitRangeAuditorCommitTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = CommitRangeAuditor(KEY)
        receipt = auditor.commit(RANGE_1)
        self.assertEqual(receipt, RECEIPT_R1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.digest, hashlib.sha256(RANGE_1.to_bytes()).digest()
        )
        self.assertEqual(receipt.end, CFRONTIER_1.to_bytes())
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        continued = auditor.commit(RANGE_FROM_CP)
        self.assertEqual(continued, RECEIPT_RCP)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_commit_accepts_canonical_bytes(self):
        auditor = CommitRangeAuditor(KEY)
        receipt = auditor.commit(RANGE_1.to_bytes())
        self.assertEqual(receipt, RECEIPT_R1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)

    def test_commit_from_checkpoint(self):
        auditor = CommitRangeAuditor(KEY, checkpoint=CFRONTIER_1)
        receipt = auditor.commit(RANGE_FROM_CP)
        self.assertEqual(receipt, RECEIPT_RCP)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_commit_type_contract(self):
        auditor = CommitRangeAuditor(KEY)
        for bad in (1, None, "x", [], bytearray(RANGE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_failed_commit_changes_nothing_and_mints_nothing(self):
        auditor = CommitRangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit(RANGE_FROM_CP)
        self.assertIsNone(auditor.checkpoint)
        auditor.commit(RANGE_1)
        tampered = dataclasses.replace(RANGE_FROM_CP, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.commit(tampered)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        # A same-end replay is rejected by the strict-advance gate.
        with self.assertRaises(ValueError):
            auditor.commit(RANGE_1)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)
        auditor.commit(RANGE_FROM_CP)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_commit_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            CommitRangeAuditor(OTHER_KEY).commit(RANGE_1)

    def test_audit_still_works_after_commit(self):
        auditor = CommitRangeAuditor(KEY)
        auditor.commit(RANGE_1)
        self.assertIs(auditor.audit(RANGE_FROM_CP), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_2)

    def test_concurrent_commits_linearize(self):
        auditor = CommitRangeAuditor(KEY)
        receipts = []
        errors = []
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            try:
                receipts.append(auditor.commit(RANGE_1))
            except ValueError:
                # Exactly one commit at the empty start can win.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(receipts, [RECEIPT_R1])
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)


class AuditReceiptTest(unittest.TestCase):
    def test_accepts_objects_and_canonical_bytes(self):
        self.assertEqual(
            audit_receipt(RECEIPT_R1, RANGE_1, KEY), CFRONTIER_1
        )
        self.assertEqual(
            audit_receipt(
                RECEIPT_R1.to_bytes(), RANGE_1.to_bytes(), KEY
            ),
            CFRONTIER_1,
        )
        self.assertEqual(
            audit_receipt(RECEIPT_RCP, RANGE_FROM_CP, KEY), CFRONTIER_2
        )

    def test_type_contract(self):
        for bad in (1, None, "x", []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_receipt(bad, RANGE_1, KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_receipt(RECEIPT_R1, bad, KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_receipt(RECEIPT_R1, RANGE_1, bad)
        with self.assertRaises(ValueError):
            audit_receipt(RECEIPT_R1, RANGE_1, b"")

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"", b"not-json", b"[]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_receipt(bad, RANGE_1, KEY)
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_receipt(RECEIPT_R1, bad, KEY)

    def test_tampered_mac_rejected(self):
        tampered = dataclasses.replace(RECEIPT_R1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_receipt(RECEIPT_R1, RANGE_1, OTHER_KEY)

    def test_tampered_digest_rejected(self):
        # Re-MAC'd so only the digest comparison can fail.
        tampered = dataclasses.replace(RECEIPT_R1, digest=ZERO)
        tampered = dataclasses.replace(
            tampered, mac=_range_receipt_mac(KEY, tampered)
        )
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_tampered_start_rejected(self):
        # Re-MAC'd so only the start comparison can fail.
        tampered = dataclasses.replace(
            RECEIPT_R1, start=CFRONTIER_1.to_bytes()
        )
        tampered = dataclasses.replace(
            tampered, mac=_range_receipt_mac(KEY, tampered)
        )
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_tampered_end_rejected(self):
        # Re-MAC'd so only the end comparison can fail.
        tampered = dataclasses.replace(
            RECEIPT_R1, end=CFRONTIER_2.to_bytes()
        )
        tampered = dataclasses.replace(
            tampered, mac=_range_receipt_mac(KEY, tampered)
        )
        with self.assertRaises(ValueError):
            audit_receipt(tampered, RANGE_1, KEY)

    def test_receipt_of_other_range_rejected(self):
        with self.assertRaises(ValueError):
            audit_receipt(RECEIPT_RCP, RANGE_1, KEY)
        with self.assertRaises(ValueError):
            audit_receipt(RECEIPT_R1, RANGE_FROM_CP, KEY)

    def test_range_reverified(self):
        # A receipt correctly attesting a range whose own MAC is broken
        # still fails: audit_receipt re-runs audit_range.
        tampered_range = dataclasses.replace(RANGE_1, mac=ZERO)
        forged = range_receipt_for(
            tampered_range, b"", CFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_receipt(forged, tampered_range, KEY)

    def test_old_interfaces_unchanged(self):
        # audit_range keeps its contract and shares no state with the
        # receipt path.
        self.assertEqual(audit_range(RANGE_1, KEY), CFRONTIER_1)
        auditor = CommitRangeAuditor(KEY)
        self.assertIs(auditor.audit(RANGE_1), auditor)
        self.assertEqual(auditor.checkpoint, CFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
