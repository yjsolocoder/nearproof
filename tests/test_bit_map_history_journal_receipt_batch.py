import dataclasses
import hashlib
import json
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptBatch,
    BitMapHistoryJournalReceiptFrontier,
    BitMapUpdate,
    _bit_map_history_journal_receipt_batch_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
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


class BatchFieldContractTest(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(BATCH_FULL.version, 1)
        self.assertEqual(BATCH_FULL.start, b"")
        self.assertEqual(
            BATCH_FULL.items,
            (
                (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
                (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
            ),
        )
        self.assertEqual(len(BATCH_FULL.mac), 32)
        self.assertEqual(BATCH_2.start, FRONTIER_1.to_bytes())

    def test_positional_construction_and_equality(self):
        clone = BitMapHistoryJournalReceiptBatch(
            1, b"", BATCH_FULL.items, BATCH_FULL.end, BATCH_FULL.mac
        )
        self.assertEqual(clone, BATCH_FULL)
        self.assertEqual(hash(clone), hash(BATCH_FULL))

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BATCH_FULL.version = 2

    def test_version_contract(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                "1", b"", BATCH_FULL.items, BATCH_FULL.end, BATCH_FULL.mac
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                2, b"", BATCH_FULL.items, BATCH_FULL.end, BATCH_FULL.mac
            )

    def test_start_contract(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                1, 0, BATCH_FULL.items, BATCH_FULL.end, BATCH_FULL.mac
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1, b"junk", BATCH_FULL.items, BATCH_FULL.end, BATCH_FULL.mac
            )

    def test_items_contract(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", list(BATCH_FULL.items), BATCH_FULL.end, BATCH_FULL.mac
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", (), BATCH_FULL.end, BATCH_FULL.mac
            )
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                1,
                b"",
                ([RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()],),
                BATCH_FULL.end,
                BATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1,
                b"",
                ((RECEIPT_1.to_bytes(),),),
                BATCH_FULL.end,
                BATCH_FULL.mac,
            )
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", ((1, BUNDLE_1.to_bytes()),), BATCH_FULL.end, BATCH_FULL.mac
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1,
                b"",
                ((b"junk", BUNDLE_1.to_bytes()),),
                BATCH_FULL.end,
                BATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1,
                b"",
                ((RECEIPT_1.to_bytes(), b"junk"),),
                BATCH_FULL.end,
                BATCH_FULL.mac,
            )

    def test_end_contract(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", BATCH_FULL.items, 0, BATCH_FULL.mac
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", BATCH_FULL.items, b"", BATCH_FULL.mac
            )

    def test_mac_contract(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", BATCH_FULL.items, BATCH_FULL.end, "mac"
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch(
                1, b"", BATCH_FULL.items, BATCH_FULL.end, b"\x00"
            )


class BatchEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for batch in (BATCH_1, BATCH_2, BATCH_FULL):
            encoded = batch.to_bytes()
            self.assertIsInstance(encoded, bytes)
            self.assertEqual(
                BitMapHistoryJournalReceiptBatch.from_bytes(encoded), batch
            )

    def test_encoding_shape(self):
        decoded = json.loads(BATCH_FULL.to_bytes())
        self.assertEqual(decoded[0], 1)
        self.assertEqual(decoded[1], "")
        self.assertEqual(
            decoded[2],
            [
                [RECEIPT_1.to_bytes().hex(), BUNDLE_1.to_bytes().hex()],
                [RECEIPT_2.to_bytes().hex(), BUNDLE_2.to_bytes().hex()],
            ],
        )
        self.assertEqual(decoded[3], BATCH_FULL.end.hex())
        self.assertEqual(decoded[4], BATCH_FULL.mac.hex())
        self.assertEqual(
            BATCH_FULL.to_bytes(),
            json.dumps(decoded, separators=(",", ":")).encode("utf-8"),
        )

    def test_from_bytes_type_contract(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch.from_bytes("x")
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(b"not json")
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(b"[1,2,3]")

    def test_from_bytes_rejects_non_canonical(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                BATCH_FULL.to_bytes().replace(b",", b", ", 1)
            )
        doc = json.loads(BATCH_FULL.to_bytes())
        doc[0] = 2
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(BATCH_FULL.to_bytes())
        doc[2] = []
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(BATCH_FULL.to_bytes())
        doc[1] = "AB"
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_verifies_no_mac(self):
        # A batch MAC'd with another key still parses: from_bytes checks the
        # field contract only, never any MAC.
        foreign = seal_map_history_journal_receipt_batch(
            [(RECEIPT_1, BUNDLE_1)], KEY
        )
        parsed = BitMapHistoryJournalReceiptBatch.from_bytes(foreign.to_bytes())
        self.assertEqual(parsed, foreign)


class BatchSealTest(unittest.TestCase):
    def test_seal_matches_manual_chain(self):
        self.assertEqual(FRONTIER_1.sequence, 1)
        frontier = audit_map_history_journal_receipt_batch(BATCH_FULL, KEY)
        self.assertEqual(frontier.sequence, 2)
        self.assertEqual(frontier.to_bytes(), BATCH_FULL.end)

    def test_seal_accepts_canonical_bytes_and_checkpoint_bytes(self):
        sealed = seal_map_history_journal_receipt_batch(
            [(RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes())],
            KEY,
            checkpoint=FRONTIER_1.to_bytes(),
        )
        self.assertEqual(sealed, BATCH_2)

    def test_seal_type_contract(self):
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch(42, KEY)
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch([(RECEIPT_1, BUNDLE_1)], "k")
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch([42], KEY)
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY, checkpoint=42
            )

    def test_seal_value_contract(self):
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch([], KEY)
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch([(RECEIPT_1, BUNDLE_1)], b"")
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch([(RECEIPT_1,)], KEY)
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_1, BUNDLE_1, RECEIPT_1)], KEY
            )
        # A receipt that does not start at the frontier breaks the chain.
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch([(RECEIPT_2, BUNDLE_2)], KEY)
        # A receipt MAC'd with another key fails the audit.
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(receipt_for(BUNDLE_1, key=OTHER_KEY), BUNDLE_1)], KEY
            )


class BatchAuditTest(unittest.TestCase):
    def test_audit_returns_frontier(self):
        frontier = audit_map_history_journal_receipt_batch(BATCH_FULL, KEY)
        self.assertIsInstance(frontier, BitMapHistoryJournalReceiptFrontier)
        self.assertEqual(frontier.to_bytes(), BATCH_FULL.end)

    def test_audit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_map_history_journal_receipt_batch(BATCH_FULL.to_bytes(), KEY),
            audit_map_history_journal_receipt_batch(BATCH_FULL, KEY),
        )

    def test_audit_type_contract(self):
        with self.assertRaises(TypeError):
            audit_map_history_journal_receipt_batch(42, KEY)
        with self.assertRaises(TypeError):
            audit_map_history_journal_receipt_batch(BATCH_FULL, "k")

    def test_audit_key_contract(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(BATCH_FULL, b"")
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(BATCH_FULL, OTHER_KEY)

    def test_audit_rejects_tampered_end(self):
        tampered = dataclasses.replace(BATCH_FULL, end=BATCH_1.end)
        tampered = dataclasses.replace(
            tampered,
            mac=_bit_map_history_journal_receipt_batch_mac(KEY, tampered),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(tampered, KEY)

    def test_audit_rejects_tampered_end_frontier_mac(self):
        frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(BATCH_FULL.end)
        bad_frontier = dataclasses.replace(frontier, mac=ZERO)
        tampered = dataclasses.replace(BATCH_FULL, end=bad_frontier.to_bytes())
        tampered = dataclasses.replace(
            tampered,
            mac=_bit_map_history_journal_receipt_batch_mac(KEY, tampered),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(tampered, KEY)

    def test_audit_rejects_tampered_start_frontier_mac(self):
        frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(BATCH_2.start)
        bad_frontier = dataclasses.replace(frontier, mac=ZERO)
        tampered = dataclasses.replace(BATCH_2, start=bad_frontier.to_bytes())
        tampered = dataclasses.replace(
            tampered,
            mac=_bit_map_history_journal_receipt_batch_mac(KEY, tampered),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(tampered, KEY)

    def test_audit_rejects_reordered_items(self):
        tampered = dataclasses.replace(
            BATCH_FULL,
            items=(BATCH_FULL.items[1], BATCH_FULL.items[0]),
        )
        tampered = dataclasses.replace(
            tampered,
            mac=_bit_map_history_journal_receipt_batch_mac(KEY, tampered),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(tampered, KEY)


if __name__ == "__main__":
    unittest.main()
