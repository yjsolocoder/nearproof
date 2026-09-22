import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalReceiptAuditor,
    BitMapUpdate,
    JournalBatchReceipt,
    JournalBatchReceiptFrontier,
    RangeAuditor,
    RangeFrontier,
    RangeReceipt,
    RangeReceiptBatch,
    _bit_map_history_journal_batch_receipt_frontier_mac,
    _bit_map_history_journal_batch_receipt_frontier_next_digest,
    _bit_map_history_journal_batch_receipt_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _range_frontier_mac,
    _range_frontier_next_digest,
    _range_receipt_batch_content_bytes,
    _range_receipt_batch_mac,
    _range_receipt_mac,
    audit_range_receipt_batch,
    seal_map_history,
    seal_map_history_journal_bundle,
    seal_map_history_journal_receipt_batch,
    seal_range,
    seal_range_receipt_batch,
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

RBATCH_1 = seal_range_receipt_batch([(RECEIPT_R1, RANGE_1)], KEY)
RBATCH_2 = seal_range_receipt_batch(
    [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint=RFRONTIER_1
)
RBATCH_FULL = seal_range_receipt_batch(CHAIN, KEY)


class BatchFieldContractTest(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(RBATCH_FULL.version, 1)
        self.assertEqual(RBATCH_FULL.start, b"")
        self.assertEqual(
            RBATCH_FULL.items,
            (
                (RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),
                (RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),
            ),
        )
        self.assertEqual(len(RBATCH_FULL.mac), 32)
        self.assertEqual(RBATCH_2.start, RFRONTIER_1.to_bytes())
        self.assertEqual(RBATCH_2.end, RFRONTIER_2.to_bytes())

    def test_positional_construction_and_equality(self):
        clone = RangeReceiptBatch(
            1,
            RBATCH_FULL.start,
            RBATCH_FULL.items,
            RBATCH_FULL.end,
            RBATCH_FULL.mac,
        )
        self.assertEqual(clone, RBATCH_FULL)
        self.assertEqual(hash(clone), hash(RBATCH_FULL))

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RBATCH_FULL.version = 2

    def test_version_contract(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                "1",
                b"",
                RBATCH_FULL.items,
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                2,
                b"",
                RBATCH_FULL.items,
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )

    def test_start_contract(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1,
                0,
                RBATCH_FULL.items,
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1,
                b"junk",
                RBATCH_FULL.items,
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )

    def test_items_contract(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1,
                b"",
                list(RBATCH_FULL.items),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1, b"", (), RBATCH_FULL.end, RBATCH_FULL.mac
            )
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1,
                b"",
                ([RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()],),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1,
                b"",
                ((RECEIPT_R1.to_bytes(),),),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1,
                b"",
                ((1, RANGE_1.to_bytes()),),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1,
                b"",
                ((RECEIPT_R1.to_bytes(), 1),),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1,
                b"",
                ((b"junk", RANGE_1.to_bytes()),),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1,
                b"",
                ((RECEIPT_R1.to_bytes(), b"junk"),),
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            )

    def test_end_contract(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1, b"", RBATCH_FULL.items, 0, RBATCH_FULL.mac
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1, b"", RBATCH_FULL.items, b"", RBATCH_FULL.mac
            )

    def test_mac_contract(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch(
                1, b"", RBATCH_FULL.items, RBATCH_FULL.end, "mac"
            )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1,
                b"",
                RBATCH_FULL.items,
                RBATCH_FULL.end,
                b"\x00",
            )


class BatchEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for batch in (RBATCH_1, RBATCH_2, RBATCH_FULL):
            encoded = batch.to_bytes()
            self.assertIsInstance(encoded, bytes)
            self.assertEqual(
                RangeReceiptBatch.from_bytes(encoded), batch
            )

    def test_encoding_shape(self):
        decoded = json.loads(RBATCH_FULL.to_bytes())
        self.assertEqual(decoded[0], 1)
        self.assertEqual(decoded[1], "")
        self.assertEqual(
            decoded[2],
            [
                [RECEIPT_R1.to_bytes().hex(), RANGE_1.to_bytes().hex()],
                [RECEIPT_RCP.to_bytes().hex(), RANGE_FROM_CP.to_bytes().hex()],
            ],
        )
        self.assertEqual(decoded[3], RBATCH_FULL.end.hex())
        self.assertEqual(decoded[4], RBATCH_FULL.mac.hex())
        self.assertEqual(
            RBATCH_FULL.to_bytes(),
            json.dumps(decoded, separators=(",", ":")).encode("utf-8"),
        )

    def test_items_round_trip_as_nested_tuples(self):
        parsed = RangeReceiptBatch.from_bytes(RBATCH_FULL.to_bytes())
        self.assertIsInstance(parsed.items, tuple)
        for item in parsed.items:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)

    def test_from_bytes_type_contract(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch.from_bytes("x")
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(b"not json")
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(b"[1,2,3]")

    def test_from_bytes_rejects_non_canonical(self):
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(
                RBATCH_FULL.to_bytes().replace(b",", b", ", 1)
            )
        doc = json.loads(RBATCH_FULL.to_bytes())
        doc[0] = 2
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(RBATCH_FULL.to_bytes())
        doc[2] = []
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(RBATCH_FULL.to_bytes())
        doc[1] = "AB"
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(RBATCH_FULL.to_bytes())
        doc[4] = doc[4].upper()
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_verifies_no_mac(self):
        # A batch whose own NPBJ15 MAC was made with another key still
        # parses: from_bytes checks the field contract only, never any MAC.
        placeholder = RangeReceiptBatch(
            1,
            RBATCH_1.start,
            RBATCH_1.items,
            RBATCH_1.end,
            ZERO,
        )
        foreign = dataclasses.replace(
            placeholder,
            mac=_range_receipt_batch_mac(OTHER_KEY, placeholder),
        )
        parsed = RangeReceiptBatch.from_bytes(foreign.to_bytes())
        self.assertEqual(parsed, foreign)


class BatchMacTest(unittest.TestCase):
    def test_mac_is_npbj15_hmac(self):
        for batch in (RBATCH_1, RBATCH_2, RBATCH_FULL):
            expected = hmac.new(
                KEY,
                b"NPBJ15" + _range_receipt_batch_content_bytes(batch),
                hashlib.sha256,
            ).digest()
            self.assertEqual(batch.mac, expected)
            self.assertEqual(
                batch.mac, _range_receipt_batch_mac(KEY, batch)
            )
            self.assertEqual(len(batch.mac), 32)

    def test_mac_covers_only_first_four_fields(self):
        content = json.loads(
            _range_receipt_batch_content_bytes(RBATCH_FULL)
        )
        self.assertEqual(len(content), 4)
        self.assertEqual(content[0], 1)


class BatchSealTest(unittest.TestCase):
    def test_seal_matches_manual_chain(self):
        self.assertEqual(audit_range_receipt_batch(RBATCH_1, KEY), RFRONTIER_1)
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_FULL, KEY), RFRONTIER_2
        )
        self.assertEqual(RBATCH_1.start, b"")
        self.assertEqual(RBATCH_1.end, RFRONTIER_1.to_bytes())

    def test_seal_from_checkpoint_object_and_bytes(self):
        via_object = seal_range_receipt_batch(
            [(RECEIPT_RCP, RANGE_FROM_CP)],
            KEY,
            checkpoint=RFRONTIER_1,
        )
        via_bytes = seal_range_receipt_batch(
            [(RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes())],
            KEY,
            checkpoint=RFRONTIER_1.to_bytes(),
        )
        self.assertEqual(via_object, RBATCH_2)
        self.assertEqual(via_bytes, RBATCH_2)

    def test_seal_accepts_canonical_bytes_items(self):
        sealed = seal_range_receipt_batch(
            [
                (RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),
                (RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),
            ],
            KEY,
        )
        self.assertEqual(sealed, RBATCH_FULL)

    def test_seal_accepts_any_non_empty_iterable(self):
        via_list = seal_range_receipt_batch(list(CHAIN), KEY)
        via_tuple = seal_range_receipt_batch(CHAIN, KEY)
        via_generator = seal_range_receipt_batch(
            (pair for pair in CHAIN), KEY
        )
        self.assertEqual(via_list, RBATCH_FULL)
        self.assertEqual(via_tuple, RBATCH_FULL)
        self.assertEqual(via_generator, RBATCH_FULL)

    def test_seal_is_pure_computation(self):
        # Sealing must not leave any auditor state behind: re-sealing the
        # same chain from nothing always works even after a prior seal of
        # the same items.
        self.assertEqual(
            seal_range_receipt_batch(CHAIN, KEY), RBATCH_FULL
        )
        self.assertEqual(
            seal_range_receipt_batch(CHAIN, KEY), RBATCH_FULL
        )

    def test_seal_type_contract(self):
        with self.assertRaises(TypeError):
            seal_range_receipt_batch(42, KEY)
        with self.assertRaises(TypeError):
            seal_range_receipt_batch([(RECEIPT_R1, RANGE_1)], "k")
        with self.assertRaises(TypeError):
            seal_range_receipt_batch([42], KEY)
        with self.assertRaises(TypeError):
            seal_range_receipt_batch(
                [(RECEIPT_R1, RANGE_1)], KEY, checkpoint=42
            )
        for bad in (42, None, "x"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range_receipt_batch([(bad, RANGE_1)], KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range_receipt_batch([(RECEIPT_R1, bad)], KEY)

    def test_seal_value_contract(self):
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([], KEY)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(iter(()), KEY)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([(RECEIPT_R1,)], KEY)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                [(RECEIPT_R1, RANGE_1, RECEIPT_R1)], KEY
            )
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([(RECEIPT_R1, RANGE_1)], b"")
        # The continuation receipt cannot seal a batch from nothing.
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                [(RECEIPT_RCP, RANGE_FROM_CP)], KEY
            )
        # A receipt MAC'd with another key fails the replay.
        foreign = range_receipt_for(
            RANGE_1, b"", CFRONTIER_1.to_bytes(), key=OTHER_KEY
        )
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([(foreign, RANGE_1)], KEY)
        # A broken link inside the chain fails the whole batch.
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                ((RECEIPT_R1, RANGE_1), (RECEIPT_R1, RANGE_1)), KEY
            )


class BatchAuditTest(unittest.TestCase):
    def test_audit_returns_frontier(self):
        frontier = audit_range_receipt_batch(RBATCH_FULL, KEY)
        self.assertIsInstance(frontier, RangeFrontier)
        self.assertEqual(frontier, RFRONTIER_2)
        self.assertEqual(frontier.sequence, 2)
        self.assertEqual(frontier.end, CFRONTIER_2.to_bytes())
        self.assertEqual(frontier.digest, RDIGEST_2)
        self.assertEqual(frontier.mac, _range_frontier_mac(KEY, frontier))

    def test_audit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_FULL.to_bytes(), KEY),
            RFRONTIER_2,
        )

    def test_audit_single_item_batch(self):
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_1, KEY), RFRONTIER_1
        )

    def test_audit_from_carried_checkpoint(self):
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_2, KEY), RFRONTIER_2
        )

    def test_audit_matches_stateful_auditor(self):
        via_batch = audit_range_receipt_batch(RBATCH_FULL, KEY)
        via_auditor = RangeAuditor(KEY).audit_batch(CHAIN).state
        self.assertEqual(via_batch, via_auditor)

    def test_audit_is_pure_check(self):
        # Auditing never mutates shared state: the same batch audits twice.
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_FULL, KEY),
            audit_range_receipt_batch(RBATCH_FULL, KEY),
        )

    def test_audit_type_contract(self):
        with self.assertRaises(TypeError):
            audit_range_receipt_batch(42, KEY)
        with self.assertRaises(TypeError):
            audit_range_receipt_batch(RBATCH_FULL, "k")
        with self.assertRaises(TypeError):
            audit_range_receipt_batch(RBATCH_FULL, None)

    def test_audit_value_contract(self):
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(b"junk", KEY)
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(RBATCH_FULL, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(RBATCH_FULL, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(RBATCH_FULL.to_bytes(), OTHER_KEY)

    def test_batch_mac_mismatch_rejected(self):
        forged = dataclasses.replace(RBATCH_FULL, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(forged, KEY)

    def test_tampered_item_rejected(self):
        # Re-seal over a tampered carried receipt: the batch NPBJ15 MAC can
        # be made consistent, but the receipt's own NPBJ12 MAC cannot.
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
            audit_range_receipt_batch(signed, KEY)

    def test_end_must_match_replayed_chain(self):
        # A structurally valid batch whose end frontier is not where the
        # replay lands is rejected, even with a consistent NPBJ15 MAC.
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
            audit_range_receipt_batch(signed, KEY)

    def test_start_mismatch_rejected(self):
        # RBATCH_2 carries a non-empty start; auditing its carried chain
        # from nothing (empty start) cannot reach its end.
        placeholder = RangeReceiptBatch(
            1,
            b"",
            RBATCH_2.items,
            RBATCH_2.end,
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(signed, KEY)

    def test_tampered_start_frontier_rejected(self):
        # Flip the carried start frontier's range MAC: the five-layer
        # endpoint MAC check rejects it before replay.
        bad_start_frontier = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                [(RECEIPT_RCP, RANGE_FROM_CP)],
                KEY,
                checkpoint=bad_start_frontier,
            )
        # And a hand-built batch pointing at the tampered frontier fails
        # the endpoint MAC verification.
        placeholder = RangeReceiptBatch(
            1,
            bad_start_frontier.to_bytes(),
            RBATCH_2.items,
            RBATCH_2.end,
            ZERO,
        )
        signed = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(signed, KEY)


if __name__ == "__main__":
    unittest.main()
