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
    BitMapHistoryJournalReceiptBatch,
    BitMapHistoryJournalReceiptFrontier,
    BitMapUpdate,
    CommitRange,
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

RBATCH_FULL = seal_range_receipt_batch(list(CHAIN), KEY)
RBATCH_1 = seal_range_receipt_batch(
    [(RECEIPT_R1, RANGE_1)], KEY
)
RBATCH_CP = seal_range_receipt_batch(
    [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint=RFRONTIER_1
)


def reseal(batch, key=KEY):
    return dataclasses.replace(
        batch, mac=_range_receipt_batch_mac(key, batch)
    )


class RangeReceiptBatchShapeTest(unittest.TestCase):
    def test_positional_construction_and_fields(self):
        batch = RangeReceiptBatch(
            1,
            RBATCH_FULL.start,
            RBATCH_FULL.items,
            RBATCH_FULL.end,
            RBATCH_FULL.mac,
        )
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, RBATCH_FULL.start)
        self.assertEqual(batch.items, RBATCH_FULL.items)
        self.assertEqual(batch.end, RBATCH_FULL.end)
        self.assertEqual(batch.mac, RBATCH_FULL.mac)
        self.assertEqual(batch, RBATCH_FULL)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RBATCH_FULL.version = 2

    def test_equality_by_fields(self):
        self.assertEqual(
            RBATCH_FULL,
            RangeReceiptBatch(
                1,
                RBATCH_FULL.start,
                RBATCH_FULL.items,
                RBATCH_FULL.end,
                RBATCH_FULL.mac,
            ),
        )
        self.assertNotEqual(
            RBATCH_FULL, dataclasses.replace(RBATCH_FULL, mac=ZERO)
        )

    def test_empty_start_allowed_but_not_empty_end(self):
        RangeReceiptBatch(
            1, b"", ((RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),),
            RFRONTIER_1.to_bytes(), ZERO,
        )
        with self.assertRaises(ValueError):
            RangeReceiptBatch(
                1, b"", ((RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),),
                b"", ZERO,
            )

    def test_wrong_field_types(self):
        good_items = ((RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),)

        def build(**changes):
            fields = dict(
                version=1,
                start=b"",
                items=good_items,
                end=RFRONTIER_1.to_bytes(),
                mac=ZERO,
            )
            fields.update(changes)
            return RangeReceiptBatch(**fields)

        with self.assertRaises(TypeError):
            build(version=True)
        with self.assertRaises(TypeError):
            build(version="1")
        with self.assertRaises(ValueError):
            build(version=2)
        with self.assertRaises(TypeError):
            build(start="")
        with self.assertRaises(ValueError):
            build(start=b"junk")
        with self.assertRaises(TypeError):
            build(items=[good_items[0]])
        with self.assertRaises(ValueError):
            build(items=())
        with self.assertRaises(TypeError):
            build(items=([RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()],))
        with self.assertRaises(ValueError):
            build(items=((RECEIPT_R1.to_bytes(),),))
        with self.assertRaises(ValueError):
            build(
                items=(
                    (
                        RECEIPT_R1.to_bytes(),
                        RANGE_1.to_bytes(),
                        b"",
                    ),
                )
            )
        with self.assertRaises(TypeError):
            build(items=((RECEIPT_R1, RANGE_1.to_bytes()),))
        with self.assertRaises(TypeError):
            build(items=((RECEIPT_R1.to_bytes(), RANGE_1),))
        with self.assertRaises(ValueError):
            build(items=((b"junk", RANGE_1.to_bytes()),))
        with self.assertRaises(ValueError):
            build(items=((RECEIPT_R1.to_bytes(), b"junk"),))
        with self.assertRaises(TypeError):
            build(end=RFRONTIER_1)
        with self.assertRaises(ValueError):
            build(end=b"junk")
        with self.assertRaises(TypeError):
            build(mac=bytearray(32))
        with self.assertRaises(ValueError):
            build(mac=b"\x00" * 31)


class RangeReceiptBatchEncodingTest(unittest.TestCase):
    def test_compact_json_array_shape(self):
        decoded = json.loads(RBATCH_FULL.to_bytes())
        self.assertEqual(
            decoded,
            [
                1,
                RBATCH_FULL.start.hex(),
                [
                    [receipt.hex(), record.hex()]
                    for receipt, record in RBATCH_FULL.items
                ],
                RBATCH_FULL.end.hex(),
                RBATCH_FULL.mac.hex(),
            ],
        )
        # Compact: no whitespace, lowercase hex.
        self.assertNotIn(b" ", RBATCH_FULL.to_bytes())
        self.assertEqual(
            RBATCH_FULL.to_bytes(),
            json.dumps(
                decoded, separators=(",", ":"), allow_nan=False
            ).encode("utf-8"),
        )

    def test_round_trip(self):
        self.assertEqual(
            RangeReceiptBatch.from_bytes(RBATCH_FULL.to_bytes()),
            RBATCH_FULL,
        )
        self.assertEqual(
            RangeReceiptBatch.from_bytes(RBATCH_CP.to_bytes()), RBATCH_CP
        )

    def test_data_must_be_bytes(self):
        with self.assertRaises(TypeError):
            RangeReceiptBatch.from_bytes(RBATCH_FULL.to_bytes().decode())
        with self.assertRaises(TypeError):
            RangeReceiptBatch.from_bytes(None)

    def test_malformed_documents_rejected(self):
        for bad in (
            b"junk",
            b"[1,2,3]",
            b"{}",
            b"[1,\"\",[],\"" + RBATCH_FULL.end.hex().encode() + b"\",\"\"]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeReceiptBatch.from_bytes(bad)

    def test_non_canonical_spelling_rejected(self):
        raw = RBATCH_FULL.to_bytes()
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(b" " + raw)
        decoded = json.loads(raw)
        pretty = json.dumps(decoded, indent=2).encode()
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(pretty)
        upper = bytearray(raw)
        # Flip a lowercase hex letter in the mac field to uppercase.
        for index in range(len(upper) - 1, -1, -1):
            if upper[index] in range(ord("a"), ord("f") + 1):
                upper[index] -= 32
                break
        with self.assertRaises(ValueError):
            RangeReceiptBatch.from_bytes(bytes(upper))

    def test_parse_does_not_verify_mac(self):
        forged = dataclasses.replace(RBATCH_FULL, mac=ZERO)
        parsed = RangeReceiptBatch.from_bytes(forged.to_bytes())
        self.assertEqual(parsed.mac, ZERO)

    def test_mac_is_npbj15_over_first_four_fields(self):
        content = [
            RBATCH_FULL.version,
            RBATCH_FULL.start.hex(),
            [
                [receipt.hex(), record.hex()]
                for receipt, record in RBATCH_FULL.items
            ],
            RBATCH_FULL.end.hex(),
        ]
        c = json.dumps(
            content, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        expected = hmac.new(KEY, b"NPBJ15" + c, hashlib.sha256).digest()
        self.assertEqual(_range_receipt_batch_mac(KEY, RBATCH_FULL), expected)
        self.assertEqual(RBATCH_FULL.mac, expected)
        self.assertEqual(len(RBATCH_FULL.mac), 32)


class SealRangeReceiptBatchTest(unittest.TestCase):
    def test_seals_full_chain_against_range_frontier(self):
        self.assertEqual(RBATCH_FULL.version, 1)
        self.assertEqual(RBATCH_FULL.start, b"")
        self.assertEqual(
            RBATCH_FULL.items,
            tuple(
                (receipt.to_bytes(), record.to_bytes())
                for receipt, record in CHAIN
            ),
        )
        self.assertEqual(RBATCH_FULL.end, RFRONTIER_2.to_bytes())
        self.assertEqual(
            RBATCH_FULL.mac, _range_receipt_batch_mac(KEY, RBATCH_FULL)
        )

    def test_single_item_batch(self):
        self.assertEqual(RBATCH_1.start, b"")
        self.assertEqual(
            RBATCH_1.items,
            ((RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),),
        )
        self.assertEqual(RBATCH_1.end, RFRONTIER_1.to_bytes())

    def test_checkpoint_object_and_bytes(self):
        via_object = seal_range_receipt_batch(
            [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint=RFRONTIER_1
        )
        via_bytes = seal_range_receipt_batch(
            [(RECEIPT_RCP, RANGE_FROM_CP)],
            KEY,
            checkpoint=RFRONTIER_1.to_bytes(),
        )
        self.assertEqual(via_object, RBATCH_CP)
        self.assertEqual(via_bytes, RBATCH_CP)
        self.assertEqual(via_object.start, RFRONTIER_1.to_bytes())
        self.assertEqual(via_object.end, RFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes_pairs(self):
        sealed = seal_range_receipt_batch(
            [
                (RECEIPT_R1.to_bytes(), RANGE_1.to_bytes()),
                (RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),
            ],
            KEY,
        )
        self.assertEqual(sealed, RBATCH_FULL)

    def test_accepts_any_non_empty_iterable(self):
        via_tuple = seal_range_receipt_batch(CHAIN, KEY)
        via_generator = seal_range_receipt_batch(
            (pair for pair in CHAIN), KEY
        )
        self.assertEqual(via_tuple, RBATCH_FULL)
        self.assertEqual(via_generator, RBATCH_FULL)

    def test_matches_stateful_batch_audit(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(CHAIN)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(
            RangeFrontier.from_bytes(RBATCH_FULL.end), auditor.state
        )

    def test_non_iterable_items_is_type_error(self):
        for bad in (1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range_receipt_batch(bad, KEY)

    def test_non_pair_entries(self):
        with self.assertRaises(TypeError):
            seal_range_receipt_batch([RECEIPT_R1], KEY)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([(RECEIPT_R1,)], KEY)

    def test_wrong_pair_member_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_R1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range_receipt_batch([(bad, RANGE_1)], KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range_receipt_batch([(RECEIPT_R1, bad)], KEY)

    def test_empty_sequence_is_value_error(self):
        for empty in ([], (), iter(())):
            with self.assertRaises(ValueError, msg=repr(empty)):
                seal_range_receipt_batch(empty, KEY)

    def test_key_contract(self):
        with self.assertRaises(TypeError):
            seal_range_receipt_batch(CHAIN, "key")
        with self.assertRaises(TypeError):
            seal_range_receipt_batch(CHAIN, None)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(CHAIN, b"")

    def test_malformed_item_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([(b"junk", RANGE_1)], KEY)
        with self.assertRaises(ValueError):
            seal_range_receipt_batch([(RECEIPT_R1, b"junk")], KEY)

    def test_broken_chain_rejected(self):
        forged = range_receipt_for(
            RANGE_FROM_CP, b"", CFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                ((RECEIPT_R1, RANGE_1), (forged, RANGE_FROM_CP)), KEY
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(CHAIN, OTHER_KEY)

    def test_checkpoint_kind_contract(self):
        with self.assertRaises(TypeError):
            seal_range_receipt_batch(
                [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint="x"
            )
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint=b"junk"
            )

    def test_checkpoint_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                [(RECEIPT_RCP, RANGE_FROM_CP)],
                OTHER_KEY,
                checkpoint=RFRONTIER_1,
            )

    def test_first_receipt_must_start_at_checkpoint(self):
        # An empty-start batch cannot seal from a non-empty checkpoint.
        with self.assertRaises(ValueError):
            seal_range_receipt_batch(
                [(RECEIPT_R1, RANGE_1)], KEY, checkpoint=RFRONTIER_1
            )


class AuditRangeReceiptBatchTest(unittest.TestCase):
    def test_returns_frozen_frontier_at_end(self):
        result = audit_range_receipt_batch(RBATCH_FULL, KEY)
        self.assertEqual(result, RFRONTIER_2)
        self.assertEqual(result.sequence, 2)
        self.assertEqual(result.end, CFRONTIER_2.to_bytes())
        self.assertEqual(result.digest, RDIGEST_2)
        self.assertEqual(result.mac, _range_frontier_mac(KEY, result))

    def test_accepts_canonical_bytes(self):
        via_bytes = audit_range_receipt_batch(RBATCH_FULL.to_bytes(), KEY)
        self.assertEqual(via_bytes, RFRONTIER_2)

    def test_single_and_checkpoint_batches(self):
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_1, KEY), RFRONTIER_1
        )
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_CP, KEY), RFRONTIER_2
        )

    def test_matches_stateful_audits(self):
        via_batch = audit_range_receipt_batch(RBATCH_FULL, KEY)
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(via_batch, auditor.state)

    def test_chained_batches_each_auditable_on_their_own(self):
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_1, KEY), RFRONTIER_1
        )
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_CP, KEY), RFRONTIER_2
        )

    def test_pure_check_touches_no_state(self):
        # Auditing is a function: auditing twice yields identical results
        # and neither call influences the other.
        self.assertEqual(
            audit_range_receipt_batch(RBATCH_FULL, KEY),
            audit_range_receipt_batch(RBATCH_FULL, KEY),
        )

    def test_argument_kind_contract(self):
        for bad in (1, "x", None, [RBATCH_FULL], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_range_receipt_batch(bad, KEY)
        with self.assertRaises(TypeError):
            audit_range_receipt_batch(RBATCH_FULL, "key")
        with self.assertRaises(TypeError):
            audit_range_receipt_batch(RBATCH_FULL, None)
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(RBATCH_FULL, b"")

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_range_receipt_batch(bad, KEY)

    def test_batch_mac_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(
                dataclasses.replace(RBATCH_FULL, mac=ZERO), KEY
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(RBATCH_FULL, OTHER_KEY)

    def test_tampered_end_frontier_mac_rejected(self):
        frontier = RangeFrontier.from_bytes(RBATCH_FULL.end)
        bad = dataclasses.replace(
            RBATCH_FULL,
            end=dataclasses.replace(frontier, mac=ZERO).to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(reseal(bad), KEY)

    def test_tampered_start_frontier_mac_rejected(self):
        frontier = RangeFrontier.from_bytes(RBATCH_CP.start)
        bad = dataclasses.replace(
            RBATCH_CP,
            start=dataclasses.replace(frontier, mac=ZERO).to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(reseal(bad), KEY)

    def test_reordered_items_rejected(self):
        bad = dataclasses.replace(
            RBATCH_FULL,
            items=(RBATCH_FULL.items[1], RBATCH_FULL.items[0]),
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(reseal(bad), KEY)

    def test_end_not_matching_replay_rejected(self):
        bad = dataclasses.replace(RBATCH_FULL, end=RFRONTIER_1.to_bytes())
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(reseal(bad), KEY)

    def test_tampered_carried_receipt_rejected(self):
        receipt, record = RBATCH_FULL.items[1]
        bad_receipt = dataclasses.replace(
            RangeReceipt.from_bytes(receipt), mac=ZERO
        ).to_bytes()
        bad = dataclasses.replace(
            RBATCH_FULL,
            items=(RBATCH_FULL.items[0], (bad_receipt, record)),
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(reseal(bad), KEY)

    def test_tampered_carried_range_rejected(self):
        receipt, record = RBATCH_FULL.items[1]
        bad_record = dataclasses.replace(
            CommitRange.from_bytes(record), mac=ZERO
        ).to_bytes()
        bad = dataclasses.replace(
            RBATCH_FULL,
            items=(RBATCH_FULL.items[0], (receipt, bad_record)),
        )
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(reseal(bad), KEY)

    def test_start_mismatch_rejected(self):
        # Forcing the checkpoint-started batch to claim an empty start
        # makes the first receipt (whose start is non-empty) fail replay.
        bad = reseal(dataclasses.replace(RBATCH_CP, start=b""))
        with self.assertRaises(ValueError):
            audit_range_receipt_batch(bad, KEY)

    def test_seal_then_audit_round_trip_from_checkpoint_bytes(self):
        first = RangeAuditor(KEY)
        first.audit(RECEIPT_R1, RANGE_1)
        batch = seal_range_receipt_batch(
            [(RECEIPT_RCP, RANGE_FROM_CP)],
            KEY,
            checkpoint=first.state.to_bytes(),
        )
        result = audit_range_receipt_batch(batch.to_bytes(), KEY)
        self.assertEqual(result, RFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
