import dataclasses
import json
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalReceiptAuditor,
    BitMapHistoryJournalReceiptBatch,
    BitMapUpdate,
    _bit_map_history_journal_receipt_batch_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _encode_payload,
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
STATE_2 = audited_state(EVIDENCE_1, EVIDENCE_2)

BUNDLE_1 = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
BUNDLE_2 = seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=STATE_1)
BUNDLE_FULL = seal_map_history_journal_bundle([EVIDENCE_1, EVIDENCE_2], KEY)

JOURNAL_AUDITOR = BitMapHistoryJournalAuditor(KEY)
RECEIPT_1 = JOURNAL_AUDITOR.audit_bundle_receipt(BUNDLE_1)
RECEIPT_2 = JOURNAL_AUDITOR.audit_bundle_receipt(BUNDLE_2)
RECEIPT_FULL = BitMapHistoryJournalAuditor(KEY).audit_bundle_receipt(
    BUNDLE_FULL
)

ITEMS_12 = (
    (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
    (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
)
ITEMS_FULL = ((RECEIPT_FULL.to_bytes(), BUNDLE_FULL.to_bytes()),)


def audited_frontier(*pairs, key=KEY):
    auditor = BitMapHistoryJournalReceiptAuditor(key)
    for receipt, bundle in pairs:
        auditor.audit(receipt, bundle)
    return auditor.checkpoint


FRONTIER_1 = audited_frontier((RECEIPT_1, BUNDLE_1))
FRONTIER_2 = audited_frontier(
    (RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)
)

BATCH_12 = seal_map_history_journal_receipt_batch(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
)
BATCH_FULL = seal_map_history_journal_receipt_batch(
    [(RECEIPT_FULL, BUNDLE_FULL)], KEY
)


def batch_for(start, items, end, key=KEY):
    placeholder = BitMapHistoryJournalReceiptBatch(
        1, start, tuple(items), end, ZERO
    )
    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_receipt_batch_mac(key, placeholder)
    )


class BatchFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        batch = BitMapHistoryJournalReceiptBatch(
            1, BATCH_12.start, BATCH_12.items, BATCH_12.end, BATCH_12.mac
        )
        self.assertEqual(batch, BATCH_12)
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, b"")
        self.assertEqual(batch.items, ITEMS_12)
        self.assertEqual(batch.end, FRONTIER_2.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BATCH_12.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_12, version=2)

    def test_start_contract(self):
        for bad in (1, "x", None, bytearray(b"")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, start=bad)
        # b"" and a canonical frontier are both accepted.
        self.assertEqual(dataclasses.replace(BATCH_12, start=b"").start, b"")
        self.assertEqual(
            dataclasses.replace(
                BATCH_12, start=FRONTIER_1.to_bytes()
            ).start,
            FRONTIER_1.to_bytes(),
        )
        # A journal state is not a receipt frontier.
        for bad in (b"junk", STATE_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, start=bad)

    def test_items_must_be_a_tuple(self):
        for bad in (1, "x", None, [BATCH_12.items[0]]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, items=bad)

    def test_items_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_12, items=())

    def test_items_entry_shape_contract(self):
        # A non-tuple entry is the wrong kind -> TypeError; a tuple item of
        # the wrong length is a value-contract failure -> ValueError.
        with self.assertRaises(TypeError):
            dataclasses.replace(BATCH_12, items=([RECEIPT_1, BUNDLE_1],))
        receipt, bundle = BATCH_12.items[0]
        for bad in (((receipt,),), ((receipt, bundle, b"x"),)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, items=bad)

    def test_items_element_type_contract(self):
        with self.assertRaises(TypeError):
            dataclasses.replace(
                BATCH_12,
                items=(("not-bytes", BUNDLE_1.to_bytes()),) + BATCH_12.items[1:],
            )
        with self.assertRaises(TypeError):
            dataclasses.replace(
                BATCH_12,
                items=((RECEIPT_1.to_bytes(), 7),) + BATCH_12.items[1:],
            )

    def test_items_elements_must_be_canonical(self):
        # bytes of the right kind but not the canonical record encoding.
        with self.assertRaises(ValueError):
            dataclasses.replace(
                BATCH_12,
                items=((b"junk", BUNDLE_1.to_bytes()),) + BATCH_12.items[1:],
            )
        with self.assertRaises(ValueError):
            dataclasses.replace(
                BATCH_12,
                items=((RECEIPT_1.to_bytes(), b"junk"),) + BATCH_12.items[1:],
            )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(FRONTIER_2.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, end=bad)
        # Unlike start, end must be non-empty canonical frontier bytes.
        for bad in (b"", b"junk", STATE_2.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, end=bad)

    def test_mac_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, mac=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_12, mac=bad)


class BatchEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",['
            b'["' + RECEIPT_1.to_bytes().hex().encode()
            + b'","' + BUNDLE_1.to_bytes().hex().encode() + b'"],'
            b'["' + RECEIPT_2.to_bytes().hex().encode()
            + b'","' + BUNDLE_2.to_bytes().hex().encode() + b'"]],'
            b'"' + FRONTIER_2.to_bytes().hex().encode() + b'",'
            b'"' + BATCH_12.mac.hex().encode() + b'"]'
        )
        self.assertEqual(BATCH_12.to_bytes(), expected)

    def test_round_trip(self):
        for batch in (BATCH_12, BATCH_FULL):
            blob = batch.to_bytes()
            self.assertEqual(
                BitMapHistoryJournalReceiptBatch.from_bytes(blob), batch
            )
            self.assertEqual(
                BitMapHistoryJournalReceiptBatch.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        for bad in (1, "x", None, bytearray(BATCH_12.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceiptBatch.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalReceiptBatch.from_bytes(bad)

    def test_from_bytes_rejects_item_shape(self):
        blob = BATCH_12.to_bytes()
        outer = json.loads(blob)
        # items[0] missing its bundle side -> wrong length -> ValueError.
        outer[2][0] = [outer[2][0][0]]
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                _encode_payload(outer)
            )
        # items[0] not an array -> wrong kind -> TypeError.
        outer = json.loads(blob)
        outer[2][0] = "nope"
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                _encode_payload(outer)
            )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = BATCH_12.to_bytes()
        spaced = blob.replace(b",", b", ")
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(spaced)
        upper = blob.replace(
            BATCH_12.mac.hex().encode(),
            BATCH_12.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(upper)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptBatch.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(BATCH_12, mac=ZERO)
        parsed = BitMapHistoryJournalReceiptBatch.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)


class SealTest(unittest.TestCase):
    def test_seals_from_empty_frontier(self):
        batch = seal_map_history_journal_receipt_batch(
            [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
        )
        self.assertEqual(batch, BATCH_12)
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, b"")
        self.assertEqual(batch.items, ITEMS_12)
        self.assertEqual(batch.end, FRONTIER_2.to_bytes())
        self.assertEqual(
            batch.mac, _bit_map_history_journal_receipt_batch_mac(KEY, batch)
        )

    def test_seals_from_checkpoint(self):
        batch = seal_map_history_journal_receipt_batch(
            [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=FRONTIER_1
        )
        self.assertEqual(batch.start, FRONTIER_1.to_bytes())
        self.assertEqual(
            batch.items, ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),)
        )
        self.assertEqual(batch.end, FRONTIER_2.to_bytes())

    def test_seal_accepts_bytes_everywhere(self):
        batch = seal_map_history_journal_receipt_batch(
            [(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
             (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes())],
            KEY,
        )
        self.assertEqual(batch, BATCH_12)
        from_bytes = seal_map_history_journal_receipt_batch(
            [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=FRONTIER_1.to_bytes()
        )
        self.assertEqual(
            from_bytes.start, FRONTIER_1.to_bytes()
        )
        self.assertEqual(from_bytes.end, FRONTIER_2.to_bytes())

    def test_single_full_bundle_batch(self):
        batch = seal_map_history_journal_receipt_batch(
            [(RECEIPT_FULL, BUNDLE_FULL)], KEY
        )
        self.assertEqual(batch.items, ITEMS_FULL)
        self.assertEqual(batch.end, audited_frontier((RECEIPT_FULL, BUNDLE_FULL)).to_bytes())

    def test_items_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch([], KEY)

    def test_items_must_be_iterable(self):
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch(123, KEY)

    def test_item_kind_and_shape_contract(self):
        # A list item is the wrong kind -> TypeError.
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch(
                [[RECEIPT_1, BUNDLE_1]], KEY
            )
        # A wrong-kind element -> TypeError.
        with self.assertRaises(TypeError):
            seal_map_history_journal_receipt_batch(
                [("nope", BUNDLE_1)], KEY
            )
        # A wrong-length tuple item -> ValueError.
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch([(RECEIPT_1,)], KEY)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history_journal_receipt_batch(
                    [(RECEIPT_1, BUNDLE_1)], bad
                )
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], b""
            )

    def test_checkpoint_kind_contract(self):
        for bad in (1, "x", [FRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history_journal_receipt_batch(
                    [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=b"junk"
            )

    def test_checkpoint_frontier_mac_verified(self):
        tampered = dataclasses.replace(FRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=tampered
            )

    def test_broken_chain_rejected(self):
        # The second pair cannot follow the first when reordered.
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_2, BUNDLE_2), (RECEIPT_1, BUNDLE_1)], KEY
            )

    def test_first_receipt_must_start_empty(self):
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY
            )

    def test_receipt_bundle_mismatch_rejected(self):
        # An honest RECEIPT_1 does not attest BUNDLE_FULL.
        with self.assertRaises(ValueError):
            seal_map_history_journal_receipt_batch(
                [(RECEIPT_1, BUNDLE_FULL)], KEY
            )

    def test_sealing_touches_no_auditor_state(self):
        before = FRONTIER_1
        seal_map_history_journal_receipt_batch(
            [(RECEIPT_2, BUNDLE_2)], KEY, checkpoint=before
        )
        self.assertEqual(before, FRONTIER_1)


class AuditBatchTest(unittest.TestCase):
    def test_returns_final_frontier(self):
        self.assertEqual(
            audit_map_history_journal_receipt_batch(BATCH_12, KEY),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_map_history_journal_receipt_batch(BATCH_FULL, KEY),
            audited_frontier((RECEIPT_FULL, BUNDLE_FULL)),
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_map_history_journal_receipt_batch(BATCH_12.to_bytes(), KEY),
            FRONTIER_2,
        )

    def test_audits_from_non_empty_start(self):
        batch = batch_for(
            FRONTIER_1.to_bytes(),
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            FRONTIER_2.to_bytes(),
        )
        self.assertEqual(
            audit_map_history_journal_receipt_batch(batch, KEY), FRONTIER_2
        )

    def test_x_type_contract(self):
        for bad in (1, "x", None, [BATCH_12], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt_batch(bad, KEY)

    def test_x_malformed_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(b"junk", KEY)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt_batch(BATCH_12, bad)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(BATCH_12, b"")

    def test_tampered_batch_mac_rejected(self):
        tampered = dataclasses.replace(BATCH_12, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(tampered, KEY)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(BATCH_12, OTHER_KEY)

    def test_start_frontier_mac_verified(self):
        bad_start = dataclasses.replace(FRONTIER_1, mac=ZERO)
        batch = BitMapHistoryJournalReceiptBatch(
            1,
            bad_start.to_bytes(),
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            FRONTIER_2.to_bytes(),
            ZERO,
        )
        batch = dataclasses.replace(
            batch, mac=_bit_map_history_journal_receipt_batch_mac(KEY, batch)
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(batch, KEY)

    def test_end_must_match_replayed_chain(self):
        # Honest batch MAC over an end that the replay does not reach.
        batch = batch_for(
            b"",
            ITEMS_12,
            FRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(batch, KEY)

    def test_inner_receipt_tamper_rejected(self):
        bad_receipt = dataclasses.replace(RECEIPT_1, mac=ZERO)
        batch = batch_for(
            b"",
            ((bad_receipt.to_bytes(), BUNDLE_1.to_bytes()),)
            + ITEMS_12[1:],
            FRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt_batch(batch, KEY)

    def test_audit_is_a_pure_check(self):
        result = audit_map_history_journal_receipt_batch(BATCH_12, KEY)
        self.assertEqual(result, FRONTIER_2)
        # Auditing twice yields the same frontier and mutates nothing.
        self.assertEqual(
            audit_map_history_journal_receipt_batch(BATCH_12, KEY), result
        )


if __name__ == "__main__":
    unittest.main()
