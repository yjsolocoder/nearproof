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
    CommitRange,
    JournalBatchReceipt,
    JournalBatchReceiptFrontier,
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
    _commit_range_body_bytes,
    _commit_range_mac,
    audit_range,
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


def body_parts(record):
    return json.loads(record.body.decode("utf-8"))


class CommitRangeFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        record = CommitRange(1, RANGE_1.body, RANGE_1.mac)
        self.assertEqual(record, RANGE_1)
        self.assertEqual(hash(record), hash(RANGE_1))
        self.assertEqual(record.version, 1)
        self.assertEqual(record.body, RANGE_1.body)
        self.assertEqual(record.mac, RANGE_1.mac)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RANGE_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRange(bad, RANGE_1.body, RANGE_1.mac)
        with self.assertRaises(ValueError):
            CommitRange(2, RANGE_1.body, RANGE_1.mac)

    def test_body_type_contract(self):
        for bad in (1, "x", None, bytearray(RANGE_1.body)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRange(1, bad, RANGE_1.mac)

    def test_body_value_contract(self):
        good_s, good_items, good_e = body_parts(RANGE_1)

        def body_with(start=good_s, items=good_items, end=good_e):
            return _commit_range_body_bytes(
                bytes.fromhex(start),
                tuple(
                    (bytes.fromhex(r), bytes.fromhex(b)) for r, b in items
                ),
                bytes.fromhex(end),
            )

        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b'["",[],' + json.dumps(good_e).encode() + b"]",
            body_with(end=""),
            body_with(start=bytes([1]).hex()),
            body_with(end=bytes([1]).hex()),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRange(1, bad, RANGE_1.mac)
        # An inner entry of the wrong shape is a value violation too.
        for bad_items in (
            [[good_items[0][0]]],
            [[good_items[0][0], good_items[0][1], ""]],
            [["", good_items[0][1]]],
            [[good_items[0][0], ""]],
        ):
            bad = json.dumps(
                [good_s, bad_items, good_e], separators=(",", ":")
            ).encode()
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRange(1, bad, RANGE_1.mac)

    def test_mac_contract(self):
        for bad in (1, "x", None, bytearray(RANGE_1.mac)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRange(1, RANGE_1.body, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRange(1, RANGE_1.body, bad)


class CommitRangeEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"'
            + RANGE_1.body.hex().encode()
            + b'","'
            + RANGE_1.mac.hex().encode()
            + b'"]'
        )
        self.assertEqual(RANGE_1.to_bytes(), expected)

    def test_body_shape_is_hex_s_items_e(self):
        start, items, end = body_parts(RANGE_2)
        self.assertEqual(start, "")
        self.assertEqual(end, CFRONTIER_2.to_bytes().hex())
        self.assertEqual(len(items), 2)
        self.assertEqual(
            items,
            [
                [COMMIT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()],
                [COMMIT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()],
            ],
        )
        cp_start, cp_items, cp_end = body_parts(RANGE_FROM_CP)
        self.assertEqual(cp_start, CFRONTIER_1.to_bytes().hex())
        self.assertEqual(
            cp_items,
            [[COMMIT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()]],
        )
        self.assertEqual(cp_end, CFRONTIER_2.to_bytes().hex())

    def test_mac_is_npbj11_over_raw_body(self):
        self.assertEqual(
            RANGE_2.mac,
            hmac.new(
                KEY, b"NPBJ11" + RANGE_2.body, hashlib.sha256
            ).digest(),
        )

    def test_round_trip(self):
        for record in (RANGE_1, RANGE_2, RANGE_FROM_CP):
            blob = record.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(CommitRange.from_bytes(blob), record)
            self.assertEqual(
                CommitRange.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = RANGE_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRange.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2]",
            b"[1,2,3,4]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRange.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RANGE_1.to_bytes()
        with self.assertRaises(ValueError):
            CommitRange.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            RANGE_1.mac.hex().encode(),
            RANGE_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            CommitRange.from_bytes(upper)
        with self.assertRaises(ValueError):
            CommitRange.from_bytes(blob.replace(b"[1,", b"[2,", 1))

    def test_from_bytes_does_not_verify_mac(self):
        tampered = CommitRange(1, RANGE_1.body, ZERO)
        parsed = CommitRange.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)


class SealRangeTest(unittest.TestCase):
    def test_seals_one_and_many_commits(self):
        self.assertEqual(
            audit_range(RANGE_1, KEY), CFRONTIER_1
        )
        self.assertEqual(
            audit_range(RANGE_2, KEY), CFRONTIER_2
        )
        self.assertEqual(
            audit_range(RANGE_FROM_CP, KEY), CFRONTIER_2
        )

    def test_single_full_batch_is_one_commit(self):
        record = seal_range([(COMMIT_FULL, BATCH_FULL)], KEY)
        final = audit_range(record, KEY)
        self.assertEqual(final.sequence, 1)
        self.assertEqual(final.end, BATCH_FULL.end)

    def test_accepts_canonical_bytes_and_mixed_pairs(self):
        record = seal_range(
            [(COMMIT_1.to_bytes(), BATCH_1.to_bytes()), (COMMIT_2, BATCH_2)],
            KEY,
        )
        self.assertEqual(audit_range(record, KEY), CFRONTIER_2)
        record = seal_range(
            [(COMMIT_2.to_bytes(), BATCH_2.to_bytes())],
            KEY,
            checkpoint=CFRONTIER_1.to_bytes(),
        )
        self.assertEqual(audit_range(record, KEY), CFRONTIER_2)

    def test_accepts_tuples_and_lists_and_generators(self):
        record = seal_range(
            ((COMMIT_1, BATCH_1), (COMMIT_2, BATCH_2)), KEY
        )
        self.assertEqual(audit_range(record, KEY), CFRONTIER_2)
        record = seal_range(
            ([COMMIT_1, BATCH_1], [COMMIT_2, BATCH_2]), KEY
        )
        self.assertEqual(audit_range(record, KEY), CFRONTIER_2)
        record = seal_range(
            ((c, b) for c, b in ((COMMIT_1, BATCH_1), (COMMIT_2, BATCH_2))),
            KEY,
        )
        self.assertEqual(audit_range(record, KEY), CFRONTIER_2)

    def test_key_contract(self):
        items = [(COMMIT_1, BATCH_1)]
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range(items, bad)
        with self.assertRaises(ValueError):
            seal_range(items, b"")

    def test_items_type_contract(self):
        for bad in (1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range(bad, KEY)
        for bad in (1, "x", None, [COMMIT_1], (COMMIT_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range([(bad, BATCH_1)], KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range([(COMMIT_1, bad)], KEY)

    def test_empty_items_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_range([], KEY)

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                seal_range([(bad, BATCH_1)], KEY)
            with self.assertRaises(ValueError, msg=repr(bad)):
                seal_range([(COMMIT_1, bad)], KEY)

    def test_pair_shape_contract(self):
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1,)], KEY)
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, BATCH_1, None)], KEY)

    def test_checkpoint_type_contract(self):
        items = [(COMMIT_2, BATCH_2)]
        for bad in (1, "x", [CFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range(items, KEY, checkpoint=bad)

    def test_checkpoint_malformed_or_bad_mac(self):
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_2, BATCH_2)], KEY, checkpoint=b"junk"
            )
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_2, BATCH_2)],
                KEY,
                checkpoint=dataclasses.replace(CFRONTIER_1, mac=ZERO),
            )

    def test_first_commit_without_checkpoint_must_start_empty(self):
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_2, BATCH_2)], KEY)

    def test_replayed_or_gapped_commit_rejected(self):
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, BATCH_1), (COMMIT_1, BATCH_1)], KEY)
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_1, BATCH_1), (COMMIT_FULL, BATCH_FULL)], KEY
            )

    def test_checkpoint_must_match_first_start(self):
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_1, BATCH_1)], KEY, checkpoint=CFRONTIER_1
            )

    def test_wrong_batch_rejected(self):
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, BATCH_FULL)], KEY)

    def test_tampered_commit_rejected(self):
        with self.assertRaises(ValueError):
            seal_range(
                [(dataclasses.replace(COMMIT_1, mac=ZERO), BATCH_1)], KEY
            )

    def test_wrong_key_checkpoint_rejected(self):
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_2, BATCH_2)], OTHER_KEY, checkpoint=CFRONTIER_1
            )


class AuditRangeTest(unittest.TestCase):
    def test_returns_frontier_at_e(self):
        self.assertEqual(audit_range(RANGE_1, KEY), CFRONTIER_1)
        self.assertEqual(audit_range(RANGE_2, KEY), CFRONTIER_2)
        self.assertEqual(audit_range(RANGE_FROM_CP, KEY), CFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_range(RANGE_2.to_bytes(), KEY), CFRONTIER_2
        )

    def test_independent_party_verifies_from_empty_start(self):
        # A third party with only the serialized proof and the shared key
        # re-checks the NPBJ11 MAC itself, then replays the commits.
        blob = RANGE_2.to_bytes()
        outer = json.loads(blob)
        self.assertEqual(outer[0], 1)
        body = bytes.fromhex(outer[1])
        mac = bytes.fromhex(outer[2])
        self.assertTrue(
            hmac.compare_digest(
                hmac.new(KEY, b"NPBJ11" + body, hashlib.sha256).digest(),
                mac,
            )
        )
        final = audit_range(blob, KEY)
        self.assertEqual(final, CFRONTIER_2)

    def test_independent_party_verifies_from_checkpoint(self):
        blob = RANGE_FROM_CP.to_bytes()
        final = audit_range(blob, KEY)
        self.assertEqual(final, CFRONTIER_2)
        self.assertEqual(final.sequence, 2)

    def test_x_type_contract(self):
        for bad in (1, "x", None, [RANGE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_range(bad, KEY)

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_range(bad, KEY)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_range(RANGE_1, bad)
        with self.assertRaises(ValueError):
            audit_range(RANGE_1, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_range(RANGE_1, OTHER_KEY)

    def test_tampered_mac_rejected(self):
        tampered = CommitRange(1, RANGE_1.body, ZERO)
        with self.assertRaises(ValueError):
            audit_range(tampered, KEY)
        with self.assertRaises(ValueError):
            audit_range(tampered.to_bytes(), KEY)

    def test_tampered_body_rejected(self):
        start, items, end = body_parts(RANGE_2)
        bad_body = _commit_range_body_bytes(
            bytes.fromhex(start),
            tuple(
                (bytes.fromhex(r), BATCH_FULL.to_bytes()) for r, _ in items
            ),
            bytes.fromhex(end),
        )
        # A range MAC'd correctly over a substituted batch still fails the
        # per-commit replay.
        record = CommitRange(
            1, bad_body, _commit_range_mac(KEY, bad_body)
        )
        with self.assertRaises(ValueError):
            audit_range(record, KEY)

    def test_non_contiguous_chain_rejected(self):
        start, _, end = body_parts(RANGE_2)
        items = [
            [COMMIT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()],
            [COMMIT_FULL.to_bytes().hex(), BATCH_FULL.to_bytes().hex()],
        ]
        bad_body = json.dumps(
            [start, items, end], separators=(",", ":")
        ).encode()
        record = CommitRange(
            1, bad_body, _commit_range_mac(KEY, bad_body)
        )
        with self.assertRaises(ValueError):
            audit_range(record, KEY)

    def test_end_must_equal_replayed_frontier(self):
        start, items, _ = body_parts(RANGE_2)
        # Only the first commit is carried but E claims the two-commit end.
        bad_body = json.dumps(
            [start, items[:1], CFRONTIER_2.to_bytes().hex()],
            separators=(",", ":"),
        ).encode()
        record = CommitRange(
            1, bad_body, _commit_range_mac(KEY, bad_body)
        )
        with self.assertRaises(ValueError):
            audit_range(record, KEY)

    def test_carried_checkpoint_mac_verified(self):
        bad_checkpoint = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_2, BATCH_2)], KEY, checkpoint=bad_checkpoint
            )


if __name__ == "__main__":
    unittest.main()
