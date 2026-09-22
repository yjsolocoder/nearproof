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
    JournalBatchReceiptAuditor,
    JournalBatchReceiptFrontier,
    _bit_map_history_journal_batch_receipt_frontier_mac,
    _bit_map_history_journal_batch_receipt_frontier_next_digest,
    _bit_map_history_journal_batch_receipt_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
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
RANGE_2 = seal_range([(COMMIT_2, BATCH_2)], KEY, checkpoint=CFRONTIER_1)
RANGE_FULL = seal_range([(COMMIT_1, BATCH_1), (COMMIT_2, BATCH_2)], KEY)


def range_for(body, key=KEY):
    return CommitRange(1, body, _commit_range_mac(key, body))


class CommitRangeFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        commit_range = CommitRange(1, RANGE_1.body, RANGE_1.mac)
        self.assertEqual(commit_range, RANGE_1)
        self.assertEqual(hash(commit_range), hash(RANGE_1))
        self.assertEqual(commit_range.version, 1)
        self.assertEqual(commit_range.body, RANGE_1.body)
        self.assertEqual(commit_range.mac, RANGE_1.mac)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RANGE_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RANGE_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RANGE_1, version=2)

    def test_body_contract(self):
        for bad in (1, "x", None, bytearray(RANGE_1.body)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RANGE_1, body=bad)
        for bad in (b"", b"junk", b"{}", b"[1,2]", b"[1,2,3,4]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RANGE_1, body=bad)

    def test_body_shape_contract(self):
        pair = [COMMIT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()]
        end = CFRONTIER_1.to_bytes().hex()
        # start must be empty or a canonical commit frontier.
        for bad_start in ("zz", COMMIT_1.to_bytes().hex(), end.upper()):
            body = json.dumps(
                [bad_start, [pair], end], separators=(",", ":")
            ).encode()
            with self.assertRaises(ValueError, msg=bad_start):
                dataclasses.replace(RANGE_1, body=body)
        # items must be a non-empty array of [receipt, batch] pairs.
        for bad_items in ("x", [], [[pair]], [["x"], [pair]], [[pair[0]]]):
            body = json.dumps(
                ["", bad_items, end], separators=(",", ":")
            ).encode()
            with self.assertRaises(ValueError, msg=repr(bad_items)):
                dataclasses.replace(RANGE_1, body=body)
        # pair members must be canonical receipt/batch encodings.
        for bad_pair in (
            [BATCH_1.to_bytes().hex(), BATCH_1.to_bytes().hex()],
            [COMMIT_1.to_bytes().hex(), COMMIT_1.to_bytes().hex()],
            [COMMIT_1.to_bytes().hex().upper(), BATCH_1.to_bytes().hex()],
        ):
            body = json.dumps(
                ["", [bad_pair], end], separators=(",", ":")
            ).encode()
            with self.assertRaises(ValueError, msg=repr(bad_pair)):
                dataclasses.replace(RANGE_1, body=body)
        # end must be a non-empty canonical commit frontier.
        for bad_end in ("", "zz", COMMIT_1.to_bytes().hex()):
            body = json.dumps(
                ["", [pair], bad_end], separators=(",", ":")
            ).encode()
            with self.assertRaises(ValueError, msg=repr(bad_end)):
                dataclasses.replace(RANGE_1, body=body)

    def test_body_must_be_canonical(self):
        body = RANGE_1.body.replace(b",", b", ")
        with self.assertRaises(ValueError):
            dataclasses.replace(RANGE_1, body=body)

    def test_mac_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RANGE_1, mac=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RANGE_1, mac=bad)


class CommitRangeEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,'
            b'"' + RANGE_1.body.hex().encode() + b'",'
            b'"' + RANGE_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(RANGE_1.to_bytes(), expected)

    def test_body_shape(self):
        self.assertEqual(
            json.loads(RANGE_1.body),
            [
                "",
                [[COMMIT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()]],
                CFRONTIER_1.to_bytes().hex(),
            ],
        )
        self.assertEqual(
            json.loads(RANGE_2.body),
            [
                CFRONTIER_1.to_bytes().hex(),
                [[COMMIT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()]],
                CFRONTIER_2.to_bytes().hex(),
            ],
        )
        self.assertEqual(
            json.loads(RANGE_FULL.body)[1],
            [
                [COMMIT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()],
                [COMMIT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()],
            ],
        )

    def test_mac_is_npBJ11_over_body(self):
        self.assertEqual(RANGE_1.mac, _commit_range_mac(KEY, RANGE_1.body))
        self.assertEqual(
            RANGE_1.mac,
            hmac.new(
                KEY, b"NPBJ11" + RANGE_1.body, hashlib.sha256
            ).digest(),
        )

    def test_round_trip(self):
        for commit_range in (RANGE_1, RANGE_2, RANGE_FULL):
            blob = commit_range.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(CommitRange.from_bytes(blob), commit_range)
            self.assertEqual(CommitRange.from_bytes(blob).to_bytes(), blob)

    def test_from_bytes_type_contract(self):
        blob = RANGE_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CommitRange.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"junk", b"{}", b"[1,2]", b"[1,2,3,4]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CommitRange.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RANGE_1.to_bytes()
        with self.assertRaises(ValueError):
            CommitRange.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            RANGE_1.mac.hex().encode(), RANGE_1.mac.hex().upper().encode()
        )
        with self.assertRaises(ValueError):
            CommitRange.from_bytes(upper)
        with self.assertRaises(ValueError):
            CommitRange.from_bytes(blob.replace(b"[1,", b"[2,", 1))

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(RANGE_1, mac=ZERO)
        parsed = CommitRange.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)


class SealRangeTest(unittest.TestCase):
    def test_seals_single_commit_from_empty_start(self):
        commit_range = seal_range([(COMMIT_1, BATCH_1)], KEY)
        self.assertEqual(commit_range, RANGE_1)
        self.assertEqual(json.loads(commit_range.body)[0], "")
        self.assertEqual(
            json.loads(commit_range.body)[2], CFRONTIER_1.to_bytes().hex()
        )

    def test_seals_contiguous_chain(self):
        commit_range = seal_range(
            [(COMMIT_1, BATCH_1), (COMMIT_2, BATCH_2)], KEY
        )
        self.assertEqual(commit_range, RANGE_FULL)
        self.assertEqual(
            json.loads(commit_range.body)[2], CFRONTIER_2.to_bytes().hex()
        )

    def test_seals_from_checkpoint_object_and_bytes(self):
        for checkpoint in (CFRONTIER_1, CFRONTIER_1.to_bytes()):
            commit_range = seal_range(
                [(COMMIT_2, BATCH_2)], KEY, checkpoint=checkpoint
            )
            self.assertEqual(commit_range, RANGE_2)
            self.assertEqual(
                json.loads(commit_range.body)[0],
                CFRONTIER_1.to_bytes().hex(),
            )

    def test_accepts_canonical_bytes_pairs(self):
        commit_range = seal_range(
            [
                (COMMIT_1.to_bytes(), BATCH_1.to_bytes()),
                [COMMIT_2, BATCH_2],
            ],
            KEY,
        )
        self.assertEqual(commit_range, RANGE_FULL)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range([(COMMIT_1, BATCH_1)], bad)
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, BATCH_1)], b"")

    def test_items_contract(self):
        for bad in (1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range(bad, KEY)
        # A string is iterable but its items are not (receipt, batch)
        # pairs.
        with self.assertRaises(ValueError):
            seal_range("x", KEY)
        with self.assertRaises(ValueError):
            seal_range([], KEY)
        for bad_item in (1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad_item)):
                seal_range([bad_item], KEY)
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, BATCH_1, COMMIT_1)], KEY)
        for bad_member in (1, None, [COMMIT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad_member)):
                seal_range([(bad_member, BATCH_1)], KEY)
            with self.assertRaises(TypeError, msg=repr(bad_member)):
                seal_range([(COMMIT_1, bad_member)], KEY)

    def test_malformed_pair_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_range([(b"junk", BATCH_1)], KEY)
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, b"junk")], KEY)

    def test_checkpoint_contract(self):
        for bad in (1, "x", [CFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_range([(COMMIT_2, BATCH_2)], KEY, checkpoint=bad)
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_2, BATCH_2)], KEY, checkpoint=b"junk")
        tampered = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_2, BATCH_2)], KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_2, BATCH_2)], OTHER_KEY, checkpoint=CFRONTIER_1
            )

    def test_broken_chain_rejected(self):
        # The second commit does not chain from an empty start.
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_2, BATCH_2)], KEY)
        # A gap inside the range.
        with self.assertRaises(ValueError):
            seal_range(
                [(COMMIT_1, BATCH_1), (COMMIT_2, BATCH_2)],
                KEY,
                checkpoint=CFRONTIER_1,
            )

    def test_tampered_commit_rejected(self):
        with self.assertRaises(ValueError):
            seal_range(
                [(dataclasses.replace(COMMIT_1, mac=ZERO), BATCH_1)], KEY
            )

    def test_wrong_batch_rejected(self):
        batch_full = seal_map_history_journal_receipt_batch(
            [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
        )
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, batch_full)], KEY)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            seal_range([(COMMIT_1, BATCH_1)], OTHER_KEY)


class AuditRangeTest(unittest.TestCase):
    def test_audits_single_commit_from_empty_start(self):
        final = audit_range(RANGE_1, KEY)
        self.assertEqual(final, CFRONTIER_1)

    def test_audits_contiguous_chain(self):
        final = audit_range(RANGE_FULL, KEY)
        self.assertEqual(final, CFRONTIER_2)
        self.assertEqual(final.sequence, 2)
        self.assertEqual(final.digest, CDIGEST_2)

    def test_audits_from_checkpoint(self):
        final = audit_range(RANGE_2, KEY)
        self.assertEqual(final, CFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        self.assertEqual(audit_range(RANGE_1.to_bytes(), KEY), CFRONTIER_1)
        self.assertEqual(audit_range(RANGE_2.to_bytes(), KEY), CFRONTIER_2)

    def test_third_party_replay_from_empty_start(self):
        # An independent verifier replays the carried pairs with a fresh
        # auditor and lands on the same frontier.
        auditor = JournalBatchReceiptAuditor(KEY)
        auditor.audit(COMMIT_1, BATCH_1)
        auditor.audit(COMMIT_2, BATCH_2)
        self.assertEqual(audit_range(RANGE_FULL, KEY), auditor.state)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_range(RANGE_1, bad)
        with self.assertRaises(ValueError):
            audit_range(RANGE_1, b"")

    def test_x_type_contract(self):
        for bad in (1, "x", None, [RANGE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_range(bad, KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_range(bad, KEY)

    def test_mac_verified(self):
        tampered = dataclasses.replace(RANGE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_range(tampered, KEY)
        with self.assertRaises(ValueError):
            audit_range(tampered.to_bytes(), KEY)
        with self.assertRaises(ValueError):
            audit_range(RANGE_1, OTHER_KEY)

    def test_tampered_body_rejected(self):
        # A body that does not match its carried MAC is rejected even
        # though the body itself is well-formed.
        body = RANGE_2.body  # starts from CFRONTIER_1, not empty
        tampered = CommitRange(1, body, RANGE_1.mac)
        with self.assertRaises(ValueError):
            audit_range(tampered, KEY)

    def test_end_mismatch_rejected(self):
        # Validly MAC'd body whose end does not match the replayed chain.
        pair = [COMMIT_1.to_bytes().hex(), BATCH_1.to_bytes().hex()]
        body = json.dumps(
            ["", [pair], CFRONTIER_2.to_bytes().hex()],
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_range(range_for(body), KEY)

    def test_broken_chain_rejected(self):
        # Validly MAC'd body whose chain does not start where claimed.
        pair = [COMMIT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()]
        body = json.dumps(
            ["", [pair], CFRONTIER_2.to_bytes().hex()],
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_range(range_for(body), KEY)

    def test_tampered_commit_rejected(self):
        bad_commit = dataclasses.replace(COMMIT_1, mac=ZERO)
        pair = [bad_commit.to_bytes().hex(), BATCH_1.to_bytes().hex()]
        body = json.dumps(
            ["", [pair], CFRONTIER_1.to_bytes().hex()],
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_range(range_for(body), KEY)

    def test_checkpoint_frontier_mac_verified(self):
        # The carried starting frontier's own MAC layer is rechecked.
        tampered_start = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        pair = [COMMIT_2.to_bytes().hex(), BATCH_2.to_bytes().hex()]
        body = json.dumps(
            [tampered_start.to_bytes().hex(), [pair], CFRONTIER_2.to_bytes().hex()],
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_range(range_for(body), KEY)


if __name__ == "__main__":
    unittest.main()
