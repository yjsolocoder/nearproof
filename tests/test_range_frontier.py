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
    RangeAuditor,
    RangeFrontier,
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
    _range_frontier_mac,
    _range_frontier_next_digest,
    _range_receipt_mac,
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


class RangeFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = RangeFrontier(
            1, 1, CFRONTIER_1.to_bytes(), RDIGEST_1, RFRONTIER_1.mac
        )
        self.assertEqual(frontier, RFRONTIER_1)
        self.assertEqual(hash(frontier), hash(RFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, CFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, RDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RFRONTIER_1.mac = ZERO

    def test_no_key_material(self):
        for field in dataclasses.fields(RFRONTIER_1):
            self.assertNotEqual(getattr(RFRONTIER_1, field.name), KEY)
        self.assertNotIn(KEY, RFRONTIER_1.to_bytes())

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(RFRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, end=bad)
        # end must be the canonical non-empty JournalBatchReceiptFrontier
        # encoding: not empty, not junk, not a receipt frontier or a range
        # receipt.
        for bad in (
            b"",
            b"junk",
            FRONTIER_1.to_bytes(),
            RECEIPT_R1.to_bytes(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RFRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(RFRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(RFRONTIER_1, **{name: bad})


class RangeFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + RDIGEST_1.hex().encode() + b'",'
            b'"' + RFRONTIER_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(RFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (RFRONTIER_1, RFRONTIER_2):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(RangeFrontier.from_bytes(blob), frontier)
            self.assertEqual(
                RangeFrontier.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = RFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeFrontier.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            RFRONTIER_1.mac.hex().encode(),
            RFRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(blob.replace(b"[1,", b"[2,", 1))

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        parsed = RangeFrontier.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)


class RangeAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeAuditor(bad)
        with self.assertRaises(ValueError):
            RangeAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(RangeAuditor(KEY).state)
        self.assertIsNone(RangeAuditor(KEY, checkpoint=None).state)

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (RFRONTIER_1, RFRONTIER_1.to_bytes()):
            auditor = RangeAuditor(KEY, checkpoint=checkpoint)
            self.assertEqual(auditor.state, RFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [RFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_range_frontier_mac_verified(self):
        tampered = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered.to_bytes())

    def test_checkpoint_end_commit_frontier_mac_verified(self):
        # The NPBJ9 layer of the end commit frontier is recomputed on load.
        bad_end = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        tampered = range_frontier_for(
            1, bad_end.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_receipt_frontier_mac_verified(self):
        # The NPBJ5 layer of the end receipt frontier is recomputed.
        bad_end = dataclasses.replace(
            BitMapHistoryJournalReceiptFrontier.from_bytes(CFRONTIER_1.end),
            mac=ZERO,
        )
        tampered_commit = commit_frontier_for(
            1, bad_end.to_bytes(), CDIGEST_1
        )
        tampered = range_frontier_for(
            1, tampered_commit.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_state_mac_verified(self):
        # The NPBJ1 layer of the end journal state is recomputed on load.
        end_frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
            CFRONTIER_1.end
        )
        bad_state = dataclasses.replace(
            BitMapHistoryJournalState.from_bytes(end_frontier.end), mac=ZERO
        )
        bad_frontier = dataclasses.replace(
            end_frontier, end=bad_state.to_bytes()
        )
        bad_frontier = dataclasses.replace(
            bad_frontier,
            mac=_bit_map_history_journal_receipt_frontier_mac(
                KEY, bad_frontier
            ),
        )
        bad_commit = commit_frontier_for(
            1, bad_frontier.to_bytes(), CDIGEST_1
        )
        tampered = range_frontier_for(
            1, bad_commit.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_table_mac_verified(self):
        # The NPBL1 layer of the embedded checkpoint table is recomputed.
        end_frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
            CFRONTIER_1.end
        )
        state = BitMapHistoryJournalState.from_bytes(end_frontier.end)
        bad_map = dataclasses.replace(
            BitMap.from_bytes(state.checkpoint), mac=ZERO
        )
        bad_state = dataclasses.replace(
            state, checkpoint=bad_map.to_bytes()
        )
        bad_state = dataclasses.replace(
            bad_state, mac=_bit_map_history_journal_mac(KEY, bad_state)
        )
        bad_frontier = dataclasses.replace(
            end_frontier, end=bad_state.to_bytes()
        )
        bad_frontier = dataclasses.replace(
            bad_frontier,
            mac=_bit_map_history_journal_receipt_frontier_mac(
                KEY, bad_frontier
            ),
        )
        bad_commit = commit_frontier_for(
            1, bad_frontier.to_bytes(), CDIGEST_1
        )
        tampered = range_frontier_for(
            1, bad_commit.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY, checkpoint=RFRONTIER_1)

    def test_state_is_read_only(self):
        with self.assertRaises(AttributeError):
            RangeAuditor(KEY).state = RFRONTIER_1


class RangeAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_R1, RANGE_1), auditor)
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, CFRONTIER_1.to_bytes())
        self.assertEqual(auditor.state.digest, RDIGEST_1)
        self.assertEqual(
            auditor.state.mac, _range_frontier_mac(KEY, auditor.state)
        )

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.end, CFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state.digest, RDIGEST_2)

    def test_digest_chain_step(self):
        # d' = SHA256(b"NPBJ14" + d + u64be(n) + R), direct concatenation.
        manual = hashlib.sha256(
            b"NPBJ14"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_R1.to_bytes()
        ).digest()
        self.assertEqual(RDIGEST_1, manual)
        manual_two = hashlib.sha256(
            b"NPBJ14"
            + RDIGEST_1
            + (2).to_bytes(8, "big")
            + RECEIPT_RCP.to_bytes()
        ).digest()
        self.assertEqual(RDIGEST_2, manual_two)

    def test_mac_prefix_is_npbj13(self):
        # HMAC-SHA256(key, b"NPBJ13" + C) with no separator or length
        # prefix, C the field-order compact JSON of the first four fields.
        content = json.dumps(
            [
                1,
                1,
                CFRONTIER_1.to_bytes().hex(),
                RDIGEST_1.hex(),
            ],
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            RFRONTIER_1.mac,
            hmac.new(KEY, b"NPBJ13" + content, hashlib.sha256).digest(),
        )

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1.to_bytes(), RANGE_1.to_bytes())
        self.assertEqual(auditor.state, RFRONTIER_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        blob = auditor.state.to_bytes()
        restored = RangeAuditor(KEY, checkpoint=blob)
        restored.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(restored.state, RFRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertIsNone(auditor.state)

    def test_replayed_receipt_rejected(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_R1, RANGE_1)
        self.assertIs(auditor.state, before)

    def test_gap_rejected(self):
        # After R1, skipping straight to a receipt attesting a different
        # range with a non-matching start is rejected.
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        with self.assertRaises(ValueError):
            auditor.audit(
                range_receipt_for(
                    RANGE_FROM_CP, b"", CFRONTIER_2.to_bytes()
                ),
                RANGE_FROM_CP,
            )
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_tampered_receipt_rejected(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_R1, mac=ZERO), RANGE_1
            )
        self.assertIsNone(auditor.state)

    def test_tampered_range_rejected(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                RECEIPT_R1, dataclasses.replace(RANGE_1, mac=ZERO)
            )
        self.assertIsNone(auditor.state)

    def test_wrong_argument_type(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_R1], (RECEIPT_R1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, RANGE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_R1, bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, RANGE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_R1, bad)
        self.assertIsNone(auditor.state)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).audit(RECEIPT_R1, RANGE_1)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_R1, mac=ZERO), RANGE_1
            )
        self.assertIsNone(auditor.state)
        auditor.audit(RECEIPT_R1, RANGE_1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_reuses_audit_receipt_semantics(self):
        # A receipt that fails audit_receipt (digest mismatch against the
        # presented range) can never advance the auditor.
        forged = range_receipt_for(
            RANGE_FROM_CP, b"", CFRONTIER_1.to_bytes()
        )
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(forged, RANGE_1)
        self.assertIsNone(auditor.state)

    def test_sequence_overflow(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        auditor = RangeAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertIs(auditor.state, before)

    def test_competing_audits_linearize(self):
        auditor = RangeAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(5)

        def run():
            barrier.wait()
            try:
                auditor.audit(RECEIPT_R1, RANGE_1)
                successes.append(1)
            except ValueError:
                failures.append(1)

        threads = [threading.Thread(target=run) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 4)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_old_interfaces_unchanged(self):
        # The receipt/range layer keeps its contract and shares no state
        # with the range-frontier ledger.
        from nearproof import audit_receipt

        self.assertEqual(
            audit_receipt(RECEIPT_R1, RANGE_1, KEY), CFRONTIER_1
        )
        commit_auditor = CommitRangeAuditor(KEY)
        receipt = commit_auditor.commit(RANGE_1)
        self.assertEqual(receipt, RECEIPT_R1)
        self.assertEqual(commit_auditor.checkpoint, CFRONTIER_1)
        # The range ledger is a separate, still-empty object.
        self.assertIsNone(RangeAuditor(KEY).state)


if __name__ == "__main__":
    unittest.main()
