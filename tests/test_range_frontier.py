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


class RangeFrontierFieldTest(unittest.TestCase):
    def test_version_contract(self):
        for bad in (1.0, True, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier(
                    bad, 0, CFRONTIER_1.to_bytes(), ZERO, ZERO
                )
        with self.assertRaises(ValueError):
            RangeFrontier(2, 0, CFRONTIER_1.to_bytes(), ZERO, ZERO)

    def test_sequence_contract(self):
        for bad in (1.0, True, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier(
                    1, bad, CFRONTIER_1.to_bytes(), ZERO, ZERO
                )
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeFrontier(
                    1, bad, CFRONTIER_1.to_bytes(), ZERO, ZERO
                )
        # Both boundaries construct.
        RangeFrontier(1, 0, CFRONTIER_1.to_bytes(), ZERO, ZERO)
        RangeFrontier(1, U64_MAX, CFRONTIER_1.to_bytes(), ZERO, ZERO)

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier(1, 1, bad, ZERO, ZERO)
        for bad in (b"", b"not-json", b"[]", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeFrontier(1, 1, bad, ZERO, ZERO)

    def test_digest_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier(1, 1, CFRONTIER_1.to_bytes(), bad, ZERO)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeFrontier(1, 1, CFRONTIER_1.to_bytes(), bad, ZERO)

    def test_mac_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier(1, 1, CFRONTIER_1.to_bytes(), ZERO, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeFrontier(1, 1, CFRONTIER_1.to_bytes(), ZERO, bad)

    def test_positional_construction_and_field_equality(self):
        left = RangeFrontier(1, 1, CFRONTIER_1.to_bytes(), ZERO, ZERO)
        right = RangeFrontier(1, 1, CFRONTIER_1.to_bytes(), ZERO, ZERO)
        self.assertEqual(left, right)
        self.assertEqual(
            dataclasses.replace(left, digest=b"\x01" * 32),
            left.__class__(
                1, 1, CFRONTIER_1.to_bytes(), b"\x01" * 32, ZERO
            ),
        )
        self.assertNotEqual(
            left, dataclasses.replace(left, sequence=2)
        )
        self.assertNotEqual(
            left,
            dataclasses.replace(left, end=CFRONTIER_2.to_bytes()),
        )

    def test_frozen_and_no_key_material(self):
        frontier = RFRONTIER_1
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frontier.mac = ZERO
        for field in dataclasses.fields(frontier):
            self.assertNotEqual(getattr(frontier, field.name), KEY)
        self.assertNotIn(KEY, frontier.to_bytes())


class RangeFrontierEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for frontier in (RFRONTIER_1, RFRONTIER_2):
            self.assertEqual(
                RangeFrontier.from_bytes(frontier.to_bytes()), frontier
            )

    def test_encoding_shape(self):
        document = json.loads(RFRONTIER_1.to_bytes().decode("utf-8"))
        self.assertEqual(
            document,
            [
                1,
                1,
                CFRONTIER_1.to_bytes().hex(),
                RDIGEST_1.hex(),
                RFRONTIER_1.mac.hex(),
            ],
        )
        self.assertEqual(
            RFRONTIER_1.to_bytes(),
            json.dumps(document, separators=(",", ":")).encode("utf-8"),
        )

    def test_from_bytes_type_contract(self):
        for bad in (
            1,
            None,
            "[]",
            bytearray(RFRONTIER_1.to_bytes()),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeFrontier.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (b"", b"not-json", b"{}", b"[1,2,3]", b"[1,2,3,4,5,6]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        document = json.loads(RFRONTIER_1.to_bytes().decode("utf-8"))
        for index, bad in ((0, "1"), (1, "1"), (2, 1), (3, 1), (4, 1)):
            tampered = list(document)
            tampered[index] = bad
            with self.assertRaises(TypeError, msg=repr(tampered)):
                RangeFrontier.from_bytes(
                    json.dumps(tampered, separators=(",", ":")).encode(
                        "utf-8"
                    )
                )

    def test_from_bytes_rejects_non_canonical(self):
        document = json.loads(RFRONTIER_1.to_bytes().decode("utf-8"))
        # Pretty-printed JSON parses but is not the canonical encoding.
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(json.dumps(document).encode("utf-8"))
        # Uppercase hex is not canonical.
        tampered = list(document)
        tampered[4] = tampered[4].upper()
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(
                json.dumps(tampered, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_rejects_bad_end_and_lengths(self):
        document = json.loads(RFRONTIER_1.to_bytes().decode("utf-8"))
        # A receipt-frontier encoding is not a commit-frontier encoding.
        tampered = list(document)
        tampered[2] = FRONTIER_1.to_bytes().hex()
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(
                json.dumps(tampered, separators=(",", ":")).encode("utf-8")
            )
        # A 31-byte digest is a value error.
        tampered = list(document)
        tampered[3] = (b"\x00" * 31).hex()
        with self.assertRaises(ValueError):
            RangeFrontier.from_bytes(
                json.dumps(tampered, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_does_not_verify_mac(self):
        # A zero-MAC frontier over a well-shaped (but itself un-MAC'd)
        # commit frontier parses fine; verifying any layer is the
        # RangeAuditor's job.
        unmacd_commit = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        forged = RangeFrontier(
            1, 1, unmacd_commit.to_bytes(), ZERO, ZERO
        )
        self.assertEqual(RangeFrontier.from_bytes(forged.to_bytes()), forged)


class RangeAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, None, "k", bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeAuditor(bad)
        with self.assertRaises(ValueError):
            RangeAuditor(b"")

    def test_empty_checkpoint(self):
        auditor = RangeAuditor(KEY)
        self.assertIsNone(auditor.frontier)

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        self.assertEqual(
            RangeAuditor(KEY, checkpoint=RFRONTIER_1).frontier,
            RFRONTIER_1,
        )
        self.assertEqual(
            RangeAuditor(KEY, checkpoint=RFRONTIER_1.to_bytes()).frontier,
            RFRONTIER_1,
        )

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", bytearray(RFRONTIER_1.to_bytes()), [], True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        for bad in (b"", b"not-json", b"[]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeAuditor(KEY, checkpoint=bad)

    def test_checkpoint_range_frontier_mac_verified(self):
        # The NPBJ13 layer of the range frontier is recomputed on load.
        tampered = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered.to_bytes())

    def test_checkpoint_end_commit_frontier_mac_verified(self):
        # The NPBJ9 layer of the end commit frontier is recomputed on load.
        bad_commit = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        tampered = range_frontier_for(
            1, bad_commit.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_receipt_frontier_mac_verified(self):
        # The NPBJ5 layer of the end receipt frontier is recomputed.
        bad_end = dataclasses.replace(
            BitMapHistoryJournalReceiptFrontier.from_bytes(CFRONTIER_1.end),
            mac=ZERO,
        )
        bad_commit = commit_frontier_for(1, bad_end.to_bytes(), CDIGEST_1)
        tampered = range_frontier_for(
            1, bad_commit.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            RangeAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_end_state_mac_verified(self):
        # The NPBJ1 layer of the end journal state is recomputed.
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
        # The NPBL1 layer of the end checkpoint table is recomputed.
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

    def test_frontier_is_frozen_read_only_export(self):
        auditor = RangeAuditor(KEY, checkpoint=RFRONTIER_1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            auditor.frontier.sequence = 9
        with self.assertRaises(AttributeError):
            auditor.frontier = RFRONTIER_2


class RangeAuditorAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_R1, RANGE_1), auditor)
        self.assertEqual(auditor.frontier, RFRONTIER_1)
        self.assertEqual(auditor.frontier.sequence, 1)
        self.assertEqual(auditor.frontier.end, CFRONTIER_1.to_bytes())
        self.assertEqual(auditor.frontier.digest, RDIGEST_1)
        self.assertEqual(auditor.frontier.mac, RFRONTIER_1.mac)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.frontier, RFRONTIER_2)

    def test_audit_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1.to_bytes(), RANGE_1.to_bytes())
        self.assertEqual(auditor.frontier, RFRONTIER_1)

    def test_restart_from_checkpoint(self):
        first = RangeAuditor(KEY)
        first.audit(RECEIPT_R1, RANGE_1)
        restarted = RangeAuditor(
            KEY, checkpoint=first.frontier.to_bytes()
        )
        restarted.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(restarted.frontier, RFRONTIER_2)

    def test_audit_type_contract(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, None, "x", [], bytearray(RECEIPT_R1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, RANGE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_R1, bad)
        self.assertIsNone(auditor.frontier)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (b"", b"not-json", b"[]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, RANGE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_R1, bad)
        self.assertIsNone(auditor.frontier)

    def test_empty_frontier_requires_empty_start(self):
        # A receipt continuing from a commit checkpoint cannot start the
        # chain from nothing.
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertIsNone(auditor.frontier)

    def test_continuation_requires_current_end(self):
        auditor = RangeAuditor(KEY, checkpoint=RFRONTIER_1)
        # An empty-start receipt does not equal the frontier end.
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_R1, RANGE_1)
        self.assertEqual(auditor.frontier, RFRONTIER_1)

    def test_failed_audit_changes_nothing_then_recovers(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertIsNone(auditor.frontier)
        auditor.audit(RECEIPT_R1, RANGE_1)
        tampered = dataclasses.replace(RECEIPT_RCP, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered, RANGE_FROM_CP)
        self.assertEqual(auditor.frontier, RFRONTIER_1)
        # The same receipt replayed at the same end is rejected by the
        # start gate (its start no longer equals the new end).
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_R1, RANGE_1)
        self.assertEqual(auditor.frontier, RFRONTIER_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.frontier, RFRONTIER_2)

    def test_tampered_receipt_mac_rejected(self):
        tampered = dataclasses.replace(RECEIPT_R1, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit(tampered, RANGE_1)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).audit(RECEIPT_R1, RANGE_1)

    def test_receipt_of_other_range_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit(RECEIPT_RCP, RANGE_1)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit(RECEIPT_R1, RANGE_FROM_CP)

    def test_range_reverified(self):
        # A receipt correctly attesting a range whose own MAC is broken
        # still fails: the audit re-runs audit_receipt.
        tampered_range = dataclasses.replace(RANGE_1, mac=ZERO)
        forged = range_receipt_for(
            tampered_range, b"", CFRONTIER_1.to_bytes()
        )
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(forged, tampered_range)
        self.assertIsNone(auditor.frontier)

    def test_digest_chain_formula(self):
        # The frontier digest is exactly NPBJ14 over d0, u64be(n) and R.
        self.assertEqual(
            RDIGEST_1,
            hashlib.sha256(
                b"NPBJ14"
                + ZERO
                + (1).to_bytes(8, byteorder="big")
                + RECEIPT_R1.to_bytes()
            ).digest(),
        )
        self.assertEqual(
            RFRONTIER_1.mac,
            _range_frontier_mac(KEY, RFRONTIER_1),
        )

    def test_sequence_overflow_rejected(self):
        # A checkpoint at u64 max cannot be continued: the receipt and
        # range verify but the advance would overflow u64.
        saturated = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        auditor = RangeAuditor(KEY, checkpoint=saturated)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.frontier, saturated)

    def test_old_interfaces_unchanged(self):
        # audit_receipt and CommitRangeAuditor keep their contracts and
        # share no state with the range-frontier path.
        self.assertEqual(audit_receipt(RECEIPT_R1, RANGE_1, KEY), CFRONTIER_1)
        commit_auditor = CommitRangeAuditor(KEY)
        commit_auditor.audit(RANGE_1)
        range_auditor = RangeAuditor(KEY)
        self.assertIsNone(range_auditor.frontier)
        range_auditor.audit(RECEIPT_R1, RANGE_1)
        self.assertEqual(commit_auditor.checkpoint, CFRONTIER_1)


class RangeAuditorConcurrencyTest(unittest.TestCase):
    def test_concurrent_audits_linearize_to_one_chain(self):
        auditor = RangeAuditor(KEY)
        errors = []

        def worker(receipt, record):
            try:
                auditor.audit(receipt, record)
            except ValueError:
                # Exactly one audit at each frontier position can win;
                # replays and losing starts are rejected.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        # Phase 1: five identical empty-start receipts race; one wins.
        first_barrier = threading.Barrier(5)

        def first_stage():
            first_barrier.wait()
            worker(RECEIPT_R1, RANGE_1)

        threads = [threading.Thread(target=first_stage) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(auditor.frontier, RFRONTIER_1)

        # Phase 2: five continuations race from the new checkpoint; one wins.
        second_barrier = threading.Barrier(5)

        def second_stage():
            second_barrier.wait()
            worker(RECEIPT_RCP, RANGE_FROM_CP)

        threads = [threading.Thread(target=second_stage) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.frontier, RFRONTIER_2)

    def test_losing_threads_leave_state_consistent(self):
        auditor = RangeAuditor(KEY)
        start_barrier = threading.Barrier(8)

        def race(receipt, record):
            start_barrier.wait()
            try:
                auditor.audit(receipt, record)
            except ValueError:
                pass

        threads = [
            threading.Thread(target=race, args=(RECEIPT_R1, RANGE_1))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Exactly one winner: sequence 1, end exactly at CFRONTIER_1 and
        # the canonical NPBJ14 digest.
        self.assertEqual(auditor.frontier, RFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
