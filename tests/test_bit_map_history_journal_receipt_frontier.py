import dataclasses
import hashlib
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
    _bit_map_history_journal_receipt_frontier_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    seal_map_history,
    seal_map_history_journal_bundle,
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


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    placeholder = BitMapHistoryJournalReceipt(
        1,
        bundle.start if start is None else start,
        hashlib.sha256(bundle.to_bytes()).digest() if digest is None else digest,
        bundle.end if end is None else end,
        ZERO,
    )
    from nearproof import _bit_map_history_journal_receipt_mac

    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_receipt_mac(key, placeholder)
    )


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)
RECEIPT_FULL = receipt_for(BUNDLE_FULL)


def frontier_for(sequence, end, digest, key=KEY):
    placeholder = BitMapHistoryJournalReceiptFrontier(1, sequence, end, digest, ZERO)
    return dataclasses.replace(
        placeholder,
        mac=_bit_map_history_journal_receipt_frontier_mac(key, placeholder),
    )


class FrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = BitMapHistoryJournalReceiptFrontier(
            1, 7, STATE_2.to_bytes(), HASH_1, HASH_2
        )
        self.assertEqual(
            frontier,
            BitMapHistoryJournalReceiptFrontier(
                1, 7, STATE_2.to_bytes(), HASH_1, HASH_2
            ),
        )
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 7)
        self.assertEqual(frontier.end, STATE_2.to_bytes())
        self.assertEqual(frontier.digest, HASH_1)
        self.assertEqual(frontier.mac, HASH_2)
        self.assertNotEqual(
            frontier,
            BitMapHistoryJournalReceiptFrontier(
                1, 8, STATE_2.to_bytes(), HASH_1, HASH_2
            ),
        )

    def test_frozen(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frontier.mac = ZERO

    def test_version_contract(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(frontier, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(frontier, version=2)

    def test_sequence_contract(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(frontier, sequence=bad)
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(frontier, sequence=bad)

    def test_end_contract(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        for bad in (1, "x", None, bytearray(STATE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(frontier, end=bad)
        # end must be non-empty canonical state bytes.
        for bad in (b"", b"junk", MAP_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(frontier, end=bad)
        # A different valid state is accepted as a value (no MAC check here).
        self.assertEqual(
            dataclasses.replace(frontier, end=STATE_2.to_bytes()).end,
            STATE_2.to_bytes(),
        )

    def test_digest_and_mac_contract(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        for field in ("digest", "mac"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(field, repr(bad))):
                    dataclasses.replace(frontier, **{field: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(field, repr(bad))):
                    dataclasses.replace(frontier, **{field: bad})


class FrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        expected = (
            b'[1,1,"'
            + STATE_1.to_bytes().hex().encode()
            + b'","'
            + HASH_1.hex().encode()
            + b'","'
            + frontier.mac.hex().encode()
            + b'"]'
        )
        self.assertEqual(frontier.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (
            frontier_for(0, STATE_1.to_bytes(), HASH_1),
            frontier_for(2**64 - 1, STATE_2.to_bytes(), HASH_2),
        ):
            blob = frontier.to_bytes()
            self.assertEqual(
                BitMapHistoryJournalReceiptFrontier.from_bytes(blob), frontier
            )
            self.assertEqual(
                BitMapHistoryJournalReceiptFrontier.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        for bad in (1, "x", None, bytearray(frontier.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"junk", b"{}", b"[1,2,3]", b"[1,2,3,4,5,6]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        frontier = frontier_for(1, STATE_1.to_bytes(), b"\xab" * 32)
        blob = frontier.to_bytes()
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptFrontier.from_bytes(
                blob.replace(
                    (b"\xab" * 32).hex().encode(),
                    (b"\xab" * 32).hex().upper().encode(),
                )
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_macs(self):
        # A bad frontier MAC and a bad MAC inside the carried end state both
        # parse cleanly: decoding enforces shape, never authenticity.
        tampered = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        tampered = dataclasses.replace(tampered, mac=ZERO)
        parsed = BitMapHistoryJournalReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)
        bad_end = dataclasses.replace(STATE_1, mac=ZERO)
        forged = frontier_for(1, bad_end.to_bytes(), HASH_1)
        self.assertEqual(
            BitMapHistoryJournalReceiptFrontier.from_bytes(forged.to_bytes()),
            forged,
        )


class ReceiptAuditorConstructorTest(unittest.TestCase):
    def test_empty_checkpoint(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(b"")

    def test_checkpoint_wrong_kind(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=1)
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint="x")

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=b"junk")

    def test_checkpoint_frontier_mac_must_match(self):
        checkpoint = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        bad = dataclasses.replace(checkpoint, mac=ZERO)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=bad)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=bad.to_bytes())

    def test_checkpoint_end_double_mac_must_match(self):
        checkpoint = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        # Re-sign the frontier over an end whose embedded state MAC is bad:
        # the NPBJ5 layer verifies but the carried end's NPBJ1/NPBL1 do not.
        bad_end = dataclasses.replace(STATE_1, mac=ZERO)
        forged = dataclasses.replace(checkpoint, end=bad_end.to_bytes())
        forged = dataclasses.replace(
            forged,
            mac=_bit_map_history_journal_receipt_frontier_mac(KEY, forged),
        )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=forged)

    def test_checkpoint_accepts_object_and_bytes(self):
        checkpoint = frontier_for(1, STATE_1.to_bytes(), HASH_1)
        self.assertEqual(
            BitMapHistoryJournalReceiptAuditor(KEY, checkpoint=checkpoint)
            .checkpoint,
            checkpoint,
        )
        self.assertEqual(
            BitMapHistoryJournalReceiptAuditor(
                KEY, checkpoint=checkpoint.to_bytes()
            ).checkpoint,
            checkpoint,
        )

    def test_checkpoint_is_read_only(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = None


class ReceiptAuditorAuditTest(unittest.TestCase):
    def test_first_commit_from_empty_frontier(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_1, BUNDLE_1), auditor)
        checkpoint = auditor.checkpoint
        self.assertIsInstance(
            checkpoint, BitMapHistoryJournalReceiptFrontier
        )
        self.assertEqual(checkpoint.version, 1)
        self.assertEqual(checkpoint.sequence, 1)
        self.assertEqual(checkpoint.end, STATE_1.to_bytes())
        self.assertEqual(
            checkpoint.digest,
            hashlib.sha256(
                b"NPBJ6"
                + ZERO
                + (1).to_bytes(8, byteorder="big")
                + RECEIPT_1.to_bytes()
            ).digest(),
        )
        self.assertEqual(
            checkpoint.mac,
            _bit_map_history_journal_receipt_frontier_mac(KEY, checkpoint),
        )

    def test_second_commit_chains_digest_and_sequence(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        first = auditor.checkpoint
        auditor.audit(RECEIPT_2, BUNDLE_2)
        second = auditor.checkpoint
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.end, STATE_2.to_bytes())
        self.assertEqual(
            second.digest,
            hashlib.sha256(
                b"NPBJ6"
                + first.digest
                + (2).to_bytes(8, byteorder="big")
                + RECEIPT_2.to_bytes()
            ).digest(),
        )
        self.assertEqual(
            second.mac,
            _bit_map_history_journal_receipt_frontier_mac(KEY, second),
        )

    def test_full_bundle_commits_in_one_step(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        checkpoint = auditor.checkpoint
        self.assertEqual(checkpoint.sequence, 1)
        self.assertEqual(checkpoint.end, STATE_2.to_bytes())
        self.assertEqual(
            checkpoint.digest,
            hashlib.sha256(
                b"NPBJ6"
                + ZERO
                + (1).to_bytes(8, byteorder="big")
                + RECEIPT_FULL.to_bytes()
            ).digest(),
        )

    def test_accepts_canonical_bytes(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint.end, STATE_1.to_bytes())

    def test_first_start_must_be_empty(self):
        # RECEIPT_2 starts at STATE_1; an empty auditor rejects it.
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_later_start_must_equal_frontier_end_byte_for_byte(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        # A replayed first receipt no longer chains onto the advanced end.
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        # The full bundle starts empty, not at STATE_1.
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        # The frontier is untouched after both failures.
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, STATE_1.to_bytes())

    def test_bad_receipt_mac_rejected(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_receipt_for_another_bundle_rejected(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_FULL)

    def test_bad_bundle_rejected(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, tampered)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = BitMapHistoryJournalReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_types(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_resume_from_checkpoint(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        checkpoint = auditor.checkpoint
        # Simulate a restart: export bytes, build a fresh auditor, continue.
        resumed = BitMapHistoryJournalReceiptAuditor(
            KEY, checkpoint=checkpoint.to_bytes()
        )
        resumed.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(resumed.checkpoint.sequence, 2)
        self.assertEqual(resumed.checkpoint.end, STATE_2.to_bytes())
        self.assertEqual(
            resumed.checkpoint.digest,
            hashlib.sha256(
                b"NPBJ6"
                + checkpoint.digest
                + (2).to_bytes(8, byteorder="big")
                + RECEIPT_2.to_bytes()
            ).digest(),
        )

    def test_competing_commits_linearize(self):
        auditor = BitMapHistoryJournalReceiptAuditor(KEY)
        committed = []
        rejected = []

        def run(receipt, bundle):
            try:
                auditor.audit(receipt, bundle)
                committed.append(receipt)
            except ValueError:
                rejected.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(RECEIPT_1, BUNDLE_1)
            ),
            threading.Thread(
                target=run, args=(RECEIPT_FULL, BUNDLE_FULL)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(committed), 1)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertIn(
            auditor.checkpoint.end,
            (STATE_1.to_bytes(), STATE_2.to_bytes()),
        )


if __name__ == "__main__":
    unittest.main()
