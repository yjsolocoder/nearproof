import dataclasses
import hashlib
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalBundle,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalState,
    BitMapUpdate,
    _bit_map_history_journal_bundle_mac,
    _bit_map_history_journal_mac,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    audit_map_history_journal_receipt,
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

# "" -> MAP_2 and MAP_2 -> MAP_3.
EVIDENCE_1 = seal_map_history([UPDATE_1, UPDATE_2], KEY)
EVIDENCE_2 = seal_map_history([UPDATE_3], KEY, checkpoint=MAP_2)


def audited_state(*evidences, key=KEY):
    auditor = BitMapHistoryJournalAuditor(key)
    for evidence in evidences:
        auditor.audit(evidence)
    return auditor.state


STATE_1 = audited_state(EVIDENCE_1)
STATE_2 = audited_state(EVIDENCE_1, EVIDENCE_2)

# "" -> STATE_1, STATE_1 -> STATE_2 and "" -> STATE_2.
BUNDLE_1 = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
BUNDLE_2 = seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=STATE_1)
BUNDLE_FULL = seal_map_history_journal_bundle([EVIDENCE_1, EVIDENCE_2], KEY)


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPBJ4 mac recomputed over the
    first four fields; ``start``/``end``/``digest`` default to the honest
    values."""
    placeholder = BitMapHistoryJournalReceipt(
        1,
        bundle.start if start is None else start,
        hashlib.sha256(bundle.to_bytes()).digest() if digest is None else digest,
        bundle.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_receipt_mac(key, placeholder)
    )


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)
RECEIPT_FULL = receipt_for(BUNDLE_FULL)


class ReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = BitMapHistoryJournalReceipt(
            1, b"", RECEIPT_1.bundle_digest, STATE_1.to_bytes(), RECEIPT_1.mac
        )
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, STATE_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (1, "x", None, bytearray(b"")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # b"" and canonical state bytes are both accepted.
        self.assertEqual(
            dataclasses.replace(RECEIPT_1, start=b"").start, b""
        )
        self.assertEqual(
            dataclasses.replace(RECEIPT_1, start=STATE_1.to_bytes()).start,
            STATE_1.to_bytes(),
        )
        for bad in (b"junk", MAP_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)

    def test_bundle_digest_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)

    def test_end_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)
        # Unlike start, end must be non-empty canonical state bytes.
        for bad in (b"", b"junk", MAP_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)

    def test_mac_contract(self):
        for bad in (1, "x", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, mac=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, mac=bad)


class ReceiptEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'"' + RECEIPT_1.bundle_digest.hex().encode() + b'",'
            b'"' + STATE_1.to_bytes().hex().encode() + b'",'
            b'"' + RECEIPT_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(RECEIPT_1.to_bytes(), expected)

    def test_round_trip(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_FULL):
            blob = receipt.to_bytes()
            self.assertEqual(
                BitMapHistoryJournalReceipt.from_bytes(blob), receipt
            )
            self.assertEqual(
                BitMapHistoryJournalReceipt.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        for bad in (1, "x", None, bytearray(RECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"junk", b"{}", b"[1,2,3]", b"[1,2,3,4,5,6]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalReceipt.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RECEIPT_1.to_bytes()
        # Whitespace, uppercase hex and a wrong version all fail the
        # canonical re-encoding comparison or the field contract.
        spaced = blob.replace(b",", b", ")
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(spaced)
        upper = blob.replace(
            RECEIPT_1.mac.hex().encode(),
            RECEIPT_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(upper)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        parsed = BitMapHistoryJournalReceipt.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)


class AuditBundleReceiptTest(unittest.TestCase):
    def test_commit_returns_receipt(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertIsInstance(receipt, BitMapHistoryJournalReceipt)
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, STATE_1.to_bytes())
        self.assertEqual(auditor.state, STATE_1)

    def test_receipt_mac_verifies(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertEqual(
            receipt.mac,
            _bit_map_history_journal_receipt_mac(KEY, receipt),
        )
        self.assertEqual(auditor.state, STATE_2)

    def test_accepts_canonical_bytes(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1.to_bytes())
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(auditor.state, STATE_1)

    def test_continues_from_non_empty_state(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        receipt = auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertEqual(receipt, RECEIPT_2)
        self.assertEqual(receipt.start, STATE_1.to_bytes())
        self.assertEqual(receipt.end, STATE_2.to_bytes())
        self.assertEqual(auditor.state, STATE_2)

    def test_failure_changes_nothing_and_yields_no_receipt(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        before = auditor.state
        # A replayed bundle no longer chains onto the advanced state.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1)
        # A tampered bundle mac is rejected too.
        tampered = dataclasses.replace(BUNDLE_2, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(tampered)
        self.assertEqual(auditor.state, before)

    def test_wrong_argument_type(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.state)

    def test_audit_bundle_interface_unchanged(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_1), auditor)
        self.assertEqual(auditor.state, STATE_1)

    def test_receipt_verifies_against_bundle(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        final = audit_map_history_journal_receipt(receipt, BUNDLE_FULL, KEY)
        self.assertEqual(final, STATE_2)

    def test_competing_commits_linearize(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipts = []
        failures = []

        def run(bundle):
            try:
                receipts.append(auditor.audit_bundle_receipt(bundle))
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(BUNDLE_1,)),
            threading.Thread(target=run, args=(BUNDLE_FULL,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        # The one committed bundle's receipt attests the committed chain.
        receipt = receipts[0]
        self.assertEqual(receipt.end, auditor.state.to_bytes())


class AuditReceiptTest(unittest.TestCase):
    def test_verifies_and_returns_final_state(self):
        self.assertEqual(
            audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, KEY),
            STATE_1,
        )
        self.assertEqual(
            audit_map_history_journal_receipt(RECEIPT_FULL, BUNDLE_FULL, KEY),
            STATE_2,
        )
        self.assertEqual(
            audit_map_history_journal_receipt(RECEIPT_2, BUNDLE_2, KEY),
            STATE_2,
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_map_history_journal_receipt(
                RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), KEY
            ),
            STATE_1,
        )

    def test_type_contract(self):
        for bad in (1, "x", None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt(bad, BUNDLE_1, KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt(RECEIPT_1, bad, KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, bad)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, b"")

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_1, KEY)

    def test_wrong_key(self):
        foreign_evidence = seal_map_history(
            [update_for(b"", map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
                        .to_bytes(), key=OTHER_KEY)],
            OTHER_KEY,
        )
        foreign_bundle = seal_map_history_journal_bundle(
            [foreign_evidence], OTHER_KEY
        )
        foreign_receipt = receipt_for(foreign_bundle, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(
                foreign_receipt, foreign_bundle, KEY
            )

    def test_bundle_digest_mismatch(self):
        # An honest receipt for BUNDLE_1 does not attest BUNDLE_FULL.
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_FULL, KEY)

    def test_tampered_bundle_digest_field(self):
        tampered = receipt_for(BUNDLE_1, digest=ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_1, KEY)

    def test_endpoint_mismatch(self):
        # Receipt mac and bundle digest both verify, but the receipt's
        # endpoints do not match the bundle's.
        mismatched = receipt_for(
            BUNDLE_1, start=STATE_1.to_bytes(), end=STATE_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(mismatched, BUNDLE_1, KEY)

    def test_invalid_bundle_still_rejected(self):
        # Receipt honestly attests a bundle whose replayed chain does not
        # reach its claimed end.
        placeholder = BitMapHistoryJournalBundle(
            1,
            BUNDLE_1.start,
            BUNDLE_1.evidences,
            STATE_2.to_bytes(),
            ZERO,
        )
        bad_bundle = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_bundle_mac(KEY, placeholder),
        )
        receipt = receipt_for(bad_bundle)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(receipt, bad_bundle, KEY)


if __name__ == "__main__":
    unittest.main()
