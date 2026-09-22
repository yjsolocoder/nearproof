import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryEvidence,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalBundle,
    BitMapHistoryJournalReceipt,
    BitMapHistoryJournalState,
    BitMapUpdate,
    _BIT_MAP_HISTORY_JOURNAL_RECEIPT_PREFIX,
    _bit_map_history_evidence_mac,
    _bit_map_history_journal_bundle_mac,
    _bit_map_history_journal_mac,
    _bit_map_history_journal_receipt_content_bytes,
    _bit_map_history_journal_receipt_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _encode_payload,
    audit_map_history_journal_bundle,
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

# "" -> MAP_2 and MAP_2 -> MAP_3.
EVIDENCE_1 = seal_map_history([UPDATE_1, UPDATE_2], KEY)
EVIDENCE_2 = seal_map_history([UPDATE_3], KEY, checkpoint=MAP_2)
# "" -> MAP_1, a competing single segment from the empty journal.
EVIDENCE_SOLO = seal_map_history([UPDATE_1], KEY)


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
BUNDLE_SOLO = seal_map_history_journal_bundle([EVIDENCE_SOLO], KEY)


def receipt_for(start, bundle_digest, end, key=KEY):
    """A receipt with the NPBJ4 mac recomputed over the first four fields."""
    placeholder = BitMapHistoryJournalReceipt(
        1, start, bundle_digest, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_bit_map_history_journal_receipt_mac(key, placeholder),
    )


def digest_of(bundle):
    return hashlib.sha256(bundle.to_bytes()).digest()


RECEIPT_1 = receipt_for(b"", digest_of(BUNDLE_1), BUNDLE_1.end)
RECEIPT_FULL = receipt_for(b"", digest_of(BUNDLE_FULL), BUNDLE_FULL.end)
RECEIPT_2 = receipt_for(BUNDLE_2.start, digest_of(BUNDLE_2), BUNDLE_2.end)


class ReceiptShapeTest(unittest.TestCase):
    def test_positional_construction_and_field_equality(self):
        receipt = BitMapHistoryJournalReceipt(
            1, b"", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
        )
        self.assertEqual(
            receipt,
            BitMapHistoryJournalReceipt(
                1, b"", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
            ),
        )
        self.assertNotEqual(
            receipt,
            BitMapHistoryJournalReceipt(
                1, b"", digest_of(BUNDLE_1), BUNDLE_1.end, b"\x09" * 32
            ),
        )
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.bundle_digest, digest_of(BUNDLE_1))
        self.assertEqual(receipt.end, BUNDLE_1.end)
        self.assertEqual(receipt.mac, ZERO)

    def test_non_empty_start_accepted(self):
        receipt = BitMapHistoryJournalReceipt(
            1, STATE_1.to_bytes(), digest_of(BUNDLE_2), STATE_2.to_bytes(), ZERO
        )
        self.assertEqual(receipt.start, STATE_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_1.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_1.mac = b"\x09" * 32

    def test_hashable_by_fields(self):
        self.assertEqual(hash(RECEIPT_1), hash(receipt_for(b"", digest_of(BUNDLE_1), BUNDLE_1.end)))
        self.assertEqual(len({RECEIPT_1, receipt_for(b"", digest_of(BUNDLE_1), BUNDLE_1.end)}), 1)


class ReceiptTypeContractTest(unittest.TestCase):
    def assert_constructs(self, *fields):
        BitMapHistoryJournalReceipt(*fields)

    def test_version_wrong_type(self):
        for bad in ("1", 1.0, None, [1]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt(
                    bad, b"", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
                )

    def test_version_bool_is_type_error(self):
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceipt(
                True, b"", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
            )

    def test_start_wrong_type(self):
        for bad in ("", None, 1, bytearray()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt(
                    1, bad, digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
                )

    def test_digest_wrong_type(self):
        for bad in ("ab", None, 1, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt(1, b"", bad, BUNDLE_1.end, ZERO)

    def test_end_wrong_type(self):
        for bad in (None, 1, bytearray(BUNDLE_1.end)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt(
                    1, b"", digest_of(BUNDLE_1), bad, ZERO
                )

    def test_mac_wrong_type(self):
        for bad in ("ab", None, 1, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt(
                    1, b"", digest_of(BUNDLE_1), BUNDLE_1.end, bad
                )


class ReceiptValueContractTest(unittest.TestCase):
    def test_version_must_be_1(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                0, b"", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                2, b"", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
            )

    def test_start_must_be_empty_or_canonical_state(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                1, b"junk", digest_of(BUNDLE_1), BUNDLE_1.end, ZERO
            )

    def test_digest_must_be_exactly_32_bytes(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                1, b"", b"\x00" * 31, BUNDLE_1.end, ZERO
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                1, b"", b"\x00" * 33, BUNDLE_1.end, ZERO
            )

    def test_end_must_be_non_empty_canonical_state(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(1, b"", digest_of(BUNDLE_1), b"", ZERO)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                1, b"", digest_of(BUNDLE_1), b"junk", ZERO
            )

    def test_mac_must_be_exactly_32_bytes(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                1, b"", digest_of(BUNDLE_1), BUNDLE_1.end, b"\x00" * 31
            )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt(
                1, b"", digest_of(BUNDLE_1), BUNDLE_1.end, b"\x00" * 33
            )


class ReceiptEncodingTest(unittest.TestCase):
    def test_encoding_shape(self):
        encoded = RECEIPT_1.to_bytes()
        outer = json.loads(encoded)
        self.assertEqual(
            outer,
            [
                1,
                RECEIPT_1.start.hex(),
                RECEIPT_1.bundle_digest.hex(),
                RECEIPT_1.end.hex(),
                RECEIPT_1.mac.hex(),
            ],
        )
        # Compact: no whitespace.
        self.assertNotIn(b" ", encoded)
        self.assertNotIn(b"\n", encoded)
        # The field-order encoding is exactly [1,S,D,E,M] with the four
        # bytes fields lowercase hex.
        expected = _encode_payload(
            [
                1,
                RECEIPT_1.start.hex(),
                RECEIPT_1.bundle_digest.hex(),
                RECEIPT_1.end.hex(),
                RECEIPT_1.mac.hex(),
            ]
        )
        self.assertEqual(encoded, expected)

    def test_empty_start_encodes_as_empty_string(self):
        outer = json.loads(RECEIPT_1.to_bytes())
        self.assertEqual(outer[1], "")

    def test_non_empty_start_round_trips(self):
        encoded = RECEIPT_2.to_bytes()
        self.assertEqual(
            BitMapHistoryJournalReceipt.from_bytes(encoded), RECEIPT_2
        )

    def test_round_trip(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_FULL):
            self.assertEqual(
                BitMapHistoryJournalReceipt.from_bytes(receipt.to_bytes()),
                receipt,
            )

    def test_reserialization_is_byte_identical(self):
        encoded = RECEIPT_FULL.to_bytes()
        self.assertEqual(
            BitMapHistoryJournalReceipt.from_bytes(encoded).to_bytes(), encoded
        )

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("x", 1, None, [RECEIPT_1], bytearray(RECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalReceipt.from_bytes(bad)

    def test_from_bytes_rejects_malformed_json(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(b"junk")

    def test_from_bytes_rejects_empty_bytes(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(b"")

    def test_from_bytes_rejects_wrong_array_length(self):
        base = json.loads(RECEIPT_1.to_bytes())
        for length in (4, 6):
            wrong = json.dumps(base[:length]).encode()
            with self.assertRaises(ValueError, msg=length):
                BitMapHistoryJournalReceipt.from_bytes(wrong)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(b"{}")

    def test_from_bytes_rejects_non_integer_version(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[0] = "1"
        with self.assertRaises(TypeError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_version_other_than_1(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[0] = 2
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_non_string_hex_fields(self):
        base = json.loads(RECEIPT_1.to_bytes())
        for index in (1, 2, 3, 4):
            wrong = json.loads(RECEIPT_1.to_bytes())
            wrong[index] = 1
            with self.assertRaises(TypeError, msg=index):
                BitMapHistoryJournalReceipt.from_bytes(
                    json.dumps(wrong).encode()
                )

    def test_from_bytes_rejects_non_lowercase_hex(self):
        encoded = RECEIPT_1.to_bytes()
        # An uppercase hex letter survives JSON parsing but fails the
        # lowercase round-trip check.
        upper = encoded.replace(b"a", b"A", 1)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(upper)

    def test_from_bytes_rejects_odd_length_hex(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[2] = base[2][:-1]
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_wrong_digest_length(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[2] = (b"\x00" * 31).hex()
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_wrong_mac_length(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[4] = (b"\x00" * 31).hex()
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_empty_end(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[3] = ""
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_non_canonical_state_endpoints(self):
        base = json.loads(RECEIPT_1.to_bytes())
        base[3] = b"junk".hex()
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(
                json.dumps(base).encode()
            )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        encoded = RECEIPT_1.to_bytes()
        formatted = encoded.replace(b",", b", ", 1)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalReceipt.from_bytes(formatted)

    def test_from_bytes_does_not_verify_mac_or_digest(self):
        # A structurally valid record with a zero mac and a zero digest
        # still parses; verification lives in the auditor.
        record = BitMapHistoryJournalReceipt(
            1, b"", b"\x00" * 32, BUNDLE_1.end, b"\x00" * 32
        )
        self.assertEqual(
            BitMapHistoryJournalReceipt.from_bytes(record.to_bytes()), record
        )


class ReceiptCryptoConstructionTest(unittest.TestCase):
    def test_bundle_digest_is_sha256_of_canonical_bundle(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_1.to_bytes()).digest(),
        )

    def test_mac_is_hmac_npbj4_over_first_four_fields(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        content = _bit_map_history_journal_receipt_content_bytes(receipt)
        expected = hmac.new(
            KEY,
            _BIT_MAP_HISTORY_JOURNAL_RECEIPT_PREFIX + content,
            hashlib.sha256,
        ).digest()
        self.assertEqual(receipt.mac, expected)
        # The domain label is exactly NPBJ4 and is concatenated directly.
        self.assertEqual(_BIT_MAP_HISTORY_JOURNAL_RECEIPT_PREFIX, b"NPBJ4")

    def test_content_is_first_four_fields_c(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        # C is the same compact encoding used for [1,S,D,E]; the receipt MAC
        # must equal HMAC over NPBJ4 + that exact C.
        c = _encode_payload(
            [
                1,
                receipt.start.hex(),
                receipt.bundle_digest.hex(),
                receipt.end.hex(),
            ]
        )
        self.assertEqual(
            receipt.mac,
            hmac.new(KEY, b"NPBJ4" + c, hashlib.sha256).digest(),
        )


class AuditBundleReceiptSuccessTest(unittest.TestCase):
    def test_commits_from_empty_and_returns_receipt(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertIsInstance(receipt, BitMapHistoryJournalReceipt)
        self.assertEqual(auditor.state, STATE_1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, BUNDLE_1.end)
        self.assertEqual(receipt.bundle_digest, digest_of(BUNDLE_1))
        self.assertEqual(
            receipt.mac, _bit_map_history_journal_receipt_mac(KEY, receipt)
        )

    def test_commits_full_chain_in_one_step(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertEqual(auditor.state, STATE_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(receipt.end, STATE_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL.to_bytes())
        self.assertEqual(auditor.state, STATE_2)
        self.assertEqual(receipt.bundle_digest, digest_of(BUNDLE_FULL))

    def test_continues_from_non_empty_state(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        receipt = auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertEqual(auditor.state, STATE_2)
        self.assertEqual(receipt.start, STATE_1.to_bytes())
        self.assertEqual(receipt.end, STATE_2.to_bytes())
        self.assertEqual(receipt.bundle_digest, digest_of(BUNDLE_2))

    def test_mixes_with_single_segment_audit_and_bundle(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        receipt = auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertEqual(auditor.state, STATE_2)
        self.assertEqual(receipt.start, STATE_1.to_bytes())

        auditor2 = BitMapHistoryJournalAuditor(KEY)
        auditor2.audit_bundle_receipt(BUNDLE_1)
        auditor2.audit(EVIDENCE_2)
        self.assertEqual(auditor2.state, STATE_2)

    def test_receipt_verifies_standalone_after_commit(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertEqual(
            audit_map_history_journal_receipt(receipt, BUNDLE_FULL, KEY),
            STATE_2,
        )


class AuditBundleReceiptTypeContractTest(unittest.TestCase):
    def test_wrong_argument_type(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.state)

    def test_empty_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(b"")
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(b"junk")
        self.assertIsNone(auditor.state)


class AuditBundleReceiptFailureTest(unittest.TestCase):
    def test_bad_start_commits_nothing_and_mints_no_receipt(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_replay_commits_nothing(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertEqual(auditor.state, STATE_1)

    def test_tampered_bundle_mac_commits_nothing(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(tampered)
        self.assertIsNone(auditor.state)

    def test_wrong_key_commits_nothing(self):
        foreign_map = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        foreign_update = update_for(
            b"", foreign_map.to_bytes(), key=OTHER_KEY
        )
        foreign_evidence = seal_map_history([foreign_update], OTHER_KEY)
        foreign_bundle = seal_map_history_journal_bundle(
            [foreign_evidence], OTHER_KEY
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(foreign_bundle)
        self.assertIsNone(auditor.state)

    def test_failure_after_first_segment_is_atomic(self):
        # Two segments that cannot chain: nothing visible afterwards.
        placeholder = BitMapHistoryJournalBundle(
            1,
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_1.to_bytes()),
            STATE_2.to_bytes(),
            ZERO,
        )
        broken = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_bundle_mac(KEY, placeholder),
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(broken)
        self.assertIsNone(auditor.state)


class AuditBundleReceiptConcurrencyTest(unittest.TestCase):
    def test_competing_submissions_linearize_on_same_lock(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        receipts = []
        failures = []

        def run(bundle):
            try:
                receipts.append(auditor.audit_bundle_receipt(bundle))
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(BUNDLE_SOLO,)),
            threading.Thread(target=run, args=(BUNDLE_1,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        # The one surviving receipt is for the one committed bundle: the
        # bundle that did not fail is the one that committed.
        committed = (
            BUNDLE_1 if failures[0] == BUNDLE_SOLO else BUNDLE_SOLO
        )
        self.assertEqual(receipts[0].bundle_digest, digest_of(committed))
        self.assertIn(
            auditor.state.checkpoint,
            (MAP_1.to_bytes(), MAP_2.to_bytes()),
        )


class StandaloneReceiptAuditSuccessTest(unittest.TestCase):
    def test_verifies_objects_and_returns_end_state(self):
        final = audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, KEY)
        self.assertEqual(final, STATE_1)
        self.assertEqual(final.to_bytes(), BUNDLE_1.end)

    def test_verifies_full_chain(self):
        final = audit_map_history_journal_receipt(RECEIPT_FULL, BUNDLE_FULL, KEY)
        self.assertEqual(final, STATE_2)

    def test_verifies_non_empty_start(self):
        final = audit_map_history_journal_receipt(RECEIPT_2, BUNDLE_2, KEY)
        self.assertEqual(final, STATE_2)

    def test_accepts_canonical_bytes_for_receipt_and_bundle(self):
        final = audit_map_history_journal_receipt(
            RECEIPT_FULL.to_bytes(), BUNDLE_FULL.to_bytes(), KEY
        )
        self.assertEqual(final, STATE_2)

    def test_agrees_with_bundle_verifier(self):
        self.assertEqual(
            audit_map_history_journal_receipt(RECEIPT_FULL, BUNDLE_FULL, KEY),
            audit_map_history_journal_bundle(BUNDLE_FULL, KEY),
        )


class StandaloneReceiptAuditTypeContractTest(unittest.TestCase):
    def test_receipt_wrong_type(self):
        for bad in (1, None, "x", [RECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt(bad, BUNDLE_1, KEY)

    def test_bundle_wrong_type(self):
        for bad in (1, None, "x", [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt(RECEIPT_1, bad, KEY)

    def test_key_wrong_type(self):
        for bad in ("k", None, 1, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, bad)

    def test_empty_key_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, b"")

    def test_malformed_receipt_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(b"junk", BUNDLE_1, KEY)

    def test_malformed_bundle_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, b"junk", KEY)


class StandaloneReceiptAuditFailureTest(unittest.TestCase):
    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_1, OTHER_KEY)

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_1, KEY)

    def test_tampered_receipt_digest(self):
        tampered = dataclasses.replace(RECEIPT_1, bundle_digest=ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_1, KEY)

    def test_tampered_receipt_end(self):
        tampered = dataclasses.replace(RECEIPT_1, end=STATE_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_1, KEY)

    def test_tampered_empty_start_to_non_empty(self):
        tampered = dataclasses.replace(RECEIPT_1, start=STATE_1.to_bytes())
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_1, KEY)

    def test_tampered_non_empty_start_to_empty(self):
        tampered = dataclasses.replace(RECEIPT_2, start=b"")
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(tampered, BUNDLE_2, KEY)

    def test_receipt_does_not_belong_to_bundle(self):
        # A structurally valid receipt minted for BUNDLE_1 must not verify
        # against BUNDLE_FULL: digest, start (both empty there) and end
        # differ.
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, BUNDLE_FULL, KEY)

    def test_corrupted_bundle_bytes_rejected(self):
        raw = bytearray(BUNDLE_1.to_bytes())
        raw[-10] ^= 0x01
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(RECEIPT_1, bytes(raw), KEY)

    def test_receipt_mac_made_with_other_key(self):
        foreign = receipt_for(
            b"", digest_of(BUNDLE_1), BUNDLE_1.end, key=OTHER_KEY
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(foreign, BUNDLE_1, KEY)

    def test_bundle_with_broken_chain_rejected(self):
        # Receipt endpoints and digest match a bundle whose inner chain
        # cannot replay: the full bundle audit still runs and fails.
        placeholder = BitMapHistoryJournalBundle(
            1,
            b"",
            (EVIDENCE_2.to_bytes(),),
            STATE_2.to_bytes(),
            ZERO,
        )
        bundle = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_bundle_mac(KEY, placeholder),
        )
        receipt = receipt_for(b"", digest_of(bundle), bundle.end)
        with self.assertRaises(ValueError):
            audit_map_history_journal_receipt(receipt, bundle, KEY)


if __name__ == "__main__":
    unittest.main()
