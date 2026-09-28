import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListBundleReceiptAuditor,
    EvidenceRevocationListBundleReceiptBatch,
    EvidenceRevocationListBundleReceiptFrontier,
    EvidenceRevocationListState,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_PREFIX,
    _encode_payload,
    _evidence_revocation_list_bundle_receipt_batch_payload,
    _evidence_revocation_list_bundle_receipt_batch_signature,
    audit_evidence_revocation_list_bundle_receipt_batch,
    seal_evidence_revocation_list_bundle,
    seal_evidence_revocation_list_bundle_receipt_batch,
)
from test_evidence_revocation_list_bundle import (
    KEY,
    OTHER_KEY,
    snapshot,
)
from test_evidence_revocation_list_bundle_receipt import receipt_for
from test_evidence_revocation_list_bundle_receipt_frontier import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    FRONTIER_1,
    FRONTIER_2,
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
    STATE_1,
    STATE_2,
    U64_MAX,
    ZERO,
    frontier_for_sequence,
)

CHAIN = ((RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2))
BATCH = seal_evidence_revocation_list_bundle_receipt_batch(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
)
# A one-receipt batch sealed from the empty ledger and one continuing it.
BATCH_1 = seal_evidence_revocation_list_bundle_receipt_batch(
    [(RECEIPT_1, BUNDLE_1)], KEY
)
BATCH_2 = seal_evidence_revocation_list_bundle_receipt_batch(
    [(RECEIPT_2, BUNDLE_2)], KEY, start=FRONTIER_1
)


def reencode(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def batch_for(items, key=KEY, *, start=b"", end=None, signature=None):
    """A batch over ``items`` with the NPEBR4 signature recomputed over the
    first four fields; ``end``/``signature`` default to the honest values."""
    if end is None:
        end = FRONTIER_2.to_bytes() if len(items) == 2 else FRONTIER_1.to_bytes()
    placeholder = EvidenceRevocationListBundleReceiptBatch(
        1,
        start,
        tuple(
            (receipt.to_bytes(), bundle.to_bytes())
            for receipt, bundle in items
        ),
        end,
        ZERO,
    )
    if signature is None:
        signature = _evidence_revocation_list_bundle_receipt_batch_signature(
            key, placeholder
        )
    return dataclasses.replace(placeholder, signature=signature)


class BatchFieldContractTest(unittest.TestCase):
    def setUp(self):
        self.items = (
            (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
            (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
        )

    def make(self, **overrides):
        values = {
            "version": 1,
            "start": b"",
            "items": self.items,
            "end": FRONTIER_2.to_bytes(),
            "signature": b"\x09" * 32,
        }
        values.update(overrides)
        return EvidenceRevocationListBundleReceiptBatch(
            values["version"],
            values["start"],
            values["items"],
            values["end"],
            values["signature"],
        )

    def test_is_frozen_and_equal_by_fields(self):
        second = EvidenceRevocationListBundleReceiptBatch(
            1,
            bytes(BATCH.start),
            tuple(
                (bytes(r), bytes(b)) for r, b in BATCH.items
            ),
            bytes(BATCH.end),
            bytes(BATCH.signature),
        )
        self.assertEqual(BATCH, second)
        self.assertEqual(hash(BATCH), hash(second))
        self.assertFalse(hasattr(BATCH, "key"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BATCH.end = b""

    def test_positional_field_order(self):
        record = self.make()
        self.assertEqual(
            (
                record.version,
                record.start,
                record.items,
                record.end,
                record.signature,
            ),
            (1, b"", self.items, FRONTIER_2.to_bytes(), b"\x09" * 32),
        )

    def test_version_shape_vs_value(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError):
                self.make(version=bad)
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError):
                self.make(version=bad)

    def test_start_empty_or_canonical_frontier_bytes(self):
        for bad in ("", [], None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(start=bad)
        for bad in (b"not-json", b"[]", RECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(start=bad)
        self.make(start=b"")
        self.make(start=FRONTIER_1.to_bytes())

    def test_items_shape(self):
        for bad in ([], None, 7, "x", bytearray()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(items=bad)
        with self.assertRaises(ValueError):
            self.make(items=())
        # Entries must be two-element tuples.
        with self.assertRaises(TypeError):
            self.make(items=(self.items[0][0],))
        with self.assertRaises(TypeError):
            self.make(items=([RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()],))
        with self.assertRaises(ValueError):
            self.make(items=((RECEIPT_1.to_bytes(),),))
        with self.assertRaises(ValueError):
            self.make(
                items=(
                    (
                        RECEIPT_1.to_bytes(),
                        BUNDLE_1.to_bytes(),
                        b"",
                    ),
                )
            )

    def test_items_member_types_and_canonical_encodings(self):
        good_receipt, good_bundle = self.items[0]
        for bad in ("", None, 7, bytearray(good_receipt)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(items=((bad, good_bundle),))
        for bad in ("", None, 7, bytearray(good_bundle)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(items=((good_receipt, bad),))
        # The right kind of bytes but a non-canonical/foreign encoding.
        with self.assertRaises(ValueError):
            self.make(items=((BUNDLE_1.to_bytes(), good_bundle),))
        with self.assertRaises(ValueError):
            self.make(items=((good_receipt, RECEIPT_1.to_bytes()),))
        with self.assertRaises(ValueError):
            self.make(items=((good_receipt + b" ", good_bundle),))

    def test_end_canonical_nonempty_frontier_bytes(self):
        for bad in ("", None, 7, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(end=bad)
        for bad in (b"", b"junk", b"[]", RECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(end=bad)

    def test_signature_exactly_32_bytes(self):
        for bad in ("ab" * 32, None, 7, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(signature=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(signature=bad)


class BatchEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        obj = json.loads(BATCH.to_bytes())
        self.assertEqual(
            list(obj), ["version", "start", "items", "end", "signature"]
        )
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["start"], "")
        self.assertEqual(
            obj["items"],
            [
                [RECEIPT_1.to_bytes().hex(), BUNDLE_1.to_bytes().hex()],
                [RECEIPT_2.to_bytes().hex(), BUNDLE_2.to_bytes().hex()],
            ],
        )
        self.assertEqual(obj["end"], BATCH.end.hex())
        self.assertEqual(obj["signature"], BATCH.signature.hex())
        self.assertNotIn(b" ", BATCH.to_bytes())

    def test_non_empty_start_encodes_as_lowercase_hex(self):
        self.assertEqual(BATCH_2.start, FRONTIER_1.to_bytes())
        obj = json.loads(BATCH_2.to_bytes())
        self.assertEqual(obj["start"], FRONTIER_1.to_bytes().hex())
        self.assertEqual(obj["end"], FRONTIER_2.to_bytes().hex())

    def test_round_trip(self):
        blob = BATCH.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(
            EvidenceRevocationListBundleReceiptBatch.from_bytes(blob), BATCH
        )
        self.assertEqual(
            EvidenceRevocationListBundleReceiptBatch.from_bytes(blob).to_bytes(),
            blob,
        )

    def test_data_must_be_bytes(self):
        blob = BATCH.to_bytes()
        for bad in (blob.decode(), None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(bad)

    def test_malformed_and_wrong_shape_rejected(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3,4,5]",
            reencode([1, "", [], "", ""]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(bad)

    def test_missing_extra_reordered_and_duplicate_keys_rejected(self):
        encoding = BATCH.to_bytes()
        obj = json.loads(encoding)
        del obj["end"]
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        obj["extra"] = 0
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        reordered = {name: obj[name] for name in reversed(list(obj))}
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(
                reencode(reordered)
            )
        duplicated = encoding.replace(
            b'"version":1', b'"version":1,"version":1'
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(duplicated)

    def test_items_array_shape_rejected(self):
        encoding = BATCH.to_bytes()
        obj = json.loads(encoding)
        obj["items"] = []
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        obj["items"] = {}
        # A nested JSON object trips the ordered-field-key decoder while
        # the document is parsed, which surfaces as a value error.
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        obj["items"][0] = [obj["items"][0][0]]
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptBatch.from_bytes(reencode(obj))

    def test_non_canonical_spellings_rejected(self):
        encoding = BATCH.to_bytes()
        for bad in (
            b" " + encoding,
            encoding + b" ",
            encoding.replace(b',"', b', "'),
            encoding.replace(
                BATCH.signature.hex().encode(),
                BATCH.signature.hex().upper().encode(),
            ),
            encoding.replace(b'{"version":1', b'{"version":2', 1),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(bad)

    def test_from_bytes_does_not_verify_signature(self):
        tampered = dataclasses.replace(BATCH, signature=ZERO)
        parsed = EvidenceRevocationListBundleReceiptBatch.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_signature_scheme_is_npebr4_over_unsigned_encoding(self):
        unsigned = _encode_payload(
            _evidence_revocation_list_bundle_receipt_batch_payload(BATCH)
        )
        expected = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_PREFIX + unsigned,
            hashlib.sha256,
        ).digest()
        self.assertEqual(BATCH.signature, expected)
        self.assertEqual(
            BATCH.signature,
            _evidence_revocation_list_bundle_receipt_batch_signature(KEY, BATCH),
        )
        self.assertEqual(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_PREFIX, b"NPEBR4"
        )
        # The label distinguishes the domain from the frontier MAC and the
        # receipt MAC even over the same unsigned body bytes.
        self.assertNotEqual(
            BATCH.signature,
            hmac.new(KEY, b"NPEBR3" + unsigned, hashlib.sha256).digest(),
        )
        self.assertNotEqual(
            BATCH.signature,
            hmac.new(KEY, b"NPEBR1" + unsigned, hashlib.sha256).digest(),
        )


class SealBatchTest(unittest.TestCase):
    def test_seals_empty_start_chain(self):
        batch = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
        )
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, b"")
        self.assertEqual(
            batch.items,
            (
                (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
                (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
            ),
        )
        self.assertEqual(batch.end, FRONTIER_2.to_bytes())
        self.assertEqual(
            batch.signature,
            _evidence_revocation_list_bundle_receipt_batch_signature(KEY, batch),
        )

    def test_accepts_objects_and_canonical_bytes(self):
        from_objects = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_1, BUNDLE_1)], KEY
        )
        from_bytes = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())], KEY
        )
        self.assertEqual(from_objects, from_bytes)
        self.assertEqual(from_objects, BATCH_1)

    def test_seals_continuation_from_frontier(self):
        batch = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_2, BUNDLE_2)], KEY, start=FRONTIER_1
        )
        self.assertEqual(batch.start, FRONTIER_1.to_bytes())
        self.assertEqual(batch.end, FRONTIER_2.to_bytes())
        # A canonical-bytes start works too.
        again = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_2, BUNDLE_2)], KEY, start=FRONTIER_1.to_bytes()
        )
        self.assertEqual(again, batch)

    def test_replay_end_matches_per_receipt_audit(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(BATCH.end, auditor.checkpoint.to_bytes())

    def test_start_must_be_keyword_only(self):
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY, FRONTIER_1
            )

    def test_type_contract(self):
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(7, KEY)
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [RECEIPT_1], KEY
            )
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1, None)], KEY
            )
        for bad in (object(), None, 7, b""):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                seal_evidence_revocation_list_bundle_receipt_batch(
                    [(bad, BUNDLE_1)], KEY
                )
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                seal_evidence_revocation_list_bundle_receipt_batch(
                    [(RECEIPT_1, bad)], KEY
                )
        # A receipt is not a bundle and vice versa.
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(BUNDLE_1, BUNDLE_1)], KEY
            )
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, RECEIPT_1)], KEY
            )
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], "key"
            )
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY, start=7
            )

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch([], KEY)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], b""
            )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY, start=b"junk"
            )
        # Broken chain: the second receipt does not continue the first.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2), (RECEIPT_1, BUNDLE_1)], KEY
            )
        # A chain starting from a frontier that does not match the first
        # receipt's start.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY, start=FRONTIER_1
            )
        # The full two-snapshot bundle receipt attests BUNDLE_FULL, not
        # BUNDLE_1, so a mismatched pair fails full verification.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_FULL, BUNDLE_1)], KEY
            )

    def test_wrong_key_and_start_frontier_mac_rejected(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], OTHER_KEY
            )
        forged = dataclasses.replace(FRONTIER_1, mac=b"\x01" * 32)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY, start=forged
            )


class AuditBatchStatelessTest(unittest.TestCase):
    def test_verifies_and_returns_end_frontier(self):
        end = audit_evidence_revocation_list_bundle_receipt_batch(BATCH, KEY)
        self.assertIsInstance(end, EvidenceRevocationListBundleReceiptFrontier)
        self.assertEqual(end, FRONTIER_2)
        self.assertEqual(end.to_bytes(), BATCH.end)

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH.to_bytes(), KEY
            ),
            FRONTIER_2,
        )

    def test_verifies_non_empty_start_continuation(self):
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(BATCH_2, KEY),
            FRONTIER_2,
        )

    def test_round_trip_observation(self):
        blob = BATCH.to_bytes()
        parsed = EvidenceRevocationListBundleReceiptBatch.from_bytes(blob)
        self.assertEqual(parsed.to_bytes(), blob)
        self.assertEqual(parsed, BATCH)
        end = audit_evidence_revocation_list_bundle_receipt_batch(parsed, KEY)
        self.assertEqual(end.to_bytes(), BATCH.end)

    def test_full_replay_reaches_end(self):
        # Sealing one batch over both bundles and one over the equivalent
        # full-bundle receipt are distinct records, but each replayed
        # segment ends at its declared frontier.
        full_batch = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_FULL, BUNDLE_FULL)], KEY
        )
        end = audit_evidence_revocation_list_bundle_receipt_batch(
            full_batch, KEY
        )
        self.assertEqual(end.sequence, 1)
        self.assertEqual(end.end, BUNDLE_FULL.end)
        self.assertEqual(end.to_bytes(), full_batch.end)

    def test_type_contract(self):
        for bad in (1, "x", None, [BATCH], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt_batch(bad, KEY)
        for bad in (1, None, [KEY], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt_batch(BATCH, bad)

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(BATCH, b"")
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(b"junk", KEY)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH.to_bytes().replace(b",", b", "), KEY
            )

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(BATCH, OTHER_KEY)

    def test_tampered_batch_signature(self):
        tampered = dataclasses.replace(BATCH, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(tampered, KEY)

    def test_tampered_endpoint_frontier_rejected(self):
        forged_end = dataclasses.replace(
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(BATCH.end),
            mac=b"\x02" * 32,
        )
        tampered = batch_for(
            CHAIN, end=forged_end.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(tampered, KEY)

    def test_tampered_carried_receipt_mac(self):
        bad_receipt = dataclasses.replace(RECEIPT_1, mac=ZERO)
        tampered = batch_for(((bad_receipt, BUNDLE_1), (RECEIPT_2, BUNDLE_2)))
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(tampered, KEY)

    def test_tampered_carried_bundle_rejected(self):
        # Keep the carried receipt bytes but swap in a different bundle:
        # the bundle digest inside the receipt no longer matches.
        solo = seal_evidence_revocation_list_bundle(
            [snapshot(sequence=2)], KEY, 200.0
        )
        tampered = batch_for(((RECEIPT_1, solo),))
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(tampered, KEY)

    def test_broken_carried_link_rejected(self):
        tampered = batch_for(
            ((RECEIPT_2, BUNDLE_2), (RECEIPT_1, BUNDLE_1))
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(tampered, KEY)

    def test_replayed_end_mismatch_rejected(self):
        # Signature, endpoints and every carried MAC verify, but the
        # declared end is the frontier one step too early.
        tampered = batch_for(
            CHAIN, end=FRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(tampered, KEY)

    def test_sequence_overflow_rejected(self):
        # A start frontier already at u64 max cannot be extended even
        # once; the honest carried pair would be the first advance.
        max_frontier = frontier_for_sequence(
            U64_MAX, STATE_1.to_bytes(), ZERO
        )
        overflow = batch_for(
            ((RECEIPT_2, BUNDLE_2),),
            start=max_frontier.to_bytes(),
            end=FRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(overflow, KEY)


class AuditorAuditBatchTest(unittest.TestCase):
    def test_returns_self_and_advances_to_declared_end(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_batch(BATCH), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, STATE_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_batch(BATCH.to_bytes()), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_single_item_batch(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_matches_per_receipt_audit(self):
        via_batch = EvidenceRevocationListBundleReceiptAuditor(KEY)
        via_batch.audit_batch(BATCH_1)
        via_batch.audit_batch(BATCH_2)
        via_singles = EvidenceRevocationListBundleReceiptAuditor(KEY)
        via_singles.audit(RECEIPT_1, BUNDLE_1)
        via_singles.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch.checkpoint, via_singles.checkpoint)
        self.assertEqual(via_batch.checkpoint, FRONTIER_2)

    def test_shares_lock_and_interleaves_with_audit(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        # A single receipt continuation after a batch start.
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_restart_from_checkpoint_then_batch(self):
        first = EvidenceRevocationListBundleReceiptAuditor(KEY)
        first.audit_batch(BATCH_1)
        restored = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=first.checkpoint.to_bytes()
        )
        restored.audit_batch(BATCH_2)
        self.assertEqual(restored.checkpoint, FRONTIER_2)

    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_same_batch_replayed_rejected_and_unchanged(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH)
        checkpoint = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH)
        self.assertIs(auditor.checkpoint, checkpoint)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH.to_bytes())
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_failure_leaves_checkpoint_untouched(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        checkpoint = auditor.checkpoint
        tampered = dataclasses.replace(BATCH_2, signature=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_batch(tampered)
        self.assertIs(auditor.checkpoint, checkpoint)
        # A batch whose carried pair fails full replay.
        bad = batch_for(((RECEIPT_FULL, BUNDLE_2),))
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad)
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_type_and_value_split(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        for bad in (object(), None, 7, RECEIPT_1, [BATCH]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch(bad)
        with self.assertRaises(ValueError):
            auditor.audit_batch(b"nonsense")
        self.assertIsNone(auditor.checkpoint)

    def test_overflow_leaves_checkpoint_untouched(self):
        max_frontier = frontier_for_sequence(
            U64_MAX, STATE_1.to_bytes(), ZERO
        )
        auditor = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=max_frontier
        )
        overflow = batch_for(
            ((RECEIPT_2, BUNDLE_2),),
            start=max_frontier.to_bytes(),
            end=FRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            auditor.audit_batch(overflow)
        self.assertEqual(auditor.checkpoint, max_frontier)

    def test_concurrent_batches_linearize_in_lock_order(self):
        # Two disjoint one-receipt forks both extend the empty ledger and
        # carry honestly MAC'd but mutually incompatible endpoints:
        # exactly one is booked; the loser fails the start linkage.
        fork_one = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_1, BUNDLE_1)], KEY
        )
        solo = seal_evidence_revocation_list_bundle([snapshot(sequence=2)], KEY, 200.0)
        fork_two = seal_evidence_revocation_list_bundle_receipt_batch(
            [(receipt_for(solo), solo)], KEY
        )
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        accepted, failures = [], []
        barrier = threading.Barrier(2)

        def book(batch):
            barrier.wait()
            try:
                auditor.audit_batch(batch)
                accepted.append(batch)
            except ValueError:
                failures.append(batch)

        threads = [
            threading.Thread(target=book, args=(b,))
            for b in (fork_one, fork_two)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(
            auditor.checkpoint.to_bytes(), accepted[0].end
        )


class BatchExportsTest(unittest.TestCase):
    def test_api_is_exported(self):
        import nearproof

        for name in (
            "EvidenceRevocationListBundleReceiptBatch",
            "seal_evidence_revocation_list_bundle_receipt_batch",
            "audit_evidence_revocation_list_bundle_receipt_batch",
        ):
            self.assertIn(name, nearproof.__all__)
            self.assertIs(getattr(nearproof, name), getattr(nearproof, name))
        self.assertTrue(
            hasattr(
                nearproof.EvidenceRevocationListBundleReceiptAuditor,
                "audit_batch",
            )
        )
        # No aliases were introduced for the existing single-entry path.
        self.assertFalse(
            hasattr(
                nearproof.EvidenceRevocationListBundleReceiptAuditor,
                "audit_batches",
            )
        )


if __name__ == "__main__":
    unittest.main()
