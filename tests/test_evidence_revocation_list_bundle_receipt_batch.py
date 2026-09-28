import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListBundleReceiptAuditor,
    EvidenceRevocationListBundleReceiptBatch,
    EvidenceRevocationListState,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_PREFIX,
    _evidence_revocation_list_bundle_receipt_batch_signature,
    audit_evidence_revocation_list_bundle_receipt_batch,
    seal_evidence_revocation_list_bundle_receipt_batch,
)
from test_evidence_revocation_list_bundle import KEY, OTHER_KEY
from test_evidence_revocation_list_bundle_receipt_frontier import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    DIGEST_1,
    FRONTIER_1,
    FRONTIER_2,
    RECEIPT_1,
    RECEIPT_2,
    RECEIPT_FULL,
    U64_MAX,
    ZERO,
    frontier_for_sequence,
)


# A one-pair batch from the empty ledger to FRONTIER_1, its continuation
# from FRONTIER_1 to FRONTIER_2, and the whole segment in one batch.
BATCH_1 = seal_evidence_revocation_list_bundle_receipt_batch(
    [(RECEIPT_1, BUNDLE_1)], KEY
)
BATCH_2 = seal_evidence_revocation_list_bundle_receipt_batch(
    [(RECEIPT_2, BUNDLE_2)], KEY, start=FRONTIER_1
)
BATCH_FULL = seal_evidence_revocation_list_bundle_receipt_batch(
    [(RECEIPT_1, BUNDLE_1), (RECEIPT_2, BUNDLE_2)], KEY
)


def batch_for(start, payload, end, key=KEY):
    """A batch with the NPEBR4 signature recomputed over the first four
    fields; ``payload`` is already a tuple of canonical receipt/bundle
    byte pairs."""
    placeholder = EvidenceRevocationListBundleReceiptBatch(
        1, start, payload, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=_evidence_revocation_list_bundle_receipt_batch_signature(
            key, placeholder
        ),
    )


class BundleReceiptBatchFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    EvidenceRevocationListBundleReceiptBatch
                )
            ],
            ["version", "start", "payload", "end", "signature"],
        )
        self.assertNotIn("key", BATCH_FULL.__dict__)
        self.assertNotIn("mac", BATCH_FULL.__dict__)

    def test_constructs_positionally_and_compares_by_fields(self):
        batch = EvidenceRevocationListBundleReceiptBatch(
            1,
            BATCH_1.start,
            BATCH_1.payload,
            BATCH_1.end,
            BATCH_1.signature,
        )
        self.assertEqual(batch, BATCH_1)
        self.assertEqual(hash(batch), hash(BATCH_1))
        self.assertEqual(batch.version, 1)
        self.assertEqual(batch.start, b"")
        self.assertEqual(
            batch.payload,
            ((RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),),
        )
        self.assertEqual(batch.end, FRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BATCH_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, version=bad)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, version=bad)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, start=bad)
        for bad in (b"junk", b"[1,2,3]", RECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BATCH_1, start=b"")

    def test_payload_contract(self):
        for bad in (1, "x", None, [BATCH_1.payload[0]]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, payload=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_1, payload=())
        # Entries must be tuples.
        for bad in (1, "x", None, [RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, payload=(bad,))
        # Entries must be exactly two elements.
        with self.assertRaises(ValueError):
            dataclasses.replace(
                BATCH_1,
                payload=((RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), b""),),
            )
        with self.assertRaises(ValueError):
            dataclasses.replace(BATCH_1, payload=((RECEIPT_1.to_bytes(),),))
        # Members must be canonical bytes of the right record.
        for bad in (1, "x", None, bytearray(RECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(
                    BATCH_1, payload=((bad, BUNDLE_1.to_bytes()),)
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(
                    BATCH_1, payload=((RECEIPT_1.to_bytes(), bad),)
                )
        for bad in (b"junk", FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(
                    BATCH_1, payload=((bad, BUNDLE_1.to_bytes()),)
                )
        for bad in (b"junk", RECEIPT_1.to_bytes(), FRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(
                    BATCH_1, payload=((RECEIPT_1.to_bytes(), bad),)
                )

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, end=bad)
        # The end is a non-empty receipt frontier: empty bytes and the
        # nested state encoding are value errors.
        for bad in (b"", b"junk", b"[1,2,3]", RECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BATCH_1, signature=bad)


class BundleReceiptBatchEncodingTest(unittest.TestCase):
    def test_compact_lowercase_hex_shape(self):
        raw = BATCH_FULL.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(
            list(outer),
            ["version", "start", "payload", "end", "signature"],
        )
        self.assertEqual(outer["version"], 1)
        self.assertEqual(outer["start"], b"".hex())
        self.assertEqual(
            outer["payload"],
            [
                [RECEIPT_1.to_bytes().hex(), BUNDLE_1.to_bytes().hex()],
                [RECEIPT_2.to_bytes().hex(), BUNDLE_2.to_bytes().hex()],
            ],
        )
        self.assertEqual(outer["end"], FRONTIER_2.to_bytes().hex())
        self.assertEqual(outer["signature"], BATCH_FULL.signature.hex())
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for batch in (BATCH_1, BATCH_2, BATCH_FULL):
            raw = batch.to_bytes()
            parsed = EvidenceRevocationListBundleReceiptBatch.from_bytes(raw)
            self.assertEqual(parsed, batch)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signatures(self):
        unsigned = dataclasses.replace(BATCH_1, signature=ZERO)
        parsed = EvidenceRevocationListBundleReceiptBatch.from_bytes(
            unsigned.to_bytes()
        )
        self.assertEqual(parsed, unsigned)
        unsigned_pairs = (
            (
                dataclasses.replace(RECEIPT_1, mac=ZERO).to_bytes(),
                BUNDLE_1.to_bytes(),
            ),
        )
        unsigned_batch = dataclasses.replace(
            BATCH_1, payload=unsigned_pairs
        )
        parsed = EvidenceRevocationListBundleReceiptBatch.from_bytes(
            unsigned_batch.to_bytes()
        )
        self.assertEqual(parsed, unsigned_batch)

    def test_non_canonical_spelling_rejected(self):
        raw = BATCH_1.to_bytes()
        for bad in (
            b"",
            b"junk",
            b"[1,2,3]",
            raw + b" ",
            raw.replace(b",", b", ", 1),
            b" " + raw,
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        for bad in (
            b"[]",
            b"[1,2,3,4,5]",
            b"{}",
            b'{"version":1}',
        ):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(bad)

    def test_wrong_key_order_or_duplicate_rejected(self):
        obj = json.loads(BATCH_FULL.to_bytes())
        fields = ["version", "start", "payload", "end", "signature"]

        def encode(keys):
            return json.dumps(
                {key: obj.get(key, 0) for key in keys},
                separators=(",", ":"),
            ).encode()

        for bad_keys in (
            fields[:-1],  # missing key
            fields + ["extra"],  # extra key
            list(reversed(fields)),  # out-of-order keys
            ["version", "version", "payload", "end", "signature"],
        ):
            with self.assertRaises(ValueError, msg=repr(bad_keys)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(
                    encode(bad_keys)
                )

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [BATCH_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptBatch.from_bytes(bad)

    def test_batch_carries_receipts_and_bundles(self):
        raw = BATCH_FULL.to_bytes()
        self.assertIn(RECEIPT_1.to_bytes().hex().encode(), raw)
        self.assertIn(BUNDLE_1.to_bytes().hex().encode(), raw)
        self.assertIn(RECEIPT_2.to_bytes().hex().encode(), raw)
        self.assertIn(BUNDLE_2.to_bytes().hex().encode(), raw)


class BundleReceiptBatchSignatureTest(unittest.TestCase):
    def test_signature_is_npebr4_over_first_four_fields(self):
        from nearproof import (
            _evidence_revocation_list_bundle_receipt_batch_payload,
        )

        expected = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_BATCH_PREFIX
            + json.dumps(
                _evidence_revocation_list_bundle_receipt_batch_payload(
                    BATCH_FULL
                ),
                separators=(",", ":"),
                sort_keys=False,
            ).encode(),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BATCH_FULL.signature, expected)
        self.assertEqual(len(BATCH_FULL.signature), 32)

    def test_new_domain_label_distinct_from_neighbors(self):
        from nearproof import (
            _evidence_revocation_list_bundle_receipt_batch_content_bytes,
        )

        content = (
            _evidence_revocation_list_bundle_receipt_batch_content_bytes(
                BATCH_FULL
            )
        )
        for label in (b"NPEBR1", b"NPEBR2", b"NPEBR3"):
            wrong = hmac.new(KEY, label + content, hashlib.sha256).digest()
            self.assertNotEqual(wrong, BATCH_FULL.signature, label)


class SealBundleReceiptBatchTest(unittest.TestCase):
    def test_seals_full_segment_and_advances_to_end(self):
        self.assertEqual(BATCH_FULL.start, b"")
        self.assertEqual(
            BATCH_FULL.payload,
            (
                (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
                (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
            ),
        )
        self.assertEqual(BATCH_FULL.end, FRONTIER_2.to_bytes())
        self.assertEqual(
            BATCH_FULL.signature,
            _evidence_revocation_list_bundle_receipt_batch_signature(
                KEY, BATCH_FULL
            ),
        )

    def test_seals_from_checkpoint(self):
        self.assertEqual(BATCH_2.start, FRONTIER_1.to_bytes())
        self.assertEqual(
            BATCH_2.payload,
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
        )
        self.assertEqual(BATCH_2.end, FRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes_and_mixed_pairs(self):
        self.assertEqual(
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())], KEY
            ),
            BATCH_1,
        )
        self.assertEqual(
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)],
                KEY,
                start=FRONTIER_1.to_bytes(),
            ),
            BATCH_2,
        )

    def test_start_is_keyword_only(self):
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY, FRONTIER_1
            )

    def test_seal_touches_no_ledger_state(self):
        self.assertEqual(
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], KEY
            ),
            BATCH_1,
        )

    def test_empty_sequence_rejected(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch([], KEY)

    def test_non_iterable_is_type_error(self):
        for bad in (42, RECEIPT_1, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle_receipt_batch(bad, KEY)

    def test_pair_shape_errors(self):
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle_receipt_batch([42], KEY)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1, b"")], KEY
            )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1,)], KEY
            )

    def test_broken_chain_rejected(self):
        # RECEIPT_2 starts at STATE_1; it cannot lead an empty chain.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY
            )
        # Reordering breaks the second link.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2), (RECEIPT_1, BUNDLE_1)], KEY
            )
        # Repeating the same receipt cannot extend the frontier twice.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1), (RECEIPT_1, BUNDLE_1)], KEY
            )

    def test_receipt_must_match_bundle(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_FULL)], KEY
            )

    def test_wrong_start_rejected(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY, start=FRONTIER_2
            )

    def test_bad_receipt_signature_rejected(self):
        forged = dataclasses.replace(RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(forged, BUNDLE_1)], KEY
            )

    def test_bad_bundle_rejected(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, dataclasses.replace(BUNDLE_1, mac=ZERO))], KEY
            )

    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], OTHER_KEY
            )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1)], b""
            )

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle_receipt_batch(
                    [(RECEIPT_1, BUNDLE_1)], bad
                )

    def test_wrong_pair_member_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle_receipt_batch(
                    [(bad, BUNDLE_1)], KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle_receipt_batch(
                    [(RECEIPT_1, bad)], KEY
                )

    def test_non_canonical_bytes_are_value_error(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1.to_bytes() + b" ", BUNDLE_1)], KEY
            )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_1, BUNDLE_1.to_bytes() + b" ")], KEY
            )

    def test_matches_single_receipt_advances(self):
        via_batch = audit_evidence_revocation_list_bundle_receipt_batch(
            BATCH_FULL, KEY
        )
        ledger = EvidenceRevocationListBundleReceiptAuditor(KEY)
        ledger.audit(RECEIPT_1, BUNDLE_1)
        ledger.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch, ledger.checkpoint)


class AuditBundleReceiptBatchSuccessTest(unittest.TestCase):
    def test_returns_final_frontier(self):
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_FULL, KEY
            ),
            FRONTIER_2,
        )
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_2, KEY
            ),
            FRONTIER_2,
        )

    def test_accepts_object_or_canonical_bytes(self):
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_FULL.to_bytes(), KEY
            ),
            FRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        advanced = EvidenceRevocationListBundleReceiptAuditor(KEY)
        advanced.audit_batch(BATCH_FULL)
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_1, KEY
            ),
            FRONTIER_1,
        )
        self.assertEqual(advanced.checkpoint, FRONTIER_2)

    def test_round_trip_then_verify(self):
        transported = EvidenceRevocationListBundleReceiptBatch.from_bytes(
            BATCH_FULL.to_bytes()
        )
        self.assertEqual(transported, BATCH_FULL)
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt_batch(
                transported, KEY
            ),
            FRONTIER_2,
        )


class AuditBundleReceiptBatchViolationTest(unittest.TestCase):
    def test_wrong_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_FULL, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(
                BATCH_FULL, b""
            )

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt_batch(
                    BATCH_FULL, bad
                )

    def test_wrong_argument_kind_is_type_error(self):
        for bad in (1, "x", None, [BATCH_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt_batch(bad, KEY)

    def test_non_canonical_bytes_are_value_error(self):
        for bad in (
            BATCH_FULL.to_bytes() + b" ",
            b"junk",
            BATCH_FULL.to_bytes() + b"\n",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt_batch(bad, KEY)

    def test_tampered_batch_signature_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(
                dataclasses.replace(BATCH_FULL, signature=ZERO), KEY
            )

    def test_wrong_domain_label_rejected(self):
        from nearproof import (
            _evidence_revocation_list_bundle_receipt_batch_content_bytes,
        )

        wrong = hmac.new(
            KEY,
            b"NPEBR3"
            + _evidence_revocation_list_bundle_receipt_batch_content_bytes(
                BATCH_FULL
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(
                dataclasses.replace(BATCH_FULL, signature=wrong), KEY
            )

    def test_tampered_carried_receipt_rejected(self):
        forged_pairs = (
            (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
            (
                dataclasses.replace(RECEIPT_2, mac=ZERO).to_bytes(),
                BUNDLE_2.to_bytes(),
            ),
        )
        forged = batch_for(b"", forged_pairs, FRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(forged, KEY)

    def test_tampered_carried_bundle_rejected(self):
        forged_pairs = (
            (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
            (
                RECEIPT_2.to_bytes(),
                dataclasses.replace(BUNDLE_2, mac=ZERO).to_bytes(),
            ),
        )
        forged = batch_for(b"", forged_pairs, FRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(forged, KEY)

    def test_receipt_bundle_mismatch_rejected(self):
        mismatched = (
            (RECEIPT_1.to_bytes(), BUNDLE_FULL.to_bytes()),
            (RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),
        )
        forged = batch_for(b"", mismatched, FRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(forged, KEY)

    def test_replayed_or_reordered_body_rejected(self):
        duplicate = (
            (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
            (RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes()),
        )
        bad = batch_for(b"", duplicate, FRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(bad, KEY)

    def test_forged_endpoint_rejected(self):
        forged = dataclasses.replace(BATCH_2, end=FRONTIER_1.to_bytes())
        forged = dataclasses.replace(
            forged,
            signature=_evidence_revocation_list_bundle_receipt_batch_signature(
                KEY, forged
            ),
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(forged, KEY)

    def test_start_frontier_mac_must_verify(self):
        bad_start_frontier = dataclasses.replace(FRONTIER_1, mac=ZERO)
        bad = dataclasses.replace(
            BATCH_2, start=bad_start_frontier.to_bytes()
        )
        bad = dataclasses.replace(
            bad,
            signature=_evidence_revocation_list_bundle_receipt_batch_signature(
                KEY, bad
            ),
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(bad, KEY)

    def test_end_state_mac_must_verify(self):
        # A batch end whose nested frontier-state NPES1 mac is bad is
        # rejected at the envelope before replay.
        bad_state = EvidenceRevocationListState.from_bytes(FRONTIER_1.end)
        bad_state = dataclasses.replace(bad_state, mac=ZERO)
        bad_frontier = frontier_for_sequence(
            FRONTIER_1.sequence, bad_state.to_bytes(), FRONTIER_1.digest
        )
        bad = dataclasses.replace(BATCH_1, end=bad_frontier.to_bytes())
        bad = dataclasses.replace(
            bad,
            signature=_evidence_revocation_list_bundle_receipt_batch_signature(
                KEY, bad
            ),
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt_batch(bad, KEY)


class AuditorAuditBatchSuccessTest(unittest.TestCase):
    def test_books_segment_and_returns_self(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit_batch(BATCH_FULL), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_FULL.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_chained_batches_and_restart(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        restored = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=FRONTIER_1.to_bytes()
        )
        restored.audit_batch(BATCH_2)
        self.assertEqual(restored.checkpoint, FRONTIER_2)

    def test_single_and_batch_share_ledger(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_checkpoint_matches_single_receipt_ledger(self):
        via_batch = EvidenceRevocationListBundleReceiptAuditor(KEY)
        via_batch.audit_batch(BATCH_FULL)
        via_singles = EvidenceRevocationListBundleReceiptAuditor(KEY)
        via_singles.audit(RECEIPT_1, BUNDLE_1)
        via_singles.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_batch.checkpoint, via_singles.checkpoint)


class AuditorAuditBatchFailureTest(unittest.TestCase):
    def test_same_batch_replay_rejected_without_rollback(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1)
        self.assertIs(auditor.checkpoint, before)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_1.to_bytes())
        self.assertIs(auditor.checkpoint, before)

    def test_empty_ledger_rejects_non_empty_start(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_2)
        self.assertIsNone(auditor.checkpoint)

    def test_old_fork_rejected(self):
        fork = seal_evidence_revocation_list_bundle_receipt_batch(
            [(RECEIPT_FULL, BUNDLE_FULL)], KEY
        )
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(fork)
        self.assertIs(auditor.checkpoint, before)

    def test_broken_link_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(OTHER_KEY).audit_batch(
                BATCH_FULL
            )

    def test_failed_audit_leaves_checkpoint_and_stays_usable(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_batch(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_batch(42)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_batch(BATCH_FULL)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_failed_continuation_keeps_checkpoint(self):
        bad_end = dataclasses.replace(BATCH_2, end=FRONTIER_1.to_bytes())
        bad_end = dataclasses.replace(
            bad_end,
            signature=_evidence_revocation_list_bundle_receipt_batch_signature(
                KEY, bad_end
            ),
        )
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(bad_end)
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_kind_is_type_error(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_batch(bad)
        self.assertIsNone(auditor.checkpoint)


class AuditorAuditBatchOverflowTest(unittest.TestCase):
    def test_overflow_rejected_without_state_change(self):
        # A receipt frontier pinned at u64 max (its end is STATE_1)
        # cannot accept one more receipt through a batch: RECEIPT_2
        # starts exactly at STATE_1 and audits, then the sequence
        # advance overflows before the declared end is compared.
        maxed = frontier_for_sequence(
            U64_MAX, FRONTIER_1.end, DIGEST_1
        )
        overflow = batch_for(
            maxed.to_bytes(),
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            maxed.to_bytes(),
        )
        auditor = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch(overflow)
        self.assertIs(auditor.checkpoint, before)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle_receipt_batch(
                [(RECEIPT_2, BUNDLE_2)], KEY, start=maxed
            )


class AuditorAuditBatchLinearizationTest(unittest.TestCase):
    def test_single_and_batch_compete_on_one_lock(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_batch(BATCH_FULL),
                    "full",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(BATCH_1), "one"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_1, BUNDLE_1),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        if successes[0] != "full":
            auditor.audit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_two_competing_full_batches_one_wins(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                auditor.audit_batch(BATCH_FULL)
                outcomes.append("ok")
            except ValueError:
                outcomes.append("replay")

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ok", "replay"])
        self.assertEqual(auditor.checkpoint, FRONTIER_2)


if __name__ == "__main__":
    unittest.main()
