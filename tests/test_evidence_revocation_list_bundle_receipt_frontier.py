import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListBundleReceipt,
    EvidenceRevocationListBundleReceiptAuditor,
    EvidenceRevocationListBundleReceiptFrontier,
    EvidenceRevocationListState,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_FRONTIER_DIGEST_PREFIX,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_FRONTIER_MAC_PREFIX,
    _encode_payload,
    _evidence_revocation_list_bundle_receipt_frontier_mac,
    _evidence_revocation_list_bundle_receipt_frontier_next_digest,
    _evidence_revocation_list_bundle_receipt_frontier_payload,
    _evidence_revocation_list_bundle_receipt_mac,
    seal_evidence_revocation_list_bundle,
)
from test_evidence_revocation_list_bundle import (
    KEY,
    OTHER_KEY,
    frontier_for,
    snapshot,
)

ZERO = b"\x00" * 32
U64_MAX = 0xFFFFFFFFFFFFFFFF

SNAP_1 = snapshot(sequence=1)
SNAP_2 = snapshot(sequence=2)
SNAP_3 = snapshot(sequence=3)

STATE_1 = frontier_for(SNAP_1)
STATE_2 = frontier_for(SNAP_2)

BUNDLE_1 = seal_evidence_revocation_list_bundle([SNAP_1], KEY, 100.0)
BUNDLE_2 = seal_evidence_revocation_list_bundle(
    [SNAP_2], KEY, 100.0, start=STATE_1
)
BUNDLE_FULL = seal_evidence_revocation_list_bundle(
    [SNAP_1, SNAP_2], KEY, 100.0
)


def receipt_for(bundle, key=KEY):
    """An honestly MAC'd NPEBR1 receipt over ``bundle``."""
    placeholder = EvidenceRevocationListBundleReceipt(
        1,
        bundle.start,
        hashlib.sha256(bundle.to_bytes()).digest(),
        bundle.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        mac=_evidence_revocation_list_bundle_receipt_mac(key, placeholder),
    )


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)
RECEIPT_FULL = receipt_for(BUNDLE_FULL)

DIGEST_1 = _evidence_revocation_list_bundle_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_1.to_bytes()
)
DIGEST_2 = _evidence_revocation_list_bundle_receipt_frontier_next_digest(
    DIGEST_1, 2, RECEIPT_2.to_bytes()
)


def frontier_for_sequence(sequence, end, digest, key=KEY):
    placeholder = EvidenceRevocationListBundleReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_evidence_revocation_list_bundle_receipt_frontier_mac(
            key, placeholder
        ),
    )


FRONTIER_1 = frontier_for_sequence(1, BUNDLE_1.end, DIGEST_1)
FRONTIER_2 = frontier_for_sequence(2, BUNDLE_2.end, DIGEST_2)


def reencode(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


class ReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = EvidenceRevocationListBundleReceiptFrontier(
            1, 1, BUNDLE_1.end, DIGEST_1, FRONTIER_1.mac
        )
        self.assertEqual(frontier, FRONTIER_1)
        self.assertEqual(hash(frontier), hash(FRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, BUNDLE_1.end)
        self.assertEqual(frontier.digest, DIGEST_1)
        self.assertFalse(hasattr(frontier, "key"))

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FRONTIER_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, version=bad)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, version=bad)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(FRONTIER_1, sequence=U64_MAX).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(BUNDLE_1.end)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)
        # end must be the canonical non-empty frontier-state encoding:
        # not empty, not junk, not a receipt and not a bundle.
        for bad in (
            b"",
            b"junk",
            RECEIPT_1.to_bytes(),
            BUNDLE_1.to_bytes(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "x", None, bytearray(ZERO)):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(FRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(FRONTIER_1, **{name: bad})


class ReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        obj = json.loads(FRONTIER_1.to_bytes())
        self.assertEqual(
            list(obj), ["version", "sequence", "end", "digest", "mac"]
        )
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["sequence"], 1)
        self.assertEqual(obj["end"], FRONTIER_1.end.hex())
        self.assertEqual(obj["digest"], DIGEST_1.hex())
        self.assertEqual(obj["mac"], FRONTIER_1.mac.hex())
        # Compact JSON with no whitespace or length prefix.
        self.assertNotIn(b" ", FRONTIER_1.to_bytes())

    def test_round_trip(self):
        for frontier in (FRONTIER_1, FRONTIER_2):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(blob),
                frontier,
            )
            self.assertEqual(
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                    blob
                ).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = FRONTIER_1.to_bytes()
        for bad in (1, blob.decode(), None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"junk", b"[]", b"[1,2,3,4,5]", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(bad)

    def test_missing_extra_reordered_and_duplicate_keys_rejected(self):
        encoding = FRONTIER_1.to_bytes()
        obj = json.loads(encoding)
        del obj["digest"]
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )
        obj = json.loads(encoding)
        obj["extra"] = 0
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )
        obj = json.loads(encoding)
        reordered = {name: obj[name] for name in reversed(list(obj))}
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(reordered)
            )
        duplicated = encoding.replace(
            b'"version":1', b'"version":1,"version":1'
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(duplicated)

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = FRONTIER_1.to_bytes()
        for bad in (
            b" " + blob,
            blob + b" ",
            blob.replace(b",", b", "),
            blob.replace(
                FRONTIER_1.mac.hex().encode(),
                FRONTIER_1.mac.hex().upper().encode(),
            ),
            blob.replace(b'{"version":1', b'{"version":2', 1),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(bad)

    def test_bad_field_values(self):
        obj = json.loads(FRONTIER_1.to_bytes())
        # A non-canonical nested frontier state.
        obj["end"] = FRONTIER_1.end.hex() + "00"
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )
        obj = json.loads(FRONTIER_1.to_bytes())
        obj["end"] = ""
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )
        obj = json.loads(FRONTIER_1.to_bytes())
        obj["digest"] = "00"
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )
        obj = json.loads(FRONTIER_1.to_bytes())
        obj["mac"] = "00"
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )
        obj = json.loads(FRONTIER_1.to_bytes())
        obj["sequence"] = -1
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                reencode(obj)
            )

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(FRONTIER_1, mac=ZERO)
        parsed = EvidenceRevocationListBundleReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_mac_scheme_is_npebr3_over_unsigned_encoding(self):
        unsigned = _encode_payload(
            _evidence_revocation_list_bundle_receipt_frontier_payload(
                FRONTIER_1
            )
        )
        expected = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_FRONTIER_MAC_PREFIX
            + unsigned,
            hashlib.sha256,
        ).digest()
        self.assertEqual(FRONTIER_1.mac, expected)
        self.assertEqual(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_FRONTIER_MAC_PREFIX,
            b"NPEBR3",
        )
        # The label itself distinguishes the domain from the receipt MAC.
        self.assertNotEqual(
            FRONTIER_1.mac,
            hmac.new(KEY, b"NPEBR1" + unsigned, hashlib.sha256).digest(),
        )

    def test_digest_chain_scheme_is_npebr2(self):
        expected = hashlib.sha256(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_FRONTIER_DIGEST_PREFIX
            + ZERO
            + (1).to_bytes(8, byteorder="big")
            + RECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(DIGEST_1, expected)
        self.assertEqual(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_FRONTIER_DIGEST_PREFIX,
            b"NPEBR2",
        )


class ReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(
            EvidenceRevocationListBundleReceiptAuditor(KEY).checkpoint
        )
        self.assertIsNone(
            EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=None
            ).checkpoint
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (FRONTIER_1, FRONTIER_1.to_bytes()):
            auditor = EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [FRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptAuditor(
                    KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=b"junk"
            )

    def test_checkpoint_frontier_mac_verified(self):
        tampered = dataclasses.replace(FRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_state_mac_verified(self):
        # The end frontier state's own NPES1 layer is recomputed on load.
        bad_state = dataclasses.replace(
            EvidenceRevocationListState.from_bytes(FRONTIER_1.end), mac=ZERO
        )
        tampered = frontier_for_sequence(
            1, bad_state.to_bytes(), DIGEST_1
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                OTHER_KEY, checkpoint=FRONTIER_1
            )

    def test_checkpoint_is_read_only(self):
        with self.assertRaises(AttributeError):
            EvidenceRevocationListBundleReceiptAuditor(
                KEY
            ).checkpoint = FRONTIER_1


class ReceiptAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_1, BUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, BUNDLE_1.end)
        self.assertEqual(auditor.checkpoint.digest, DIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, BUNDLE_2.end)
        self.assertEqual(auditor.checkpoint.digest, DIGEST_2)

    def test_accepts_canonical_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        blob = auditor.checkpoint.to_bytes()
        restored = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=blob
        )
        restored.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(restored.checkpoint, FRONTIER_2)

    def test_first_receipt_must_start_empty(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_receipt_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIs(auditor.checkpoint, before)

    def test_old_fork_rejected(self):
        # A receipt over a bundle that also starts from the empty ledger
        # but ends elsewhere is an old fork once the frontier advanced.
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_receipt_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(dataclasses.replace(RECEIPT_1, mac=ZERO), BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_bundle_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_FULL)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(receipt_for(BUNDLE_1, key=OTHER_KEY), BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_1], (RECEIPT_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        for bad in (b"junk", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(dataclasses.replace(RECEIPT_1, mac=ZERO), BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)

    def test_sequence_overflow(self):
        maxed = frontier_for_sequence(U64_MAX, BUNDLE_1.end, DIGEST_1)
        auditor = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_receipts_linearize(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        commits, failures = [], []
        barrier = threading.Barrier(2)

        def run(receipt, bundle):
            barrier.wait()
            try:
                auditor.audit(receipt, bundle)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(target=run, args=(RECEIPT_1, BUNDLE_1)),
            threading.Thread(target=run, args=(RECEIPT_FULL, BUNDLE_FULL)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, commits[0].end)


class ReceiptFrontierExportsTest(unittest.TestCase):
    def test_api_is_exported(self):
        import nearproof

        for name in (
            "EvidenceRevocationListBundleReceiptAuditor",
            "EvidenceRevocationListBundleReceiptFrontier",
            # The previous tasks' bundle-receipt entries, documented
            # alongside the new ones.
            "EvidenceRevocationListBundleReceipt",
            "audit_evidence_revocation_list_bundle_receipt",
        ):
            self.assertIn(name, nearproof.__all__)
            self.assertIs(getattr(nearproof, name), getattr(nearproof, name))


if __name__ == "__main__":
    unittest.main()
