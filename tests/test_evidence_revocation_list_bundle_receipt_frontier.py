import dataclasses
import hashlib
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListBundleReceiptAuditor,
    EvidenceRevocationListBundleReceiptFrontier,
    EvidenceRevocationListState,
    _evidence_revocation_list_bundle_receipt_frontier_mac,
    _evidence_revocation_list_bundle_receipt_frontier_next_digest,
    seal_evidence_revocation_list_bundle,
)
from test_evidence_revocation_list_bundle import (
    KEY,
    OTHER_KEY,
    frontier_for,
    snapshot,
)
from test_evidence_revocation_list_bundle_receipt import receipt_for

ZERO = b"\x00" * 32
U64_MAX = 0xFFFFFFFFFFFFFFFF

SNAPSHOT_1 = snapshot(sequence=1)
SNAPSHOT_2 = snapshot(sequence=2)

STATE_1 = frontier_for(SNAPSHOT_1)
STATE_2 = frontier_for(SNAPSHOT_2)

BUNDLE_1 = seal_evidence_revocation_list_bundle([SNAPSHOT_1], KEY, 100.0)
BUNDLE_2 = seal_evidence_revocation_list_bundle(
    [SNAPSHOT_2], KEY, 100.0, start=STATE_1
)
BUNDLE_FULL = seal_evidence_revocation_list_bundle(
    [SNAPSHOT_1, SNAPSHOT_2], KEY, 100.0
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
    """A frontier with the NPEBR3 mac recomputed over the first four
    fields."""
    placeholder = EvidenceRevocationListBundleReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_evidence_revocation_list_bundle_receipt_frontier_mac(
            key, placeholder
        ),
    )


FRONTIER_1 = frontier_for_sequence(1, STATE_1.to_bytes(), DIGEST_1)
FRONTIER_2 = frontier_for_sequence(2, STATE_2.to_bytes(), DIGEST_2)


class FrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = EvidenceRevocationListBundleReceiptFrontier(
            1, 1, STATE_1.to_bytes(), DIGEST_1, FRONTIER_1.mac
        )
        self.assertEqual(frontier, FRONTIER_1)
        self.assertEqual(hash(frontier), hash(FRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, STATE_1.to_bytes())
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
        for bad in (1, "x", None, bytearray(STATE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)
        # end must be the non-empty canonical state encoding.
        for bad in (b"", b"junk", RECEIPT_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(FRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(FRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(FRONTIER_1, **{name: bad})


class FrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'{"version":1,"sequence":1,'
            b'"end":"' + STATE_1.to_bytes().hex().encode() + b'",'
            b'"digest":"' + DIGEST_1.hex().encode() + b'",'
            b'"mac":"' + FRONTIER_1.mac.hex().encode() + b'"}'
        )
        self.assertEqual(FRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (FRONTIER_1, FRONTIER_2):
            blob = frontier.to_bytes()
            parsed = EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                blob
            )
            self.assertEqual(parsed, frontier)
            self.assertEqual(parsed.to_bytes(), blob)

    def test_from_bytes_type_contract(self):
        for bad in (1, "x", None, bytearray(FRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"junk", b"[]", b"{}", b"[1,1,2,3,4]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_key_disorder(self):
        obj = json.loads(FRONTIER_1.to_bytes())

        def encode(keys):
            return json.dumps(
                {key: obj.get(key, 0) for key in keys},
                separators=(",", ":"),
            ).encode()

        fields = ["version", "sequence", "end", "digest", "mac"]
        for bad_keys in (
            fields[:-1],  # missing key
            fields + ["extra"],  # extra key
            list(reversed(fields)),  # out-of-order keys
            ["version", "version", "end", "digest", "mac"],
        ):
            with self.assertRaises(ValueError, msg=repr(bad_keys)):
                EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                    encode(bad_keys)
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = FRONTIER_1.to_bytes()
        spaced = blob.replace(b",", b", ")
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(spaced)
        upper = blob.replace(
            FRONTIER_1.mac.hex().encode(),
            FRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                blob.replace(b'"version":1', b'"version":2', 1)
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptFrontier.from_bytes(
                blob.replace(b'"sequence":1', b'"sequence":1.0', 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(FRONTIER_1, mac=ZERO)
        parsed = EvidenceRevocationListBundleReceiptFrontier.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)


class AuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
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
        # The end frontier-state's own NPES1 layer is recomputed on load.
        bad_state = dataclasses.replace(STATE_1, mac=ZERO)
        tampered = frontier_for_sequence(1, bad_state.to_bytes(), DIGEST_1)
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                KEY, checkpoint=tampered
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceiptAuditor(
                OTHER_KEY, checkpoint=FRONTIER_1
            )


class AuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_1, BUNDLE_1), auditor)
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, STATE_1.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, DIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(auditor.checkpoint, FRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.end, STATE_2.to_bytes())
        self.assertEqual(auditor.checkpoint.digest, DIGEST_2)

    def test_full_bundle_receipt(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        self.assertEqual(auditor.checkpoint.end, STATE_2.to_bytes())

    def test_accepts_canonical_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes())
        self.assertEqual(auditor.checkpoint, FRONTIER_1)
        auditor.audit(RECEIPT_2.to_bytes(), BUNDLE_2)
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
        # A receipt over a different bundle from the same (now passed)
        # start no longer links to the advanced frontier.
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, BUNDLE_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_FULL, BUNDLE_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_receipt_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit(tampered, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_bundle_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_FULL)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, BUNDLE_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_receipt_bytes(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(b"junk", BUNDLE_1)
        self.assertIsNone(auditor.checkpoint)

    def test_sequence_overflow(self):
        maxed = frontier_for_sequence(U64_MAX, STATE_1.to_bytes(), DIGEST_1)
        auditor = EvidenceRevocationListBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, BUNDLE_2)
        self.assertIs(auditor.checkpoint, before)

    def test_competing_commits_linearize(self):
        auditor = EvidenceRevocationListBundleReceiptAuditor(KEY)
        commits = []
        failures = []

        def run(receipt, bundle):
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


if __name__ == "__main__":
    unittest.main()
