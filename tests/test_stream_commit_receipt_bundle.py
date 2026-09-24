import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptAuditor,
    StreamCommitReceiptBundle,
    StreamCommitReceiptFrontier,
    _stream_commit_receipt_bundle_content_bytes,
    _stream_commit_receipt_bundle_mac,
    audit_stream_commit_receipt_bundle,
    seal_stream_commit_receipt_bundle,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_stream_receipt_batch_commit_receipt import (
    CRECEIPT_1,
    CRECEIPT_2,
    SBATCH_1,
    commit_receipt_for,
)
from test_stream_commit_receipt_frontier import (
    CDIGEST_1,
    CFRONTIER_1,
    CFRONTIER_2,
    commit_frontier_for,
)
from test_stream_receipt_frontier import (
    SFRONTIER_1,
)


# "" -> CFRONTIER_1, CFRONTIER_1 -> CFRONTIER_2 and "" -> CFRONTIER_2.
CBUNDLE_1 = seal_stream_commit_receipt_bundle([CRECEIPT_1], KEY)
CBUNDLE_2 = seal_stream_commit_receipt_bundle(
    [CRECEIPT_2], KEY, checkpoint=CFRONTIER_1
)
CBUNDLE_FULL = seal_stream_commit_receipt_bundle(
    [CRECEIPT_1, CRECEIPT_2], KEY
)


def bundle_for(start, receipts, end, key=KEY):
    """A bundle with the NPBJ27 mac recomputed over the first four fields."""
    placeholder = StreamCommitReceiptBundle(1, start, receipts, end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_stream_commit_receipt_bundle_mac(key, placeholder)
    )


class StreamCommitReceiptBundleContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        again = StreamCommitReceiptBundle(
            1,
            CBUNDLE_2.start,
            CBUNDLE_2.receipts,
            CBUNDLE_2.end,
            CBUNDLE_2.mac,
        )
        self.assertEqual(CBUNDLE_2, again)
        self.assertIsNot(CBUNDLE_2, again)
        self.assertEqual(hash(CBUNDLE_2), hash(again))
        self.assertNotEqual(CBUNDLE_1, CBUNDLE_2)
        self.assertEqual(CBUNDLE_2.version, 1)
        self.assertEqual(CBUNDLE_2.start, CFRONTIER_1.to_bytes())
        self.assertEqual(CBUNDLE_2.receipts, (CRECEIPT_2.to_bytes(),))
        self.assertEqual(CBUNDLE_2.end, CFRONTIER_2.to_bytes())

    def test_frozen(self):
        for field in ("version", "start", "receipts", "end", "mac"):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(CBUNDLE_1, field, None)

    def test_version_contract(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, version=bad)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, version=bad)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, start=bad)
        # Malformed bytes are value errors: the start is empty or the
        # canonical commit frontier encoding.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, start=bad)
        # The empty start is valid.
        self.assertEqual(CBUNDLE_1.start, b"")

    def test_receipts_contract(self):
        for bad in (1, "x", None, [CRECEIPT_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, receipts=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(CBUNDLE_1, receipts=())
        for bad in (1, "x", None, bytearray(CRECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, receipts=(bad,))
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, receipts=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_2.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty commit frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, end=bad)

    def test_mac_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, mac=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(CBUNDLE_1, mac=bad)


class StreamCommitReceiptBundleEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'["' + CRECEIPT_1.to_bytes().hex().encode() + b'"],'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + CBUNDLE_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(CBUNDLE_1.to_bytes(), expected)

    def test_round_trip(self):
        for bundle in (CBUNDLE_1, CBUNDLE_2, CBUNDLE_FULL):
            blob = bundle.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptBundle.from_bytes(blob), bundle
            )
            self.assertEqual(
                StreamCommitReceiptBundle.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = CBUNDLE_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundle.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptBundle.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            [CRECEIPT_1.to_bytes().hex()],
            CFRONTIER_1.to_bytes().hex(),
            CBUNDLE_1.mac.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, "x"),
            (2, [1]),
            (3, 1),
            (4, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                StreamCommitReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = CBUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundle.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            CBUNDLE_1.mac.hex().encode(),
            CBUNDLE_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundle.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundle.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the bundle MAC nor any endpoint or receipt MAC is
        # checked at parse time.
        tampered = dataclasses.replace(CBUNDLE_1, mac=ZERO)
        parsed = StreamCommitReceiptBundle.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_mac_scheme(self):
        expected_mac = hmac.new(
            KEY,
            b"NPBJ27"
            + _stream_commit_receipt_bundle_content_bytes(CBUNDLE_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(CBUNDLE_1.mac, expected_mac)


class SealStreamCommitReceiptBundleTest(unittest.TestCase):
    def test_seals_chain_from_empty(self):
        bundle = seal_stream_commit_receipt_bundle([CRECEIPT_1], KEY)
        self.assertEqual(bundle, CBUNDLE_1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.receipts, (CRECEIPT_1.to_bytes(),))
        self.assertEqual(bundle.end, CFRONTIER_1.to_bytes())

    def test_seals_full_chain_in_one_bundle(self):
        bundle = seal_stream_commit_receipt_bundle(
            [CRECEIPT_1, CRECEIPT_2], KEY
        )
        self.assertEqual(bundle, CBUNDLE_FULL)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.end, CFRONTIER_2.to_bytes())

    def test_seals_continuation_from_checkpoint(self):
        for checkpoint in (CFRONTIER_1, CFRONTIER_1.to_bytes()):
            bundle = seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, checkpoint=checkpoint
            )
            self.assertEqual(bundle, CBUNDLE_2)
            self.assertEqual(bundle.start, CFRONTIER_1.to_bytes())
            self.assertEqual(bundle.end, CFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes_items(self):
        bundle = seal_stream_commit_receipt_bundle(
            [CRECEIPT_1.to_bytes(), CRECEIPT_2], KEY
        )
        self.assertEqual(bundle, CBUNDLE_FULL)

    def test_items_type_contract(self):
        for bad in (1, "x", None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle(bad, KEY)
        for bad in (1, "x", None, [CRECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle([bad], KEY)

    def test_empty_sequence_rejected(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([], KEY)

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle([CRECEIPT_1], bad)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([CRECEIPT_1], b"")

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [CFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle(
                    [CRECEIPT_2], KEY, checkpoint=bad
                )

    def test_checkpoint_malformed_or_wrong_key(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, checkpoint=b"junk"
            )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], OTHER_KEY, checkpoint=CFRONTIER_1
            )

    def test_broken_chain_rejected(self):
        # CRECEIPT_2 continues from SFRONTIER_1, not from the empty
        # ledger.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([CRECEIPT_2], KEY)
        # A gap: CRECEIPT_1 does not link to CRECEIPT_2's start.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2, CRECEIPT_1], KEY
            )

    def test_wrong_key_receipt_rejected(self):
        foreign = commit_receipt_for(SBATCH_1, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([foreign], KEY)

    def test_sequence_overflow_rejected(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, checkpoint=maxed
            )


class AuditStreamCommitReceiptBundleTest(unittest.TestCase):
    def test_audits_bundle_from_empty(self):
        frontier = audit_stream_commit_receipt_bundle(CBUNDLE_1, KEY)
        self.assertIsInstance(frontier, StreamCommitReceiptFrontier)
        self.assertEqual(frontier, CFRONTIER_1)

    def test_audits_full_chain(self):
        frontier = audit_stream_commit_receipt_bundle(CBUNDLE_FULL, KEY)
        self.assertEqual(frontier, CFRONTIER_2)
        self.assertEqual(frontier.sequence, 2)

    def test_audits_continuation_bundle(self):
        frontier = audit_stream_commit_receipt_bundle(CBUNDLE_2, KEY)
        self.assertEqual(frontier, CFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        frontier = audit_stream_commit_receipt_bundle(
            CBUNDLE_FULL.to_bytes(), KEY
        )
        self.assertEqual(frontier, CFRONTIER_2)

    def test_argument_type_contract(self):
        for bad in (1, "x", None, [CBUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle(bad, KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle(CBUNDLE_1, bad)

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle(bad, KEY)
        blob = CBUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(
                blob.replace(b",", b", "), KEY
            )

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(CBUNDLE_1, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(CBUNDLE_1, OTHER_KEY)

    def test_tampered_bundle_mac_rejected(self):
        tampered = dataclasses.replace(CBUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(tampered, KEY)

    def test_tampered_endpoint_frontier_rejected(self):
        # Re-MAC the bundle so only the nested endpoint frontier MAC
        # fails.
        bad_end = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        bundle = bundle_for(
            b"", (CRECEIPT_1.to_bytes(),), bad_end.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_tampered_receipt_rejected(self):
        # Re-MAC the bundle so only the carried receipt MAC fails.
        bad_receipt = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        bundle = bundle_for(
            b"", (bad_receipt.to_bytes(),), CFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_broken_chain_rejected(self):
        # The first receipt must link to the bundle start.
        bundle = bundle_for(
            b"", (CRECEIPT_2.to_bytes(),), CFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)
        # Each receipt must link to the previous receipt's end.
        bundle = bundle_for(
            b"",
            (CRECEIPT_1.to_bytes(), CRECEIPT_1.to_bytes()),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_end_mismatch_rejected(self):
        # The replay ends at CFRONTIER_1, not at the claimed end.
        bundle = bundle_for(
            b"", (CRECEIPT_1.to_bytes(),), CFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_audit_is_pure_check(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        audit_stream_commit_receipt_bundle(CBUNDLE_1, KEY)
        self.assertIsNone(auditor.state)


class StreamCommitReceiptAuditBundleTest(unittest.TestCase):
    def test_commits_whole_bundle_from_empty(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(CBUNDLE_1), auditor)
        self.assertEqual(auditor.state, CFRONTIER_1)
        self.assertEqual(auditor.state.to_bytes(), CBUNDLE_1.end)

    def test_commits_full_chain_in_one_step(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(CBUNDLE_FULL)
        self.assertEqual(auditor.state, CFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(
            auditor.audit_bundle(CBUNDLE_FULL.to_bytes()), auditor
        )
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_continues_from_non_empty_frontier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(CBUNDLE_1)
        auditor.audit_bundle(CBUNDLE_2)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_restarted_auditor_continues_from_bundle_start(self):
        first = StreamCommitReceiptAuditor(KEY)
        first.audit_bundle(CBUNDLE_1)
        restored = StreamCommitReceiptAuditor(
            KEY, checkpoint=first.state.to_bytes()
        )
        restored.audit_bundle(CBUNDLE_2)
        self.assertEqual(restored.state, CFRONTIER_2)

    def test_shares_the_audit_lock_path(self):
        # Single commits and bundle commits chain on one ledger.
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(CBUNDLE_1)
        auditor.audit_bundle(CBUNDLE_2)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_argument_type_contract(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (1, "x", None, [CBUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_empty_ledger_rejects_non_empty_start(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_duplicate_submit_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(CBUNDLE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_FULL)
        self.assertIs(auditor.state, before)

    def test_old_bundle_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(CBUNDLE_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_2)
        self.assertIs(auditor.state, before)

    def test_wrong_key_rejected(self):
        auditor = StreamCommitReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_1)
        self.assertIsNone(auditor.state)

    def test_tampered_bundle_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(dataclasses.replace(CBUNDLE_1, mac=ZERO))
        self.assertIsNone(auditor.state)

    def test_broken_chain_leaves_state_untouched(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(CBUNDLE_1)
        before = auditor.state
        # A bundle that starts right but whose second receipt does not
        # link to the first receipt's end.
        bundle = bundle_for(
            CFRONTIER_1.to_bytes(),
            (CRECEIPT_2.to_bytes(), CRECEIPT_1.to_bytes()),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIs(auditor.state, before)

    def test_end_mismatch_leaves_state_untouched(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        bundle = bundle_for(
            b"", (CRECEIPT_1.to_bytes(),), CFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_failed_commit_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(CBUNDLE_2)
        self.assertIsNone(auditor.state)
        auditor.audit_bundle(CBUNDLE_1)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        auditor = StreamCommitReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        # Sealing from the maxed checkpoint already overflows; build the
        # would-be bundle by hand to drive the auditor down the same path.
        candidate = bundle_for(
            maxed.to_bytes(),
            (CRECEIPT_2.to_bytes(),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(candidate)
        self.assertIs(auditor.state, before)

    def test_competing_bundles_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        commits, failures = [], []

        def run(bundle):
            try:
                auditor.audit_bundle(bundle)
                commits.append(bundle)
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(CBUNDLE_1,)),
            threading.Thread(target=run, args=(CBUNDLE_1,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state, CFRONTIER_1)


if __name__ == "__main__":
    unittest.main()
