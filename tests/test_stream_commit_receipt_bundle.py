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
    CRECEIPT_FULL,
    SBATCH_1,
    SBATCH_2,
)
from test_stream_commit_receipt_frontier import (
    CDIGEST_1,
    CFRONTIER_1,
    CFRONTIER_2,
    CFRONTIER_FULL,
    commit_frontier_for,
)
from test_stream_receipt_frontier import (
    SFRONTIER_1,
    SFRONTIER_2,
)


# "" -> CFRONTIER_1, CFRONTIER_1 -> CFRONTIER_2 and "" -> CFRONTIER_2.
BUNDLE_1 = seal_stream_commit_receipt_bundle([CRECEIPT_1], KEY)
BUNDLE_2 = seal_stream_commit_receipt_bundle(
    [CRECEIPT_2], KEY, start=CFRONTIER_1
)
BUNDLE_FULL = seal_stream_commit_receipt_bundle(
    [CRECEIPT_1, CRECEIPT_2], KEY
)
# One commit straight to SFRONTIER_2: a fork competing with BUNDLE_1.
BUNDLE_SOLO = seal_stream_commit_receipt_bundle([CRECEIPT_FULL], KEY)


def bundle_for(start, receipts, end, key=KEY):
    """A bundle with the NPBJ27 mac recomputed over the first four
    fields."""
    placeholder = StreamCommitReceiptBundle(1, start, receipts, end, ZERO)
    return dataclasses.replace(
        placeholder,
        mac=_stream_commit_receipt_bundle_mac(key, placeholder),
    )


class StreamCommitReceiptBundleFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        bundle = StreamCommitReceiptBundle(
            1,
            b"",
            (CRECEIPT_1.to_bytes(),),
            CFRONTIER_1.to_bytes(),
            BUNDLE_1.mac,
        )
        self.assertEqual(bundle, BUNDLE_1)
        self.assertEqual(hash(bundle), hash(BUNDLE_1))
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.receipts, (CRECEIPT_1.to_bytes(),))
        self.assertEqual(bundle.end, CFRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BUNDLE_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BUNDLE_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, start=bad)
        # Malformed bytes are value errors: the start is empty or a
        # canonical commit frontier.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(BUNDLE_1, start=b"")

    def test_receipts_contract(self):
        for bad in (1, "1", None, [CRECEIPT_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, receipts=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(BUNDLE_1, receipts=())
        for bad in (1, "1", None, bytearray(CRECEIPT_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, receipts=(bad,))
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, receipts=(bad,))

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty commit frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, end=bad)

    def test_mac_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, mac=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(BUNDLE_1, mac=bad)


class StreamCommitReceiptBundleEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'["' + CRECEIPT_1.to_bytes().hex().encode() + b'"],'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + BUNDLE_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(BUNDLE_1.to_bytes(), expected)

    def test_round_trip(self):
        for bundle in (BUNDLE_1, BUNDLE_2, BUNDLE_FULL, BUNDLE_SOLO):
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
        blob = BUNDLE_1.to_bytes()
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
            BUNDLE_1.mac.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, "ab"),
            (2, [1]),
            (3, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                StreamCommitReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = BUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundle.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            BUNDLE_1.mac.hex().encode(),
            BUNDLE_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundle.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundle.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            [CRECEIPT_1.to_bytes().hex()],
            CFRONTIER_1.to_bytes().hex(),
            BUNDLE_1.mac.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (2, []),
            (2, ["junk"]),
            (3, ""),
            (3, "junk"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                StreamCommitReceiptBundle.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the bundle MAC nor any nested MAC is checked at parse
        # time.
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        parsed = StreamCommitReceiptBundle.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_mac_scheme(self):
        expected_mac = hmac.new(
            KEY,
            b"NPBJ27"
            + _stream_commit_receipt_bundle_content_bytes(BUNDLE_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BUNDLE_1.mac, expected_mac)


class SealStreamCommitReceiptBundleTest(unittest.TestCase):
    def test_seals_chain_from_empty_ledger(self):
        bundle = seal_stream_commit_receipt_bundle(
            [CRECEIPT_1, CRECEIPT_2], KEY
        )
        self.assertEqual(bundle, BUNDLE_FULL)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(
            bundle.receipts,
            (CRECEIPT_1.to_bytes(), CRECEIPT_2.to_bytes()),
        )
        self.assertEqual(bundle.end, CFRONTIER_2.to_bytes())

    def test_seals_single_receipt(self):
        bundle = seal_stream_commit_receipt_bundle([CRECEIPT_1], KEY)
        self.assertEqual(bundle, BUNDLE_1)
        self.assertEqual(bundle.end, CFRONTIER_1.to_bytes())

    def test_seals_from_supplied_frontier_object_and_bytes(self):
        for start in (CFRONTIER_1, CFRONTIER_1.to_bytes()):
            bundle = seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, start=start
            )
            self.assertEqual(bundle, BUNDLE_2)
            self.assertEqual(bundle.start, CFRONTIER_1.to_bytes())
            self.assertEqual(bundle.end, CFRONTIER_2.to_bytes())

    def test_accepts_canonical_receipt_bytes(self):
        bundle = seal_stream_commit_receipt_bundle(
            [CRECEIPT_1.to_bytes(), CRECEIPT_2.to_bytes()], KEY
        )
        self.assertEqual(bundle, BUNDLE_FULL)

    def test_sealing_touches_no_auditor_state(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        seal_stream_commit_receipt_bundle([CRECEIPT_1], KEY)
        self.assertIsNone(auditor.state)

    def test_type_contract(self):
        with self.assertRaises(TypeError):
            seal_stream_commit_receipt_bundle(1, KEY)
        for bad in (1, "x", None, [CRECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle([bad], KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle([CRECEIPT_1], bad)
        for bad in (1, "x", [CFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream_commit_receipt_bundle(
                    [CRECEIPT_2], KEY, start=bad
                )

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([], KEY)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([CRECEIPT_1], b"")
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([b"junk"], KEY)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, start=b"junk"
            )

    def test_broken_chain_rejected(self):
        # The continuation receipt cannot start from the empty ledger.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([CRECEIPT_2], KEY)
        # A receipt cannot follow itself.
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_1, CRECEIPT_1], KEY
            )

    def test_tampered_receipt_rejected(self):
        tampered = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([tampered], KEY)

    def test_wrong_key_receipt_rejected(self):
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle([CRECEIPT_1], OTHER_KEY)

    def test_tampered_start_frontier_rejected(self):
        tampered = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, start=tampered
            )

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_stream_commit_receipt_bundle(
                [CRECEIPT_2], KEY, start=maxed
            )


class AuditStreamCommitReceiptBundleTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_stream_commit_receipt_bundle(BUNDLE_1, KEY), CFRONTIER_1
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle(BUNDLE_FULL, KEY),
            CFRONTIER_2,
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle(BUNDLE_2, KEY), CFRONTIER_2
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle(BUNDLE_SOLO, KEY),
            CFRONTIER_FULL,
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_stream_commit_receipt_bundle(BUNDLE_FULL.to_bytes(), KEY),
            CFRONTIER_2,
        )

    def test_type_contract(self):
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle(bad, KEY)
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle(BUNDLE_1, bad)

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(b"junk", KEY)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(BUNDLE_1, b"")
        blob = BUNDLE_1.to_bytes()
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(
                blob.replace(b",", b", "), KEY
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(BUNDLE_1, OTHER_KEY)

    def test_tampered_bundle_mac(self):
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(tampered, KEY)

    def test_tampered_start_frontier_mac(self):
        tampered_start = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        bundle = bundle_for(
            tampered_start.to_bytes(),
            (CRECEIPT_2.to_bytes(),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_tampered_end_frontier_mac(self):
        tampered_end = dataclasses.replace(CFRONTIER_2, mac=ZERO)
        bundle = bundle_for(
            b"",
            (CRECEIPT_1.to_bytes(), CRECEIPT_2.to_bytes()),
            tampered_end.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        bundle = bundle_for(
            b"", (tampered.to_bytes(),), CFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_broken_chain(self):
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

    def test_end_mismatch(self):
        # Valid MACs everywhere, but the replayed chain lands at
        # CFRONTIER_1 while the bundle claims CFRONTIER_2.
        bundle = bundle_for(
            b"", (CRECEIPT_1.to_bytes(),), CFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        bundle = bundle_for(
            maxed.to_bytes(),
            (CRECEIPT_2.to_bytes(),),
            CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle(bundle, KEY)


class StreamCommitReceiptAuditorAuditBundleTest(unittest.TestCase):
    def test_commits_whole_bundle_from_empty(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_1), auditor)
        self.assertEqual(auditor.state, CFRONTIER_1)
        self.assertEqual(auditor.state.to_bytes(), BUNDLE_1.end)

    def test_commits_full_chain_in_one_step(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, CFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_FULL.to_bytes()), auditor)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_continues_from_non_empty_frontier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_restarted_auditor_continues_from_bundle_start(self):
        first = StreamCommitReceiptAuditor(KEY)
        first.audit_bundle(BUNDLE_1)
        restored = StreamCommitReceiptAuditor(
            KEY, checkpoint=first.checkpoint.to_bytes()
        )
        restored.audit_bundle(BUNDLE_2)
        self.assertEqual(restored.state, CFRONTIER_2)

    def test_mixes_with_single_receipt_audit(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit(CRECEIPT_1, SBATCH_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, CFRONTIER_2)
        auditor2 = StreamCommitReceiptAuditor(KEY)
        auditor2.audit_bundle(BUNDLE_1)
        auditor2.audit(CRECEIPT_2, SBATCH_2)
        self.assertEqual(auditor2.state, CFRONTIER_2)

    def test_agrees_with_standalone_verifier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(
            auditor.state,
            audit_stream_commit_receipt_bundle(BUNDLE_FULL, KEY),
        )

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_empty_ledger_requires_empty_start(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_non_empty_ledger_requires_current_frontier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        # An empty-start bundle no longer chains onto the advanced
        # frontier.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_same_bundle_replay_is_rejected(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.state, before)

    def test_fork_from_other_start_rejected(self):
        # Advance the ledger through the one-commit fork, then present a
        # bundle starting from the two-commit frontier.
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_SOLO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, CFRONTIER_FULL)
        self.assertEqual(auditor.state.sequence, 1)

    def test_tampered_bundle_mac(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(tampered)
        self.assertIsNone(auditor.state)

    def test_wrong_key(self):
        auditor = StreamCommitReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_1)
        self.assertIsNone(auditor.state)

    def test_tampered_start_frontier_mac(self):
        tampered_start = dataclasses.replace(CFRONTIER_1, mac=ZERO)
        bundle = bundle_for(
            tampered_start.to_bytes(),
            (CRECEIPT_2.to_bytes(),),
            CFRONTIER_2.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_tampered_end_frontier_mac(self):
        tampered_end = dataclasses.replace(CFRONTIER_2, mac=ZERO)
        bundle = bundle_for(
            b"",
            (CRECEIPT_1.to_bytes(), CRECEIPT_2.to_bytes()),
            tampered_end.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        bundle = bundle_for(
            b"", (tampered.to_bytes(),), CFRONTIER_1.to_bytes()
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_end_mismatch(self):
        # Valid MACs everywhere, but the replayed chain lands at
        # CFRONTIER_1 while the bundle claims CFRONTIER_2.
        bundle = bundle_for(
            b"", (CRECEIPT_1.to_bytes(),), CFRONTIER_2.to_bytes()
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_failure_after_first_receipt_is_atomic(self):
        # The first receipt commits on the tentative frontier, the second
        # does not chain: nothing may be visible afterwards.
        bundle = bundle_for(
            b"",
            (CRECEIPT_1.to_bytes(), CRECEIPT_1.to_bytes()),
            CFRONTIER_2.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_sequence_overflow(self):
        maxed = commit_frontier_for(
            U64_MAX, SFRONTIER_1.to_bytes(), CDIGEST_1
        )
        bundle = bundle_for(
            maxed.to_bytes(),
            (CRECEIPT_2.to_bytes(),),
            CFRONTIER_2.to_bytes(),
        )
        auditor = StreamCommitReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIs(auditor.state, before)

    def test_failed_bundle_does_not_advance_then_recovers(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)
        auditor.audit_bundle(BUNDLE_1)
        self.assertEqual(auditor.state, CFRONTIER_1)

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
            threading.Thread(target=run, args=(BUNDLE_1,)),
            threading.Thread(target=run, args=(BUNDLE_SOLO,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertIn(
            auditor.state.end,
            (SFRONTIER_1.to_bytes(), SFRONTIER_2.to_bytes()),
        )

    def test_bundle_and_single_audit_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        commits, failures = [], []

        def run_bundle():
            try:
                auditor.audit_bundle(BUNDLE_1)
                commits.append("bundle")
            except ValueError:
                failures.append("bundle")

        def run_single():
            try:
                auditor.audit(CRECEIPT_1, SBATCH_1)
                commits.append("single")
            except ValueError:
                failures.append("single")

        threads = [
            threading.Thread(target=run_bundle),
            threading.Thread(target=run_single),
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
