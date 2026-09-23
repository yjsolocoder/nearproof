import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeBatchReceiptFrontier,
    StreamReceipt,
    StreamReceiptAuditor,
    StreamReceiptFrontier,
    _stream_receipt_frontier_content_bytes,
    _stream_receipt_frontier_mac,
    _stream_receipt_frontier_next_digest,
    seal_stream,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_range_batch_receipt_frontier import (
    BFRONTIER_1,
    BFRONTIER_2,
)
from test_receipt_stream import (
    PAIR_1,
    PAIRS_12,
    stream_for,
)
from test_stream_receipt import (
    receipt_for,
)


def stream_frontier_for(sequence, end, digest, key=KEY):
    placeholder = StreamReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_receipt_frontier_mac(key, placeholder),
    )


# One-commit stream starting empty and ending at BFRONTIER_1.
STREAM_1 = stream_for(b"", PAIR_1, BFRONTIER_1.to_bytes())
RECEIPT_1 = receipt_for(STREAM_1)
# Continuation stream sealing the second pair from BFRONTIER_1.
STREAM_2 = seal_stream(
    PAIRS_12[1:2], KEY, checkpoint=BFRONTIER_1.to_bytes()
)
RECEIPT_2 = receipt_for(STREAM_2)

SDIGEST_1 = _stream_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_1.to_bytes()
)
SDIGEST_2 = _stream_receipt_frontier_next_digest(
    SDIGEST_1, 2, RECEIPT_2.to_bytes()
)
SFRONTIER_1 = stream_frontier_for(
    1, BFRONTIER_1.to_bytes(), SDIGEST_1
)
SFRONTIER_2 = stream_frontier_for(
    2, BFRONTIER_2.to_bytes(), SDIGEST_2
)


class StreamReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = StreamReceiptFrontier(
            1,
            1,
            BFRONTIER_1.to_bytes(),
            SDIGEST_1,
            SFRONTIER_1.mac,
        )
        self.assertEqual(frontier, SFRONTIER_1)
        self.assertEqual(hash(frontier), hash(SFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, BFRONTIER_1.to_bytes())
        self.assertEqual(frontier.digest, SDIGEST_1)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            SFRONTIER_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SFRONTIER_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(SFRONTIER_1, version=2)

    def test_sequence_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SFRONTIER_1, sequence=bad)
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SFRONTIER_1, sequence=bad)
        self.assertEqual(
            dataclasses.replace(
                SFRONTIER_1, sequence=U64_MAX
            ).sequence,
            U64_MAX,
        )

    def test_end_contract(self):
        for bad in (1, "x", None, bytearray(BFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SFRONTIER_1, end=bad)
        # end must be the canonical non-empty
        # RangeBatchReceiptFrontier encoding: not empty, not junk and
        # not a range frontier.
        from test_range_auditor_audit_batch import RFRONTIER_1

        for bad in (b"", b"junk", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SFRONTIER_1, end=bad)

    def test_digest_and_mac_contract(self):
        for name in ("digest", "mac"):
            for bad in (1, "x", None):
                with self.assertRaises(TypeError, msg=(name, bad)):
                    dataclasses.replace(SFRONTIER_1, **{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, bad)):
                    dataclasses.replace(SFRONTIER_1, **{name: bad})


class StreamReceiptFrontierEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,1,'
            b'"' + BFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + SDIGEST_1.hex().encode() + b'",'
            b'"' + SFRONTIER_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(SFRONTIER_1.to_bytes(), expected)

    def test_round_trip(self):
        for frontier in (SFRONTIER_1, SFRONTIER_2):
            blob = frontier.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamReceiptFrontier.from_bytes(blob), frontier
            )
            self.assertEqual(
                StreamReceiptFrontier.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = SFRONTIER_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            1,
            BFRONTIER_1.to_bytes().hex(),
            SDIGEST_1.hex(),
            SFRONTIER_1.mac.hex(),
        ]
        for index, bad_value in ((0, "1"), (1, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError):
                StreamReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = SFRONTIER_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            SFRONTIER_1.mac.hex().encode(),
            SFRONTIER_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the frontier MAC nor the nested end MACs are checked.
        tampered = dataclasses.replace(SFRONTIER_1, mac=ZERO)
        parsed = StreamReceiptFrontier.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_digest_chain_and_mac_schemes(self):
        expected_digest = hashlib.sha256(
            b"NPBJ22"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_1.to_bytes()
        ).digest()
        self.assertEqual(SDIGEST_1, expected_digest)
        expected_mac = hmac.new(
            KEY,
            b"NPBJ21"
            + _stream_receipt_frontier_content_bytes(SFRONTIER_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(SFRONTIER_1.mac, expected_mac)


class StreamReceiptAuditorConstructionTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(b"")

    def test_empty_checkpoint(self):
        self.assertIsNone(StreamReceiptAuditor(KEY).state)
        self.assertIsNone(
            StreamReceiptAuditor(KEY, checkpoint=None).state
        )

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        for checkpoint in (
            SFRONTIER_1,
            SFRONTIER_1.to_bytes(),
        ):
            auditor = StreamReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(auditor.state, SFRONTIER_1)

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [SFRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes(self):
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(KEY, checkpoint=b"junk")

    def test_checkpoint_own_frontier_mac_verified(self):
        tampered = dataclasses.replace(SFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_end_commit_frontier_mac_verified(self):
        # The nested range-batch receipt frontier's own NPBJ17 layer is
        # recomputed on load; re-MAC the outer layer so only it fails.
        bad_end = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        tampered = stream_frontier_for(
            1, bad_end.to_bytes(), SDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(OTHER_KEY, checkpoint=SFRONTIER_1)

    def test_state_is_read_only(self):
        with self.assertRaises(AttributeError):
            StreamReceiptAuditor(KEY).state = SFRONTIER_1


class StreamReceiptAuditTest(unittest.TestCase):
    def test_audit_returns_self_and_advances(self):
        auditor = StreamReceiptAuditor(KEY)
        self.assertIs(auditor.audit(RECEIPT_1, STREAM_1), auditor)
        self.assertEqual(auditor.state, SFRONTIER_1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, BFRONTIER_1.to_bytes())
        self.assertEqual(auditor.state.digest, SDIGEST_1)

    def test_chain_advances_sequence_end_and_digest(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, STREAM_1)
        auditor.audit(RECEIPT_2, STREAM_2)
        self.assertEqual(auditor.state, SFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.end, BFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state.digest, SDIGEST_2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1.to_bytes(), STREAM_1.to_bytes())
        self.assertEqual(auditor.state, SFRONTIER_1)
        auditor.audit(RECEIPT_2, STREAM_2)
        self.assertEqual(auditor.state, SFRONTIER_2)

    def test_restart_from_checkpoint(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, STREAM_1)
        blob = auditor.state.to_bytes()
        restored = StreamReceiptAuditor(KEY, checkpoint=blob)
        restored.audit(RECEIPT_2, STREAM_2)
        self.assertEqual(restored.state, SFRONTIER_2)

    def test_first_commit_must_start_empty(self):
        # A stream continuing from BFRONTIER_1 cannot be the first
        # commit of a fresh ledger.
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, STREAM_2)
        self.assertIsNone(auditor.state)

    def test_replayed_commit_rejected(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, STREAM_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, STREAM_1)
        self.assertIs(auditor.state, before)

    def test_receipt_stream_pair_mismatch_rejected(self):
        # After the first commit, a receipt for the continuation cannot
        # be audited against the first stream, nor the genesis receipt
        # against the continuation: endpoints or replay must fail.
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(RECEIPT_1, STREAM_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, STREAM_1)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, STREAM_2)
        self.assertIs(auditor.state, before)

    def test_tampered_receipt_rejected(self):
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                dataclasses.replace(RECEIPT_1, mac=ZERO), STREAM_1
            )
        self.assertIsNone(auditor.state)

    def test_broken_stream_rejected(self):
        # A structurally valid receipt does not rescue a stream whose
        # carried chain does not replay to the receipt end.
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_1, STREAM_2)
        self.assertIsNone(auditor.state)

    def test_wrong_argument_type(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (1, "x", None, [RECEIPT_1], (RECEIPT_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, STREAM_1)
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, STREAM_1)
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(RECEIPT_1, bad)
        self.assertIsNone(auditor.state)

    def test_failed_audit_does_not_advance_then_recovers(self):
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, STREAM_2)
        self.assertIsNone(auditor.state)
        auditor.audit(RECEIPT_1, STREAM_1)
        self.assertEqual(auditor.state, SFRONTIER_1)

    def test_sequence_overflow(self):
        maxed = stream_frontier_for(
            U64_MAX, BFRONTIER_1.to_bytes(), SDIGEST_1
        )
        auditor = StreamReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_2, STREAM_2)
        self.assertIs(auditor.state, before)

    def test_competing_commits_linearize(self):
        auditor = StreamReceiptAuditor(KEY)
        commits, failures = [], []

        def run(receipt, stream):
            try:
                auditor.audit(receipt, stream)
                commits.append(receipt)
            except ValueError:
                failures.append(receipt)

        threads = [
            threading.Thread(
                target=run, args=(RECEIPT_1, STREAM_1)
            ),
            threading.Thread(
                target=run, args=(RECEIPT_1, STREAM_1)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(commits), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, BFRONTIER_1.to_bytes())


if __name__ == "__main__":
    unittest.main()
