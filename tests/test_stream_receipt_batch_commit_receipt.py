import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamReceiptAuditor,
    StreamReceiptBatch,
    StreamReceiptBatchCommitReceipt,
    StreamReceiptFrontier,
    _stream_receipt_batch_commit_receipt_content_bytes,
    _stream_receipt_batch_commit_receipt_mac,
    _stream_receipt_batch_mac,
    audit_stream_receipt_batch_commit_receipt,
    seal_stream_receipt_batch,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    ZERO,
)
from test_stream_receipt_frontier import (
    RECEIPT_1,
    RECEIPT_2,
    SFRONTIER_1,
    SFRONTIER_2,
    STREAM_1,
    STREAM_2,
)

PAIR_1 = (RECEIPT_1.to_bytes(), STREAM_1.to_bytes())
PAIR_2 = (RECEIPT_2.to_bytes(), STREAM_2.to_bytes())

SBATCH_1 = seal_stream_receipt_batch([PAIR_1], KEY)
SBATCH_2 = seal_stream_receipt_batch(
    [PAIR_2], KEY, checkpoint=SFRONTIER_1.to_bytes()
)
SBATCH_FULL = seal_stream_receipt_batch([PAIR_1, PAIR_2], KEY)


def commit_receipt_for(batch, key=KEY):
    placeholder = StreamReceiptBatchCommitReceipt(
        1,
        batch.start,
        hashlib.sha256(batch.to_bytes()).digest(),
        batch.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_receipt_batch_commit_receipt_mac(key, placeholder),
    )


CRECEIPT_1 = commit_receipt_for(SBATCH_1)
CRECEIPT_2 = commit_receipt_for(SBATCH_2)
CRECEIPT_FULL = commit_receipt_for(SBATCH_FULL)


class CommitReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = StreamReceiptBatchCommitReceipt(
            1,
            CRECEIPT_1.start,
            CRECEIPT_1.batch_digest,
            CRECEIPT_1.end,
            CRECEIPT_1.mac,
        )
        self.assertEqual(receipt, CRECEIPT_1)
        self.assertEqual(hash(receipt), hash(CRECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.batch_digest,
            hashlib.sha256(SBATCH_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, SFRONTIER_1.to_bytes())

    def test_version_contract(self):
        for bad in ("1", 1.0, True, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    bad, b"", ZERO, SFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (0, 2):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    bad, b"", ZERO, SFRONTIER_1.to_bytes(), ZERO
                )

    def test_start_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    1, bad, ZERO, SFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            StreamReceiptBatchCommitReceipt(
                1, b"\xff", ZERO, SFRONTIER_1.to_bytes(), ZERO
            )
        # b"" (no stream commit yet) is a valid start.
        StreamReceiptBatchCommitReceipt(
            1, b"", ZERO, SFRONTIER_1.to_bytes(), ZERO
        )

    def test_batch_digest_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    1, b"", bad, SFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    1, b"", bad, SFRONTIER_1.to_bytes(), ZERO
                )

    def test_end_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(1, b"", ZERO, bad, ZERO)
        for bad in (b"", b"\xff"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(1, b"", ZERO, bad, ZERO)

    def test_mac_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    1, b"", ZERO, SFRONTIER_1.to_bytes(), bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt(
                    1, b"", ZERO, SFRONTIER_1.to_bytes(), bad
                )


class CommitReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for receipt in (CRECEIPT_1, CRECEIPT_2, CRECEIPT_FULL):
            data = receipt.to_bytes()
            self.assertEqual(
                StreamReceiptBatchCommitReceipt.from_bytes(data), receipt
            )
            self.assertEqual(
                StreamReceiptBatchCommitReceipt.from_bytes(data).to_bytes(),
                data,
            )

    def test_canonical_shape(self):
        data = CRECEIPT_1.to_bytes()
        outer = json.loads(data)
        self.assertEqual(
            outer,
            [
                1,
                "",
                hashlib.sha256(SBATCH_1.to_bytes()).hexdigest(),
                SFRONTIER_1.to_bytes().hex(),
                CRECEIPT_1.mac.hex(),
            ],
        )
        self.assertEqual(data, json.dumps(outer, separators=(",", ":")).encode())

    def test_mac_covers_first_four_fields_with_domain_prefix(self):
        expected = hmac.new(
            KEY,
            b"NPBJ24"
            + _stream_receipt_batch_commit_receipt_content_bytes(CRECEIPT_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(CRECEIPT_1.mac, expected)

    def test_from_bytes_type_contract(self):
        for bad in (1, "ab", None, [b""], 1.0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical(self):
        data = CRECEIPT_1.to_bytes()
        outer = json.loads(data)
        # Formatted JSON with whitespace.
        with self.assertRaises(ValueError):
            StreamReceiptBatchCommitReceipt.from_bytes(
                json.dumps(outer, indent=2).encode()
            )
        # Uppercase hex.
        with self.assertRaises(ValueError):
            StreamReceiptBatchCommitReceipt.from_bytes(
                data.replace(
                    outer[2].encode(), outer[2].upper().encode()
                )
            )
        # Wrong field count.
        with self.assertRaises(ValueError):
            StreamReceiptBatchCommitReceipt.from_bytes(
                json.dumps(outer[:4]).encode()
            )
        # Not JSON at all.
        with self.assertRaises(ValueError):
            StreamReceiptBatchCommitReceipt.from_bytes(b"\xff")

    def test_from_bytes_verifies_no_mac(self):
        # A receipt with a garbage mac still parses: no MAC is checked.
        data = CRECEIPT_1.to_bytes()
        outer = json.loads(data)
        outer[4] = (ZERO).hex()
        record = StreamReceiptBatchCommitReceipt.from_bytes(
            json.dumps(outer, separators=(",", ":")).encode()
        )
        self.assertEqual(record.mac, ZERO)


class CommitBatchMethodTest(unittest.TestCase):
    def test_commit_batch_mints_receipt_and_advances(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_1)
        self.assertEqual(receipt, CRECEIPT_1)
        self.assertEqual(auditor.state, SFRONTIER_1)
        receipt = auditor.commit_batch(SBATCH_2)
        self.assertEqual(receipt, CRECEIPT_2)
        self.assertEqual(auditor.state, SFRONTIER_2)

    def test_commit_batch_accepts_canonical_bytes(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_FULL.to_bytes())
        self.assertEqual(receipt, CRECEIPT_FULL)
        self.assertEqual(auditor.state, SFRONTIER_2)

    def test_commit_batch_receipt_fields(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_1)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, SBATCH_1.start)
        self.assertEqual(
            receipt.batch_digest,
            hashlib.sha256(SBATCH_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, SBATCH_1.end)

    def test_commit_batch_matches_audit_batch_frontier(self):
        via_commit = StreamReceiptAuditor(KEY)
        via_commit.commit_batch(SBATCH_1)
        via_commit.commit_batch(SBATCH_2)
        via_audit = StreamReceiptAuditor(KEY)
        via_audit.audit_batch(SBATCH_FULL)
        self.assertEqual(via_commit.state, via_audit.state)

    def test_commit_batch_type_contract(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (1, "ab", None, [b""], 1.0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_commit_batch_failure_changes_no_state_and_mints_nothing(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (b"\xff", b"[]", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_batch(bad)
        with self.assertRaises(ValueError):
            auditor.commit_batch(SBATCH_2)  # start does not match
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(OTHER_KEY).commit_batch(SBATCH_1)
        forged = dataclasses.replace(
            SBATCH_1,
            mac=_stream_receipt_batch_commit_receipt_mac(
                OTHER_KEY, CRECEIPT_1
            ),
        )
        with self.assertRaises(ValueError):
            auditor.commit_batch(forged)
        self.assertIsNone(auditor.state)

    def test_commit_batch_replay_rejected(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.commit_batch(SBATCH_1)
        with self.assertRaises(ValueError):
            auditor.commit_batch(SBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(SBATCH_1)
        self.assertEqual(auditor.state, SFRONTIER_1)

    def test_commit_batch_linearizes_with_audit_batch(self):
        auditor = StreamReceiptAuditor(KEY)
        outcomes = []

        def work(fn, tag):
            try:
                fn()
                outcomes.append((tag, "ok"))
            except ValueError:
                outcomes.append((tag, "rejected"))

        threads = [
            threading.Thread(
                target=work,
                args=(lambda: auditor.commit_batch(SBATCH_FULL), "commit"),
            ),
            threading.Thread(
                target=work,
                args=(
                    lambda: auditor.audit_batch(SBATCH_FULL.to_bytes()),
                    "audit",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Exactly one wins the race; the loser's replay is rejected and
        # the committed frontier is never lost or rolled back.
        self.assertEqual(
            sorted(outcomes),
            [("audit", "ok"), ("commit", "rejected")]
            if outcomes[0][0] == "audit"
            else [("audit", "rejected"), ("commit", "ok")],
        )
        self.assertEqual(auditor.state, SFRONTIER_2)


class AuditCommitReceiptTest(unittest.TestCase):
    def test_accepts_object_and_canonical_bytes(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_FULL)
        end = audit_stream_receipt_batch_commit_receipt(
            receipt, SBATCH_FULL, KEY
        )
        self.assertIsInstance(end, StreamReceiptFrontier)
        self.assertEqual(end, SFRONTIER_2)
        again = audit_stream_receipt_batch_commit_receipt(
            receipt.to_bytes(), SBATCH_FULL.to_bytes(), KEY
        )
        self.assertEqual(again, end)

    def test_mixed_object_and_bytes_forms(self):
        end = audit_stream_receipt_batch_commit_receipt(
            CRECEIPT_1.to_bytes(), SBATCH_1, KEY
        )
        self.assertEqual(end, SFRONTIER_1)
        end = audit_stream_receipt_batch_commit_receipt(
            CRECEIPT_1, SBATCH_1.to_bytes(), KEY
        )
        self.assertEqual(end, SFRONTIER_1)

    def test_type_contract(self):
        for bad in (1, "ab", None, [b""], 1.0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_receipt_batch_commit_receipt(
                    bad, SBATCH_1, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_receipt_batch_commit_receipt(
                    CRECEIPT_1, bad, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_receipt_batch_commit_receipt(
                    CRECEIPT_1, SBATCH_1, bad
                )

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                CRECEIPT_1, SBATCH_1, b""
            )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                CRECEIPT_1, SBATCH_1, OTHER_KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(b"\xff", SBATCH_1, KEY)
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                CRECEIPT_1, b"\xff", KEY
            )

    def test_tampered_mac_rejected(self):
        forged = commit_receipt_for(SBATCH_1, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                forged, SBATCH_1, KEY
            )
        tampered = dataclasses.replace(CRECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                tampered, SBATCH_1, KEY
            )

    def test_receipt_batch_mismatch_rejected(self):
        # A valid receipt for a different batch does not attest this one.
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                CRECEIPT_2, SBATCH_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                CRECEIPT_1, SBATCH_2, KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                CRECEIPT_1, SBATCH_FULL, KEY
            )

    def test_tampered_digest_rejected(self):
        tampered = dataclasses.replace(
            CRECEIPT_1, batch_digest=ZERO
        )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                tampered, SBATCH_1, KEY
            )

    def test_tampered_endpoints_rejected(self):
        tampered = dataclasses.replace(
            CRECEIPT_2, start=SFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                tampered, SBATCH_2, KEY
            )
        tampered = dataclasses.replace(
            CRECEIPT_1, end=SFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(
                tampered, SBATCH_1, KEY
            )

    def test_tampered_batch_rejected(self):
        # A batch re-MAC'd with the wrong key fails full verification
        # even when the receipt itself is honestly minted over it.
        forged = dataclasses.replace(
            SBATCH_1, mac=_stream_receipt_batch_mac(OTHER_KEY, SBATCH_1)
        )
        receipt = commit_receipt_for(forged)
        with self.assertRaises(ValueError):
            audit_stream_receipt_batch_commit_receipt(receipt, forged, KEY)


if __name__ == "__main__":
    unittest.main()
