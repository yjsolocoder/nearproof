import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamReceiptAuditor,
    StreamReceiptBatchCommitReceipt,
    StreamReceiptFrontier,
    _stream_receipt_batch_commit_receipt_content_bytes,
    _stream_receipt_batch_commit_receipt_mac,
    audit_batch_commit_receipt,
    audit_stream_batch_commit_receipt,
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
    stream_frontier_for,
)
from test_range_batch_receipt_frontier import (
    BFRONTIER_1,
)

SBATCH_1 = seal_stream_receipt_batch(
    [(RECEIPT_1.to_bytes(), STREAM_1.to_bytes())], KEY
)
SBATCH_2 = seal_stream_receipt_batch(
    [(RECEIPT_2.to_bytes(), STREAM_2.to_bytes())],
    KEY,
    checkpoint=SFRONTIER_1.to_bytes(),
)
SBATCH_FULL = seal_stream_receipt_batch(
    [
        (RECEIPT_1.to_bytes(), STREAM_1.to_bytes()),
        (RECEIPT_2.to_bytes(), STREAM_2.to_bytes()),
    ],
    KEY,
)


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


RECEIPT_SB1 = commit_receipt_for(SBATCH_1)
RECEIPT_SB2 = commit_receipt_for(SBATCH_2)
RECEIPT_SBFULL = commit_receipt_for(SBATCH_FULL)


class StreamReceiptBatchCommitReceiptFieldTest(unittest.TestCase):
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

    def test_positional_construction_and_field_equality(self):
        receipt = StreamReceiptBatchCommitReceipt(
            1,
            SBATCH_FULL.start,
            hashlib.sha256(SBATCH_FULL.to_bytes()).digest(),
            SBATCH_FULL.end,
            _stream_receipt_batch_commit_receipt_mac(KEY, RECEIPT_SBFULL),
        )
        self.assertEqual(receipt, RECEIPT_SBFULL)
        self.assertEqual(
            dataclasses.astuple(receipt),
            dataclasses.astuple(RECEIPT_SBFULL),
        )
        self.assertNotEqual(
            receipt, dataclasses.replace(receipt, mac=b"\x01" * 32)
        )
        self.assertEqual(hash(receipt), hash(RECEIPT_SBFULL))

    def test_frozen_and_no_key_material(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_SB1.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_SB1.mac = b""
        self.assertIsNone(getattr(RECEIPT_SB1, "key", None))


class StreamReceiptBatchCommitReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for receipt in (RECEIPT_SB1, RECEIPT_SB2, RECEIPT_SBFULL):
            data = receipt.to_bytes()
            self.assertIsInstance(data, bytes)
            self.assertEqual(
                StreamReceiptBatchCommitReceipt.from_bytes(data), receipt
            )

    def test_encoding_shape(self):
        data = RECEIPT_SB1.to_bytes()
        outer = json.loads(data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 5)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], RECEIPT_SB1.start.hex())
        self.assertEqual(outer[2], RECEIPT_SB1.batch_digest.hex())
        self.assertEqual(outer[3], RECEIPT_SB1.end.hex())
        self.assertEqual(outer[4], RECEIPT_SB1.mac.hex())
        # Compact: no whitespace, bytes as lowercase hex.
        self.assertNotIn(b" ", data)
        self.assertNotIn(b"\n", data)
        # C is exactly the first four fields, compact and with no length
        # prefix; the MAC prefix is concatenated directly.
        self.assertEqual(
            _stream_receipt_batch_commit_receipt_content_bytes(RECEIPT_SB1),
            json.dumps(
                [outer[0], outer[1], outer[2], outer[3]],
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        expected_mac = hmac.new(
            KEY,
            b"NPBJ24"
            + _stream_receipt_batch_commit_receipt_content_bytes(
                RECEIPT_SB1
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_SB1.mac, expected_mac)

    def test_uppercase_hex_rejected(self):
        data = RECEIPT_SB1.to_bytes()
        outer = json.loads(data)
        outer[2] = outer[2].upper()
        with self.assertRaises(ValueError):
            StreamReceiptBatchCommitReceipt.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_type_contract(self):
        for bad in ("x", 1, None, [RECEIPT_SB1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (
            b"junk",
            b"[]",
            b"[1]",
            json.dumps(
                [1, "", ZERO.hex(), SFRONTIER_1.to_bytes().hex(), ZERO.hex(), 0],
                separators=(",", ":"),
            ).encode("utf-8"),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            RECEIPT_SB1.start.hex(),
            RECEIPT_SB1.batch_digest.hex(),
            RECEIPT_SB1.end.hex(),
            RECEIPT_SB1.mac.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError):
                StreamReceiptBatchCommitReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical(self):
        data = RECEIPT_SB1.to_bytes()
        outer = json.loads(data)
        variants = (
            json.dumps(outer).encode("utf-8"),
            json.dumps(outer, indent=1).encode("utf-8"),
            b" " + data,
            data + b" ",
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptBatchCommitReceipt.from_bytes(bad)

    def test_from_bytes_does_not_verify_mac(self):
        forged = dataclasses.replace(RECEIPT_SB1, mac=ZERO)
        decoded = StreamReceiptBatchCommitReceipt.from_bytes(
            forged.to_bytes()
        )
        self.assertEqual(decoded, forged)


class CommitBatchTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_FULL)
        self.assertIsInstance(receipt, StreamReceiptBatchCommitReceipt)
        self.assertEqual(receipt, RECEIPT_SBFULL)
        self.assertEqual(auditor.state, SFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.batch_digest,
            hashlib.sha256(SBATCH_FULL.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, SFRONTIER_2.to_bytes())
        self.assertEqual(
            receipt.mac,
            _stream_receipt_batch_commit_receipt_mac(KEY, receipt),
        )

    def test_commit_accepts_canonical_bytes(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_FULL.to_bytes())
        self.assertEqual(receipt, RECEIPT_SBFULL)
        self.assertEqual(auditor.state, SFRONTIER_2)

    def test_commit_single_item_batch(self):
        auditor = StreamReceiptAuditor(KEY)
        receipt = auditor.commit_batch(SBATCH_1)
        self.assertEqual(receipt, RECEIPT_SB1)
        self.assertEqual(auditor.state, SFRONTIER_1)

    def test_chained_commits(self):
        auditor = StreamReceiptAuditor(KEY)
        first = auditor.commit_batch(SBATCH_1)
        self.assertEqual(first, RECEIPT_SB1)
        second = auditor.commit_batch(SBATCH_2)
        self.assertEqual(second, RECEIPT_SB2)
        self.assertEqual(auditor.state, SFRONTIER_2)

    def test_commit_matches_audit_batch(self):
        via_commit = StreamReceiptAuditor(KEY)
        via_commit.commit_batch(SBATCH_1)
        via_commit.commit_batch(SBATCH_2)
        via_audit = StreamReceiptAuditor(KEY)
        via_audit.audit_batch(SBATCH_1)
        via_audit.audit_batch(SBATCH_2)
        self.assertEqual(via_commit.state, via_audit.state)

    def test_commit_type_contract(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (1, "x", None, [SBATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]", b"", SBATCH_FULL.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_failed_commit_changes_nothing_and_mints_nothing(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit_batch(SBATCH_1)
        before = auditor.state
        # SBATCH_FULL starts from the empty frontier: it cannot extend
        # SFRONTIER_1, so the commit fails and no receipt is minted.
        with self.assertRaises(ValueError):
            auditor.commit_batch(SBATCH_FULL)
        self.assertIs(auditor.state, before)
        auditor.commit_batch(SBATCH_2)
        self.assertEqual(auditor.state, SFRONTIER_2)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(OTHER_KEY).commit_batch(SBATCH_FULL)

    def test_batch_mac_mismatch_rejected(self):
        forged = dataclasses.replace(SBATCH_FULL, mac=ZERO)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(KEY).commit_batch(forged)

    def test_replay_rejected_without_state_change(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.commit_batch(SBATCH_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_batch(SBATCH_FULL)
        self.assertIs(auditor.state, before)

    def test_concurrent_commits_linearize(self):
        auditor = StreamReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        # All three actions start from the empty frontier, so exactly one
        # can win regardless of lock-acquisition order.
        threads = [
            threading.Thread(
                target=run,
                args=(lambda: auditor.commit_batch(SBATCH_FULL), "full"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.commit_batch(SBATCH_1), "one"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_1, STREAM_1),
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
        winner = successes[0]
        if winner == "full":
            self.assertEqual(auditor.state, SFRONTIER_2)
        else:
            self.assertEqual(auditor.state, SFRONTIER_1)


class AuditBatchCommitReceiptTest(unittest.TestCase):
    def test_accepts_objects_and_canonical_bytes(self):
        final = audit_batch_commit_receipt(
            RECEIPT_SBFULL, SBATCH_FULL, KEY
        )
        self.assertEqual(final, SFRONTIER_2)
        self.assertIsInstance(final, StreamReceiptFrontier)
        again = audit_batch_commit_receipt(
            RECEIPT_SBFULL.to_bytes(), SBATCH_FULL.to_bytes(), KEY
        )
        self.assertEqual(again, SFRONTIER_2)

    def test_alias_is_same_function(self):
        self.assertIs(
            audit_stream_batch_commit_receipt, audit_batch_commit_receipt
        )

    def test_single_and_chained_batches(self):
        self.assertEqual(
            audit_batch_commit_receipt(RECEIPT_SB1, SBATCH_1, KEY),
            SFRONTIER_1,
        )
        self.assertEqual(
            audit_batch_commit_receipt(RECEIPT_SB2, SBATCH_2, KEY),
            SFRONTIER_2,
        )

    def test_type_contract(self):
        for bad_r in (1, "x", None, [RECEIPT_SBFULL], object()):
            with self.assertRaises(TypeError, msg=repr(bad_r)):
                audit_batch_commit_receipt(bad_r, SBATCH_FULL, KEY)
        for bad_b in (1, "x", None, [SBATCH_FULL], object()):
            with self.assertRaises(TypeError, msg=repr(bad_b)):
                audit_batch_commit_receipt(RECEIPT_SBFULL, bad_b, KEY)
        for bad_key in (1, "x", None, [KEY], object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                audit_batch_commit_receipt(
                    RECEIPT_SBFULL, SBATCH_FULL, bad_key
                )

    def test_empty_key_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(RECEIPT_SBFULL, SBATCH_FULL, b"")

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_batch_commit_receipt(bad, SBATCH_FULL, KEY)
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_batch_commit_receipt(RECEIPT_SBFULL, bad, KEY)

    def test_tampered_mac_rejected(self):
        forged = dataclasses.replace(RECEIPT_SBFULL, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(forged, SBATCH_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(
                forged.to_bytes(), SBATCH_FULL, KEY
            )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(
                RECEIPT_SBFULL, SBATCH_FULL, OTHER_KEY
            )

    def test_tampered_digest_rejected(self):
        forged = dataclasses.replace(RECEIPT_SBFULL, batch_digest=ZERO)
        signed = dataclasses.replace(
            forged,
            mac=_stream_receipt_batch_commit_receipt_mac(KEY, forged),
        )
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(signed, SBATCH_FULL, KEY)

    def test_tampered_start_rejected(self):
        # A structurally valid StreamReceiptFrontier different from the
        # batch's declared start; the receipt MAC is recomputed so only
        # the endpoint comparison can fail.
        other_frontier = stream_frontier_for(
            1, BFRONTIER_1.to_bytes(), b"\x02" * 32
        )
        forged = dataclasses.replace(
            RECEIPT_SBFULL, start=other_frontier.to_bytes()
        )
        signed = dataclasses.replace(
            forged,
            mac=_stream_receipt_batch_commit_receipt_mac(KEY, forged),
        )
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(signed, SBATCH_FULL, KEY)

    def test_tampered_end_rejected(self):
        forged = dataclasses.replace(
            RECEIPT_SBFULL, end=SFRONTIER_1.to_bytes()
        )
        signed = dataclasses.replace(
            forged,
            mac=_stream_receipt_batch_commit_receipt_mac(KEY, forged),
        )
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(signed, SBATCH_FULL, KEY)

    def test_receipt_batch_mismatch_rejected(self):
        # RECEIPT_SB1 attests SBATCH_1, not SBATCH_2.
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(RECEIPT_SB1, SBATCH_2, KEY)
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(RECEIPT_SB2, SBATCH_1, KEY)

    def test_tampered_batch_rejected(self):
        forged_batch = dataclasses.replace(
            SBATCH_FULL, mac=_zero_padded(SBATCH_FULL.mac)
        )
        with self.assertRaises(ValueError):
            audit_batch_commit_receipt(
                RECEIPT_SBFULL, forged_batch, KEY
            )

    def test_replayed_batch_rejected_by_auditor(self):
        # The stateless check is pure, but committing the same batch
        # twice against one auditor fails on the start match.
        auditor = StreamReceiptAuditor(KEY)
        auditor.commit_batch(SBATCH_1)
        with self.assertRaises(ValueError):
            auditor.audit_batch(SBATCH_1)


def _zero_padded(mac):
    return bytes(mac[i] ^ 1 for i in range(32))


if __name__ == "__main__":
    unittest.main()
