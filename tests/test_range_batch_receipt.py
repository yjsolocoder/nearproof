import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeAuditor,
    RangeBatchReceipt,
    RangeFrontier,
    _range_batch_receipt_content_bytes,
    _range_batch_receipt_mac,
    _range_receipt_batch_mac,
    audit_batch_receipt,
)
from test_range_receipt_batch import (
    CHAIN,
    KEY,
    OTHER_KEY,
    RANGE_1,
    RBATCH_1,
    RBATCH_2,
    RBATCH_FULL,
    RECEIPT_R1,
    RFRONTIER_1,
    RFRONTIER_2,
    ZERO,
)


def batch_receipt_for(batch, start=None, end=None, key=KEY):
    placeholder = RangeBatchReceipt(
        1,
        batch.start if start is None else start,
        hashlib.sha256(batch.to_bytes()).digest(),
        batch.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_range_batch_receipt_mac(key, placeholder)
    )


COMMIT_FULL = batch_receipt_for(RBATCH_FULL)
COMMIT_1 = batch_receipt_for(RBATCH_1)
COMMIT_2 = batch_receipt_for(RBATCH_2)


class BatchReceiptFieldContractTest(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(COMMIT_FULL.version, 1)
        self.assertEqual(COMMIT_FULL.start, b"")
        self.assertEqual(
            COMMIT_FULL.digest,
            hashlib.sha256(RBATCH_FULL.to_bytes()).digest(),
        )
        self.assertEqual(COMMIT_FULL.end, RBATCH_FULL.end)
        self.assertEqual(len(COMMIT_FULL.digest), 32)
        self.assertEqual(len(COMMIT_FULL.mac), 32)
        self.assertEqual(COMMIT_2.start, RFRONTIER_1.to_bytes())

    def test_positional_construction_and_equality(self):
        clone = RangeBatchReceipt(
            1,
            COMMIT_FULL.start,
            COMMIT_FULL.digest,
            COMMIT_FULL.end,
            COMMIT_FULL.mac,
        )
        self.assertEqual(clone, COMMIT_FULL)
        self.assertEqual(hash(clone), hash(COMMIT_FULL))

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            COMMIT_FULL.version = 2

    def test_version_contract(self):
        with self.assertRaises(TypeError):
            RangeBatchReceipt(
                "1", b"", COMMIT_FULL.digest, COMMIT_FULL.end, ZERO
            )
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                2, b"", COMMIT_FULL.digest, COMMIT_FULL.end, ZERO
            )

    def test_start_contract(self):
        with self.assertRaises(TypeError):
            RangeBatchReceipt(
                1, 0, COMMIT_FULL.digest, COMMIT_FULL.end, ZERO
            )
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                1, b"junk", COMMIT_FULL.digest, COMMIT_FULL.end, ZERO
            )

    def test_digest_contract(self):
        with self.assertRaises(TypeError):
            RangeBatchReceipt(1, b"", "d", COMMIT_FULL.end, ZERO)
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                1, b"", b"\x00" * 31, COMMIT_FULL.end, ZERO
            )

    def test_end_contract(self):
        with self.assertRaises(TypeError):
            RangeBatchReceipt(1, b"", COMMIT_FULL.digest, 0, ZERO)
        with self.assertRaises(ValueError):
            RangeBatchReceipt(1, b"", COMMIT_FULL.digest, b"", ZERO)

    def test_mac_contract(self):
        with self.assertRaises(TypeError):
            RangeBatchReceipt(
                1, b"", COMMIT_FULL.digest, COMMIT_FULL.end, "mac"
            )
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                1,
                b"",
                COMMIT_FULL.digest,
                COMMIT_FULL.end,
                b"\x00",
            )


class BatchReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for receipt in (COMMIT_1, COMMIT_2, COMMIT_FULL):
            encoded = receipt.to_bytes()
            self.assertIsInstance(encoded, bytes)
            self.assertEqual(
                RangeBatchReceipt.from_bytes(encoded), receipt
            )

    def test_encoding_shape(self):
        decoded = json.loads(COMMIT_FULL.to_bytes())
        self.assertEqual(decoded[0], 1)
        self.assertEqual(decoded[1], "")
        self.assertEqual(
            decoded[2],
            hashlib.sha256(RBATCH_FULL.to_bytes()).hexdigest(),
        )
        self.assertEqual(decoded[3], RBATCH_FULL.end.hex())
        self.assertEqual(decoded[4], COMMIT_FULL.mac.hex())
        self.assertEqual(
            COMMIT_FULL.to_bytes(),
            json.dumps(decoded, separators=(",", ":")).encode("utf-8"),
        )

    def test_non_empty_start_encodes_as_lowercase_hex(self):
        decoded = json.loads(COMMIT_2.to_bytes())
        self.assertEqual(decoded[1], RFRONTIER_1.to_bytes().hex())

    def test_from_bytes_type_contract(self):
        with self.assertRaises(TypeError):
            RangeBatchReceipt.from_bytes("x")
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(b"not json")
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(b"[1,2,3]")

    def test_from_bytes_rejects_non_canonical(self):
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                COMMIT_FULL.to_bytes().replace(b",", b", ", 1)
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[0] = 2
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[1] = "AB"
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[2] = doc[2].upper()
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[4] = doc[4].upper()
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )
        doc = json.loads(COMMIT_FULL.to_bytes())
        doc[2] = "ab"
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                json.dumps(doc, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_verifies_no_mac(self):
        # A receipt MAC'd with another key still parses: from_bytes checks
        # the field contract only, never any MAC.
        foreign = batch_receipt_for(RBATCH_FULL, key=OTHER_KEY)
        parsed = RangeBatchReceipt.from_bytes(foreign.to_bytes())
        self.assertEqual(parsed, foreign)


class BatchReceiptMacTest(unittest.TestCase):
    def test_mac_is_npbj16_hmac(self):
        for receipt in (COMMIT_1, COMMIT_2, COMMIT_FULL):
            content = json.loads(
                _range_batch_receipt_content_bytes(receipt)
            )
            expected = hmac.new(
                KEY,
                b"NPBJ16"
                + json.dumps(content, separators=(",", ":")).encode(),
                hashlib.sha256,
            ).digest()
            self.assertEqual(receipt.mac, expected)
            self.assertEqual(
                receipt.mac, _range_batch_receipt_mac(KEY, receipt)
            )
            self.assertEqual(len(receipt.mac), 32)

    def test_mac_covers_only_first_four_fields(self):
        content = json.loads(
            _range_batch_receipt_content_bytes(COMMIT_FULL)
        )
        self.assertEqual(len(content), 4)
        self.assertEqual(
            content,
            [
                1,
                COMMIT_FULL.start.hex(),
                COMMIT_FULL.digest.hex(),
                COMMIT_FULL.end.hex(),
            ],
        )


class AuditorCommitBatchTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_batch(RBATCH_FULL)
        self.assertIsInstance(receipt, RangeBatchReceipt)
        self.assertEqual(receipt, COMMIT_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_commit_accepts_canonical_bytes(self):
        receipt = RangeAuditor(KEY).commit_batch(RBATCH_FULL.to_bytes())
        self.assertEqual(receipt, COMMIT_FULL)

    def test_chained_commits(self):
        auditor = RangeAuditor(KEY)
        first = auditor.commit_batch(RBATCH_1)
        self.assertEqual(first, COMMIT_1)
        self.assertEqual(auditor.state, RFRONTIER_1)
        second = auditor.commit_batch(RBATCH_2)
        self.assertEqual(second, COMMIT_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_commit_matches_audit_batch_record_frontier(self):
        committed = RangeAuditor(KEY)
        committed.commit_batch(RBATCH_1)
        committed.commit_batch(RBATCH_2)
        recorded = RangeAuditor(KEY)
        recorded.audit_batch_record(RBATCH_FULL)
        via_batch = RangeAuditor(KEY)
        via_batch.audit_batch(CHAIN)
        self.assertEqual(committed.state, recorded.state)
        self.assertEqual(committed.state, via_batch.state)

    def test_commit_digest_is_sha256_of_canonical_batch(self):
        receipt = RangeAuditor(KEY).commit_batch(RBATCH_FULL)
        self.assertEqual(
            receipt.digest,
            hashlib.sha256(RBATCH_FULL.to_bytes()).digest(),
        )

    def test_commit_type_contract(self):
        auditor = RangeAuditor(KEY)
        for bad in (
            1,
            "x",
            None,
            [RBATCH_FULL],
            (RBATCH_FULL,),
            object(),
            True,
            False,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_commit_malformed_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (
            b"junk",
            b"[1,2,3]",
            b"",
            RBATCH_FULL.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_failed_commit_does_not_advance(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_batch(
                dataclasses.replace(RBATCH_FULL, mac=ZERO)
            )
        self.assertIsNone(auditor.state)
        # The auditor still commits a correct batch afterwards, and the
        # receipt is minted only then.
        receipt = auditor.commit_batch(RBATCH_FULL)
        self.assertEqual(receipt, COMMIT_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_failed_chained_commit_keeps_prior_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.commit_batch(RBATCH_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_batch(
                dataclasses.replace(RBATCH_2, mac=ZERO)
            )
        self.assertIs(auditor.state, before)

    def test_replayed_commit_rejected_on_start(self):
        auditor = RangeAuditor(KEY)
        auditor.commit_batch(RBATCH_1)
        with self.assertRaises(ValueError):
            auditor.commit_batch(RBATCH_1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_wrong_key_rejected_without_state_change(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).commit_batch(RBATCH_FULL)
        self.assertIsNone(auditor.state)

    def test_restart_from_checkpoint_then_commit(self):
        first = RangeAuditor(KEY)
        first.commit_batch(RBATCH_1)
        restored = RangeAuditor(
            KEY, checkpoint=first.state.to_bytes()
        )
        second = restored.commit_batch(RBATCH_2)
        self.assertEqual(restored.state, RFRONTIER_2)
        self.assertEqual(second, COMMIT_2)

    def test_commit_shares_lock_with_record_batch_and_audit(self):
        auditor = RangeAuditor(KEY)
        successes = []
        failures = []
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
                    lambda: auditor.commit_batch(RBATCH_FULL),
                    "commit",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit_batch_record(RBATCH_1),
                    "record",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_R1, RANGE_1),
                    "one",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        self.assertIn(auditor.state, (RFRONTIER_1, RFRONTIER_2))


class AuditBatchReceiptTest(unittest.TestCase):
    def test_audit_returns_end_frontier(self):
        frontier = audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, KEY)
        self.assertIsInstance(frontier, RangeFrontier)
        self.assertEqual(frontier, RFRONTIER_2)
        self.assertEqual(frontier.to_bytes(), RBATCH_FULL.end)

    def test_audit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_batch_receipt(
                COMMIT_FULL.to_bytes(), RBATCH_FULL.to_bytes(), KEY
            ),
            audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, KEY),
        )

    def test_audit_verifies_chained_batches(self):
        self.assertEqual(
            audit_batch_receipt(COMMIT_1, RBATCH_1, KEY), RFRONTIER_1
        )
        self.assertEqual(
            audit_batch_receipt(COMMIT_2, RBATCH_2, KEY), RFRONTIER_2
        )

    def test_audit_type_contract(self):
        with self.assertRaises(TypeError):
            audit_batch_receipt(42, RBATCH_FULL, KEY)
        with self.assertRaises(TypeError):
            audit_batch_receipt(COMMIT_FULL, 42, KEY)
        with self.assertRaises(TypeError):
            audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, "k")

    def test_audit_malformed_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(b"junk", RBATCH_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_batch_receipt(COMMIT_FULL, b"junk", KEY)

    def test_audit_key_contract(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, b"")
        with self.assertRaises(ValueError):
            audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, OTHER_KEY)

    def test_audit_rejects_bad_mac(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(
                dataclasses.replace(COMMIT_FULL, mac=ZERO),
                RBATCH_FULL,
                KEY,
            )

    def test_audit_rejects_bad_digest(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(
                dataclasses.replace(COMMIT_FULL, digest=ZERO),
                RBATCH_FULL,
                KEY,
            )

    def test_audit_rejects_endpoint_mismatch(self):
        # A receipt over RBATCH_1 cannot attest the full batch and
        # vice-versa: the digest and the endpoints both disagree.
        with self.assertRaises(ValueError):
            audit_batch_receipt(COMMIT_1, RBATCH_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_batch_receipt(COMMIT_FULL, RBATCH_1, KEY)

    def test_audit_rejects_start_mismatch_with_consistent_mac(self):
        # Re-mint COMMIT_2's MAC over a forged empty start: the NPBJ16 MAC
        # is consistent, but the receipt start no longer matches the
        # batch start.
        forged = dataclasses.replace(COMMIT_2, start=b"")
        forged = dataclasses.replace(
            forged, mac=_range_batch_receipt_mac(KEY, forged)
        )
        with self.assertRaises(ValueError):
            audit_batch_receipt(forged, RBATCH_2, KEY)

    def test_audit_rejects_end_mismatch_with_consistent_mac(self):
        # Forge a receipt with a consistent NPBJ16 MAC and the correct
        # batch digest, but pointing at a different valid endpoint
        # (RFRONTIER_1) than the batch actually ends at (RFRONTIER_2).
        forged = dataclasses.replace(
            COMMIT_2, end=RFRONTIER_1.to_bytes()
        )
        forged = dataclasses.replace(
            forged,
            digest=hashlib.sha256(RBATCH_2.to_bytes()).digest(),
        )
        forged = dataclasses.replace(
            forged, mac=_range_batch_receipt_mac(KEY, forged)
        )
        with self.assertRaises(ValueError):
            audit_batch_receipt(forged, RBATCH_2, KEY)

    def test_audit_rejects_tampered_carried_batch(self):
        # A consistent NPBJ16 receipt over a batch whose own NPBJ15 MAC
        # was zeroed fails the batch verification underneath.
        with self.assertRaises(ValueError):
            audit_batch_receipt(
                COMMIT_FULL,
                dataclasses.replace(RBATCH_FULL, mac=ZERO),
                KEY,
            )

    def test_audit_rejects_resealed_batch_over_different_content(self):
        # Re-sealing an unchanged batch verifies...
        resealed = dataclasses.replace(
            RBATCH_FULL,
            mac=_range_receipt_batch_mac(KEY, RBATCH_FULL),
        )
        self.assertEqual(
            audit_batch_receipt(COMMIT_FULL, resealed, KEY), RFRONTIER_2
        )

    def test_audit_is_pure_and_deterministic(self):
        first = audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, KEY)
        second = audit_batch_receipt(COMMIT_FULL, RBATCH_FULL, KEY)
        self.assertEqual(first, second)
        # It leaves no auditor state behind.
        self.assertIsNone(RangeAuditor(KEY).state)


if __name__ == "__main__":
    unittest.main()
