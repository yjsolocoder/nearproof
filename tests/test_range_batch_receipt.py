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
    RangeReceiptBatch,
    _range_batch_receipt_content_bytes,
    _range_batch_receipt_mac,
    _range_receipt_batch_mac,
    audit_batch_receipt,
    seal_range_receipt_batch,
)
from test_range_auditor_audit_batch import (
    CHAIN,
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RANGE_1,
    RANGE_FROM_CP,
    RDIGEST_1,
    RECEIPT_R1,
    RECEIPT_RCP,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    range_frontier_for,
)

RBATCH_1 = seal_range_receipt_batch([(RECEIPT_R1, RANGE_1)], KEY)
RBATCH_2 = seal_range_receipt_batch(
    [(RECEIPT_RCP, RANGE_FROM_CP)], KEY, checkpoint=RFRONTIER_1
)
RBATCH_FULL = seal_range_receipt_batch(CHAIN, KEY)


def batch_receipt_for(batch, key=KEY):
    placeholder = RangeBatchReceipt(
        1,
        batch.start,
        hashlib.sha256(batch.to_bytes()).digest(),
        batch.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_range_batch_receipt_mac(key, placeholder)
    )


RECEIPT_B1 = batch_receipt_for(RBATCH_1)
RECEIPT_B2 = batch_receipt_for(RBATCH_2)
RECEIPT_BFULL = batch_receipt_for(RBATCH_FULL)


class RangeBatchReceiptFieldTest(unittest.TestCase):
    def test_version_contract(self):
        for bad in ("1", 1.0, True, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceipt(
                    bad, b"", ZERO, RFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                2, b"", ZERO, RFRONTIER_1.to_bytes(), ZERO
            )
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                0, b"", ZERO, RFRONTIER_1.to_bytes(), ZERO
            )

    def test_start_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceipt(
                    1, bad, ZERO, RFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            RangeBatchReceipt(
                1, b"\xff", ZERO, RFRONTIER_1.to_bytes(), ZERO
            )
        # b"" (no receipt yet) is a valid start.
        RangeBatchReceipt(1, b"", ZERO, RFRONTIER_1.to_bytes(), ZERO)

    def test_digest_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceipt(
                    1, b"", bad, RFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceipt(
                    1, b"", bad, RFRONTIER_1.to_bytes(), ZERO
                )

    def test_end_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceipt(1, b"", ZERO, bad, ZERO)
        for bad in (b"", b"\xff", CFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceipt(1, b"", ZERO, bad, ZERO)

    def test_mac_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceipt(
                    1, b"", ZERO, RFRONTIER_1.to_bytes(), bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceipt(
                    1, b"", ZERO, RFRONTIER_1.to_bytes(), bad
                )

    def test_positional_construction_and_field_equality(self):
        receipt = RangeBatchReceipt(
            1,
            RBATCH_FULL.start,
            hashlib.sha256(RBATCH_FULL.to_bytes()).digest(),
            RBATCH_FULL.end,
            _range_batch_receipt_mac(KEY, RECEIPT_BFULL),
        )
        self.assertEqual(receipt, RECEIPT_BFULL)
        self.assertEqual(
            dataclasses.astuple(receipt), dataclasses.astuple(RECEIPT_BFULL)
        )
        self.assertNotEqual(
            receipt, dataclasses.replace(receipt, mac=b"\x01" * 32)
        )
        self.assertEqual(hash(receipt), hash(RECEIPT_BFULL))

    def test_frozen_and_no_key_material(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_B1.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_B1.mac = b""
        self.assertIsNone(
            getattr(RECEIPT_B1, "key", None)
        )


class RangeBatchReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for receipt in (RECEIPT_B1, RECEIPT_B2, RECEIPT_BFULL):
            data = receipt.to_bytes()
            self.assertIsInstance(data, bytes)
            self.assertEqual(RangeBatchReceipt.from_bytes(data), receipt)

    def test_encoding_shape(self):
        data = RECEIPT_B1.to_bytes()
        outer = json.loads(data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 5)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], RECEIPT_B1.start.hex())
        self.assertEqual(outer[2], RECEIPT_B1.digest.hex())
        self.assertEqual(outer[3], RECEIPT_B1.end.hex())
        self.assertEqual(outer[4], RECEIPT_B1.mac.hex())
        # Compact: no whitespace, bytes as lowercase hex.
        self.assertNotIn(b" ", data)
        self.assertNotIn(b"\n", data)
        # C is exactly the first four fields, compact and with no length
        # prefix; the MAC prefix is concatenated directly.
        self.assertEqual(
            _range_batch_receipt_content_bytes(RECEIPT_B1),
            json.dumps(
                [outer[0], outer[1], outer[2], outer[3]],
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        expected_mac = hmac.new(
            KEY,
            b"NPBJ16" + _range_batch_receipt_content_bytes(RECEIPT_B1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_B1.mac, expected_mac)

    def test_uppercase_hex_rejected(self):
        data = RECEIPT_B1.to_bytes()
        outer = json.loads(data)
        outer[2] = outer[2].upper()
        with self.assertRaises(ValueError):
            RangeBatchReceipt.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_type_contract(self):
        for bad in ("x", 1, None, [RECEIPT_B1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceipt.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (
            b"junk",
            b"[]",
            b"[1]",
            json.dumps(
                [
                    1,
                    "",
                    ZERO.hex(),
                    RFRONTIER_1.to_bytes().hex(),
                    ZERO.hex(),
                    0,
                ],
                separators=(",", ":"),
            ).encode("utf-8"),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            RECEIPT_B1.start.hex(),
            RECEIPT_B1.digest.hex(),
            RECEIPT_B1.end.hex(),
            RECEIPT_B1.mac.hex(),
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
                RangeBatchReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical(self):
        data = RECEIPT_B1.to_bytes()
        outer = json.loads(data)
        variants = (
            json.dumps(outer).encode("utf-8"),
            json.dumps(outer, indent=1).encode("utf-8"),
            b" " + data,
            data + b" ",
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceipt.from_bytes(bad)

    def test_from_bytes_does_not_verify_mac(self):
        forged = dataclasses.replace(RECEIPT_B1, mac=ZERO)
        decoded = RangeBatchReceipt.from_bytes(forged.to_bytes())
        self.assertEqual(decoded, forged)


class CommitBatchTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_batch(RBATCH_FULL)
        self.assertIsInstance(receipt, RangeBatchReceipt)
        self.assertEqual(receipt, RECEIPT_BFULL)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.digest,
            hashlib.sha256(RBATCH_FULL.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, RFRONTIER_2.to_bytes())
        self.assertEqual(
            receipt.mac, _range_batch_receipt_mac(KEY, receipt)
        )

    def test_commit_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_batch(RBATCH_FULL.to_bytes())
        self.assertEqual(receipt, RECEIPT_BFULL)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_commit_single_item_batch(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_batch(RBATCH_1)
        self.assertEqual(receipt, RECEIPT_B1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_chained_commits(self):
        auditor = RangeAuditor(KEY)
        first = auditor.commit_batch(RBATCH_1)
        self.assertEqual(first, RECEIPT_B1)
        second = auditor.commit_batch(RBATCH_2)
        self.assertEqual(second, RECEIPT_B2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_commit_matches_audit_batch_record(self):
        via_commit = RangeAuditor(KEY)
        via_commit.commit_batch(RBATCH_1)
        via_commit.commit_batch(RBATCH_2)
        via_record = RangeAuditor(KEY)
        via_record.audit_batch_record(RBATCH_1)
        via_record.audit_batch_record(RBATCH_2)
        self.assertEqual(via_commit.state, via_record.state)

    def test_commit_type_contract(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [RBATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (b"junk", b"[1,2,3]", b"", RBATCH_FULL.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.state)

    def test_failed_commit_changes_nothing_and_mints_nothing(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_batch_record(RBATCH_1)
        before = auditor.state
        # RBATCH_FULL starts from the empty frontier: it cannot extend
        # RFRONTIER_1, so the commit fails and no receipt is minted.
        with self.assertRaises(ValueError):
            auditor.commit_batch(RBATCH_FULL)
        self.assertIs(auditor.state, before)
        auditor.commit_batch(RBATCH_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).commit_batch(RBATCH_FULL)

    def test_batch_mac_mismatch_rejected(self):
        forged = dataclasses.replace(RBATCH_FULL, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).commit_batch(forged)

    def test_replay_rejected_without_state_change(self):
        auditor = RangeAuditor(KEY)
        auditor.commit_batch(RBATCH_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_batch(RBATCH_FULL)
        self.assertIs(auditor.state, before)

    def test_concurrent_commits_linearize(self):
        auditor = RangeAuditor(KEY)
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
                args=(lambda: auditor.commit_batch(RBATCH_FULL), "full"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.commit_batch(RBATCH_1), "one"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_R1, RANGE_1),
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
            self.assertEqual(auditor.state, RFRONTIER_2)
        else:
            self.assertEqual(auditor.state, RFRONTIER_1)


class AuditBatchReceiptTest(unittest.TestCase):
    def test_accepts_objects_and_canonical_bytes(self):
        final = audit_batch_receipt(RECEIPT_BFULL, RBATCH_FULL, KEY)
        self.assertEqual(final, RFRONTIER_2)
        self.assertIsInstance(final, RangeFrontier)
        again = audit_batch_receipt(
            RECEIPT_BFULL.to_bytes(), RBATCH_FULL.to_bytes(), KEY
        )
        self.assertEqual(again, RFRONTIER_2)

    def test_single_and_chained_batches(self):
        self.assertEqual(
            audit_batch_receipt(RECEIPT_B1, RBATCH_1, KEY), RFRONTIER_1
        )
        self.assertEqual(
            audit_batch_receipt(RECEIPT_B2, RBATCH_2, KEY), RFRONTIER_2
        )

    def test_type_contract(self):
        for bad_r in (1, "x", None, [RECEIPT_BFULL], object()):
            with self.assertRaises(TypeError, msg=repr(bad_r)):
                audit_batch_receipt(bad_r, RBATCH_FULL, KEY)
        for bad_b in (1, "x", None, [RBATCH_FULL], object()):
            with self.assertRaises(TypeError, msg=repr(bad_b)):
                audit_batch_receipt(RECEIPT_BFULL, bad_b, KEY)
        for bad_key in (1, "x", None, [KEY], object()):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                audit_batch_receipt(RECEIPT_BFULL, RBATCH_FULL, bad_key)

    def test_empty_key_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(RECEIPT_BFULL, RBATCH_FULL, b"")

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_batch_receipt(bad, RBATCH_FULL, KEY)
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_batch_receipt(RECEIPT_BFULL, bad, KEY)

    def test_tampered_mac_rejected(self):
        forged = dataclasses.replace(RECEIPT_BFULL, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_batch_receipt(forged, RBATCH_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_batch_receipt(forged.to_bytes(), RBATCH_FULL, KEY)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(RECEIPT_BFULL, RBATCH_FULL, OTHER_KEY)

    def test_tampered_digest_rejected(self):
        forged = dataclasses.replace(RECEIPT_BFULL, digest=ZERO)
        signed = dataclasses.replace(
            forged, mac=_range_batch_receipt_mac(KEY, forged)
        )
        with self.assertRaises(ValueError):
            audit_batch_receipt(signed, RBATCH_FULL, KEY)

    def test_tampered_start_rejected(self):
        # A structurally valid RangeFrontier different from the batch's
        # declared start; the receipt MAC is recomputed so only the
        # endpoint comparison can fail.
        other_frontier = range_frontier_for(
            1, CFRONTIER_1.to_bytes(), b"\x02" * 32
        )
        forged = dataclasses.replace(
            RECEIPT_B2, start=other_frontier.to_bytes()
        )
        signed = dataclasses.replace(
            forged, mac=_range_batch_receipt_mac(KEY, forged)
        )
        with self.assertRaises(ValueError):
            audit_batch_receipt(signed, RBATCH_2, KEY)

    def test_tampered_end_rejected(self):
        forged = dataclasses.replace(
            RECEIPT_B1, end=RFRONTIER_2.to_bytes()
        )
        signed = dataclasses.replace(
            forged, mac=_range_batch_receipt_mac(KEY, forged)
        )
        with self.assertRaises(ValueError):
            audit_batch_receipt(signed, RBATCH_1, KEY)

    def test_receipt_of_other_batch_rejected(self):
        with self.assertRaises(ValueError):
            audit_batch_receipt(RECEIPT_B1, RBATCH_2, KEY)
        with self.assertRaises(ValueError):
            audit_batch_receipt(RECEIPT_B2, RBATCH_1, KEY)

    def test_batch_reverified(self):
        # The NPBJ15 batch MAC is re-checked as part of the batch audit.
        forged_batch = dataclasses.replace(RBATCH_FULL, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_batch_receipt(RECEIPT_BFULL, forged_batch, KEY)
        # A tampered carried receipt fails the replay even with a freshly
        # MAC'd batch and a matching receipt.
        broken_items = (
            (
                dataclasses.replace(RECEIPT_R1, mac=ZERO).to_bytes(),
                RANGE_1.to_bytes(),
            ),
            (RECEIPT_RCP.to_bytes(), RANGE_FROM_CP.to_bytes()),
        )
        placeholder = RangeReceiptBatch(
            1, b"", broken_items, RFRONTIER_2.to_bytes(), ZERO
        )
        signed_batch = dataclasses.replace(
            placeholder, mac=_range_receipt_batch_mac(KEY, placeholder)
        )
        signed_receipt = batch_receipt_for(signed_batch)
        with self.assertRaises(ValueError):
            audit_batch_receipt(signed_receipt, signed_batch, KEY)

    def test_returns_end_frontier(self):
        final = audit_batch_receipt(RECEIPT_B2, RBATCH_2, KEY)
        self.assertEqual(final.to_bytes(), RBATCH_2.end)
        self.assertEqual(final, RFRONTIER_2)

    def test_pure_check_changes_nothing(self):
        auditor = RangeAuditor(KEY)
        audit_batch_receipt(RECEIPT_BFULL, RBATCH_FULL, KEY)
        self.assertIsNone(auditor.state)
        auditor.audit_batch_record(RBATCH_1)
        before = auditor.state
        # A pure standalone audit succeeds on its own merits regardless
        # of the live auditor's state and changes none of it...
        audit_batch_receipt(RECEIPT_BFULL, RBATCH_FULL, KEY)
        self.assertIs(auditor.state, before)
        # ...just as a failing one does.
        with self.assertRaises(ValueError):
            audit_batch_receipt(
                dataclasses.replace(RECEIPT_BFULL, mac=ZERO),
                RBATCH_FULL,
                KEY,
            )
        self.assertIs(auditor.state, before)


if __name__ == "__main__":
    unittest.main()
