import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeBatchReceipt,
    RangeBatchReceiptAuditor,
    RangeBatchReceiptFrontier,
    RangeFrontier,
    _range_batch_receipt_frontier_content_bytes,
    _range_batch_receipt_frontier_mac,
    _range_batch_receipt_frontier_next_digest,
    _range_batch_receipt_mac,
    _range_frontier_mac,
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
    RECEIPT_R1,
    RECEIPT_RCP,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
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


def frontier_for(sequence, end, digest, key=KEY):
    placeholder = RangeBatchReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_range_batch_receipt_frontier_mac(key, placeholder),
    )


# The frontier a first accepted batch receipt ends at.
FRONTIER_1 = frontier_for(
    1,
    RECEIPT_B1.end,
    _range_batch_receipt_frontier_next_digest(
        ZERO, 1, RECEIPT_B1.to_bytes()
    ),
)


class RangeBatchReceiptFrontierFieldTest(unittest.TestCase):
    def test_version_contract(self):
        for bad in ("1", 1.0, True, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    bad, 0, RFRONTIER_1.to_bytes(), ZERO, ZERO
                )
        with self.assertRaises(ValueError):
            RangeBatchReceiptFrontier(
                2, 0, RFRONTIER_1.to_bytes(), ZERO, ZERO
            )
        with self.assertRaises(ValueError):
            RangeBatchReceiptFrontier(
                0, 0, RFRONTIER_1.to_bytes(), ZERO, ZERO
            )

    def test_sequence_contract(self):
        for bad in (True, False, 1.0, "1", None, [0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    1, bad, RFRONTIER_1.to_bytes(), ZERO, ZERO
                )
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    1, bad, RFRONTIER_1.to_bytes(), ZERO, ZERO
                )
        for good in (0, 1, U64_MAX):
            RangeBatchReceiptFrontier(
                1, good, RFRONTIER_1.to_bytes(), ZERO, ZERO
            )

    def test_end_contract(self):
        for bad in (1, "ab", None, [RFRONTIER_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier(1, 0, bad, ZERO, ZERO)
        # The end must be the canonical non-empty RangeFrontier encoding:
        # empty bytes, junk, and a commit-frontier encoding all fail.
        for bad in (b"", b"\xff", CFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier(1, 0, bad, ZERO, ZERO)
        RangeBatchReceiptFrontier(
            1, 0, RFRONTIER_1.to_bytes(), ZERO, ZERO
        )

    def test_digest_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    1, 0, RFRONTIER_1.to_bytes(), bad, ZERO
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    1, 0, RFRONTIER_1.to_bytes(), bad, ZERO
                )

    def test_mac_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    1, 0, RFRONTIER_1.to_bytes(), ZERO, bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier(
                    1, 0, RFRONTIER_1.to_bytes(), ZERO, bad
                )

    def test_positional_construction_and_field_equality(self):
        frontier = frontier_for(
            FRONTIER_1.sequence, FRONTIER_1.end, FRONTIER_1.digest
        )
        self.assertEqual(frontier, FRONTIER_1)
        self.assertEqual(
            dataclasses.astuple(frontier), dataclasses.astuple(FRONTIER_1)
        )
        self.assertNotEqual(
            frontier, dataclasses.replace(frontier, sequence=2)
        )
        self.assertNotEqual(
            frontier, dataclasses.replace(frontier, end=RFRONTIER_2.to_bytes())
        )
        self.assertNotEqual(
            frontier, dataclasses.replace(frontier, digest=b"\x01" * 32)
        )
        self.assertNotEqual(
            frontier, dataclasses.replace(frontier, mac=b"\x01" * 32)
        )
        self.assertEqual(hash(frontier), hash(FRONTIER_1))

    def test_frozen_and_no_key_material(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FRONTIER_1.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            FRONTIER_1.mac = b""
        self.assertIsNone(getattr(FRONTIER_1, "key", None))


class RangeBatchReceiptFrontierEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        data = FRONTIER_1.to_bytes()
        self.assertIsInstance(data, bytes)
        self.assertEqual(
            RangeBatchReceiptFrontier.from_bytes(data), FRONTIER_1
        )

    def test_encoding_shape(self):
        data = FRONTIER_1.to_bytes()
        outer = json.loads(data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 5)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], FRONTIER_1.sequence)
        self.assertEqual(outer[2], FRONTIER_1.end.hex())
        self.assertEqual(outer[3], FRONTIER_1.digest.hex())
        self.assertEqual(outer[4], FRONTIER_1.mac.hex())
        # Compact: no whitespace, bytes as lowercase hex.
        self.assertNotIn(b" ", data)
        self.assertNotIn(b"\n", data)
        # C is exactly the first four fields, compact and with no length
        # prefix; the MAC prefix is concatenated directly.
        self.assertEqual(
            _range_batch_receipt_frontier_content_bytes(FRONTIER_1),
            json.dumps(
                [outer[0], outer[1], outer[2], outer[3]],
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        expected_mac = hmac.new(
            KEY,
            b"NPBJ17" + _range_batch_receipt_frontier_content_bytes(FRONTIER_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(FRONTIER_1.mac, expected_mac)

    def test_digest_chain_prefix(self):
        # d0 is 32 zero bytes; the step is SHA256(b"NPBJ18" + d + u64be(n)
        # + R), direct concatenation with an 8-byte big-endian sequence.
        expected = hashlib.sha256(
            b"NPBJ18"
            + ZERO
            + (1).to_bytes(8, "big")
            + RECEIPT_B1.to_bytes()
        ).digest()
        self.assertEqual(FRONTIER_1.digest, expected)

    def test_uppercase_hex_rejected(self):
        data = FRONTIER_1.to_bytes()
        outer = json.loads(data)
        outer[3] = outer[3].upper()
        with self.assertRaises(ValueError):
            RangeBatchReceiptFrontier.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_type_contract(self):
        for bad in ("x", 1, None, [FRONTIER_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (
            b"junk",
            b"[]",
            b"[1]",
            json.dumps(
                [
                    1,
                    0,
                    RFRONTIER_1.to_bytes().hex(),
                    ZERO.hex(),
                    ZERO.hex(),
                    0,
                ],
                separators=(",", ":"),
            ).encode("utf-8"),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            FRONTIER_1.sequence,
            FRONTIER_1.end.hex(),
            FRONTIER_1.digest.hex(),
            FRONTIER_1.mac.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, "1"),
            (2, 0),
            (3, 0),
            (4, 0),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=str(index)):
                RangeBatchReceiptFrontier.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical(self):
        data = FRONTIER_1.to_bytes()
        outer = json.loads(data)
        variants = (
            json.dumps(outer).encode("utf-8"),
            json.dumps(outer, indent=1).encode("utf-8"),
            b" " + data,
            data + b" ",
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptFrontier.from_bytes(bad)

    def test_from_bytes_does_not_verify_mac(self):
        forged = dataclasses.replace(FRONTIER_1, mac=ZERO)
        decoded = RangeBatchReceiptFrontier.from_bytes(forged.to_bytes())
        self.assertEqual(decoded, forged)


class RangeBatchReceiptAuditorConstructorTest(unittest.TestCase):
    def test_key_contract(self):
        for bad in (1, "x", None, [KEY], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(b"")

    def test_empty_state(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        self.assertIsNone(auditor.state)

    def test_checkpoint_kind_contract(self):
        for bad in (1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                RangeBatchReceiptAuditor(KEY, checkpoint=bad)

    def test_malformed_checkpoint_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b"", FRONTIER_1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                RangeBatchReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_accepts_object_and_canonical_bytes(self):
        self.assertEqual(
            RangeBatchReceiptAuditor(KEY, checkpoint=FRONTIER_1).state,
            FRONTIER_1,
        )
        self.assertEqual(
            RangeBatchReceiptAuditor(
                KEY, checkpoint=FRONTIER_1.to_bytes()
            ).state,
            FRONTIER_1,
        )

    def test_checkpoint_own_mac_verified(self):
        forged = dataclasses.replace(FRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=forged)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=forged.to_bytes())

    def test_checkpoint_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(OTHER_KEY, checkpoint=FRONTIER_1)

    def test_checkpoint_nested_end_mac_verified(self):
        # A structurally valid frontier whose end RangeFrontier was MAC'd
        # with another key: the nested NPBJ13 layer must fail.
        other_end = dataclasses.replace(
            RFRONTIER_1,
            mac=_range_frontier_mac(OTHER_KEY, RFRONTIER_1),
        )
        broken = frontier_for(1, other_end.to_bytes(), ZERO)
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(KEY, checkpoint=broken)


class RangeBatchReceiptAuditorAuditTest(unittest.TestCase):
    def setUp(self):
        self.auditor = RangeBatchReceiptAuditor(KEY)

    def test_audit_advances_empty_state(self):
        result = self.auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertIs(result, self.auditor)
        frontier = self.auditor.state
        self.assertEqual(frontier, FRONTIER_1)
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, RECEIPT_B1.end)
        self.assertEqual(frontier.end, RFRONTIER_1.to_bytes())
        self.assertEqual(
            frontier.digest,
            hashlib.sha256(
                b"NPBJ18" + ZERO + (1).to_bytes(8, "big")
                + RECEIPT_B1.to_bytes()
            ).digest(),
        )
        self.assertEqual(
            frontier.mac,
            hmac.new(
                KEY,
                b"NPBJ17"
                + _range_batch_receipt_frontier_content_bytes(frontier),
                hashlib.sha256,
            ).digest(),
        )

    def test_accepts_canonical_bytes(self):
        self.auditor.audit(RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes())
        self.assertEqual(self.auditor.state, FRONTIER_1)

    def test_empty_state_requires_empty_start(self):
        # RECEIPT_B2 starts at RFRONTIER_1 and cannot seed an empty auditor.
        with self.assertRaises(ValueError):
            self.auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertIsNone(self.auditor.state)

    def test_chained_audits(self):
        self.auditor.audit(RECEIPT_B1, RBATCH_1)
        self.auditor.audit(RECEIPT_B2, RBATCH_2)
        frontier = self.auditor.state
        self.assertEqual(frontier.sequence, 2)
        self.assertEqual(frontier.end, RFRONTIER_2.to_bytes())
        self.assertEqual(
            frontier.digest,
            _range_batch_receipt_frontier_next_digest(
                FRONTIER_1.digest, 2, RECEIPT_B2.to_bytes()
            ),
        )
        self.assertEqual(
            frontier.mac,
            _range_batch_receipt_frontier_mac(KEY, frontier),
        )

    def test_restart_from_checkpoint(self):
        self.auditor.audit(RECEIPT_B1, RBATCH_1)
        restarted = RangeBatchReceiptAuditor(
            KEY, checkpoint=self.auditor.state
        )
        restarted.audit(RECEIPT_B2, RBATCH_2)
        self.assertEqual(restarted.state.sequence, 2)
        self.assertEqual(restarted.state.end, RFRONTIER_2.to_bytes())

    def test_replay_rejected_without_state_change(self):
        self.auditor.audit(RECEIPT_B1, RBATCH_1)
        before = self.auditor.state
        with self.assertRaises(ValueError):
            self.auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertIs(self.auditor.state, before)

    def test_old_fork_rejected_without_state_change(self):
        self.auditor.audit(RECEIPT_B1, RBATCH_1)
        self.auditor.audit(RECEIPT_B2, RBATCH_2)
        before = self.auditor.state
        # An old batch receipt cannot be replayed onto the advanced end.
        with self.assertRaises(ValueError):
            self.auditor.audit(RECEIPT_B1, RBATCH_1)
        self.assertIs(self.auditor.state, before)

    def test_full_batch_from_empty(self):
        self.auditor.audit(RECEIPT_BFULL, RBATCH_FULL)
        self.assertEqual(self.auditor.state.sequence, 1)
        self.assertEqual(self.auditor.state.end, RFRONTIER_2.to_bytes())

    def test_type_contract(self):
        for bad in (1, "x", None, [RECEIPT_B1], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.auditor.audit(bad, RBATCH_1)
        for bad in (1, "x", None, [RBATCH_1], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.auditor.audit(RECEIPT_B1, bad)
        self.assertIsNone(self.auditor.state)

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b"", RECEIPT_B1.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.auditor.audit(bad, RBATCH_1)
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.auditor.audit(RECEIPT_B1, bad)
        self.assertIsNone(self.auditor.state)

    def test_tampered_receipt_mac_rejected(self):
        forged = dataclasses.replace(RECEIPT_B1, mac=ZERO)
        with self.assertRaises(ValueError):
            self.auditor.audit(forged, RBATCH_1)
        with self.assertRaises(ValueError):
            self.auditor.audit(forged.to_bytes(), RBATCH_1)
        self.assertIsNone(self.auditor.state)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeBatchReceiptAuditor(OTHER_KEY).audit(
                RECEIPT_B1, RBATCH_1
            )

    def test_batch_reverified(self):
        # The NPBJ16 audit runs first and re-verifies the attested batch:
        # a tampered batch MAC is rejected before the frontier moves.
        forged_batch = dataclasses.replace(RBATCH_1, mac=ZERO)
        with self.assertRaises(ValueError):
            self.auditor.audit(RECEIPT_B1, forged_batch)
        self.assertIsNone(self.auditor.state)

    def test_receipt_of_other_batch_rejected(self):
        with self.assertRaises(ValueError):
            self.auditor.audit(RECEIPT_B1, RBATCH_FULL)
        self.assertIsNone(self.auditor.state)

    def test_u64_overflow_rejected_without_state_change(self):
        # A checkpoint already at u64 max: the linking receipt B2 starts at
        # RFRONTIER_1 (the checkpoint end), so the only remaining failure is
        # the sequence overflow.
        checkpoint = frontier_for(
            U64_MAX, RECEIPT_B2.start, b"\x09" * 32
        )
        auditor = RangeBatchReceiptAuditor(KEY, checkpoint=checkpoint)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertIs(auditor.state, checkpoint)

    def test_failure_changes_nothing_then_recovery(self):
        self.auditor.audit(RECEIPT_B1, RBATCH_1)
        before = self.auditor.state
        for bad_call in (
            lambda: self.auditor.audit(RECEIPT_B2, RBATCH_1),
            lambda: self.auditor.audit(RECEIPT_B1, RBATCH_1),
            lambda: self.auditor.audit(
                dataclasses.replace(RECEIPT_B2, mac=ZERO), RBATCH_2
            ),
        ):
            with self.assertRaises(ValueError):
                bad_call()
            self.assertIs(self.auditor.state, before)
        # The genuine next receipt still links and advances.
        self.auditor.audit(RECEIPT_B2, RBATCH_2)
        self.assertEqual(self.auditor.state.sequence, 2)

    def test_concurrent_audits_linearize(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        # All three start from the empty frontier; only B1 links there.
        threads = [
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit(RECEIPT_B1, RBATCH_1), "b1"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit(RECEIPT_B1, RBATCH_1), "replay"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit(RECEIPT_B2, RBATCH_2), "b2"),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(successes, ["b1"])
        self.assertEqual(sorted(failures), ["b2", "replay"])
        self.assertEqual(auditor.state, FRONTIER_1)


class AuditBatchReceiptFirstTest(unittest.TestCase):
    def test_pure_audit_runs_under_lock_and_returns_frontier(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        # audit delegates to audit_batch_receipt first; its pure result is
        # the RangeFrontier at the batch end and no standalone state is
        # touched by that call.
        final = audit_batch_receipt(RECEIPT_B1, RBATCH_1, KEY)
        self.assertIsInstance(final, RangeFrontier)
        self.assertIsNone(auditor.state)


if __name__ == "__main__":
    unittest.main()
