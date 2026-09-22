import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    RangeBatchReceiptFrontier,
    ReceiptStream,
    _receipt_stream_content_bytes,
    _receipt_stream_mac,
    audit_stream,
    seal_stream,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    RFRONTIER_1,
    RFRONTIER_2,
    ZERO,
)
from test_range_batch_receipt import (
    RBATCH_1,
    RBATCH_2,
    RBATCH_FULL,
    RECEIPT_B1,
    RECEIPT_B2,
    RECEIPT_BFULL,
)
from test_range_batch_receipt_frontier import (
    BFRONTIER_1,
    BFRONTIER_2,
)

PAIRS_1 = ((RECEIPT_B1, RBATCH_1),)
PAIRS_2 = ((RECEIPT_B2, RBATCH_2),)
PAIRS_CHAIN = ((RECEIPT_B1, RBATCH_1), (RECEIPT_B2, RBATCH_2))

STREAM_1 = seal_stream(PAIRS_1, KEY)
STREAM_2 = seal_stream(PAIRS_2, KEY, checkpoint=BFRONTIER_1.to_bytes())
STREAM_CHAIN = seal_stream(PAIRS_CHAIN, KEY)


def stream_for(start, items, end, key=KEY):
    placeholder = ReceiptStream(1, start, items, end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_receipt_stream_mac(key, placeholder)
    )


class ReceiptStreamFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        stream = ReceiptStream(
            1,
            STREAM_1.start,
            STREAM_1.items,
            STREAM_1.end,
            STREAM_1.mac,
        )
        self.assertEqual(stream, STREAM_1)
        self.assertEqual(hash(stream), hash(STREAM_1))
        self.assertEqual(
            dataclasses.astuple(stream), dataclasses.astuple(STREAM_1)
        )
        self.assertNotEqual(
            stream,
            dataclasses.replace(stream, mac=b"\x01" * 32),
        )

    def test_frozen_and_no_key_material(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            STREAM_1.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            STREAM_1.mac = b"\x00" * 32
        self.assertIsNone(getattr(STREAM_1, "key", None))

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    bad, b"", STREAM_1.items, BFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            ReceiptStream(
                2, b"", STREAM_1.items, BFRONTIER_1.to_bytes(), ZERO
            )

    def test_start_contract(self):
        for bad in (1, "ab", None, [b""], bytearray()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    1, bad, STREAM_1.items, BFRONTIER_1.to_bytes(), ZERO
                )
        # b"" (no commit yet) is a valid start; junk and a range
        # frontier are not canonical RangeBatchReceiptFrontier bytes.
        ReceiptStream(
            1, b"", STREAM_1.items, BFRONTIER_1.to_bytes(), ZERO
        )
        for bad in (b"junk", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream(
                    1, bad, STREAM_1.items, BFRONTIER_1.to_bytes(), ZERO
                )

    def test_end_contract(self):
        for bad in (1, "ab", None, [BFRONTIER_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(1, b"", STREAM_1.items, bad, ZERO)
        for bad in (b"", b"junk", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream(1, b"", STREAM_1.items, bad, ZERO)

    def test_items_must_be_a_non_empty_tuple_of_pairs(self):
        for bad in (1, "ab", None, [STREAM_1.items[0]], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    1, b"", bad, BFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            ReceiptStream(1, b"", (), BFRONTIER_1.to_bytes(), ZERO)
        # Entries must be tuples (a type error); wrong arity is a
        # value error.
        for bad in (
            RECEIPT_B1.to_bytes(),
            [RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes()],
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    1, b"", (bad,), BFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (
            (RECEIPT_B1.to_bytes(),),
            (RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes(), 0),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream(
                    1, b"", (bad,), BFRONTIER_1.to_bytes(), ZERO
                )

    def test_items_member_type_contract(self):
        for bad in (1, "ab", None, [RECEIPT_B1.to_bytes()]):
            with self.assertRaises(TypeError, msg=("receipt", bad)):
                ReceiptStream(
                    1,
                    b"",
                    ((bad, RBATCH_1.to_bytes()),),
                    BFRONTIER_1.to_bytes(),
                    ZERO,
                )
            with self.assertRaises(TypeError, msg=("batch", bad)):
                ReceiptStream(
                    1,
                    b"",
                    ((RECEIPT_B1.to_bytes(), bad),),
                    BFRONTIER_1.to_bytes(),
                    ZERO,
                )

    def test_items_members_must_be_canonical_bytes(self):
        # bytes that are not the canonical inner encodings are a value
        # error, not a type error.
        for bad_receipt, bad_batch in (
            (b"junk", RBATCH_1.to_bytes()),
            (RECEIPT_B1.to_bytes(), b"junk"),
            (RBATCH_1.to_bytes(), RBATCH_1.to_bytes()),
        ):
            with self.assertRaises(
                ValueError, msg=(bad_receipt, bad_batch)
            ):
                ReceiptStream(
                    1,
                    b"",
                    ((bad_receipt, bad_batch),),
                    BFRONTIER_1.to_bytes(),
                    ZERO,
                )

    def test_mac_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    1, b"", STREAM_1.items, BFRONTIER_1.to_bytes(), bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream(
                    1, b"", STREAM_1.items, BFRONTIER_1.to_bytes(), bad
                )


class ReceiptStreamEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for stream in (STREAM_1, STREAM_2, STREAM_CHAIN):
            blob = stream.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(ReceiptStream.from_bytes(blob), stream)
            self.assertEqual(
                ReceiptStream.from_bytes(blob).to_bytes(), blob
            )

    def test_encoding_shape(self):
        blob = STREAM_1.to_bytes()
        outer = json.loads(blob)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 5)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], STREAM_1.start.hex())
        self.assertEqual(
            outer[2],
            [
                [receipt.hex(), batch.hex()]
                for receipt, batch in STREAM_1.items
            ],
        )
        self.assertEqual(outer[3], STREAM_1.end.hex())
        self.assertEqual(outer[4], STREAM_1.mac.hex())
        # Compact: no whitespace; bytes as lowercase hex.
        self.assertNotIn(b" ", blob)
        self.assertNotIn(b"\n", blob)
        # C is exactly the first four fields, compact and with no length
        # prefix; the MAC prefix is concatenated directly.
        self.assertEqual(
            _receipt_stream_content_bytes(STREAM_1),
            json.dumps(
                [outer[0], outer[1], outer[2], outer[3]],
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        expected_mac = hmac.new(
            KEY,
            b"NPBJ19" + _receipt_stream_content_bytes(STREAM_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(STREAM_1.mac, expected_mac)

    def test_multi_item_encoding_order(self):
        outer = json.loads(STREAM_CHAIN.to_bytes())
        self.assertEqual(
            outer[2],
            [
                [RECEIPT_B1.to_bytes().hex(), RBATCH_1.to_bytes().hex()],
                [RECEIPT_B2.to_bytes().hex(), RBATCH_2.to_bytes().hex()],
            ],
        )

    def test_from_bytes_type_contract(self):
        blob = STREAM_1.to_bytes()
        for bad in ("x", 1, None, [STREAM_1], object(), bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            STREAM_1.start.hex(),
            [
                [receipt.hex(), batch.hex()]
                for receipt, batch in STREAM_1.items
            ],
            STREAM_1.end.hex(),
            STREAM_1.mac.hex(),
        ]
        # Wrong-typed version/items surface as TypeError; a numeric hex
        # field likewise.
        for index, bad_value in (
            (0, "1"),
            (2, {}),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                ReceiptStream.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )
        for index in (1, 3, 4):
            broken = list(good)
            broken[index] = 0
            with self.assertRaises(TypeError, msg=index):
                ReceiptStream.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_items_value_contract(self):
        good = json.loads(STREAM_1.to_bytes())
        variants = (
            # empty items
            [1, good[1], [], good[3], good[4]],
            # entry not a pair
            [1, good[1], [[good[2][0][0]]], good[3], good[4]],
            # mac wrong length
            [1, good[1], good[2], good[3], "ab"],
            # bad version
            [2, good[1], good[2], good[3], good[4]],
        )
        for broken in variants:
            with self.assertRaises(ValueError, msg=repr(broken)):
                ReceiptStream.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = STREAM_1.to_bytes()
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            STREAM_1.mac.hex().encode(),
            STREAM_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(upper)
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(json.loads(blob)).encode()
                + b" "
            )

    def test_from_bytes_does_not_verify_mac(self):
        forged = dataclasses.replace(STREAM_1, mac=ZERO)
        decoded = ReceiptStream.from_bytes(forged.to_bytes())
        self.assertEqual(decoded, forged)


class SealStreamTest(unittest.TestCase):
    def test_seals_empty_start_chain(self):
        stream = seal_stream(PAIRS_1, KEY)
        self.assertIsInstance(stream, ReceiptStream)
        self.assertEqual(stream.version, 1)
        self.assertEqual(stream.start, b"")
        self.assertEqual(
            stream.items,
            ((RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes()),),
        )
        self.assertEqual(stream.end, BFRONTIER_1.to_bytes())
        self.assertEqual(
            stream.mac, _receipt_stream_mac(KEY, stream)
        )

    def test_seals_full_chain(self):
        # RECEIPT_BFULL attests the whole two-receipt range chain in a
        # single range-batch receipt, so the commit frontier advances
        # once and ends at the range chain's RFRONTIER_2.
        stream = seal_stream(
            ((RECEIPT_BFULL, RBATCH_FULL),), KEY
        )
        self.assertEqual(stream.start, b"")
        self.assertEqual(
            audit_stream(stream, KEY), stream.end
        )
        end_frontier = RangeBatchReceiptFrontier.from_bytes(stream.end)
        self.assertEqual(end_frontier.sequence, 1)
        self.assertEqual(end_frontier.end, RFRONTIER_2.to_bytes())

    def test_seals_from_checkpoint_bytes(self):
        stream = seal_stream(
            PAIRS_2, KEY, checkpoint=BFRONTIER_1.to_bytes()
        )
        self.assertEqual(stream.start, BFRONTIER_1.to_bytes())
        self.assertEqual(stream.end, BFRONTIER_2.to_bytes())

    def test_seals_multiple_commits_in_one_stream(self):
        stream = seal_stream(PAIRS_CHAIN, KEY)
        self.assertEqual(stream.start, b"")
        self.assertEqual(stream.end, BFRONTIER_2.to_bytes())
        self.assertEqual(len(stream.items), 2)

    def test_accepts_objects_and_canonical_bytes(self):
        via_objects = seal_stream(
            [(RECEIPT_B1, RBATCH_1)], KEY
        )
        via_bytes = seal_stream(
            [(RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes())], KEY
        )
        self.assertEqual(via_objects, via_bytes)

    def test_accepts_any_non_empty_iterable(self):
        via_list = seal_stream(list(PAIRS_CHAIN), KEY)
        via_tuple = seal_stream(PAIRS_CHAIN, KEY)
        via_generator = seal_stream(
            (pair for pair in PAIRS_CHAIN), KEY
        )
        self.assertEqual(via_list, via_tuple)
        self.assertEqual(via_tuple, via_generator)

    def test_checkpoint_accepts_only_canonical_bytes(self):
        # A frontier object is not accepted; only its canonical bytes.
        with self.assertRaises(TypeError):
            seal_stream(PAIRS_2, KEY, checkpoint=BFRONTIER_1)
        for bad in (1, "x", [BFRONTIER_1.to_bytes()], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream(PAIRS_2, KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_2, KEY, checkpoint=b"junk")

    def test_checkpoint_mac_verified(self):
        tampered = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_stream(
                PAIRS_2, KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            seal_stream(
                PAIRS_2, OTHER_KEY,
                checkpoint=BFRONTIER_1.to_bytes(),
            )

    def test_non_iterable_items_is_type_error(self):
        for bad in (1, None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream(bad, KEY)

    def test_item_must_be_a_pair(self):
        # Non-unpackable entries are a type error; entries with the
        # wrong arity are a value error. A two-element list unpacks
        # like a tuple and is accepted, mirroring the batch sealers.
        for bad in (RECEIPT_B1, 42, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream([bad], KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream(
                    [(RECEIPT_B1, RBATCH_1), bad], KEY
                )
        for bad in (
            (RECEIPT_B1,),
            (RECEIPT_B1, RBATCH_1, 0),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                seal_stream([bad], KEY)
        self.assertEqual(
            seal_stream([[RECEIPT_B1, RBATCH_1]], KEY), STREAM_1
        )

    def test_wrong_pair_member_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_B1], object()):
            with self.assertRaises(TypeError, msg=("receipt", bad)):
                seal_stream([(bad, RBATCH_1)], KEY)
            with self.assertRaises(TypeError, msg=("batch", bad)):
                seal_stream([(RECEIPT_B1, bad)], KEY)

    def test_malformed_member_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=("receipt", bad)):
                seal_stream([(bad, RBATCH_1)], KEY)
            with self.assertRaises(ValueError, msg=("batch", bad)):
                seal_stream([(RECEIPT_B1, bad)], KEY)

    def test_empty_items_is_value_error(self):
        for empty in ([], (), iter(())):
            with self.assertRaises(ValueError, msg=repr(empty)):
                seal_stream(empty, KEY)

    def test_key_contract(self):
        for bad in (1, "x", None, [KEY], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_stream(PAIRS_1, bad)
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_1, b"")

    def test_broken_chain_is_value_error(self):
        # B2 starts from BFRONTIER_1, not from the empty frontier.
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_2, KEY)

    def test_first_commit_after_checkpoint_must_match(self):
        with self.assertRaises(ValueError):
            seal_stream(
                PAIRS_1, KEY, checkpoint=BFRONTIER_1.to_bytes()
            )

    def test_replayed_commit_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_stream(
                ((RECEIPT_B1, RBATCH_1), (RECEIPT_B1, RBATCH_1)), KEY
            )

    def test_tampered_receipt_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_stream(
                (
                    (dataclasses.replace(RECEIPT_B1, mac=ZERO), RBATCH_1),
                    (RECEIPT_B2, RBATCH_2),
                ),
                KEY,
            )

    def test_tampered_batch_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_stream(
                ((RECEIPT_B1, dataclasses.replace(RBATCH_1, mac=ZERO)),),
                KEY,
            )

    def test_wrong_key_is_value_error(self):
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_CHAIN, OTHER_KEY)

    def test_does_not_adopt_auditor_state_on_failure(self):
        # Sealing is pure computation: it builds no persistent auditor;
        # a second correct seal after a failing one still works, and a
        # live auditor is unaffected.
        from nearproof import RangeBatchReceiptAuditor

        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_2, KEY)
        self.assertIsNone(auditor.state)
        self.assertEqual(
            seal_stream(PAIRS_CHAIN, KEY).end, BFRONTIER_2.to_bytes()
        )
        self.assertIsNone(auditor.state)


class AuditStreamTest(unittest.TestCase):
    def test_accepts_objects_and_canonical_bytes(self):
        self.assertEqual(
            audit_stream(STREAM_1, KEY), STREAM_1.end
        )
        self.assertEqual(
            audit_stream(STREAM_1.to_bytes(), KEY), STREAM_1.end
        )

    def test_returns_canonical_end_bytes(self):
        result = audit_stream(STREAM_CHAIN, KEY)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, BFRONTIER_2.to_bytes())
        self.assertEqual(
            RangeBatchReceiptFrontier.from_bytes(result), BFRONTIER_2
        )

    def test_chained_and_checkpointed_streams(self):
        self.assertEqual(
            audit_stream(STREAM_CHAIN, KEY), BFRONTIER_2.to_bytes()
        )
        self.assertEqual(
            audit_stream(STREAM_2, KEY), BFRONTIER_2.to_bytes()
        )

    def test_type_contract(self):
        for bad in (1, "x", None, [STREAM_1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream(bad, KEY)
        for bad in (1, "x", None, [KEY], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream(STREAM_1, bad)

    def test_empty_key_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_stream(STREAM_1, b"")

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_stream(bad, KEY)

    def test_stream_mac_mismatch_rejected(self):
        forged = dataclasses.replace(STREAM_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)
        with self.assertRaises(ValueError):
            audit_stream(forged.to_bytes(), KEY)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream(STREAM_1, OTHER_KEY)

    def test_npbj19_domain_separation(self):
        # A MAC computed with a different prefix must not validate,
        # even with the correct key and content.
        content = _receipt_stream_content_bytes(STREAM_1)
        wrong_digest = hmac.new(
            KEY, b"NPBJ18" + content, hashlib.sha256
        ).digest()
        self.assertFalse(
            hmac.compare_digest(wrong_digest, STREAM_1.mac)
        )
        forged = dataclasses.replace(STREAM_1, mac=wrong_digest)
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_tampered_carried_receipt_rejected(self):
        # Freshly NPBJ19-MAC'd so the outer MAC passes: the NPBJ18
        # replay of the carried chain must fail.
        broken_items = (
            (
                dataclasses.replace(RECEIPT_B1, mac=ZERO).to_bytes(),
                RBATCH_1.to_bytes(),
            ),
            (RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),
        )
        forged = stream_for(b"", broken_items, BFRONTIER_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_tampered_carried_batch_rejected(self):
        broken_items = (
            (
                RECEIPT_B1.to_bytes(),
                dataclasses.replace(RBATCH_1, mac=ZERO).to_bytes(),
            ),
        )
        forged = stream_for(
            b"", broken_items, BFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_end_mismatch_rejected(self):
        # One committed pair but a seq-2 end frontier: the outer MAC is
        # valid, the replayed final frontier must not equal end.
        forged = stream_for(
            b"",
            (
                (
                    RECEIPT_B1.to_bytes(),
                    RBATCH_1.to_bytes(),
                ),
            ),
            BFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_start_mismatch_rejected(self):
        # Declare the BFRONTIER_1 checkpoint start while replaying only
        # B1 (which starts empty): the replay cannot take B1 after the
        # checkpoint.
        forged = stream_for(
            BFRONTIER_1.to_bytes(),
            (
                (
                    RECEIPT_B1.to_bytes(),
                    RBATCH_1.to_bytes(),
                ),
            ),
            BFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_checkpoint_frontier_macs_verified(self):
        # The carried start frontier's own NPBJ17 layer is recomputed
        # during replay setup.
        tampered = dataclasses.replace(BFRONTIER_1, mac=ZERO)
        forged = stream_for(
            tampered.to_bytes(),
            (
                (
                    RECEIPT_B2.to_bytes(),
                    RBATCH_2.to_bytes(),
                ),
            ),
            BFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_end_frontier_macs_verified(self):
        # A declared end whose own NPBJ17 mac is wrong is rejected
        # even with a valid outer NPBJ19 mac.
        bad_end = dataclasses.replace(BFRONTIER_1, mac=ZERO).to_bytes()
        forged = stream_for(
            b"",
            (
                (
                    RECEIPT_B1.to_bytes(),
                    RBATCH_1.to_bytes(),
                ),
            ),
            bad_end,
        )
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_receipt_of_other_batch_rejected(self):
        forged = stream_for(
            b"",
            (
                (
                    RECEIPT_B1.to_bytes(),
                    RBATCH_FULL.to_bytes(),
                ),
            ),
            BFRONTIER_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_pure_check_changes_nothing(self):
        from nearproof import RangeBatchReceiptAuditor

        auditor = RangeBatchReceiptAuditor(KEY)
        audit_stream(STREAM_CHAIN, KEY)
        self.assertIsNone(auditor.state)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        before = auditor.state
        # A passing standalone audit leaves the live frontier alone...
        audit_stream(STREAM_2, KEY)
        self.assertEqual(auditor.state, before)
        # ...and a failing one does too.
        with self.assertRaises(ValueError):
            audit_stream(dataclasses.replace(STREAM_1, mac=ZERO), KEY)
        self.assertEqual(auditor.state, before)


if __name__ == "__main__":
    unittest.main()
