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
    ZERO,
)
from test_range_batch_receipt import (
    RBATCH_1,
    RBATCH_2,
    RECEIPT_B1,
    RECEIPT_B2,
)
from test_range_batch_receipt_frontier import (
    BFRONTIER_1,
    BFRONTIER_2,
)


def stream_for(start, pairs, end, key=KEY):
    placeholder = ReceiptStream(1, start, tuple(pairs), end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_receipt_stream_mac(key, placeholder)
    )


PAIRS_12 = (
    (RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes()),
    (RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),
)
PAIR_1 = ((RECEIPT_B1.to_bytes(), RBATCH_1.to_bytes()),)

STREAM_12 = stream_for(b"", PAIRS_12, BFRONTIER_2.to_bytes())


class StreamFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        stream = ReceiptStream(
            1,
            b"",
            PAIRS_12,
            BFRONTIER_2.to_bytes(),
            STREAM_12.mac,
        )
        self.assertEqual(stream, STREAM_12)
        self.assertEqual(hash(stream), hash(STREAM_12))
        self.assertEqual(stream.version, 1)
        self.assertEqual(stream.start, b"")
        self.assertEqual(stream.items, PAIRS_12)
        self.assertEqual(stream.end, BFRONTIER_2.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            STREAM_12.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    bad, b"", PAIRS_12, BFRONTIER_2.to_bytes(), ZERO
                )
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream(
                    bad, b"", PAIRS_12, BFRONTIER_2.to_bytes(), ZERO
                )

    def test_start_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    1, bad, PAIRS_12, BFRONTIER_2.to_bytes(), ZERO
                )
        # Empty start is allowed; a non-canonical/non-frontier byte
        # string is not.
        ReceiptStream(1, b"", PAIRS_12, BFRONTIER_2.to_bytes(), ZERO)
        with self.assertRaises(ValueError):
            ReceiptStream(
                1, b"not-a-frontier", PAIRS_12,
                BFRONTIER_2.to_bytes(), ZERO,
            )
        # A RangeFrontier encoding is not a RangeBatchReceiptFrontier.
        with self.assertRaises(ValueError):
            ReceiptStream(
                1, RFRONTIER_1.to_bytes(), PAIRS_12,
                BFRONTIER_2.to_bytes(), ZERO,
            )
        # A valid frontier encoding is accepted.
        ReceiptStream(
            1, BFRONTIER_1.to_bytes(), PAIRS_12,
            BFRONTIER_2.to_bytes(), ZERO,
        )

    def test_items_contract(self):
        end = BFRONTIER_2.to_bytes()
        for bad in (b"", [PAIRS_12], None, "x"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(1, b"", bad, end, ZERO)
        with self.assertRaises(ValueError):
            ReceiptStream(1, b"", (), end, ZERO)
        with self.assertRaises(TypeError):
            ReceiptStream(1, b"", (["x", "y"],), end, ZERO)
        with self.assertRaises(ValueError):
            ReceiptStream(1, b"", ((b"",),), end, ZERO)
        with self.assertRaises(ValueError):
            ReceiptStream(1, b"", ((b"", b"", b""),), end, ZERO)
        with self.assertRaises(TypeError):
            ReceiptStream(
                1, b"", ((RECEIPT_B1, RBATCH_1.to_bytes()),), end, ZERO
            )
        with self.assertRaises(TypeError):
            ReceiptStream(
                1, b"",
                ((RECEIPT_B1.to_bytes(), RBATCH_1),), end, ZERO,
            )
        with self.assertRaises(ValueError):
            ReceiptStream(
                1, b"",
                ((b"nope", RBATCH_1.to_bytes()),), end, ZERO,
            )
        with self.assertRaises(ValueError):
            ReceiptStream(
                1, b"",
                ((RECEIPT_B1.to_bytes(), b"nope"),), end, ZERO,
            )

    def test_end_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(1, b"", PAIRS_12, bad, ZERO)
        with self.assertRaises(ValueError):
            ReceiptStream(1, b"", PAIRS_12, b"", ZERO)
        with self.assertRaises(ValueError):
            ReceiptStream(1, b"", PAIRS_12, b"junk", ZERO)

    def test_mac_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream(
                    1, b"", PAIRS_12, BFRONTIER_2.to_bytes(), bad
                )
        with self.assertRaises(ValueError):
            ReceiptStream(
                1, b"", PAIRS_12, BFRONTIER_2.to_bytes(), b"\x00" * 31
            )
        with self.assertRaises(ValueError):
            ReceiptStream(
                1, b"", PAIRS_12, BFRONTIER_2.to_bytes(), b"\x00" * 33
            )


class StreamEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        data = STREAM_12.to_bytes()
        self.assertEqual(ReceiptStream.from_bytes(data), STREAM_12)

    def test_shape_is_compact_json_array(self):
        data = STREAM_12.to_bytes()
        outer = json.loads(data)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], "")
        self.assertEqual(
            outer[2],
            [
                [RECEIPT_B1.to_bytes().hex(), RBATCH_1.to_bytes().hex()],
                [RECEIPT_B2.to_bytes().hex(), RBATCH_2.to_bytes().hex()],
            ],
        )
        self.assertEqual(outer[3], BFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], STREAM_12.mac.hex())
        # Compact, no whitespace or length prefix.
        self.assertEqual(
            data,
            json.dumps(outer, separators=(",", ":")).encode("utf-8"),
        )

    def test_mac_uses_npbj19_prefix_and_c_without_length_prefix(self):
        expected = hmac.new(
            KEY,
            b"NPBJ19" + _receipt_stream_content_bytes(STREAM_12),
            hashlib.sha256,
        ).digest()
        self.assertEqual(STREAM_12.mac, expected)

    def test_from_bytes_type_contract(self):
        for bad in (STREAM_12.to_bytes().decode("utf-8"), None, 1, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ReceiptStream.from_bytes(bad)

    def test_malformed_encoding_is_value_error(self):
        data = STREAM_12.to_bytes()
        for bad in (
            b"",
            b"not json",
            b"{}",
            b"[1]",
            b"[1,[],[],[],\"\",1]",
            data + b" ",
            data.replace(b",", b", "),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ReceiptStream.from_bytes(bad)

    def test_field_type_errors_surface_as_type_error(self):
        data = STREAM_12.to_bytes()
        outer = json.loads(data)
        # Bool/non-int version.
        tampered = json.dumps(
            [True] + outer[1:], separators=(",", ":")
        ).encode("utf-8")
        with self.assertRaises(TypeError):
            ReceiptStream.from_bytes(tampered)
        # items must be an array.
        tampered = json.dumps(
            [outer[0], outer[1], None, outer[3], outer[4]],
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaises(TypeError):
            ReceiptStream.from_bytes(tampered)

    def test_value_errors(self):
        data = STREAM_12.to_bytes()
        outer = json.loads(data)
        # Wrong version.
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(
                    [2] + outer[1:], separators=(",", ":")
                ).encode("utf-8")
            )
        # Empty items.
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(
                    [outer[0], outer[1], [], outer[3], outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Non-empty start that is not a canonical frontier.
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(
                    [outer[0], "ab", outer[2], outer[3], outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Empty end.
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(
                    [outer[0], outer[1], outer[2], "", outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Uppercase hex is not canonical.
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1], outer[2],
                        BFRONTIER_2.to_bytes().hex().upper(), outer[4],
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # mac of the wrong decoded length.
        with self.assertRaises(ValueError):
            ReceiptStream.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1], outer[2], outer[3],
                        "00" * 31,
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )

    def test_parse_does_not_verify_mac(self):
        # A structurally valid record carrying the zero MAC parses.
        record = ReceiptStream(
            1, b"", PAIRS_12, BFRONTIER_2.to_bytes(), ZERO
        )
        parsed = ReceiptStream.from_bytes(record.to_bytes())
        self.assertEqual(parsed, record)


class SealStreamTest(unittest.TestCase):
    def test_seal_empty_start_two_commits(self):
        stream = seal_stream(PAIRS_12, KEY)
        self.assertEqual(stream.version, 1)
        self.assertEqual(stream.start, b"")
        self.assertEqual(stream.items, PAIRS_12)
        self.assertEqual(stream.end, BFRONTIER_2.to_bytes())
        self.assertEqual(
            stream.mac, _receipt_stream_mac(KEY, stream)
        )

    def test_seal_single_commit(self):
        stream = seal_stream(PAIR_1, KEY)
        self.assertEqual(stream.end, BFRONTIER_1.to_bytes())

    def test_seal_with_bytes_checkpoint(self):
        stream = seal_stream(
            ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),),
            KEY,
            checkpoint=BFRONTIER_1.to_bytes(),
        )
        self.assertEqual(stream.start, BFRONTIER_1.to_bytes())
        self.assertEqual(stream.end, BFRONTIER_2.to_bytes())

    def test_seal_accepts_only_bytes_pairs(self):
        # Objects are not byte pairs: TypeError.
        with self.assertRaises(TypeError):
            seal_stream(((RECEIPT_B1, RBATCH_1),), KEY)
        with self.assertRaises(TypeError):
            seal_stream(
                ((RECEIPT_B1.to_bytes(), RBATCH_1),), KEY
            )

    def test_seal_checkpoint_accepts_only_bytes_or_none(self):
        with self.assertRaises(TypeError):
            seal_stream(
                ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),),
                KEY,
                checkpoint=BFRONTIER_1,
            )
        with self.assertRaises(TypeError):
            seal_stream(
                ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),),
                KEY,
                checkpoint="x",
            )

    def test_seal_type_errors(self):
        with self.assertRaises(TypeError):
            seal_stream(None, KEY)
        with self.assertRaises(TypeError):
            seal_stream(123, KEY)
        with self.assertRaises(TypeError):
            seal_stream(PAIRS_12, "not-bytes")
        with self.assertRaises(TypeError):
            seal_stream(PAIRS_12, None)
        with self.assertRaises(TypeError):
            seal_stream(((None, RBATCH_1.to_bytes()),), KEY)
        with self.assertRaises(TypeError):
            seal_stream(((RECEIPT_B1.to_bytes(), None),), KEY)

    def test_seal_value_errors(self):
        with self.assertRaises(ValueError):
            seal_stream((), KEY)
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_12, b"")
        with self.assertRaises(ValueError):
            seal_stream(
                ((b"junk", RBATCH_1.to_bytes()),), KEY
            )
        with self.assertRaises(ValueError):
            seal_stream(
                PAIRS_12, KEY, checkpoint=b"junk"
            )
        # Out of order: the second commit cannot start the chain.
        with self.assertRaises(ValueError):
            seal_stream(
                ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),), KEY
            )
        # Reversed order breaks the NPBJ18 chain.
        with self.assertRaises(ValueError):
            seal_stream(tuple(reversed(PAIRS_12)), KEY)
        # A receipt paired with the wrong batch fails the audit.
        with self.assertRaises(ValueError):
            seal_stream(
                ((RECEIPT_B1.to_bytes(), RBATCH_2.to_bytes()),), KEY
            )
        # Wrong key: the carried MACs fail to verify.
        with self.assertRaises(ValueError):
            seal_stream(PAIRS_12, OTHER_KEY)

    def test_seal_is_pure_and_deterministic(self):
        first = seal_stream(PAIRS_12, KEY)
        second = seal_stream(PAIRS_12, KEY)
        self.assertEqual(first, second)
        self.assertEqual(first.to_bytes(), second.to_bytes())
        # Sealing must not have consumed the commits: sealing again
        # from an empty start still works identically.
        self.assertEqual(
            seal_stream(PAIRS_12, KEY).end, BFRONTIER_2.to_bytes()
        )


class AuditStreamTest(unittest.TestCase):
    def test_audit_returns_canonical_end_bytes(self):
        result = audit_stream(STREAM_12, KEY)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, STREAM_12.end)
        self.assertEqual(result, BFRONTIER_2.to_bytes())

    def test_audit_accepts_canonical_bytes(self):
        result = audit_stream(STREAM_12.to_bytes(), KEY)
        self.assertEqual(result, BFRONTIER_2.to_bytes())

    def test_audit_with_starting_checkpoint(self):
        stream = seal_stream(
            ((RECEIPT_B2.to_bytes(), RBATCH_2.to_bytes()),),
            KEY,
            checkpoint=BFRONTIER_1.to_bytes(),
        )
        self.assertEqual(
            audit_stream(stream, KEY), BFRONTIER_2.to_bytes()
        )

    def test_audit_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_stream(STREAM_12, OTHER_KEY)

    def test_audit_key_contract(self):
        for bad in ("k", None, 1, b""):
            with self.assertRaises(
                (TypeError, ValueError), msg=repr(bad)
            ):
                audit_stream(STREAM_12, bad)
        with self.assertRaises(TypeError):
            audit_stream(STREAM_12, "k")
        with self.assertRaises(ValueError):
            audit_stream(STREAM_12, b"")

    def test_audit_x_contract(self):
        for bad in (None, 1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream(bad, KEY)
        with self.assertRaises(ValueError):
            audit_stream(b"not json", KEY)
        with self.assertRaises(ValueError):
            audit_stream(b"[1,[],[],[],\"\"]", KEY)

    def test_audit_tampered_mac(self):
        outer = json.loads(STREAM_12.to_bytes())
        outer[4] = (b"\x00" * 32).hex()
        forged = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_stream(forged, KEY)

    def test_audit_tampered_body_with_recomputed_mac_fails_replay(self):
        # Swap the item order but give the record a valid NPBJ19 MAC:
        # the MAC passes but the NPBJ18 replay must reject it.
        record = _rebuild(STREAM_12, items=tuple(reversed(PAIRS_12)))
        with self.assertRaises(ValueError):
            audit_stream(record, KEY)

    def test_audit_wrong_end_with_valid_mac_fails(self):
        record = _rebuild(STREAM_12, end=BFRONTIER_1.to_bytes())
        with self.assertRaises(ValueError):
            audit_stream(record, KEY)

    def test_audit_mac_from_other_key_rejected(self):
        record = dataclasses.replace(
            STREAM_12,
            mac=_receipt_stream_mac(OTHER_KEY, STREAM_12),
        )
        with self.assertRaises(ValueError):
            audit_stream(record, KEY)

    def test_audit_is_pure(self):
        # Auditing repeatedly leaves both the record and the underlying
        # checkpoint semantics untouched.
        for _ in range(3):
            self.assertEqual(
                audit_stream(STREAM_12, KEY), BFRONTIER_2.to_bytes()
            )
        self.assertEqual(
            audit_stream(STREAM_12.to_bytes(), KEY),
            audit_stream(STREAM_12, KEY),
        )


def _rebuild(stream, *, start=None, items=None, end=None):
    """Replace structural fields of a stream and re-MAC under KEY."""
    placeholder = ReceiptStream(
        1,
        stream.start if start is None else start,
        stream.items if items is None else items,
        stream.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_receipt_stream_mac(KEY, placeholder)
    )


if __name__ == "__main__":
    unittest.main()
