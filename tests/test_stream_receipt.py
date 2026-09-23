import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeBatchReceiptAuditor,
    StreamReceipt,
    _stream_receipt_content_bytes,
    _stream_receipt_digest,
    _stream_receipt_mac,
    audit_stream_receipt,
    seal_stream,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    ZERO,
)
from test_range_batch_receipt import (
    RBATCH_1,
    RECEIPT_B1,
)
from test_range_batch_receipt_frontier import (
    BFRONTIER_1,
    BFRONTIER_2,
)
from test_receipt_stream import (
    PAIR_1,
    PAIRS_12,
    STREAM_12,
    stream_for,
)


def receipt_for(stream, key=KEY, start=None, end=None):
    """Mint the stream receipt a successful commit_stream would mint."""
    placeholder = StreamReceipt(
        1,
        stream.start if start is None else start,
        _stream_receipt_digest(stream),
        stream.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder, mac=_stream_receipt_mac(key, placeholder)
    )


RECEIPT_12 = receipt_for(STREAM_12)


class StreamReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = StreamReceipt(
            1,
            RECEIPT_12.start,
            RECEIPT_12.digest,
            RECEIPT_12.end,
            RECEIPT_12.mac,
        )
        self.assertEqual(receipt, RECEIPT_12)
        self.assertEqual(hash(receipt), hash(RECEIPT_12))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.digest, RECEIPT_12.digest)
        self.assertEqual(receipt.end, BFRONTIER_2.to_bytes())
        self.assertEqual(receipt.mac, RECEIPT_12.mac)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_12.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceipt(
                    bad, b"", ZERO, BFRONTIER_2.to_bytes(), ZERO
                )
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceipt(
                    bad, b"", ZERO, BFRONTIER_2.to_bytes(), ZERO
                )

    def test_start_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceipt(
                    1, bad, ZERO, BFRONTIER_2.to_bytes(), ZERO
                )
        # Empty start is allowed; a non-frontier byte string is not.
        StreamReceipt(1, b"", ZERO, BFRONTIER_2.to_bytes(), ZERO)
        with self.assertRaises(ValueError):
            StreamReceipt(
                1, b"not-a-frontier", ZERO,
                BFRONTIER_2.to_bytes(), ZERO,
            )
        # A valid frontier encoding is accepted.
        StreamReceipt(
            1, BFRONTIER_1.to_bytes(), ZERO,
            BFRONTIER_2.to_bytes(), ZERO,
        )

    def test_digest_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceipt(
                    1, b"", bad, BFRONTIER_2.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            StreamReceipt(
                1, b"", b"\x00" * 31, BFRONTIER_2.to_bytes(), ZERO
            )
        with self.assertRaises(ValueError):
            StreamReceipt(
                1, b"", b"\x00" * 33, BFRONTIER_2.to_bytes(), ZERO
            )

    def test_end_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceipt(1, b"", ZERO, bad, ZERO)
        with self.assertRaises(ValueError):
            StreamReceipt(1, b"", ZERO, b"", ZERO)
        with self.assertRaises(ValueError):
            StreamReceipt(1, b"", ZERO, b"junk", ZERO)

    def test_mac_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceipt(
                    1, b"", ZERO, BFRONTIER_2.to_bytes(), bad
                )
        with self.assertRaises(ValueError):
            StreamReceipt(
                1, b"", ZERO, BFRONTIER_2.to_bytes(), b"\x00" * 31
            )
        with self.assertRaises(ValueError):
            StreamReceipt(
                1, b"", ZERO, BFRONTIER_2.to_bytes(), b"\x00" * 33
            )


class StreamReceiptEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        data = RECEIPT_12.to_bytes()
        self.assertEqual(StreamReceipt.from_bytes(data), RECEIPT_12)

    def test_shape_is_compact_json_array(self):
        data = RECEIPT_12.to_bytes()
        outer = json.loads(data)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], "")
        self.assertEqual(
            outer[2], hashlib.sha256(STREAM_12.to_bytes()).hexdigest()
        )
        self.assertEqual(outer[3], BFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], RECEIPT_12.mac.hex())
        # Compact, no whitespace or length prefix.
        self.assertEqual(
            data,
            json.dumps(outer, separators=(",", ":")).encode("utf-8"),
        )

    def test_digest_is_sha256_of_stream_bytes(self):
        self.assertEqual(
            RECEIPT_12.digest,
            hashlib.sha256(STREAM_12.to_bytes()).digest(),
        )

    def test_mac_uses_npbj20_prefix_and_c_without_length_prefix(self):
        expected = hmac.new(
            KEY,
            b"NPBJ20" + _stream_receipt_content_bytes(RECEIPT_12),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_12.mac, expected)

    def test_from_bytes_type_contract(self):
        for bad in (RECEIPT_12.to_bytes().decode("utf-8"), None, 1, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceipt.from_bytes(bad)

    def test_malformed_encoding_is_value_error(self):
        data = RECEIPT_12.to_bytes()
        for bad in (
            b"",
            b"not json",
            b"{}",
            b"[1]",
            b"[1,\"\",\"\",\"\",1]",
            data + b" ",
            data.replace(b",", b", "),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceipt.from_bytes(bad)

    def test_field_type_errors_surface_as_type_error(self):
        data = RECEIPT_12.to_bytes()
        outer = json.loads(data)
        # Bool/non-int version.
        tampered = json.dumps(
            [True] + outer[1:], separators=(",", ":")
        ).encode("utf-8")
        with self.assertRaises(TypeError):
            StreamReceipt.from_bytes(tampered)
        # digest must be a hex string, not null.
        tampered = json.dumps(
            [outer[0], outer[1], None, outer[3], outer[4]],
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaises(TypeError):
            StreamReceipt.from_bytes(tampered)

    def test_value_errors(self):
        data = RECEIPT_12.to_bytes()
        outer = json.loads(data)
        # Wrong version.
        with self.assertRaises(ValueError):
            StreamReceipt.from_bytes(
                json.dumps(
                    [2] + outer[1:], separators=(",", ":")
                ).encode("utf-8")
            )
        # Non-empty start that is not a canonical frontier.
        with self.assertRaises(ValueError):
            StreamReceipt.from_bytes(
                json.dumps(
                    [outer[0], "ab", outer[2], outer[3], outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # digest of the wrong decoded length.
        with self.assertRaises(ValueError):
            StreamReceipt.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1], "00" * 31,
                        outer[3], outer[4],
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Empty end.
        with self.assertRaises(ValueError):
            StreamReceipt.from_bytes(
                json.dumps(
                    [outer[0], outer[1], outer[2], "", outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Uppercase hex is not canonical.
        with self.assertRaises(ValueError):
            StreamReceipt.from_bytes(
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
            StreamReceipt.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1], outer[2], outer[3],
                        "00" * 31,
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )

    def test_parse_does_not_verify(self):
        # A structurally valid record carrying the zero digest and MAC
        # parses; no signature or digest is checked.
        record = StreamReceipt(
            1, b"", ZERO, BFRONTIER_2.to_bytes(), ZERO
        )
        parsed = StreamReceipt.from_bytes(record.to_bytes())
        self.assertEqual(parsed, record)


class CommitStreamTest(unittest.TestCase):
    def test_commits_and_mints_receipt(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        receipt = auditor.commit_stream(STREAM_12)
        self.assertIsInstance(receipt, StreamReceipt)
        self.assertEqual(auditor.state, BFRONTIER_2)
        self.assertEqual(receipt, RECEIPT_12)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, BFRONTIER_2.to_bytes())
        self.assertEqual(
            receipt.digest, hashlib.sha256(STREAM_12.to_bytes()).digest()
        )
        self.assertEqual(
            receipt.mac, _stream_receipt_mac(KEY, receipt)
        )

    def test_accepts_canonical_bytes(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        receipt = auditor.commit_stream(STREAM_12.to_bytes())
        self.assertEqual(receipt, RECEIPT_12)
        self.assertEqual(auditor.state, BFRONTIER_2)

    def test_single_commit(self):
        stream = stream_for(b"", PAIR_1, BFRONTIER_1.to_bytes())
        auditor = RangeBatchReceiptAuditor(KEY)
        receipt = auditor.commit_stream(stream)
        self.assertEqual(auditor.state, BFRONTIER_1)
        self.assertEqual(receipt.end, BFRONTIER_1.to_bytes())
        self.assertEqual(
            receipt.digest, hashlib.sha256(stream.to_bytes()).digest()
        )

    def test_continues_from_audited_frontier(self):
        continuation = seal_stream(
            (PAIRS_12[1],),
            KEY,
            checkpoint=BFRONTIER_1.to_bytes(),
        )
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        receipt = auditor.commit_stream(continuation)
        self.assertEqual(auditor.state, BFRONTIER_2)
        self.assertEqual(receipt.start, BFRONTIER_1.to_bytes())
        self.assertEqual(receipt.end, BFRONTIER_2.to_bytes())

    def test_replay_rejected_without_state_change_or_receipt(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        first = auditor.commit_stream(STREAM_12)
        self.assertEqual(first, RECEIPT_12)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_stream(STREAM_12)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.commit_stream(STREAM_12.to_bytes())
        self.assertIs(auditor.state, before)

    def test_wrong_key(self):
        auditor = RangeBatchReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.commit_stream(STREAM_12)
        self.assertIsNone(auditor.state)

    def test_x_type_contract(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        for bad in (None, 1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_stream(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_stream(b"not json")
        self.assertIsNone(auditor.state)

    def test_failed_stream_is_atomic_and_mints_nothing(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        auditor.audit(RECEIPT_B1, RBATCH_1)
        broken = (
            PAIRS_12[1],
            PAIRS_12[0],
        )
        record = stream_for(
            BFRONTIER_1.to_bytes(), broken, BFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            auditor.commit_stream(record)
        # The failed commit leaves the auditor exactly at BFRONTIER_1.
        self.assertEqual(auditor.state, BFRONTIER_1)

    def test_commit_and_audit_share_the_lock(self):
        auditor = RangeBatchReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(2)

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
                    lambda: auditor.commit_stream(STREAM_12),
                    "stream",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_B1, RBATCH_1),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Both actions start from the empty frontier; exactly one wins.
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        if successes[0] == "stream":
            self.assertEqual(auditor.state, BFRONTIER_2)
        else:
            self.assertEqual(auditor.state, BFRONTIER_1)


class AuditStreamReceiptTest(unittest.TestCase):
    def test_returns_canonical_end_bytes(self):
        result = audit_stream_receipt(RECEIPT_12, STREAM_12, KEY)
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, STREAM_12.end)
        self.assertEqual(result, BFRONTIER_2.to_bytes())

    def test_accepts_canonical_bytes_in_either_slot(self):
        end = BFRONTIER_2.to_bytes()
        self.assertEqual(
            audit_stream_receipt(
                RECEIPT_12.to_bytes(), STREAM_12.to_bytes(), KEY
            ),
            end,
        )
        self.assertEqual(
            audit_stream_receipt(RECEIPT_12, STREAM_12.to_bytes(), KEY),
            end,
        )
        self.assertEqual(
            audit_stream_receipt(RECEIPT_12.to_bytes(), STREAM_12, KEY),
            end,
        )

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_stream_receipt(RECEIPT_12, STREAM_12, OTHER_KEY)

    def test_key_contract(self):
        for bad in ("k", None, 1, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_receipt(RECEIPT_12, STREAM_12, bad)
        with self.assertRaises(ValueError):
            audit_stream_receipt(RECEIPT_12, STREAM_12, b"")

    def test_r_contract(self):
        for bad in (None, 1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_receipt(bad, STREAM_12, KEY)
        with self.assertRaises(ValueError):
            audit_stream_receipt(b"not json", STREAM_12, KEY)

    def test_x_contract(self):
        for bad in (None, 1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_receipt(RECEIPT_12, bad, KEY)
        with self.assertRaises(ValueError):
            audit_stream_receipt(RECEIPT_12, b"not json", KEY)

    def test_tampered_mac(self):
        tampered = dataclasses.replace(RECEIPT_12, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_receipt(tampered, STREAM_12, KEY)

    def test_tampered_digest_with_recomputed_mac(self):
        tampered = StreamReceipt(
            1,
            RECEIPT_12.start,
            b"\x01" + b"\x00" * 31,
            RECEIPT_12.end,
            ZERO,
        )
        tampered = dataclasses.replace(
            tampered, mac=_stream_receipt_mac(KEY, tampered)
        )
        with self.assertRaises(ValueError):
            audit_stream_receipt(tampered, STREAM_12, KEY)

    def test_wrong_endpoint_with_recomputed_mac(self):
        wrong = StreamReceipt(
            1,
            RECEIPT_12.start,
            RECEIPT_12.digest,
            BFRONTIER_1.to_bytes(),
            ZERO,
        )
        wrong = dataclasses.replace(
            wrong, mac=_stream_receipt_mac(KEY, wrong)
        )
        with self.assertRaises(ValueError):
            audit_stream_receipt(wrong, STREAM_12, KEY)

    def test_receipt_from_other_stream_rejected(self):
        stream = stream_for(b"", PAIR_1, BFRONTIER_1.to_bytes())
        other = receipt_for(stream)
        # A perfectly valid receipt over a one-commit stream does not
        # match the two-commit stream.
        with self.assertRaises(ValueError):
            audit_stream_receipt(other, STREAM_12, KEY)
        self.assertEqual(
            audit_stream_receipt(other, stream, KEY),
            BFRONTIER_1.to_bytes(),
        )

    def test_stream_replay_runs_even_when_outer_layers_pass(self):
        # Tamper only the carried stream MAC, then mint a stream receipt
        # over exactly those tampered bytes with a valid NPBJ20 MAC: the
        # receipt MAC, digest and endpoints all pass, but rerunning
        # audit_stream must reject the broken NPBJ19 stream.
        tampered_stream = dataclasses.replace(STREAM_12, mac=ZERO)
        receipt = receipt_for(tampered_stream)
        with self.assertRaises(ValueError):
            audit_stream_receipt(receipt, tampered_stream, KEY)

    def test_is_pure(self):
        for _ in range(3):
            self.assertEqual(
                audit_stream_receipt(RECEIPT_12, STREAM_12, KEY),
                BFRONTIER_2.to_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
