import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamReceiptAuditor,
    StreamReceiptFrontier,
    _range_batch_receipt_frontier_content_bytes,
    _stream_receipt_frontier_content_bytes,
    _stream_receipt_frontier_mac,
    _stream_receipt_frontier_next_digest,
    seal_stream,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    ZERO,
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
from test_stream_receipt import (
    RECEIPT_12,
    receipt_for,
)


SINGLE_STREAM = stream_for(b"", PAIR_1, BFRONTIER_1.to_bytes())
SINGLE_RECEIPT = receipt_for(SINGLE_STREAM)
# The continuation stream seals only the second commit starting from the
# BFRONTIER_1 checkpoint, so its receipt starts at BFRONTIER_1 bytes.
CONTINUATION_STREAM = seal_stream(
    (PAIRS_12[1],), KEY, checkpoint=BFRONTIER_1.to_bytes()
)
CONTINUATION_RECEIPT = receipt_for(CONTINUATION_STREAM)


def stream_frontier_for(sequence, end, digest, key=KEY):
    placeholder = StreamReceiptFrontier(
        1, sequence, end, digest, ZERO
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_receipt_frontier_mac(key, placeholder),
    )


SDIGEST_1 = _stream_receipt_frontier_next_digest(
    ZERO, 1, RECEIPT_12.to_bytes()
)
# The single-then-continuation chain: first the one-commit receipt,
# then the BFRONTIER_1 -> BFRONTIER_2 continuation receipt.
SDIGEST_SINGLE = _stream_receipt_frontier_next_digest(
    ZERO, 1, SINGLE_RECEIPT.to_bytes()
)
SDIGEST_2 = _stream_receipt_frontier_next_digest(
    SDIGEST_SINGLE, 2, CONTINUATION_RECEIPT.to_bytes()
)
SFRONTIER_1 = stream_frontier_for(
    1, BFRONTIER_2.to_bytes(), SDIGEST_1
)


class StreamReceiptFrontierFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        frontier = StreamReceiptFrontier(
            1,
            SFRONTIER_1.sequence,
            SFRONTIER_1.end,
            SFRONTIER_1.digest,
            SFRONTIER_1.mac,
        )
        self.assertEqual(frontier, SFRONTIER_1)
        self.assertEqual(hash(frontier), hash(SFRONTIER_1))
        self.assertEqual(frontier.version, 1)
        self.assertEqual(frontier.sequence, 1)
        self.assertEqual(frontier.end, BFRONTIER_2.to_bytes())
        self.assertEqual(frontier.digest, SDIGEST_1)
        self.assertEqual(frontier.mac, SFRONTIER_1.mac)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            SFRONTIER_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier(
                    bad, 1, BFRONTIER_2.to_bytes(), ZERO, ZERO
                )
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier(
                    bad, 1, BFRONTIER_2.to_bytes(), ZERO, ZERO
                )

    def test_sequence_contract(self):
        for bad in (True, False, "1", 1.0, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier(
                    1, bad, BFRONTIER_2.to_bytes(), ZERO, ZERO
                )
        for bad in (-1, 0x10000000000000000):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier(
                    1, bad, BFRONTIER_2.to_bytes(), ZERO, ZERO
                )
        # Both u64 endpoints are accepted.
        StreamReceiptFrontier(
            1, 0, BFRONTIER_2.to_bytes(), ZERO, ZERO
        )
        StreamReceiptFrontier(
            1, 0xFFFFFFFFFFFFFFFF, BFRONTIER_2.to_bytes(), ZERO, ZERO
        )

    def test_end_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier(1, 1, bad, ZERO, ZERO)
        for bad in (b"", b"junk", b"[1]", b"null"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier(1, 1, bad, ZERO, ZERO)
        # A valid canonical range-batch receipt frontier encoding.
        StreamReceiptFrontier(
            1, 1, BFRONTIER_1.to_bytes(), ZERO, ZERO
        )

    def test_digest_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier(
                    1, 1, BFRONTIER_2.to_bytes(), bad, ZERO
                )
        for bad in (b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier(
                    1, 1, BFRONTIER_2.to_bytes(), bad, ZERO
                )

    def test_mac_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier(
                    1, 1, BFRONTIER_2.to_bytes(), ZERO, bad
                )
        for bad in (b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier(
                    1, 1, BFRONTIER_2.to_bytes(), ZERO, bad
                )


class StreamReceiptFrontierEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        data = SFRONTIER_1.to_bytes()
        self.assertEqual(
            StreamReceiptFrontier.from_bytes(data), SFRONTIER_1
        )

    def test_shape_is_compact_json_array(self):
        data = SFRONTIER_1.to_bytes()
        outer = json.loads(data)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], 1)
        self.assertEqual(outer[2], BFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[3], SDIGEST_1.hex())
        self.assertEqual(outer[4], SFRONTIER_1.mac.hex())
        # Compact, no whitespace or length prefix.
        self.assertEqual(
            data,
            json.dumps(outer, separators=(",", ":")).encode("utf-8"),
        )

    def test_digest_chain_uses_npbj22_prefix(self):
        expected = hashlib.sha256(
            b"NPBJ22"
            + ZERO
            + (1).to_bytes(8, byteorder="big")
            + RECEIPT_12.to_bytes()
        ).digest()
        self.assertEqual(SDIGEST_1, expected)

    def test_mac_uses_npbj21_prefix_and_c_without_length_prefix(self):
        expected = hmac.new(
            KEY,
            b"NPBJ21" + _stream_receipt_frontier_content_bytes(SFRONTIER_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(SFRONTIER_1.mac, expected)

    def test_from_bytes_type_contract(self):
        for bad in (
            SFRONTIER_1.to_bytes().decode("utf-8"), None, 1, []
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptFrontier.from_bytes(bad)

    def test_malformed_encoding_is_value_error(self):
        data = SFRONTIER_1.to_bytes()
        for bad in (
            b"",
            b"not json",
            b"{}",
            b"[1]",
            b"[1,1,\"\",\"\",1]",
            data + b" ",
            data.replace(b",", b", "),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptFrontier.from_bytes(bad)

    def test_field_type_errors_surface_as_type_error(self):
        data = SFRONTIER_1.to_bytes()
        outer = json.loads(data)
        # Bool sequence.
        tampered = json.dumps(
            [outer[0], True] + outer[2:], separators=(",", ":")
        ).encode("utf-8")
        with self.assertRaises(TypeError):
            StreamReceiptFrontier.from_bytes(tampered)
        # digest must be a hex string, not null.
        tampered = json.dumps(
            [outer[0], outer[1], outer[2], None, outer[4]],
            separators=(",", ":"),
        ).encode("utf-8")
        with self.assertRaises(TypeError):
            StreamReceiptFrontier.from_bytes(tampered)

    def test_value_errors(self):
        data = SFRONTIER_1.to_bytes()
        outer = json.loads(data)
        # Wrong version.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [2] + outer[1:], separators=(",", ":")
                ).encode("utf-8")
            )
        # Sequence out of u64 range.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [outer[0], 0x10000000000000000] + outer[2:],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Empty end.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [outer[0], outer[1], "", outer[3], outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # end that is not a canonical frontier.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [outer[0], outer[1], "ab", outer[3], outer[4]],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # digest of the wrong decoded length.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1], outer[2],
                        "00" * 31, outer[4],
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # Uppercase hex is not canonical.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1],
                        BFRONTIER_2.to_bytes().hex().upper(),
                        outer[3], outer[4],
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        # mac of the wrong decoded length.
        with self.assertRaises(ValueError):
            StreamReceiptFrontier.from_bytes(
                json.dumps(
                    [
                        outer[0], outer[1], outer[2], outer[3],
                        "00" * 31,
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            )

    def test_parse_does_not_verify_mac(self):
        # A structurally valid record carrying the zero digest and MAC
        # parses; neither its own MAC nor the nested end MACs are
        # checked.
        record = StreamReceiptFrontier(
            1, 3, BFRONTIER_2.to_bytes(), ZERO, ZERO
        )
        parsed = StreamReceiptFrontier.from_bytes(record.to_bytes())
        self.assertEqual(parsed, record)


class StreamReceiptAuditorConstructorTest(unittest.TestCase):
    def test_starts_empty(self):
        auditor = StreamReceiptAuditor(KEY)
        self.assertIsNone(auditor.state)

    def test_key_contract(self):
        for bad in ("k", None, 1, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptAuditor(bad)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(b"")

    def test_checkpoint_type_contract(self):
        for bad in (1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamReceiptAuditor(KEY, checkpoint=bad)
        # bytes is the right kind of argument; malformed or empty byte
        # content surfaces as a value error, like the other auditors.
        for bad in (b"", b"[1,1,\"\",\"\",\"\"]", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamReceiptAuditor(KEY, checkpoint=bad)

    def test_checkpoint_bytes_field_shape_is_value_error(self):
        # Kept explicit: the right kind of argument whose content
        # violates the field contract is a value error.
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(
                KEY, checkpoint=b"[1,1,\"ab\",\"\",\"00\"]"
            )

    def test_checkpoint_accepts_frozen_object_and_bytes(self):
        auditor = StreamReceiptAuditor(
            KEY, checkpoint=SFRONTIER_1
        )
        self.assertEqual(auditor.state, SFRONTIER_1)
        self.assertIsNot(auditor.state, None)
        restarted = StreamReceiptAuditor(
            KEY, checkpoint=SFRONTIER_1.to_bytes()
        )
        self.assertEqual(restarted.state, SFRONTIER_1)

    def test_checkpoint_state_export_is_read_only(self):
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(AttributeError):
            auditor.state = SFRONTIER_1

    def test_checkpoint_own_mac_must_verify(self):
        tampered = dataclasses.replace(SFRONTIER_1, mac=ZERO)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(KEY, checkpoint=tampered)
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(
                KEY, checkpoint=tampered.to_bytes()
            )

    def test_checkpoint_digest_tamper_with_recomputed_mac_rejected_via_restart_semantics(self):
        # A forged digest with a fresh NPBJ21 MAC loads (no history is
        # stored to compare against), but an inconsistent end never can:
        # pointing the frontier end at a frontier MAC'd under another
        # key fails the nested MAC verification.
        forged = stream_frontier_for(
            SFRONTIER_1.sequence,
            BFRONTIER_2.to_bytes(),
            b"\x01" + b"\x00" * 31,
        )
        auditor = StreamReceiptAuditor(KEY, checkpoint=forged)
        self.assertEqual(auditor.state, forged)

    def test_checkpoint_nested_end_macs_must_verify(self):
        # Re-tag the end with another key's NPBJ17 MAC and re-MAC the
        # outer checkpoint with our key: the outer layer passes but the
        # nested end verification must fail.
        foreign_end = dataclasses.replace(
            BFRONTIER_2,
            mac=hmac.new(
                OTHER_KEY,
                b"NPBJ17"
                + _range_batch_receipt_frontier_content_bytes(
                    BFRONTIER_2
                ),
                hashlib.sha256,
            ).digest(),
        )
        forged = stream_frontier_for(
            1, foreign_end.to_bytes(), SDIGEST_1
        )
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(KEY, checkpoint=forged)

    def test_checkpoint_wrong_key(self):
        with self.assertRaises(ValueError):
            StreamReceiptAuditor(OTHER_KEY, checkpoint=SFRONTIER_1)


class StreamReceiptAuditorAuditTest(unittest.TestCase):
    def test_audit_advances_to_frontier(self):
        auditor = StreamReceiptAuditor(KEY)
        result = auditor.audit(RECEIPT_12, STREAM_12)
        self.assertIs(result, auditor)
        self.assertEqual(auditor.state, SFRONTIER_1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.end, BFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state.digest, SDIGEST_1)
        self.assertEqual(
            auditor.state.mac,
            _stream_receipt_frontier_mac(KEY, auditor.state),
        )

    def test_accepts_canonical_bytes_in_either_slot(self):
        a = StreamReceiptAuditor(KEY)
        a.audit(RECEIPT_12.to_bytes(), STREAM_12.to_bytes())
        self.assertEqual(a.state, SFRONTIER_1)
        b = StreamReceiptAuditor(KEY)
        b.audit(RECEIPT_12, STREAM_12.to_bytes())
        self.assertEqual(b.state, SFRONTIER_1)
        c = StreamReceiptAuditor(KEY)
        c.audit(RECEIPT_12.to_bytes(), STREAM_12)
        self.assertEqual(c.state, SFRONTIER_1)

    def test_chains_receipts_by_start_equals_end(self):
        auditor = StreamReceiptAuditor(KEY)
        # First the single-commit receipt ends at BFRONTIER_1.
        first = stream_frontier_for(
            1,
            BFRONTIER_1.to_bytes(),
            _stream_receipt_frontier_next_digest(
                ZERO, 1, SINGLE_RECEIPT.to_bytes()
            ),
        )
        auditor.audit(SINGLE_RECEIPT, SINGLE_STREAM)
        self.assertEqual(auditor.state, first)
        # The continuation receipt starts exactly at BFRONTIER_1 and
        # ends at BFRONTIER_2.
        auditor.audit(CONTINUATION_RECEIPT, CONTINUATION_STREAM)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.end, BFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state.digest, SDIGEST_2)

    def test_restarts_from_exported_checkpoint(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(SINGLE_RECEIPT, SINGLE_STREAM)
        exported = auditor.state.to_bytes()
        restarted = StreamReceiptAuditor(KEY, checkpoint=exported)
        restarted.audit(CONTINUATION_RECEIPT, CONTINUATION_STREAM)
        self.assertEqual(restarted.state.sequence, 2)
        self.assertEqual(restarted.state.end, BFRONTIER_2.to_bytes())
        self.assertEqual(restarted.state.digest, SDIGEST_2)
        # And again from the frozen object itself.
        again = StreamReceiptAuditor(
            KEY, checkpoint=restarted.state
        )
        self.assertEqual(again.state, restarted.state)

    def test_replay_is_rollback(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(SINGLE_RECEIPT, SINGLE_STREAM)
        before = auditor.state
        # The same genesis receipt again: its empty start no longer
        # matches the ledger at BFRONTIER_1.
        with self.assertRaises(ValueError):
            auditor.audit(SINGLE_RECEIPT, SINGLE_STREAM)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.audit(
                SINGLE_RECEIPT.to_bytes(), SINGLE_STREAM.to_bytes()
            )
        self.assertIs(auditor.state, before)

    def test_forked_receipt_with_matching_start_rejected_on_audit(self):
        # After the two-commit receipt, a different receipt also ending
        # at BFRONTIER_2 but starting at BFRONTIER_1 cannot be chained:
        # the ledger stands at BFRONTIER_2 and its start is old.
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(RECEIPT_12, STREAM_12)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(
                CONTINUATION_RECEIPT, CONTINUATION_STREAM
            )
        self.assertIs(auditor.state, before)

    def test_genesis_receipt_requires_empty_start(self):
        # An auditor seeded at BFRONTIER_1 rejects the genesis receipt.
        seeded = stream_frontier_for(
            1,
            BFRONTIER_1.to_bytes(),
            _stream_receipt_frontier_next_digest(
                ZERO, 1, SINGLE_RECEIPT.to_bytes()
            ),
        )
        auditor = StreamReceiptAuditor(KEY, checkpoint=seeded)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_12, STREAM_12)
        self.assertEqual(auditor.state, seeded)

    def test_wrong_key(self):
        auditor = StreamReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_12, STREAM_12)
        self.assertIsNone(auditor.state)

    def test_argument_type_contract(self):
        auditor = StreamReceiptAuditor(KEY)
        for bad in (None, 1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad, STREAM_12)
        for bad in (None, 1, "x", [], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(RECEIPT_12, bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(b"not json", STREAM_12)
        with self.assertRaises(ValueError):
            auditor.audit(RECEIPT_12, b"not json")
        self.assertIsNone(auditor.state)

    def test_bad_stream_receipt_pair_is_value_error(self):
        # A perfectly MAC'd receipt over one stream does not match
        # another stream.
        auditor = StreamReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(SINGLE_RECEIPT, STREAM_12)
        self.assertIsNone(auditor.state)

    def test_failed_audit_is_atomic(self):
        auditor = StreamReceiptAuditor(KEY)
        auditor.audit(SINGLE_RECEIPT, SINGLE_STREAM)
        before = auditor.state
        # A broken committed stream (tampered NPBJ19 MAC) carrying a
        # valid-looking NPBJ20 receipt fails inside audit_stream_receipt
        # before the ledger advances.
        tampered_stream = dataclasses.replace(STREAM_12, mac=ZERO)
        tampered_receipt = receipt_for(tampered_stream)
        with self.assertRaises(ValueError):
            auditor.audit(tampered_receipt, tampered_stream)
        self.assertIs(auditor.state, before)

    def test_sequence_overflow_is_value_error_without_state_change(self):
        # A checkpoint legitimately MAC'd at the u64 top sequence loads;
        # the continuation receipt starts exactly at its BFRONTIER_1 end,
        # so its audit reaches the increment and must refuse to
        # overflow.
        top = stream_frontier_for(
            0xFFFFFFFFFFFFFFFF,
            BFRONTIER_1.to_bytes(),
            SDIGEST_1,
        )
        auditor = StreamReceiptAuditor(KEY, checkpoint=top)
        with self.assertRaises(ValueError):
            auditor.audit(
                CONTINUATION_RECEIPT, CONTINUATION_STREAM
            )
        self.assertIs(auditor.state, top)

    def test_concurrent_audits_linearize(self):
        auditor = StreamReceiptAuditor(KEY)
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
                    lambda: auditor.audit(RECEIPT_12, STREAM_12),
                    "full",
                ),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(
                        SINGLE_RECEIPT, SINGLE_STREAM
                    ),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Both receipts require the empty start; exactly one wins.
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        if successes[0] == "full":
            self.assertEqual(auditor.state.end, BFRONTIER_2.to_bytes())
            self.assertEqual(auditor.state.sequence, 1)
        else:
            self.assertEqual(auditor.state.end, BFRONTIER_1.to_bytes())
            self.assertEqual(auditor.state.sequence, 1)


if __name__ == "__main__":
    unittest.main()
