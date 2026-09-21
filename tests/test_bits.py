import hashlib
import hmac
import json
import math
import unittest

from nearproof import Prover, Verifier, audit_b, bit_commitment, bit_response

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret-key"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
TOKEN = b"t" * 16
DIGEST = bit_commitment(CONTEXT, OPENING)
SPEED = 1000.0


class TickingClock:
    """A clock that advances by a fixed step on every read."""

    def __init__(self, step: float = 0.0, start: float = 100.0) -> None:
        self.step = step
        self.now = start

    def __call__(self) -> float:
        now = self.now
        self.now += self.step
        return now


def make_bits(step=0.001953125, rounds=4, timeout=0.01, verifier_key=KEY,
              prover_key=KEY, speed=SPEED):
    clock = TickingClock(step=step)
    prover = Prover(prover_key)
    verifier = Verifier(verifier_key, clock=clock, speed_mps=speed)
    blob = verifier.bits(prover, CONTEXT, OPENING, rounds=rounds, timeout=timeout)
    return blob, clock


def encode_record(payload, key=KEY):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(key, b"NPFB1" + body, hashlib.sha256).hexdigest()
    return json.dumps(payload + [mac], separators=(",", ":")).encode("utf-8")


class ProverBitTest(unittest.TestCase):
    def setUp(self):
        self.prover = Prover(KEY)

    def test_response_matches_hmac_formula(self):
        for index in (0, 1, 2**32 - 1):
            for bit in (0, 1):
                expected = hmac.new(
                    KEY,
                    b"NPFR1"
                    + TOKEN
                    + index.to_bytes(4, "big")
                    + bytes([bit])
                    + DIGEST,
                    hashlib.sha256,
                ).digest()
                self.assertEqual(
                    self.prover.bit(TOKEN, DIGEST, index, bit), expected
                )

    def test_token_must_be_exactly_16_bytes(self):
        for bad in (b"", b"t" * 15, b"t" * 17, "t" * 16, None, 16):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.prover.bit(bad, DIGEST, 0, 0)

    def test_digest_must_be_exactly_32_bytes(self):
        for bad in (b"", b"d" * 31, b"d" * 33, "d" * 32, None, 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.prover.bit(TOKEN, bad, 0, 0)

    def test_index_must_be_non_bool_u32(self):
        for bad in (True, False, 0.0, 1.5, "0", None, -1, 2**32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.prover.bit(TOKEN, DIGEST, bad, 0)

    def test_bit_must_be_zero_or_one(self):
        for bad in (2, -1, 0.0, 1.0, "0", None, b"\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.prover.bit(TOKEN, DIGEST, 0, bad)

    def test_commitment_matches_sha256_formula(self):
        self.assertEqual(
            bit_commitment(CONTEXT, OPENING),
            hashlib.sha256(b"NPFC1" + CONTEXT + OPENING).digest(),
        )


class VerifierBitsContractTest(unittest.TestCase):
    def setUp(self):
        self.prover = Prover(KEY)
        self.verifier = Verifier(KEY, clock=TickingClock(), speed_mps=SPEED)

    def test_context_must_be_exactly_32_bytes(self):
        for bad in (b"", b"c" * 31, b"c" * 33, "c" * 32, None, 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.verifier.bits(self.prover, bad, OPENING)

    def test_opening_must_be_exactly_32_bytes(self):
        for bad in (b"", b"o" * 31, b"o" * 33, "o" * 32, None, 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.verifier.bits(self.prover, CONTEXT, bad)

    def test_rounds_must_be_non_bool_int_in_range(self):
        for bad in (True, False, 0, -1, 2**32 + 1, 1.0, 32.0, "32", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.verifier.bits(self.prover, CONTEXT, OPENING, rounds=bad)

    def test_rounds_boundaries_accepted(self):
        blob = self.verifier.bits(self.prover, CONTEXT, OPENING, rounds=1)
        self.assertEqual(len(json.loads(blob)[5]), 1)

    def test_timeout_must_be_finite_positive_non_bool(self):
        for bad in (True, 0, 0.0, -1.0, math.inf, -math.inf, math.nan, "1", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.verifier.bits(self.prover, CONTEXT, OPENING, timeout=bad)

    def test_int_timeout_accepted(self):
        blob = self.verifier.bits(self.prover, CONTEXT, OPENING, rounds=1, timeout=1)
        self.assertEqual(json.loads(blob)[7], 1.0)

    def test_wrong_prover_key_rejected(self):
        prover = Prover(OTHER_KEY)
        with self.assertRaises(ValueError):
            self.verifier.bits(prover, CONTEXT, OPENING, rounds=1)

    def test_slow_round_trip_rejected(self):
        clock = TickingClock(step=0.02)
        verifier = Verifier(KEY, clock=clock, speed_mps=SPEED)
        with self.assertRaises(ValueError):
            verifier.bits(self.prover, CONTEXT, OPENING, timeout=0.01)

    def test_negative_round_trip_rejected(self):
        clock = TickingClock(step=-0.01)
        verifier = Verifier(KEY, clock=clock, speed_mps=SPEED)
        with self.assertRaises(ValueError):
            verifier.bits(self.prover, CONTEXT, OPENING, timeout=0.01)

    def test_non_finite_clock_rejected(self):
        verifier = Verifier(KEY, clock=lambda: math.inf, speed_mps=SPEED)
        with self.assertRaises(ValueError):
            verifier.bits(self.prover, CONTEXT, OPENING, timeout=0.01)

    def test_non_finite_speed_rejected(self):
        verifier = Verifier(KEY, clock=TickingClock(), speed_mps=math.inf)
        with self.assertRaises(ValueError):
            verifier.bits(self.prover, CONTEXT, OPENING, timeout=0.01)


class BitsRecordEncodingTest(unittest.TestCase):
    def setUp(self):
        self.blob, _ = make_bits(rounds=4, timeout=0.01)
        self.record = json.loads(self.blob)

    def test_record_shape(self):
        record = self.record
        self.assertIsInstance(record, list)
        self.assertEqual(len(record), 10)
        self.assertEqual(record[0], 1)
        self.assertEqual(bytes.fromhex(record[2]), CONTEXT)
        self.assertEqual(bytes.fromhex(record[4]), OPENING)
        self.assertEqual(len(record[5]), 4)
        self.assertEqual(record[6], SPEED)
        self.assertEqual(record[7], 0.01)
        self.assertEqual(record[8], 0.001953125 * SPEED / 2.0)

    def test_token_is_random_16_bytes(self):
        token = bytes.fromhex(self.record[1])
        self.assertEqual(len(token), 16)
        other, _ = make_bits()
        self.assertNotEqual(token, bytes.fromhex(json.loads(other)[1]))

    def test_digest_is_npfc1_commitment(self):
        self.assertEqual(
            bytes.fromhex(self.record[3]),
            hashlib.sha256(b"NPFC1" + CONTEXT + OPENING).digest(),
        )

    def test_sample_entries_and_responses(self):
        token = bytes.fromhex(self.record[1])
        digest = bytes.fromhex(self.record[3])
        for index, entry in enumerate(self.record[5]):
            self.assertEqual(len(entry), 4)
            bit, response_hex, start, end = entry
            self.assertIn(bit, (0, 1))
            expected = hmac.new(
                KEY,
                b"NPFR1" + token + index.to_bytes(4, "big") + bytes([bit]) + digest,
                hashlib.sha256,
            ).digest()
            self.assertEqual(bytes.fromhex(response_hex), expected)
            self.assertEqual(end - start, 0.001953125)

    def test_mac_is_npfb1_over_encoding_without_mac(self):
        body = json.dumps(self.record[:9], separators=(",", ":")).encode("utf-8")
        expected = hmac.new(KEY, b"NPFB1" + body, hashlib.sha256).hexdigest()
        self.assertEqual(self.record[9], expected)

    def test_distance_bound_is_slowest_round_trip_halved(self):
        blob, _ = make_bits(step=0.00390625, rounds=3, timeout=0.01)
        self.assertEqual(json.loads(blob)[8], 0.00390625 * SPEED / 2.0)
        self.assertEqual(audit_b(blob, KEY), 0.00390625 * SPEED / 2.0)

    def test_encoding_is_compact_canonical_json(self):
        self.assertEqual(self.blob, json.dumps(self.record, separators=(",", ":")).encode("utf-8"))
        self.assertNotIn(b" ", self.blob)


class AuditBTest(unittest.TestCase):
    def setUp(self):
        self.blob, _ = make_bits(rounds=4, timeout=0.01)
        self.record = json.loads(self.blob)

    def test_round_trip_returns_distance_bound(self):
        bound = audit_b(self.blob, KEY)
        self.assertIsInstance(bound, float)
        self.assertEqual(bound, 0.001953125 * SPEED / 2.0)

    def test_x_must_be_non_empty_bytes(self):
        for bad in (b"", "", None, self.record, 42, bytearray(self.blob)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_b(bad, KEY)

    def test_k_must_be_non_empty_bytes(self):
        for bad in (b"", "", None, 42, bytearray(KEY)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_b(self.blob, bad)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_b(self.blob, OTHER_KEY)

    def test_tampered_mac_rejected(self):
        record = list(self.record)
        record[9] = ("00" if record[9][:2] != "00" else "11") + record[9][2:]
        blob = json.dumps(record, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(ValueError):
            audit_b(blob, KEY)

    def test_tampered_response_rejected(self):
        record = json.loads(self.blob)
        entry = record[5][0]
        entry[1] = ("00" if entry[1][:2] != "00" else "11") + entry[1][2:]
        with self.assertRaises(ValueError):
            audit_b(encode_record(record[:9]), KEY)

    def test_tampered_digest_rejected(self):
        record = json.loads(self.blob)
        record[3] = hashlib.sha256(b"NPFC1" + CONTEXT + b"x" * 32).hexdigest()
        # Re-key every sample response to the tampered digest so only the
        # commitment check can fail.
        token = bytes.fromhex(record[1])
        digest = bytes.fromhex(record[3])
        for index, entry in enumerate(record[5]):
            entry[1] = hmac.new(
                KEY,
                b"NPFR1" + token + index.to_bytes(4, "big") + bytes([entry[0]]) + digest,
                hashlib.sha256,
            ).hexdigest()
        with self.assertRaises(ValueError):
            audit_b(encode_record(record[:9]), KEY)

    def test_round_trip_outside_timeout_rejected(self):
        record = json.loads(self.blob)
        entry = record[5][0]
        entry[3] = entry[2] + 0.02  # R = 0.02 > T = 0.01
        record[8] = (entry[3] - entry[2]) * SPEED / 2.0
        with self.assertRaises(ValueError):
            audit_b(encode_record(record[:9]), KEY)

    def test_distance_mismatch_rejected(self):
        record = json.loads(self.blob)
        record[8] = record[8] + 1.0
        with self.assertRaises(ValueError):
            audit_b(encode_record(record[:9]), KEY)

    def test_non_canonical_encoding_rejected(self):
        pretty = json.dumps(self.record, indent=2).encode("utf-8")
        with self.assertRaises(ValueError):
            audit_b(pretty, KEY)
        record = json.loads(self.blob)
        record[8] = 1  # integer spelling of a float field
        blob = json.dumps(record, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(ValueError):
            audit_b(blob, KEY)

    def test_malformed_records_rejected(self):
        bad_records = [
            b"not json",
            b"{}",
            b"[]",
            json.dumps(self.record[:9]).encode("utf-8"),  # too few elements
            json.dumps(self.record + [0]).encode("utf-8"),  # too many
            json.dumps([2] + self.record[1:]).encode("utf-8"),  # version
            json.dumps([True] + self.record[1:]).encode("utf-8"),
        ]
        for blob in bad_records:
            with self.assertRaises(ValueError, msg=blob[:40]):
                audit_b(blob, KEY)

    def test_bad_sample_entries_rejected(self):
        record = json.loads(self.blob)
        variants = []
        bad_bit = json.loads(self.blob)
        bad_bit[5][0][0] = 2
        variants.append(bad_bit)
        bad_bool_bit = json.loads(self.blob)
        bad_bool_bit[5][0][0] = True
        variants.append(bad_bool_bit)
        bad_start = json.loads(self.blob)
        bad_start[5][0][2] = "100.0"
        variants.append(bad_start)
        empty_samples = json.loads(self.blob)
        empty_samples[5] = []
        variants.append(empty_samples)
        for variant in variants:
            blob = json.dumps(variant, separators=(",", ":")).encode("utf-8")
            with self.assertRaises(ValueError):
                audit_b(blob, KEY)

    def test_negative_distance_rejected(self):
        record = json.loads(self.blob)
        record[8] = -1.0
        blob = json.dumps(record, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(ValueError):
            audit_b(blob, KEY)


if __name__ == "__main__":
    unittest.main()
