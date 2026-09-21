import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BitEvidence,
    Prover,
    Verifier,
    audit_b,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2
CONTEXT = bytes(range(32))
OPENING = bytes(range(1, 33))
SPEED = 299_792_458.0
PREFIX_FC = b"NPFC1"
PREFIX_FR = b"NPFR1"
PREFIX_FB = b"NPFB1"


class SteppedClock:
    def __init__(self, start=1000.0, step=0.00002):
        self.now = start
        self.step = step

    def __call__(self):
        return self.now


class RecordingProver:
    """Real-key prover that records (t, d, i, b) and drives the clock."""

    def __init__(self, key, clock=None, delay=0.00002):
        self._prover = Prover(key)
        self._clock = clock
        self.delay = delay
        self.calls = []

    def bit(self, t, d, i, b):
        self.calls.append((t, d, i, b))
        if self._clock is not None:
            self._clock.now += self.delay
        return self._prover.bit(t, d, i, b)


def expected_r(key, t, d, i, b):
    return hmac.new(
        key, PREFIX_FR + t + i.to_bytes(4, "big") + bytes([b]) + d, hashlib.sha256
    ).digest()


def digest_of(context, opening):
    return hashlib.sha256(PREFIX_FC + context + opening).digest()


def make_verifier(clock=None, speed=SPEED):
    return Verifier(KEY, clock=clock or SteppedClock(), speed_mps=speed)


def session(blob):
    return json.loads(blob)


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def assert_distance_close(test_case, actual, expected):
    # The recorded durations are differences of float clock readings, so the
    # derived distance only matches the algebraic value to float precision.
    test_case.assertTrue(
        math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9),
        f"{actual!r} != {expected!r}",
    )


def resign(blob, mutate, key=KEY):
    """Decode a bit-evidence blob, apply ``mutate`` to its array, re-MAC M."""
    array = json.loads(blob)
    mutate(array)
    array[-1] = hmac.new(
        key, PREFIX_FB + compact(array[:-1]), hashlib.sha256
    ).digest().hex()
    return compact(array)


class ProverBitTest(unittest.TestCase):
    def test_response_definition(self):
        t, d = b"t" * 16, b"d" * 32
        for i in (0, 1, 31, 2**32 - 1):
            for b in (0, 1):
                self.assertEqual(
                    Prover(KEY).bit(t, d, i, b), expected_r(KEY, t, d, i, b)
                )

    def test_response_is_32_bytes(self):
        self.assertEqual(len(Prover(KEY).bit(b"t" * 16, b"d" * 32, 0, 0)), 32)

    def test_t_contract(self):
        for bad in (b"", b"x" * 15, b"x" * 17, bytearray(16), "t" * 16, None):
            with self.assertRaises(ValueError):
                Prover(KEY).bit(bad, b"d" * 32, 0, 0)

    def test_d_contract(self):
        for bad in (b"", b"x" * 31, b"x" * 33, bytearray(32), "d" * 32, None):
            with self.assertRaises(ValueError):
                Prover(KEY).bit(b"t" * 16, bad, 0, 0)

    def test_i_must_be_non_bool_u32(self):
        for bad in (True, False, -1, 2**32, 1.0, 0.0, "0", None, 1j):
            with self.assertRaises(ValueError):
                Prover(KEY).bit(b"t" * 16, b"d" * 32, bad, 0)

    def test_b_must_be_exactly_zero_or_one_and_not_bool(self):
        for bad in (True, False, 2, -1, "0", 1.0, None, b"\x00"):
            with self.assertRaises(ValueError):
                Prover(KEY).bit(b"t" * 16, b"d" * 32, 0, bad)


class VerifierBitsTest(unittest.TestCase):
    def test_returns_canonical_bytes_that_audit(self):
        clock = SteppedClock()
        blob = make_verifier(clock).bits(
            RecordingProver(KEY, clock), CONTEXT, OPENING, rounds=4
        )
        self.assertIsInstance(blob, bytes)
        record = BitEvidence.from_bytes(blob)
        self.assertEqual(record.to_bytes(), blob)
        self.assertEqual(audit_b(blob, KEY), record.limit)

    def test_default_rounds_is_32(self):
        clock = SteppedClock()
        prover = RecordingProver(KEY, clock)
        make_verifier(clock).bits(prover, CONTEXT, OPENING)
        self.assertEqual(len(prover.calls), 32)

    def test_default_timeout_is_one_millisecond(self):
        record = BitEvidence.from_bytes(
            make_verifier().bits(
                RecordingProver(KEY), CONTEXT, OPENING, rounds=1
            )
        )
        self.assertEqual(record.timeout, 0.001)

    def test_single_round(self):
        clock = SteppedClock()
        record = BitEvidence.from_bytes(
            make_verifier(clock).bits(
                RecordingProver(KEY, clock), CONTEXT, OPENING, rounds=1
            )
        )
        self.assertEqual(len(record.queries), 1)
        self.assertIn(record.queries[0][0], (0, 1))

    def test_rounds_contract(self):
        v = make_verifier()
        for bad in (0, 2**32 + 1, -1, True, False, 1.0, 32.0, "32", None):
            with self.assertRaises(ValueError):
                v.bits(RecordingProver(KEY), CONTEXT, OPENING, rounds=bad)

    def test_timeout_contract(self):
        v = make_verifier()
        for bad in (0, -0.001, math.inf, -math.inf, math.nan, True, "0.001", None):
            with self.assertRaises(ValueError):
                v.bits(RecordingProver(KEY), CONTEXT, OPENING, timeout=bad)

    def test_context_and_opening_contract(self):
        v = make_verifier()
        good, bad31, bad33 = b"x" * 32, b"x" * 31, b"x" * 33
        for bad_context in (b"", bad31, bad33, bytearray(32), "x" * 32, None):
            with self.assertRaises(ValueError):
                v.bits(RecordingProver(KEY), bad_context, good)
        for bad_opening in (b"", bad31, bad33, bytearray(32), "x" * 32, None):
            with self.assertRaises(ValueError):
                v.bits(RecordingProver(KEY), good, bad_opening)

    def test_prover_must_offer_callable_bit(self):
        class Bare:
            pass

        class NonCallable:
            bit = 42

        for bogus in (object(), Bare(), NonCallable(), None):
            with self.assertRaises(ValueError):
                make_verifier().bits(bogus, CONTEXT, OPENING, rounds=1)

    def test_prover_arguments_and_constant_transcript(self):
        clock = SteppedClock()
        prover = RecordingProver(KEY, clock)
        blob = make_verifier(clock).bits(prover, CONTEXT, OPENING, rounds=5)
        t = BitEvidence.from_bytes(blob).t
        self.assertEqual(len(t), 16)
        self.assertEqual({call[0] for call in prover.calls}, {t})
        for index, (call_t, d, i, b) in enumerate(prover.calls):
            self.assertEqual(call_t, t)
            self.assertEqual(d, digest_of(CONTEXT, OPENING))
            self.assertEqual(i, index)
            self.assertIn(b, (0, 1))

    def test_query_encoding_and_responses(self):
        clock = SteppedClock()
        prover = RecordingProver(KEY, clock)
        blob = make_verifier(clock).bits(prover, CONTEXT, OPENING, rounds=6)
        record = BitEvidence.from_bytes(blob)
        self.assertEqual(
            [q[0] for q in record.queries], [c[3] for c in prover.calls]
        )
        for i, (b, r, s, e) in enumerate(record.queries):
            self.assertEqual(r, expected_r(KEY, record.t, record.digest, i, b))
            self.assertAlmostEqual(e - s, clock.step, places=12)

    def test_limit_is_max_round_trip_times_speed_half(self):
        clock = SteppedClock(start=0.0, step=0.00005)
        record = BitEvidence.from_bytes(
            make_verifier(clock, speed=300_000_000.0).bits(
                RecordingProver(KEY, clock, delay=0.00005),
                CONTEXT,
                OPENING,
                rounds=3,
            )
        )
        self.assertEqual(record.speed, 300_000_000.0)
        assert_distance_close(self, record.limit, 0.00005 * 300_000_000.0 / 2.0)

    def test_zero_duration_gives_zero_limit(self):
        clock = SteppedClock()
        record = BitEvidence.from_bytes(
            make_verifier(clock).bits(
                RecordingProver(KEY, clock, delay=0.0), CONTEXT, OPENING, rounds=2
            )
        )
        self.assertEqual(record.limit, 0.0)

    def test_round_trip_longer_than_timeout_rejected(self):
        clock = SteppedClock()
        prover = RecordingProver(KEY, clock, delay=0.002)
        with self.assertRaises(ValueError):
            make_verifier(clock).bits(
                prover, CONTEXT, OPENING, rounds=2, timeout=0.001
            )

    def test_round_trip_exactly_at_timeout_accepted(self):
        clock = SteppedClock(start=0.0)
        prover = RecordingProver(KEY, clock, delay=0.0005)
        blob = make_verifier(clock).bits(
            prover, CONTEXT, OPENING, rounds=2, timeout=0.0005
        )
        record = BitEvidence.from_bytes(blob)
        assert_distance_close(self, record.limit, 0.0005 * record.speed / 2.0)

    def test_negative_duration_rejected(self):
        clock = SteppedClock(start=10.0)

        class Backwards:
            def bit(self, t, d, i, b):
                # The pre-call clock read already happened at 10.0; push the
                # clock back so the post-call reading is earlier.
                clock.now = 9.0
                return Prover(KEY).bit(t, d, i, b)

        with self.assertRaises(ValueError):
            make_verifier(clock).bits(Backwards(), CONTEXT, OPENING, rounds=1)

    def test_non_finite_clock_reading_rejected(self):
        class BadClock:
            def __call__(self):
                return math.nan

        with self.assertRaises(ValueError):
            make_verifier(BadClock()).bits(
                RecordingProver(KEY), CONTEXT, OPENING, rounds=1
            )

    def test_bad_prover_response_rejected(self):
        class ShortResponse:
            def bit(self, t, d, i, b):
                return b"\x00" * 31

        class WrongResponse:
            def bit(self, t, d, i, b):
                return b"\x00" * 32

        class NonBytesResponse:
            def bit(self, t, d, i, b):
                return bytearray(32)

        for bogus in (ShortResponse(), WrongResponse(), NonBytesResponse()):
            with self.assertRaises(ValueError):
                make_verifier().bits(bogus, CONTEXT, OPENING, rounds=1)

    def test_prover_with_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            make_verifier().bits(
                RecordingProver(OTHER_KEY), CONTEXT, OPENING, rounds=1
            )

    def test_prover_bit_with_bad_arity_rejected(self):
        class TwoArgs:
            def bit(self, t, d):
                return b"\x00" * 32

        with self.assertRaises(ValueError):
            make_verifier().bits(TwoArgs(), CONTEXT, OPENING, rounds=1)

    def test_recorded_fields(self):
        blob = make_verifier().bits(
            RecordingProver(KEY), CONTEXT, OPENING, rounds=2, timeout=0.002
        )
        array = session(blob)
        self.assertEqual(len(array), 10)
        version, t, c, d, o, q, v, timeout, l, m = array
        self.assertEqual(version, 1)
        self.assertEqual(t, bytes.fromhex(t).hex())
        self.assertEqual(len(bytes.fromhex(t)), 16)
        self.assertEqual(c, CONTEXT.hex())
        self.assertEqual(o, OPENING.hex())
        self.assertEqual(d, digest_of(CONTEXT, OPENING).hex())
        self.assertEqual(len(bytes.fromhex(m)), 32)
        self.assertEqual(len(q), 2)
        for query in q:
            self.assertEqual(len(query), 4)
            self.assertIn(query[0], (0, 1))
            self.assertEqual(len(bytes.fromhex(query[1])), 32)

    def test_mac_definition(self):
        blob = make_verifier().bits(
            RecordingProver(KEY), CONTEXT, OPENING, rounds=3
        )
        array = session(blob)
        self.assertEqual(
            array[-1],
            hmac.new(KEY, PREFIX_FB + compact(array[:-1]), hashlib.sha256)
            .digest()
            .hex(),
        )

    def test_random_transcripts_differ(self):
        transcripts = {
            session(
                make_verifier().bits(
                    RecordingProver(KEY), CONTEXT, OPENING, rounds=4
                )
            )[1]
            for _ in range(4)
        }
        self.assertEqual(len(transcripts), 4)


class BitEvidenceEncodingTest(unittest.TestCase):
    def _blob(self, rounds=2):
        return make_verifier().bits(
            RecordingProver(KEY), CONTEXT, OPENING, rounds=rounds
        )

    def test_is_frozen(self):
        record = BitEvidence.from_bytes(self._blob())
        with self.assertRaises(AttributeError):
            record.limit = 1.0

    def test_round_trip(self):
        blob = self._blob()
        self.assertEqual(BitEvidence.from_bytes(blob).to_bytes(), blob)

    def test_rejects_non_bytes(self):
        blob = self._blob()
        for bad in (blob.decode(), bytearray(blob), None, 42, []):
            with self.assertRaises(ValueError):
                BitEvidence.from_bytes(bad)

    def test_rejects_malformed_json(self):
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(b"{not json")

    def test_rejects_wrong_array_shape(self):
        array = session(self._blob())
        for mutated in (
            array[:-1],
            array + [1],
            [2] + array[1:],
        ):
            with self.assertRaises(ValueError):
                BitEvidence.from_bytes(compact(mutated))

    def test_rejects_non_array(self):
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(b"{}")

    def test_rejects_bad_hex_and_lengths(self):
        array = session(self._blob())
        broken = list(array)
        broken[1] = broken[1].upper()
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(compact(broken))
        broken = list(array)
        broken[1] = bytes.fromhex(broken[1])[:-1].hex()
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(compact(broken))
        broken = list(array)
        broken[5][0][1] = bytes.fromhex(broken[5][0][1])[:-1].hex()
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(compact(broken))

    def test_rejects_bool_and_out_of_range_bits(self):
        array = session(self._blob())
        for bad_bit in (True, False, 2, -1):
            broken = list(array)
            broken[5][0][0] = bad_bit
            with self.assertRaises(ValueError):
                BitEvidence.from_bytes(compact(broken))

    def test_rejects_bad_query_shape(self):
        array = session(self._blob())
        broken = list(array)
        broken[5][0] = [0, broken[5][0][1], 1.0]
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(compact(broken))

    def test_rejects_non_finite_numbers(self):
        array = session(self._blob())
        for bad_literal in (b"1e999", b"true"):
            broken = list(array)
            broken[6] = json.loads(bad_literal)
            with self.assertRaises(ValueError):
                BitEvidence.from_bytes(compact(broken))
        for slot in (2, 3):
            broken = list(array)
            broken[5][0][slot] = math.inf
            with self.assertRaises(ValueError):
                BitEvidence.from_bytes(compact(broken))

    def test_rejects_non_positive_timeout_and_negative_limit(self):
        array = session(self._blob())
        for index, bad in ((7, 0.0), (7, -1.0), (8, -0.1)):
            broken = list(array)
            broken[index] = bad
            with self.assertRaises(ValueError):
                BitEvidence.from_bytes(compact(broken))

    def test_rejects_empty_queries(self):
        array = session(self._blob())
        broken = list(array)
        broken[5] = []
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(compact(broken))

    def test_rejects_integer_clock_literal(self):
        # s/e are float numbers in the contract; an int literal re-encodes
        # to a different spelling, so the canonical round-trip rejects it.
        array = session(self._blob())
        broken = list(array)
        broken[5][0][2] = 1
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(compact(broken))

    def test_rejects_whitespace_and_pretty_printing(self):
        with self.assertRaises(ValueError):
            BitEvidence.from_bytes(
                json.dumps(session(self._blob()), indent=2).encode()
            )


class AuditBTest(unittest.TestCase):
    def _blob(
        self, rounds=4, timeout=0.001, speed=SPEED, clock=None, step=0.00002
    ):
        clock = clock or SteppedClock(start=0.0, step=step)
        return make_verifier(clock, speed).bits(
            RecordingProver(KEY, clock, delay=step),
            CONTEXT,
            OPENING,
            rounds=rounds,
            timeout=timeout,
        )

    def test_returns_recomputed_limit(self):
        blob = self._blob(step=0.00003)
        assert_distance_close(self, audit_b(blob, KEY), 0.00003 * SPEED / 2.0)

    def test_x_and_k_must_be_non_empty_bytes(self):
        blob = self._blob()
        record = BitEvidence.from_bytes(blob)
        for bad_x in (record, bytearray(blob), blob.decode(), b"", None, 42):
            with self.assertRaises(ValueError):
                audit_b(bad_x, KEY)
        for bad_k in (b"", bytearray(KEY), "k", None, 42):
            with self.assertRaises(ValueError):
                audit_b(blob, bad_k)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_b(self._blob(), OTHER_KEY)

    def test_tampered_blob_rejected(self):
        blob = self._blob()
        for flip in (1, 20, len(blob) // 2, len(blob) - 5):
            broken = bytearray(blob)
            broken[flip] ^= 0xFF
            with self.assertRaises(ValueError):
                audit_b(bytes(broken), KEY)

    def test_digest_recomputed_even_with_valid_mac(self):
        # MAC is re-signed with the right key and every r is recomputed over
        # the forged D, so the only check that can fail is D == H(NPFC1+C+O).
        def mutate(array):
            forged = hashlib.sha256(b"forged").digest()
            t = bytes.fromhex(array[1])
            array[3] = forged.hex()
            for index, query in enumerate(array[5]):
                query[1] = expected_r(KEY, t, forged, index, query[0]).hex()

        with self.assertRaises(ValueError):
            audit_b(resign(self._blob(), mutate), KEY)

    def test_response_recomputed_by_index(self):
        # Swap two whole queries and re-sign: the responses are now checked
        # at new indices and must no longer match.
        def mutate(array):
            array[5][0], array[5][1] = array[5][1], array[5][0]

        with self.assertRaises(ValueError):
            audit_b(resign(self._blob(), mutate), KEY)

    def test_forged_response_even_with_valid_mac(self):
        def mutate(array):
            array[5][0][1] = (b"\x00" * 32).hex()

        with self.assertRaises(ValueError):
            audit_b(resign(self._blob(), mutate), KEY)

    def test_round_trip_over_timeout_rejected_even_with_valid_mac(self):
        def mutate(array):
            array[5][0][3] = array[5][0][2] + array[7] + 1.0

        with self.assertRaises(ValueError):
            audit_b(resign(self._blob(), mutate), KEY)

    def test_negative_round_trip_rejected_even_with_valid_mac(self):
        def mutate(array):
            array[5][0][3] = array[5][0][2] - 0.0001

        with self.assertRaises(ValueError):
            audit_b(resign(self._blob(), mutate), KEY)

    def test_limit_recomputed_even_with_valid_mac(self):
        def mutate(array):
            array[8] = array[8] + 1.0

        with self.assertRaises(ValueError):
            audit_b(resign(self._blob(), mutate), KEY)

    def test_boundary_round_trip_equal_timeout_accepted(self):
        # One round from t=0: end - start is exactly the timeout value.
        blob = self._blob(rounds=1, timeout=0.0001, step=0.0001)
        assert_distance_close(self, audit_b(blob, KEY), 0.0001 * SPEED / 2.0)

    def test_zero_round_trip_accepted(self):
        clock = SteppedClock()

        class Instant:
            def __init__(self):
                self.prover = Prover(KEY)

            def bit(self, t, d, i, b):
                return self.prover.bit(t, d, i, b)

        blob = make_verifier(clock).bits(
            Instant(), CONTEXT, OPENING, rounds=3
        )
        self.assertEqual(audit_b(blob, KEY), 0.0)

    def test_uses_maximum_round_trip_for_limit(self):
        # Monotone schedule of post-call readings: durations are
        # 0.00001, 0.00005, 0.00001, so L must track the 0.00005 round.
        clock = SteppedClock(start=0.0)
        end_times = iter((0.00001, 0.00006, 0.00007))
        real = Prover(KEY)

        class VariableDelay:
            def bit(self, t, d, i, b):
                clock.now = next(end_times)
                return real.bit(t, d, i, b)

        blob = make_verifier(clock).bits(
            VariableDelay(), CONTEXT, OPENING, rounds=3, timeout=0.001
        )
        assert_distance_close(self, audit_b(blob, KEY), 0.00005 * SPEED / 2.0)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_b(b"not json", KEY)


if __name__ == "__main__":
    unittest.main()
