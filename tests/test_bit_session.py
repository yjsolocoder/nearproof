import hashlib
import hmac
import json
import math
import threading
import unittest

from nearproof import (
    BitEvidence,
    BitRound,
    BitSession,
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
T_GOOD = b"t" * 16
D_GOOD = b"d" * 32


class SteppedClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def expected_r(key, t, d, i, b):
    return hmac.new(
        key, PREFIX_FR + t + i.to_bytes(4, "big") + bytes([b]) + d, hashlib.sha256
    ).digest()


def digest_of(context, opening):
    return hashlib.sha256(PREFIX_FC + context + opening).digest()


def make_verifier(clock=None, speed=SPEED, key=KEY):
    return Verifier(key, clock=clock or SteppedClock(), speed_mps=speed)


class BitRoundContractTest(unittest.TestCase):
    def test_positional_fields_and_equality(self):
        a = BitRound(1, T_GOOD, 0, 0)
        b = BitRound(1, T_GOOD, 0, 0)
        self.assertEqual((a.version, a.t, a.index, a.bit), (1, T_GOOD, 0, 0))
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, BitRound(1, T_GOOD, 0, 1))
        self.assertNotEqual(a, BitRound(1, T_GOOD, 1, 0))
        self.assertNotEqual(a, BitRound(1, b"u" * 16, 0, 0))

    def test_is_frozen(self):
        round_ = BitRound(1, T_GOOD, 0, 0)
        with self.assertRaises(AttributeError):
            round_.bit = 1

    def test_version_contract(self):
        for bad in (2, 0, -1):
            with self.assertRaises(ValueError):
                BitRound(bad, T_GOOD, 0, 0)
        for bad in (1.0, "1", True, None):
            with self.assertRaises(TypeError):
                BitRound(bad, T_GOOD, 0, 0)

    def test_t_contract(self):
        for bad in (b"", b"x" * 15, b"x" * 17):
            with self.assertRaises(ValueError):
                BitRound(1, bad, 0, 0)
        for bad in (bytearray(16), "t" * 16, None, 42):
            with self.assertRaises(TypeError):
                BitRound(1, bad, 0, 0)

    def test_index_contract(self):
        for good in (0, 1, 31, 2**32 - 1):
            self.assertEqual(BitRound(1, T_GOOD, good, 0).index, good)
        for bad in (-1, 2**32):
            with self.assertRaises(ValueError):
                BitRound(1, T_GOOD, bad, 0)
        for bad in (True, False, 1.0, 0.0, "0", None):
            with self.assertRaises(TypeError):
                BitRound(1, T_GOOD, bad, 0)

    def test_bit_contract(self):
        for good in (0, 1):
            self.assertEqual(BitRound(1, T_GOOD, 0, good).bit, good)
        for bad in (2, -1):
            with self.assertRaises(ValueError):
                BitRound(1, T_GOOD, 0, bad)
        for bad in (True, False, 1.0, 0.0, "0", None, b"\x00"):
            with self.assertRaises(TypeError):
                BitRound(1, T_GOOD, 0, bad)


class StartBitsTest(unittest.TestCase):
    def test_returns_a_session_with_random_transcript(self):
        v = make_verifier()
        s1 = v.start_bits(CONTEXT, OPENING, rounds=4)
        s2 = v.start_bits(CONTEXT, OPENING, rounds=4)
        self.assertIsInstance(s1, BitSession)
        self.assertIsInstance(s2, BitSession)
        self.assertNotEqual(s1._t, s2._t)
        self.assertEqual(len(s1._t), 16)
        self.assertEqual(s1.round_count, 0)

    def test_digest_is_computed_once(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=2)
        self.assertEqual(s._digest, digest_of(CONTEXT, OPENING))

    def test_defaults_match_bits(self):
        s = make_verifier().start_bits(CONTEXT, OPENING)
        self.assertEqual(s._rounds, 32)
        self.assertEqual(s._timeout, 0.001)

    def test_rounds_contract(self):
        v = make_verifier()
        for bad in (0, 2**32 + 1, -1, True, False, 1.0, 32.0, "32", None):
            with self.assertRaises(ValueError):
                v.start_bits(CONTEXT, OPENING, rounds=bad)

    def test_timeout_contract(self):
        v = make_verifier()
        for bad in (0, -0.001, math.inf, -math.inf, math.nan, True, "0.001", None):
            with self.assertRaises(ValueError):
                v.start_bits(CONTEXT, OPENING, timeout=bad)

    def test_context_and_opening_contract(self):
        v = make_verifier()
        good, bad31, bad33 = b"x" * 32, b"x" * 31, b"x" * 33
        for bad_context in (b"", bad31, bad33, bytearray(32), "x" * 32, None):
            with self.assertRaises(ValueError):
                v.start_bits(bad_context, good)
        for bad_opening in (b"", bad31, bad33, bytearray(32), "x" * 32, None):
            with self.assertRaises(ValueError):
                v.start_bits(good, bad_opening)

    def test_non_finite_speed_rejected(self):
        v = Verifier(KEY, speed_mps=math.inf, clock=SteppedClock())
        with self.assertRaises(ValueError):
            v.start_bits(CONTEXT, OPENING, rounds=1)

    def test_verifier_bits_still_works(self):
        # The existing one-shot interface is unchanged.
        clock = SteppedClock()
        blob = make_verifier(clock).bits(
            RecordingProver(KEY, clock), CONTEXT, OPENING, rounds=4
        )
        self.assertEqual(audit_b(blob, KEY), BitEvidence.from_bytes(blob).limit)


class RecordingProver:
    def __init__(self, key, clock=None, delay=0.0):
        self._prover = Prover(key)
        self._clock = clock
        self.delay = delay

    def bit(self, t, d, i, b):
        if self._clock is not None:
            self._clock.now += self.delay
        return self._prover.bit(t, d, i, b)


class SessionDrivingTest(unittest.TestCase):
    def test_happy_path_produces_auditable_bytes(self):
        clock = SteppedClock()
        v = make_verifier(clock)
        s = v.start_bits(CONTEXT, OPENING, rounds=5, timeout=1.0)
        prover = Prover(KEY)
        bits = []
        for _ in range(5):
            r = s.next()
            self.assertEqual(r.t, s._t)
            self.assertEqual(r.index, len(bits))
            self.assertIn(r.bit, (0, 1))
            bits.append(r.bit)
            s.submit(r, prover.bit(r.t, s._digest, r.index, r.bit))
            self.assertEqual(s.round_count, len(bits))
        blob = s.finish()
        self.assertIsInstance(blob, bytes)
        record = BitEvidence.from_bytes(blob)
        self.assertEqual(record.to_bytes(), blob)
        self.assertEqual(record.t, s._t)
        self.assertEqual([q[0] for q in record.queries], bits)
        self.assertEqual(audit_b(blob, KEY), record.limit)

    def test_single_round_session(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        s.submit(r, Prover(KEY).bit(r.t, s._digest, r.index, r.bit))
        record = BitEvidence.from_bytes(s.finish())
        self.assertEqual(len(record.queries), 1)
        self.assertEqual(record.timeout, 1.0)

    def test_recorded_s_is_next_reading_and_e_submit_reading(self):
        clock = SteppedClock(start=0.0)
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=2, timeout=1.0)
        prover = Prover(KEY)
        r0 = s.next()
        self.assertEqual(clock.now, 0.0)
        clock.now = 0.0002
        s.submit(r0, prover.bit(r0.t, s._digest, 0, r0.bit))
        r1 = s.next()
        clock.now = 0.0007
        s.submit(r1, prover.bit(r1.t, s._digest, 1, r1.bit))
        record = BitEvidence.from_bytes(s.finish())
        self.assertEqual((record.queries[0][2], record.queries[0][3]), (0.0, 0.0002))
        self.assertEqual((record.queries[1][2], record.queries[1][3]), (0.0002, 0.0007))
        # L tracks the larger round trip (0.0005 vs 0.0002).
        self.assertTrue(
            math.isclose(record.limit, 0.0005 * SPEED / 2.0, rel_tol=1e-12)
        )

    def test_only_one_round_outstanding(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=3, timeout=1.0)
        s.next()
        with self.assertRaises(ValueError):
            s.next()

    def test_submit_without_next(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=3, timeout=1.0)
        r = BitRound(1, s._t, 0, 0)
        with self.assertRaises(ValueError):
            s.submit(r, expected_r(KEY, s._t, s._digest, 0, 0))

    def test_finish_requires_every_round(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=3, timeout=1.0)
        with self.assertRaises(ValueError):
            s.finish()
        r = s.next()
        s.submit(r, Prover(KEY).bit(r.t, s._digest, 0, r.bit))
        with self.assertRaises(ValueError):
            s.finish()

    def test_finish_rejected_while_round_outstanding(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        s.next()
        with self.assertRaises(ValueError):
            s.finish()

    def test_finish_is_terminal(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        s.submit(r, Prover(KEY).bit(r.t, s._digest, 0, r.bit))
        s.finish()
        with self.assertRaises(ValueError):
            s.finish()
        with self.assertRaises(ValueError):
            s.next()
        with self.assertRaises(ValueError):
            s.revoke()

    def test_next_after_all_rounds_issued(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        s.submit(r, Prover(KEY).bit(r.t, s._digest, 0, r.bit))
        with self.assertRaises(ValueError):
            s.next()

    def test_revoke_blocks_everything_and_is_idempotent_only_once(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=2, timeout=1.0)
        r = s.next()
        s.revoke()
        for action in (
            lambda: s.next(),
            lambda: s.submit(r, expected_r(KEY, s._t, s._digest, 0, r.bit)),
            lambda: s.finish(),
            lambda: s.revoke(),
        ):
            with self.assertRaises(ValueError):
                action()

    def test_revoke_without_any_round(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=2, timeout=1.0)
        s.revoke()
        with self.assertRaises(ValueError):
            s.next()

    def test_round_bound_to_session(self):
        s1 = make_verifier().start_bits(CONTEXT, OPENING, rounds=2, timeout=1.0)
        s2 = make_verifier().start_bits(CONTEXT, OPENING, rounds=2, timeout=1.0)
        foreign = s2.next()
        own = s1.next()
        # A round object issued by another session (different t) is rejected,
        # even carrying a response valid for that foreign round.
        with self.assertRaises(ValueError):
            s1.submit(foreign, Prover(KEY).bit(
                foreign.t, s2._digest, foreign.index, foreign.bit))
        # The outstanding round of s1 is untouched and still completable.
        s1.submit(own, Prover(KEY).bit(own.t, s1._digest, own.index, own.bit))
        self.assertEqual(s1.round_count, 1)

    def test_reordered_and_duplicate_round_rejected(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=3, timeout=1.0)
        prover = Prover(KEY)
        r0 = s.next()
        s.submit(r0, prover.bit(r0.t, s._digest, 0, r0.bit))
        r1 = s.next()
        # Resubmitting the already-completed r0 instead of the pending r1.
        with self.assertRaises(ValueError):
            s.submit(r0, prover.bit(r0.t, s._digest, 0, r0.bit))
        # An equal-but-distinct round object never passes identity binding.
        twin = BitRound(1, r1.t, r1.index, r1.bit)
        with self.assertRaises(ValueError):
            s.submit(twin, prover.bit(twin.t, s._digest, twin.index, twin.bit))
        # r1 remains outstanding and now completes.
        s.submit(r1, prover.bit(r1.t, s._digest, 1, r1.bit))
        self.assertEqual(s.round_count, 2)

    def test_round_with_foreign_t_rejected(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        own = s.next()
        forged = BitRound(1, b"z" * 16, own.index, own.bit)
        with self.assertRaises(ValueError):
            s.submit(forged, expected_r(KEY, forged.t, s._digest, 0, own.bit))
        s.submit(own, expected_r(KEY, own.t, s._digest, 0, own.bit))

    def test_wrong_response_does_not_advance_and_is_retryable(self):
        clock = SteppedClock(start=10.0)
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=2, timeout=1.0)
        r = s.next()
        start_reading = clock.now
        with self.assertRaises(ValueError):
            s.submit(r, expected_r(OTHER_KEY, r.t, s._digest, 0, r.bit))
        self.assertEqual(s.round_count, 0)
        # Still the same outstanding round; a correct answer in time succeeds
        # and keeps the original s from next().
        clock.now = 10.0001
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        # Complete the session properly through the public API.
        r1 = s.next()
        s.submit(r1, expected_r(KEY, r1.t, s._digest, 1, r1.bit))
        record = BitEvidence.from_bytes(s.finish())
        self.assertEqual(record.queries[0][2], start_reading)
        self.assertEqual(record.queries[0][3], 10.0001)

    def test_wrong_length_and_non_bytes_response(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        with self.assertRaises(ValueError):
            s.submit(r, b"\x00" * 31)
        with self.assertRaises(ValueError):
            s.submit(r, b"\x00" * 32)
        for bad in (bytearray(32), None, "r" * 32, 42):
            with self.assertRaises(TypeError):
                s.submit(r, bad)
        # Still pending and completable.
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))

    def test_non_bitround_argument_is_type_error(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        s.next()
        for bad in (None, 42, "round", (1, s._t, 0, 0), object()):
            with self.assertRaises(TypeError):
                s.submit(bad, b"\x00" * 32)

    def test_timeout_failure_then_retry_while_within_timeout(self):
        clock = SteppedClock(start=0.0)
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=1, timeout=0.001)
        r = s.next()
        clock.now = 0.002
        with self.assertRaises(ValueError):
            s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        self.assertEqual(s.round_count, 0)
        # A correct answer that arrives within the timeout against the same s.
        clock.now = 0.0005
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        self.assertEqual(s.round_count, 1)

    def test_round_trip_exactly_at_timeout_accepted(self):
        clock = SteppedClock(start=0.0)
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=1, timeout=0.0005)
        r = s.next()
        clock.now = 0.0005
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        record = BitEvidence.from_bytes(s.finish())
        self.assertTrue(
            math.isclose(record.limit, 0.0005 * SPEED / 2.0, rel_tol=1e-12)
        )

    def test_negative_round_trip_rejected_but_recoverable(self):
        clock = SteppedClock(start=10.0)
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        clock.now = 9.0
        with self.assertRaises(ValueError):
            s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        clock.now = 10.0
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        self.assertEqual(s.round_count, 1)

    def test_non_finite_clock_at_next_leaves_no_outstanding_round(self):
        clock = SteppedClock()
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        clock.now = math.nan
        with self.assertRaises(ValueError):
            s.next()
        # No round was registered, so a recovered clock issues round 0.
        clock.now = 1.0
        r = s.next()
        self.assertEqual(r.index, 0)

    def test_non_finite_clock_at_submit_leaves_round_pending(self):
        clock = SteppedClock()
        s = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        clock.now = math.nan
        with self.assertRaises(ValueError):
            s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        clock.now = 1000.0001
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        self.assertEqual(s.round_count, 1)

    def test_terminal_session_shape_vs_value_errors(self):
        s = make_verifier().start_bits(CONTEXT, OPENING, rounds=1, timeout=1.0)
        r = s.next()
        s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        s.finish()
        # A well-shaped round/response still hits the terminal-state ValueError.
        with self.assertRaises(ValueError):
            s.submit(r, expected_r(KEY, r.t, s._digest, 0, r.bit))
        # A malformed shape is a TypeError even on a terminal session.
        with self.assertRaises(TypeError):
            s.submit(object(), b"\x00" * 32)

    def test_evidence_matches_bits_protocol_bytes(self):
        # The step-driven record must carry exactly the BitEvidence layout,
        # including the NPFB1 MAC over the array without M.
        clock = SteppedClock(start=0.0)
        s = make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=3, timeout=0.002
        )
        prover = Prover(KEY)
        # Absolute end readings: per-round durations 0.0001, 0.0004, 0.0002.
        end_times = iter((0.0001, 0.0005, 0.0007))
        rounds = []
        while True:
            try:
                r = s.next()
            except ValueError:
                break
            clock.now = next(end_times)
            s.submit(r, prover.bit(r.t, s._digest, r.index, r.bit))
            rounds.append(r)
        blob = s.finish()
        array = json.loads(blob)
        self.assertEqual(len(array), 10)
        version, t, c, d, o, q, v, timeout, limit, m = array
        self.assertEqual(version, 1)
        self.assertEqual(t, s._t.hex())
        self.assertEqual(c, CONTEXT.hex())
        self.assertEqual(o, OPENING.hex())
        self.assertEqual(d, digest_of(CONTEXT, OPENING).hex())
        self.assertEqual(len(q), 3)
        self.assertEqual(timeout, 0.002)
        self.assertEqual(v, SPEED)
        compact = json.dumps(array[:-1], separators=(",", ":")).encode()
        self.assertEqual(
            m, hmac.new(KEY, PREFIX_FB + compact, hashlib.sha256).digest().hex()
        )
        self.assertTrue(math.isclose(limit, 0.0004 * SPEED / 2.0, rel_tol=1e-12))
        self.assertEqual(audit_b(blob, KEY), BitEvidence.from_bytes(blob).limit)


class ConcurrentSubmitTest(unittest.TestCase):
    def test_concurrent_submissions_succeed_at_most_once(self):
        for _ in range(20):
            s = Verifier(KEY).start_bits(CONTEXT, OPENING, rounds=4, timeout=5.0)
            r = s.next()
            response = expected_r(KEY, r.t, s._digest, r.index, r.bit)
            threads_n = 8
            barrier = threading.Barrier(threads_n)
            outcomes = []
            outcome_lock = threading.Lock()

            def worker():
                barrier.wait()
                try:
                    s.submit(r, response)
                    result = "ok"
                except ValueError:
                    result = "value"
                except TypeError:
                    result = "type"
                with outcome_lock:
                    outcomes.append(result)

            threads = [threading.Thread(target=worker) for _ in range(threads_n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(outcomes.count("ok"), 1, outcomes)
            self.assertEqual(outcomes.count("value"), threads_n - 1, outcomes)
            self.assertEqual(s.round_count, 1)
            # Exactly one next round is now available.
            r2 = s.next()
            with self.assertRaises(ValueError):
                s.next()
            s.submit(r2, expected_r(KEY, r2.t, s._digest, 1, r2.bit))


if __name__ == "__main__":
    unittest.main()
