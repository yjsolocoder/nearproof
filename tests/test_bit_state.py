import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BitEvidence,
    BitRound,
    BitState,
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
PREFIX_BS = b"NPBS1"
DELAY = 0.00002


class SteppedClock:
    def __init__(self, start=1000.0, step=DELAY):
        self.now = start
        self.step = step

    def __call__(self):
        return self.now


class RecordingProver:
    def __init__(self, key, clock, delay=DELAY):
        self._prover = Prover(key)
        self._clock = clock
        self.delay = delay

    def bit(self, t, d, i, b):
        self._clock.now += self.delay
        return self._prover.bit(t, d, i, b)


def digest_of(context=CONTEXT, opening=OPENING):
    return hashlib.sha256(PREFIX_FC + context + opening).digest()


def expected_r(key, t, d, i, b):
    return hmac.new(
        key, PREFIX_FR + t + i.to_bytes(4, "big") + bytes([b]) + d, hashlib.sha256
    ).digest()


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def make_verifier(clock=None, speed=SPEED):
    return Verifier(KEY, clock=clock or SteppedClock(), speed_mps=speed)


def drive(session, clock, n, delay=DELAY, key=KEY):
    """Successfully drive ``n`` rounds of a step-driven session."""
    prover = RecordingProver(key, clock, delay=delay)
    for _ in range(n):
        round_ = session.next()
        session.submit(
            round_, prover.bit(round_.t, digest_of(), round_.index, round_.bit)
        )


def state_body(state):
    return json.loads(state.body)


def resign(blob, mutate, key=KEY):
    """Decode a BitState blob, mutate the body array, re-MAC the state."""
    outer = json.loads(blob)
    body = json.loads(bytes.fromhex(outer[2]))
    mutate(body)
    body_blob = compact(body)
    seq = outer[1]
    mac = hmac.new(
        key, PREFIX_BS + compact([1, seq, body_blob.hex()]), hashlib.sha256
    ).digest().hex()
    return compact([1, seq, body_blob.hex(), mac])


def raw_state(body, seq=None, key=KEY):
    """Build a canonical BitState blob from a body array/list."""
    if seq is None:
        seq = len(body[7])
    body_blob = compact(body)
    mac = hmac.new(
        key, PREFIX_BS + compact([1, seq, body_blob.hex()]), hashlib.sha256
    ).digest().hex()
    return compact([1, seq, body_blob.hex(), mac])


def base_body(rounds=4, timeout=0.001, speed=SPEED):
    return [
        "ab" * 16,
        CONTEXT.hex(),
        digest_of().hex(),
        OPENING.hex(),
        rounds,
        timeout,
        speed,
        [],
        None,
    ]


class BitStateContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        body = compact(base_body())
        mac = b"\x01" * 32
        first = BitState(1, 0, body, mac)
        second = BitState(1, 0, body, mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        later_body = base_body()
        later_body[7].append([0, "00" * 32, 1.0, 1.0])
        self.assertNotEqual(first, BitState(1, 1, compact(later_body), mac))
        self.assertEqual(
            (first.version, first.seq, first.body, first.mac), (1, 0, body, mac)
        )

    def test_is_frozen(self):
        state = BitState(1, 0, compact(base_body()), b"\x00" * 32)
        with self.assertRaises(AttributeError):
            state.seq = 1

    def test_version_contract(self):
        body = compact(base_body())
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError):
                BitState(bad, 0, body, b"\x00" * 32)
        with self.assertRaises(ValueError):
            BitState(2, 0, body, b"\x00" * 32)

    def test_seq_contract(self):
        body = compact(base_body())
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError):
                BitState(1, bad, body, b"\x00" * 32)
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError):
                BitState(1, bad, body, b"\x00" * 32)

    def test_body_must_be_bytes(self):
        for bad in (compact(base_body()).decode(), bytearray(), None, 42, []):
            with self.assertRaises(TypeError):
                BitState(1, 0, bad, b"\x00" * 32)

    def test_mac_contract(self):
        body = compact(base_body())
        for bad in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError):
                BitState(1, 0, body, bad)
        with self.assertRaises(ValueError):
            BitState(1, 0, body, b"\x00" * 31)
        with self.assertRaises(ValueError):
            BitState(1, 0, body, b"\x00" * 33)

    def test_seq_must_match_query_count(self):
        body = base_body()
        body[7].append([0, "00" * 32, 1.0, 1.0])
        with self.assertRaises(ValueError):
            BitState(1, 0, compact(body), b"\x00" * 32)
        with self.assertRaises(ValueError):
            BitState(1, 2, compact(body), b"\x00" * 32)
        self.assertEqual(
            BitState(1, 1, compact(body), b"\x00" * 32).seq, 1
        )


class BitStateBodyContractTest(unittest.TestCase):
    def state_for(self, body, seq=None):
        return BitState(
            1, len(body[7]) if seq is None else seq, compact(body), b"\x00" * 32
        )

    @staticmethod
    def _body(**over):
        body = base_body()
        for key, value in over.items():
            body[{"R": 4, "T": 5, "V": 6}[key]] = value
        return body

    def test_wrong_array_shape_is_value_error(self):
        for raw in (
            b"{}",
            b"null",
            b"[]",
            b"[1]",
            compact(base_body()[:-1]),
            compact(base_body() + [None]),
            b"{not json",
        ):
            with self.assertRaises(ValueError):
                BitState(1, 0, raw, b"\x00" * 32)

    def test_hex_fields(self):
        base = base_body()
        for index, length in ((0, 16), (1, 32), (2, 32), (3, 32)):
            for bad in (42, None, True, []):
                broken = base_body()
                broken[index] = bad
                with self.assertRaises(TypeError):
                    self.state_for(broken)
            for bad in ("z" * (length * 2), "00" * (length - 1),
                        base[index].upper()):
                broken = base_body()
                broken[index] = bad
                with self.assertRaises(ValueError):
                    self.state_for(broken)

    def test_R_is_non_bool_integer_in_range(self):
        for bad in ("4", 4.0, True, False, None, []):
            with self.assertRaises(TypeError):
                self.state_for(self._body(R=bad))
        for bad in (0, -1, 2**32 + 1):
            with self.assertRaises(ValueError):
                self.state_for(self._body(R=bad))
        for good in (1, 2**32):
            state = self.state_for(self._body(R=good))
            self.assertEqual(BitState.from_bytes(state.to_bytes()), state)

    def test_T_and_V_finite_positive(self):
        for index in (5, 6):
            for bad in ("0.001", None, []):
                broken = base_body()
                broken[index] = bad
                with self.assertRaises(TypeError):
                    self.state_for(broken)
            for bad in (True, math.inf, -math.inf, math.nan):
                broken = base_body()
                broken[index] = bad
                with self.assertRaises(ValueError):
                    self.state_for(broken)
        for bad in (0, -1.0):
            broken = base_body()
            broken[5] = bad
            with self.assertRaises(ValueError):
                self.state_for(broken)
        for bad in (0.0, -1.0):
            broken = base_body()
            broken[6] = bad
            with self.assertRaises(ValueError):
                self.state_for(broken)

    def test_Q_items(self):
        body = base_body()
        body[7] = {}
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[7] = ["x"]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[7] = [[0, "00" * 32, 0.0]]
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[7] = [[True, "00" * 32, 0.0, 0.0]]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[7] = [[2, "00" * 32, 0.0, 0.0]]
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[7] = [[0, 42, 0.0, 0.0]]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[7] = [[0, "00" * 31, 0.0, 0.0]]
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[7] = [[0, "00" * 32, "x", 0.0]]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[7] = [[0, "00" * 32, math.inf, 0.0]]
        with self.assertRaises(ValueError):
            self.state_for(body)

    def test_seq_must_not_exceed_R(self):
        body = base_body(rounds=1)
        body[7] = [
            [0, "00" * 32, 0.0, 0.0],
            [1, "00" * 32, 0.0, 0.0],
        ]
        with self.assertRaises(ValueError):
            self.state_for(body, seq=2)

    def test_P_null_or_triple(self):
        body = base_body()
        body[8] = 42
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[8] = [0, 0]
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[8] = ["0", 0, 0.0]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[8] = [True, 0, 0.0]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[8] = [4, 0, 0.0]  # 4 >= R
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body(rounds=3)
        body[8] = [3, 0, 0.0]  # seq == R is not strictly below
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[8] = [0, 2, 0.0]
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[8] = [0, 0, "x"]
        with self.assertRaises(TypeError):
            self.state_for(body)
        body = base_body()
        body[8] = [0, 0, math.nan]
        with self.assertRaises(ValueError):
            self.state_for(body)
        body = base_body()
        body[8] = [0, 0, 0.0]
        self.state_for(body)

    def test_P_seq_must_be_next_query_index(self):
        # With one completed query the pending round must be index 1; an
        # outstanding index 2 leaves an unfillable gap.
        body = base_body(rounds=4)
        body[7].append([0, "00" * 32, 0.0, 0.0])
        body[8] = [2, 0, 0.0]
        with self.assertRaises(ValueError):
            self.state_for(body, seq=1)
        # The matching index 1 is fine.
        body[8] = [1, 0, 0.0]
        self.state_for(body, seq=1)


class BitStateEncodingTest(unittest.TestCase):
    def _state(self, rounds=3, seq=0, previous=False):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=rounds, timeout=0.001
        )
        drive(session, clock, seq)
        if previous:
            session.next()
        return BitState.from_bytes(session.checkpoint())

    def test_round_trip(self):
        state = self._state(seq=2)
        self.assertEqual(BitState.from_bytes(state.to_bytes()), state)
        self.assertEqual(
            BitState.from_bytes(state.to_bytes()).to_bytes(), state.to_bytes()
        )

    def test_outer_is_four_element_array_hex_body_and_mac(self):
        blob = self._state(seq=1).to_bytes()
        outer = json.loads(blob)
        self.assertEqual(len(outer), 4)
        version, seq, body_hex, mac_hex = outer
        self.assertEqual((version, seq), (1, 1))
        self.assertEqual(bytes.fromhex(body_hex).hex(), body_hex)
        self.assertEqual(len(bytes.fromhex(mac_hex)), 32)

    def test_body_is_nine_element_array(self):
        self.assertEqual(len(state_body(self._state(seq=1))), 9)

    def test_from_bytes_rejects_non_bytes(self):
        blob = self._state().to_bytes()
        for bad in (blob.decode(), bytearray(blob), None, 42, []):
            with self.assertRaises(TypeError):
                BitState.from_bytes(bad)

    def test_non_canonical_outer_rejected(self):
        state = self._state(seq=1)
        outer = json.loads(state.to_bytes())
        for mutated in (
            compact(outer[:-1]),
            compact(outer + [1]),
            b"{}",
            json.dumps(outer, indent=2).encode(),
            state.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError):
                BitState.from_bytes(mutated)

    def test_non_canonical_body_rejected(self):
        state = self._state(seq=1)
        outer = json.loads(state.to_bytes())
        pretty_body = json.dumps(state_body(state), indent=2).encode().hex()
        mutated = list(outer)
        mutated[2] = pretty_body
        with self.assertRaises(ValueError):
            BitState.from_bytes(compact(mutated))

    def test_integer_number_spellings_do_not_round_trip(self):
        state = self._state(seq=1)
        outer = json.loads(state.to_bytes())
        body = state_body(state)
        body[7][0][2] = 1  # an integer s literal re-encodes as a float
        mutated = list(outer)
        mutated[2] = compact(body).hex()
        with self.assertRaises(ValueError):
            BitState.from_bytes(compact(mutated))

    def test_canonical_body_stored_bytes_never_rewritten(self):
        state = self._state(seq=1)
        self.assertEqual(
            BitState(1, 1, state.body, state.mac).to_bytes(), state.to_bytes()
        )

    def test_mac_definition(self):
        blob = self._state(seq=2, previous=True).to_bytes()
        outer = json.loads(blob)
        self.assertEqual(
            outer[3],
            hmac.new(
                KEY, PREFIX_BS + compact([1, outer[1], outer[2]]),
                hashlib.sha256,
            ).digest().hex(),
        )

    def test_pending_encoded_in_P(self):
        state = self._state(rounds=4, seq=2, previous=True)
        body = state_body(state)
        self.assertIsNotNone(body[8])
        self.assertEqual(body[8][0], 2)
        self.assertIn(body[8][1], (0, 1))

    def test_no_pending_P_is_null(self):
        self.assertIsNone(state_body(self._state(seq=2))[8])


class CheckpointTest(unittest.TestCase):
    def _session(self, rounds=4):
        clock = SteppedClock()
        return clock, make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=rounds, timeout=0.001
        )

    def test_returns_canonical_state_bytes(self):
        _clock, session = self._session()
        blob = session.checkpoint()
        self.assertIsInstance(blob, bytes)
        state = BitState.from_bytes(blob)
        self.assertEqual(state.to_bytes(), blob)
        body = state_body(state)
        self.assertEqual(state.seq, 0)
        self.assertEqual(body[4], 4)
        self.assertEqual(body[7], [])
        self.assertIsNone(body[8])

    def test_checkpoint_carries_completed_queries(self):
        clock, session = self._session(rounds=4)
        drive(session, clock, 3)
        state = BitState.from_bytes(session.checkpoint())
        self.assertEqual(state.seq, 3)
        body = state_body(state)
        self.assertEqual(len(body[7]), 3)
        t, d = bytes.fromhex(body[0]), bytes.fromhex(body[2])
        for index, item in enumerate(body[7]):
            self.assertEqual(
                item[1], expected_r(KEY, t, d, index, item[0]).hex()
            )

    def test_checkpoint_carries_pending_round(self):
        clock, session = self._session(rounds=4)
        drive(session, clock, 1)
        pending = session.next()
        state = BitState.from_bytes(session.checkpoint())
        body = state_body(state)
        self.assertEqual(state.seq, 1)
        self.assertEqual(body[8], [1, pending.bit, 1000.0 + DELAY])

    def test_checkpoint_does_not_advance_session(self):
        clock, session = self._session(rounds=3)
        drive(session, clock, 1)
        pending = session.next()
        before = session.checkpoint()
        self.assertEqual(session.checkpoint(), before)
        # The same pending round can still be submitted.
        clock.now += DELAY
        session.submit(
            pending, expected_r(KEY, pending.t, digest_of(), 1, pending.bit)
        )

    def test_checkpoint_after_all_rounds(self):
        clock, session = self._session(rounds=2)
        drive(session, clock, 2)
        state = BitState.from_bytes(session.checkpoint())
        self.assertEqual(state.seq, 2)
        body = state_body(state)
        self.assertEqual(len(body[7]), 2)
        self.assertIsNone(body[8])

    def test_checkpoint_rejected_after_finish(self):
        clock, session = self._session(rounds=1)
        drive(session, clock, 1)
        session.finish()
        with self.assertRaises(ValueError):
            session.checkpoint()

    def test_checkpoint_rejected_after_revoke(self):
        _clock, session = self._session()
        session.revoke()
        with self.assertRaises(ValueError):
            session.checkpoint()


class ResumeBitsTest(unittest.TestCase):
    def _started(self, rounds=4, timeout=0.001, clock=None):
        clock = clock or SteppedClock()
        return clock, make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=rounds, timeout=timeout
        )

    def test_resume_no_pending_and_finish(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 3)
        restored = make_verifier(clock).resume_bits(session.checkpoint())
        evidence = restored.finish()
        self.assertEqual(len(BitEvidence.from_bytes(evidence).queries), 3)
        self.assertGreater(audit_b(evidence, KEY), 0.0)

    def test_resume_pending_then_finish(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 1)
        pending = session.next()
        restored = make_verifier(clock).resume_bits(session.checkpoint())
        # next() stays blocked: the carried round remains outstanding.
        with self.assertRaises(ValueError):
            restored.next()
        clock.now += DELAY
        restored.submit(
            pending, expected_r(KEY, pending.t, digest_of(), 1, pending.bit)
        )
        drive(restored, clock, 1)
        evidence = restored.finish()
        record = BitEvidence.from_bytes(evidence)
        self.assertEqual(audit_b(evidence, KEY), record.limit)

    def test_pending_round_reconstructable_from_bytes(self):
        # A crashed process has only the checkpoint bytes: t, index and b
        # all come from P and the body, with no in-memory object.
        clock, session = self._started(rounds=2)
        session.next()
        checkpoint = session.checkpoint()
        body = state_body(BitState.from_bytes(checkpoint))
        rebuilt = BitRound(1, bytes.fromhex(body[0]), body[8][0], body[8][1])
        clock.now += DELAY
        restored = make_verifier(clock).resume_bits(checkpoint)
        restored.submit(
            rebuilt, expected_r(KEY, rebuilt.t, digest_of(), 0, rebuilt.bit)
        )
        drive(restored, clock, 1)
        self.assertGreater(audit_b(restored.finish(), KEY), 0.0)

    def test_accepts_bit_state_object(self):
        clock, session = self._started(rounds=2)
        drive(session, clock, 1)
        state = BitState.from_bytes(session.checkpoint())
        restored = make_verifier(clock).resume_bits(state)
        drive(restored, clock, 1)
        restored.finish()

    def test_restored_uses_checkpoint_speed(self):
        clock = SteppedClock()
        session = Verifier(KEY, clock=clock, speed_mps=123.0).start_bits(
            CONTEXT, OPENING, rounds=1, timeout=0.001
        )
        drive(session, clock, 1)
        restored = Verifier(KEY, clock=clock, speed_mps=999.0).resume_bits(
            session.checkpoint()
        )
        self.assertEqual(BitEvidence.from_bytes(restored.finish()).speed, 123.0)

    def test_restored_uses_new_verifier_clock(self):
        first_clock = SteppedClock()
        session = make_verifier(first_clock).start_bits(
            CONTEXT, OPENING, rounds=2, timeout=0.001
        )
        drive(session, first_clock, 1)
        second_clock = SteppedClock(start=5000.0)
        restored = make_verifier(second_clock).resume_bits(session.checkpoint())
        pending = restored.next()
        self.assertEqual(second_clock.now, 5000.0)
        second_clock.now += DELAY
        restored.submit(
            pending, expected_r(KEY, pending.t, digest_of(), 1, pending.bit)
        )
        restored.finish()

    def test_checkpoint_resume_checkpoint_is_identical(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 2)
        blob = session.checkpoint()
        restored = make_verifier(clock).resume_bits(blob)
        self.assertEqual(restored.checkpoint(), blob)

    def test_wrong_key_rejected(self):
        clock, session = self._started(rounds=2)
        drive(session, clock, 1)
        with self.assertRaises(ValueError):
            Verifier(OTHER_KEY, clock=clock).resume_bits(session.checkpoint())

    def test_tampered_blob_rejected(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 2)
        blob = bytearray(session.checkpoint())
        blob[len(blob) // 2] ^= 0xFF
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(bytes(blob))

    def test_forged_digest_rejected(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 2)
        forged = resign(
            session.checkpoint(),
            lambda body: body.__setitem__(2, hashlib.sha256(b"x").digest().hex()),
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(forged)

    def test_forged_response_rejected(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 2)
        forged = resign(
            session.checkpoint(),
            lambda body: body[7][0].__setitem__(1, "00" * 32),
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(forged)

    def test_round_trip_outside_timeout_rejected(self):
        clock, session = self._started(rounds=2)
        drive(session, clock, 1)
        forged = resign(
            session.checkpoint(),
            lambda body: body[7][0].__setitem__(3, body[7][0][2] + 1.0),
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(forged)

    def test_negative_round_trip_rejected(self):
        clock, session = self._started(rounds=2)
        drive(session, clock, 1)
        forged = resign(
            session.checkpoint(),
            lambda body: body[7][0].__setitem__(3, body[7][0][2] - 0.1),
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(forged)

    def test_pending_index_must_be_next(self):
        clock, session = self._started(rounds=3)
        drive(session, clock, 1)
        forged = resign(
            session.checkpoint(),
            lambda body: body.__setitem__(8, [2, 0, body[7][0][2]]),
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(forged)

    def test_malformed_bytes_rejected(self):
        for bad in (b"not json", b"{}", b"[1]", b"null"):
            with self.assertRaises(ValueError):
                make_verifier().resume_bits(bad)

    def test_wrong_argument_types_raise_type_error(self):
        clock, session = self._started(rounds=2)
        drive(session, clock, 1)
        blob = session.checkpoint()
        for bad in (None, 42, "x", [], {}, bytearray(blob)):
            with self.assertRaises(TypeError):
                make_verifier().resume_bits(bad)
        for bad in (42, "x", [], {}, bytearray(blob)):
            with self.assertRaises(TypeError):
                make_verifier().resume_bits(blob, floor=bad)

    def test_wrong_field_type_inside_bytes_is_value_error(self):
        # The argument kind (bytes) is right; its malformed content is a
        # value error rather than a type error.
        body = base_body()
        body[4] = "4"
        blob = raw_state(body, seq=0)
        with self.assertRaises(ValueError):
            make_verifier().resume_bits(blob)
        clock, session = self._started(rounds=2)
        drive(session, clock, 1)
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(
                session.checkpoint(), floor=blob
            )


class ResumeFloorTest(unittest.TestCase):
    def _sessions(self, rounds=4, timeout=0.001):
        clock = SteppedClock()
        return clock, make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=rounds, timeout=timeout
        )

    def test_higher_seq_without_floor_pending_extends(self):
        clock, session = self._sessions()
        drive(session, clock, 1)
        floor = session.checkpoint()
        drive(session, clock, 2)
        newer = session.checkpoint()
        restored = make_verifier(clock).resume_bits(newer, floor=floor)
        drive(restored, clock, 1)
        restored.finish()

    def test_lower_seq_rejected(self):
        clock, session = self._sessions()
        drive(session, clock, 2)
        older = session.checkpoint()
        drive(session, clock, 1)
        newer = session.checkpoint()
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(older, floor=newer)

    def test_equal_seq_identical_body_is_replay(self):
        clock, session = self._sessions()
        drive(session, clock, 2)
        checkpoint = session.checkpoint()
        restored = make_verifier(clock).resume_bits(
            checkpoint, floor=checkpoint
        )
        self.assertEqual(restored.checkpoint(), checkpoint)

    def test_equal_seq_different_body_rejected(self):
        clock, session = self._sessions()
        drive(session, clock, 1)
        checkpoint = session.checkpoint()
        other = resign(
            checkpoint, lambda body: body.__setitem__(6, body[6] + 1.0)
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(other, floor=checkpoint)

    def test_higher_seq_fixed_parameters_must_match(self):
        clock, session = self._sessions(rounds=4, timeout=0.001)
        drive(session, clock, 2)
        floor = session.checkpoint()
        drive(session, clock, 1)
        newer = session.checkpoint()  # seq 3, so the gate sees a higher seq

        def tampered(mutate):
            return resign(newer, mutate)

        # R/T/V survive recovery (the carried rounds still satisfy them) and
        # are rejected by the higher-seq fixed-parameter comparison.
        for setter in (
            lambda body: body.__setitem__(4, 3),
            lambda body: body.__setitem__(5, 0.002),
            lambda body: body.__setitem__(6, 1.0),
        ):
            with self.assertRaises(ValueError):
                make_verifier(clock).resume_bits(tampered(setter), floor=floor)
        # t/C/D/O cannot drift without invalidating a recomputed value; the
        # state is rejected either way.
        for field in (0, 1, 2, 3):
            forged = resign(
                newer,
                lambda body, f=field: body.__setitem__(
                    f, "11" * (16 if f == 0 else 32)
                ),
            )
            with self.assertRaises(ValueError):
                make_verifier(clock).resume_bits(forged, floor=floor)

    def test_Q_must_extend_floor_prefix(self):
        clock, session = self._sessions(rounds=4)
        drive(session, clock, 2)
        floor = session.checkpoint()
        body = state_body(BitState.from_bytes(floor))
        t, d = bytes.fromhex(body[0]), bytes.fromhex(body[2])
        newer = json.loads(bytes.fromhex(json.loads(floor)[2]))
        # Flip the first floor-covered query's bit and re-sign its response
        # so recovery passes but the floor Q prefix no longer matches.
        flipped = newer[7][0][0] ^ 1
        newer[7][0][0] = flipped
        newer[7][0][1] = expected_r(KEY, t, d, 0, flipped).hex()
        # Append one more valid query to raise seq to 3.
        last_end = newer[7][-1][3]
        bit = 0
        newer[7].append(
            [bit, expected_r(KEY, t, d, 2, bit).hex(), last_end, last_end + DELAY]
        )
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(raw_state(newer, seq=3), floor=floor)

    def test_floor_pending_next_q_continues_b_and_s(self):
        clock, session = self._sessions(rounds=3)
        drive(session, clock, 1)
        pending = session.next()
        floor = session.checkpoint()
        clock.now += DELAY
        restored = make_verifier(clock).resume_bits(floor)
        restored.submit(
            pending, expected_r(KEY, pending.t, digest_of(), 1, pending.bit)
        )
        newer = restored.checkpoint()
        make_verifier(clock).resume_bits(newer, floor=floor)

    def test_floor_pending_b_mismatch_rejected(self):
        clock, session = self._sessions(rounds=3)
        drive(session, clock, 1)
        session.next()
        floor = session.checkpoint()
        flipped_floor = resign(
            floor, lambda body: body[8].__setitem__(1, body[8][1] ^ 1)
        )
        newer = self._complete_pending(clock, floor)
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(newer, floor=flipped_floor)

    def test_floor_pending_s_mismatch_rejected(self):
        clock, session = self._sessions(rounds=3)
        drive(session, clock, 1)
        session.next()
        floor = session.checkpoint()
        shifted_floor = resign(
            floor, lambda body: body[8].__setitem__(2, body[8][2] + 0.0005)
        )
        newer = self._complete_pending(clock, floor)
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(newer, floor=shifted_floor)

    @staticmethod
    def _complete_pending(clock, floor):
        """Resume floor and finish exactly its one carried pending round."""
        body = state_body(BitState.from_bytes(floor))
        index, bit, start = body[8]
        round_ = BitRound(1, bytes.fromhex(body[0]), index, bit)
        clock.now = start + DELAY
        restored = make_verifier(clock).resume_bits(floor)
        restored.submit(
            round_, expected_r(KEY, round_.t, digest_of(), index, bit)
        )
        return restored.checkpoint()

    def test_floor_accepts_bit_state_objects(self):
        clock, session = self._sessions()
        drive(session, clock, 1)
        floor = BitState.from_bytes(session.checkpoint())
        drive(session, clock, 1)
        newer = BitState.from_bytes(session.checkpoint())
        make_verifier(clock).resume_bits(newer, floor=floor)

    def test_floor_mac_verified_too(self):
        clock, session = self._sessions()
        drive(session, clock, 1)
        floor = session.checkpoint()
        drive(session, clock, 1)
        newer = session.checkpoint()
        bad_floor = resign(floor, lambda body: None, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            make_verifier(clock).resume_bits(newer, floor=bad_floor)


if __name__ == "__main__":
    unittest.main()
