import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BitEvidence,
    BitState,
    Prover,
    Verifier,
    audit_b,
    bit_transcript_digest,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2
CONTEXT = bytes(range(32))
OPENING = bytes(range(1, 33))
DIGEST = bit_transcript_digest(CONTEXT, OPENING)
PREFIX_BS = b"NPBS1"
PREFIX_FR = b"NPFR1"
SPEED = 299_792_458.0


class SteppedClock:
    def __init__(self, start=1000.0, step=0.00002):
        self.now = start
        self.step = step

    def __call__(self):
        return self.now

    def advance(self):
        self.now += self.step


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def expected_r(key, t, d, i, b):
    return hmac.new(
        key, PREFIX_FR + t + i.to_bytes(4, "big") + bytes([b]) + d,
        hashlib.sha256,
    ).digest()


def make_verifier(clock=None, speed=SPEED):
    return Verifier(KEY, clock=clock or SteppedClock(), speed_mps=speed)


def run_rounds(session, clock, prover, count):
    for _ in range(count):
        rnd = session.next()
        response = prover.bit(rnd.t, DIGEST, rnd.index, rnd.bit)
        clock.advance()
        session.submit(rnd, response)


def make_state(seq, *, rounds=4, timeout=0.001, speed=SPEED, queries=None,
               pending=None, t=None, key=KEY):
    """Craft a signed BitState with chosen body content."""
    t = t or b"t" * 16
    queries = queries if queries is not None else []
    body = compact([
        t.hex(),
        CONTEXT.hex(),
        DIGEST.hex(),
        OPENING.hex(),
        rounds,
        timeout,
        speed,
        queries,
        pending,
    ])
    mac = hmac.new(
        key, PREFIX_BS + compact([1, seq, body.hex()]), hashlib.sha256
    ).digest()
    return BitState(version=1, seq=seq, body=body, mac=mac)


def resign(blob, mutate, key=KEY):
    """Decode a checkpoint, mutate its body array, re-MAC the outer layer."""
    outer = json.loads(blob)
    inner = json.loads(bytes.fromhex(outer[2]))
    mutate(inner)
    body = compact(inner)
    outer[1] = len(inner[7])
    outer[2] = body.hex()
    outer[3] = hmac.new(
        key, PREFIX_BS + compact(outer[:3]), hashlib.sha256
    ).digest().hex()
    return compact(outer)


class CheckpointTest(unittest.TestCase):
    def test_checkpoint_shape_and_fields(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4, timeout=0.002)
        run_rounds(session, clock, Prover(KEY), 2)
        blob = session.checkpoint()
        self.assertIsInstance(blob, bytes)

        outer = json.loads(blob)
        self.assertEqual(len(outer), 4)
        version, seq, body_hex, mac_hex = outer
        self.assertEqual(version, 1)
        self.assertEqual(seq, 2)
        self.assertEqual(len(bytes.fromhex(mac_hex)), 32)

        body = json.loads(bytes.fromhex(body_hex))
        self.assertEqual(len(body), 9)
        t, c, d, o, rounds, timeout, speed, queries, pending = body
        self.assertEqual(len(bytes.fromhex(t)), 16)
        self.assertEqual(c, CONTEXT.hex())
        self.assertEqual(o, OPENING.hex())
        self.assertEqual(d, DIGEST.hex())
        self.assertEqual(rounds, 4)
        self.assertEqual(timeout, 0.002)
        self.assertEqual(speed, SPEED)
        self.assertEqual(len(queries), 2)
        self.assertIsNone(pending)
        for i, query in enumerate(queries):
            self.assertEqual(len(query), 4)
            self.assertIn(query[0], (0, 1))
            self.assertEqual(len(bytes.fromhex(query[1])), 32)

    def test_mac_definition(self):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=3)
        run_rounds(session, clock, Prover(KEY), 2)
        blob = session.checkpoint()
        outer = json.loads(blob)
        self.assertEqual(
            outer[3],
            hmac.new(
                KEY, PREFIX_BS + compact(outer[:3]), hashlib.sha256
            ).digest().hex(),
        )

    def test_checkpoint_at_seq_zero(self):
        session = make_verifier().start_bits(CONTEXT, OPENING, rounds=2)
        blob = session.checkpoint()
        state = BitState.from_bytes(blob)
        self.assertEqual(state.seq, 0)
        body = json.loads(state.body)
        self.assertEqual(body[7], [])
        self.assertIsNone(body[8])

    def test_pending_round_is_recorded_in_p(self):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), 1)
        rnd = session.next()
        blob = session.checkpoint()
        body = json.loads(BitState.from_bytes(blob).body)
        self.assertEqual(BitState.from_bytes(blob).seq, 1)
        self.assertEqual(body[8], [1, rnd.bit, body[8][2]])
        self.assertEqual(body[8][2], clock.now)

    def test_checkpoint_is_a_pure_read(self):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=3)
        rnd = session.next()
        session.checkpoint()
        session.checkpoint()
        # The pending round is still pending: next() must fail, submit works.
        with self.assertRaises(ValueError):
            session.next()
        clock.advance()
        session.submit(rnd, Prover(KEY).bit(rnd.t, DIGEST, rnd.index, rnd.bit))
        body = json.loads(BitState.from_bytes(session.checkpoint()).body)
        self.assertIsNone(body[8])

    def test_checkpoint_only_while_active(self):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=2)
        run_rounds(session, clock, Prover(KEY), 2)
        session.finish()
        with self.assertRaises(ValueError):
            session.checkpoint()

        other = make_verifier().start_bits(CONTEXT, OPENING, rounds=1)
        other.revoke()
        with self.assertRaises(ValueError):
            other.checkpoint()


class BitStateEncodingTest(unittest.TestCase):
    def _state(self, seq=2, **kwargs):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), seq)
        return BitState.from_bytes(session.checkpoint())

    def test_frozen_positional_and_field_equality(self):
        state = self._state()
        self.assertEqual(
            state,
            BitState(state.version, state.seq, state.body, state.mac),
        )
        with self.assertRaises(AttributeError):
            state.seq = 3

    def test_round_trip(self):
        blob = self._state().to_bytes()
        self.assertEqual(BitState.from_bytes(blob).to_bytes(), blob)

    def test_from_bytes_rejects_non_bytes_with_type_error(self):
        blob = self._state().to_bytes()
        for bad in (blob.decode(), bytearray(blob), None, 42, [], object()):
            with self.assertRaises(TypeError):
                BitState.from_bytes(bad)

    def test_malformed_json(self):
        with self.assertRaises(ValueError):
            BitState.from_bytes(b"{not json")

    def test_outer_shape(self):
        blob = self._state().to_bytes()
        outer = json.loads(blob)
        for mutated in (outer[:-1], outer + [1], [2] + outer[1:], []):
            with self.assertRaises(ValueError):
                BitState.from_bytes(compact(mutated))
        with self.assertRaises(ValueError):
            BitState.from_bytes(b"{}")

    def test_version_contract(self):
        outer = json.loads(self._state().to_bytes())
        outer[0] = 2
        outer[3] = "00" * 32
        with self.assertRaises(ValueError):
            BitState.from_bytes(compact(outer))
        for bad_version in ("1", 1.0, None):
            broken = json.loads(self._state().to_bytes())
            broken[0] = bad_version
            with self.assertRaises(TypeError):
                BitState.from_bytes(compact(broken))

    def test_seq_contract(self):
        blob = self._state().to_bytes()
        for bad_seq in (True, False, 1.0, "2", None, -1, 2**64):
            broken = json.loads(blob)
            broken[1] = bad_seq
            with self.assertRaises((TypeError, ValueError)):
                BitState.from_bytes(compact(broken))
        # bool and other non-int types are TypeErrors; out-of-range ints
        # ValueErrors.
        for bad_seq in (True, False, 1.0, "2", None):
            broken = json.loads(blob)
            broken[1] = bad_seq
            with self.assertRaises(TypeError):
                BitState.from_bytes(compact(broken))
        for bad_seq in (-1, 2**64):
            broken = json.loads(blob)
            broken[1] = bad_seq
            with self.assertRaises(ValueError):
                BitState.from_bytes(compact(broken))

    def test_body_and_mac_hex_rules(self):
        outer = json.loads(self._state().to_bytes())
        for slot in (2, 3):
            for bad in (123, None, [], "zz"):
                broken = json.loads(self._state().to_bytes())
                broken[slot] = bad
                with self.assertRaises(ValueError):
                    BitState.from_bytes(compact(broken))
        # Uppercase hex and whitespace are non-canonical.
        broken = json.loads(self._state().to_bytes())
        broken[3] = broken[3].upper()
        with self.assertRaises(ValueError):
            BitState.from_bytes(compact(broken))
        with self.assertRaises(ValueError):
            BitState.from_bytes(
                json.dumps(json.loads(self._state().to_bytes()), indent=2).encode()
            )

    def test_mac_wrong_length(self):
        outer = json.loads(self._state().to_bytes())
        outer[3] = (b"\x00" * 31).hex()
        with self.assertRaises(ValueError):
            BitState.from_bytes(compact(outer))

    def test_body_must_be_canonical(self):
        state = self._state()
        with self.assertRaises(ValueError):
            BitState(1, state.seq, b" not json", state.mac)
        pretty = json.dumps(json.loads(state.body), indent=2).encode()
        with self.assertRaises(ValueError):
            BitState(1, state.seq, pretty, state.mac)

    def test_empty_body_rejected(self):
        state = self._state()
        with self.assertRaises(ValueError):
            BitState(1, 0, b"", state.mac)

    def test_constructor_type_errors(self):
        state = self._state()
        cases = [
            dict(version="1", seq=0, body=state.body, mac=state.mac),
            dict(version=1, seq=True, body=state.body, mac=state.mac),
            dict(version=1, seq=0, body="x", mac=state.mac),
            dict(version=1, seq=0, body=state.body, mac="m"),
            dict(version=1, seq=0, body=state.body, mac=bytearray(32)),
            dict(version=True, seq=0, body=state.body, mac=state.mac),
        ]
        for kwargs in cases:
            with self.assertRaises(TypeError):
                BitState(**kwargs)

    def test_constructor_value_errors(self):
        state = self._state()
        cases = [
            dict(version=2, seq=0, body=state.body, mac=state.mac),
            dict(version=1, seq=-1, body=state.body, mac=state.mac),
            dict(version=1, seq=2**64, body=state.body, mac=state.mac),
            dict(version=1, seq=0, body=state.body, mac=b"\x00" * 31),
            dict(version=1, seq=99, body=state.body, mac=state.mac),
        ]
        for kwargs in cases:
            with self.assertRaises(ValueError):
                BitState(**kwargs)

    def test_body_field_lengths(self):
        blob = self._state().to_bytes()
        body = json.loads(bytes.fromhex(json.loads(blob)[2]))
        for slot, length in ((0, 16), (1, 32), (2, 32), (3, 32)):
            broken = json.loads(blob)
            inner = json.loads(bytes.fromhex(broken[2]))
            inner[slot] = (b"\x00" * (length - 1)).hex()
            broken[2] = compact(inner).hex()
            with self.assertRaises(ValueError):
                BitState.from_bytes(compact(broken))

    def test_rounds_contract(self):
        blob = self._state().to_bytes()
        for bad_rounds in (0, -1, 2**32 + 1, True, 4.0, "4", None):
            broken = json.loads(blob)
            inner = json.loads(bytes.fromhex(broken[2]))
            inner[4] = bad_rounds
            broken[2] = compact(inner).hex()
            with self.assertRaises(ValueError):
                BitState.from_bytes(compact(broken))
        # R == 2**32 is allowed (closed range; indices run 0 .. R-1).
        broken = json.loads(blob)
        inner = json.loads(bytes.fromhex(broken[2]))
        inner[4] = 2**32
        broken[2] = compact(inner).hex()
        BitState.from_bytes(compact(broken))

    def test_timeout_and_speed_contract(self):
        blob = self._state().to_bytes()
        for slot in (5, 6):
            for bad in (0.0, -1.0, math.inf, -math.inf, math.nan, True, "1", None):
                broken = json.loads(blob)
                inner = json.loads(bytes.fromhex(broken[2]))
                inner[slot] = bad
                broken[2] = compact(inner).hex()
                with self.assertRaises(ValueError):
                    BitState.from_bytes(compact(broken))

    def test_query_contract(self):
        blob = self._state().to_bytes()

        def rebuild(mutate_inner):
            broken = json.loads(blob)
            inner = json.loads(bytes.fromhex(broken[2]))
            mutate_inner(inner)
            broken[2] = compact(inner).hex()
            return compact(broken)

        # Q must be an array of 4-tuples.
        with self.assertRaises(ValueError):
            BitState.from_bytes(rebuild(lambda i: i.__setitem__(7, "q")))
        with self.assertRaises(ValueError):
            BitState.from_bytes(
                rebuild(lambda i: i[7].__setitem__(0, i[7][0][:3]))
            )
        # b in {0,1}, not bool.
        for bad_bit in (True, False, 2, -1):
            with self.assertRaises(ValueError):
                BitState.from_bytes(
                    rebuild(lambda i, x=bad_bit: i[7][0].__setitem__(0, x))
                )
        # r must decode to 32 bytes.
        with self.assertRaises(ValueError):
            BitState.from_bytes(
                rebuild(lambda i: i[7][0].__setitem__(1, (b"\x00" * 31).hex()))
            )
        # s/e finite non-bool numbers; an int literal fails the canonical
        # round-trip.
        with self.assertRaises(ValueError):
            BitState.from_bytes(
                rebuild(lambda i: i[7][0].__setitem__(2, 1))
            )
        for bad_reading in (math.inf, math.nan, True, None, "1.0"):
            with self.assertRaises(ValueError):
                BitState.from_bytes(
                    rebuild(lambda i, x=bad_reading: i[7][0].__setitem__(2, x))
                )

    def test_q_longer_than_rounds_rejected(self):
        state = make_state(0, rounds=1, queries=[])
        body = json.loads(state.body)
        body[7] = [[0, (b"\x00" * 32).hex(), 0.0, 0.0],
                   [1, (b"\x01" * 32).hex(), 0.0, 0.0]]
        with self.assertRaises(ValueError):
            BitState(1, 2, compact(body), state.mac)

    def test_pending_contract(self):
        t = b"t" * 16

        def state_with(pending, seq=1, rounds=4):
            body = compact([
                t.hex(), CONTEXT.hex(), DIGEST.hex(), OPENING.hex(),
                rounds, 0.001, SPEED, [], pending,
            ])
            return BitState(1, seq, body, b"\x00" * 32)

        # P present at seq == R is forbidden.
        with self.assertRaises(ValueError):
            state_with([2, 0, 1000.0], seq=2, rounds=2)
        # P seq must equal len(Q).
        with self.assertRaises(ValueError):
            state_with([2, 0, 1000.0], seq=1)
        # Wrong shape / types.
        for bad_p in ([1, 0], [1, 0, 1000.0, 9], "p", 42, [True, 0, 1.0],
                      [1, 2, 1.0], [1, 0, math.inf], [1, 0, True]):
            with self.assertRaises(ValueError):
                state_with(bad_p)

    def test_seq_must_equal_q_length(self):
        state = self._state()
        body = json.loads(state.body)
        with self.assertRaises(ValueError):
            BitState(1, 3, compact(body), state.mac)
        with self.assertRaises(ValueError):
            BitState(1, 1, compact(body), state.mac)


class ResumeBitsTest(unittest.TestCase):
    def _session(self, clock=None, rounds=4, **kwargs):
        clock = clock or SteppedClock()
        return clock, make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=rounds, **kwargs
        )

    def test_accepts_state_and_bytes(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 2)
        blob = session.checkpoint()
        state = BitState.from_bytes(blob)
        verifier = make_verifier(clock)
        self.assertIsNotNone(verifier.resume_bits(blob))
        self.assertIsNotNone(verifier.resume_bits(state))
        self.assertIsNotNone(verifier.resume_bits(blob, floor=None))

    def test_wrong_types_raise_type_error(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 1)
        blob = session.checkpoint()
        verifier = make_verifier()
        for bad in (None, 42, "x", bytearray(blob), [], object(), 1.5):
            with self.assertRaises(TypeError):
                verifier.resume_bits(bad)
        for bad in (42, "x", bytearray(blob), [], object()):
            with self.assertRaises(TypeError):
                verifier.resume_bits(blob, floor=bad)

    def test_malformed_bytes_raise_value_error(self):
        with self.assertRaises(ValueError):
            make_verifier().resume_bits(b"not json")

    def test_wrong_key_rejected(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 2)
        with self.assertRaises(ValueError):
            Verifier(OTHER_KEY).resume_bits(session.checkpoint())

    def test_tampered_blob_rejected(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 2)
        blob = bytearray(session.checkpoint())
        blob[10] ^= 0xFF
        with self.assertRaises(ValueError):
            make_verifier().resume_bits(bytes(blob))

    def test_digest_recomputed(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 2)
        forged = hashlib.sha256(b"forged").digest()

        def mutate(inner):
            t = bytes.fromhex(inner[0])
            inner[2] = forged.hex()
            for index, query in enumerate(inner[7]):
                query[1] = expected_r(KEY, t, forged, index, query[0]).hex()

        with self.assertRaises(ValueError):
            make_verifier().resume_bits(resign(session.checkpoint(), mutate))

    def test_response_recomputed_by_index(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 3)

        def mutate(inner):
            inner[7][0], inner[7][1] = inner[7][1], inner[7][0]

        with self.assertRaises(ValueError):
            make_verifier().resume_bits(resign(session.checkpoint(), mutate))

    def test_round_trip_bounds_checked(self):
        clock, session = self._session()
        run_rounds(session, clock, Prover(KEY), 2)

        def mutate(inner):
            inner[7][0][3] = inner[7][0][3] - 0.0001  # e < s

        with self.assertRaises(ValueError):
            make_verifier().resume_bits(resign(session.checkpoint(), mutate))

        def mutate2(inner):
            inner[7][0][3] = inner[7][0][2] + inner[5] + 1.0

        with self.assertRaises(ValueError):
            make_verifier().resume_bits(resign(session.checkpoint(), mutate2))

    def test_resume_and_finish_audits(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=5, timeout=0.002)
        run_rounds(session, clock, Prover(KEY), 2)
        saved = session.checkpoint()

        resumed = verifier.resume_bits(saved)
        self.assertEqual(len(resumed._queries), 2)
        run_rounds(resumed, clock, Prover(KEY), 3)
        evidence = resumed.finish()
        record = BitEvidence.from_bytes(evidence)
        self.assertEqual(len(record.queries), 5)
        self.assertEqual(audit_b(evidence, KEY), record.limit)
        with self.assertRaises(ValueError):
            resumed.checkpoint()

    def test_resume_with_pending_round(self):
        clock = SteppedClock(start=0.0)
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=3, timeout=0.01)
        rnd = session.next()
        saved = session.checkpoint()

        resumed = verifier.resume_bits(saved)
        # The carried round is still pending.
        with self.assertRaises(ValueError):
            resumed.next()
        clock.advance()
        # The original BitRound (same t/index/bit) completes it.
        resumed.submit(
            rnd, Prover(KEY).bit(rnd.t, DIGEST, rnd.index, rnd.bit)
        )
        run_rounds(resumed, clock, Prover(KEY), 2)
        evidence = resumed.finish()
        self.assertTrue(math.isclose(
            audit_b(evidence, KEY), clock.step * SPEED / 2,
            rel_tol=1e-12, abs_tol=1e-9,
        ))

    def test_resume_completed_session_can_finish(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=2)
        run_rounds(session, clock, Prover(KEY), 2)
        saved = session.checkpoint()
        resumed = verifier.resume_bits(saved)
        with self.assertRaises(ValueError):
            resumed.next()
        evidence = resumed.finish()
        self.assertEqual(len(BitEvidence.from_bytes(evidence).queries), 2)

    def test_floor_low_sequence_rejected(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), 1)
        low = session.checkpoint()
        run_rounds(session, clock, Prover(KEY), 1)
        high = session.checkpoint()
        with self.assertRaises(ValueError):
            verifier.resume_bits(low, floor=high)

    def test_floor_equal_sequence_replay(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), 2)
        saved = session.checkpoint()
        self.assertIsNotNone(verifier.resume_bits(saved, floor=saved))
        self.assertIsNotNone(
            verifier.resume_bits(
                saved, floor=BitState.from_bytes(saved)
            )
        )

    def test_floor_equal_sequence_different_body_rejected(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), 2)
        saved = session.checkpoint()
        different = resign(saved, lambda inner: inner[7][0].__setitem__(
            3, inner[7][0][3] + 0.0000001))
        with self.assertRaises(ValueError):
            verifier.resume_bits(different, floor=saved)

    def test_floor_high_sequence_continuation(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=5)
        run_rounds(session, clock, Prover(KEY), 1)
        floor = session.checkpoint()
        run_rounds(session, clock, Prover(KEY), 2)
        top = session.checkpoint()
        self.assertIsNotNone(verifier.resume_bits(top, floor=floor))

    def test_floor_requires_q_prefix(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=5)
        run_rounds(session, clock, Prover(KEY), 2)
        floor = session.checkpoint()
        run_rounds(session, clock, Prover(KEY), 1)
        top = session.checkpoint()
        # Swap the first two completed rounds and re-sign: prefix broken.
        broken = resign(top, lambda inner: inner[7].__setitem__(
            slice(0, 2), [inner[7][1], inner[7][0]]))
        with self.assertRaises(ValueError):
            verifier.resume_bits(broken, floor=floor)

    def test_floor_requires_first_seven_identical(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=5, timeout=0.005)
        run_rounds(session, clock, Prover(KEY), 2)
        floor = session.checkpoint()
        run_rounds(session, clock, Prover(KEY), 1)
        top = session.checkpoint()
        # Change T; responses stay valid but the continuation must fail.
        broken = resign(top, lambda inner: inner.__setitem__(5, 0.004))
        with self.assertRaises(ValueError):
            verifier.resume_bits(broken, floor=floor)

    def test_floor_pending_round_chains_next_query(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=5)
        run_rounds(session, clock, Prover(KEY), 1)
        rnd = session.next()  # outstanding at seq 1
        floor = session.checkpoint()
        clock.advance()
        session.submit(rnd, Prover(KEY).bit(rnd.t, DIGEST, rnd.index, rnd.bit))
        run_rounds(session, clock, Prover(KEY), 1)
        top = session.checkpoint()
        # The real continuation answers the floor's exact pending round.
        self.assertIsNotNone(verifier.resume_bits(top, floor=floor))

        # A forged seq-2 state whose first new Q item answers the opposite
        # bit must be rejected even though its NPFR1 response is valid.
        floor_outer = json.loads(floor)
        inner = json.loads(bytes.fromhex(floor_outer[2]))
        pending_bit, pending_start = inner[8][1], inner[8][2]
        wrong = 1 - pending_bit
        response = expected_r(
            KEY, bytes.fromhex(inner[0]), bytes.fromhex(inner[2]), 1, wrong
        )
        inner[7].append([wrong, response.hex(), pending_start,
                         pending_start + 0.00002])
        inner[8] = None
        body = compact(inner)
        outer = [1, 2, body.hex(), hmac.new(
            KEY, PREFIX_BS + compact([1, 2, body.hex()]), hashlib.sha256
        ).digest().hex()]
        with self.assertRaises(ValueError):
            verifier.resume_bits(compact(outer), floor=floor)

    def test_floor_itself_must_verify(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), 2)
        saved = session.checkpoint()
        # A floor MAC'd with another key is rejected even when x is valid.
        bogus_floor = resign(saved, lambda inner: None, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            verifier.resume_bits(saved, floor=bogus_floor)

    def test_floor_malformed_bytes_rejected(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4)
        run_rounds(session, clock, Prover(KEY), 1)
        with self.assertRaises(ValueError):
            verifier.resume_bits(session.checkpoint(), floor=b"not json")


if __name__ == "__main__":
    unittest.main()
