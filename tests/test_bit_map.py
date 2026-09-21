import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitGate,
    BitGuard,
    BitMap,
    BitState,
    Prover,
    Verifier,
    _BIT_MAP_PREFIX,
    _bit_map_mac,
    _bit_map_payload,
    _bit_state_mac,
    _bit_state_sid,
    _encode_payload,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2
CONTEXT = bytes(range(32))
OPENING = bytes(range(1, 33))
OTHER_CONTEXT = bytes(range(32, 64))
OTHER_OPENING = bytes(range(33, 65))
SPEED = 299_792_458.0
DELAY = 0.00002

SID_A = b"\x0a" * 32
SID_B = b"\x0b" * 32
SID_C = b"\x0c" * 32
HASH_1 = b"\x01" * 32
HASH_2 = b"\x02" * 32
ZERO = b"\x00" * 32


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
    return hashlib.sha256(b"NPFC1" + context + opening).digest()


def make_verifier(clock=None, speed=SPEED, key=KEY):
    return Verifier(key, clock=clock or SteppedClock(), speed_mps=speed)


def drive(session, clock, n, delay=DELAY, key=KEY, digest=None):
    """Successfully drive ``n`` rounds of a step-driven session."""
    prover = RecordingProver(key, clock, delay=delay)
    digest = digest if digest is not None else digest_of()
    for _ in range(n):
        round_ = session.next()
        session.submit(round_, prover.bit(round_.t, digest, round_.index, round_.bit))


def checkpoint_after(
    rounds_done, *, total=4, clock=None, key=KEY, context=CONTEXT,
    opening=OPENING,
):
    """A fresh valid BitState checkpoint carrying ``rounds_done`` queries."""
    clock = clock or SteppedClock()
    session = make_verifier(clock, key=key).start_bits(
        context, opening, rounds=total, timeout=0.01
    )
    drive(
        session, clock, rounds_done, key=key,
        digest=digest_of(context, opening),
    )
    return session.checkpoint()


def map_for(*blobs, key=KEY, mac=None):
    """The BitMap a gate would hold after accepting ``blobs`` in order."""
    entries = {}
    for blob in blobs:
        state = BitState.from_bytes(blob)
        entries[_bit_state_sid(state)] = (
            state.seq,
            hashlib.sha256(state.body).digest(),
        )
    ordered = tuple(
        (sid, seq, digest)
        for sid, (seq, digest) in sorted(entries.items())
    )
    placeholder = BitMap(1, ordered, ZERO)
    if mac is None:
        mac = _bit_map_mac(key, _bit_map_payload(ordered))
    return BitMap(1, ordered, mac)


class BitMapContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        entries = ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))
        first = BitMap(1, entries, ZERO)
        second = BitMap(
            1, tuple(tuple(entry) for entry in entries), bytes(ZERO)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.entries, first.mac),
            (1, entries, ZERO),
        )
        self.assertNotEqual(first, BitMap(1, entries, b"\x01" * 32))
        self.assertNotEqual(
            first, BitMap(1, ((SID_A, 1, HASH_1),), ZERO)
        )

    def test_empty_entries(self):
        table = BitMap(1, (), ZERO)
        self.assertEqual(table.entries, ())

    def test_is_frozen(self):
        table = BitMap(1, (), ZERO)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            table.mac = b"\x01" * 32

    def test_version_contract(self):
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(bad, (), ZERO)
        with self.assertRaises(ValueError):
            BitMap(2, (), ZERO)

    def test_entries_must_be_a_tuple(self):
        for bad in ([[SID_A, 1, HASH_1]], "x", None, 42, {SID_A: 1}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, bad, ZERO)

    def test_entry_shape(self):
        for bad in ([SID_A, 1, HASH_1], "x", None, 42):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, (bad,), ZERO)
        for bad in ((), (SID_A,), (SID_A, 1), (SID_A, 1, HASH_1, SID_B)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, (bad,), ZERO)

    def test_entry_sid_and_hash_contract(self):
        for bad in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, ((bad, 1, HASH_1),), ZERO)
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, ((SID_A, 1, bad),), ZERO)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, ((bad, 1, HASH_1),), ZERO)
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, ((SID_A, 1, bad),), ZERO)

    def test_entry_seq_is_non_bool_u64(self):
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, ((SID_A, bad, HASH_1),), ZERO)
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, ((SID_A, bad, HASH_1),), ZERO)
        for good in (0, 1, 2**64 - 1):
            BitMap(1, ((SID_A, good, HASH_1),), ZERO)

    def test_entries_sorted_and_unique(self):
        with self.assertRaises(ValueError):
            BitMap(1, ((SID_B, 1, HASH_1), (SID_A, 2, HASH_2)), ZERO)
        with self.assertRaises(ValueError):
            BitMap(1, ((SID_A, 1, HASH_1), (SID_A, 2, HASH_2)), ZERO)
        BitMap(1, ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)), ZERO)

    def test_mac_contract(self):
        for bad in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, (), bad)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, (), bad)


class BitMapEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        entries = ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))
        table = BitMap(1, entries, ZERO)
        obj = json.loads(table.to_bytes())
        self.assertEqual(
            obj,
            [
                1,
                [[SID_A.hex(), 1, HASH_1.hex()],
                 [SID_B.hex(), 2, HASH_2.hex()]],
                ZERO.hex(),
            ],
        )
        self.assertNotIn(b" ", table.to_bytes())
        self.assertEqual(
            table.to_bytes(),
            json.dumps(obj, separators=(",", ":")).encode("utf-8"),
        )

    def test_round_trip(self):
        for entries in (
            (),
            ((SID_A, 0, HASH_1),),
            ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2), (SID_C, 3, ZERO)),
        ):
            table = BitMap(1, entries, b"\x0f" * 32)
            self.assertEqual(BitMap.from_bytes(table.to_bytes()), table)

    def test_round_trip_u64_extreme(self):
        table = BitMap(1, ((SID_A, 2**64 - 1, HASH_1),), ZERO)
        self.assertEqual(BitMap.from_bytes(table.to_bytes()), table)

    def test_from_bytes_rejects_non_bytes(self):
        data = BitMap(1, (), ZERO).to_bytes()
        for bad in (data.decode(), None, 42, [1], bytearray(data), {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap.from_bytes(bad)

    def test_from_bytes_rejects_outer_shape(self):
        good = json.loads(BitMap(1, ((SID_A, 1, HASH_1),), ZERO).to_bytes())
        blobs = [
            json.dumps(good[:2], separators=(",", ":")).encode(),
            json.dumps(good + [0], separators=(",", ":")).encode(),
            json.dumps({"version": 1}, separators=(",", ":")).encode(),
            json.dumps([1, [], ZERO.hex()], separators=(",", ":")).encode()
            .replace(b"[1,", b"[2,"),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_rejects_wrong_field_types_with_type_error(self):
        entry = [SID_A.hex(), 1, HASH_1.hex()]
        mac = ZERO.hex()
        blobs = [
            json.dumps(["1", [entry], mac], separators=(",", ":")).encode(),
            json.dumps([1, "x", mac], separators=(",", ":")).encode(),
            json.dumps([1, ["x"], mac], separators=(",", ":")).encode(),
            json.dumps([1, [[42, 1, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex(), 1.0, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex(), True, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex(), 1, None]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [entry], 42], separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(TypeError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        entry = [SID_A.hex(), 1, HASH_1.hex()]
        mac = ZERO.hex()
        blobs = [
            json.dumps([2, [entry], mac], separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex(), -1, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex(), 2**64, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [["zz", 1, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex().upper(), 1, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [["00", 1, HASH_1.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [[SID_A.hex(), 1, "ab" * 31]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [entry[:-1]], mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, [entry + [SID_B.hex()]], mac],
                       separators=(",", ":")).encode(),
            json.dumps(
                [1, [[SID_B.hex(), 1, HASH_1.hex()],
                     [SID_A.hex(), 2, HASH_2.hex()]], mac],
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                [1, [[SID_A.hex(), 1, HASH_1.hex()],
                     [SID_A.hex(), 2, HASH_2.hex()]], mac],
                separators=(",", ":"),
            ).encode(),
            json.dumps([1, [entry], "ab" * 31],
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = BitMap(1, ((SID_A, 1, HASH_1),), ZERO).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}",
                     b"not json", b"", b"null"):
            with self.assertRaises(ValueError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        table = BitMap(1, ((SID_A, 1, HASH_1),), ZERO)
        decoded = BitMap.from_bytes(table.to_bytes())
        self.assertEqual(decoded, table)
        self.assertEqual(decoded.mac, ZERO)


class BitMapMacTest(unittest.TestCase):
    def test_mac_formula_direct_concatenation(self):
        table = map_for(checkpoint_after(1), checkpoint_after(1))
        encoding = _encode_payload(_bit_map_payload(table.entries))
        self.assertEqual(
            table.mac,
            hmac.new(KEY, _BIT_MAP_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            KEY,
            _BIT_MAP_PREFIX + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(table.mac, forged)
        self.assertNotEqual(
            table.mac,
            hmac.new(OTHER_KEY, _BIT_MAP_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )

    def test_sid_is_sha256_of_first_seven_body_items(self):
        state = BitState.from_bytes(checkpoint_after(2, total=4))
        body = json.loads(state.body)
        expected = hashlib.sha256(
            _encode_payload(body[:7])
        ).digest()
        self.assertEqual(_bit_state_sid(state), expected)
        table = map_for(state.to_bytes())
        self.assertEqual(table.entries[0][0], expected)

    def test_entry_hash_is_sha256_of_state_body(self):
        state = BitState.from_bytes(checkpoint_after(3, total=4))
        table = map_for(state.to_bytes())
        self.assertEqual(
            table.entries[0][2], hashlib.sha256(state.body).digest()
        )
        self.assertEqual(table.entries[0][1], state.seq)


class BitGateInitTest(unittest.TestCase):
    def test_verifier_must_be_a_verifier(self):
        for bad in (KEY, None, 42, object(), "verifier"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitGate(bad)

    def test_checkpoint_is_keyword_only(self):
        verifier = make_verifier()
        table = map_for(checkpoint_after(1))
        with self.assertRaises(TypeError):
            BitGate(verifier, table)
        self.assertIsNone(BitGate(verifier).checkpoint)
        self.assertIs(BitGate(verifier, checkpoint=None).checkpoint, None)

    def test_checkpoint_must_be_map_bytes_or_none(self):
        verifier = make_verifier()
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitGate(verifier, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            BitGate(make_verifier(), checkpoint=b"not json")

    def test_checkpoint_accepts_object_and_bytes(self):
        table = map_for(checkpoint_after(1))
        from_object = BitGate(make_verifier(), checkpoint=table)
        from_bytes = BitGate(
            make_verifier(), checkpoint=table.to_bytes()
        )
        self.assertEqual(from_object.checkpoint, table)
        self.assertEqual(from_bytes.checkpoint, table)

    def test_checkpoint_mac_verified_against_verifier_key(self):
        table = map_for(checkpoint_after(1))
        bad_mac = BitMap(1, table.entries, ZERO)
        with self.assertRaises(ValueError):
            BitGate(make_verifier(), checkpoint=bad_mac)
        with self.assertRaises(ValueError):
            BitGate(make_verifier(key=OTHER_KEY), checkpoint=table)
        other = map_for(checkpoint_after(1), key=OTHER_KEY)
        with self.assertRaises(ValueError):
            BitGate(make_verifier(), checkpoint=other)


class BitGateResumeTest(unittest.TestCase):
    def test_first_resume_establishes_entry(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(1)
        session = gate.resume(blob)
        self.assertIsNotNone(session)
        self.assertEqual(gate.checkpoint, map_for(blob))

    def test_resume_accepts_state_object_and_bytes(self):
        blob = checkpoint_after(1)
        state = BitState.from_bytes(blob)
        first = BitGate(make_verifier())
        second = BitGate(make_verifier())
        first.resume(state)
        second.resume(blob)
        self.assertEqual(first.checkpoint, second.checkpoint)

    def test_resume_rejects_wrong_types(self):
        gate = BitGate(make_verifier())
        for bad in ("x", 1, None, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                gate.resume(bad)
        self.assertIsNone(gate.checkpoint)

    def test_resume_rejects_bad_mac_and_malformed_bytes(self):
        gate = BitGate(make_verifier())
        state = BitState.from_bytes(checkpoint_after(1))
        forged = BitState(1, state.seq, state.body, ZERO)
        with self.assertRaises(ValueError):
            gate.resume(forged)
        with self.assertRaises(ValueError):
            gate.resume(b"not json")
        self.assertIsNone(gate.checkpoint)

    def test_higher_seq_advances_entry(self):
        gate = BitGate(make_verifier())
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 1)
        gate.resume(session.checkpoint())
        drive(session, clock, 1)
        gate.resume(session.checkpoint())
        self.assertEqual(gate.checkpoint.entries[0][1], 2)
        self.assertEqual(gate.checkpoint, map_for(session.checkpoint()))

    def test_equal_seq_same_body_is_replay(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(2)
        gate.resume(blob)
        before = gate.checkpoint
        session = gate.resume(blob)
        self.assertIsNotNone(session)
        self.assertEqual(gate.checkpoint, before)
        self.assertIs(gate.checkpoint, before)

    def test_equal_seq_different_body_rejected(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(1)
        gate.resume(blob)
        # Same session parameters and seq, but a different transcript t
        # yields a different sid; same sid with a different body needs a
        # tampered state, which the MAC rejects. Forge a same-sid body by
        # re-signing a mutated body with the key instead.
        state = BitState.from_bytes(blob)
        body = json.loads(state.body)
        body[7][0][3] += 0.0001  # different e, same seq
        mutated = _encode_payload(body)
        mac = _bit_state_mac(KEY, state.seq, mutated)
        forged = BitState(1, state.seq, mutated, mac)
        before = gate.checkpoint
        with self.assertRaises(ValueError):
            gate.resume(forged)
        self.assertEqual(gate.checkpoint, before)

    def test_lower_seq_rejected_without_state_change(self):
        gate = BitGate(make_verifier())
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 1)
        first = session.checkpoint()
        drive(session, clock, 1)
        second = session.checkpoint()
        gate.resume(second)
        before = gate.checkpoint
        with self.assertRaises(ValueError):
            gate.resume(first)
        self.assertEqual(gate.checkpoint, before)

    def test_partitions_advance_independently(self):
        gate = BitGate(make_verifier())
        clock_a = SteppedClock()
        session_a = make_verifier(clock_a).start_bits(
            CONTEXT, OPENING, rounds=4, timeout=0.01
        )
        clock_b = SteppedClock()
        session_b = make_verifier(clock_b).start_bits(
            OTHER_CONTEXT, OTHER_OPENING, rounds=4, timeout=0.01
        )
        drive(session_a, clock_a, 1, digest=digest_of(CONTEXT, OPENING))
        stale_a = session_a.checkpoint()
        drive(session_a, clock_a, 1, digest=digest_of(CONTEXT, OPENING))
        drive(session_b, clock_b, 1,
              digest=digest_of(OTHER_CONTEXT, OTHER_OPENING))
        gate.resume(session_a.checkpoint())
        gate.resume(session_b.checkpoint())
        table = gate.checkpoint
        self.assertEqual(len(table.entries), 2)
        sids = [entry[0] for entry in table.entries]
        self.assertEqual(sids, sorted(sids))
        self.assertEqual(sorted(entry[1] for entry in table.entries), [1, 2])
        # A rollback on one partition is rejected, leaving both untouched.
        with self.assertRaises(ValueError):
            gate.resume(stale_a)
        self.assertEqual(gate.checkpoint, table)
        # The other partition still advances.
        drive(session_b, clock_b, 1,
              digest=digest_of(OTHER_CONTEXT, OTHER_OPENING))
        gate.resume(session_b.checkpoint())
        self.assertEqual(len(gate.checkpoint.entries), 2)
        self.assertEqual(
            sorted(entry[1] for entry in gate.checkpoint.entries), [2, 2]
        )

    def test_checkpoint_round_trip_across_restart(self):
        clock = SteppedClock()
        session = make_verifier(clock).start_bits(
            CONTEXT, OPENING, rounds=4, timeout=0.01
        )
        drive(session, clock, 1)
        blob1 = session.checkpoint()
        drive(session, clock, 1)
        blob2 = session.checkpoint()
        gate = BitGate(make_verifier())
        gate.resume(blob1)
        gate.resume(blob2)
        persisted = gate.checkpoint.to_bytes()
        restored = BitGate(make_verifier(), checkpoint=persisted)
        self.assertEqual(restored.checkpoint, gate.checkpoint)
        restored.resume(blob2)  # replay accepted after restart
        with self.assertRaises(ValueError):
            restored.resume(blob1)

    def test_checkpoint_is_read_only_frozen_export(self):
        gate = BitGate(make_verifier())
        gate.resume(checkpoint_after(1))
        table = gate.checkpoint
        self.assertIs(table, gate.checkpoint)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            table.entries = ()
        with self.assertRaises(AttributeError):
            gate.checkpoint = None

    def test_concurrent_resumes_do_not_lose_updates(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=64,
                                      timeout=0.01)
        blobs = []
        for _ in range(16):
            drive(session, clock, 1)
            blobs.append(session.checkpoint())
        gate = BitGate(make_verifier())
        errors = []

        def worker(blob):
            try:
                gate.resume(blob)
            except ValueError as error:
                errors.append(error)

        threads = [
            threading.Thread(target=worker, args=(blob,))
            for blob in reversed(blobs)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # Out-of-order deliveries are rejected, but the highest seq wins
        # and no update is lost: the table holds seq 16 exactly once.
        self.assertEqual(len(gate.checkpoint.entries), 1)
        self.assertEqual(gate.checkpoint.entries[0][1], 16)
        self.assertEqual(
            gate.checkpoint.entries[0][2],
            hashlib.sha256(BitState.from_bytes(blobs[-1]).body).digest(),
        )

    def test_concurrent_partitions_all_recorded(self):
        blobs = [
            checkpoint_after(
                1, context=bytes([i]) * 32, opening=OPENING
            )
            for i in range(8)
        ]
        gate = BitGate(make_verifier())
        threads = [
            threading.Thread(target=gate.resume, args=(blob,))
            for blob in blobs
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(gate.checkpoint.entries), 8)
        sids = [entry[0] for entry in gate.checkpoint.entries]
        self.assertEqual(sids, sorted(sids))


class BitGateOldInterfaceTest(unittest.TestCase):
    def test_bit_guard_unchanged(self):
        guard = BitGuard(make_verifier())
        blob = checkpoint_after(1)
        guard.resume(blob)
        self.assertEqual(guard.checkpoint.seq, 1)

    def test_resume_bits_unchanged(self):
        verifier = make_verifier()
        blob = checkpoint_after(1)
        session = verifier.resume_bits(blob)
        self.assertIsNotNone(session)


if __name__ == "__main__":
    unittest.main()
