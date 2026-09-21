import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitEvidence,
    BitGate,
    BitMap,
    BitState,
    Prover,
    Verifier,
    _BIT_MAP_PREFIX,
    _bit_map_mac,
    _bit_map_payload,
    _encode_payload,
    audit_b,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2
CONTEXT = bytes(range(32))
OPENING = bytes(range(1, 33))
SPEED = 299_792_458.0
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
    return hashlib.sha256(b"NPFC1" + context + opening).digest()


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def make_verifier(clock=None, speed=SPEED, key=KEY):
    return Verifier(key, clock=clock or SteppedClock(), speed_mps=speed)


def drive(session, clock, n, delay=DELAY, key=KEY):
    """Successfully drive ``n`` rounds of a step-driven session."""
    prover = RecordingProver(key, clock, delay=delay)
    for _ in range(n):
        round_ = session.next()
        session.submit(
            round_, prover.bit(round_.t, digest_of(), round_.index, round_.bit)
        )


def checkpoint_after(rounds_done, *, total=4, clock=None, key=KEY):
    """A fresh valid BitState checkpoint carrying ``rounds_done`` queries."""
    clock = clock or SteppedClock()
    session = make_verifier(clock, key=key).start_bits(
        CONTEXT, OPENING, rounds=total, timeout=0.01
    )
    drive(session, clock, rounds_done, key=key)
    return session.checkpoint()


def row_for(blob):
    """The ``(sid, seq, hash)`` partition row a checkpoint state maps to."""
    state = BitState.from_bytes(blob)
    body = json.loads(state.body)
    sid = hashlib.sha256(compact(body[:7])).digest()
    return sid, state.seq, hashlib.sha256(state.body).digest()


def map_for(*blobs, key=KEY, mac=None):
    """A valid BitMap carrying the rows of the given checkpoint blobs."""
    rows = sorted(row_for(blob) for blob in blobs)
    placeholder = BitMap(1, tuple(rows), b"\x00" * 32)
    if mac is None:
        mac = _bit_map_mac(key, _bit_map_payload(placeholder))
    return BitMap(1, tuple(rows), mac)


class BitMapContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        first = map_for(checkpoint_after(1))
        second = BitMap(
            1,
            tuple(tuple(row) for row in first.entries),
            bytes(first.mac),
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        later = map_for(checkpoint_after(2))
        self.assertNotEqual(first, later)
        self.assertEqual(
            (first.version, first.entries, first.mac),
            (1, first.entries, first.mac),
        )

    def test_is_frozen(self):
        table = map_for(checkpoint_after(0))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            table.version = 2

    def test_version_contract(self):
        row = row_for(checkpoint_after(0))
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(bad, (row,), b"\x00" * 32)
        with self.assertRaises(ValueError):
            BitMap(2, (row,), b"\x00" * 32)

    def test_entries_must_be_a_tuple_of_triples(self):
        row = row_for(checkpoint_after(0))
        for bad in ("x", None, 42, [row], b"y"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, bad, b"\x00" * 32)
        for bad in ([row[0], row[1], row[2]], "abc", 42, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, (bad,), b"\x00" * 32)
        for bad in ((), (row[0], row[1]), row + (b"\x00",)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, (bad,), b"\x00" * 32)

    def test_sid_and_hash_contract(self):
        row = row_for(checkpoint_after(0))
        for index in (0, 2):
            for bad in ("x", None, 42, bytearray(32)):
                broken = list(row)
                broken[index] = bad
                with self.assertRaises(TypeError, msg=repr(bad)):
                    BitMap(1, (tuple(broken),), b"\x00" * 32)
            for bad in (b"\x00" * 31, b"\x00" * 33, b""):
                broken = list(row)
                broken[index] = bad
                with self.assertRaises(ValueError, msg=repr(bad)):
                    BitMap(1, (tuple(broken),), b"\x00" * 32)

    def test_seq_is_non_bool_u64(self):
        row = row_for(checkpoint_after(0))
        for bad in (True, False, 1.0, "1", None):
            broken = (row[0], bad, row[2])
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, (broken,), b"\x00" * 32)
        for bad in (-1, 2**64, 2**64 + 1):
            broken = (row[0], bad, row[2])
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, (broken,), b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            BitMap(1, ((row[0], good, row[2]),), b"\x00" * 32)

    def test_entries_sorted_unique_by_sid(self):
        one = row_for(checkpoint_after(1))
        two = row_for(checkpoint_after(1))
        ordered = tuple(sorted((one, two)))
        BitMap(1, ordered, b"\x00" * 32)
        with self.assertRaises(ValueError):
            BitMap(1, tuple(reversed(ordered)), b"\x00" * 32)
        with self.assertRaises(ValueError):
            BitMap(1, (one, one), b"\x00" * 32)

    def test_mac_contract(self):
        row = row_for(checkpoint_after(0))
        for bad in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap(1, (row,), bad)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMap(1, (row,), bad)

    def test_empty_entries_allowed(self):
        table = BitMap(1, (), b"\x00" * 32)
        self.assertEqual(table.entries, ())


class BitMapEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        table = map_for(checkpoint_after(1), checkpoint_after(2))
        obj = json.loads(table.to_bytes())
        self.assertEqual(len(obj), 3)
        version, entries, mac = obj
        self.assertEqual(version, 1)
        self.assertEqual(mac, table.mac.hex())
        self.assertEqual(len(entries), 2)
        for (sid, seq, digest), row in zip(entries, table.entries):
            self.assertEqual([sid, seq, digest], [row[0].hex(), row[1], row[2].hex()])
        self.assertNotIn(b" ", table.to_bytes())
        self.assertEqual(
            table.to_bytes(),
            compact(
                [
                    1,
                    [[row[0].hex(), row[1], row[2].hex()] for row in table.entries],
                    table.mac.hex(),
                ]
            ),
        )

    def test_round_trip(self):
        for blobs in (
            (),
            (checkpoint_after(0),),
            (checkpoint_after(1), checkpoint_after(2), checkpoint_after(3)),
        ):
            table = map_for(*blobs)
            self.assertEqual(BitMap.from_bytes(table.to_bytes()), table)

    def test_round_trip_u64_extreme(self):
        table = BitMap(1, ((b"\x0a" * 32, 2**64 - 1, b"\x0b" * 32),), b"\x0c" * 32)
        self.assertEqual(BitMap.from_bytes(table.to_bytes()), table)

    def test_from_bytes_rejects_non_bytes(self):
        data = map_for(checkpoint_after(1)).to_bytes()
        for bad in (data.decode(), None, 42, [1], bytearray(data), {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMap.from_bytes(bad)

    def test_from_bytes_rejects_wrong_shape(self):
        good = json.loads(map_for(checkpoint_after(1)).to_bytes())
        blobs = [
            compact(good[:2]),
            compact(good + [1]),
            b"{}",
            b'"x"',
            b"1",
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_rejects_wrong_field_types_with_type_error(self):
        good = json.loads(map_for(checkpoint_after(1)).to_bytes())
        row = good[1][0]
        blobs = [
            compact(["1", good[1], good[2]]),
            compact([1.0, good[1], good[2]]),
            compact([True, good[1], good[2]]),
            compact([1, {}, good[2]]),
            compact([1, [42], good[2]]),
            compact([1, [[42, row[1], row[2]]], good[2]]),
            compact([1, [[row[0], "1", row[2]]], good[2]]),
            compact([1, [[row[0], 1.0, row[2]]], good[2]]),
            compact([1, [[row[0], True, row[2]]], good[2]]),
            compact([1, [[row[0], row[1], 42]], good[2]]),
            compact([1, good[1], None]),
            compact([1, good[1], 42]),
        ]
        for blob in blobs:
            with self.assertRaises(TypeError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(map_for(checkpoint_after(1)).to_bytes())
        row = good[1][0]
        blobs = [
            compact([2, good[1], good[2]]),
            compact([1, [[row[0], row[1]]], good[2]]),
            compact([1, [[row[0], row[1], row[2], 0]], good[2]]),
            compact([1, [[row[0], -1, row[2]]], good[2]]),
            compact([1, [[row[0], 2**64, row[2]]], good[2]]),
            compact([1, [["zz", row[1], row[2]]], good[2]]),
            compact([1, [[row[0].upper(), row[1], row[2]]], good[2]]),
            compact([1, [["00", row[1], row[2]]], good[2]]),
            compact([1, [[row[0], row[1], "zz"]], good[2]]),
            compact([1, [[row[0], row[1], row[2].upper()]], good[2]]),
            compact([1, [[row[0], row[1], "ab" * 31]], good[2]]),
            compact([1, good[1], "ab" * 31]),
            compact([1, good[1], good[2].upper()]),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_rejects_unsorted_and_duplicate_rows(self):
        one = row_for(checkpoint_after(1))
        two = row_for(checkpoint_after(1))
        ordered = sorted((one, two))
        table = map_for(checkpoint_after(1))
        good_mac = json.loads(table.to_bytes())[2]
        rows = [[r[0].hex(), r[1], r[2].hex()] for r in ordered]
        with self.assertRaises(ValueError):
            BitMap.from_bytes(compact([1, rows[::-1], good_mac]))
        with self.assertRaises(ValueError):
            BitMap.from_bytes(compact([1, [rows[0], rows[0]], good_mac]))

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = map_for(checkpoint_after(1)).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"[]",
                     b"not json", b"", b"null"):
            with self.assertRaises(ValueError, msg=blob):
                BitMap.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        table = map_for(checkpoint_after(1), mac=b"\x00" * 32)
        decoded = BitMap.from_bytes(table.to_bytes())
        self.assertEqual(decoded, table)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class BitMapMacTest(unittest.TestCase):
    def test_sid_is_sha256_of_canonical_first_seven_body_items(self):
        blob = checkpoint_after(2, total=4)
        state = BitState.from_bytes(blob)
        body = json.loads(state.body)
        self.assertEqual(
            row_for(blob)[0],
            hashlib.sha256(compact(body[:7])).digest(),
        )
        # The first seven items are exactly [t, C, D, O, R, T, V].
        self.assertEqual(len(body[:7]), 7)

    def test_hash_is_sha256_of_body(self):
        blob = checkpoint_after(2, total=4)
        state = BitState.from_bytes(blob)
        self.assertEqual(row_for(blob)[2], hashlib.sha256(state.body).digest())

    def test_mac_formula_direct_concatenation(self):
        table = map_for(checkpoint_after(2, total=4))
        encoding = _encode_payload(_bit_map_payload(table))
        self.assertEqual(encoding, compact([1, json.loads(table.to_bytes())[1]]))
        self.assertEqual(
            table.mac,
            hmac.new(KEY, _BIT_MAP_PREFIX + encoding, hashlib.sha256).digest(),
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
            hmac.new(OTHER_KEY, _BIT_MAP_PREFIX + encoding, hashlib.sha256).digest(),
        )


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

    def test_checkpoint_mac_verified(self):
        blob = checkpoint_after(1)
        with self.assertRaises(ValueError):
            BitGate(make_verifier(),
                    checkpoint=map_for(blob, mac=b"\x00" * 32))
        with self.assertRaises(ValueError):
            BitGate(make_verifier(),
                    checkpoint=map_for(blob, key=OTHER_KEY))
        # A verifier holding another key rejects a good table.
        with self.assertRaises(ValueError):
            BitGate(make_verifier(key=OTHER_KEY),
                    checkpoint=map_for(blob))
        # Object and canonical bytes forms both accepted when the MAC is good.
        table = map_for(blob)
        self.assertIs(
            BitGate(make_verifier(), checkpoint=table).checkpoint,
            table,
        )
        restored = BitGate(
            make_verifier(), checkpoint=table.to_bytes()
        ).checkpoint
        self.assertEqual(restored, table)

    def test_checkpoint_property_is_read_only(self):
        gate = BitGate(make_verifier())
        with self.assertRaises(AttributeError):
            gate.checkpoint = map_for(checkpoint_after(1))


class BitGateGatingTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.verifier = make_verifier(self.clock)
        # One continuous session checkpointed at seq 0/1/2: every later
        # checkpoint extends the same transcript and body prefix.
        self.session = self.verifier.start_bits(
            CONTEXT, OPENING, rounds=4, timeout=0.01
        )
        self.b0 = self.session.checkpoint()
        drive(self.session, self.clock, 1)
        self.b1 = self.session.checkpoint()
        drive(self.session, self.clock, 1)
        self.b2 = self.session.checkpoint()

    def test_first_resume_establishes_row(self):
        gate = BitGate(self.verifier)
        self.assertIsNone(gate.checkpoint)
        restored = gate.resume(self.b1)
        self.assertEqual(gate.checkpoint, map_for(self.b1))
        self.assertEqual(gate.checkpoint.entries[0][1], 1)
        # The resumed session is active and can be driven to completion.
        drive(restored, self.clock, 3)
        self.assertGreater(audit_b(restored.finish(), KEY), 0.0)

    def test_first_resume_accepts_seq_zero(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b0)
        self.assertEqual(gate.checkpoint, map_for(self.b0))

    def test_bytes_and_object_inputs_equivalent(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        gate_from_bytes = BitGate(self.verifier)
        gate_from_bytes.resume(BitState.from_bytes(self.b1))
        self.assertEqual(gate.checkpoint, gate_from_bytes.checkpoint)

    def test_higher_seq_advances(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b0)
        gate.resume(self.b1)
        self.assertEqual(gate.checkpoint, map_for(self.b1))
        gate.resume(self.b2)
        self.assertEqual(gate.checkpoint, map_for(self.b2))

    def test_lower_seq_rejected_and_table_unchanged(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b2)
        with self.assertRaises(ValueError):
            gate.resume(self.b1)
        with self.assertRaises(ValueError):
            gate.resume(self.b0)
        self.assertEqual(gate.checkpoint, map_for(self.b2))

    def test_same_seq_same_hash_is_a_replay(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        for _ in range(3):
            gate.resume(self.b1)
            gate.resume(BitState.from_bytes(self.b1))
        self.assertEqual(gate.checkpoint, map_for(self.b1))

    def test_same_seq_different_hash_rejected(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        # Re-sign a body whose first seven items (and hence the sid) are
        # unchanged but whose bytes differ: shift one query's start/end
        # readings by the same amount so the round trip still recovers.
        outer = json.loads(self.b1)
        body = json.loads(bytes.fromhex(outer[2]))
        body[7][0][2] += 0.5
        body[7][0][3] += 0.5
        body_blob = compact(body)
        mac = hmac.new(
            KEY, b"NPBS1" + compact([1, outer[1], body_blob.hex()]),
            hashlib.sha256,
        ).digest().hex()
        forged = compact([1, outer[1], body_blob.hex(), mac])
        self.assertEqual(row_for(forged)[0], row_for(self.b1)[0])
        self.assertEqual(row_for(forged)[1], row_for(self.b1)[1])
        self.assertNotEqual(row_for(forged)[2], row_for(self.b1)[2])
        with self.assertRaises(ValueError):
            gate.resume(forged)
        self.assertEqual(gate.checkpoint, map_for(self.b1))

    def test_partitions_are_independent(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b2)
        # A different session is a different partition row: its lower seq
        # is not a rollback of the first partition.
        other1 = checkpoint_after(1, total=4)
        gate.resume(other1)
        self.assertEqual(gate.checkpoint, map_for(self.b2, other1))
        # The first partition still replays and cannot roll back.
        gate.resume(self.b2)
        with self.assertRaises(ValueError):
            gate.resume(self.b1)
        self.assertEqual(gate.checkpoint, map_for(self.b2, other1))

    def test_higher_seq_need_not_extend_after_a_replay(self):
        # The row binds only seq and SHA256(body); a higher seq from the
        # same partition advances since the recovery itself is valid.
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        gate.resume(self.b2)
        self.assertEqual(gate.checkpoint, map_for(self.b2))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        # A state whose checkpoint MAC does not match never reaches the gate.
        outer = json.loads(self.b2)
        tampered_mac = bytearray(bytes.fromhex(outer[3]))
        tampered_mac[0] ^= 1
        outer[3] = bytes(tampered_mac).hex()
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            gate.resume(tampered)
        # A state object carrying a bad MAC is rejected identically.
        bad_state = BitState.from_bytes(self.b2)
        bad_state = dataclasses.replace(
            bad_state, mac=bytes(b ^ 1 for b in bad_state.mac)
        )
        with self.assertRaises(ValueError):
            gate.resume(bad_state)
        # Malformed bytes and wrong-typed inner fields.
        for bad in (b"not json", b"[]", b"{}"):
            with self.assertRaises(ValueError, msg=bad):
                gate.resume(bad)
        outer = json.loads(self.b2)
        broken_body = json.loads(bytes.fromhex(outer[2]))
        broken_body[4] = "4"  # R wrong-typed -> BitState.from_bytes TypeError
        outer[2] = json.dumps(broken_body, separators=(",", ":")).encode().hex()
        with self.assertRaises(ValueError):
            gate.resume(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        self.assertEqual(gate.checkpoint, map_for(self.b1))

    def test_wrong_type_arguments_raise_type_error(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        for bad in (None, 42, "x", [], {}, object(), bytearray(self.b1)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                gate.resume(bad)

    def test_resumed_session_uses_gate_verifier(self):
        fast = Verifier(KEY, clock=SteppedClock(), speed_mps=123.0)
        session = fast.start_bits(CONTEXT, OPENING, rounds=2, timeout=0.01)
        clock = SteppedClock()
        drive(session, clock, 1)
        gate = BitGate(fast)
        restored = gate.resume(session.checkpoint())
        drive(restored, clock, 1)
        self.assertEqual(BitEvidence.from_bytes(restored.finish()).speed, 123.0)

    def test_checkpoint_restarts_at_the_table(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b2)
        saved = gate.checkpoint.to_bytes()
        restarted = BitGate(self.verifier, checkpoint=saved)
        # The old row still replays.
        restarted.resume(self.b2)
        self.assertEqual(restarted.checkpoint, map_for(self.b2))
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.resume(self.b1)

    def test_table_mac_uses_npbl1_with_verifier_key(self):
        gate = BitGate(self.verifier)
        gate.resume(self.b1)
        sid, seq, digest = row_for(self.b1)
        expected = BitMap(
            1,
            ((sid, seq, digest),),
            hmac.new(
                KEY,
                _BIT_MAP_PREFIX
                + _encode_payload([1, [[sid.hex(), seq, digest.hex()]]]),
                hashlib.sha256,
            ).digest(),
        )
        self.assertEqual(gate.checkpoint, expected)


class BitGateConcurrencyTest(unittest.TestCase):
    def test_concurrent_resumes_never_roll_back_or_lose_updates(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4, timeout=0.01)
        drive(session, clock, 1)
        b1 = session.checkpoint()
        drive(session, clock, 1)
        b2 = session.checkpoint()
        other = checkpoint_after(2, total=4)
        gate = BitGate(verifier)
        errors = []

        def worker(item):
            try:
                gate.resume(item)
            except ValueError:
                # A replay delivered after the advance reads as a lower-seq
                # rollback and is rejected.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [b1, BitState.from_bytes(b1), b2, other, b1, b2, other] * 8
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        # Both partitions reached their highest offered seq; no update lost.
        self.assertEqual(gate.checkpoint, map_for(b2, other))

    def test_advance_wins_against_rejected_rollback(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4, timeout=0.01)
        drive(session, clock, 1)
        b1 = session.checkpoint()
        drive(session, clock, 1)
        b2 = session.checkpoint()
        start = threading.Barrier(2)
        gate = BitGate(verifier)
        gate.resume(b1)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    gate.resume(b1)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            gate.resume(b2)
            outcomes.append("advanced")

        threads = [threading.Thread(target=rollback),
                   threading.Thread(target=advance)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(gate.checkpoint, map_for(b2))


if __name__ == "__main__":
    unittest.main()
