import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitFrontier,
    BitGuard,
    BitState,
    Prover,
    Verifier,
    _BIT_FRONTIER_PREFIX,
    _bit_frontier_mac,
    _bit_frontier_payload,
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


def frontier_for(blob, *, key=KEY, mac=None):
    state = BitState.from_bytes(blob)
    placeholder = BitFrontier(
        1, state.seq, hashlib.sha256(state.body).digest(), b"\x00" * 32
    )
    if mac is None:
        mac = _bit_frontier_mac(key, _bit_frontier_payload(placeholder))
    return BitFrontier(1, state.seq, hashlib.sha256(state.body).digest(), mac)


class BitFrontierContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        blob = checkpoint_after(1)
        first = frontier_for(blob)
        second = BitFrontier(
            1, first.seq, bytes(first.digest), bytes(first.mac)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        later = frontier_for(checkpoint_after(2))
        self.assertNotEqual(first, later)
        self.assertEqual(
            (first.version, first.seq, first.digest, first.mac),
            (1, 1, hashlib.sha256(BitState.from_bytes(blob).body).digest(),
             first.mac),
        )

    def test_is_frozen(self):
        frontier = frontier_for(checkpoint_after(0))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frontier.seq = 2

    def test_version_contract(self):
        digest = b"\x01" * 32
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier(bad, 1, digest, b"\x00" * 32)
        with self.assertRaises(ValueError):
            BitFrontier(2, 1, digest, b"\x00" * 32)

    def test_seq_is_non_bool_u64(self):
        digest = b"\x01" * 32
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier(1, bad, digest, b"\x00" * 32)
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(1, bad, digest, b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            BitFrontier(1, good, digest, b"\x00" * 32)

    def test_digest_and_mac_contract(self):
        for bad_digest in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad_digest)):
                BitFrontier(1, 1, bad_digest, b"\x00" * 32)
        for bad_mac in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad_mac)):
                BitFrontier(1, 1, b"\x00" * 32, bad_mac)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(1, 1, bad, b"\x00" * 32)
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(1, 1, b"\x00" * 32, bad)


class BitFrontierEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        frontier = frontier_for(checkpoint_after(7, total=8))
        obj = json.loads(frontier.to_bytes())
        self.assertEqual(list(obj), ["version", "seq", "digest", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["seq"], 7)
        self.assertEqual(obj["digest"], frontier.digest.hex())
        self.assertEqual(obj["mac"], frontier.mac.hex())
        self.assertNotIn(b" ", frontier.to_bytes())
        self.assertEqual(
            frontier.to_bytes(),
            json.dumps(
                {
                    "version": 1,
                    "seq": 7,
                    "digest": frontier.digest.hex(),
                    "mac": frontier.mac.hex(),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def test_round_trip(self):
        for seq in (0, 1, 2):
            frontier = frontier_for(checkpoint_after(seq, total=4))
            self.assertEqual(BitFrontier.from_bytes(frontier.to_bytes()), frontier)

    def test_round_trip_u64_extreme(self):
        frontier = BitFrontier(1, 2**64 - 1, b"\x0a" * 32, b"\x0b" * 32)
        self.assertEqual(BitFrontier.from_bytes(frontier.to_bytes()), frontier)

    def test_from_bytes_rejects_non_bytes(self):
        data = frontier_for(checkpoint_after(1)).to_bytes()
        for bad in (data.decode(), None, 42, [1], bytearray(data), {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(frontier_for(checkpoint_after(1)).to_bytes())
        blobs = [
            json.dumps({"seq": 1, "version": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": good["digest"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": good["digest"], "mac": good["mac"],
                        "extra": 1}, separators=(",", ":")).encode(),
            (
                b'{"version":1,"seq":1,"digest":'
                + json.dumps(good["digest"]).encode()
                + b',"mac":'
                + json.dumps(good["mac"]).encode()
                + b',"version":1}'
            ),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_rejects_wrong_field_types_with_type_error(self):
        good = json.loads(frontier_for(checkpoint_after(1)).to_bytes())
        blobs = [
            json.dumps({"version": "1", "seq": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1.0,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": 42, "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": good["digest"], "mac": None},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(TypeError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(frontier_for(checkpoint_after(1)).to_bytes())
        blobs = [
            json.dumps({"version": 2, "seq": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": -1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 2**64,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": "zz", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": good["digest"].upper(),
                        "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": "00", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "seq": 1,
                        "digest": good["digest"], "mac": "ab" * 31},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = frontier_for(checkpoint_after(1)).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json", b"", b"null"):
            with self.assertRaises(ValueError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        state_blob = checkpoint_after(1)
        frontier = frontier_for(state_blob, mac=b"\x00" * 32)
        decoded = BitFrontier.from_bytes(frontier.to_bytes())
        self.assertEqual(decoded, frontier)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class BitFrontierMacTest(unittest.TestCase):
    def test_digest_is_sha256_of_state_body(self):
        state = BitState.from_bytes(checkpoint_after(3, total=4))
        frontier = frontier_for(state.to_bytes())
        self.assertEqual(frontier.digest, hashlib.sha256(state.body).digest())

    def test_mac_formula_direct_concatenation(self):
        frontier = frontier_for(checkpoint_after(2, total=4))
        encoding = _encode_payload(_bit_frontier_payload(frontier))
        self.assertEqual(
            frontier.mac,
            hmac.new(KEY, _BIT_FRONTIER_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            KEY,
            _BIT_FRONTIER_PREFIX + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(frontier.mac, forged)
        self.assertNotEqual(
            frontier.mac,
            hmac.new(OTHER_KEY, _BIT_FRONTIER_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )


class BitGuardInitTest(unittest.TestCase):
    def test_verifier_must_be_a_verifier(self):
        for bad in (KEY, None, 42, object(), "verifier"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitGuard(bad)

    def test_checkpoint_is_keyword_only(self):
        verifier = make_verifier()
        frontier = frontier_for(checkpoint_after(1))
        with self.assertRaises(TypeError):
            BitGuard(verifier, frontier)
        self.assertIsNone(BitGuard(verifier).checkpoint)
        self.assertIs(BitGuard(verifier, checkpoint=None).checkpoint, None)

    def test_checkpoint_must_be_frontier_bytes_or_none(self):
        verifier = make_verifier()
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitGuard(verifier, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(), checkpoint=b"not json")

    def test_checkpoint_mac_verified(self):
        blob = checkpoint_after(1)
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(),
                     checkpoint=frontier_for(blob, mac=b"\x00" * 32))
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(),
                     checkpoint=frontier_for(blob, key=OTHER_KEY))
        # A verifier holding another key rejects a good frontier.
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(key=OTHER_KEY),
                     checkpoint=frontier_for(blob))
        # Object and canonical bytes forms both accepted when the MAC is good.
        frontier = frontier_for(blob)
        self.assertIs(
            BitGuard(make_verifier(), checkpoint=frontier).checkpoint,
            frontier,
        )
        restored = BitGuard(
            make_verifier(), checkpoint=frontier.to_bytes()
        ).checkpoint
        self.assertEqual(restored, frontier)

    def test_checkpoint_property_is_read_only(self):
        guard = BitGuard(make_verifier())
        with self.assertRaises(AttributeError):
            guard.checkpoint = frontier_for(checkpoint_after(1))


class BitGuardGatingTest(unittest.TestCase):
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

    def test_first_resume_establishes_frontier(self):
        guard = BitGuard(self.verifier)
        self.assertIsNone(guard.checkpoint)
        restored = guard.resume(self.b1)
        self.assertEqual(guard.checkpoint, frontier_for(self.b1))
        self.assertEqual(guard.checkpoint.seq, 1)
        self.assertEqual(
            guard.checkpoint.digest,
            hashlib.sha256(BitState.from_bytes(self.b1).body).digest(),
        )
        # The resumed session is active and can be driven to completion.
        drive(restored, self.clock, 3)
        self.assertGreater(audit_b(restored.finish(), KEY), 0.0)

    def test_first_resume_accepts_seq_zero(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b0)
        self.assertEqual(guard.checkpoint.seq, 0)
        self.assertEqual(guard.checkpoint, frontier_for(self.b0))

    def test_bytes_and_object_inputs_equivalent(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        guard_from_bytes = BitGuard(self.verifier)
        guard_from_bytes.resume(BitState.from_bytes(self.b1))
        self.assertEqual(guard.checkpoint, guard_from_bytes.checkpoint)

    def test_higher_seq_advances(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b0)
        guard.resume(self.b1)
        self.assertEqual(guard.checkpoint, frontier_for(self.b1))
        guard.resume(self.b2)
        self.assertEqual(guard.checkpoint, frontier_for(self.b2))

    def test_lower_seq_rejected_and_frontier_unchanged(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b2)
        with self.assertRaises(ValueError):
            guard.resume(self.b1)
        with self.assertRaises(ValueError):
            guard.resume(self.b0)
        self.assertEqual(guard.checkpoint, frontier_for(self.b2))

    def test_same_seq_same_digest_is_a_replay(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        for _ in range(3):
            guard.resume(self.b1)
            guard.resume(BitState.from_bytes(self.b1))
        self.assertEqual(guard.checkpoint, frontier_for(self.b1))

    def test_same_seq_different_digest_rejected(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        # A different session at seq 1 carries a different transcript t and
        # hence a different body digest.
        other = checkpoint_after(1, total=4)
        self.assertNotEqual(
            hashlib.sha256(BitState.from_bytes(self.b1).body).digest(),
            hashlib.sha256(BitState.from_bytes(other).body).digest(),
        )
        with self.assertRaises(ValueError):
            guard.resume(other)
        self.assertEqual(guard.checkpoint, frontier_for(self.b1))

    def test_higher_seq_need_not_extend_after_a_replay(self):
        # The frontier binds only seq and SHA256(body); a higher seq from a
        # different session advances since the recovery itself is valid.
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        other2 = checkpoint_after(2, total=4)
        guard.resume(other2)
        self.assertEqual(guard.checkpoint, frontier_for(other2))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        # A state whose checkpoint MAC does not match never reaches the gate.
        outer = json.loads(self.b2)
        tampered_mac = bytearray(bytes.fromhex(outer[3]))
        tampered_mac[0] ^= 1
        outer[3] = bytes(tampered_mac).hex()
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            guard.resume(tampered)
        # A state object carrying a bad MAC is rejected identically.
        bad_state = BitState.from_bytes(self.b2)
        bad_state = dataclasses.replace(
            bad_state, mac=bytes(b ^ 1 for b in bad_state.mac)
        )
        with self.assertRaises(ValueError):
            guard.resume(bad_state)
        # Malformed bytes and wrong-typed inner fields.
        for bad in (b"not json", b"[]", b"{}"):
            with self.assertRaises(ValueError, msg=bad):
                guard.resume(bad)
        outer = json.loads(self.b2)
        broken_body = json.loads(bytes.fromhex(outer[2]))
        broken_body[4] = "4"  # R wrong-typed -> BitState.from_bytes TypeError
        outer[2] = json.dumps(broken_body, separators=(",", ":")).encode().hex()
        with self.assertRaises(ValueError):
            guard.resume(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        self.assertEqual(guard.checkpoint, frontier_for(self.b1))

    def test_wrong_type_arguments_raise_type_error(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        for bad in (None, 42, "x", [], {}, object(), bytearray(self.b1)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                guard.resume(bad)

    def test_resumed_session_uses_guard_verifier(self):
        fast = Verifier(KEY, clock=SteppedClock(), speed_mps=123.0)
        session = fast.start_bits(CONTEXT, OPENING, rounds=2, timeout=0.01)
        clock = SteppedClock()
        drive(session, clock, 1)
        guard = BitGuard(fast)
        restored = guard.resume(session.checkpoint())
        drive(restored, clock, 1)
        from nearproof import BitEvidence

        self.assertEqual(BitEvidence.from_bytes(restored.finish()).speed, 123.0)

    def test_checkpoint_restarts_at_the_frontier(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b2)
        saved = guard.checkpoint.to_bytes()
        restarted = BitGuard(self.verifier, checkpoint=saved)
        # The old frontier still replays.
        restarted.resume(self.b2)
        self.assertEqual(restarted.checkpoint, frontier_for(self.b2))
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.resume(self.b1)
        # A same-seq different body is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.resume(checkpoint_after(2, total=4))

    def test_frontier_mac_uses_npbf1_with_verifier_key(self):
        guard = BitGuard(self.verifier)
        guard.resume(self.b1)
        state = BitState.from_bytes(self.b1)
        expected = BitFrontier(
            1,
            1,
            hashlib.sha256(state.body).digest(),
            hmac.new(
                KEY,
                _BIT_FRONTIER_PREFIX
                + _encode_payload(
                    {
                        "version": 1,
                        "seq": 1,
                        "digest": hashlib.sha256(state.body).digest().hex(),
                    }
                ),
                hashlib.sha256,
            ).digest(),
        )
        self.assertEqual(guard.checkpoint, expected)


class BitGuardConcurrencyTest(unittest.TestCase):
    def test_concurrent_resumes_never_roll_back(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4, timeout=0.01)
        drive(session, clock, 1)
        b1 = session.checkpoint()
        drive(session, clock, 1)
        b2 = session.checkpoint()
        guard = BitGuard(verifier)
        errors = []

        def worker(item):
            try:
                guard.resume(item)
            except ValueError:
                # A replay delivered after the advance reads as a lower-seq
                # rollback and is rejected.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [b1, BitState.from_bytes(b1), b2, b1, b2, b1] * 8
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(guard.checkpoint.seq, 2)
        self.assertEqual(guard.checkpoint, frontier_for(b2))

    def test_advance_wins_against_rejected_rollback(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4, timeout=0.01)
        drive(session, clock, 1)
        b1 = session.checkpoint()
        drive(session, clock, 1)
        b2 = session.checkpoint()
        start = threading.Barrier(2)
        guard = BitGuard(verifier)
        guard.resume(b1)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    guard.resume(b1)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            guard.resume(b2)
            outcomes.append("advanced")

        threads = [threading.Thread(target=rollback),
                   threading.Thread(target=advance)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(guard.checkpoint, frontier_for(b2))


if __name__ == "__main__":
    unittest.main()
