import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitFrontier,
    BitGuard,
    BitSession,
    BitState,
    Prover,
    Verifier,
    _BIT_FRONTIER_PREFIX,
    _bit_frontier_mac,
    _bit_frontier_payload,
    _encode_payload,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2
CONTEXT = bytes(range(32))
OPENING = bytes(range(1, 33))
SPEED = 299_792_458.0
PREFIX_FC = b"NPFC1"
PREFIX_BS = b"NPBS1"
DELAY = 0.00002


class SteppedClock:
    def __init__(self, start=1000.0, step=DELAY):
        self.now = start
        self.step = step

    def __call__(self):
        return self.now


def digest_of():
    return hashlib.sha256(PREFIX_FC + CONTEXT + OPENING).digest()


def make_verifier(clock=None, speed=SPEED):
    return Verifier(KEY, clock=clock or SteppedClock(), speed_mps=speed)


def drive(session, clock, n, delay=DELAY, key=KEY):
    """Successfully drive ``n`` rounds of a step-driven session."""
    prover = Prover(key)
    for _ in range(n):
        round_ = session.next()
        clock.now += delay
        session.submit(
            round_, prover.bit(round_.t, digest_of(), round_.index, round_.bit)
        )


def checkpoint_blob(seq, *, rounds=4, pending=False, clock=None):
    """A canonical BitState checkpoint carrying ``seq`` completed queries."""
    clock = clock or SteppedClock()
    session = make_verifier(clock).start_bits(
        CONTEXT, OPENING, rounds=rounds, timeout=0.001
    )
    drive(session, clock, seq)
    if pending:
        session.next()
    return session.checkpoint()

def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


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


def frontier_mac(key, frontier):
    return _bit_frontier_mac(key, _bit_frontier_payload(frontier))


def make_frontier(seq, body, *, key=KEY, mac=None):
    if mac is None:
        placeholder = BitFrontier(1, seq, hashlib.sha256(body).digest(),
                                  b"\x00" * 32)
        mac = frontier_mac(key, placeholder)
    return BitFrontier(1, seq, hashlib.sha256(body).digest(), mac)


class BitFrontierContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        digest = b"\xaa" * 32
        mac = b"\x01" * 32
        first = BitFrontier(1, 7, digest, mac)
        second = BitFrontier(1, 7, digest, mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertNotEqual(first, BitFrontier(1, 8, digest, mac))
        self.assertNotEqual(first, BitFrontier(1, 7, b"\xbb" * 32, mac))
        self.assertEqual(
            (first.version, first.seq, first.digest, first.mac),
            (1, 7, digest, mac),
        )

    def test_is_frozen(self):
        frontier = BitFrontier(1, 0, b"\xaa" * 32, b"\x00" * 32)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frontier.seq = 1

    def test_version_contract(self):
        digest = b"\xaa" * 32
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier(bad, 0, digest, b"\x00" * 32)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(bad, 0, digest, b"\x00" * 32)

    def test_seq_is_non_bool_u64(self):
        digest = b"\xaa" * 32
        for bad in (True, False, 1.0, "0", None, 1j):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier(1, bad, digest, b"\x00" * 32)
        for bad in (-1, 2**64, 2**64 + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(1, bad, digest, b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            BitFrontier(1, good, digest, b"\x00" * 32)

    def test_digest_contract(self):
        for bad in ("ab" * 32, bytearray(32), None, 42, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier(1, 0, bad, b"\x00" * 32)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(1, 0, bad, b"\x00" * 32)

    def test_mac_contract(self):
        digest = b"\xaa" * 32
        for bad in ("ab" * 32, bytearray(32), None, 42, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier(1, 0, digest, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitFrontier(1, 0, digest, bad)


class BitFrontierEncodingTest(unittest.TestCase):
    def _frontier(self, seq=7, digest=None):
        return BitFrontier(
            1, seq, digest or hashlib.sha256(b"body").digest(), b"\x7f" * 32
        )

    def test_to_bytes_shape(self):
        frontier = self._frontier()
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
        for seq in (0, 1, 2**64 - 1):
            frontier = self._frontier(seq=seq)
            self.assertEqual(BitFrontier.from_bytes(frontier.to_bytes()), frontier)
            self.assertEqual(
                BitFrontier.from_bytes(frontier.to_bytes()).to_bytes(),
                frontier.to_bytes(),
            )

    def test_from_bytes_rejects_non_bytes(self):
        blob = self._frontier().to_bytes()
        for bad in (blob.decode(), bytearray(blob), None, 42, [], {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(self._frontier().to_bytes())
        blobs = [
            # Out of order.
            json.dumps(
                {
                    "seq": good["seq"],
                    "version": 1,
                    "digest": good["digest"],
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            # Missing mac.
            json.dumps(
                {
                    "version": 1,
                    "seq": good["seq"],
                    "digest": good["digest"],
                },
                separators=(",", ":"),
            ).encode(),
            # Extra key.
            json.dumps(
                {
                    "version": 1,
                    "seq": good["seq"],
                    "digest": good["digest"],
                    "mac": good["mac"],
                    "extra": 1,
                },
                separators=(",", ":"),
            ).encode(),
            # A genuinely duplicated key cannot come from a Python dict.
            (
                b'{"version":1,"seq":7,"digest":'
                + json.dumps(good["digest"]).encode()
                + b',"mac":'
                + json.dumps(good["mac"]).encode()
                + b',"version":1}'
            ),
            b"{}",
            b"[]",
            b"null",
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_rejects_wrong_field_types(self):
        good = json.loads(self._frontier().to_bytes())

        def blob_with(**over):
            obj = {
                "version": 1,
                "seq": good["seq"],
                "digest": good["digest"],
                "mac": good["mac"],
            }
            obj.update(over)
            return compact(obj)

        for bad_version in ("1", 1.0, True):
            with self.assertRaises(TypeError, msg=repr(bad_version)):
                BitFrontier.from_bytes(blob_with(version=bad_version))
        for bad_seq in (True, False, 1.0, "7", None):
            with self.assertRaises(TypeError, msg=repr(bad_seq)):
                BitFrontier.from_bytes(blob_with(seq=bad_seq))
        for bad in (42, None, True, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier.from_bytes(blob_with(digest=bad))
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitFrontier.from_bytes(blob_with(mac=bad))

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(self._frontier().to_bytes())

        def blob_with(**over):
            obj = {
                "version": 1,
                "seq": good["seq"],
                "digest": good["digest"],
                "mac": good["mac"],
            }
            obj.update(over)
            return compact(obj)

        for blob in (
            blob_with(version=2),
            blob_with(seq=-1),
            blob_with(seq=2**64),
            blob_with(digest="zz"),
            blob_with(digest=good["digest"].upper()),
            blob_with(digest="ab" * 31),
            blob_with(mac="ab" * 31),
            blob_with(mac="ab" * 33),
        ):
            with self.assertRaises(ValueError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = self._frontier().to_bytes()
        for blob in (
            data + b" ",
            data.replace(b",", b", ", 1),
            json.dumps(json.loads(data), indent=2).encode(),
            b"not json",
            b"",
        ):
            with self.assertRaises(ValueError, msg=blob):
                BitFrontier.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        frontier = BitFrontier(1, 7, self._frontier().digest, b"\x00" * 32)
        decoded = BitFrontier.from_bytes(frontier.to_bytes())
        self.assertEqual(decoded, frontier)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class BitFrontierMacTest(unittest.TestCase):
    def test_digest_is_sha256_of_state_body(self):
        blob = checkpoint_blob(3)
        state = BitState.from_bytes(blob)
        frontier = make_frontier(3, state.body)
        self.assertEqual(frontier.digest, hashlib.sha256(state.body).digest())

    def test_mac_formula_direct_concatenation(self):
        frontier = make_frontier(5, b"a body")
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
        for bad in (None, object(), "x", 42, b"key", Prover(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitGuard(bad)
        self.assertIsNone(BitGuard(make_verifier()).checkpoint)

    def test_checkpoint_is_keyword_only(self):
        verifier = make_verifier()
        blob = checkpoint_blob(1)
        state = BitState.from_bytes(blob)
        frontier = make_frontier(1, state.body)
        with self.assertRaises(TypeError):
            BitGuard(verifier, frontier)
        self.assertIsNone(BitGuard(verifier, checkpoint=None).checkpoint)

    def test_checkpoint_must_be_frontier_bytes_or_none(self):
        guard = BitGuard(make_verifier())
        for bad in ("x", 1, [], {}, object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitGuard(guard._verifier, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        verifier = make_verifier()
        for bad in (b"not json", b"{}", b"[1]", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                BitGuard(verifier, checkpoint=bad)

    def test_checkpoint_bytes_with_inner_type_error_is_value_error(self):
        # The argument kind (bytes) is right; a wrong-typed field inside its
        # content is a value error, not a type error — as with resume_bits.
        state = BitState.from_bytes(checkpoint_blob(1))
        frontier = make_frontier(1, state.body)
        obj = json.loads(frontier.to_bytes())
        obj["seq"] = True
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(), checkpoint=compact(obj))

    def test_checkpoint_mac_verified_constant_time(self):
        blob = checkpoint_blob(1)
        state = BitState.from_bytes(blob)
        # A bogus MAC and a frontier MAC'd with another key are both rejected.
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(), checkpoint=make_frontier(
                1, state.body, mac=b"\x00" * 32))
        with self.assertRaises(ValueError):
            BitGuard(make_verifier(), checkpoint=make_frontier(
                1, state.body, key=OTHER_KEY))
        # Object and canonical bytes forms both authenticate.
        frontier = make_frontier(1, state.body)
        verifier = make_verifier()
        self.assertIs(
            BitGuard(verifier, checkpoint=frontier).checkpoint, frontier
        )
        restored = BitGuard(
            verifier, checkpoint=frontier.to_bytes()
        ).checkpoint
        self.assertEqual(restored, frontier)

    def test_checkpoint_property_is_read_only(self):
        guard = BitGuard(make_verifier())
        with self.assertRaises(AttributeError):
            guard.checkpoint = None


class BitGuardResumeTest(unittest.TestCase):
    def setUp(self):
        self.clock = SteppedClock()
        self.verifier = make_verifier(self.clock)
        self.guard = BitGuard(self.verifier)

    def test_first_resume_establishes_frontier(self):
        blob = checkpoint_blob(2, clock=self.clock)
        state = BitState.from_bytes(blob)
        session = self.guard.resume(blob)
        self.assertIsInstance(session, BitSession)
        frontier = self.guard.checkpoint
        self.assertEqual(frontier, BitFrontier(
            1, 2, hashlib.sha256(state.body).digest(), frontier.mac
        ))
        self.assertEqual(frontier.seq, 2)
        self.assertEqual(
            frontier.mac, frontier_mac(KEY, BitFrontier(
                1, 2, frontier.digest, b"\x00" * 32))
        )
        # A BitState object input establishes the identical frontier.
        guard = BitGuard(make_verifier())
        guard.resume(state)
        self.assertEqual(guard.checkpoint, frontier)

    def test_frontier_tracks_pending_checkpoints_by_completed_count(self):
        blob = checkpoint_blob(2, pending=True, clock=self.clock)
        state = BitState.from_bytes(blob)
        self.assertEqual(state.seq, 2)
        self.guard.resume(blob)
        self.assertEqual(self.guard.checkpoint.seq, 2)
        self.assertEqual(
            self.guard.checkpoint.digest, hashlib.sha256(state.body).digest()
        )

    def test_restored_session_is_active_and_finishable(self):
        blob = checkpoint_blob(3, rounds=3, clock=self.clock)
        session = self.guard.resume(blob)
        evidence = session.finish()
        self.assertEqual(json.loads(evidence)[0], 1)

    def test_equal_seq_identical_body_is_a_replay(self):
        blob = checkpoint_blob(2, clock=self.clock)
        first = self.guard.resume(blob)
        first.checkpoint()
        for _ in range(3):
            restored = self.guard.resume(blob)
            self.assertIsInstance(restored, BitSession)
        self.assertEqual(self.guard.checkpoint.seq, 2)
        # The bytes and the BitState object are interchangeable replays.
        self.guard.resume(BitState.from_bytes(blob))
        self.assertEqual(self.guard.checkpoint.seq, 2)

    def test_equal_seq_different_body_rejected(self):
        blob = checkpoint_blob(2, clock=self.clock)
        self.guard.resume(blob)
        # Same seq, a genuinely different body re-MAC'd with the real key:
        # recovery succeeds but the frontier gate must reject it.
        forged = resign(blob, lambda body: body.__setitem__(6, body[6] + 1.0))
        with self.assertRaises(ValueError):
            self.guard.resume(forged)
        self.assertEqual(self.guard.checkpoint.seq, 2)
        self.assertEqual(
            self.guard.checkpoint.digest,
            hashlib.sha256(BitState.from_bytes(blob).body).digest(),
        )

    def test_lower_seq_rejected_and_frontier_unchanged(self):
        low = checkpoint_blob(1, clock=self.clock)
        high = checkpoint_blob(3, clock=self.clock)
        self.guard.resume(high)
        with self.assertRaises(ValueError):
            self.guard.resume(low)
        self.assertEqual(self.guard.checkpoint.seq, 3)

    def test_higher_seq_advances(self):
        first = checkpoint_blob(1, clock=self.clock)
        session = self.guard.resume(first)
        self.assertEqual(self.guard.checkpoint.seq, 1)
        # Make progress on the restored session and checkpoint again.
        drive(session, self.clock, 2)
        second = session.checkpoint()
        self.guard.resume(second)
        frontier = self.guard.checkpoint
        self.assertEqual(frontier.seq, 3)
        self.assertEqual(
            frontier.digest, hashlib.sha256(BitState.from_bytes(second).body).digest()
        )
        self.assertEqual(frontier.mac, frontier_mac(KEY, BitFrontier(
            1, 3, frontier.digest, b"\x00" * 32)))

    def test_cryptographic_failure_leaves_frontier_unchanged(self):
        blob = checkpoint_blob(2, clock=self.clock)
        self.guard.resume(blob)
        # A checkpoint re-MAC'd with another key fails verification, so the
        # gate is never reached.
        wrong_key = resign(checkpoint_blob(1), lambda body: None, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            self.guard.resume(wrong_key)
        # Tampered bytes.
        broken = bytearray(blob)
        broken[len(broken) // 2] ^= 0xFF
        with self.assertRaises(ValueError):
            self.guard.resume(bytes(broken))
        # Malformed right-kind argument.
        for bad in (b"not json", b"{}", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                self.guard.resume(bad)
        self.assertEqual(self.guard.checkpoint.seq, 2)

    def test_wrong_argument_type_raises_type_error(self):
        blob = checkpoint_blob(1, clock=self.clock)
        self.guard.resume(blob)
        # Wrong kinds are TypeErrors...
        for bad in (None, 42, "x", [], {}, bytearray(blob),
                    self.guard.checkpoint):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.guard.resume(bad)
        # ...bytes that are simply not a BitState encoding stay a ValueError.
        with self.assertRaises(ValueError):
            self.guard.resume(self.guard.checkpoint.to_bytes())


class BitGuardRestartTest(unittest.TestCase):
    def test_restarts_at_the_frontier_from_bytes_and_object(self):
        clock = SteppedClock()
        guard = BitGuard(make_verifier(clock))
        blob = checkpoint_blob(2, clock=clock)
        guard.resume(blob)
        saved = guard.checkpoint.to_bytes()
        for restarted in (
            BitGuard(make_verifier(clock), checkpoint=saved),
            BitGuard(make_verifier(clock), checkpoint=guard.checkpoint),
        ):
            # The old frontier still replays.
            restarted.resume(blob)
            self.assertEqual(restarted.checkpoint.seq, 2)
            # Rollback across a restart is refused.
            with self.assertRaises(ValueError):
                restarted.resume(checkpoint_blob(1, clock=SteppedClock()))
            # Progress past the restored frontier still advances.
            session = restarted.resume(blob)
            drive(session, clock, 2)
            restarted.resume(session.checkpoint())
            self.assertEqual(restarted.checkpoint.seq, 4)


class BitGuardConcurrencyTest(unittest.TestCase):
    def test_concurrent_resumes_never_roll_back(self):
        clock = SteppedClock()
        guard = BitGuard(make_verifier(clock))
        blobs = [checkpoint_blob(seq, clock=clock) for seq in (1, 2, 3)]
        errors = []

        def worker(item):
            try:
                guard.resume(item)
            except ValueError:
                # A lower-seq resume after the frontier advanced rejects.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = (blobs * 4 + [blobs[0]] * 8 + [blobs[1]] * 4)
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(guard.checkpoint.seq, 3)
        self.assertEqual(
            guard.checkpoint.digest,
            hashlib.sha256(BitState.from_bytes(blobs[2]).body).digest(),
        )

    def test_advance_wins_against_rejected_rollback(self):
        clock = SteppedClock()
        guard = BitGuard(make_verifier(clock))
        low = checkpoint_blob(1, clock=clock)
        high = checkpoint_blob(2, clock=clock)
        guard.resume(low)
        start = threading.Barrier(2)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    guard.resume(low)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            guard.resume(high)
            outcomes.append("advanced")

        threads = [
            threading.Thread(target=rollback),
            threading.Thread(target=advance),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(guard.checkpoint.seq, 2)


if __name__ == "__main__":
    unittest.main()
