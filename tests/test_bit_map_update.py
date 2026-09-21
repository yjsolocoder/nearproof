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
    BitMapUpdate,
    BitState,
    Prover,
    Verifier,
    _BIT_MAP_PREFIX,
    _BIT_MAP_UPDATE_PREFIX,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _bit_state_mac,
    _bit_state_sid,
    _encode_payload,
    audit_map_history,
    audit_map_update,
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
HASH_3 = b"\x03" * 32
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


def map_for_entries(entries, key=KEY, mac=None):
    """A BitMap over ``entries`` MAC'd with ``key`` (or ``mac`` as given)."""
    ordered = tuple(sorted(entries))
    placeholder = BitMap(1, ordered, ZERO)
    if mac is None:
        mac = _bit_map_mac(key, _bit_map_payload(ordered))
    return BitMap(1, ordered, mac)


def map_bytes_for(entries, key=KEY):
    return map_for_entries(entries, key=key).to_bytes()


def update_for(before, after, key=KEY, mac=None):
    """A BitMapUpdate over the raw table encodings, MAC'd with ``key``."""
    placeholder = BitMapUpdate(1, before, after, ZERO)
    if mac is None:
        mac = _bit_map_update_mac(
            key, _bit_map_update_payload(placeholder)
        )
    return BitMapUpdate(1, before, after, mac)


EMPTY_MAP = map_bytes_for(())
ONE_MAP = map_bytes_for(((SID_A, 1, HASH_1),))
TWO_MAP = map_bytes_for(((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)))


class BitMapUpdateContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        first = BitMapUpdate(1, b"", ONE_MAP, ZERO)
        second = BitMapUpdate(1, bytes(b""), bytes(ONE_MAP), bytes(ZERO))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.before, first.after, first.mac),
            (1, b"", ONE_MAP, ZERO),
        )
        self.assertNotEqual(first, BitMapUpdate(1, b"", ONE_MAP, HASH_1))
        self.assertNotEqual(first, BitMapUpdate(1, b"", TWO_MAP, ZERO))
        self.assertNotEqual(first, BitMapUpdate(1, ONE_MAP, ONE_MAP, ZERO))

    def test_is_frozen(self):
        update = BitMapUpdate(1, b"", ONE_MAP, ZERO)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            update.mac = b"\x01" * 32

    def test_version_contract(self):
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(bad, b"", ONE_MAP, ZERO)
        with self.assertRaises(ValueError):
            BitMapUpdate(2, b"", ONE_MAP, ZERO)

    def test_before_contract(self):
        for bad in ("x", None, 42, bytearray(ONE_MAP), [1]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(1, bad, ONE_MAP, ZERO)
        for bad in (b"not json", b"{}", ONE_MAP + b" ", ONE_MAP[:-1],
                    json.dumps([1, [], ZERO.hex()]).encode()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapUpdate(1, bad, ONE_MAP, ZERO)
        # b"" (no table yet) and any canonical BitMap encoding are fine.
        BitMapUpdate(1, b"", ONE_MAP, ZERO)
        BitMapUpdate(1, EMPTY_MAP, ONE_MAP, ZERO)
        BitMapUpdate(1, ONE_MAP, TWO_MAP, ZERO)

    def test_before_rejects_table_with_unsorted_entries(self):
        raw = json.dumps(
            [1, [[SID_B.hex(), 1, HASH_1.hex()],
                 [SID_A.hex(), 2, HASH_2.hex()]], ZERO.hex()],
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            BitMapUpdate(1, raw, ONE_MAP, ZERO)

    def test_after_contract(self):
        for bad in ("x", None, 42, bytearray(ONE_MAP)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(1, b"", bad, ZERO)
        # after must always be a canonical BitMap encoding, never b"".
        for bad in (b"", b"not json", ONE_MAP + b"\n"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapUpdate(1, b"", bad, ZERO)

    def test_mac_contract(self):
        for bad in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(1, b"", ONE_MAP, bad)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapUpdate(1, b"", ONE_MAP, bad)


class BitMapUpdateEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        update = BitMapUpdate(1, b"", ONE_MAP, ZERO)
        obj = json.loads(update.to_bytes())
        self.assertEqual(obj, [1, "", ONE_MAP.hex(), ZERO.hex()])
        self.assertNotIn(b" ", update.to_bytes())
        self.assertEqual(
            update.to_bytes(),
            json.dumps(obj, separators=(",", ":")).encode("utf-8"),
        )

    def test_round_trip(self):
        for before, after in (
            (b"", EMPTY_MAP),
            (b"", ONE_MAP),
            (EMPTY_MAP, EMPTY_MAP),
            (ONE_MAP, ONE_MAP),
            (ONE_MAP, TWO_MAP),
        ):
            update = BitMapUpdate(1, before, after, b"\x0f" * 32)
            self.assertEqual(
                BitMapUpdate.from_bytes(update.to_bytes()), update
            )

    def test_from_bytes_rejects_non_bytes(self):
        data = BitMapUpdate(1, b"", EMPTY_MAP, ZERO).to_bytes()
        for bad in (data.decode(), None, 42, [1], bytearray(data), {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate.from_bytes(bad)

    def test_from_bytes_rejects_outer_shape(self):
        good = json.loads(BitMapUpdate(1, b"", ONE_MAP, ZERO).to_bytes())
        blobs = [
            json.dumps(good[:3], separators=(",", ":")).encode(),
            json.dumps(good + [0], separators=(",", ":")).encode(),
            json.dumps({"version": 1}, separators=(",", ":")).encode(),
            json.dumps(good, separators=(",", ":")).encode()
            .replace(b"[1,", b"[2,"),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_from_bytes_rejects_wrong_field_types_with_type_error(self):
        good = [1, "", ONE_MAP.hex(), ZERO.hex()]
        blobs = [
            json.dumps(["1", "", ONE_MAP.hex(), ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, 42, ONE_MAP.hex(), ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", None, ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", ONE_MAP.hex(), ["x"]],
                       separators=(",", ":")).encode(),
            json.dumps([1, True, ONE_MAP.hex(), ZERO.hex()],
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(TypeError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        blobs = [
            json.dumps([2, "", ONE_MAP.hex(), ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, "zz", ONE_MAP.hex(), ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, ONE_MAP.hex().upper(), ONE_MAP.hex(), ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", "", ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", "ab" * 31, ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", ONE_MAP.hex(), "ab" * 31],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", ONE_MAP.hex(), (b"\x0f" * 32).hex().upper()],
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = BitMapUpdate(1, b"", ONE_MAP, ZERO).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}",
                     b"not json", b"", b"null"):
            with self.assertRaises(ValueError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        update = BitMapUpdate(1, b"", ONE_MAP, ZERO)
        decoded = BitMapUpdate.from_bytes(update.to_bytes())
        self.assertEqual(decoded, update)
        self.assertEqual(decoded.mac, ZERO)


class BitMapUpdateMacTest(unittest.TestCase):
    def test_mac_formula_direct_concatenation(self):
        update = update_for(b"", ONE_MAP)
        encoding = _encode_payload([1, "", ONE_MAP.hex()])
        self.assertEqual(
            update.mac,
            hmac.new(KEY, _BIT_MAP_UPDATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            KEY,
            _BIT_MAP_UPDATE_PREFIX + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(update.mac, forged)
        self.assertNotEqual(
            update.mac,
            hmac.new(OTHER_KEY, _BIT_MAP_UPDATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        # Distinct domain from the table MAC.
        self.assertNotEqual(
            update.mac,
            hmac.new(KEY, _BIT_MAP_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )


class AuditMapUpdateTest(unittest.TestCase):
    def test_accepts_object_and_bytes_returns_none(self):
        update = update_for(b"", ONE_MAP)
        self.assertIsNone(audit_map_update(update, KEY))
        self.assertIsNone(audit_map_update(update.to_bytes(), KEY))

    def test_wrong_argument_types_raise_type_error(self):
        update = update_for(b"", ONE_MAP)
        for bad in ("x", 1, None, [], {}, object(), bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_update(bad, KEY)
        for bad in ("x", 1, None, [], {}, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_update(update, bad)

    def test_malformed_bytes_and_empty_key_raise_value_error(self):
        with self.assertRaises(ValueError):
            audit_map_update(b"not json", KEY)
        with self.assertRaises(ValueError):
            audit_map_update(update_for(b"", ONE_MAP).to_bytes(), b"")

    def test_update_mac_verified(self):
        update = update_for(b"", ONE_MAP)
        self.assertIsNone(audit_map_update(update, KEY))
        with self.assertRaises(ValueError):
            audit_map_update(update, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_map_update(
                BitMapUpdate(1, update.before, update.after, ZERO), KEY
            )
        # A proof over different content re-signed with the wrong key.
        with self.assertRaises(ValueError):
            audit_map_update(update_for(b"", ONE_MAP, key=OTHER_KEY), KEY)

    def test_carried_table_macs_verified(self):
        # before table re-signed under another key, update re-signed.
        bad_before = map_for_entries(
            ((SID_A, 1, HASH_1),), key=OTHER_KEY
        ).to_bytes()
        update = update_for(bad_before, TWO_MAP)
        with self.assertRaises(ValueError):
            audit_map_update(update, KEY)
        # after table re-signed under another key, update re-signed.
        bad_after = map_for_entries(
            ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)), key=OTHER_KEY
        ).to_bytes()
        update = update_for(ONE_MAP, bad_after)
        with self.assertRaises(ValueError):
            audit_map_update(update, KEY)

    def test_same_table_accepted(self):
        for before in (EMPTY_MAP, ONE_MAP, TWO_MAP):
            self.assertIsNone(
                audit_map_update(update_for(before, before), KEY)
            )

    def test_add_one_entry_accepted(self):
        self.assertIsNone(audit_map_update(update_for(b"", ONE_MAP), KEY))
        self.assertIsNone(
            audit_map_update(update_for(EMPTY_MAP, ONE_MAP), KEY)
        )
        self.assertIsNone(audit_map_update(update_for(ONE_MAP, TWO_MAP), KEY))
        # Insertion in the middle keeps every other entry unchanged.
        middle = map_bytes_for(((SID_A, 1, HASH_1), (SID_C, 3, HASH_3)))
        full = map_bytes_for(
            ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2), (SID_C, 3, HASH_3))
        )
        self.assertIsNone(audit_map_update(update_for(middle, full), KEY))

    def test_advance_one_entry_accepted(self):
        after = map_bytes_for(((SID_A, 2, HASH_2),))
        self.assertIsNone(audit_map_update(update_for(ONE_MAP, after), KEY))
        before = TWO_MAP
        after = map_bytes_for(((SID_A, 1, HASH_1), (SID_B, 5, HASH_3)))
        self.assertIsNone(audit_map_update(update_for(before, after), KEY))

    def test_advance_requires_same_sid_higher_seq_and_new_hash(self):
        # seq up but hash unchanged.
        after = map_bytes_for(((SID_A, 2, HASH_1),))
        with self.assertRaises(ValueError):
            audit_map_update(update_for(ONE_MAP, after), KEY)
        # hash changed but seq unchanged.
        after = map_bytes_for(((SID_A, 1, HASH_2),))
        with self.assertRaises(ValueError):
            audit_map_update(update_for(ONE_MAP, after), KEY)
        # seq down.
        before = map_bytes_for(((SID_A, 2, HASH_2),))
        after = map_bytes_for(((SID_A, 1, HASH_1),))
        with self.assertRaises(ValueError):
            audit_map_update(update_for(before, after), KEY)
        # sid swapped for a different session.
        after = map_bytes_for(((SID_B, 2, HASH_2),))
        with self.assertRaises(ValueError):
            audit_map_update(update_for(ONE_MAP, after), KEY)

    def test_other_transitions_rejected(self):
        # An entry removed.
        with self.assertRaises(ValueError):
            audit_map_update(update_for(TWO_MAP, ONE_MAP), KEY)
        with self.assertRaises(ValueError):
            audit_map_update(update_for(ONE_MAP, EMPTY_MAP), KEY)
        # Two entries added at once.
        full = map_bytes_for(
            ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2), (SID_C, 3, HASH_3))
        )
        with self.assertRaises(ValueError):
            audit_map_update(update_for(ONE_MAP, full), KEY)
        # One added but another entry touched.
        after = map_bytes_for(((SID_A, 9, HASH_1), (SID_B, 2, HASH_2)))
        with self.assertRaises(ValueError):
            audit_map_update(update_for(ONE_MAP, after), KEY)
        # Two entries advanced at once.
        after = map_bytes_for(((SID_A, 2, HASH_2), (SID_B, 3, HASH_3)))
        with self.assertRaises(ValueError):
            audit_map_update(update_for(TWO_MAP, after), KEY)
        # An empty after table is not even a valid proof field; the empty
        # before table may only grow.
        with self.assertRaises(ValueError):
            audit_map_update(
                update_for(ONE_MAP, EMPTY_MAP).to_bytes(), KEY
            )

    def test_no_before_table_requires_exactly_one_entry(self):
        # The initial transition creates the first partition: exactly one
        # entry in the after table.
        self.assertIsNone(audit_map_update(update_for(b"", ONE_MAP), KEY))
        # An empty initial table is not a valid start, even though the
        # no-op shape would otherwise read as an accepted replay.
        with self.assertRaises(ValueError):
            audit_map_update(update_for(b"", EMPTY_MAP), KEY)
        # Two partitions cannot be created by a single initial transition.
        with self.assertRaises(ValueError):
            audit_map_update(update_for(b"", TWO_MAP), KEY)
        # The boundary is b"" (no table yet), not the empty-table encoding:
        # a replay of the empty table stays a valid no-op.
        self.assertIsNone(
            audit_map_update(update_for(EMPTY_MAP, EMPTY_MAP), KEY)
        )


class AuditMapHistoryTest(unittest.TestCase):
    def chain(self):
        """A valid three-transition history: create, insert, advance."""
        first = update_for(b"", ONE_MAP)
        second = update_for(ONE_MAP, TWO_MAP)
        advanced = map_bytes_for(((SID_A, 1, HASH_1), (SID_B, 5, HASH_3)))
        third = update_for(TWO_MAP, advanced)
        return [first, second, third], BitMap.from_bytes(advanced)

    def test_valid_chain_returns_final_table(self):
        updates, final = self.chain()
        result = audit_map_history(updates, KEY)
        self.assertIsInstance(result, BitMap)
        self.assertEqual(result, final)
        self.assertEqual(result.to_bytes(), updates[-1].after)

    def test_items_may_mix_objects_and_bytes(self):
        updates, final = self.chain()
        mixed = [updates[0].to_bytes(), updates[1], updates[2].to_bytes()]
        self.assertEqual(audit_map_history(mixed, KEY), final)
        # Any iterable works, not just a list.
        self.assertEqual(audit_map_history(iter(mixed), KEY), final)

    def test_single_update_chain(self):
        result = audit_map_history([update_for(b"", ONE_MAP)], KEY)
        self.assertEqual(result, BitMap.from_bytes(ONE_MAP))

    def test_replay_links_are_accepted(self):
        updates, _ = self.chain()
        replayed = update_for(ONE_MAP, ONE_MAP)
        result = audit_map_history([updates[0], replayed, updates[1]], KEY)
        self.assertEqual(result, BitMap.from_bytes(TWO_MAP))

    def test_checkpoint_object_and_bytes_start_the_chain(self):
        updates, final = self.chain()
        tail = updates[1:]
        checkpoint = BitMap.from_bytes(ONE_MAP)
        self.assertEqual(
            audit_map_history(tail, KEY, checkpoint=checkpoint), final
        )
        self.assertEqual(
            audit_map_history(tail, KEY, checkpoint=ONE_MAP), final
        )

    def test_checkpoint_mac_verified(self):
        updates, _ = self.chain()
        with self.assertRaises(ValueError):
            audit_map_history(
                updates[1:], KEY,
                checkpoint=map_for_entries(
                    ((SID_A, 1, HASH_1),), key=OTHER_KEY
                ),
            )
        with self.assertRaises(ValueError):
            audit_map_history(updates, KEY, checkpoint=ONE_MAP)

    def test_wrong_types_raise_type_error(self):
        updates, _ = self.chain()
        for bad in ("x", 1, None, object(), updates[0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history(bad, KEY)
        for bad in ("x", 1, None, [], {}, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history(updates, bad)
        for bad in ("x", 1, [], {}, bytearray(ONE_MAP)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history(updates, KEY, checkpoint=bad)
        for bad_item in ("x", 1, None, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad_item)):
                audit_map_history([updates[0], bad_item], KEY)

    def test_empty_sequence_and_empty_key_raise_value_error(self):
        updates, _ = self.chain()
        with self.assertRaises(ValueError):
            audit_map_history([], KEY)
        with self.assertRaises(ValueError):
            audit_map_history(updates, b"")

    def test_malformed_bytes_raise_value_error(self):
        updates, _ = self.chain()
        with self.assertRaises(ValueError):
            audit_map_history([updates[0], b"not json"], KEY)
        with self.assertRaises(ValueError):
            audit_map_history(updates[1:], KEY, checkpoint=b"not json")
        # A well-formed update signed under the wrong key.
        with self.assertRaises(ValueError):
            audit_map_history(
                [update_for(b"", ONE_MAP, key=OTHER_KEY)], KEY
            )

    def test_broken_or_reordered_chain_rejected(self):
        updates, _ = self.chain()
        # A gap: the second update does not chain from the first after.
        with self.assertRaises(ValueError):
            audit_map_history([updates[0], updates[2]], KEY)
        # Reordered links.
        with self.assertRaises(ValueError):
            audit_map_history([updates[1], updates[0]], KEY)
        with self.assertRaises(ValueError):
            audit_map_history(list(reversed(updates)), KEY)
        # The first update must start from no table without a checkpoint.
        with self.assertRaises(ValueError):
            audit_map_history(updates[1:], KEY)
        # A first update not chaining from the checkpoint.
        with self.assertRaises(ValueError):
            audit_map_history(
                updates[1:], KEY, checkpoint=BitMap.from_bytes(TWO_MAP)
            )

    def test_failed_link_audit_rejects_the_whole_history(self):
        updates, _ = self.chain()
        # The last link is individually invalid (seq down), so the whole
        # history is rejected even though the earlier links are fine.
        stale = update_for(TWO_MAP, ONE_MAP)
        with self.assertRaises(ValueError):
            audit_map_history(updates[:2] + [stale], KEY)
        # The initial-boundary rule applies inside a history too.
        with self.assertRaises(ValueError):
            audit_map_history([update_for(b"", EMPTY_MAP)], KEY)


class BitGateResumeTxTest(unittest.TestCase):
    def test_first_resume_tx_attests_empty_before(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(1)
        session, update = gate.resume_tx(blob)
        self.assertIsNotNone(session)
        self.assertEqual(update.before, b"")
        self.assertEqual(update.after, gate.checkpoint.to_bytes())
        self.assertIsNone(audit_map_update(update, KEY))

    def test_resume_tx_returns_proof_for_state_object_and_bytes(self):
        blob = checkpoint_after(1)
        state = BitState.from_bytes(blob)
        first = BitGate(make_verifier())
        second = BitGate(make_verifier())
        first.resume_tx(state)
        second.resume_tx(blob)
        self.assertEqual(first.checkpoint, second.checkpoint)

    def test_resume_tx_rejects_wrong_types(self):
        gate = BitGate(make_verifier())
        for bad in ("x", 1, None, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                gate.resume_tx(bad)
        self.assertIsNone(gate.checkpoint)

    def test_resume_tx_rejects_bad_mac_and_malformed_bytes(self):
        gate = BitGate(make_verifier())
        state = BitState.from_bytes(checkpoint_after(1))
        forged = BitState(1, state.seq, state.body, ZERO)
        with self.assertRaises(ValueError):
            gate.resume_tx(forged)
        with self.assertRaises(ValueError):
            gate.resume_tx(b"not json")
        self.assertIsNone(gate.checkpoint)

    def test_advance_attests_before_and_after(self):
        gate = BitGate(make_verifier())
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 1)
        _, first = gate.resume_tx(session.checkpoint())
        before_table = gate.checkpoint
        drive(session, clock, 1)
        _, second = gate.resume_tx(session.checkpoint())
        self.assertEqual(second.before, before_table.to_bytes())
        self.assertEqual(second.after, gate.checkpoint.to_bytes())
        self.assertNotEqual(first.after, second.after)
        self.assertIsNone(audit_map_update(first, KEY))
        self.assertIsNone(audit_map_update(second, KEY))

    def test_replay_attests_unchanged_table(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(2)
        gate.resume_tx(blob)
        table = gate.checkpoint
        session, update = gate.resume_tx(blob)
        self.assertIsNotNone(session)
        self.assertIs(gate.checkpoint, table)
        self.assertEqual(update.before, table.to_bytes())
        self.assertEqual(update.after, table.to_bytes())
        self.assertIsNone(audit_map_update(update, KEY))

    def test_new_partition_attests_added_entry(self):
        gate = BitGate(make_verifier())
        gate.resume_tx(checkpoint_after(1))
        table = gate.checkpoint
        _, update = gate.resume_tx(
            checkpoint_after(1, context=OTHER_CONTEXT, opening=OTHER_OPENING)
        )
        self.assertEqual(update.before, table.to_bytes())
        self.assertEqual(update.after, gate.checkpoint.to_bytes())
        self.assertEqual(len(gate.checkpoint.entries), 2)
        self.assertIsNone(audit_map_update(update, KEY))

    def test_failure_changes_nothing_and_issues_no_proof(self):
        gate = BitGate(make_verifier())
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 1)
        stale = session.checkpoint()
        drive(session, clock, 1)
        gate.resume_tx(session.checkpoint())
        table = gate.checkpoint
        with self.assertRaises(ValueError):
            gate.resume_tx(stale)
        self.assertEqual(gate.checkpoint, table)
        # A forged same-seq body is rejected without touching the table.
        state = BitState.from_bytes(stale)
        body = json.loads(state.body)
        body[7][0][3] += 0.0001
        mutated = _encode_payload(body)
        mac = _bit_state_mac(KEY, state.seq, mutated)
        with self.assertRaises(ValueError):
            gate.resume_tx(BitState(1, state.seq, mutated, mac))
        self.assertEqual(gate.checkpoint, table)

    def test_concurrent_resume_tx_do_not_lose_updates(self):
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
        updates = []
        lock = threading.Lock()

        def worker(blob):
            try:
                _session, update = gate.resume_tx(blob)
            except ValueError as error:
                with lock:
                    errors.append(error)
            else:
                with lock:
                    updates.append(update)

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
        # Every accepted transition chained from the previous table and
        # every issued proof audits cleanly.
        self.assertEqual(len(updates) + len(errors), 16)
        for update in updates:
            self.assertIsNone(audit_map_update(update, KEY))
        self.assertEqual(
            sorted(update.after for update in updates)[-1],
            gate.checkpoint.to_bytes(),
        )

    def test_old_interface_unchanged(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(1)
        session = gate.resume(blob)
        self.assertIsNotNone(session)
        self.assertNotIsInstance(session, tuple)
        guard = BitGuard(make_verifier())
        guard.resume(blob)
        self.assertEqual(guard.checkpoint.seq, 1)


if __name__ == "__main__":
    unittest.main()
