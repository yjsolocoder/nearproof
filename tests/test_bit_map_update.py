import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitGate,
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
    _encode_payload,
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


def map_bytes(entries, key=KEY):
    """Canonical bytes of a correctly NPBL1-MAC'd table over ``entries``."""
    table = BitMap(
        1,
        tuple(entries),
        _bit_map_mac(key, _bit_map_payload(tuple(entries))),
    )
    return table.to_bytes()


def signed_update(before, after, key=KEY):
    """A correctly NPBU1-MAC'd update wrapping the two table encodings."""
    placeholder = BitMapUpdate(1, before, after, ZERO)
    return dataclasses.replace(
        placeholder,
        mac=_bit_map_update_mac(key, _bit_map_update_payload(placeholder)),
    )


class BitMapUpdateContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        before = map_bytes(((SID_A, 1, HASH_1),))
        after = map_bytes(((SID_A, 2, HASH_2),))
        first = BitMapUpdate(1, before, after, ZERO)
        second = BitMapUpdate(1, bytes(before), bytes(after), bytes(ZERO))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.before, first.after, first.mac),
            (1, before, after, ZERO),
        )
        self.assertNotEqual(first, BitMapUpdate(1, b"", after, ZERO))
        self.assertNotEqual(first, BitMapUpdate(1, before, before, ZERO))
        self.assertNotEqual(first, BitMapUpdate(1, before, after, HASH_1))

    def test_empty_before_and_frozen(self):
        after = map_bytes(((SID_A, 1, HASH_1),))
        update = BitMapUpdate(1, b"", after, ZERO)
        self.assertEqual(update.before, b"")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            update.mac = b"\x01" * 32

    def test_version_contract(self):
        after = map_bytes(())
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(bad, b"", after, ZERO)
        with self.assertRaises(ValueError):
            BitMapUpdate(2, b"", after, ZERO)

    def test_byte_fields_must_be_bytes(self):
        after = map_bytes(())
        for bad in ("", None, 42, bytearray(), []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(1, bad, after, ZERO)
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(1, b"", bad, ZERO)
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate(1, b"", after, bad)

    def test_mac_length(self):
        after = map_bytes(())
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapUpdate(1, b"", after, bad)

    def test_after_must_be_canonical_map_bytes(self):
        for bad in (b"", b"not json", b"null", b"[1,[],\"00\"]",
                    map_bytes(((SID_A, 1, HASH_1),)) + b" "):
            with self.assertRaises(ValueError, msg=bad):
                BitMapUpdate(1, b"", bad, ZERO)

    def test_non_empty_before_must_be_canonical_map_bytes(self):
        after = map_bytes(((SID_A, 1, HASH_1),))
        for bad in (b"not json", b"null", b"[1,[],\"00\"]"):
            with self.assertRaises(ValueError, msg=bad):
                BitMapUpdate(1, bad, after, ZERO)

    def test_inner_field_shape_error_is_value_error(self):
        # A carried map whose entry field has the wrong shape is invalid
        # content; the update fields themselves are bytes, so the
        # constructor reports ValueError, never a nested TypeError.
        bad_map = _encode_payload(
            [1, [[42, 1, HASH_1.hex()]], ZERO.hex()]
        )
        with self.assertRaises(ValueError):
            BitMapUpdate(1, b"", bad_map, ZERO)
        with self.assertRaises(ValueError):
            BitMapUpdate(1, bad_map, bad_map, ZERO)


class BitMapUpdateEncodingTest(unittest.TestCase):
    def _update(self, before_entries, after_entries):
        before = b"" if before_entries is None else map_bytes(before_entries)
        return signed_update(before, map_bytes(after_entries))

    def test_to_bytes_shape(self):
        before = map_bytes(((SID_A, 1, HASH_1),))
        after = map_bytes(((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)))
        update = BitMapUpdate(1, before, after, ZERO)
        obj = json.loads(update.to_bytes())
        self.assertEqual(obj, [1, before.hex(), after.hex(), ZERO.hex()])
        self.assertNotIn(b" ", update.to_bytes())
        self.assertEqual(
            update.to_bytes(),
            json.dumps(obj, separators=(",", ":")).encode("utf-8"),
        )

    def test_empty_before_spells_empty_string(self):
        update = BitMapUpdate(1, b"", map_bytes(()), ZERO)
        self.assertEqual(
            json.loads(update.to_bytes()),
            [1, "", BitMap(1, (), _bit_map_mac(KEY, _bit_map_payload(()))).to_bytes().hex(),
             ZERO.hex()],
        )

    def test_round_trip(self):
        cases = [
            (None, ()),
            (None, ((SID_A, 1, HASH_1),)),
            (((SID_A, 1, HASH_1),), ((SID_A, 1, HASH_1),)),
            (((SID_A, 1, HASH_1),),
             ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))),
            (((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)),
             ((SID_A, 3, HASH_3), (SID_B, 2, HASH_2))),
        ]
        for before_entries, after_entries in cases:
            update = self._update(before_entries, after_entries)
            decoded = BitMapUpdate.from_bytes(update.to_bytes())
            self.assertEqual(decoded, update)

    def test_from_bytes_rejects_non_bytes(self):
        data = self._update(None, ()).to_bytes()
        for bad in (data.decode(), None, 42, [1], bytearray(data), {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapUpdate.from_bytes(bad)

    def test_from_bytes_rejects_outer_shape(self):
        good = json.loads(self._update(None, ((SID_A, 1, HASH_1),)).to_bytes())
        blobs = [
            json.dumps(good[:3], separators=(",", ":")).encode(),
            json.dumps(good + [0], separators=(",", ":")).encode(),
            json.dumps({"version": 1}, separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_from_bytes_version_wrong_type_raises_type_error(self):
        good = json.loads(self._update(None, ((SID_A, 1, HASH_1),)).to_bytes())
        blob = json.dumps(
            ["1", good[1], good[2], good[3]], separators=(",", ":")
        ).encode()
        with self.assertRaises(TypeError):
            BitMapUpdate.from_bytes(blob)

    def test_from_bytes_wrong_field_types_raise_type_error(self):
        good = json.loads(self._update(None, ()).to_bytes())
        mac = good[3]
        empty_map = BitMap(
            1, (), _bit_map_mac(KEY, _bit_map_payload(()))
        ).to_bytes().hex()
        blobs = [
            json.dumps([1, 42, empty_map, mac], separators=(",", ":")).encode(),
            json.dumps([1, None, empty_map, mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", 42, mac], separators=(",", ":")).encode(),
            json.dumps([1, "", empty_map, 42],
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(TypeError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(self._update(None, ()).to_bytes())
        mac = good[3]
        empty_map = BitMap(
            1, (), _bit_map_mac(KEY, _bit_map_payload(()))
        ).to_bytes().hex()
        one_entry = map_bytes(((SID_A, 1, HASH_1),)).hex()
        # An embedded map whose entries are out of sid order: satisfies the
        # outer update spelling but fails the BitMap value contract.
        unsorted_map = json.dumps(
            [1,
             [[SID_B.hex(), 1, HASH_1.hex()],
              [SID_A.hex(), 2, HASH_2.hex()]],
             ZERO.hex()],
            separators=(",", ":"),
        ).encode().decode()
        blobs = [
            # version 2
            json.dumps([2, "", empty_map, mac],
                       separators=(",", ":")).encode(),
            # non-hex / odd hex
            json.dumps([1, "zz", empty_map, mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, "abc", empty_map, mac],
                       separators=(",", ":")).encode(),
            json.dumps([1, "", "zz", mac],
                       separators=(",", ":")).encode(),
            # uppercase hex around an otherwise valid embedded map
            json.dumps([1, "", one_entry.upper(), mac],
                       separators=(",", ":")).encode(),
            # embedded map value-contract violation (unsorted sids)
            json.dumps([1, "", unsorted_map, mac],
                       separators=(",", ":")).encode(),
            # mac wrong length
            json.dumps([1, "", empty_map, "ab" * 31],
                       separators=(",", ":")).encode(),
            # trailing / inserted whitespace breaks canonical re-encoding
            self._update(None, ()).to_bytes() + b" ",
            b"not json",
            b"",
            b"null",
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                BitMapUpdate.from_bytes(blob)

    def test_nested_shape_error_is_value_error(self):
        # An embedded map whose JSON field has the wrong shape is a value
        # error even though the nested parse itself raises TypeError,
        # exactly like the other container records.
        blob = json.dumps(
            [1, "", _encode_payload([1, ["x"], ZERO.hex()]).decode(),
             ZERO.hex()],
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            BitMapUpdate.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        update = BitMapUpdate(1, b"", map_bytes(()), ZERO)
        decoded = BitMapUpdate.from_bytes(update.to_bytes())
        self.assertEqual(decoded, update)
        self.assertEqual(decoded.mac, ZERO)


class BitMapUpdateMacTest(unittest.TestCase):
    def test_mac_formula_direct_concatenation(self):
        before = map_bytes(((SID_A, 1, HASH_1),))
        after = map_bytes(((SID_A, 2, HASH_2),))
        update = signed_update(before, after)
        encoding = _encode_payload([1, before.hex(), after.hex()])
        self.assertEqual(
            update.mac,
            hmac.new(KEY, _BIT_MAP_UPDATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
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

    def test_domain_separation_from_table_mac(self):
        after = map_bytes(())
        update = signed_update(b"", after)
        # The NPBL1 prefix over the same encoding never produces the
        # receipt MAC.
        self.assertNotEqual(
            update.mac,
            hmac.new(
                KEY,
                _BIT_MAP_PREFIX
                + _encode_payload([1, b"".hex(), after.hex()]),
                hashlib.sha256,
            ).digest(),
        )


class AuditMapUpdateTest(unittest.TestCase):
    def test_key_contract(self):
        update = signed_update(b"", map_bytes(()))
        for bad in (None, 42, "key", bytearray(KEY), []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_update(update, bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_update(update.to_bytes(), bad)
        with self.assertRaises(ValueError):
            audit_map_update(update, b"")

    def test_x_contract(self):
        for bad in (None, 42, "x", [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_update(bad, KEY)

    def test_inner_shape_error_in_bytes_is_value_error(self):
        # Only the argument kind (non-bytes x / non-bytes key) is a
        # TypeError; wrong-typed fields inside byte content are invalid
        # records and report as ValueError.
        empty_map = BitMap(
            1, (), _bit_map_mac(KEY, _bit_map_payload(()))
        ).to_bytes().hex()
        blob = json.dumps([1, "", empty_map, 42],
                          separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_map_update(blob, KEY)

    def test_accepts_object_and_bytes(self):
        update = signed_update(b"", map_bytes(()))
        audit_map_update(update, KEY)
        audit_map_update(update.to_bytes(), KEY)

    def test_receipt_mac_must_match(self):
        update = BitMapUpdate(1, b"", map_bytes(()), ZERO)
        with self.assertRaises(ValueError):
            audit_map_update(update, KEY)
        wrong_key = dataclasses.replace(
            update, mac=_bit_map_update_mac(
                OTHER_KEY, _bit_map_update_payload(update)
            )
        )
        with self.assertRaises(ValueError):
            audit_map_update(wrong_key, KEY)

    def test_after_table_mac_must_match(self):
        # Correct NPBU1 wrapper around an after table with a bogus NPBL1 mac.
        after = BitMap(1, (), ZERO).to_bytes()
        with self.assertRaises(ValueError):
            audit_map_update(signed_update(b"", after), KEY)

    def test_before_table_mac_must_match(self):
        before = BitMap(1, (), ZERO).to_bytes()
        after = map_bytes(((SID_A, 1, HASH_1),))
        with self.assertRaises(ValueError):
            audit_map_update(signed_update(before, after), KEY)

    def test_allowed_transitions_accepted(self):
        one = ((SID_A, 1, HASH_1),)
        two = ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))
        advanced = ((SID_A, 3, HASH_3), (SID_B, 2, HASH_2))
        # First establishment over the empty table (one entry and the empty
        # table both start a partition set).
        audit_map_update(signed_update(b"", map_bytes(())), KEY)
        audit_map_update(signed_update(b"", map_bytes(one)), KEY)
        # Replay: identical tables.
        audit_map_update(signed_update(map_bytes(one), map_bytes(one)), KEY)
        # One entry added, in ascending sid order.
        audit_map_update(signed_update(map_bytes(one), map_bytes(two)), KEY)
        # One entry advanced in place.
        audit_map_update(
            signed_update(map_bytes(two), map_bytes(advanced)), KEY
        )
        # Adding the smaller sid (insertion at index 0) is still one add.
        audit_map_update(
            signed_update(map_bytes(((SID_B, 2, HASH_2),)), map_bytes(two)),
            KEY,
        )

    def test_empty_before_allows_at_most_one_entry(self):
        two = ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))
        with self.assertRaises(ValueError):
            audit_map_update(signed_update(b"", map_bytes(two)), KEY)

    def test_rejected_transitions(self):
        one = ((SID_A, 1, HASH_1),)
        two = ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))
        cases = [
            # Entry removed.
            (two, one),
            # Two entries added at once.
            ((), ((SID_A, 1, HASH_1), (SID_B, 2, HASH_2))),
            # Two entries advanced at once.
            (((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)),
             ((SID_A, 9, HASH_3), (SID_B, 8, HASH_1))),
            # Advance that keeps the old hash.
            (((SID_A, 1, HASH_1),), ((SID_A, 2, HASH_1),)),
            # Hash changes without a seq increase.
            (((SID_A, 1, HASH_1),), ((SID_A, 1, HASH_2),)),
            # A seq decrease.
            (((SID_A, 2, HASH_2),), ((SID_A, 1, HASH_1),)),
            # An entry replaced by a different sid at the same index.
            (((SID_A, 1, HASH_1),), ((SID_B, 1, HASH_1),)),
            # Entire table replaced by a disjoint entry.
            (((SID_A, 1, HASH_1),), ((SID_B, 5, HASH_2),)),
        ]
        for before_entries, after_entries in cases:
            with self.assertRaises(
                ValueError, msg=(before_entries, after_entries)
            ):
                audit_map_update(
                    signed_update(
                        map_bytes(before_entries), map_bytes(after_entries)
                    ),
                    KEY,
                )

    def test_wrong_key_rejects_otherwise_valid_transition(self):
        update = signed_update(
            b"", map_bytes(((SID_A, 1, HASH_1),)), key=OTHER_KEY
        )
        with self.assertRaises(ValueError):
            audit_map_update(update, KEY)

    def test_audit_is_pure(self):
        update = signed_update(b"", map_bytes(((SID_A, 1, HASH_1),)))
        self.assertIsNone(audit_map_update(update, KEY))
        # The record is untouched and still verifies.
        audit_map_update(update, KEY)


class ResumeTxTest(unittest.TestCase):
    def test_first_transaction_receipt(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(1)
        session, receipt = gate.resume_tx(blob)
        self.assertIsNotNone(session)
        self.assertIsInstance(receipt, BitMapUpdate)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.before, b"")
        self.assertEqual(receipt.after, gate.checkpoint.to_bytes())
        self.assertEqual(len(gate.checkpoint.entries), 1)
        audit_map_update(receipt, KEY)

    def test_receipt_mac_formula(self):
        gate = BitGate(make_verifier())
        _, receipt = gate.resume_tx(checkpoint_after(1))
        encoding = _encode_payload(
            [1, receipt.before.hex(), receipt.after.hex()]
        )
        self.assertEqual(
            receipt.mac,
            hmac.new(KEY, b"NPBU1" + encoding, hashlib.sha256).digest(),
        )

    def test_advance_transaction(self):
        gate = BitGate(make_verifier())
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 1)
        _, first = gate.resume_tx(session.checkpoint())
        drive(session, clock, 1)
        _, second = gate.resume_tx(session.checkpoint())
        self.assertEqual(second.before, first.after)
        self.assertEqual(second.after, gate.checkpoint.to_bytes())
        before_map = BitMap.from_bytes(second.before)
        after_map = BitMap.from_bytes(second.after)
        self.assertEqual(before_map.entries[0][1], 1)
        self.assertEqual(after_map.entries[0][1], 2)
        self.assertNotEqual(
            before_map.entries[0][2], after_map.entries[0][2]
        )
        audit_map_update(first, KEY)
        audit_map_update(second, KEY)

    def test_new_partition_is_an_add_receipt(self):
        gate = BitGate(make_verifier())
        clock_a = SteppedClock()
        session_a = make_verifier(clock_a).start_bits(
            CONTEXT, OPENING, rounds=4, timeout=0.01
        )
        drive(session_a, clock_a, 1, digest=digest_of(CONTEXT, OPENING))
        _, first = gate.resume_tx(session_a.checkpoint())
        clock_b = SteppedClock()
        session_b = make_verifier(clock_b).start_bits(
            OTHER_CONTEXT, OTHER_OPENING, rounds=4, timeout=0.01
        )
        drive(session_b, clock_b, 1,
              digest=digest_of(OTHER_CONTEXT, OTHER_OPENING))
        _, second = gate.resume_tx(session_b.checkpoint())
        self.assertEqual(second.before, first.after)
        self.assertEqual(len(BitMap.from_bytes(second.before).entries), 1)
        self.assertEqual(len(BitMap.from_bytes(second.after).entries), 2)
        audit_map_update(second, KEY)

    def test_replay_receipt_has_identical_tables(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(2)
        _, first = gate.resume_tx(blob)
        snapshot = gate.checkpoint
        session, replay = gate.resume_tx(blob)
        self.assertIsNotNone(session)
        self.assertNotEqual(replay.before, b"")
        self.assertEqual(replay.before, replay.after)
        self.assertEqual(replay.after, snapshot.to_bytes())
        self.assertIs(gate.checkpoint, snapshot)
        audit_map_update(replay, KEY)

    def test_resume_after_restart_baselines_before(self):
        gate = BitGate(make_verifier())
        gate.resume(checkpoint_after(1))
        persisted = gate.checkpoint.to_bytes()
        restored = BitGate(make_verifier(), checkpoint=persisted)
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 2)
        _, receipt = restored.resume_tx(session.checkpoint())
        self.assertEqual(receipt.before, persisted)
        self.assertEqual(receipt.after, restored.checkpoint.to_bytes())
        audit_map_update(receipt, KEY)

    def test_wrong_types_raise_type_error(self):
        gate = BitGate(make_verifier())
        for bad in ("x", 1, None, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                gate.resume_tx(bad)
        self.assertIsNone(gate.checkpoint)

    def test_failure_leaves_table_untouched_and_no_effect(self):
        gate = BitGate(make_verifier())
        blob = checkpoint_after(1)
        gate.resume_tx(blob)
        before = gate.checkpoint
        # Forged checkpoint: NPBS1 verification fails inside the lock.
        state = BitState.from_bytes(blob)
        forged = BitState(1, state.seq, state.body, ZERO)
        with self.assertRaises(ValueError):
            gate.resume_tx(forged)
        self.assertEqual(gate.checkpoint, before)
        # A lower seq is rejected with no table change.
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=4,
                                      timeout=0.01)
        drive(session, clock, 1)
        stale = session.checkpoint()
        drive(session, clock, 1)
        gate.resume_tx(session.checkpoint())
        advanced = gate.checkpoint
        with self.assertRaises(ValueError):
            gate.resume_tx(stale)
        self.assertIs(gate.checkpoint, advanced)

    def test_concurrent_transactions_do_not_lose_updates(self):
        clock = SteppedClock()
        verifier = make_verifier(clock)
        session = verifier.start_bits(CONTEXT, OPENING, rounds=64,
                                      timeout=0.01)
        blobs = []
        for _ in range(16):
            drive(session, clock, 1)
            blobs.append(session.checkpoint())
        gate = BitGate(make_verifier())
        receipts = []
        errors = []

        def worker(blob):
            try:
                _session, receipt = gate.resume_tx(blob)
                receipts.append(receipt)
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
        # Out-of-order deliveries may be rejected, but the highest seq wins
        # and no update is lost: the table ends at seq 16 exactly once.
        # Every issued receipt witnesses a real locked transition and
        # verifies independently, however the threads interleaved.
        self.assertGreaterEqual(len(receipts), 1)
        self.assertEqual(len(gate.checkpoint.entries), 1)
        self.assertEqual(gate.checkpoint.entries[0][1], 16)
        for receipt in receipts:
            audit_map_update(receipt, KEY)

    def test_concurrent_partition_receipts_all_valid(self):
        blobs = [
            checkpoint_after(1, context=bytes([i]) * 32, opening=OPENING)
            for i in range(8)
        ]
        gate = BitGate(make_verifier())
        receipts = []
        lock = threading.Lock()

        def worker(blob):
            _session, receipt = gate.resume_tx(blob)
            with lock:
                receipts.append(receipt)

        threads = [
            threading.Thread(target=worker, args=(blob,)) for blob in blobs
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 8)
        self.assertEqual(len(gate.checkpoint.entries), 8)
        # Every receipt independently verifies: each before/after pair is
        # a genuine one-entry-add chain off the empty table.
        for receipt in receipts:
            audit_map_update(receipt, KEY)

    def test_resume_still_returns_session_only(self):
        gate = BitGate(make_verifier())
        session = gate.resume(checkpoint_after(1))
        self.assertIsNotNone(session)
        self.assertEqual(len(gate.checkpoint.entries), 1)


if __name__ == "__main__":
    unittest.main()
