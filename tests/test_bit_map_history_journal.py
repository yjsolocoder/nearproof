import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryEvidence,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalBundle,
    BitMapHistoryJournalState,
    BitMapUpdate,
    _BIT_MAP_HISTORY_JOURNAL_BUNDLE_PREFIX,
    _BIT_MAP_HISTORY_JOURNAL_DIGEST_PREFIX,
    _BIT_MAP_HISTORY_JOURNAL_MAC_PREFIX,
    _bit_map_history_evidence_mac,
    _bit_map_history_journal_bundle_mac,
    _bit_map_history_journal_mac,
    _bit_map_history_journal_next_digest,
    _bit_map_history_journal_u64be,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _encode_payload,
    seal_map_history,
    seal_map_history_journal_bundle,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2

SID_A = b"\x0a" * 32
SID_B = b"\x0b" * 32
HASH_1 = b"\x01" * 32
HASH_2 = b"\x02" * 32
HASH_3 = b"\x03" * 32
ZERO = b"\x00" * 32

U64_MAX = 0xFFFFFFFFFFFFFFFF


def map_for(entries, key=KEY):
    ordered = tuple(sorted(entries))
    return BitMap(1, ordered, _bit_map_mac(key, _bit_map_payload(ordered)))


def update_for(before, after, key=KEY):
    placeholder = BitMapUpdate(1, before, after, ZERO)
    mac = _bit_map_update_mac(key, _bit_map_update_payload(placeholder))
    return BitMapUpdate(1, before, after, mac)


MAP_1 = map_for(((SID_A, 1, HASH_1),))
MAP_2 = map_for(((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)))
MAP_3 = map_for(((SID_A, 3, HASH_3), (SID_B, 2, HASH_2)))

UPDATE_1 = update_for(b"", MAP_1.to_bytes())
UPDATE_2 = update_for(MAP_1.to_bytes(), MAP_2.to_bytes())
UPDATE_3 = update_for(MAP_2.to_bytes(), MAP_3.to_bytes())

# "" -> MAP_2 and MAP_2 -> MAP_3.
EVIDENCE_1 = seal_map_history([UPDATE_1, UPDATE_2], KEY)
EVIDENCE_2 = seal_map_history([UPDATE_3], KEY, checkpoint=MAP_2)


def state_for(sequence, checkpoint, digest, key=KEY):
    """A journal state with the NPBJ1 mac recomputed over the first four."""
    placeholder = BitMapHistoryJournalState(
        1, sequence, checkpoint, digest, ZERO
    )
    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_mac(key, placeholder)
    )


class BitMapHistoryJournalStateContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        again = BitMapHistoryJournalState(
            1, 1, MAP_2.to_bytes(), ZERO, state.mac
        )
        self.assertEqual(state, again)
        self.assertIsNot(state, again)
        self.assertNotEqual(
            state, state_for(2, MAP_2.to_bytes(), ZERO)
        )

    def test_frozen(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        for field in ("version", "sequence", "checkpoint", "digest", "mac"):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(state, field, None)

    def test_version_contract(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    bad, 1, MAP_2.to_bytes(), ZERO, ZERO
                )
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    bad, 1, MAP_2.to_bytes(), ZERO, ZERO
                )

    def test_sequence_contract(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    1, bad, MAP_2.to_bytes(), ZERO, ZERO
                )
        for bad in (-1, U64_MAX + 1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    1, bad, MAP_2.to_bytes(), ZERO, ZERO
                )

    def test_checkpoint_contract(self):
        for bad in ("x", 1, None, [], b"", b"junk"):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                BitMapHistoryJournalState(1, 1, bad, ZERO, ZERO)
        self.assertIsInstance(
            BitMapHistoryJournalState(
                1, 0, MAP_1.to_bytes(), ZERO, ZERO
            ),
            BitMapHistoryJournalState,
        )

    def test_digest_and_mac_contract(self):
        for bad in ("x", 1, None, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    1, 1, MAP_2.to_bytes(), bad, ZERO
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    1, 1, MAP_2.to_bytes(), ZERO, bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    1, 1, MAP_2.to_bytes(), bad, ZERO
                )
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalState(
                    1, 1, MAP_2.to_bytes(), ZERO, bad
                )


class BitMapHistoryJournalStateEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        state = state_for(3, MAP_3.to_bytes(), HASH_1)
        data = state.to_bytes()
        self.assertIsInstance(data, bytes)
        self.assertEqual(
            BitMapHistoryJournalState.from_bytes(data), state
        )

    def test_encoding_shape(self):
        state = state_for(3, MAP_3.to_bytes(), HASH_1)
        self.assertEqual(
            json.loads(state.to_bytes()),
            [
                1,
                3,
                MAP_3.to_bytes().hex(),
                HASH_1.hex(),
                state.mac.hex(),
            ],
        )
        self.assertEqual(
            state.to_bytes(),
            _encode_payload(
                [
                    1,
                    3,
                    MAP_3.to_bytes().hex(),
                    HASH_1.hex(),
                    state.mac.hex(),
                ]
            ),
        )

    def test_from_bytes_type_contract(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        for bad in ("x", 1, None, [], {}, bytearray(state.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalState.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        outer = json.loads(state.to_bytes())
        for bad in (
            b"",
            b"not json",
            b"{}",
            b"[1]",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalState.from_bytes(bad)
        # Field-shape failures keep the TypeError/ValueError split.
        for raw_version in ("1", 1.0, True, None):
            bad = _encode_payload(
                [raw_version, outer[1], outer[2], outer[3], outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_version)):
                BitMapHistoryJournalState.from_bytes(bad)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalState.from_bytes(
                _encode_payload([2, outer[1], outer[2], outer[3], outer[4]])
            )
        for raw_sequence in ("1", 1.0, True, None):
            bad = _encode_payload(
                [1, raw_sequence, outer[2], outer[3], outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_sequence)):
                BitMapHistoryJournalState.from_bytes(bad)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalState.from_bytes(
                _encode_payload(
                    [1, U64_MAX + 1, outer[2], outer[3], outer[4]]
                )
            )
        # checkpoint must be a lowercase hex string (wrong shape ->
        # TypeError) decoding to canonical non-empty BitMap bytes (bad
        # hex/canonical content -> ValueError).
        for raw_checkpoint in (0, None, []):
            bad = _encode_payload(
                [1, outer[1], raw_checkpoint, outer[3], outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_checkpoint)):
                BitMapHistoryJournalState.from_bytes(bad)
        for raw_checkpoint in ("", b"junk".hex()):
            bad = _encode_payload(
                [1, outer[1], raw_checkpoint, outer[3], outer[4]]
            )
            with self.assertRaises(ValueError, msg=repr(raw_checkpoint)):
                BitMapHistoryJournalState.from_bytes(bad)
        # digest/mac wrong hex shape or length.
        for raw in (0, None, [], b"junk".hex(), (b"\x00" * 31).hex()):
            bad = _encode_payload(
                [1, outer[1], outer[2], raw, outer[4]]
            )
            with self.assertRaises((TypeError, ValueError), msg=repr(raw)):
                BitMapHistoryJournalState.from_bytes(bad)
            bad = _encode_payload(
                [1, outer[1], outer[2], outer[3], raw]
            )
            with self.assertRaises((TypeError, ValueError), msg=repr(raw)):
                BitMapHistoryJournalState.from_bytes(bad)

    def test_from_bytes_rejects_noncanonical_spelling(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        spaced = json.dumps(json.loads(state.to_bytes())).encode()
        self.assertNotEqual(spaced, state.to_bytes())
        with self.assertRaises(ValueError):
            BitMapHistoryJournalState.from_bytes(spaced)
        # A non-canonical checkpoint spelling is rejected too.
        table_spaced = json.dumps(json.loads(MAP_2.to_bytes())).encode()
        with self.assertRaises(ValueError):
            BitMapHistoryJournalState.from_bytes(
                _encode_payload(
                    [1, 1, table_spaced.hex(), ZERO.hex(), ZERO.hex()]
                )
            )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the state NPBJ1 mac nor the checkpoint NPBL1 mac is
        # checked: a zero mac and a foreign-key checkpoint both parse.
        foreign = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        state = BitMapHistoryJournalState(
            1, 7, foreign.to_bytes(), ZERO, ZERO
        )
        self.assertEqual(
            BitMapHistoryJournalState.from_bytes(state.to_bytes()), state
        )


class CryptoVectorTest(unittest.TestCase):
    def test_u64be_is_fixed_eight_big_endian(self):
        self.assertEqual(_bit_map_history_journal_u64be(0), b"\x00" * 8)
        self.assertEqual(
            _bit_map_history_journal_u64be(1), b"\x00" * 7 + b"\x01"
        )
        self.assertEqual(
            _bit_map_history_journal_u64be(U64_MAX), b"\xff" * 8
        )
        self.assertEqual(
            _bit_map_history_journal_u64be(0x0102030405060708),
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        )

    def test_state_mac_vector(self):
        state = state_for(1, MAP_2.to_bytes(), HASH_1)
        content = _encode_payload(
            [1, 1, MAP_2.to_bytes().hex(), HASH_1.hex()]
        )
        self.assertEqual(
            state.mac,
            hmac.new(
                KEY, _BIT_MAP_HISTORY_JOURNAL_MAC_PREFIX + content,
                hashlib.sha256,
            ).digest(),
        )

    def test_digest_chain_vector(self):
        d0 = b"\x00" * 32
        d1 = _bit_map_history_journal_next_digest(
            d0, 1, EVIDENCE_1.to_bytes()
        )
        self.assertEqual(
            d1,
            hashlib.sha256(
                _BIT_MAP_HISTORY_JOURNAL_DIGEST_PREFIX
                + d0
                + (1).to_bytes(8, "big")
                + EVIDENCE_1.to_bytes()
            ).digest(),
        )
        d2 = _bit_map_history_journal_next_digest(
            d1, 2, EVIDENCE_2.to_bytes()
        )
        self.assertEqual(
            d2,
            hashlib.sha256(
                _BIT_MAP_HISTORY_JOURNAL_DIGEST_PREFIX
                + d1
                + (2).to_bytes(8, "big")
                + EVIDENCE_2.to_bytes()
            ).digest(),
        )


class AuditorConstructorTest(unittest.TestCase):
    def test_key_must_be_bytes(self):
        for bad in ("secret", 7, None, bytearray(b"k")):
            with self.assertRaises(TypeError):
                BitMapHistoryJournalAuditor(bad)

    def test_key_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalAuditor(b"")

    def test_fresh_auditor_has_no_state(self):
        self.assertIsNone(BitMapHistoryJournalAuditor(KEY).state)

    def test_state_kind(self):
        for bad in ("x", 1, [], {}):
            with self.assertRaises(TypeError):
                BitMapHistoryJournalAuditor(KEY, state=bad)

    def test_state_must_be_canonical(self):
        with self.assertRaises(ValueError):
            BitMapHistoryJournalAuditor(KEY, state=b"junk")

    def test_state_mac_must_match(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        tampered = dataclasses.replace(state, mac=ZERO)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalAuditor(KEY, state=tampered)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalAuditor(OTHER_KEY, state=state)

    def test_checkpoint_mac_must_match(self):
        # A valid state mac over a checkpoint signed under a different key
        # fails the inner NPBL1 layer.
        foreign = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        state = state_for(1, foreign.to_bytes(), ZERO, key=KEY)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalAuditor(KEY, state=state)

    def test_state_accepts_instance_and_bytes(self):
        state = state_for(1, MAP_2.to_bytes(), ZERO)
        self.assertEqual(
            BitMapHistoryJournalAuditor(KEY, state=state).state, state
        )
        self.assertEqual(
            BitMapHistoryJournalAuditor(KEY, state=state.to_bytes()).state,
            state,
        )


class AuditorAuditTest(unittest.TestCase):
    def _advance(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        self.assertIs(auditor.audit(EVIDENCE_1), auditor)
        return auditor

    def test_advance_from_empty(self):
        auditor = self._advance()
        state = auditor.state
        d1 = _bit_map_history_journal_next_digest(
            b"\x00" * 32, 1, EVIDENCE_1.to_bytes()
        )
        self.assertEqual(state.version, 1)
        self.assertEqual(state.sequence, 1)
        self.assertEqual(state.checkpoint, MAP_2.to_bytes())
        self.assertEqual(state.digest, d1)
        self.assertEqual(
            state.mac, _bit_map_history_journal_mac(KEY, state)
        )

    def test_accepts_bytes_and_chains(self):
        auditor = self._advance()
        d1 = auditor.state.digest
        auditor.audit(EVIDENCE_2.to_bytes())
        state = auditor.state
        self.assertEqual(state.sequence, 2)
        self.assertEqual(state.checkpoint, MAP_3.to_bytes())
        self.assertEqual(
            state.digest,
            _bit_map_history_journal_next_digest(
                d1, 2, EVIDENCE_2.to_bytes()
            ),
        )

    def test_empty_state_requires_empty_start(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(EVIDENCE_2)
        self.assertIsNone(auditor.state)

    def test_replay_is_rejected_and_state_kept(self):
        auditor = self._advance()
        auditor.audit(EVIDENCE_2)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit(EVIDENCE_2)
        self.assertEqual(auditor.state, before)

    def test_fork_from_same_start_is_rejected(self):
        auditor = self._advance()
        fork = seal_map_history([UPDATE_1], KEY)
        with self.assertRaises(ValueError):
            auditor.audit(fork)
        self.assertEqual(auditor.state.checkpoint, MAP_2.to_bytes())
        self.assertEqual(auditor.state.sequence, 1)

    def test_old_segment_rejected_after_restart(self):
        auditor = self._advance()
        auditor.audit(EVIDENCE_2)
        restored = BitMapHistoryJournalAuditor(
            KEY, state=auditor.state.to_bytes()
        )
        with self.assertRaises(ValueError):
            restored.audit(EVIDENCE_2)
        self.assertEqual(restored.state, auditor.state)

    def test_resume_after_restart_continues_chain(self):
        auditor = self._advance()
        blob = auditor.state.to_bytes()
        restored = BitMapHistoryJournalAuditor(KEY, state=blob)
        restored.audit(EVIDENCE_2)
        auditor.audit(EVIDENCE_2)
        self.assertEqual(restored.state, auditor.state)

    def test_wrong_argument_type(self):
        auditor = self._advance()
        for bad in (1, "x", None, [EVIDENCE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertEqual(auditor.state.sequence, 1)

    def test_malformed_bytes(self):
        auditor = self._advance()
        with self.assertRaises(ValueError):
            auditor.audit(b"junk")
        self.assertEqual(auditor.state.sequence, 1)

    def test_wrong_key_evidence(self):
        other_map = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        other_update = update_for(b"", other_map.to_bytes(), key=OTHER_KEY)
        foreign = seal_map_history([other_update], OTHER_KEY)
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(foreign)
        self.assertIsNone(auditor.state)

    def test_tampered_evidence(self):
        tampered = BitMapHistoryEvidence(1, EVIDENCE_1.body, ZERO)
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        self.assertIsNone(auditor.state)

    def test_broken_chain_inside_body(self):
        body = _encode_payload(
            [
                "",
                [
                    UPDATE_1.to_bytes().hex(),
                    UPDATE_3.to_bytes().hex(),
                ],
                MAP_3.to_bytes().hex(),
            ]
        )
        broken = BitMapHistoryEvidence(
            1, body, _bit_map_history_evidence_mac(KEY, body)
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(broken)
        self.assertIsNone(auditor.state)

    def test_sequence_overflow(self):
        # A restored state at u64 max rejects the next segment even though
        # the segment chains onto its checkpoint.
        digest = HASH_2
        state = state_for(U64_MAX, MAP_2.to_bytes(), digest)
        auditor = BitMapHistoryJournalAuditor(KEY, state=state)
        with self.assertRaises(ValueError):
            auditor.audit(EVIDENCE_2)
        self.assertEqual(auditor.state, state)

    def test_state_property_is_read_only(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(AttributeError):
            auditor.state = state_for(1, MAP_2.to_bytes(), ZERO)


class AuditorAuditBundleTest(unittest.TestCase):
    def _next_evidence(self, auditor):
        """One evidence segment appending one entry to the checkpoint."""
        index = auditor.state.sequence
        before = auditor.state.checkpoint
        existing = BitMap.from_bytes(before).entries
        sid = bytes((0x10 + index,)) * 32
        table = map_for(existing + ((sid, index + 10, sid),))
        return seal_map_history(
            [update_for(before, table.to_bytes())], KEY,
            checkpoint=BitMap.from_bytes(before),
        )

    def test_commit_from_empty_returns_same_auditor(self):
        bundle = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
        auditor = BitMapHistoryJournalAuditor(KEY)
        self.assertIs(auditor.audit_bundle(bundle), auditor)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertEqual(auditor.state.checkpoint, MAP_2.to_bytes())
        d1 = _bit_map_history_journal_next_digest(
            b"\x00" * 32, 1, EVIDENCE_1.to_bytes()
        )
        self.assertEqual(auditor.state.digest, d1)

    def test_commit_full_chain_and_accepts_bytes(self):
        bundle = seal_map_history_journal_bundle(
            [EVIDENCE_1, EVIDENCE_2], KEY
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        self.assertIs(auditor.audit_bundle(bundle.to_bytes()), auditor)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.checkpoint, MAP_3.to_bytes())

    def test_commit_from_current_state_then_chain_again(self):
        first = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(first)
        middle = auditor.state
        second = seal_map_history_journal_bundle(
            [EVIDENCE_2], KEY, state=middle
        )
        self.assertIs(auditor.audit_bundle(second), auditor)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.checkpoint, MAP_3.to_bytes())
        third = seal_map_history_journal_bundle(
            [self._next_evidence(auditor)], KEY, state=auditor.state
        )
        auditor.audit_bundle(third)
        self.assertEqual(auditor.state.sequence, 3)

    def test_same_bundle_replay_rejected_state_kept(self):
        bundle = seal_map_history_journal_bundle(
            [EVIDENCE_1, EVIDENCE_2], KEY
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(bundle)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle.to_bytes())
        self.assertEqual(auditor.state, before)

    def test_empty_auditor_rejects_nonempty_start(self):
        bundle = seal_map_history_journal_bundle(
            [EVIDENCE_2], KEY,
            state=BitMapHistoryJournalAuditor(KEY).audit(EVIDENCE_1).state,
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_nonempty_auditor_rejects_empty_start(self):
        bundle = seal_map_history_journal_bundle(
            [EVIDENCE_1, EVIDENCE_2], KEY
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, before)

    def test_start_from_different_state_rejected(self):
        # A validly sealed bundle whose start state sits at the same
        # checkpoint table but carries a different digest head does not
        # match the auditor's current state bytes.
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        before = auditor.state
        divergent_start = state_for(1, MAP_2.to_bytes(), ZERO)
        divergent_digest = _bit_map_history_journal_next_digest(
            ZERO, 2, EVIDENCE_2.to_bytes()
        )
        divergent_end = state_for(2, MAP_3.to_bytes(), divergent_digest)
        bundle = self._bundle_for(
            divergent_start.to_bytes(),
            (EVIDENCE_2.to_bytes(),),
            divergent_end.to_bytes(),
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, before)

    def test_argument_type_contract(self):
        bundle = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
        auditor = BitMapHistoryJournalAuditor(KEY)
        for bad in (1, "x", None, [bundle], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        with self.assertRaises(TypeError):
            auditor.audit_bundle(bytearray(bundle.to_bytes()))
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(b"junk")
        self.assertIsNone(auditor.state)

    def test_failure_never_changes_state_chain(self):
        bundle = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(bundle)
        before = auditor.state
        # Every failure mode below must leave the state untouched.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)  # replay
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                dataclasses.replace(bundle, mac=ZERO)
            )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                dataclasses.replace(
                    bundle,
                    mac=_bit_map_history_journal_bundle_mac(
                        b"a-different-key!!" * 2, bundle
                    ),
                )
            )
        self.assertEqual(auditor.state, before)

    def _bundle_for(self, start, evidences, end, key=KEY):
        placeholder = BitMapHistoryJournalBundle(
            1, start, evidences, end, ZERO
        )
        return dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_bundle_mac(key, placeholder),
        )

    def test_tampered_start_state_mac(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        end = BitMapHistoryJournalAuditor(
            KEY, state=auditor.state.to_bytes()
        )
        end.audit(EVIDENCE_2)
        bundle = self._bundle_for(
            dataclasses.replace(auditor.state, mac=ZERO).to_bytes(),
            (EVIDENCE_2.to_bytes(),),
            end.state.to_bytes(),
        )
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, before)

    def test_tampered_end_state_mac(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        end = BitMapHistoryJournalAuditor(
            KEY, state=auditor.state.to_bytes()
        )
        end.audit(EVIDENCE_2)
        bundle = self._bundle_for(
            auditor.state.to_bytes(),
            (EVIDENCE_2.to_bytes(),),
            dataclasses.replace(end.state, mac=ZERO).to_bytes(),
        )
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, before)

    def test_foreign_checkpoint_key_fails_npbl1_layer(self):
        other_key = b"a-different-key!!" * 2
        foreign = map_for(((SID_A, 1, HASH_1),), key=other_key)
        foreign_update = update_for(b"", foreign.to_bytes(), key=other_key)
        foreign_evidence = seal_map_history(
            [foreign_update], other_key
        )
        foreign_auditor = BitMapHistoryJournalAuditor(other_key)
        foreign_auditor.audit(foreign_evidence)
        placeholder = BitMapHistoryJournalState(
            1,
            foreign_auditor.state.sequence,
            foreign_auditor.state.checkpoint,
            foreign_auditor.state.digest,
            ZERO,
        )
        # NPBJ1 valid under KEY but the carried checkpoint is not: the
        # NPBL1 layer must fail before replay starts.
        mixed = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_mac(KEY, placeholder),
        )
        bundle = self._bundle_for(
            b"", (foreign_evidence.to_bytes(),), mixed.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_end_mismatch_state_kept(self):
        first = BitMapHistoryJournalAuditor(KEY)
        first.audit(EVIDENCE_1)
        bundle = self._bundle_for(
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_2.to_bytes()),
            first.state.to_bytes(),
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_broken_inner_chain_state_kept(self):
        end = BitMapHistoryJournalAuditor(KEY)
        end.audit(EVIDENCE_1)
        end.audit(EVIDENCE_2)
        # First segment does not start from the empty journal.
        bundle = self._bundle_for(
            b"", (EVIDENCE_2.to_bytes(),), end.state.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_tampered_carried_evidence_mac(self):
        # Rebuild the bundle bytes over an evidence whose NPBH1 mac was
        # zeroed, re-sealing only the outer NPBJ3 mac: the endpoint MACs
        # stay valid but segment replay must fail.
        sealed = seal_map_history_journal_bundle(
            [EVIDENCE_1, EVIDENCE_2], KEY
        )
        outer = json.loads(sealed.to_bytes())
        evidence_outer = json.loads(bytes.fromhex(outer[2][0]))
        evidence_outer[2] = ZERO.hex()
        outer[2][0] = json.dumps(
            evidence_outer, separators=(",", ":")
        ).encode().hex()
        content = _encode_payload(
            [outer[0], outer[1], outer[2], outer[3]]
        )
        outer[4] = hmac.new(
            KEY,
            _BIT_MAP_HISTORY_JOURNAL_BUNDLE_PREFIX + content,
            hashlib.sha256,
        ).hexdigest()
        evil = _encode_payload(outer)
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(evil)
        self.assertIsNone(auditor.state)

    def test_sequence_overflow(self):
        state = state_for(U64_MAX, MAP_2.to_bytes(), HASH_2)
        end = state_for(U64_MAX, MAP_2.to_bytes(), HASH_2)
        bundle = self._bundle_for(
            state.to_bytes(), (EVIDENCE_2.to_bytes(),), end.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY, state=state)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, state)

    def test_audit_still_works_after_bundle(self):
        bundle = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(bundle)
        auditor.audit(EVIDENCE_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(auditor.state.checkpoint, MAP_3.to_bytes())


class AuditorConcurrencyTest(unittest.TestCase):
    def test_competing_segments_linearize(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        first = seal_map_history([UPDATE_1], KEY)  # "" -> MAP_1
        second = EVIDENCE_1  # "" -> MAP_2
        results = []
        failures = []

        def run(evidence):
            try:
                results.append(auditor.audit(evidence))
            except ValueError:
                failures.append(evidence)

        threads = [
            threading.Thread(target=run, args=(first,)),
            threading.Thread(target=run, args=(second,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertIn(
            auditor.state.checkpoint,
            (MAP_1.to_bytes(), MAP_2.to_bytes()),
        )

    def test_competing_bundles_linearize(self):
        # Two validly sealed bundles both start from the empty journal;
        # only the first to take the lock commits, the other is rejected
        # on the start match and the committed state is never lost.
        one_segment = seal_map_history([UPDATE_1], KEY)  # "" -> MAP_1
        first_bundle = seal_map_history_journal_bundle(
            [one_segment], KEY
        )
        full_bundle = seal_map_history_journal_bundle(
            [EVIDENCE_1, EVIDENCE_2], KEY
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        results = []
        failures = []

        def run(bundle):
            try:
                results.append(auditor.audit_bundle(bundle))
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(first_bundle,)),
            threading.Thread(target=run, args=(full_bundle,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertIn(auditor.state.sequence, (1, 2))
        # A bundle replays multiple segments atomically or not at all, so
        # a partial two-segment commit ending at sequence 1 cannot happen.
        if auditor.state.sequence == 1:
            self.assertEqual(
                auditor.state.checkpoint, MAP_1.to_bytes()
            )
        else:
            self.assertEqual(
                auditor.state.checkpoint, MAP_3.to_bytes()
            )


if __name__ == "__main__":
    unittest.main()
