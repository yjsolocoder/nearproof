import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalBundle,
    BitMapHistoryJournalState,
    BitMapUpdate,
    _BIT_MAP_HISTORY_JOURNAL_BUNDLE_PREFIX,
    _bit_map_history_journal_bundle_mac,
    _bit_map_history_journal_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _encode_payload,
    audit_map_history_journal_bundle,
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


def audited_state(*evidences, key=KEY):
    auditor = BitMapHistoryJournalAuditor(key)
    for evidence in evidences:
        auditor.audit(evidence)
    return auditor.state


STATE_1 = audited_state(EVIDENCE_1)
STATE_2 = audited_state(EVIDENCE_1, EVIDENCE_2)

# A parallel history signed under a different key.
FOREIGN_MAP = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
FOREIGN_UPDATE = update_for(b"", FOREIGN_MAP.to_bytes(), key=OTHER_KEY)
FOREIGN_EVIDENCE = seal_map_history([FOREIGN_UPDATE], OTHER_KEY)
FOREIGN_STATE = audited_state(FOREIGN_EVIDENCE, key=OTHER_KEY)

# "" -> STATE_1, STATE_1 -> STATE_2 and "" -> STATE_2.
BUNDLE_1 = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
BUNDLE_2 = seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=STATE_1)
BUNDLE_FULL = seal_map_history_journal_bundle([EVIDENCE_1, EVIDENCE_2], KEY)


def bundle_for(start, evidences, end, key=KEY):
    """A bundle with the NPBJ3 mac recomputed over the first four fields."""
    placeholder = BitMapHistoryJournalBundle(1, start, evidences, end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_bundle_mac(key, placeholder)
    )


class BitMapHistoryJournalBundleContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        again = BitMapHistoryJournalBundle(
            1,
            BUNDLE_2.start,
            BUNDLE_2.evidences,
            BUNDLE_2.end,
            BUNDLE_2.mac,
        )
        self.assertEqual(BUNDLE_2, again)
        self.assertIsNot(BUNDLE_2, again)
        self.assertNotEqual(BUNDLE_1, BUNDLE_2)

    def test_frozen(self):
        for field in ("version", "start", "evidences", "end", "mac"):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(BUNDLE_1, field, None)

    def test_version_contract(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    bad, b"", (EVIDENCE_1.to_bytes(),), STATE_1.to_bytes(), ZERO
                )
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    bad, b"", (EVIDENCE_1.to_bytes(),), STATE_1.to_bytes(), ZERO
                )

    def test_start_contract(self):
        for bad in ("x", 1, None, [], b"junk", MAP_2.to_bytes()):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    1, bad, (EVIDENCE_2.to_bytes(),), STATE_2.to_bytes(), ZERO
                )
        self.assertIsInstance(
            BitMapHistoryJournalBundle(
                1, b"", (EVIDENCE_1.to_bytes(),), STATE_1.to_bytes(), ZERO
            ),
            BitMapHistoryJournalBundle,
        )
        self.assertIsInstance(
            BitMapHistoryJournalBundle(
                1,
                STATE_1.to_bytes(),
                (EVIDENCE_2.to_bytes(),),
                STATE_2.to_bytes(),
                ZERO,
            ),
            BitMapHistoryJournalBundle,
        )

    def test_evidences_contract(self):
        for bad in ("x", 1, None, [EVIDENCE_1.to_bytes()]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    1, b"", bad, STATE_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            BitMapHistoryJournalBundle(1, b"", (), STATE_1.to_bytes(), ZERO)
        for bad_item in ("x", 1, None, []):
            with self.assertRaises(TypeError, msg=repr(bad_item)):
                BitMapHistoryJournalBundle(
                    1, b"", (bad_item,), STATE_1.to_bytes(), ZERO
                )
        for bad_item in (b"", b"junk", MAP_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad_item)):
                BitMapHistoryJournalBundle(
                    1, b"", (bad_item,), STATE_1.to_bytes(), ZERO
                )

    def test_end_contract(self):
        for bad in ("x", 1, None, [], b"", b"junk", MAP_3.to_bytes()):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    1, b"", (EVIDENCE_1.to_bytes(),), bad, ZERO
                )

    def test_mac_contract(self):
        for bad in ("x", 1, None, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    1, b"", (EVIDENCE_1.to_bytes(),), STATE_1.to_bytes(), bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalBundle(
                    1, b"", (EVIDENCE_1.to_bytes(),), STATE_1.to_bytes(), bad
                )


class BitMapHistoryJournalBundleEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for bundle in (BUNDLE_1, BUNDLE_2, BUNDLE_FULL):
            data = bundle.to_bytes()
            self.assertIsInstance(data, bytes)
            self.assertEqual(
                BitMapHistoryJournalBundle.from_bytes(data), bundle
            )

    def test_encoding_shape(self):
        self.assertEqual(
            json.loads(BUNDLE_FULL.to_bytes()),
            [
                1,
                "",
                [EVIDENCE_1.to_bytes().hex(), EVIDENCE_2.to_bytes().hex()],
                STATE_2.to_bytes().hex(),
                BUNDLE_FULL.mac.hex(),
            ],
        )
        self.assertEqual(
            BUNDLE_2.to_bytes(),
            _encode_payload(
                [
                    1,
                    STATE_1.to_bytes().hex(),
                    [EVIDENCE_2.to_bytes().hex()],
                    STATE_2.to_bytes().hex(),
                    BUNDLE_2.mac.hex(),
                ]
            ),
        )

    def test_from_bytes_type_contract(self):
        for bad in ("x", 1, None, [], {}, bytearray(BUNDLE_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryJournalBundle.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        outer = json.loads(BUNDLE_2.to_bytes())
        for bad in (
            b"",
            b"not json",
            b"{}",
            b"[1]",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        # Field-shape failures keep the TypeError/ValueError split.
        for raw_version in ("1", 1.0, True, None):
            bad = _encode_payload(
                [raw_version, outer[1], outer[2], outer[3], outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_version)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        with self.assertRaises(ValueError):
            BitMapHistoryJournalBundle.from_bytes(
                _encode_payload([2, outer[1], outer[2], outer[3], outer[4]])
            )
        # start must be a lowercase hex string (wrong shape -> TypeError)
        # that is empty or decodes to canonical state bytes (bad hex or
        # non-canonical content -> ValueError).
        for raw_start in (0, None, []):
            bad = _encode_payload(
                [1, raw_start, outer[2], outer[3], outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_start)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        for raw_start in (b"junk".hex(), MAP_2.to_bytes().hex()):
            bad = _encode_payload(
                [1, raw_start, outer[2], outer[3], outer[4]]
            )
            with self.assertRaises(ValueError, msg=repr(raw_start)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        # evidences must be a non-empty array of lowercase hex strings each
        # decoding to canonical evidence bytes.
        for raw_evidences in (0, None, "x"):
            bad = _encode_payload(
                [1, outer[1], raw_evidences, outer[3], outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_evidences)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        for raw_evidences in ([], [""], [b"junk".hex()], [0]):
            bad = _encode_payload(
                [1, outer[1], raw_evidences, outer[3], outer[4]]
            )
            with self.assertRaises((TypeError, ValueError), msg=repr(raw_evidences)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        # end must decode to canonical non-empty state bytes.
        for raw_end in (0, None, []):
            bad = _encode_payload(
                [1, outer[1], outer[2], raw_end, outer[4]]
            )
            with self.assertRaises(TypeError, msg=repr(raw_end)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        for raw_end in ("", b"junk".hex(), MAP_3.to_bytes().hex()):
            bad = _encode_payload(
                [1, outer[1], outer[2], raw_end, outer[4]]
            )
            with self.assertRaises(ValueError, msg=repr(raw_end)):
                BitMapHistoryJournalBundle.from_bytes(bad)
        # mac wrong hex shape or length.
        for raw in (0, None, [], b"junk".hex(), (b"\x00" * 31).hex()):
            bad = _encode_payload(
                [1, outer[1], outer[2], outer[3], raw]
            )
            with self.assertRaises((TypeError, ValueError), msg=repr(raw)):
                BitMapHistoryJournalBundle.from_bytes(bad)

    def test_from_bytes_rejects_noncanonical_spelling(self):
        spaced = json.dumps(json.loads(BUNDLE_2.to_bytes())).encode()
        self.assertNotEqual(spaced, BUNDLE_2.to_bytes())
        with self.assertRaises(ValueError):
            BitMapHistoryJournalBundle.from_bytes(spaced)
        # A non-canonical start spelling is rejected too.
        state_spaced = json.dumps(json.loads(STATE_1.to_bytes())).encode()
        with self.assertRaises(ValueError):
            BitMapHistoryJournalBundle.from_bytes(
                _encode_payload(
                    [
                        1,
                        state_spaced.hex(),
                        [EVIDENCE_2.to_bytes().hex()],
                        STATE_2.to_bytes().hex(),
                        ZERO.hex(),
                    ]
                )
            )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the bundle NPBJ3 mac nor the endpoint state MACs are
        # checked: a zero mac and foreign-key states both parse.
        bundle = BitMapHistoryJournalBundle(
            1,
            FOREIGN_STATE.to_bytes(),
            (EVIDENCE_2.to_bytes(),),
            FOREIGN_STATE.to_bytes(),
            ZERO,
        )
        self.assertEqual(
            BitMapHistoryJournalBundle.from_bytes(bundle.to_bytes()), bundle
        )


class CryptoVectorTest(unittest.TestCase):
    def test_bundle_mac_vector(self):
        content = _encode_payload(
            [
                1,
                STATE_1.to_bytes().hex(),
                [EVIDENCE_2.to_bytes().hex()],
                STATE_2.to_bytes().hex(),
            ]
        )
        self.assertEqual(
            BUNDLE_2.mac,
            hmac.new(
                KEY,
                _BIT_MAP_HISTORY_JOURNAL_BUNDLE_PREFIX + content,
                hashlib.sha256,
            ).digest(),
        )
        self.assertEqual(
            BUNDLE_2.mac, _bit_map_history_journal_bundle_mac(KEY, BUNDLE_2)
        )


class SealTest(unittest.TestCase):
    def test_seal_from_empty_start(self):
        bundle = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(bundle.evidences, (EVIDENCE_1.to_bytes(),))
        self.assertEqual(bundle.end, STATE_1.to_bytes())
        self.assertEqual(
            bundle.mac, _bit_map_history_journal_bundle_mac(KEY, bundle)
        )

    def test_seal_chains_segments_in_order(self):
        self.assertEqual(BUNDLE_FULL.start, b"")
        self.assertEqual(
            BUNDLE_FULL.evidences,
            (EVIDENCE_1.to_bytes(), EVIDENCE_2.to_bytes()),
        )
        self.assertEqual(BUNDLE_FULL.end, STATE_2.to_bytes())

    def test_seal_from_state_instance_and_bytes(self):
        from_instance = seal_map_history_journal_bundle(
            [EVIDENCE_2], KEY, state=STATE_1
        )
        from_bytes = seal_map_history_journal_bundle(
            [EVIDENCE_2], KEY, state=STATE_1.to_bytes()
        )
        self.assertEqual(from_instance, from_bytes)
        self.assertEqual(from_instance.start, STATE_1.to_bytes())
        self.assertEqual(from_instance.end, STATE_2.to_bytes())

    def test_seal_accepts_evidence_bytes(self):
        self.assertEqual(
            seal_map_history_journal_bundle(
                [EVIDENCE_1.to_bytes()], KEY
            ),
            BUNDLE_1,
        )

    def test_seal_type_contract(self):
        for bad in (1, "x", None, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history_journal_bundle(bad, KEY)
        for bad_item in (1, "x", None, object()):
            with self.assertRaises(TypeError, msg=repr(bad_item)):
                seal_map_history_journal_bundle([bad_item], KEY)
        for bad_key in ("secret", 7, None, bytearray(b"k")):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                seal_map_history_journal_bundle([EVIDENCE_1], bad_key)
        for bad_state in ("x", 1, [], {}):
            with self.assertRaises(TypeError, msg=repr(bad_state)):
                seal_map_history_journal_bundle(
                    [EVIDENCE_1], KEY, state=bad_state
                )

    def test_seal_value_contract(self):
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([], KEY)
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([EVIDENCE_1], b"")
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([b"junk"], KEY)
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([EVIDENCE_1], KEY, state=b"junk")
        tampered_state = dataclasses.replace(STATE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle(
                [EVIDENCE_2], KEY, state=tampered_state
            )
        # A segment that does not start where the state stands.
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([EVIDENCE_2], KEY)
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle(
                [EVIDENCE_1], KEY, state=STATE_1
            )
        # A wrong-key segment.
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([FOREIGN_EVIDENCE], KEY)

    def test_seal_sequence_overflow(self):
        digest = HASH_2
        placeholder = BitMapHistoryJournalState(
            1, U64_MAX, MAP_2.to_bytes(), digest, ZERO
        )
        state = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_mac(KEY, placeholder),
        )
        with self.assertRaises(ValueError):
            seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=state)


class AuditTest(unittest.TestCase):
    def test_audit_round_trip(self):
        self.assertEqual(
            audit_map_history_journal_bundle(BUNDLE_1, KEY), STATE_1
        )
        self.assertEqual(
            audit_map_history_journal_bundle(BUNDLE_2, KEY), STATE_2
        )
        self.assertEqual(
            audit_map_history_journal_bundle(BUNDLE_FULL, KEY), STATE_2
        )

    def test_audit_accepts_bytes(self):
        self.assertEqual(
            audit_map_history_journal_bundle(BUNDLE_FULL.to_bytes(), KEY),
            STATE_2,
        )

    def test_audit_type_contract(self):
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_journal_bundle(bad, KEY)
        for bad_key in ("secret", 7, None, bytearray(b"k")):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                audit_map_history_journal_bundle(BUNDLE_1, bad_key)

    def test_audit_malformed_bytes(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(b"junk", KEY)

    def test_audit_empty_key(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(BUNDLE_1, b"")

    def test_audit_tampered_bundle_mac(self):
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(tampered, KEY)

    def test_audit_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(BUNDLE_1, OTHER_KEY)
        foreign = seal_map_history_journal_bundle(
            [FOREIGN_EVIDENCE], OTHER_KEY
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(foreign, KEY)

    def test_audit_tampered_start_state_mac(self):
        tampered_start = dataclasses.replace(STATE_1, mac=ZERO).to_bytes()
        bundle = bundle_for(
            tampered_start, (EVIDENCE_2.to_bytes(),), STATE_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(bundle, KEY)

    def test_audit_tampered_end_state_mac(self):
        tampered_end = dataclasses.replace(STATE_2, mac=ZERO).to_bytes()
        bundle = bundle_for(
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_2.to_bytes()),
            tampered_end,
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(bundle, KEY)

    def test_audit_foreign_checkpoint_key(self):
        # A validly MAC'd bundle whose end state's checkpoint is signed
        # under a different key fails the inner NPBL1 layer: the state
        # NPBJ1 mac is recomputed under KEY so only that layer can fail.
        placeholder = BitMapHistoryJournalState(
            1,
            FOREIGN_STATE.sequence,
            FOREIGN_STATE.checkpoint,
            FOREIGN_STATE.digest,
            ZERO,
        )
        mixed = dataclasses.replace(
            placeholder,
            mac=_bit_map_history_journal_mac(KEY, placeholder),
        )
        bundle = bundle_for(
            b"", (FOREIGN_EVIDENCE.to_bytes(),), mixed.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(bundle, KEY)

    def test_audit_end_mismatch(self):
        # Valid bundle mac and valid endpoint MACs, but the replayed chain
        # does not end at the carried end state.
        bundle = bundle_for(
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_2.to_bytes()),
            STATE_1.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(bundle, KEY)

    def test_audit_broken_chain(self):
        # The first segment does not start from the empty journal.
        bundle = bundle_for(b"", (EVIDENCE_2.to_bytes(),), STATE_2.to_bytes())
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(bundle, KEY)
        # A gap between the carried start and the first segment.
        bundle = bundle_for(
            STATE_1.to_bytes(), (EVIDENCE_1.to_bytes(),), STATE_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_map_history_journal_bundle(bundle, KEY)

    def test_audit_is_pure(self):
        before = (BUNDLE_FULL.start, BUNDLE_FULL.evidences, BUNDLE_FULL.end)
        audit_map_history_journal_bundle(BUNDLE_FULL, KEY)
        self.assertEqual(
            (BUNDLE_FULL.start, BUNDLE_FULL.evidences, BUNDLE_FULL.end), before
        )


if __name__ == "__main__":
    unittest.main()
