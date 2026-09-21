import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryEvidence,
    BitMapUpdate,
    _BIT_MAP_HISTORY_PREFIX,
    _bit_map_history_evidence_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _encode_payload,
    audit_map_history,
    audit_map_history_evidence,
    seal_map_history,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2

SID_A = b"\x0a" * 32
SID_B = b"\x0b" * 32
HASH_1 = b"\x01" * 32
HASH_2 = b"\x02" * 32
HASH_3 = b"\x03" * 32
ZERO = b"\x00" * 32


def map_for_entries(entries, key=KEY, mac=None):
    """A BitMap over ``entries`` MAC'd with ``key`` (or ``mac`` as given)."""
    ordered = tuple(sorted(entries))
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
ADVANCED_MAP = map_bytes_for(((SID_A, 1, HASH_1), (SID_B, 5, HASH_3)))


def make_chain():
    """A valid three-transition history: create, insert, advance."""
    first = update_for(b"", ONE_MAP)
    second = update_for(ONE_MAP, TWO_MAP)
    third = update_for(TWO_MAP, ADVANCED_MAP)
    return [first, second, third]


def body_for(start, updates, end):
    """The canonical history body over raw table/update encodings."""
    return _encode_payload(
        [start.hex(), [u.hex() for u in updates], end.hex()]
    )


def evidence_for(start, updates, end, key=KEY, mac=None):
    """A BitMapHistoryEvidence over the raw parts, MAC'd with ``key``."""
    body = body_for(start, updates, end)
    if mac is None:
        mac = _bit_map_history_evidence_mac(key, body)
    return BitMapHistoryEvidence(1, body, mac)


def sealed_chain(key=KEY):
    updates = make_chain()
    return updates, seal_map_history(updates, key)


class BitMapHistoryEvidenceContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        updates, evidence = sealed_chain()
        again = BitMapHistoryEvidence(1, evidence.body, evidence.mac)
        self.assertEqual(evidence, again)
        self.assertIsNot(evidence, again)
        other = evidence_for(b"", [u.to_bytes() for u in updates], TWO_MAP)
        self.assertNotEqual(evidence, other)

    def test_frozen(self):
        _, evidence = sealed_chain()
        for field in ("version", "body", "mac"):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(evidence, field, None)

    def test_version_contract(self):
        _, evidence = sealed_chain()
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence(bad, evidence.body, evidence.mac)
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence(bad, evidence.body, evidence.mac)

    def test_body_and_mac_type_contract(self):
        _, evidence = sealed_chain()
        for bad in ("x", 1, None, bytearray(evidence.body)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence(1, bad, evidence.mac)
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence(1, evidence.body, bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence(1, evidence.body, bad)

    def test_body_shape_contract(self):
        _, evidence = sealed_chain()
        good_parts = json.loads(evidence.body)
        # Not JSON, not an array, wrong arity.
        for bad in (b"", b"not json", b"{}", b'["",[]]', b'["",[],"",""]'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence(1, bad, evidence.mac)
        # start must be "" or a canonical BitMap encoding.
        for raw_start in (0, None, "zz", ONE_MAP.hex().upper(),
                          b"junk".hex()):
            bad = _encode_payload(
                [raw_start, good_parts[1], good_parts[2]]
            )
            with self.assertRaises(ValueError, msg=repr(raw_start)):
                BitMapHistoryEvidence(1, bad, evidence.mac)
        # updates must be a non-empty array of canonical update encodings.
        for raw_updates in ("x", 0, [], [""], ["zz"], [0],
                            [EMPTY_MAP.hex()]):
            bad = _encode_payload(
                [good_parts[0], raw_updates, good_parts[2]]
            )
            with self.assertRaises(ValueError, msg=repr(raw_updates)):
                BitMapHistoryEvidence(1, bad, evidence.mac)
        # end must be a canonical BitMap encoding.
        for raw_end in ("", 0, "zz", b"junk".hex()):
            bad = _encode_payload(
                [good_parts[0], good_parts[1], raw_end]
            )
            with self.assertRaises(ValueError, msg=repr(raw_end)):
                BitMapHistoryEvidence(1, bad, evidence.mac)

    def test_body_must_be_canonical_json(self):
        _, evidence = sealed_chain()
        spaced = json.dumps(json.loads(evidence.body)).encode()
        self.assertNotEqual(spaced, evidence.body)
        with self.assertRaises(ValueError):
            BitMapHistoryEvidence(1, spaced, evidence.mac)


class BitMapHistoryEvidenceEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        _, evidence = sealed_chain()
        data = evidence.to_bytes()
        self.assertIsInstance(data, bytes)
        self.assertEqual(BitMapHistoryEvidence.from_bytes(data), evidence)

    def test_encoding_shape(self):
        _, evidence = sealed_chain()
        outer = json.loads(evidence.to_bytes())
        self.assertEqual(
            outer, [1, evidence.body.hex(), evidence.mac.hex()]
        )
        # Compact, lowercase hex, no whitespace.
        self.assertEqual(
            evidence.to_bytes(),
            _encode_payload([1, evidence.body.hex(), evidence.mac.hex()]),
        )

    def test_from_bytes_type_contract(self):
        _, evidence = sealed_chain()
        for bad in ("x", 1, None, [], {}, bytearray(evidence.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        _, evidence = sealed_chain()
        data = evidence.to_bytes()
        outer = json.loads(data)
        for bad in (b"", b"not json", b"{}", b"[1]", b"[1,2]", b"[1,2,3,4]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence.from_bytes(bad)
        # Wrong field shapes surface their usual split.
        for raw_version in ("1", 1.0, True):
            bad = _encode_payload([raw_version, outer[1], outer[2]])
            with self.assertRaises(TypeError, msg=repr(raw_version)):
                BitMapHistoryEvidence.from_bytes(bad)
        with self.assertRaises(ValueError):
            BitMapHistoryEvidence.from_bytes(
                _encode_payload([2, outer[1], outer[2]])
            )
        for raw_hex in (0, None, []):
            with self.assertRaises(TypeError, msg=repr(raw_hex)):
                BitMapHistoryEvidence.from_bytes(
                    _encode_payload([1, raw_hex, outer[2]])
                )
            with self.assertRaises(TypeError, msg=repr(raw_hex)):
                BitMapHistoryEvidence.from_bytes(
                    _encode_payload([1, outer[1], raw_hex])
                )
        # Uppercase hex and a short mac are value errors.
        with self.assertRaises(ValueError):
            BitMapHistoryEvidence.from_bytes(
                _encode_payload([1, outer[1].upper(), outer[2]])
            )
        with self.assertRaises(ValueError):
            BitMapHistoryEvidence.from_bytes(
                _encode_payload([1, outer[1], (ZERO + b"\x00").hex()])
            )

    def test_from_bytes_rejects_noncanonical_spelling(self):
        _, evidence = sealed_chain()
        spaced = json.dumps(json.loads(evidence.to_bytes())).encode()
        with self.assertRaises(ValueError):
            BitMapHistoryEvidence.from_bytes(spaced)

    def test_from_bytes_does_not_verify_mac(self):
        updates = make_chain()
        evidence = evidence_for(
            b"", [u.to_bytes() for u in updates], ADVANCED_MAP, mac=ZERO
        )
        self.assertEqual(
            BitMapHistoryEvidence.from_bytes(evidence.to_bytes()), evidence
        )


class SealMapHistoryTest(unittest.TestCase):
    def test_seals_valid_chain(self):
        updates, evidence = sealed_chain()
        self.assertIsInstance(evidence, BitMapHistoryEvidence)
        self.assertEqual(evidence.version, 1)
        start, raw_updates, end = json.loads(evidence.body)
        self.assertEqual(start, "")
        self.assertEqual(
            raw_updates, [u.to_bytes().hex() for u in updates]
        )
        self.assertEqual(end, ADVANCED_MAP.hex())
        self.assertEqual(
            evidence.mac,
            hmac.new(
                KEY, _BIT_MAP_HISTORY_PREFIX + evidence.body, hashlib.sha256
            ).digest(),
        )

    def test_sealed_evidence_audits_back(self):
        updates, evidence = sealed_chain()
        final = audit_map_history_evidence(evidence, KEY)
        self.assertEqual(final, BitMap.from_bytes(ADVANCED_MAP))
        self.assertEqual(
            final, audit_map_history(updates, KEY)
        )

    def test_items_may_mix_objects_and_bytes(self):
        updates = make_chain()
        mixed = [updates[0].to_bytes(), updates[1], updates[2].to_bytes()]
        self.assertEqual(
            seal_map_history(mixed, KEY), seal_map_history(updates, KEY)
        )
        # Any iterable works, not just a list.
        self.assertEqual(
            seal_map_history(iter(updates), KEY),
            seal_map_history(updates, KEY),
        )

    def test_checkpoint_object_and_bytes(self):
        updates = make_chain()[1:]
        sealed_bytes = seal_map_history(updates, KEY, checkpoint=ONE_MAP)
        sealed_object = seal_map_history(
            updates, KEY, checkpoint=BitMap.from_bytes(ONE_MAP)
        )
        self.assertEqual(sealed_bytes, sealed_object)
        start, _, end = json.loads(sealed_bytes.body)
        self.assertEqual(start, ONE_MAP.hex())
        self.assertEqual(end, ADVANCED_MAP.hex())
        self.assertEqual(
            audit_map_history_evidence(sealed_bytes, KEY),
            BitMap.from_bytes(ADVANCED_MAP),
        )

    def test_wrong_types_raise_type_error(self):
        updates = make_chain()
        for bad in ("x", 1, None, object(), updates[0]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history(bad, KEY)
        for bad in ("x", 1, None, [], {}, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history(updates, bad)
        for bad in ("x", 1, [], {}, bytearray(ONE_MAP)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history(updates, KEY, checkpoint=bad)
        for bad_item in ("x", 1, None, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad_item)):
                seal_map_history([updates[0], bad_item], KEY)

    def test_failed_chain_produces_no_evidence(self):
        updates = make_chain()
        with self.assertRaises(ValueError):
            seal_map_history([], KEY)
        with self.assertRaises(ValueError):
            seal_map_history(updates, b"")
        # A gap in the chain.
        with self.assertRaises(ValueError):
            seal_map_history([updates[0], updates[2]], KEY)
        # A link signed under the wrong key.
        with self.assertRaises(ValueError):
            seal_map_history(
                [update_for(b"", ONE_MAP, key=OTHER_KEY)], KEY
            )
        # A checkpoint that does not match the key.
        with self.assertRaises(ValueError):
            seal_map_history(
                updates[1:], KEY,
                checkpoint=map_bytes_for(
                    ((SID_A, 1, HASH_1),), key=OTHER_KEY
                ),
            )


class AuditMapHistoryEvidenceTest(unittest.TestCase):
    def test_object_and_bytes_input(self):
        _, evidence = sealed_chain()
        final = BitMap.from_bytes(ADVANCED_MAP)
        self.assertEqual(audit_map_history_evidence(evidence, KEY), final)
        self.assertEqual(
            audit_map_history_evidence(evidence.to_bytes(), KEY), final
        )

    def test_returns_final_table(self):
        updates, evidence = sealed_chain()
        result = audit_map_history_evidence(evidence, KEY)
        self.assertIsInstance(result, BitMap)
        self.assertEqual(result.to_bytes(), updates[-1].after)

    def test_checkpoint_chain_audits(self):
        updates = make_chain()[1:]
        evidence = seal_map_history(updates, KEY, checkpoint=ONE_MAP)
        self.assertEqual(
            audit_map_history_evidence(evidence, KEY),
            BitMap.from_bytes(ADVANCED_MAP),
        )

    def test_wrong_types_raise_type_error(self):
        _, evidence = sealed_chain()
        for bad in ("x", 1, None, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_evidence(bad, KEY)
        for bad in ("x", 1, None, [], {}, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_evidence(evidence, bad)

    def test_empty_key_and_malformed_bytes_raise_value_error(self):
        _, evidence = sealed_chain()
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, b"")
        with self.assertRaises(ValueError):
            audit_map_history_evidence(b"not json", KEY)
        # A field-shape failure inside byte content is a value error.
        with self.assertRaises(ValueError):
            audit_map_history_evidence(
                _encode_payload([1, 0, ZERO.hex()]), KEY
            )

    def test_mac_verified_in_constant_time(self):
        updates = make_chain()
        evidence = evidence_for(
            b"", [u.to_bytes() for u in updates], ADVANCED_MAP, mac=ZERO
        )
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, KEY)
        # Signed under a different key, chain and all.
        other_one = map_bytes_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        other = seal_map_history(
            [update_for(b"", other_one, key=OTHER_KEY)], OTHER_KEY
        )
        with self.assertRaises(ValueError):
            audit_map_history_evidence(other, KEY)

    def test_tampered_body_rejected(self):
        updates, evidence = sealed_chain()
        start, raw_updates, end = json.loads(evidence.body)
        # A tampered body fails the MAC even before the chain is read.
        for tampered_parts in (
            [ONE_MAP.hex(), raw_updates, end],
            [start, raw_updates[1:], end],
            [start, raw_updates, ONE_MAP.hex()],
        ):
            body = _encode_payload(tampered_parts)
            tampered = BitMapHistoryEvidence(1, body, evidence.mac)
            with self.assertRaises(ValueError):
                audit_map_history_evidence(tampered, KEY)

    def test_recomputed_end_must_match(self):
        updates = make_chain()
        # A valid MAC over a body whose end is not the chain's final after.
        evidence = evidence_for(
            b"", [u.to_bytes() for u in updates], TWO_MAP
        )
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, KEY)

    def test_broken_carried_chain_rejected(self):
        updates = make_chain()
        # A valid MAC over a body whose carried chain does not link.
        broken = [updates[0].to_bytes(), updates[2].to_bytes()]
        evidence = evidence_for(b"", broken, ADVANCED_MAP)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, KEY)
        # A carried update signed under the wrong key.
        bad_link = update_for(ONE_MAP, TWO_MAP, key=OTHER_KEY)
        carried = [updates[0].to_bytes(), bad_link.to_bytes()]
        evidence = evidence_for(b"", carried, TWO_MAP)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, KEY)


if __name__ == "__main__":
    unittest.main()
