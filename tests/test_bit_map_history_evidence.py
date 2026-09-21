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
        mac = _bit_map_update_mac(key, _bit_map_update_payload(placeholder))
    return BitMapUpdate(1, before, after, mac)


EMPTY_MAP = map_bytes_for(())
ONE_MAP = map_bytes_for(((SID_A, 1, HASH_1),))
TWO_MAP = map_bytes_for(((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)))
ADVANCED_MAP = map_bytes_for(((SID_A, 1, HASH_1), (SID_B, 5, HASH_3)))


def chain():
    """A valid three-transition history: create, insert, advance."""
    first = update_for(b"", ONE_MAP)
    second = update_for(ONE_MAP, TWO_MAP)
    third = update_for(TWO_MAP, ADVANCED_MAP)
    return [first, second, third]


def body_for(start, updates, end):
    return _encode_payload([start, updates, end])


def evidence_for(start, updates, end, key=KEY, mac=None):
    body = body_for(start, updates, end)
    if mac is None:
        mac = _bit_map_history_evidence_mac(key, body)
    return BitMapHistoryEvidence(1, body, mac)


def sealed(key=KEY):
    return seal_map_history(chain(), key)


class BitMapHistoryEvidenceContractTest(unittest.TestCase):
    def test_positional_and_field_equality(self):
        first = sealed()
        second = BitMapHistoryEvidence(1, bytes(first.body), bytes(first.mac))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual((first.version, first.body, first.mac),
                         (1, first.body, first.mac))
        other = evidence_for("", [chain()[0].to_bytes().hex()], ONE_MAP.hex())
        self.assertNotEqual(first, other)
        self.assertNotEqual(
            first, BitMapHistoryEvidence(1, first.body, HASH_1)
        )

    def test_is_frozen(self):
        evidence = sealed()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            evidence.mac = b"\x01" * 32

    def test_version_contract(self):
        body = sealed().body
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence(bad, body, ZERO)
        with self.assertRaises(ValueError):
            BitMapHistoryEvidence(2, body, ZERO)

    def test_body_contract(self):
        for bad in ("x", None, 42, bytearray(b""), [1]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence(1, bad, ZERO)
        update_hex = chain()[0].to_bytes().hex()
        for bad in (
            b"not json",
            b"{}",
            body_for("", [update_hex], ONE_MAP.hex()) + b" ",
            body_for("", [update_hex], ONE_MAP.hex())[:-1],
            # start must be "" or a canonical BitMap encoding.
            body_for(EMPTY_MAP.hex()[:-1], [update_hex], ONE_MAP.hex()),
            body_for("zz", [update_hex], ONE_MAP.hex()),
            body_for(ONE_MAP.hex().upper(), [update_hex], ONE_MAP.hex()),
            # updates must be a non-empty array of canonical encodings.
            body_for("", [], ONE_MAP.hex()),
            body_for("", "not-a-list", ONE_MAP.hex()),
            body_for("", [42], ONE_MAP.hex()),
            body_for("", ["zz"], ONE_MAP.hex()),
            body_for("", [update_hex[:-2]], ONE_MAP.hex()),
            # end must be a canonical BitMap encoding.
            body_for("", [update_hex], ""),
            body_for("", [update_hex], ONE_MAP.hex()[:-2]),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence(1, bad, ZERO)
        # "" (no table yet) and a canonical start encoding are both fine.
        BitMapHistoryEvidence(
            1, body_for("", [update_hex], ONE_MAP.hex()), ZERO
        )
        BitMapHistoryEvidence(
            1, body_for(ONE_MAP.hex(), [update_hex], ONE_MAP.hex()), ZERO
        )

    def test_mac_contract(self):
        body = sealed().body
        for bad in ("x", None, 42, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence(1, body, bad)
        for bad in (b"\x00" * 31, b"\x00" * 33, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence(1, body, bad)


class BitMapHistoryEvidenceEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        evidence = sealed()
        obj = json.loads(evidence.to_bytes())
        self.assertEqual(obj, [1, evidence.body.hex(), evidence.mac.hex()])
        self.assertNotIn(b" ", evidence.to_bytes())
        self.assertEqual(
            evidence.to_bytes(),
            json.dumps(obj, separators=(",", ":")).encode("utf-8"),
        )

    def test_body_shape(self):
        updates = chain()
        evidence = seal_map_history(updates, KEY)
        self.assertEqual(
            json.loads(evidence.body),
            [
                "",
                [update.to_bytes().hex() for update in updates],
                ADVANCED_MAP.hex(),
            ],
        )

    def test_round_trip(self):
        evidence = sealed()
        self.assertEqual(
            BitMapHistoryEvidence.from_bytes(evidence.to_bytes()), evidence
        )

    def test_from_bytes_rejects_non_bytes(self):
        data = sealed().to_bytes()
        for bad in (data.decode(), None, 42, [1], bytearray(data), {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical(self):
        data = sealed().to_bytes()
        obj = json.loads(data)
        for bad in (
            b"not json",
            b"{}",
            b"[]",
            data + b" ",
            data + b"\n",
            json.dumps(obj).encode(),  # whitespace is not canonical
            json.dumps([2] + obj[1:], separators=(",", ":")).encode(),
            json.dumps([1] + obj[1:] + [ZERO.hex()],
                       separators=(",", ":")).encode(),
            json.dumps([1, obj[1].upper(), obj[2]],
                       separators=(",", ":")).encode(),
            json.dumps([1, obj[1], obj[2][:-2]],
                       separators=(",", ":")).encode(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BitMapHistoryEvidence.from_bytes(bad)
        for bad in (
            json.dumps(["1"] + obj[1:], separators=(",", ":")).encode(),
            json.dumps([1, 42, obj[2]], separators=(",", ":")).encode(),
            json.dumps([1, obj[1], 42], separators=(",", ":")).encode(),
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                BitMapHistoryEvidence.from_bytes(bad)

    def test_from_bytes_does_not_verify_mac(self):
        evidence = evidence_for(
            "", [chain()[0].to_bytes().hex()], ONE_MAP.hex(), key=OTHER_KEY
        )
        self.assertEqual(
            BitMapHistoryEvidence.from_bytes(evidence.to_bytes()), evidence
        )


class SealMapHistoryTest(unittest.TestCase):
    def test_seals_valid_chain(self):
        updates = chain()
        evidence = seal_map_history(updates, KEY)
        self.assertIsInstance(evidence, BitMapHistoryEvidence)
        start, chain_hex, end = json.loads(evidence.body)
        self.assertEqual(start, "")
        self.assertEqual(
            chain_hex, [update.to_bytes().hex() for update in updates]
        )
        self.assertEqual(end, ADVANCED_MAP.hex())
        self.assertEqual(
            evidence.mac,
            hmac.new(
                KEY, b"NPBH1" + evidence.body, hashlib.sha256
            ).digest(),
        )

    def test_mac_is_over_prefix_plus_raw_body(self):
        evidence = sealed()
        self.assertEqual(_BIT_MAP_HISTORY_PREFIX, b"NPBH1")
        expected = hmac.new(
            KEY, b"NPBH1" + evidence.body, hashlib.sha256
        ).digest()
        self.assertEqual(evidence.mac, expected)

    def test_items_may_mix_objects_and_bytes(self):
        updates = chain()
        mixed = [updates[0].to_bytes(), updates[1], updates[2].to_bytes()]
        self.assertEqual(seal_map_history(mixed, KEY), sealed())
        self.assertEqual(seal_map_history(iter(mixed), KEY), sealed())

    def test_checkpoint_object_and_bytes_start_the_chain(self):
        updates = chain()[1:]
        for checkpoint in (BitMap.from_bytes(ONE_MAP), ONE_MAP):
            evidence = seal_map_history(
                updates, KEY, checkpoint=checkpoint
            )
            start, _, end = json.loads(evidence.body)
            self.assertEqual(start, ONE_MAP.hex())
            self.assertEqual(end, ADVANCED_MAP.hex())

    def test_type_errors(self):
        updates = chain()
        for bad in (42, "x", None, b"bytes"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history(bad, KEY)
        for bad in ("x", None, 42, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_map_history(updates, bad)
        with self.assertRaises(TypeError):
            seal_map_history(updates, KEY, checkpoint=42)
        with self.assertRaises(TypeError):
            seal_map_history([updates[0], 42], KEY)

    def test_value_errors(self):
        updates = chain()
        with self.assertRaises(ValueError):
            seal_map_history([], KEY)
        with self.assertRaises(ValueError):
            seal_map_history(updates, b"")
        with self.assertRaises(ValueError):
            seal_map_history([updates[0], b"not json"], KEY)
        # A broken chain is never sealed.
        with self.assertRaises(ValueError):
            seal_map_history([updates[0], updates[2]], KEY)
        with self.assertRaises(ValueError):
            seal_map_history([updates[1], updates[0]], KEY)
        # A tampered update is never sealed.
        tampered = update_for(ONE_MAP, TWO_MAP, mac=ZERO)
        with self.assertRaises(ValueError):
            seal_map_history([updates[0], tampered, updates[2]], KEY)
        # A checkpoint that does not match the key is never sealed.
        with self.assertRaises(ValueError):
            seal_map_history(
                updates[1:], KEY, checkpoint=map_bytes_for(
                    ((SID_A, 1, HASH_1),), key=OTHER_KEY
                )
            )


class AuditMapHistoryEvidenceTest(unittest.TestCase):
    def test_valid_evidence_returns_final_table(self):
        evidence = sealed()
        result = audit_map_history_evidence(evidence, KEY)
        self.assertIsInstance(result, BitMap)
        self.assertEqual(result, BitMap.from_bytes(ADVANCED_MAP))

    def test_accepts_canonical_bytes(self):
        evidence = sealed()
        self.assertEqual(
            audit_map_history_evidence(evidence.to_bytes(), KEY),
            BitMap.from_bytes(ADVANCED_MAP),
        )

    def test_matches_audit_map_history(self):
        updates = chain()
        evidence = seal_map_history(updates, KEY)
        self.assertEqual(
            audit_map_history_evidence(evidence, KEY),
            audit_map_history(updates, KEY),
        )

    def test_checkpoint_chain_round_trip(self):
        updates = chain()
        evidence = seal_map_history(updates[1:], KEY, checkpoint=ONE_MAP)
        self.assertEqual(
            audit_map_history_evidence(evidence, KEY),
            audit_map_history(updates[1:], KEY, checkpoint=ONE_MAP),
        )

    def test_type_errors(self):
        evidence = sealed()
        for bad in (evidence.to_bytes().decode(), None, 42, [1], {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_evidence(bad, KEY)
        for bad in ("x", None, 42, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_map_history_evidence(evidence, bad)

    def test_value_errors(self):
        evidence = sealed()
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, b"")
        with self.assertRaises(ValueError):
            audit_map_history_evidence(b"not json", KEY)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence.to_bytes() + b" ", KEY)

    def test_tampered_mac_rejected(self):
        evidence = sealed()
        body = evidence.body
        wrong_key = evidence_for("", json.loads(body)[1],
                                 json.loads(body)[2], key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(wrong_key, KEY)
        forged = BitMapHistoryEvidence(1, body, ZERO)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(forged, KEY)

    def test_tampered_chain_rejected(self):
        updates = chain()
        # A gap in the carried chain fails the re-audit.
        broken = [updates[0], updates[2]]
        evidence = seal_map_history([updates[0]], KEY)  # placeholder mac
        body = body_for(
            "", [u.to_bytes().hex() for u in broken], ADVANCED_MAP.hex()
        )
        mac = _bit_map_history_evidence_mac(KEY, body)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(
                BitMapHistoryEvidence(1, body, mac), KEY
            )
        self.assertIsInstance(evidence, BitMapHistoryEvidence)

    def test_end_mismatch_rejected(self):
        updates = chain()
        # A well-MAC'd body whose end is not the recomputed final table.
        body = body_for(
            "", [u.to_bytes().hex() for u in updates], TWO_MAP.hex()
        )
        evidence = evidence_for("", [u.to_bytes().hex() for u in updates],
                                TWO_MAP.hex())
        self.assertEqual(evidence.body, body)
        with self.assertRaises(ValueError):
            audit_map_history_evidence(evidence, KEY)


if __name__ == "__main__":
    unittest.main()
