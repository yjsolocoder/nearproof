import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    EvidenceRevocationList,
    Prover,
    Verifier,
    audit_assess_evidence,
    audit_assess_evidence_policy,
    audit_evidence_revocation_list,
    make_evidence_revocation_list,
    revoke_evidence,
    seal_assess_evidence,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


class AutoClock:
    """Two readings per round, ``step`` apart, giving deterministic RTTs."""

    def __init__(self, step=1e-7):
        self.readings = 0
        self.step = step

    def __call__(self):
        value = self.readings * self.step
        self.readings += 1
        return value


def make_evidence_list(count, key=KEY, step=1e-7):
    prover = Prover(key)
    verifier = Verifier(key, clock=AutoClock(step), replay_protection=True)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, prover, records


def revocation(record, revoked_at=0.0, key=KEY):
    return revoke_evidence(record, revoked_at, key)


def signed_entry(record, *, revoked_at=0.0, mac=b"\x00" * 32):
    return BoundEvidenceRevocation(
        1, record.round_index, record.nonce, revoked_at, mac
    )


class EvidenceRevocationListContractTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)
        self.entry = revocation(self.records[0])

    def make(self, **overrides):
        values = {
            "version": 1,
            "sequence": 7,
            "issued_at": 100.0,
            "entries": (self.entry,),
            "mac": b"\x00" * 32,
        }
        values.update(overrides)
        return EvidenceRevocationList(
            values["version"],
            values["sequence"],
            values["issued_at"],
            values["entries"],
            values["mac"],
        )

    def test_is_frozen_and_equal_by_fields(self):
        first = make_evidence_revocation_list([self.entry], 3, 50.0, KEY)
        second = EvidenceRevocationList(
            1, 3, 50.0, tuple(first.entries), bytes(first.mac)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 4

    def test_positional_field_order(self):
        erl = EvidenceRevocationList(
            1, 9, 25.0, (self.entry,), b"\x01" * 32
        )
        self.assertEqual(
            (
                erl.version,
                erl.sequence,
                erl.issued_at,
                erl.entries,
                erl.mac,
            ),
            (1, 9, 25.0, (self.entry,), b"\x01" * 32),
        )

    def test_empty_entries_allowed(self):
        self.assertEqual(self.make(entries=()).entries, ())

    def test_version_shape_and_value(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)
        for bad in ("1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(version=bad)
        with self.assertRaises(TypeError):
            self.make(version=True)

    def test_sequence_shape_and_value(self):
        for good in (0, 1, 0xFFFFFFFFFFFFFFFF):
            self.assertEqual(self.make(sequence=good).sequence, good)
        for bad in ("1", 1.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(sequence=bad)
        for bad in (-1, 0x10000000000000000):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(sequence=bad)

    def test_issued_at_shape_value_and_float_coercion(self):
        erl = self.make(issued_at=5)
        self.assertEqual(erl.issued_at, 5.0)
        self.assertIs(type(erl.issued_at), float)
        self.assertEqual(self.make(issued_at=0).issued_at, 0.0)
        for bad in ("1", None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(issued_at=bad)
        for bad in (-0.1, float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(issued_at=bad)

    def test_entries_must_be_tuple_of_bound_evidence_revocation(self):
        for bad in (None, "entries", 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(entries=bad)
        # A list is a shape error even when its contents are right.
        with self.assertRaises(TypeError):
            self.make(entries=[self.entry])
        with self.assertRaises(TypeError):
            self.make(entries=(self.entry.to_bytes(),))
        with self.assertRaises(TypeError):
            self.make(entries=(signed_entry(self.records[0]), None))

    def test_entries_must_be_sorted_without_duplicates(self):
        r0 = revocation(self.records[0])
        r1 = revocation(self.records[1])
        pair = sorted(
            [r0, r1], key=lambda e: (e.round_index, e.nonce)
        )
        # Not sorted.
        with self.assertRaises(ValueError):
            self.make(entries=tuple(reversed(pair)))
        # Sorted pair constructs.
        self.make(entries=tuple(pair))
        # Duplicate pair (different revoked_at does not change the key).
        dup = dataclasses.replace(r0, revoked_at=99.0)
        with self.assertRaises(ValueError):
            self.make(entries=(r0, dup))

    def test_mac_shape_and_value(self):
        with self.assertRaises(TypeError):
            self.make(mac="00" * 32)
        with self.assertRaises(TypeError):
            self.make(mac=None)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(mac=bad)


class SerializationTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def test_round_trip_empty(self):
        erl = make_evidence_revocation_list([], 1, 100.0, KEY)
        self.assertEqual(EvidenceRevocationList.from_bytes(erl.to_bytes()), erl)

    def test_round_trip_with_entries(self):
        entries = [
            revocation(self.records[2]),
            revocation(self.records[0]),
            revocation(self.records[1]),
        ]
        erl = make_evidence_revocation_list(entries, 2, 5.5, KEY)
        decoded = EvidenceRevocationList.from_bytes(erl.to_bytes())
        self.assertEqual(decoded, erl)
        self.assertEqual(
            [e.round_index for e in decoded.entries],
            sorted(e.round_index for e in entries),
        )

    def test_integer_entry_revoked_at_spelling_round_trips(self):
        # The list issued_at is always a float; nested entry revoked_at keeps
        # its parsed type like BoundEvidenceRevocation itself.
        entry = revocation(self.records[0], revoked_at=3)
        self.assertEqual(entry.revoked_at, 3)
        erl = make_evidence_revocation_list([entry], 0, 0.0, KEY)
        blob = erl.to_bytes()
        self.assertIn(b'"revoked_at":3,', blob)
        self.assertEqual(EvidenceRevocationList.from_bytes(blob), erl)

    def test_canonical_encoding_shape(self):
        entry = revocation(self.records[0])
        erl = make_evidence_revocation_list([entry], 1, 100.0, KEY)
        blob = erl.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj), ["version", "sequence", "issued_at", "entries", "mac"]
        )
        self.assertIsInstance(obj["entries"], list)
        self.assertEqual(
            list(obj["entries"][0]),
            ["version", "round_index", "nonce", "revoked_at", "mac"],
        )
        self.assertEqual(obj["entries"][0]["mac"], entry.mac.hex())

    def _blob(self, *, sequence=1, issued_at=100.0, entries=None,
              mac="00" * 32):
        if entries is None:
            entries = []
        return json.dumps(
            {
                "version": 1,
                "sequence": sequence,
                "issued_at": issued_at,
                "entries": entries,
                "mac": mac,
            },
            separators=(",", ":"),
        ).encode()

    def _entry_blob(self, record, revoked_at=0.0, mac="00" * 32):
        return {
            "version": 1,
            "round_index": record.round_index,
            "nonce": record.nonce.hex(),
            "revoked_at": revoked_at,
            "mac": mac,
        }

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", None, 42, bytearray(b"{}")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationList.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"1", b'"s"', b"null", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationList.from_bytes(bad)

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["entries"]
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_outer_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"sequence":2}'
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_entries_must_be_array(self):
        sentinel = object()

        def blob(entries=sentinel):
            if entries is sentinel:
                entries = []
            return json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "issued_at": 100.0,
                    "entries": entries,
                    "mac": "00" * 32,
                },
                separators=(",", ":"),
            ).encode()

        for bad in ({}, "x", 1, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationList.from_bytes(blob(entries=bad))

    def test_entry_key_set_enforced(self):
        good = self._entry_blob(self.records[0])
        broken = dict(good)
        del broken["mac"]
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[broken]))
        broken = dict(good)
        broken["extra"] = 1
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[broken]))
        with self.assertRaises(ValueError):
            reordered = {
                "round_index": good["round_index"],
                "version": 1,
                "nonce": good["nonce"],
                "revoked_at": 0.0,
                "mac": good["mac"],
            }
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[reordered])
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[1]))

    def test_bad_sequence_in_bytes(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(sequence=-1))
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(sequence=True))
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(sequence=0x10000000000000000)
            )

    def test_bad_issued_at_in_bytes(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(issued_at=-1))
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(issued_at=True))

    def test_integer_issued_at_spelling_is_not_canonical(self):
        erl = EvidenceRevocationList(1, 0, 5, (), b"\x00" * 32)
        canonical = erl.to_bytes()
        self.assertIn(b"5.0", canonical)
        self.assertEqual(
            EvidenceRevocationList.from_bytes(canonical).issued_at, 5.0
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(canonical.replace(b"5.0", b"5"))

    def test_unsorted_and_duplicate_entries_in_bytes_rejected(self):
        a = self._entry_blob(self.records[0])
        b = self._entry_blob(self.records[1])
        ordered = sorted(
            [a, b], key=lambda e: (e["round_index"], bytes.fromhex(e["nonce"]))
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=list(reversed(ordered)))
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[a, dict(a)]))

    def test_entry_wrong_field_shape_is_value_error(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(self.records[0], mac=123)])
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(self.records[0], mac=None)])
            )

    def test_mac_encoding(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(mac="00" * 31))
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(mac="ZZ" * 32))

    def test_whitespace_and_framing_rejected(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(blob.replace(b",", b", ", 1))
        for bad in (b" " + blob, blob + b"\n", bytes([len(blob)]) + blob):
            with self.assertRaises(ValueError, msg=repr(bad[:8])):
                EvidenceRevocationList.from_bytes(bad)

    def test_from_bytes_does_not_verify_any_mac(self):
        entry = self._entry_blob(self.records[0], mac="01" * 32)
        record = EvidenceRevocationList.from_bytes(
            self._blob(entries=[entry])
        )
        self.assertEqual(record.mac, b"\x00" * 32)
        self.assertEqual(record.entries[0].mac, b"\x01" * 32)


class MakeEvidenceRevocationListTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def test_signs_empty_list(self):
        erl = make_evidence_revocation_list([], 3, 100.0, KEY)
        self.assertIsInstance(erl, EvidenceRevocationList)
        self.assertEqual((erl.version, erl.sequence, erl.issued_at),
                         (1, 3, 100.0))
        self.assertEqual(erl.entries, ())
        self.assertEqual(len(erl.mac), 32)
        self.assertNotEqual(erl.mac, b"\x00" * 32)

    def test_sorts_entries(self):
        entries = [
            revocation(self.records[2]),
            revocation(self.records[0]),
            revocation(self.records[1]),
        ]
        erl = make_evidence_revocation_list(entries, 0, 0.0, KEY)
        keys = [(e.round_index, e.nonce) for e in erl.entries]
        self.assertEqual(keys, sorted(keys))

    def test_mac_uses_nperl1_prefix_and_canonical_payload(self):
        r0 = revocation(self.records[0], revoked_at=4.0)
        r1 = revocation(self.records[1], revoked_at=9.0)
        erl = make_evidence_revocation_list([r1, r0], 4, 9.0, KEY)

        def entry_payload(entry):
            return {
                "version": 1,
                "round_index": entry.round_index,
                "nonce": entry.nonce.hex(),
                "revoked_at": entry.revoked_at,
                "mac": entry.mac.hex(),
            }

        ordered = sorted(
            [r0, r1], key=lambda e: (e.round_index, e.nonce)
        )
        payload = {
            "version": 1,
            "sequence": 4,
            "issued_at": 9.0,
            "entries": [entry_payload(entry) for entry in ordered],
        }
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(KEY, b"NPERL1" + encoding, hashlib.sha256).digest()
        self.assertEqual(erl.mac, expected)

    def test_prefix_has_no_length_prefix(self):
        erl = make_evidence_revocation_list([], 0, 0.0, KEY)
        payload = json.dumps(
            {"version": 1, "sequence": 0, "issued_at": 0.0, "entries": []},
            separators=(",", ":"),
        ).encode("utf-8")
        forged = hmac.new(
            KEY, b"NPERL1" + str(len(payload)).encode() + payload,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(erl.mac, forged)

    def test_different_keys_give_different_macs(self):
        self.assertNotEqual(
            make_evidence_revocation_list([], 0, 0.0, KEY).mac,
            make_evidence_revocation_list([], 0, 0.0, OTHER_KEY).mac,
        )

    def test_is_pure_data(self):
        entries = [revocation(self.records[0])]
        first = make_evidence_revocation_list(entries, 1, 1.0, KEY)
        second = make_evidence_revocation_list(entries, 1, 1.0, KEY)
        self.assertEqual(first, second)

    def test_entry_macs_carried_through(self):
        entry = revocation(self.records[0], revoked_at=3.5)
        erl = make_evidence_revocation_list([entry], 0, 0.0, KEY)
        self.assertEqual(erl.entries[0].mac, entry.mac)

    def test_duplicate_pair_rejected(self):
        entry = revocation(self.records[0])
        duplicate = dataclasses.replace(entry, revoked_at=11.0)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([entry, duplicate], 0, 0.0, KEY)

    def test_items_must_be_bound_evidence_revocations(self):
        for bad in ([b"x"], [None], [42], [self.records[0]], ["revocation"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_evidence_revocation_list(bad, 0, 0.0, KEY)

    def test_non_iterable_items_rejected(self):
        with self.assertRaises(TypeError):
            make_evidence_revocation_list(42, 0, 0.0, KEY)

    def test_sequence_contract(self):
        with self.assertRaises(TypeError):
            make_evidence_revocation_list([], True, 0.0, KEY)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], -1, 0.0, KEY)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list(
                [], 0x10000000000000000, 0.0, KEY
            )

    def test_issued_at_contract(self):
        with self.assertRaises(TypeError):
            make_evidence_revocation_list([], 0, True, KEY)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], 0, -0.5, KEY)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], 0, float("nan"), KEY)

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], 0, 0.0, b"")
        for bad in (bytearray(KEY), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_evidence_revocation_list([], 0, 0.0, bad)


class AuditEvidenceRevocationListTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def _erl(self, entries=(), *, sequence=1, issued_at=100.0, key=KEY):
        return make_evidence_revocation_list(
            list(entries), sequence, issued_at, key
        )

    def test_accepts_object_and_bytes(self):
        erl = self._erl()
        self.assertIsNone(audit_evidence_revocation_list(erl, KEY, 100.0))
        self.assertIsNone(audit_evidence_revocation_list(erl.to_bytes(), KEY, 100.0))

    def test_boundary_issued_at_equals_now(self):
        self.assertIsNone(
            audit_evidence_revocation_list(self._erl(issued_at=10.0), KEY, 10.0)
        )

    def test_boundary_sequence_equals_min(self):
        erl = self._erl(sequence=5)
        self.assertIsNone(audit_evidence_revocation_list(erl, KEY, 100.0, min=5))
        self.assertIsNone(audit_evidence_revocation_list(erl, KEY, 100.0, min=0))

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(self._erl(), OTHER_KEY, 100.0)

    def test_future_issued_at_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(
                self._erl(issued_at=100.0001), KEY, 100.0
            )

    def test_sequence_below_min_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(
                self._erl(sequence=4), KEY, 100.0, min=5
            )

    def test_inner_entry_mac_checked(self):
        bogus = signed_entry(self.records[0], mac=b"\x01" * 32)
        placeholder = EvidenceRevocationList(
            1, 0, 0.0, (bogus,), b"\x00" * 32
        )
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": 0.0,
            "entries": [
                {
                    "version": 1,
                    "round_index": bogus.round_index,
                    "nonce": bogus.nonce.hex(),
                    "revoked_at": 0.0,
                    "mac": "01" * 32,
                }
            ],
        }
        outer = hmac.new(
            KEY,
            b"NPERL1"
            + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(placeholder, mac=outer)
        with self.assertRaisesRegex(ValueError, "bound evidence revocation mac"):
            audit_evidence_revocation_list(forged, KEY, 100.0)

    def test_entry_signed_under_other_key_rejected(self):
        erl = self._erl(
            [revocation(self.records[0], key=OTHER_KEY)]
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(erl, KEY, 100.0)

    def test_tampered_list_bytes_rejected(self):
        blob = self._erl(sequence=1).to_bytes()
        tampered = blob.replace(b'"sequence":1', b'"sequence":2')
        self.assertNotEqual(tampered, blob)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(tampered, KEY, 100.0)

    def test_bad_x_type(self):
        for bad in (None, 42, object(), [], revocation(self.records[0])):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                audit_evidence_revocation_list(bad, KEY, 100.0)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(b"not json", KEY, 100.0)

    def test_bad_now(self):
        erl = self._erl()
        for bad in ("100", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_evidence_revocation_list(erl, KEY, bad)

    def test_bad_min(self):
        erl = self._erl()
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_evidence_revocation_list(erl, KEY, 100.0, min=bad)

    def test_key_contract(self):
        erl = self._erl()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(erl, b"", 100.0)
        for bad in (bytearray(KEY), None, "key"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list(erl, bad, 100.0)


class PolicySnapshotTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, records = make_evidence_list(7)
        self.used = records[:6]
        self.foreign_record = records[6]
        self.evidence = seal_assess_evidence(self.used, 100.0, KEY)
        self.data = self.evidence.to_bytes()
        self.latest_end = max(record.end for record in self.used)
        self.now = self.latest_end + 1.0
        self.decision = audit_assess_evidence(self.evidence, KEY)

    def _snapshot(self, entries, *, sequence=0, issued_at=None, key=KEY):
        return make_evidence_revocation_list(
            entries, sequence, self.now if issued_at is None else issued_at, key
        )

    def test_empty_snapshot_leaves_decision_unchanged(self):
        erl = self._snapshot([], issued_at=0.0)
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.data, KEY, now=self.now, revocations=erl.to_bytes()
            ),
            self.decision,
        )

    def test_snapshot_requires_now(self):
        erl = self._snapshot([], issued_at=0.0)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(self.evidence, KEY, revocations=erl)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, revocations=erl.to_bytes()
            )

    def test_hit_voids_object_and_bytes(self):
        target = self.used[0]
        erl = self._snapshot([revocation(target, target.end)])
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl.to_bytes()
            )

    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        erl = self._snapshot([revocation(target, target.end - 1e-9)])
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        erl = self._snapshot([revocation(target, target.end)])
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_non_matching_entries_are_ignored(self):
        erl = self._snapshot(
            [revocation(self.foreign_record, 0.0)], issued_at=0.0
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )

    def test_mixed_matching_and_non_matching_entries(self):
        target = self.used[0]
        erl = self._snapshot(
            [
                revocation(target, target.end - 1e-9),
                revocation(self.foreign_record, 0.0),
            ],
            issued_at=0.0,
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )
        voiding = self._snapshot(
            [
                revocation(target, target.end),
                revocation(self.foreign_record, 0.0),
            ],
            issued_at=0.0,
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=voiding
            )

    def test_min_floor_enforced_default_zero(self):
        erl = self._snapshot([], sequence=3)
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl, min=3
            ),
            self.decision,
        )
        # The floor defaults to 0.
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl, min=4
            )

    def test_bad_min_rejected(self):
        erl = self._snapshot([], issued_at=0.0)
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now,
                    revocations=erl, min=bad,
                )

    def test_future_snapshot_rejected(self):
        erl = self._snapshot([], issued_at=self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_wrong_key_rejected(self):
        erl = self._snapshot([], key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_malformed_snapshot_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=b"not json"
            )

    def test_inner_entry_mac_checked(self):
        target = self.used[0]
        bogus = signed_entry(target, mac=b"\x01" * 32)
        placeholder = EvidenceRevocationList(
            1, 0, float(self.now), (bogus,), b"\x00" * 32
        )
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": float(self.now),
            "entries": [
                {
                    "version": 1,
                    "round_index": bogus.round_index,
                    "nonce": bogus.nonce.hex(),
                    "revoked_at": 0.0,
                    "mac": "01" * 32,
                }
            ],
        }
        outer = hmac.new(
            KEY,
            b"NPERL1"
            + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(placeholder, mac=outer)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=forged
            )

    def test_age_and_snapshot_enforced_together(self):
        target = self.used[0]
        surviving = self._snapshot(
            [revocation(target, target.end - 1e-9)], issued_at=0.0
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, max_age=0.5,
                revocations=surviving,
            )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, max_age=10.0,
                revocations=surviving,
            ),
            self.decision,
        )

    def test_legacy_iterable_path_unchanged(self):
        target = self.used[0]
        entry = revocation(target, target.end)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[entry]
            )
        surviving = revocation(target, target.end - 1e-9)
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[surviving]
            ),
            self.decision,
        )
        # An empty iterable still requires now, exactly as before.
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(self.evidence, KEY, revocations=[])
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[]
            ),
            self.decision,
        )
        # min is meaningless for the legacy iterable (it has no sequence)
        # and is ignored there, mirroring the locate_cert legacy path.
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[], min=999
            ),
            self.decision,
        )

    def test_snapshot_check_is_pure(self):
        erl = self._snapshot([], issued_at=0.0)
        audit_evidence_revocation_list(erl, KEY, self.now)
        audit_assess_evidence_policy(
            self.evidence, KEY, now=self.now, revocations=erl
        )


if __name__ == "__main__":
    unittest.main()
