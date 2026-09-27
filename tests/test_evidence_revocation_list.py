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
    context_digest,
    make_evidence_revocation_list,
    revoke_evidence,
    seal_assess_evidence,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


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


def revocation(record, revoked_at=0.0, *, key=KEY):
    return revoke_evidence(record, revoked_at, key)


def signed_entry(round_index, nonce, revoked_at=0.0, *, mac=b"\x00" * 32):
    return BoundEvidenceRevocation(1, round_index, nonce, revoked_at, mac)


class EvidenceRevocationListContractTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, records = make_evidence_list(3)
        self.entries = tuple(
            revocation(record, float(index)) for index, record in enumerate(records)
        )

    def make(self, **overrides):
        values = {
            "version": 1,
            "sequence": 7,
            "issued_at": 100.0,
            "entries": self.entries[:1],
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
        first = make_evidence_revocation_list(self.entries, 3, 50.0, KEY)
        second = EvidenceRevocationList(
            1, 3, 50.0, tuple(first.entries), bytes(first.mac)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 4

    def test_positional_field_order(self):
        snapshot = EvidenceRevocationList(
            1, 9, 25.0, self.entries[:1], b"\x01" * 32
        )
        self.assertEqual(
            (
                snapshot.version,
                snapshot.sequence,
                snapshot.issued_at,
                snapshot.entries,
                snapshot.mac,
            ),
            (1, 9, 25.0, self.entries[:1], b"\x01" * 32),
        )

    def test_empty_entries_allowed(self):
        snapshot = self.make(entries=())
        self.assertEqual(snapshot.entries, ())

    def test_version_wrong_type_is_type_error(self):
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(version=bad)

    def test_version_wrong_value_is_value_error(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)

    def test_sequence_wrong_type_is_type_error(self):
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(sequence=bad)

    def test_sequence_contract(self):
        for good in (0, 1, 0xFFFFFFFFFFFFFFFF):
            self.assertEqual(self.make(sequence=good).sequence, good)
        for bad in (-1, 0x10000000000000000):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(sequence=bad)

    def test_issued_at_wrong_type_is_type_error(self):
        for bad in (True, False, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(issued_at=bad)

    def test_issued_at_contract_and_float_coercion(self):
        snapshot = self.make(issued_at=5)
        self.assertEqual(snapshot.issued_at, 5.0)
        self.assertIs(type(snapshot.issued_at), float)
        self.assertEqual(self.make(issued_at=0).issued_at, 0.0)
        for bad in (-0.1, float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(issued_at=bad)

    def test_entries_wrong_shape_is_type_error(self):
        for bad in ([], list(self.entries), None, "entries", 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(entries=bad)
        with self.assertRaises(TypeError):
            self.make(entries=(self.entries[0].to_bytes(),))
        with self.assertRaises(TypeError):
            self.make(entries=(self.entries[0], None))

    def test_entries_must_be_sorted_without_duplicates(self):
        first, second, third = self.entries
        # Not sorted: later round before earlier.
        with self.assertRaises(ValueError):
            self.make(entries=(second, first))
        # Same round_index, two different nonces: exactly one ordering sorts.
        other = signed_entry(first.round_index, b"\xaa" * 16)
        pair = [first, other]
        ordered = tuple(
            sorted(pair, key=lambda entry: (entry.round_index, entry.nonce))
        )
        self.make(entries=ordered)
        with self.assertRaises(ValueError):
            self.make(entries=tuple(reversed(ordered)))
        # Duplicate pair.
        with self.assertRaises(ValueError):
            self.make(
                entries=(
                    first,
                    BoundEvidenceRevocation.from_bytes(first.to_bytes()),
                )
            )
        # Three well-formed sorted entries are fine.
        self.make(entries=(first, second, third))

    def test_mac_wrong_type_is_type_error(self):
        for bad in ("00" * 32, None, bytearray(32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(mac=bad)

    def test_mac_wrong_length_is_value_error(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(mac=bad)


class SerializationTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, records = make_evidence_list(3)
        self.records = records
        self.entries = [
            revocation(record, float(index)) for index, record in enumerate(records)
        ]

    def test_round_trip_empty(self):
        snapshot = make_evidence_revocation_list([], 1, 100.0, KEY)
        self.assertEqual(
            EvidenceRevocationList.from_bytes(snapshot.to_bytes()), snapshot
        )

    def test_round_trip_with_entries(self):
        snapshot = make_evidence_revocation_list(
            list(reversed(self.entries)), 2, 5.5, KEY
        )
        decoded = EvidenceRevocationList.from_bytes(snapshot.to_bytes())
        self.assertEqual(decoded, snapshot)
        self.assertEqual(
            [(entry.round_index, entry.nonce) for entry in decoded.entries],
            [(entry.round_index, entry.nonce) for entry in self.entries],
        )

    def test_canonical_encoding_shape(self):
        snapshot = make_evidence_revocation_list(self.entries[:1], 1, 100.0, KEY)
        blob = snapshot.to_bytes()
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
        self.assertEqual(obj["entries"][0]["mac"], self.entries[0].mac.hex())

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

    def _entry_blob(self, round_index=1, nonce="ab" * 16, revoked_at=0.0,
                    mac="00" * 32):
        return {
            "version": 1,
            "round_index": round_index,
            "nonce": nonce,
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
        good = self._entry_blob()
        # Missing entry key.
        broken = dict(good)
        del broken["mac"]
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[broken]))
        # Extra entry key.
        broken = dict(good)
        broken["extra"] = 1
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[broken]))
        # Duplicate entry key, built as raw text (json.dumps cannot carry a
        # hand-written duplicate-key object).
        duplicate_entry = (
            b'{"version":1,"round_index":1,"nonce":"' + b"ab" * 16
            + b'","revoked_at":0.0,"mac":"' + b"00" * 32
            + b'","mac":"' + b"01" * 32 + b'"}'
        )
        raw = (
            b'{"version":1,"sequence":1,"issued_at":100.0,"entries":['
            + duplicate_entry
            + b'],"mac":"' + b"00" * 32 + b'"}'
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(raw)
        # Out-of-order entry keys.
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(
                    entries=[
                        {
                            "version": 1,
                            "nonce": "ab" * 16,
                            "round_index": 1,
                            "revoked_at": 0.0,
                            "mac": "00" * 32,
                        }
                    ]
                )
            )
        # Entry is not an object.
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
        # The constructor stores issued_at as float, so the float spelling
        # round-trips while the integer spelling does not.
        snapshot = EvidenceRevocationList(1, 0, 5, (), b"\x00" * 32)
        canonical = snapshot.to_bytes()
        self.assertIn(b"5.0", canonical)
        self.assertEqual(
            EvidenceRevocationList.from_bytes(canonical).issued_at, 5.0
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(canonical.replace(b"5.0", b"5"))

    def test_unsorted_and_duplicate_entries_in_bytes_rejected(self):
        a = self._entry_blob(1, "aa" * 16)
        b = self._entry_blob(2, "bb" * 16)
        same_round_a = self._entry_blob(1, "aa" * 16)
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(self._blob(entries=[b, a]))
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[a, dict(same_round_a)])
            )

    def test_entry_wrong_field_shape_is_value_error(self):
        # Non-bytes input is the only TypeError from from_bytes; a nested
        # entry whose field has the wrong shape makes the encoding
        # non-canonical (ValueError).
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(round_index="1")])
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(nonce=123)])
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(revoked_at=None)])
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
        entry = self._entry_blob(mac="01" * 32)
        record = EvidenceRevocationList.from_bytes(self._blob(entries=[entry]))
        self.assertEqual(record.mac, b"\x00" * 32)
        self.assertEqual(record.entries[0].mac, b"\x01" * 32)


class MakeEvidenceRevocationListTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, records = make_evidence_list(3)
        self.entries = [
            revocation(record, float(index)) for index, record in enumerate(records)
        ]

    def test_signs_empty_list(self):
        snapshot = make_evidence_revocation_list([], 3, 100.0, KEY)
        self.assertIsInstance(snapshot, EvidenceRevocationList)
        self.assertEqual(snapshot.version, 1)
        self.assertEqual(snapshot.sequence, 3)
        self.assertEqual(snapshot.issued_at, 100.0)
        self.assertIs(type(snapshot.issued_at), float)
        self.assertEqual(snapshot.entries, ())
        self.assertEqual(len(snapshot.mac), 32)
        self.assertNotEqual(snapshot.mac, b"\x00" * 32)

    def test_sorts_entries(self):
        snapshot = make_evidence_revocation_list(
            list(reversed(self.entries)), 0, 0.0, KEY
        )
        pairs = [(entry.round_index, entry.nonce) for entry in snapshot.entries]
        self.assertEqual(
            pairs, [(entry.round_index, entry.nonce) for entry in self.entries]
        )

    def test_integer_time_stored_as_float(self):
        snapshot = make_evidence_revocation_list([], 0, 7, KEY)
        self.assertEqual(snapshot.issued_at, 7.0)
        self.assertIs(type(snapshot.issued_at), float)

    def test_mac_uses_nperl1_prefix_and_canonical_payload(self):
        snapshot = make_evidence_revocation_list(
            list(reversed(self.entries[:2])), 4, 9.0, KEY
        )
        payload = {
            "version": 1,
            "sequence": 4,
            "issued_at": 9.0,
            "entries": [
                {
                    "version": 1,
                    "round_index": entry.round_index,
                    "nonce": entry.nonce.hex(),
                    "revoked_at": entry.revoked_at,
                    "mac": entry.mac.hex(),
                }
                for entry in sorted(
                    self.entries[:2],
                    key=lambda entry: (entry.round_index, entry.nonce),
                )
            ],
        }
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(KEY, b"NPERL1" + encoding, hashlib.sha256).digest()
        self.assertEqual(snapshot.mac, expected)

    def test_prefix_has_no_length_prefix(self):
        snapshot = make_evidence_revocation_list([], 0, 0.0, KEY)
        payload = json.dumps(
            {"version": 1, "sequence": 0, "issued_at": 0.0, "entries": []},
            separators=(",", ":"),
        ).encode("utf-8")
        forged = hmac.new(
            KEY, b"NPERL1" + str(len(payload)).encode() + payload,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(snapshot.mac, forged)

    def test_domain_separated_from_trust_list_prefix(self):
        # NPERL1 must not be the trust-list tag (or any other existing tag).
        snapshot = make_evidence_revocation_list([], 0, 0.0, KEY)
        payload = json.dumps(
            {"version": 1, "sequence": 0, "issued_at": 0.0, "entries": []},
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertNotEqual(
            snapshot.mac,
            hmac.new(KEY, b"NPVRL1" + payload, hashlib.sha256).digest(),
        )

    def test_different_keys_give_different_macs(self):
        self.assertNotEqual(
            make_evidence_revocation_list([], 0, 0.0, KEY).mac,
            make_evidence_revocation_list([], 0, 0.0, OTHER_KEY).mac,
        )

    def test_is_pure_data(self):
        entries = list(self.entries)
        first = make_evidence_revocation_list(entries, 1, 1.0, KEY)
        second = make_evidence_revocation_list(entries, 1, 1.0, KEY)
        self.assertEqual(first, second)

    def test_entry_macs_carried_through_unchanged(self):
        snapshot = make_evidence_revocation_list(self.entries, 1, 1.0, KEY)
        self.assertEqual(
            [entry.mac for entry in snapshot.entries],
            [entry.mac for entry in self.entries],
        )

    def test_duplicate_pair_rejected(self):
        entry = self.entries[0]
        with self.assertRaises(ValueError):
            make_evidence_revocation_list(
                [entry, BoundEvidenceRevocation.from_bytes(entry.to_bytes())],
                0, 0.0, KEY,
            )

    def test_items_must_be_bound_evidence_revocations(self):
        for bad in (
            [b"x"],
            [None],
            [42],
            [self.entries[0].to_bytes()],
            ["revocation"],
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_evidence_revocation_list(bad, 0, 0.0, KEY)

    def test_non_iterable_items_rejected(self):
        for bad in (42, 1.5, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_evidence_revocation_list(bad, 0, 0.0, KEY)

    def test_sequence_violations_are_value_errors(self):
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], True, 0.0, KEY)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], -1, 0.0, KEY)
        with self.assertRaises(ValueError):
            make_evidence_revocation_list(
                [], 0x10000000000000000, 0.0, KEY
            )
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], 1.0, 0.0, KEY)

    def test_time_violations_are_value_errors(self):
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], 0, -0.5, KEY)
        for bad in (True, math.nan, math.inf, "1", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_evidence_revocation_list([], 0, bad, KEY)

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            make_evidence_revocation_list([], 0, 0.0, b"")
        for bad in (bytearray(KEY), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_evidence_revocation_list([], 0, 0.0, bad)


class AuditEvidenceRevocationListTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, records = make_evidence_list(3)
        self.entries = [
            revocation(record, 0.0) for record in records
        ]

    def _snapshot(self, entries=(), *, sequence=1, issued_at=100.0, key=KEY):
        return make_evidence_revocation_list(list(entries), sequence, issued_at, key)

    def test_accepts_object_and_bytes(self):
        snapshot = self._snapshot()
        self.assertIsNone(audit_evidence_revocation_list(snapshot, KEY, 100.0))
        self.assertIsNone(
            audit_evidence_revocation_list(snapshot.to_bytes(), KEY, 100.0)
        )

    def test_boundary_issued_at_equals_now(self):
        self.assertIsNone(
            audit_evidence_revocation_list(self._snapshot(issued_at=10.0), KEY, 10.0)
        )

    def test_boundary_sequence_equals_min_and_default_zero(self):
        snapshot = self._snapshot(sequence=5)
        self.assertIsNone(audit_evidence_revocation_list(snapshot, KEY, 100.0))
        self.assertIsNone(
            audit_evidence_revocation_list(snapshot, KEY, 100.0, min=5)
        )

    def test_with_entries(self):
        snapshot = self._snapshot(self.entries)
        self.assertIsNone(audit_evidence_revocation_list(snapshot, KEY, 100.0))
        self.assertIsNone(
            audit_evidence_revocation_list(snapshot.to_bytes(), KEY, 100.0)
        )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(self._snapshot(), OTHER_KEY, 100.0)

    def test_future_issued_at_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(
                self._snapshot(issued_at=100.0001), KEY, 100.0
            )

    def test_sequence_below_min_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(
                self._snapshot(sequence=4), KEY, 100.0, min=5
            )

    def test_inner_entry_mac_checked(self):
        # Outer list MAC valid under KEY, but its entry carries a bogus
        # entry MAC: the second MAC layer must catch it.
        entry = self.entries[0]
        bogus = signed_entry(
            entry.round_index, entry.nonce, entry.revoked_at, mac=b"\x01" * 32
        )
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
                    "round_index": entry.round_index,
                    "nonce": entry.nonce.hex(),
                    "revoked_at": entry.revoked_at,
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
            audit_evidence_revocation_list(forged, KEY, 0.0)

    def test_entry_signed_under_other_key_rejected(self):
        # The list MAC is valid under KEY, but the entry carries an NPBR1 MAC
        # minted under OTHER_KEY: the second MAC layer must reject it.
        _verifier, _prover, other_records = make_evidence_list(1, key=OTHER_KEY)
        entry = revocation(other_records[0], 0.0, key=OTHER_KEY)
        snapshot = self._snapshot([entry])
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(snapshot, KEY, 100.0)

    def test_tampered_list_bytes_rejected(self):
        blob = self._snapshot(sequence=1).to_bytes()
        tampered = blob.replace(b'"sequence":1', b'"sequence":2')
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(tampered, KEY, 100.0)

    def test_bad_x_type(self):
        for bad in (None, 42, object(), [], self.entries[0]):
            with self.assertRaises(ValueError, msg=repr(type(bad))):
                audit_evidence_revocation_list(bad, KEY, 100.0)

    def test_bad_now(self):
        snapshot = self._snapshot()
        for bad in ("100", None, True, False, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_evidence_revocation_list(snapshot, KEY, bad)

    def test_bad_min(self):
        snapshot = self._snapshot()
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_evidence_revocation_list(snapshot, KEY, 100.0, min=bad)

    def test_key_contract(self):
        snapshot = self._snapshot()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(snapshot, b"", 100.0)
        for bad in (bytearray(KEY), None, "key"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list(snapshot, bad, 100.0)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list(b"not json", KEY, 100.0)


class PolicySnapshotTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.prover, self.records = make_evidence_list(7)
        self.used = self.records[:6]
        self.evidence = seal_assess_evidence(self.used, 100.0, KEY)
        self.data = self.evidence.to_bytes()
        self.latest_end = max(record.end for record in self.used)
        self.now = self.latest_end + 1.0
        self.decision = audit_assess_evidence(self.evidence, KEY)

    def _snapshot(self, entries, *, sequence=1, issued_at=None, key=KEY):
        return make_evidence_revocation_list(
            entries, sequence, self.now if issued_at is None else issued_at, key
        )

    def test_empty_snapshot_leaves_decision_unchanged(self):
        snapshot = self._snapshot([])
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            ),
            self.decision,
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.data, KEY, now=self.now, revocations=snapshot.to_bytes()
            ),
            self.decision,
        )

    def test_snapshot_requires_now(self):
        snapshot = self._snapshot([])
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(self.evidence, KEY, revocations=snapshot)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, revocations=snapshot.to_bytes()
            )

    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        snapshot = self._snapshot(
            [revoke_evidence(target, target.end - 1e-9, KEY)]
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            ),
            self.decision,
        )

    def test_sample_completed_at_revocation_moment_voids(self):
        target = self.used[0]
        snapshot = self._snapshot([revoke_evidence(target, target.end, KEY)])
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.data, KEY, now=self.now, revocations=snapshot.to_bytes()
            )

    def test_sample_completed_before_revocation_moment_voids(self):
        target = self.used[0]
        snapshot = self._snapshot(
            [revoke_evidence(target, target.end + 10.0, KEY)],
            issued_at=target.end + 20.0,
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=target.end + 20.0, revocations=snapshot
            )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        snapshot = self._snapshot([revoke_evidence(target, target.end, KEY)])
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )

    def test_non_matching_entries_are_ignored(self):
        # records[6] is not carried by the sealed decision.
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        snapshot = self._snapshot([foreign], issued_at=0.0)
        for artifact in (snapshot, snapshot.to_bytes()):
            self.assertEqual(
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=artifact
                ),
                self.decision,
            )

    def test_snapshot_entries_are_sorted_by_the_maker(self):
        # Unsorted input is sorted by the maker; hits and misses coexist.
        entries = [
            revoke_evidence(self.records[6], 0.0, KEY),
            revoke_evidence(self.used[2], self.used[2].end - 1e-9, KEY),
            revoke_evidence(self.used[0], 0.0, KEY),
        ]
        snapshot = self._snapshot(entries)
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            ),
            self.decision,
        )

    def test_wrong_key_rejected(self):
        snapshot = self._snapshot([], key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )

    def test_future_snapshot_rejected(self):
        snapshot = self._snapshot([], issued_at=self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )

    def test_entry_signed_under_other_key_rejected(self):
        foreign = revoke_evidence(self.records[6], 0.0, OTHER_KEY)
        snapshot = make_evidence_revocation_list([foreign], 1, 0.0, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )

    def test_tampered_snapshot_bytes_rejected(self):
        snapshot = self._snapshot([])
        blob = bytearray(snapshot.to_bytes())
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=bytes(blob)
            )

    def test_malformed_snapshot_bytes_rejected(self):
        for bad in (b"not json", b"{}", b"[]", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_bad_now_with_snapshot_rejected(self):
        snapshot = self._snapshot([])
        for bad in ("1", True, False, math.nan, math.inf):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=bad, revocations=snapshot
                )

    def test_snapshot_vetoes_even_without_max_age(self):
        # The snapshot path works with revocations alone; no max_age needed.
        target = self.used[0]
        snapshot = self._snapshot([revoke_evidence(target, target.end, KEY)])
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )

    def test_legacy_iterable_path_unchanged(self):
        # Empty iterable still requires now; hits and misses behave as before.
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, revocations=[]
            )
        target = self.used[0]
        surviving = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[surviving],
            ),
            self.decision,
        )
        voiding = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[voiding]
            )

    def test_non_snapshot_non_iterable_rejected(self):
        for bad in (7, 1.5, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        snapshot = self._snapshot([])
        audit_assess_evidence_policy(
            self.evidence, KEY, now=self.now, revocations=snapshot
        )
        audit_assess_evidence_policy(
            self.evidence,
            KEY,
            now=self.now,
            revocations=snapshot.to_bytes(),
        )
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
