import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    RangeDecision,
    TrustRevocation,
    TrustRevocationList,
    attest_observation_for_point,
    audit_crl,
    cert,
    locate_cert,
    make_crl,
    revoke_trust,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, root=ROOT, key=None, x=None, y=None):
    px, py = POSITIONS[ident]
    return cert(ident, x if x is not None else px, y if y is not None else py,
                key or KEYS[ident], root)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), point, context, 0.0,
        key or KEYS[ident],
    )


def triangle_records():
    return [record("a"), record("b"), record("c")]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


def revocation(ident, *, root=ROOT):
    return revoke_trust(trust(ident, root=root), root)


def signed_entry(ident, target=None, *, root=ROOT, mac=b"\x00" * 32):
    return TrustRevocation(1, ident, target if target is not None else trust(ident).mac, mac)


class TrustRevocationListContractTest(unittest.TestCase):
    def make(self, **overrides):
        values = {
            "version": 1,
            "sequence": 7,
            "issued_at": 100.0,
            "entries": (revocation("a"),),
            "mac": b"\x00" * 32,
        }
        values.update(overrides)
        return TrustRevocationList(
            values["version"],
            values["sequence"],
            values["issued_at"],
            values["entries"],
            values["mac"],
        )

    def test_is_frozen_and_equal_by_fields(self):
        first = make_crl([revocation("a")], 3, 50.0, ROOT)
        second = TrustRevocationList(
            1, 3, 50.0, tuple(first.entries), bytes(first.mac)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 4

    def test_positional_field_order(self):
        entry = revocation("a")
        crl = TrustRevocationList(1, 9, 25.0, (entry,), b"\x01" * 32)
        self.assertEqual(
            (crl.version, crl.sequence, crl.issued_at, crl.entries, crl.mac),
            (1, 9, 25.0, (entry,), b"\x01" * 32),
        )

    def test_empty_entries_allowed(self):
        crl = self.make(entries=())
        self.assertEqual(crl.entries, ())

    def test_version_must_be_one(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)

    def test_sequence_contract(self):
        for good in (0, 1, 0xFFFFFFFFFFFFFFFF):
            self.assertEqual(self.make(sequence=good).sequence, good)
        for bad in (True, False, 1.0, "1", None, -1,
                    0x10000000000000000):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(sequence=bad)

    def test_issued_at_contract_and_float_coercion(self):
        crl = self.make(issued_at=5)
        self.assertEqual(crl.issued_at, 5.0)
        self.assertIs(type(crl.issued_at), float)
        self.assertEqual(self.make(issued_at=0).issued_at, 0.0)
        for bad in (True, False, "1", None, -0.1, float("nan"),
                    float("inf"), float("-inf")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(issued_at=bad)

    def test_entries_must_be_tuple_of_trust_revocation(self):
        for bad in ([], [revocation("a")], None, "entries", 7):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(entries=bad)
        with self.assertRaises(ValueError):
            self.make(entries=(revocation("a").to_bytes(),))
        with self.assertRaises(ValueError):
            self.make(entries=(signed_entry("a", mac=b"\x01" * 32), None))

    def test_entries_must_be_sorted_without_duplicates(self):
        ra = revocation("a")
        rb = revocation("b")
        other_target = cert("a", 9.0, 9.0, KEY_A, ROOT).mac
        ra_other = signed_entry("a", target=other_target)
        # Not sorted: b before a.
        with self.assertRaises(ValueError):
            self.make(entries=(rb, ra))
        # Same id, two different targets: exactly one ordering is sorted.
        pair = [ra, ra_other]
        ordered = tuple(sorted(pair, key=lambda e: (e.id, e.target)))
        reversed_order = tuple(reversed(ordered))
        self.make(entries=ordered)
        with self.assertRaises(ValueError):
            self.make(entries=reversed_order)
        # Duplicate pair.
        with self.assertRaises(ValueError):
            self.make(entries=(ra, TrustRevocation.from_bytes(ra.to_bytes())))

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "00" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(mac=bad)


class SerializationTest(unittest.TestCase):
    def test_round_trip_empty(self):
        crl = make_crl([], 1, 100.0, ROOT)
        self.assertEqual(TrustRevocationList.from_bytes(crl.to_bytes()), crl)

    def test_round_trip_with_entries(self):
        crl = make_crl([revocation("c"), revocation("a")], 2, 5.5, ROOT)
        decoded = TrustRevocationList.from_bytes(crl.to_bytes())
        self.assertEqual(decoded, crl)
        self.assertEqual([e.id for e in decoded.entries], ["a", "c"])

    def test_canonical_encoding_shape(self):
        crl = make_crl([revocation("a")], 1, 100.0, ROOT)
        blob = crl.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj), ["version", "sequence", "issued_at", "entries", "mac"]
        )
        self.assertIsInstance(obj["entries"], list)
        self.assertEqual(
            list(obj["entries"][0]), ["version", "id", "target", "mac"]
        )
        self.assertEqual(obj["entries"][0]["mac"], revocation("a").mac.hex())

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

    def _entry_blob(self, ident="a", target="ab" * 32, mac="00" * 32):
        return {"version": 1, "id": ident, "target": target, "mac": mac}

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", None, 42, bytearray(b"{}")):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocationList.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"1", b'"s"', b"null", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocationList.from_bytes(bad)

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["entries"]
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_outer_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"sequence":2}'
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
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
                TrustRevocationList.from_bytes(blob(entries=bad))

    def test_entry_key_set_enforced(self):
        good = self._entry_blob()
        # Missing entry key.
        broken = dict(good)
        del broken["mac"]
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[broken]))
        # Extra entry key.
        broken = dict(good)
        broken["extra"] = 1
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[broken]))
        # Out-of-order entry keys.
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                self._blob(entries=[
                    {"id": "a", "version": 1,
                     "target": "ab" * 32, "mac": "00" * 32}
                ])
            )
        # Entry is not an object.
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[1]))

    def test_bad_sequence_in_bytes(self):
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(sequence=-1))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(sequence=True))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                self._blob(sequence=0x10000000000000000)
            )

    def test_bad_issued_at_in_bytes(self):
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(issued_at=-1))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(issued_at=True))

    def test_integer_issued_at_spelling_is_not_canonical(self):
        # The constructor stores issued_at as float, so the float spelling
        # round-trips while the integer spelling does not.
        crl = TrustRevocationList(1, 0, 5, (), b"\x00" * 32)
        canonical = crl.to_bytes()
        self.assertIn(b"5.0", canonical)
        self.assertEqual(
            TrustRevocationList.from_bytes(canonical).issued_at, 5.0
        )
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(canonical.replace(b"5.0", b"5"))

    def test_unsorted_and_duplicate_entries_in_bytes_rejected(self):
        a = self._entry_blob("a")
        b = self._entry_blob("b")
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[b, a]))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[a, dict(a)]))

    def test_entry_wrong_field_shape_is_value_error(self):
        # Non-bytes input is the only TypeError from from_bytes; a nested
        # entry whose field has the wrong shape makes the encoding
        # non-canonical (ValueError).
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(target=123)])
            )
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                self._blob(entries=[self._entry_blob(target=None)])
            )

    def test_mac_encoding(self):
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(mac="00" * 31))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(mac="ZZ" * 32))

    def test_whitespace_and_framing_rejected(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(blob.replace(b",", b", ", 1))
        for bad in (b" " + blob, blob + b"\n", bytes([len(blob)]) + blob):
            with self.assertRaises(ValueError, msg=repr(bad[:8])):
                TrustRevocationList.from_bytes(bad)

    def test_from_bytes_does_not_verify_any_mac(self):
        entry = self._entry_blob(mac="01" * 32)
        record = TrustRevocationList.from_bytes(
            self._blob(entries=[entry])
        )
        self.assertEqual(record.mac, b"\x00" * 32)
        self.assertEqual(record.entries[0].mac, b"\x01" * 32)


class MakeCrlTest(unittest.TestCase):
    def test_signs_empty_list(self):
        crl = make_crl([], 3, 100.0, ROOT)
        self.assertIsInstance(crl, TrustRevocationList)
        self.assertEqual(crl.version, 1)
        self.assertEqual(crl.sequence, 3)
        self.assertEqual(crl.issued_at, 100.0)
        self.assertEqual(crl.entries, ())
        self.assertEqual(len(crl.mac), 32)
        self.assertNotEqual(crl.mac, b"\x00" * 32)

    def test_sorts_entries(self):
        crl = make_crl(
            [revocation("c"), revocation("a"), revocation("b")],
            0, 0.0, ROOT,
        )
        self.assertEqual([e.id for e in crl.entries], ["a", "b", "c"])

    def test_mac_uses_npvrl1_prefix_and_canonical_payload(self):
        ra, rb = revocation("a"), revocation("b")
        crl = make_crl([rb, ra], 4, 9.0, ROOT)
        payload = {
            "version": 1,
            "sequence": 4,
            "issued_at": 9.0,
            "entries": [
                {"version": 1, "id": "a", "target": ra.target.hex(),
                 "mac": ra.mac.hex()},
                {"version": 1, "id": "b", "target": rb.target.hex(),
                 "mac": rb.mac.hex()},
            ],
        }
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(ROOT, b"NPVRL1" + encoding, hashlib.sha256).digest()
        self.assertEqual(crl.mac, expected)

    def test_prefix_has_no_length_prefix(self):
        crl = make_crl([], 0, 0.0, ROOT)
        payload = json.dumps(
            {"version": 1, "sequence": 0, "issued_at": 0.0, "entries": []},
            separators=(",", ":"),
        ).encode("utf-8")
        forged = hmac.new(
            ROOT, b"NPVRL1" + str(len(payload)).encode() + payload,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(crl.mac, forged)

    def test_different_roots_give_different_macs(self):
        self.assertNotEqual(
            make_crl([], 0, 0.0, ROOT).mac,
            make_crl([], 0, 0.0, OTHER_ROOT).mac,
        )

    def test_is_pure_data(self):
        entries = [revocation("a")]
        first = make_crl(entries, 1, 1.0, ROOT)
        second = make_crl(entries, 1, 1.0, ROOT)
        self.assertEqual(first, second)

    def test_duplicate_pair_rejected(self):
        ra = revocation("a")
        with self.assertRaises(ValueError):
            make_crl([ra, TrustRevocation.from_bytes(ra.to_bytes())],
                     0, 0.0, ROOT)

    def test_items_must_be_trust_revocations(self):
        for bad in ([b"x"], [None], [42], [trust("a")], ["revocation"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_crl(bad, 0, 0.0, ROOT)

    def test_non_iterable_items_rejected(self):
        with self.assertRaises(ValueError):
            make_crl(42, 0, 0.0, ROOT)

    def test_field_contracts_passthrough(self):
        with self.assertRaises(ValueError):
            make_crl([], True, 0.0, ROOT)
        with self.assertRaises(ValueError):
            make_crl([], -1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            make_crl([], 0, -0.5, ROOT)

    def test_root_contract(self):
        with self.assertRaises(ValueError):
            make_crl([], 0, 0.0, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_crl([], 0, 0.0, bad)


class AuditCrlTest(unittest.TestCase):
    def _crl(self, entries=(), *, sequence=1, issued_at=100.0, root=ROOT):
        return make_crl(list(entries), sequence, issued_at, root)

    def test_accepts_object_and_bytes(self):
        crl = self._crl()
        self.assertIsNone(audit_crl(crl, ROOT, 100.0))
        self.assertIsNone(audit_crl(crl.to_bytes(), ROOT, 100.0))

    def test_boundary_issued_at_equals_now(self):
        self.assertIsNone(audit_crl(self._crl(issued_at=10.0), ROOT, 10.0))

    def test_boundary_sequence_equals_min(self):
        crl = self._crl(sequence=5)
        self.assertIsNone(audit_crl(crl, ROOT, 100.0, min=5))
        self.assertIsNone(audit_crl(crl, ROOT, 100.0, min=0))

    def test_wrong_root_rejected(self):
        with self.assertRaises(ValueError):
            audit_crl(self._crl(), OTHER_ROOT, 100.0)

    def test_future_issued_at_rejected(self):
        with self.assertRaises(ValueError):
            audit_crl(self._crl(issued_at=100.0001), ROOT, 100.0)

    def test_sequence_below_min_rejected(self):
        with self.assertRaises(ValueError):
            audit_crl(self._crl(sequence=4), ROOT, 100.0, min=5)

    def test_inner_entry_mac_checked(self):
        # Outer list MAC valid under ROOT, but its entry carries a bogus
        # entry MAC: the second MAC layer must catch it.
        target = trust("a").mac
        bogus = TrustRevocation(1, "a", target, b"\x01" * 32)
        placeholder = TrustRevocationList(1, 0, 0.0, (bogus,), b"\x00" * 32)
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": 0.0,
            "entries": [
                {"version": 1, "id": "a", "target": target.hex(),
                 "mac": "01" * 32}
            ],
        }
        outer = hmac.new(
            ROOT,
            b"NPVRL1"
            + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(placeholder, mac=outer)
        with self.assertRaisesRegex(ValueError, "trust revocation mac"):
            audit_crl(forged, ROOT, 0.0)

    def test_entry_signed_under_other_root_rejected(self):
        crl = self._crl([revocation("a", root=OTHER_ROOT)])
        with self.assertRaises(ValueError):
            audit_crl(crl, ROOT, 100.0)

    def test_tampered_list_bytes_rejected(self):
        blob = self._crl(sequence=1).to_bytes()
        tampered = blob.replace(b'"sequence":1', b'"sequence":2')
        with self.assertRaises(ValueError):
            audit_crl(tampered, ROOT, 100.0)

    def test_bad_x_type(self):
        for bad in (None, 42, object(), [], revocation("a")):
            with self.assertRaises(ValueError, msg=repr(type(bad))):
                audit_crl(bad, ROOT, 100.0)

    def test_bad_now(self):
        crl = self._crl()
        for bad in ("100", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_crl(crl, ROOT, bad)

    def test_bad_min(self):
        crl = self._crl()
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_crl(crl, ROOT, 100.0, min=bad)

    def test_root_contract(self):
        crl = self._crl()
        with self.assertRaises(ValueError):
            audit_crl(crl, b"", 100.0)
        for bad in (bytearray(ROOT), None, "root"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_crl(crl, bad, 100.0)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_crl(b"not json", ROOT, 100.0)


class LocateCertSnapshotTest(unittest.TestCase):
    def consensus(self, *, revocations, **kwargs):
        return locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
            revocations=revocations, **kwargs
        )

    def baseline(self):
        return locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )

    def test_empty_snapshot_leaves_consensus_unchanged(self):
        crl = make_crl([], 1, 0.0, ROOT)
        self.assertEqual(
            self.consensus(revocations=crl, now=0.0), self.baseline()
        )
        self.assertEqual(
            self.consensus(revocations=crl.to_bytes(), now=10.0),
            self.baseline(),
        )

    def test_snapshot_requires_now(self):
        crl = make_crl([], 1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl)
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl.to_bytes())

    def test_hit_revokes_certificate(self):
        trusts = triangle_trusts()
        for index in range(3):
            crl = make_crl([revoke_trust(trusts[index], ROOT)], 1, 0.0, ROOT)
            with self.assertRaises(ValueError, msg=f"index {index}"):
                self.consensus(revocations=crl, now=0.0)
            with self.assertRaises(ValueError, msg=f"index {index} bytes"):
                self.consensus(revocations=crl.to_bytes(), now=0.0)

    def test_snapshot_is_global_unrelated_entries_ignored(self):
        foreign = cert("zzz", 50.0, 50.0, b"\x77" * 32, ROOT)
        crl = make_crl([revoke_trust(foreign, ROOT)], 1, 0.0, ROOT)
        self.assertEqual(
            self.consensus(revocations=crl, now=0.0), self.baseline()
        )

    def test_min_floor_enforced(self):
        crl = make_crl([], 3, 0.0, ROOT)
        self.assertEqual(
            self.consensus(revocations=crl, now=10.0, min=3), self.baseline()
        )
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl, now=10.0, min=4)

    def test_future_snapshot_rejected(self):
        crl = make_crl([], 1, 11.0, ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl, now=10.0)

    def test_wrong_root_rejected(self):
        crl = make_crl([], 1, 0.0, OTHER_ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl, now=0.0)

    def test_malformed_snapshot_bytes_rejected(self):
        with self.assertRaises(ValueError):
            self.consensus(revocations=b"not json", now=0.0)

    def test_now_and_min_are_keyword_only(self):
        crl = make_crl([], 1, 0.0, ROOT)
        with self.assertRaises(TypeError):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                None, crl, 0.0,
            )

    def test_legacy_iterable_path_unchanged(self):
        trusts = triangle_trusts()
        # Empty iterable: no now needed.
        self.assertEqual(self.consensus(revocations=[]), self.baseline())
        # now/min are ignored on the legacy path.
        self.assertEqual(
            self.consensus(revocations=[], now="ignored", min=999),
            self.baseline(),
        )
        # Hits still revoke.
        with self.assertRaisesRegex(ValueError, r"revoked: 'b'"):
            self.consensus(revocations=[revoke_trust(trusts[1], ROOT)])
        # Misses are still a contract breach on the legacy path, unlike a
        # global snapshot.
        foreign = cert("zzz", 50.0, 50.0, b"\x77" * 32, ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revoke_trust(foreign, ROOT)])


if __name__ == "__main__":
    unittest.main()
