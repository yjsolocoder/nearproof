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
NOW = 100.0


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


def triangle_records(upper_bound=5.0, **kwargs):
    return [
        record("a", upper_bound, **kwargs),
        record("b", upper_bound, **kwargs),
        record("c", upper_bound, **kwargs),
    ]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


def revocation(ident="a", **kwargs):
    return revoke_trust(trust(ident), kwargs.pop("root", ROOT))


class TrustRevocationListContractTest(unittest.TestCase):
    def make(self, **overrides):
        values = {
            "version": 1,
            "sequence": 0,
            "issued_at": 1.0,
            "entries": (),
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
        first = make_crl([revoke_trust(trust("a"), ROOT)], 3, NOW, ROOT)
        second = TrustRevocationList(
            1, 3, NOW, tuple(first.entries), bytes(first.mac)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 4

    def test_positional_field_order(self):
        entries = (revoke_trust(trust("a"), ROOT),)
        crl = self.make(entries=entries)
        self.assertEqual(
            (crl.version, crl.sequence, crl.issued_at, crl.entries, crl.mac),
            (1, 0, 1.0, entries, b"\x00" * 32),
        )

    def test_valid_construction(self):
        crl = make_crl(
            [revoke_trust(trust("a"), ROOT)], 0xFFFFFFFFFFFFFFFF, 2.5, ROOT
        )
        self.assertEqual(crl.version, 1)
        self.assertEqual(crl.sequence, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(crl.issued_at, 2.5)
        self.assertEqual(len(crl.entries), 1)
        self.assertEqual(len(crl.mac), 32)

    def test_empty_entries_allowed(self):
        crl = self.make()
        self.assertEqual(crl.entries, ())

    def test_version_shape_type_error(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(version=bad)

    def test_version_must_be_one(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)

    def test_sequence_must_be_non_bool_u64(self):
        for bad in (True, False, -1, 2 ** 64, "0", 1.0, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(sequence=bad)

    def test_issued_at_must_be_finite_non_negative_non_bool(self):
        for bad in (True, "1.0", None, float("inf"), float("nan"), -0.1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(issued_at=bad)

    def test_issued_at_normalized_to_float(self):
        self.assertEqual(self.make(issued_at=7).issued_at, 7.0)
        self.assertIsInstance(self.make(issued_at=7).issued_at, float)
        self.assertEqual(
            self.make(issued_at=7), self.make(issued_at=7.0)
        )
        self.assertEqual(
            hash(self.make(issued_at=7)), hash(self.make(issued_at=7.0))
        )

    def test_entries_shape_value_error(self):
        for bad in ([], "x", 7, None, bytearray()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(entries=bad)

    def test_entries_element_type_value_error(self):
        for bad in (1, None, "revocation", b"not json", object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(entries=(bad,))

    def test_entries_must_be_ascending_without_duplicates(self):
        low = TrustRevocation(1, "a", b"\x01" * 32, b"\x00" * 32)
        high = TrustRevocation(1, "b", b"\x01" * 32, b"\x00" * 32)
        with self.assertRaises(ValueError):
            self.make(entries=(high, low))
        with self.assertRaises(ValueError):
            self.make(entries=(low, low))
        # Same id, different targets: ordered by target bytes.
        t1 = TrustRevocation(1, "a", b"\x01" * 32, b"\x00" * 32)
        t2 = TrustRevocation(1, "a", b"\x02" * 32, b"\x00" * 32)
        with self.assertRaises(ValueError):
            self.make(entries=(t2, t1))
        self.make(entries=(t1, t2))  # ascending is fine

    def test_mac_shape_type_error(self):
        for bad in ("00" * 32, None, 7, bytearray(b"\x00" * 32)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(mac=bad)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(mac=bad)


class TrustRevocationListSerializationTest(unittest.TestCase):
    def _crl(self):
        return make_crl(
            [
                revoke_trust(trust("a"), ROOT),
                revoke_trust(trust("c"), ROOT),
            ],
            4,
            NOW,
            ROOT,
        )

    def test_round_trip(self):
        crl = self._crl()
        self.assertEqual(TrustRevocationList.from_bytes(crl.to_bytes()), crl)

    def test_empty_round_trip(self):
        crl = make_crl([], 0, 0.0, ROOT)
        self.assertEqual(TrustRevocationList.from_bytes(crl.to_bytes()), crl)

    def test_canonical_encoding(self):
        crl = self._crl()
        blob = crl.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj), ["version", "sequence", "issued_at", "entries", "mac"]
        )
        self.assertEqual([e["id"] for e in obj["entries"]], ["a", "c"])
        for entry in obj["entries"]:
            self.assertEqual(list(entry), ["version", "id", "target", "mac"])

    def _blob(self, *, entries=..., **overrides):
        if entries is ...:
            entries = [
                {
                    "version": 1,
                    "id": "a",
                    "target": "ab" * 32,
                    "mac": "00" * 32,
                }
            ]
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": 1.0,
            "entries": entries,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

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
        del obj["sequence"]
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

    def test_from_bytes_rejects_duplicate_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"sequence":1}'
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_sequence(self):
        for bad in (-1, 2 ** 64, "0", 1.0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocationList.from_bytes(self._blob(sequence=bad))

    def test_from_bytes_rejects_bad_issued_at(self):
        for bad in (-0.1, "1.0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocationList.from_bytes(self._blob(issued_at=bad))

    def test_from_bytes_rejects_integer_issued_at_spelling(self):
        # The canonical spelling of issued_at is a float; 1 re-encodes as
        # 1.0, so the byte-for-byte comparison rejects the integer form.
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(issued_at=1))

    def test_from_bytes_rejects_entries_not_array(self):
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries={}))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=None))

    def test_from_bytes_rejects_bad_nested_entry(self):
        good = {
            "version": 1,
            "id": "a",
            "target": "ab" * 32,
            "mac": "00" * 32,
        }
        bad_order = dict(good)
        bad_order = {"version": 1, "id": "a", "mac": "00" * 32,
                     "target": "ab" * 32}
        bad_target = dict(good, target="zz" * 32)
        bad_version = dict(good, version=2)
        for bad_entry in (bad_order, bad_target, bad_version, 1, "x"):
            with self.assertRaises(ValueError, msg=repr(bad_entry)):
                TrustRevocationList.from_bytes(self._blob(entries=[bad_entry]))

    def test_from_bytes_rejects_unsorted_and_duplicate_entries(self):
        e1 = {
            "version": 1, "id": "b", "target": "01" * 32, "mac": "00" * 32
        }
        e0 = {
            "version": 1, "id": "a", "target": "01" * 32, "mac": "00" * 32
        }
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[e1, e0]))
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(self._blob(entries=[e0, e0]))

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "0g" * 32, "AA" * 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                TrustRevocationList.from_bytes(self._blob(mac=bad))
        # A non-string mac is a shape error, matching TrustRevocation.
        for bad in (123, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                TrustRevocationList.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_whitespace_and_framing(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            TrustRevocationList.from_bytes(blob.replace(b",", b", ", 1))
        for bad in (b" " + blob, blob + b"\n", b"\xff" + blob):
            with self.assertRaises(ValueError, msg=repr(bad[:8])):
                TrustRevocationList.from_bytes(bad)

    def test_from_bytes_does_not_verify_either_mac_layer(self):
        # All-zero MACs decode fine; audit_crl is what rejects them.
        record = TrustRevocationList.from_bytes(self._blob())
        self.assertEqual(record.mac, b"\x00" * 32)
        self.assertEqual(record.entries[0].mac, b"\x00" * 32)
        self.assertEqual(record.entries[0].target, b"\xab" * 32)


class MakeCrlTest(unittest.TestCase):
    def test_signs_list_with_sorted_entries(self):
        trusts = triangle_trusts()
        crl = make_crl(
            [revoke_trust(trusts[2], ROOT), revoke_trust(trusts[0], ROOT)],
            7,
            NOW,
            ROOT,
        )
        self.assertIsInstance(crl, TrustRevocationList)
        self.assertEqual(crl.version, 1)
        self.assertEqual(crl.sequence, 7)
        self.assertEqual(crl.issued_at, NOW)
        self.assertEqual([e.id for e in crl.entries], ["a", "c"])
        self.assertEqual(len(crl.mac), 32)
        self.assertNotEqual(crl.mac, b"\x00" * 32)
        # The entries themselves come out unchanged (their NPVR1 MACs are
        # not recomputed by make_crl).
        self.assertEqual(crl.entries[0], revoke_trust(trusts[0], ROOT))

    def test_mac_uses_npvrl1_prefix_and_canonical_payload(self):
        signed = revoke_trust(trust("a"), ROOT)
        crl = make_crl([signed], 2, 3.5, ROOT)
        obj = json.loads(crl.to_bytes())
        payload = {key: obj[key] for key in
                   ("version", "sequence", "issued_at", "entries")}
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(
            ROOT, b"NPVRL1" + encoding, hashlib.sha256
        ).digest()
        self.assertEqual(crl.mac, expected)

    def test_prefix_has_no_length_prefix(self):
        signed = revoke_trust(trust("a"), ROOT)
        crl = make_crl([signed], 2, 3.5, ROOT)
        obj = json.loads(crl.to_bytes())
        payload = {key: obj[key] for key in
                   ("version", "sequence", "issued_at", "entries")}
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        forged = hmac.new(
            ROOT,
            b"NPVRL1" + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(crl.mac, forged)

    def test_accepts_mixed_objects_and_bytes(self):
        signed = revoke_trust(trust("a"), ROOT)
        crl = make_crl([signed.to_bytes()], 0, 1.0, ROOT)
        self.assertEqual(crl.entries, (signed,))

    def test_duplicate_pair_rejected(self):
        signed = revoke_trust(trust("a"), ROOT)
        with self.assertRaises(ValueError):
            make_crl([signed, TrustRevocation.from_bytes(signed.to_bytes())],
                     0, 1.0, ROOT)

    def test_empty_items(self):
        crl = make_crl([], 0, 0.0, ROOT)
        self.assertEqual(crl.entries, ())

    def test_invalid_items_rejected(self):
        signed = revoke_trust(trust("a"), ROOT)
        for bad in (42, [object()], [b"not json"], [signed, 42], None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_crl(bad, 0, 1.0, ROOT)

    def test_bad_sequence_rejected(self):
        for bad in (True, -1, 2 ** 64, 1.0, "0"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_crl([], bad, 1.0, ROOT)

    def test_bad_time_rejected(self):
        for bad in (True, -1.0, float("inf"), float("nan"), "1"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                make_crl([], 0, bad, ROOT)

    def test_time_coerced_to_float(self):
        crl = make_crl([], 0, 5, ROOT)
        self.assertEqual(crl.issued_at, 5.0)
        self.assertIsInstance(crl.issued_at, float)

    def test_root_validation(self):
        with self.assertRaises(ValueError):
            make_crl([], 0, 1.0, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                make_crl([], 0, 1.0, bad)

    def test_pure_data(self):
        signed = revoke_trust(trust("a"), ROOT)
        first = make_crl([signed], 1, NOW, ROOT)
        second = make_crl([signed], 1, NOW, ROOT)
        self.assertEqual(first, second)

    def test_same_root_as_cert_needed_to_audit(self):
        # The two entry points use the same root: an entry issued under
        # ROOT only audits under ROOT.
        crl = make_crl([revoke_trust(trust("a"), ROOT)], 1, NOW, ROOT)
        audit_crl(crl, ROOT, NOW)
        with self.assertRaises(ValueError):
            audit_crl(crl, OTHER_ROOT, NOW)


class AuditCrlTest(unittest.TestCase):
    def _crl(self, **kwargs):
        values = dict(items=[revoke_trust(trust("a"), ROOT)],
                      seq=3, time=NOW, root=ROOT)
        values.update(kwargs)
        return make_crl(**values)

    def test_success_returns_none_for_object_and_bytes(self):
        crl = self._crl()
        self.assertIsNone(audit_crl(crl, ROOT, NOW))
        self.assertIsNone(audit_crl(crl.to_bytes(), ROOT, NOW + 1, min=3))

    def test_empty_list_audits(self):
        crl = make_crl([], 0, NOW, ROOT)
        self.assertIsNone(audit_crl(crl, ROOT, NOW))

    def test_bad_x_type_error(self):
        for bad in (42, None, object(), "blob"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_crl(bad, ROOT, NOW)

    def test_non_canonical_bytes_value_error(self):
        with self.assertRaises(ValueError):
            audit_crl(b"not json", ROOT, NOW)

    def test_root_validation(self):
        crl = self._crl()
        with self.assertRaises(ValueError):
            audit_crl(crl, b"", NOW)
        for bad in (bytearray(ROOT), "", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_crl(crl, bad, NOW)

    def test_now_validation(self):
        crl = self._crl()
        for bad in (None, "100", True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_crl(crl, ROOT, bad)

    def test_min_validation(self):
        crl = self._crl()
        for bad in (True, 1.0, "0", -1, 2 ** 64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_crl(crl, ROOT, NOW, bad)

    def test_wrong_root_rejected(self):
        with self.assertRaises(ValueError):
            audit_crl(self._crl(), OTHER_ROOT, NOW)

    def test_future_list_rejected(self):
        crl = self._crl()
        with self.assertRaisesRegex(ValueError, "future"):
            audit_crl(crl, ROOT, NOW - 1e-9)
        # Issued exactly at now is accepted.
        self.assertIsNone(audit_crl(crl, ROOT, NOW))

    def test_sequence_below_min_rejected(self):
        crl = self._crl(seq=5)
        with self.assertRaises(ValueError):
            audit_crl(crl, ROOT, NOW, min=6)
        # Equal to the floor is accepted.
        self.assertIsNone(audit_crl(crl, ROOT, NOW, min=5))

    def test_tampered_list_fields_rejected(self):
        crl = self._crl()
        for name, value in (("sequence", 4), ("issued_at", NOW + 1.0)):
            tampered = dataclasses.replace(crl, **{name: value})
            with self.assertRaises(ValueError, msg=name):
                audit_crl(tampered, ROOT, NOW + 10.0)

    def test_tampered_entry_mac_rejected_even_with_valid_list_mac(self):
        # Forge a valid list-layer MAC over a tampered entry so the check
        # reaches the inner layer.
        crl = self._crl()
        bad_entry = dataclasses.replace(crl.entries[0], mac=b"\x11" * 32)
        forged_list = dataclasses.replace(crl, entries=(bad_entry,))
        obj = json.loads(forged_list.to_bytes())
        payload = {key: obj[key] for key in
                   ("version", "sequence", "issued_at", "entries")}
        encoding = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        list_mac = hmac.new(
            ROOT, b"NPVRL1" + encoding, hashlib.sha256
        ).digest()
        forged = dataclasses.replace(forged_list, mac=list_mac)
        with self.assertRaisesRegex(ValueError, "trust revocation mac"):
            audit_crl(forged, ROOT, NOW)

    def test_entry_from_other_root_rejected(self):
        foreign = revoke_trust(trust("a", root=OTHER_ROOT), OTHER_ROOT)
        crl = make_crl([foreign], 1, NOW, ROOT)
        # The list MAC is root-valid, but the entry's MAC is not.
        with self.assertRaisesRegex(ValueError, "trust revocation mac"):
            audit_crl(crl, ROOT, NOW)


class LocateCertSnapshotTest(unittest.TestCase):
    def consensus(self, *, revocations, **kwargs):
        options = {"now": NOW, "min": 0}
        options.update(kwargs)
        return locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
            revocations=revocations, **options,
        )

    def _snapshot(self, idents=(), *, seq=1, issued_at=NOW):
        return make_crl(
            [revoke_trust(trust(ident), ROOT) for ident in idents],
            seq, issued_at, ROOT,
        )

    def test_snapshot_hit_revokes_certificate(self):
        for ident in ("a", "b", "c"):
            with self.assertRaises(ValueError, msg=ident):
                self.consensus(revocations=self._snapshot([ident]))

    def test_snapshot_bytes_form_equally_rejected(self):
        crl = self._snapshot(["c"])
        with self.assertRaisesRegex(ValueError, r"revoked: 'c'"):
            self.consensus(revocations=crl.to_bytes())

    def test_snapshot_requires_now(self):
        crl = self._snapshot(["c"])
        with self.assertRaisesRegex(ValueError, "now is required"):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                revocations=crl,
            )

    def test_bytes_snapshot_requires_now(self):
        with self.assertRaisesRegex(ValueError, "now is required"):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                revocations=self._snapshot(["c"]).to_bytes(),
            )

    def test_snapshot_sequence_floor_enforced(self):
        crl = self._snapshot(["c"], seq=5)
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl, min=6)

    def test_snapshot_future_issued_at_rejected(self):
        crl = self._snapshot(["c"], issued_at=NOW + 1.0)
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl)

    def test_snapshot_wrong_root_rejected(self):
        crl = make_crl(
            [revoke_trust(trust("c"), OTHER_ROOT)], 1, NOW, OTHER_ROOT
        )
        with self.assertRaises(ValueError):
            self.consensus(revocations=crl)

    def test_tampered_snapshot_rejected(self):
        crl = self._snapshot(["c"])
        with self.assertRaises(ValueError):
            self.consensus(revocations=dataclasses.replace(crl, sequence=9))

    def test_non_hitting_snapshot_entry_is_inapplicable(self):
        # Unlike loose revocations, a global snapshot may name certs the
        # records do not use: those entries simply do not apply.
        foreign = cert("zzz", 9.0, 9.0, b"\x77" * 32, ROOT)
        crl = make_crl([revoke_trust(foreign, ROOT)], 1, NOW, ROOT)
        consensus = self.consensus(revocations=crl)
        self.assertTrue(consensus.accepted)

    def test_mixed_hitting_and_non_hitting_entries(self):
        foreign = cert("zzz", 9.0, 9.0, b"\x77" * 32, ROOT)
        crl = make_crl(
            [revoke_trust(foreign, ROOT), revoke_trust(trust("c"), ROOT)],
            1, NOW, ROOT,
        )
        with self.assertRaisesRegex(ValueError, r"revoked: 'c'"):
            self.consensus(revocations=crl)

    def test_empty_snapshot_leaves_consensus_unchanged(self):
        expected = locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )
        self.assertEqual(self.consensus(revocations=self._snapshot()), expected)

    def test_snapshot_must_not_be_wrapped_in_a_list(self):
        # A snapshot inside an iterable is just an invalid loose item.
        crl = self._snapshot(["c"])
        with self.assertRaises(ValueError):
            self.consensus(revocations=[crl])

    def test_loose_path_does_not_require_now(self):
        # The loose-revocation path keeps its old contract entirely.
        crl = self._snapshot(["c"])
        del crl  # snapshots are a different branch
        revoked = revoke_trust(trust("c"), ROOT)
        with self.assertRaisesRegex(ValueError, r"revoked: 'c'"):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                revocations=[revoked],
            )

    def test_loose_path_still_rejects_misses_with_min_set(self):
        foreign = cert("zzz", 9.0, 9.0, b"\x77" * 32, ROOT)
        with self.assertRaises(ValueError):
            self.consensus(revocations=[revoke_trust(foreign, ROOT)], min=0)

    def test_now_and_min_are_keyword_only(self):
        crl = self._snapshot(["c"])
        with self.assertRaises(TypeError):
            locate_cert(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                crl,
            )

    def test_min_validation_on_snapshot_path(self):
        crl = self._snapshot(["c"])
        for bad in (True, 1.0, -1, 2 ** 64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.consensus(revocations=crl, min=bad)

    def test_non_canonical_snapshot_bytes_rejected(self):
        blob = self._snapshot(["c"]).to_bytes()
        with self.assertRaises(ValueError):
            self.consensus(revocations=blob.replace(b",", b", ", 1))


if __name__ == "__main__":
    unittest.main()
