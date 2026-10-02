import json
import unittest

from nearproof import (
    ObservationRevocation,
    ObservationRevocationList,
    RangeDecision,
    attest_observation,
    attest_observation_for_point,
    audit_observation_crl,
    locate_attested,
    locate_bound_attested,
    make_observation_crl,
    revoke_observation,
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


def revocation(ident, revoked_at=100.0, *, key=None):
    return revoke_observation(ident, revoked_at, key or KEYS[ident])


def observation(ident, issued_at=10.0, *, key=None):
    x, y = POSITIONS[ident]
    return attest_observation(
        ident, x, y, decision(), issued_at, key or KEYS[ident]
    )


def bound_observation(ident, issued_at=10.0, *, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(), point, context, issued_at, KEYS[ident]
    )


def triangle(issued_at=10.0):
    return [observation("a", issued_at), observation("b", issued_at),
            observation("c", issued_at)]


def bound_triangle(issued_at=10.0):
    return [bound_observation("a", issued_at), bound_observation("b", issued_at),
            bound_observation("c", issued_at)]


def crl(entries=("a",), sequence=7, issued_at=120.0, *, root=ROOT, revoked_at=100.0):
    return make_observation_crl(
        [revocation(ident, revoked_at) for ident in entries],
        sequence,
        issued_at,
        root,
    )


class ObservationRevocationListContractTest(unittest.TestCase):
    def make(self, **overrides):
        values = {
            "version": 1,
            "sequence": 7,
            "issued_at": 100.0,
            "entries": (revocation("a"),),
            "mac": b"\x00" * 32,
        }
        values.update(overrides)
        return ObservationRevocationList(
            values["version"],
            values["sequence"],
            values["issued_at"],
            values["entries"],
            values["mac"],
        )

    def test_valid_construction(self):
        record = self.make()
        self.assertEqual(record.version, 1)
        self.assertEqual(record.sequence, 7)
        self.assertEqual(record.issued_at, 100.0)
        self.assertIs(type(record.issued_at), float)
        self.assertEqual(len(record.entries), 1)

    def test_empty_entries_allowed(self):
        record = self.make(entries=())
        self.assertEqual(record.entries, ())

    def test_issued_at_int_coerced_to_float(self):
        record = self.make(issued_at=100)
        self.assertIs(type(record.issued_at), float)

    def test_version_must_be_one(self):
        for bad in (0, 2, True, "1"):
            with self.assertRaises(ValueError):
                self.make(version=bad)

    def test_sequence_contract(self):
        for bad in (True, 1.5, "7", -1, 1 << 64):
            with self.assertRaises(ValueError):
                self.make(sequence=bad)
        self.make(sequence=0)
        self.make(sequence=(1 << 64) - 1)

    def test_issued_at_contract(self):
        for bad in (True, "100", float("nan"), float("inf"), -0.5):
            with self.assertRaises(ValueError):
                self.make(issued_at=bad)

    def test_entries_must_be_tuple(self):
        with self.assertRaises(ValueError):
            self.make(entries=[revocation("a")])

    def test_entries_element_type(self):
        with self.assertRaises(ValueError):
            self.make(entries=(b"bytes",))

    def test_entries_must_be_sorted_by_id(self):
        record = self.make(entries=(revocation("a"), revocation("b")))
        self.assertEqual([e.id for e in record.entries], ["a", "b"])
        with self.assertRaises(ValueError):
            self.make(entries=(revocation("b"), revocation("a")))

    def test_entries_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            self.make(entries=(revocation("a"), revocation("a", 200.0)))

    def test_mac_contract(self):
        with self.assertRaises(ValueError):
            self.make(mac=b"\x00" * 31)
        with self.assertRaises(ValueError):
            self.make(mac="00" * 32)


class ObservationRevocationListEncodingTest(unittest.TestCase):
    def test_roundtrip(self):
        record = crl(("a", "b"))
        self.assertEqual(
            ObservationRevocationList.from_bytes(record.to_bytes()), record
        )

    def test_empty_roundtrip(self):
        record = crl(())
        self.assertEqual(
            ObservationRevocationList.from_bytes(record.to_bytes()), record
        )

    def test_from_bytes_rejects_non_bytes(self):
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes("{}")
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(None)

    def test_from_bytes_rejects_non_json(self):
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(b"not json")

    def test_from_bytes_rejects_wrong_keys(self):
        record = crl(("a",))
        payload = json.loads(record.to_bytes())
        for mutated in (
            {**payload, "extra": 1},
            {k: v for k, v in payload.items() if k != "sequence"},
            dict(reversed(list(payload.items()))),
        ):
            with self.assertRaises(ValueError):
                ObservationRevocationList.from_bytes(
                    json.dumps(mutated, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_noncanonical(self):
        record = crl(("a",))
        blob = record.to_bytes()
        # Whitespace anywhere breaks the canonical form.
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(
                blob.replace(b'"version":1', b'"version": 1')
            )
        # An integer-spelled issued_at is not the canonical float spelling.
        payload = json.loads(blob)
        payload["issued_at"] = 120
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(
                json.dumps(payload, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_unsorted_and_duplicate_entries(self):
        record = crl(("a", "b"))
        payload = json.loads(record.to_bytes())
        payload["entries"] = list(reversed(payload["entries"]))
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(
                json.dumps(payload, separators=(",", ":")).encode()
            )
        payload["entries"] = [payload["entries"][0], payload["entries"][0]]
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(
                json.dumps(payload, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_entry(self):
        record = crl(("a",))
        payload = json.loads(record.to_bytes())
        payload["entries"][0]["mac"] = "00"
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(
                json.dumps(payload, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_uppercase_mac(self):
        record = crl(("a",))
        payload = json.loads(record.to_bytes())
        payload["mac"] = payload["mac"].upper()
        with self.assertRaises(ValueError):
            ObservationRevocationList.from_bytes(
                json.dumps(payload, separators=(",", ":")).encode()
            )

    def test_from_bytes_does_not_verify_mac(self):
        record = crl(("a",))
        payload = json.loads(record.to_bytes())
        payload["mac"] = "00" * 32
        blob = json.dumps(payload, separators=(",", ":")).encode()
        decoded = ObservationRevocationList.from_bytes(blob)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class MakeObservationCrlTest(unittest.TestCase):
    def test_entries_sorted_and_signed(self):
        record = crl(("b", "a"))
        self.assertEqual([e.id for e in record.entries], ["a", "b"])
        self.assertEqual(record.version, 1)
        self.assertEqual(len(record.mac), 32)

    def test_input_order_does_not_change_bytes(self):
        self.assertEqual(
            crl(("a", "b")).to_bytes(), crl(("b", "a")).to_bytes()
        )

    def test_duplicate_id_rejected(self):
        with self.assertRaises(ValueError):
            make_observation_crl(
                [revocation("a"), revocation("a", 200.0)], 1, 100.0, ROOT
            )

    def test_bytes_items_rejected(self):
        with self.assertRaises(ValueError):
            make_observation_crl([revocation("a").to_bytes()], 1, 100.0, ROOT)

    def test_non_iterable_items_rejected(self):
        with self.assertRaises(ValueError):
            make_observation_crl(42, 1, 100.0, ROOT)

    def test_root_shape(self):
        with self.assertRaises(TypeError):
            make_observation_crl([], 1, 100.0, "root")
        with self.assertRaises(ValueError):
            make_observation_crl([], 1, 100.0, b"")

    def test_field_contract(self):
        with self.assertRaises(ValueError):
            make_observation_crl([], -1, 100.0, ROOT)
        with self.assertRaises(ValueError):
            make_observation_crl([], 1, float("nan"), ROOT)


class AuditObservationCrlTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        record = crl(("a", "b"))
        self.assertIsNone(audit_observation_crl(record, ROOT, KEYS, now=130.0))
        self.assertIsNone(
            audit_observation_crl(record.to_bytes(), ROOT, KEYS, now=130.0)
        )

    def test_empty_list_audits(self):
        record = crl(())
        self.assertIsNone(audit_observation_crl(record, ROOT, KEYS, now=130.0))

    def test_rejects_wrong_type(self):
        with self.assertRaises(ValueError):
            audit_observation_crl("crl", ROOT, KEYS, now=130.0)

    def test_root_shape(self):
        record = crl(("a",))
        with self.assertRaises(TypeError):
            audit_observation_crl(record, "root", KEYS, now=130.0)
        with self.assertRaises(ValueError):
            audit_observation_crl(record, b"", KEYS, now=130.0)

    def test_keys_shape(self):
        record = crl(("a",))
        with self.assertRaises(TypeError):
            audit_observation_crl(record, ROOT, ["a"], now=130.0)
        with self.assertRaises(TypeError):
            audit_observation_crl(record, ROOT, {1: KEY_A}, now=130.0)
        with self.assertRaises(TypeError):
            audit_observation_crl(record, ROOT, {"a": "key"}, now=130.0)
        with self.assertRaises(ValueError):
            audit_observation_crl(record, ROOT, {"a": b""}, now=130.0)
        with self.assertRaises(ValueError):
            audit_observation_crl(record, ROOT, {"": KEY_A}, now=130.0)

    def test_wrong_root_rejected(self):
        record = crl(("a",))
        with self.assertRaises(ValueError):
            audit_observation_crl(record, OTHER_ROOT, KEYS, now=130.0)

    def test_tampered_list_rejected(self):
        record = crl(("a",))
        payload = json.loads(record.to_bytes())
        payload["sequence"] = 8
        blob = json.dumps(payload, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_observation_crl(blob, ROOT, KEYS, now=130.0)

    def test_tampered_entry_rejected(self):
        record = crl(("a",))
        payload = json.loads(record.to_bytes())
        payload["entries"][0]["revoked_at"] = 50.0
        blob = json.dumps(payload, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_observation_crl(blob, ROOT, KEYS, now=130.0)

    def test_unknown_entry_id_rejected(self):
        record = crl(("a", "b"))
        with self.assertRaises(ValueError):
            audit_observation_crl(record, ROOT, {"a": KEY_A}, now=130.0)

    def test_future_list_rejected(self):
        record = crl(("a",), issued_at=120.0)
        with self.assertRaises(ValueError):
            audit_observation_crl(record, ROOT, KEYS, now=119.0)

    def test_future_entry_rejected(self):
        record = crl(("a",), revoked_at=100.0)
        with self.assertRaises(ValueError):
            audit_observation_crl(record, ROOT, KEYS, now=99.0)

    def test_sequence_floor(self):
        record = crl(("a",), sequence=7)
        self.assertIsNone(audit_observation_crl(record, ROOT, KEYS, now=130.0, min=7))
        with self.assertRaises(ValueError):
            audit_observation_crl(record, ROOT, KEYS, now=130.0, min=8)

    def test_now_and_min_contract(self):
        record = crl(("a",))
        for bad_now in (None, True, "130", float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                audit_observation_crl(record, ROOT, KEYS, now=bad_now)
        for bad_min in (True, 1.5, "7"):
            with self.assertRaises(ValueError):
                audit_observation_crl(record, ROOT, KEYS, now=130.0, min=bad_min)
        with self.assertRaises(TypeError):
            audit_observation_crl(record, ROOT, KEYS)


class LocateAttestedRevocationListTest(unittest.TestCase):
    def test_snapshot_accepts_post_revocation_observations(self):
        record = crl(("a",), revoked_at=100.0)
        consensus = locate_attested(
            [observation("a", 101.0), observation("b", 10.0), observation("c", 10.0)],
            POINT,
            KEYS,
            revocation_list=record,
            root=ROOT,
            now=130.0,
        )
        self.assertTrue(consensus.accepted)

    def test_snapshot_bytes_accepted(self):
        record = crl(("a",), revoked_at=100.0)
        consensus = locate_attested(
            [observation("a", 101.0), observation("b", 10.0), observation("c", 10.0)],
            POINT,
            KEYS,
            revocation_list=record.to_bytes(),
            root=ROOT,
            now=130.0,
        )
        self.assertTrue(consensus.accepted)

    def test_observation_at_or_before_revocation_rejected(self):
        record = crl(("a",), revoked_at=100.0)
        for issued_at in (100.0, 99.0):
            with self.assertRaises(ValueError):
                locate_attested(
                    [observation("a", issued_at), observation("b", 10.0),
                     observation("c", 10.0)],
                    POINT,
                    KEYS,
                    revocation_list=record,
                    root=ROOT,
                    now=130.0,
                )

    def test_unrelated_entries_do_not_hit(self):
        record = make_observation_crl(
            [revoke_observation("d", 100.0, b"\xdd" * 32)], 7, 120.0, ROOT
        )
        keys = {**KEYS, "d": b"\xdd" * 32}
        consensus = locate_attested(
            triangle(10.0), POINT, keys,
            revocation_list=record, root=ROOT, now=130.0,
        )
        self.assertTrue(consensus.accepted)

    def test_now_must_be_explicit(self):
        record = crl(("a",))
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root=ROOT,
            )

    def test_root_shape(self):
        record = crl(("a",))
        with self.assertRaises(TypeError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root="root", now=130.0,
            )
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root=b"", now=130.0,
            )

    def test_stale_sequence_rejected(self):
        record = crl(("a",), sequence=7)
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root=ROOT, now=130.0, min=8,
            )

    def test_expired_list_rejected(self):
        record = crl(("a",), issued_at=120.0)
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root=ROOT, now=119.0,
            )

    def test_unknown_entry_id_rejected(self):
        record = make_observation_crl(
            [revocation("a"), revoke_observation("z", 100.0, b"\xee" * 32)],
            7,
            120.0,
            ROOT,
        )
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root=ROOT, now=130.0,
            )

    def test_duplicate_entry_id_rejected(self):
        payload = json.loads(crl(("a",)).to_bytes())
        payload["entries"] = [payload["entries"][0], payload["entries"][0]]
        blob = json.dumps(payload, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=blob, root=ROOT, now=130.0,
            )

    def test_wrong_root_rejected(self):
        record = crl(("a",))
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(101.0), POINT, KEYS,
                revocation_list=record, root=OTHER_ROOT, now=130.0,
            )

    def test_single_revocations_and_snapshot_combine(self):
        record = crl(("a",), revoked_at=100.0)
        single = revocation("c", 5.0)
        # c's observation at 4.0 is caught by the per-call revocation even
        # though the snapshot does not name c.
        with self.assertRaises(ValueError):
            locate_attested(
                [observation("a", 101.0), observation("b", 10.0),
                 observation("c", 4.0)],
                POINT,
                KEYS,
                revocations=[single],
                revocation_list=record,
                root=ROOT,
                now=130.0,
            )
        # Both sources name a: the observation must postdate each.
        single_a = revocation("a", 150.0)
        with self.assertRaises(ValueError):
            locate_attested(
                [observation("a", 120.0), observation("b", 10.0),
                 observation("c", 10.0)],
                POINT,
                KEYS,
                revocations=[single_a],
                revocation_list=record,
                root=ROOT,
                now=130.0,
            )
        consensus = locate_attested(
            [observation("a", 151.0), observation("b", 10.0),
             observation("c", 10.0)],
            POINT,
            KEYS,
            revocations=[single_a],
            revocation_list=record,
            root=ROOT,
            now=200.0,
        )
        self.assertTrue(consensus.accepted)

    def test_none_snapshot_leaves_behaviour_unchanged(self):
        consensus = locate_attested(triangle(), POINT, KEYS)
        self.assertTrue(consensus.accepted)
        # root and min are ignored without a snapshot.
        consensus = locate_attested(
            triangle(), POINT, KEYS, root="not-bytes", min="junk"
        )
        self.assertTrue(consensus.accepted)


class LocateBoundAttestedRevocationListTest(unittest.TestCase):
    def test_snapshot_round(self):
        record = crl(("a",), revoked_at=100.0)
        consensus = locate_bound_attested(
            [bound_observation("a", 101.0), bound_observation("b", 10.0),
             bound_observation("c", 10.0)],
            POINT,
            CONTEXT,
            KEYS,
            revocation_list=record,
            root=ROOT,
            now=130.0,
        )
        self.assertTrue(consensus.accepted)

    def test_revoked_observation_rejected(self):
        record = crl(("a",), revoked_at=100.0)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                bound_triangle(10.0), POINT, CONTEXT, KEYS,
                revocation_list=record, root=ROOT, now=130.0,
            )

    def test_binding_still_enforced(self):
        record = crl(("a",), revoked_at=100.0)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [bound_observation("a", 101.0), bound_observation("b", 10.0),
                 bound_observation("c", 10.0, context="other")],
                POINT,
                CONTEXT,
                KEYS,
                revocation_list=record,
                root=ROOT,
                now=130.0,
            )

    def test_now_must_be_explicit(self):
        record = crl(("a",))
        with self.assertRaises(ValueError):
            locate_bound_attested(
                bound_triangle(101.0), POINT, CONTEXT, KEYS,
                revocation_list=record, root=ROOT,
            )


if __name__ == "__main__":
    unittest.main()
