import dataclasses
import json
import math
import unittest

from nearproof import (
    AttestedObservation,
    Consensus,
    RangeDecision,
    attest_observation,
    locate_attested,
)

KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def attest(ident, x, y, upper_bound=5.0, *, key=None, issued_at=0.0, **kwargs):
    return attest_observation(
        ident, x, y, decision(upper_bound, **kwargs), issued_at, key or KEYS[ident]
    )


# Three verifiers at the corners of a 3-4-5 triangle around the origin.
def triangle(**kwargs):
    return [
        attest("a", 3.0, 0.0, 5.0, **kwargs),
        attest("b", 0.0, 4.0, 5.0, **kwargs),
        attest("c", 0.0, 0.0, 0.0, **kwargs),
    ]


class AttestedObservationContractTest(unittest.TestCase):
    def test_is_frozen(self):
        record = attest("a", 1.0, 2.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.x = 9.0

    def test_valid_construction(self):
        record = attest("a", 1, 2.0, issued_at=3)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.id, "a")
        self.assertEqual(len(record.mac), 32)

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(bad, "a", 0.0, 0.0, decision(), 0.0, b"\x00" * 32)

    def test_id_must_be_non_empty_str(self):
        for bad in ("", 1, None, b"a"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(1, bad, 0.0, 0.0, decision(), 0.0, b"\x00" * 32)

    def test_numbers_must_be_finite_non_bool_non_negative(self):
        for name in ("x", "y", "issued_at"):
            for bad in (True, -1.0, -0.5, math.inf, -math.inf, math.nan, "0", None):
                fields = {
                    "version": 1,
                    "id": "a",
                    "x": 0.0,
                    "y": 0.0,
                    "decision": decision(),
                    "issued_at": 0.0,
                    "mac": b"\x00" * 32,
                }
                fields[name] = bad
                with self.assertRaises(ValueError, msg=f"{name}={bad!r}"):
                    AttestedObservation(**fields)

    def test_decision_must_be_range_decision(self):
        for bad in (None, (1, 5.0, True), "decision"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(1, "a", 0.0, 0.0, bad, 0.0, b"\x00" * 32)

    def test_decision_sample_count_positive_int(self):
        for bad in (0, -1, 1.0, True, "1"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(
                    1, "a", 0.0, 0.0, decision(sample_count=bad), 0.0, b"\x00" * 32
                )

    def test_decision_upper_bound_finite_non_negative(self):
        for bad in (-1.0, math.inf, math.nan, True, "5"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(
                    1,
                    "a",
                    0.0,
                    0.0,
                    RangeDecision(1, bad, True),
                    0.0,
                    b"\x00" * 32,
                )

    def test_decision_accepted_must_be_bool(self):
        for bad in (0, 1, "true", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(
                    1,
                    "a",
                    0.0,
                    0.0,
                    RangeDecision(1, 5.0, bad),
                    0.0,
                    b"\x00" * 32,
                )

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "00" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation(1, "a", 0.0, 0.0, decision(), 0.0, bad)


class AttestObservationTest(unittest.TestCase):
    def test_signs_with_key(self):
        record = attest_observation("a", 1.0, 2.0, decision(), 3.0, KEY_A)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.id, "a")
        # The mac verifies under the signing key (checked via locate_attested).
        consensus = locate_attested(
            [record, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
            (0.0, 0.0),
            KEYS,
        )
        self.assertEqual(consensus.support, 3)

    def test_empty_key_rejected(self):
        for bad in (b"", "", None, 0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                attest_observation("a", 1.0, 2.0, decision(), 3.0, bad)

    def test_invalid_fields_rejected(self):
        with self.assertRaises(ValueError):
            attest_observation("", 1.0, 2.0, decision(), 3.0, KEY_A)
        with self.assertRaises(ValueError):
            attest_observation("a", -1.0, 2.0, decision(), 3.0, KEY_A)
        with self.assertRaises(ValueError):
            attest_observation("a", 1.0, 2.0, decision(), -3.0, KEY_A)

    def test_different_keys_give_different_macs(self):
        one = attest_observation("a", 1.0, 2.0, decision(), 3.0, KEY_A)
        two = attest_observation("a", 1.0, 2.0, decision(), 3.0, KEY_B)
        self.assertNotEqual(one.mac, two.mac)


class AttestedSerializationTest(unittest.TestCase):
    def test_round_trip(self):
        record = attest("a", 1.5, 2.0, issued_at=7.25)
        clone = AttestedObservation.from_bytes(record.to_bytes())
        self.assertEqual(clone, record)

    def test_canonical_encoding(self):
        record = AttestedObservation(
            1, "a", 1.0, 2.0, decision(5.0), 3.0, b"\x00" * 32
        )
        blob = record.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj),
            ["version", "id", "x", "y", "decision", "issued_at", "mac"],
        )
        self.assertEqual(list(obj["decision"]), ["sample_count", "upper_bound", "accepted"])
        self.assertEqual(obj["mac"], "00" * 32)

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", b"{}".decode(), None, 42, bytearray(b"{}")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3]", b'"s"', b"1", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation.from_bytes(bad)

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "id": "a",
            "x": 1.0,
            "y": 2.0,
            "decision": {"sample_count": 1, "upper_bound": 5.0, "accepted": True},
            "issued_at": 3.0,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_from_bytes_rejects_missing_key(self):
        blob = self._blob()
        obj = json.loads(blob)
        del obj["issued_at"]
        blob = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(blob)

    def test_from_bytes_rejects_extra_key(self):
        blob = self._blob()
        obj = json.loads(blob)
        obj["extra"] = 1
        blob = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(blob)

    def test_from_bytes_rejects_duplicate_key(self):
        blob = self._blob()
        text = blob.decode()
        text = text[:-1] + ',"id":"b"}'
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        blob = self._blob()
        obj = json.loads(blob)
        reordered = {key: obj[key] for key in reversed(list(obj))}
        blob = json.dumps(reordered, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(blob)

    def test_from_bytes_rejects_decision_key_disorder(self):
        blob = self._blob()
        obj = json.loads(blob)
        dec = obj["decision"]
        obj["decision"] = {key: dec[key] for key in reversed(list(dec))}
        blob = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(blob)

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0G" * 32, "AA" * 32, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AttestedObservation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(self._blob(version=2))
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(self._blob(id=""))
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(self._blob(x=-1.0))
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(self._blob(issued_at=True))
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(
                self._blob(decision={"sample_count": 0, "upper_bound": 5.0, "accepted": True})
            )
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(self._blob(decision=[1, 5.0, True]))

    def test_from_bytes_does_not_verify_mac(self):
        blob = self._blob()  # all-zero mac, not a real signature
        record = AttestedObservation.from_bytes(blob)
        self.assertEqual(record.mac, b"\x00" * 32)


class LocateAttestedTest(unittest.TestCase):
    def test_basic_consensus(self):
        consensus = locate_attested(triangle(), (0.0, 0.0), KEYS)
        self.assertIsInstance(consensus, Consensus)
        self.assertEqual((consensus.total, consensus.support), (3, 3))
        self.assertEqual(consensus.rejected, ())
        self.assertTrue(consensus.accepted)

    def test_mixed_objects_and_bytes(self):
        records = triangle()
        mixed = [records[0].to_bytes(), records[1], records[2].to_bytes()]
        consensus = locate_attested(mixed, (0.0, 0.0), KEYS)
        self.assertEqual(consensus.support, 3)

    def test_locate_rules_apply(self):
        # quorum not reached -> accepted False; rejected ids sorted.
        consensus = locate_attested(triangle(), (100.0, 100.0), KEYS)
        self.assertEqual(consensus.support, 0)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        self.assertFalse(consensus.accepted)
        with self.assertRaises(ValueError):
            locate_attested(triangle(), (0.0, 0.0), KEYS, quorum=4)
        with self.assertRaises(ValueError):
            locate_attested(triangle(), [0.0, 0.0], KEYS)
        with self.assertRaises(ValueError):
            locate_attested(triangle()[:2], (0.0, 0.0), KEYS)

    def test_tolerance_applies(self):
        # Point (9, 0): distance 6 from a (bound 5), ~9.85 from b (bound 5),
        # 9 from c (bound 0). Without tolerance all reject; with tolerance 4
        # only a is covered (6 <= 5 + 4).
        records = triangle()
        consensus = locate_attested(records, (9.0, 0.0), KEYS)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        consensus = locate_attested(records, (9.0, 0.0), KEYS, tolerance=4.0)
        self.assertEqual(consensus.rejected, ("b", "c"))

    def test_unknown_id_rejected(self):
        records = triangle()
        with self.assertRaises(ValueError):
            locate_attested(records, (0.0, 0.0), {"a": KEY_A, "b": KEY_B})

    def test_duplicate_id_rejected(self):
        records = triangle()
        records.append(attest("a", 1.0, 1.0))
        with self.assertRaises(ValueError):
            locate_attested(records, (0.0, 0.0), KEYS)

    def test_wrong_key_rejected(self):
        records = triangle()
        bad_keys = dict(KEYS, b=KEY_C)
        with self.assertRaises(ValueError):
            locate_attested(records, (0.0, 0.0), bad_keys)

    def test_tampering_rejected(self):
        record = attest("a", 3.0, 0.0)
        tampered = dataclasses.replace(record, x=99.0)
        with self.assertRaises(ValueError):
            locate_attested(
                [tampered, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
                (0.0, 0.0),
                KEYS,
            )

    def test_tampered_bytes_rejected(self):
        record = attest("a", 3.0, 0.0)
        blob = record.to_bytes().replace(b'"x":3.0', b'"x":99.0')
        with self.assertRaises(ValueError):
            locate_attested(
                [blob, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
                (0.0, 0.0),
                KEYS,
            )

    def test_keys_contract(self):
        records = triangle()
        for bad in ({}, None, [], "keys"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_attested(records, (0.0, 0.0), bad)
        with self.assertRaises(ValueError):
            locate_attested(records, (0.0, 0.0), dict(KEYS, a=b""))
        with self.assertRaises(ValueError):
            locate_attested(records, (0.0, 0.0), dict(KEYS, a="not-bytes"))

    def test_invalid_items_rejected(self):
        with self.assertRaises(ValueError):
            locate_attested([1, 2, 3], (0.0, 0.0), KEYS)
        with self.assertRaises(ValueError):
            locate_attested(None, (0.0, 0.0), KEYS)

    def test_max_age_none_skips_freshness(self):
        # issued_at far in the past and no max_age: accepted.
        consensus = locate_attested(triangle(issued_at=1e9), (0.0, 0.0), KEYS)
        self.assertEqual(consensus.support, 3)

    def test_max_age_fresh_records_accepted(self):
        consensus = locate_attested(
            triangle(issued_at=100.0), (0.0, 0.0), KEYS, now=110.0, max_age=20.0
        )
        self.assertEqual(consensus.support, 3)

    def test_max_age_boundary_is_closed(self):
        records = triangle(issued_at=100.0)
        consensus = locate_attested(
            records, (0.0, 0.0), KEYS, now=120.0, max_age=20.0
        )
        self.assertEqual(consensus.support, 3)
        consensus = locate_attested(records, (0.0, 0.0), KEYS, now=100.0, max_age=0.0)
        self.assertEqual(consensus.support, 3)

    def test_stale_records_rejected(self):
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=100.0), (0.0, 0.0), KEYS, now=121.0, max_age=20.0
            )

    def test_future_records_rejected(self):
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=100.0), (0.0, 0.0), KEYS, now=99.0, max_age=20.0
            )

    def test_max_age_contract(self):
        records = triangle()
        for bad in (-1.0, math.inf, math.nan, True, "5"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_attested(records, (0.0, 0.0), KEYS, max_age=bad)

    def test_now_contract(self):
        records = triangle()
        for bad in (math.inf, math.nan, True, "now"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_attested(records, (0.0, 0.0), KEYS, now=bad, max_age=10.0)

    def test_now_defaults_to_wall_clock(self):
        import time

        records = triangle(issued_at=time.time())
        consensus = locate_attested(records, (0.0, 0.0), KEYS, max_age=60.0)
        self.assertEqual(consensus.support, 3)


if __name__ == "__main__":
    unittest.main()
