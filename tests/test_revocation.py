import dataclasses
import json
import math
import time
import unittest
import unittest.mock

from nearproof import (
    ObservationRevocation,
    RangeDecision,
    attest_observation,
    locate_attested,
    revoke_observation,
)

KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}


def decision(upper_bound=5.0):
    return RangeDecision(sample_count=1, upper_bound=upper_bound, accepted=True)


def attest(ident, x, y, upper_bound=5.0, *, key=None, issued_at=0.0):
    return attest_observation(
        ident, x, y, decision(upper_bound), issued_at, key or KEYS[ident]
    )


# Three verifiers at the corners of a 3-4-5 triangle around the origin.
def triangle(**kwargs):
    return [
        attest("a", 3.0, 0.0, 5.0, **kwargs),
        attest("b", 0.0, 4.0, 5.0, **kwargs),
        attest("c", 0.0, 0.0, 0.0, **kwargs),
    ]


def revoke(ident, revoked_at, *, key=None):
    return revoke_observation(ident, revoked_at, key or KEYS[ident])


class ObservationRevocationContractTest(unittest.TestCase):
    def test_is_frozen(self):
        record = revoke("a", 1.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.revoked_at = 9.0

    def test_valid_construction(self):
        record = revoke("a", 3)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.id, "a")
        self.assertEqual(record.revoked_at, 3)
        self.assertEqual(len(record.mac), 32)

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation(bad, "a", 0.0, b"\x00" * 32)

    def test_id_must_be_non_empty_str(self):
        for bad in ("", 1, None, b"a"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation(1, bad, 0.0, b"\x00" * 32)

    def test_revoked_at_must_be_finite_non_bool_non_negative(self):
        for bad in (True, -1.0, -0.5, math.inf, -math.inf, math.nan, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation(1, "a", bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "00" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation(1, "a", 0.0, bad)


class RevokeObservationTest(unittest.TestCase):
    def test_signs_with_key(self):
        record = revoke_observation("a", 3.0, KEY_A)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.id, "a")
        # The mac verifies under the signing key (checked via locate_attested).
        consensus = locate_attested(
            triangle(issued_at=10.0), (0.0, 0.0), KEYS,
            revocations=[record], now=20.0,
        )
        self.assertEqual(consensus.support, 3)

    def test_empty_key_rejected(self):
        for bad in (b"", "", None, 0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                revoke_observation("a", 3.0, bad)

    def test_invalid_fields_rejected(self):
        with self.assertRaises(ValueError):
            revoke_observation("", 3.0, KEY_A)
        with self.assertRaises(ValueError):
            revoke_observation("a", -3.0, KEY_A)
        with self.assertRaises(ValueError):
            revoke_observation("a", math.nan, KEY_A)

    def test_different_keys_give_different_macs(self):
        one = revoke_observation("a", 3.0, KEY_A)
        two = revoke_observation("a", 3.0, KEY_B)
        self.assertNotEqual(one.mac, two.mac)


class RevocationSerializationTest(unittest.TestCase):
    def test_round_trip(self):
        record = revoke("a", 7.25)
        clone = ObservationRevocation.from_bytes(record.to_bytes())
        self.assertEqual(clone, record)

    def test_canonical_encoding(self):
        record = ObservationRevocation(1, "a", 3.0, b"\x00" * 32)
        blob = record.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(list(obj), ["version", "id", "revoked_at", "mac"])
        self.assertEqual(obj["mac"], "00" * 32)

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "id": "a",
            "revoked_at": 3.0,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", None, 42, bytearray(b"{}")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3]", b'"s"', b"1", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation.from_bytes(bad)

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["revoked_at"]
        blob = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(blob)

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        blob = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(blob)

    def test_from_bytes_rejects_duplicate_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"id":"b"}'
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        blob = json.dumps(reordered, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(blob)

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0G" * 32, "AA" * 32, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(self._blob(version=2))
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(self._blob(id=""))
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(self._blob(revoked_at=-1.0))
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(self._blob(revoked_at=True))

    def test_from_bytes_rejects_whitespace(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(blob.replace(b",", b", ", 1))
        for padded in (b" " + blob, blob + b"\n"):
            with self.assertRaises(ValueError, msg=repr(padded[:8])):
                ObservationRevocation.from_bytes(padded)

    def test_from_bytes_rejects_pretty_printed_json(self):
        obj = json.loads(self._blob())
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(json.dumps(obj, indent=2).encode())

    def test_from_bytes_rejects_noncanonical_numbers(self):
        blob = self._blob().replace(b'"revoked_at":3.0', b'"revoked_at":3.00')
        with self.assertRaises(ValueError):
            ObservationRevocation.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        record = ObservationRevocation.from_bytes(self._blob())
        self.assertEqual(record.mac, b"\x00" * 32)


class LocateAttestedRevocationsTest(unittest.TestCase):
    def test_none_keeps_original_behaviour(self):
        consensus = locate_attested(triangle(), (0.0, 0.0), KEYS, revocations=None)
        self.assertEqual(consensus.support, 3)

    def test_empty_revocations_accepted(self):
        consensus = locate_attested(triangle(), (0.0, 0.0), KEYS, revocations=[])
        self.assertEqual(consensus.support, 3)

    def test_observation_issued_after_revocation_survives(self):
        records = triangle(issued_at=10.0)
        revocations = [revoke("a", 5.0)]
        consensus = locate_attested(
            records, (0.0, 0.0), KEYS, revocations=revocations, now=20.0
        )
        self.assertEqual(consensus.support, 3)

    def test_observation_issued_at_revocation_rejected(self):
        records = triangle(issued_at=5.0)
        with self.assertRaises(ValueError):
            locate_attested(
                records, (0.0, 0.0), KEYS, revocations=[revoke("a", 5.0)], now=20.0
            )

    def test_observation_issued_before_revocation_rejected(self):
        records = triangle(issued_at=4.0)
        with self.assertRaises(ValueError):
            locate_attested(
                records, (0.0, 0.0), KEYS, revocations=[revoke("a", 5.0)], now=20.0
            )

    def test_mixed_objects_and_bytes(self):
        records = triangle(issued_at=10.0)
        revocations = [revoke("a", 5.0).to_bytes(), revoke("b", 6.0)]
        consensus = locate_attested(
            records, (0.0, 0.0), KEYS, revocations=revocations, now=20.0
        )
        self.assertEqual(consensus.support, 3)

    def test_revocation_without_matching_observation_is_fine(self):
        # A revocation for an id with no observation is still verified but
        # does not affect the consensus.
        records = triangle(issued_at=10.0)
        keys = dict(KEYS, d=b"\xdd" * 32)
        consensus = locate_attested(
            records, (0.0, 0.0), keys,
            revocations=[revoke_observation("d", 20.0, keys["d"])], now=30.0,
        )
        self.assertEqual(consensus.support, 3)

    def test_unknown_revocation_id_rejected(self):
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=[revoke_observation("zzz", 1.0, KEY_A)], now=20.0,
            )

    def test_duplicate_revocation_id_rejected(self):
        revocations = [revoke("a", 1.0), revoke("a", 2.0)]
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=revocations, now=20.0,
            )

    def test_wrong_key_rejected(self):
        revocation = revoke_observation("a", 1.0, KEY_B)
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=[revocation], now=20.0,
            )

    def test_tampered_revocation_rejected(self):
        tampered = dataclasses.replace(revoke("a", 1.0), revoked_at=2.0)
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=[tampered], now=20.0,
            )

    def test_tampered_revocation_bytes_rejected(self):
        blob = revoke("a", 1.0).to_bytes().replace(b'"revoked_at":1.0', b'"revoked_at":2.0')
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=[blob], now=20.0,
            )

    def test_invalid_revocation_items_rejected(self):
        for bad in ([1], [None], ["revocation"], [b"not json"], [object()]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_attested(
                    triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                    revocations=bad, now=20.0,
                )
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=42, now=20.0,
            )

    def test_future_revocation_rejected(self):
        with self.assertRaises(ValueError):
            locate_attested(
                triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                revocations=[revoke("a", 30.0)], now=20.0,
            )

    def test_now_contract_with_revocations(self):
        for bad in (math.inf, math.nan, True, "now"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_attested(
                    triangle(issued_at=10.0), (0.0, 0.0), KEYS,
                    revocations=[revoke("a", 1.0)], now=bad,
                )

    def test_now_defaults_to_single_wall_clock_reading(self):
        records = triangle(issued_at=time.time())
        calls = []
        real_time = time.time

        def fake_time():
            calls.append(1)
            return real_time()

        with unittest.mock.patch.object(time, "time", fake_time):
            consensus = locate_attested(
                records, (0.0, 0.0), KEYS, revocations=[]
            )
        self.assertEqual(consensus.support, 3)
        self.assertEqual(len(calls), 1)

    def test_revocation_check_composes_with_max_age(self):
        records = triangle(issued_at=100.0)
        # Fresh enough for max_age and issued after the revocation: accepted.
        consensus = locate_attested(
            records, (0.0, 0.0), KEYS,
            revocations=[revoke("a", 50.0)], now=110.0, max_age=20.0,
        )
        self.assertEqual(consensus.support, 3)
        # Same setup but stale per max_age: rejected.
        with self.assertRaises(ValueError):
            locate_attested(
                records, (0.0, 0.0), KEYS,
                revocations=[revoke("a", 50.0)], now=121.0, max_age=20.0,
            )

    def test_geometry_rules_unchanged_for_surviving_observations(self):
        records = triangle(issued_at=10.0)
        revocations = [revoke("a", 5.0), revoke("b", 5.0), revoke("c", 5.0)]
        consensus = locate_attested(
            records, (100.0, 100.0), KEYS, revocations=revocations, now=20.0
        )
        self.assertEqual(consensus.support, 0)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        self.assertFalse(consensus.accepted)


if __name__ == "__main__":
    unittest.main()
