import dataclasses
import json
import math
import unittest

from nearproof import (
    AttestedObservation,
    BoundAttestedObservation,
    Consensus,
    RangeDecision,
    attest_observation,
    attest_observation_for_point,
    locate_bound_attested,
    revoke_observation,
)

KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def attest(ident, x, y, upper_bound=5.0, *, key=None, issued_at=0.0,
           point=POINT, context=CONTEXT, **kwargs):
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound, **kwargs), point, context,
        issued_at, key or KEYS[ident],
    )


# Three verifiers at the corners of a 3-4-5 triangle around the origin.
def triangle(**kwargs):
    return [
        attest("a", 3.0, 0.0, 5.0, **kwargs),
        attest("b", 0.0, 4.0, 5.0, **kwargs),
        attest("c", 0.0, 0.0, 0.0, **kwargs),
    ]


class BoundAttestedObservationContractTest(unittest.TestCase):
    def test_is_frozen(self):
        record = attest("a", 1.0, 2.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.x = 9.0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.context = "other"

    def test_valid_construction(self):
        record = attest("a", 1, 2.0, issued_at=3, point=(1.5, -2.5))
        self.assertEqual(record.version, 1)
        self.assertEqual(record.id, "a")
        self.assertEqual(record.point, (1.5, -2.5))
        self.assertEqual(record.context, CONTEXT)
        self.assertEqual(len(record.mac), 32)

    def test_point_is_a_tuple_on_the_record(self):
        record = attest("a", 1.0, 2.0, point=(1.0, 2.0))
        self.assertIsInstance(record.point, tuple)

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    bad, "a", 0.0, 0.0, decision(), POINT, CONTEXT, 0.0,
                    b"\x00" * 32,
                )

    def test_id_must_be_non_empty_str(self):
        for bad in ("", 1, None, b"a"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, bad, 0.0, 0.0, decision(), POINT, CONTEXT, 0.0,
                    b"\x00" * 32,
                )

    def test_numbers_must_be_finite_non_bool_non_negative(self):
        for name in ("x", "y", "issued_at"):
            for bad in (True, -1.0, -0.5, math.inf, -math.inf, math.nan, "0", None):
                fields = {
                    "version": 1,
                    "id": "a",
                    "x": 0.0,
                    "y": 0.0,
                    "decision": decision(),
                    "point": POINT,
                    "context": CONTEXT,
                    "issued_at": 0.0,
                    "mac": b"\x00" * 32,
                }
                fields[name] = bad
                with self.assertRaises(ValueError, msg=f"{name}={bad!r}"):
                    BoundAttestedObservation(**fields)

    def test_decision_must_be_range_decision(self):
        for bad in (None, (1, 5.0, True), "decision"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, bad, POINT, CONTEXT, 0.0, b"\x00" * 32
                )

    def test_decision_sample_count_positive_int(self):
        for bad in (0, -1, 1.0, True, "1"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, decision(sample_count=bad), POINT,
                    CONTEXT, 0.0, b"\x00" * 32,
                )

    def test_decision_upper_bound_finite_non_negative(self):
        for bad in (-1.0, math.inf, math.nan, True, "5"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, RangeDecision(1, bad, True), POINT,
                    CONTEXT, 0.0, b"\x00" * 32,
                )

    def test_decision_accepted_must_be_bool(self):
        for bad in (0, 1, "true", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, RangeDecision(1, 5.0, bad), POINT,
                    CONTEXT, 0.0, b"\x00" * 32,
                )

    def test_point_must_be_tuple_of_two_finite_non_bool_numbers(self):
        for bad in (
            (1.0,),
            (1.0, 2.0, 3.0),
            [1.0, 2.0],
            (True, 2.0),
            (1.0, False),
            (math.nan, 2.0),
            (1.0, math.inf),
            ("1", 2.0),
            None,
            1.0,
            (),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, decision(), bad, CONTEXT, 0.0,
                    b"\x00" * 32,
                )

    def test_point_coordinates_may_be_negative_or_integer(self):
        record = BoundAttestedObservation(
            1, "a", 0.0, 0.0, decision(), (-1, -2.5), CONTEXT, 0.0,
            b"\x00" * 32,
        )
        self.assertEqual(record.point, (-1, -2.5))

    def test_context_must_be_non_empty_string(self):
        for bad in ("", b"room-7", 7, None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, decision(), POINT, bad, 0.0,
                    b"\x00" * 32,
                )

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"", b"\x00" * 31, b"\x00" * 33, "00" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation(
                    1, "a", 0.0, 0.0, decision(), POINT, CONTEXT, 0.0, bad
                )


class AttestObservationForPointTest(unittest.TestCase):
    def test_signs_with_key(self):
        record = attest_observation_for_point(
            "a", 1.0, 2.0, decision(), (0.0, 0.0), CONTEXT, 3.0, KEY_A
        )
        self.assertEqual(record.version, 1)
        self.assertEqual(record.id, "a")
        # The mac verifies under the signing key (checked via locate).
        consensus = locate_bound_attested(
            [record, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
            POINT, CONTEXT, KEYS,
        )
        self.assertEqual(consensus.support, 3)

    def test_empty_key_rejected(self):
        for bad in (b"", "", None, 0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                attest_observation_for_point(
                    "a", 1.0, 2.0, decision(), POINT, CONTEXT, 3.0, bad
                )

    def test_invalid_fields_rejected(self):
        with self.assertRaises(ValueError):
            attest_observation_for_point(
                "", 1.0, 2.0, decision(), POINT, CONTEXT, 3.0, KEY_A
            )
        with self.assertRaises(ValueError):
            attest_observation_for_point(
                "a", -1.0, 2.0, decision(), POINT, CONTEXT, 3.0, KEY_A
            )
        with self.assertRaises(ValueError):
            attest_observation_for_point(
                "a", 1.0, 2.0, decision(), [0.0, 0.0], CONTEXT, 3.0, KEY_A
            )
        with self.assertRaises(ValueError):
            attest_observation_for_point(
                "a", 1.0, 2.0, decision(), POINT, "", 3.0, KEY_A
            )

    def test_different_keys_give_different_macs(self):
        args = ("a", 1.0, 2.0, decision(), POINT, CONTEXT, 3.0)
        self.assertNotEqual(
            attest_observation_for_point(*args, KEY_A).mac,
            attest_observation_for_point(*args, KEY_B).mac,
        )

    def test_mac_covers_point_and_context(self):
        base = attest_observation_for_point(
            "a", 1.0, 2.0, decision(), (0.0, 0.0), "one", 3.0, KEY_A
        )
        other_point = attest_observation_for_point(
            "a", 1.0, 2.0, decision(), (1.0, 0.0), "one", 3.0, KEY_A
        )
        other_context = attest_observation_for_point(
            "a", 1.0, 2.0, decision(), (0.0, 0.0), "two", 3.0, KEY_A
        )
        self.assertNotEqual(base.mac, other_point.mac)
        self.assertNotEqual(base.mac, other_context.mac)

    def test_missing_arguments_raise_type_error(self):
        with self.assertRaises(TypeError):
            attest_observation_for_point("a", 1.0, 2.0, decision(), POINT, CONTEXT)


class BoundAttestedSerializationTest(unittest.TestCase):
    def test_round_trip(self):
        record = attest("a", 1.5, 2.0, issued_at=7.25, point=(1.5, -2.0))
        clone = BoundAttestedObservation.from_bytes(record.to_bytes())
        self.assertEqual(clone, record)
        self.assertIsInstance(clone.point, tuple)

    def test_canonical_encoding(self):
        record = BoundAttestedObservation(
            1, "a", 1.0, 2.0, decision(5.0), (3.0, 4.0), CONTEXT, 3.0,
            b"\x00" * 32,
        )
        blob = record.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj),
            [
                "version", "id", "x", "y", "decision", "point", "context",
                "issued_at", "mac",
            ],
        )
        self.assertEqual(list(obj["decision"]), ["sample_count", "upper_bound", "accepted"])
        # The point is a bare JSON array: no type label, no length prefix.
        self.assertEqual(obj["point"], [3.0, 4.0])
        self.assertNotIn(b"tuple", blob)
        self.assertEqual(obj["context"], CONTEXT)
        self.assertEqual(obj["mac"], "00" * 32)

    def test_encoding_is_a_single_unframed_json_document(self):
        blob = attest("a", 1.0, 2.0).to_bytes()
        # Empty domain label / no length prefix / no extra delimiting: the
        # whole blob parses as exactly one JSON object and nothing follows it.
        obj, end = json.JSONDecoder().raw_decode(blob.decode())
        self.assertEqual(end, len(blob))
        self.assertIsInstance(obj, dict)

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", b"{}".decode(), None, 42, bytearray(b"{}")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3]", b'"s"', b"1", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation.from_bytes(bad)

    def _blob(self, **overrides):
        payload = {
            "version": 1,
            "id": "a",
            "x": 1.0,
            "y": 2.0,
            "decision": {"sample_count": 1, "upper_bound": 5.0, "accepted": True},
            "point": [3.0, 4.0],
            "context": CONTEXT,
            "issued_at": 3.0,
            "mac": "00" * 32,
        }
        payload.update(overrides)
        return json.dumps(payload, separators=(",", ":")).encode()

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["context"]
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_key(self):
        text = self._blob().decode()
        text = text[:-1] + ',"id":"b"}'
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(text.encode())

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_decision_key_disorder(self):
        obj = json.loads(self._blob())
        dec = obj["decision"]
        obj["decision"] = {key: dec[key] for key in reversed(list(dec))}
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_point_not_two_element_array(self):
        for bad_point in ([3.0], [3.0, 4.0, 5.0], {"0": 3.0, "1": 4.0},
                          "3,4", 3, None, True):
            with self.assertRaises(ValueError, msg=repr(bad_point)):
                BoundAttestedObservation.from_bytes(self._blob(point=bad_point))

    def test_from_bytes_rejects_bad_point_elements(self):
        for bad_point in ([[True, 4.0]], [[3.0, "4"]], [[3.0, None]],
                          [[math.nan, 4.0]]):
            with self.assertRaises(ValueError, msg=repr(bad_point)):
                BoundAttestedObservation.from_bytes(self._blob(point=bad_point[0]))

    def test_from_bytes_rejects_empty_context(self):
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(self._blob(context=""))
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(self._blob(context=7))

    def test_from_bytes_rejects_bad_mac_encoding(self):
        for bad in ("00" * 31, "00" * 33, "0G" * 32, "AA" * 32, 123, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundAttestedObservation.from_bytes(self._blob(mac=bad))

    def test_from_bytes_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(self._blob(version=2))
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(self._blob(id=""))
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(self._blob(x=-1.0))
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(self._blob(issued_at=True))
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(
                self._blob(
                    decision={"sample_count": 0, "upper_bound": 5.0,
                              "accepted": True}
                )
            )
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(
                self._blob(decision=[1, 5.0, True])
            )

    def test_from_bytes_does_not_verify_mac(self):
        record = BoundAttestedObservation.from_bytes(self._blob())
        self.assertEqual(record.mac, b"\x00" * 32)

    def test_from_bytes_rejects_whitespace(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(blob.replace(b",", b", ", 1))
        for padded in (b" " + blob, blob + b"\n", b"\t" + blob + b" "):
            with self.assertRaises(ValueError, msg=repr(padded[:8])):
                BoundAttestedObservation.from_bytes(padded)

    def test_from_bytes_rejects_pretty_printed_json(self):
        obj = json.loads(self._blob())
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(json.dumps(obj, indent=2).encode())

    def test_from_bytes_rejects_noncanonical_numbers(self):
        blob = self._blob().replace(b'"issued_at":3.0', b'"issued_at":3.00')
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(blob)
        blob = self._blob().replace(b'"point":[3.0,4.0]', b'"point":[3.00,4.0]')
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(blob)

    def test_from_bytes_rejects_noncanonical_strings(self):
        blob = self._blob().replace(
            b'"context":"room-7"', b'"context":"room-\\u0037"'
        )
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(blob)

    def test_old_attested_blob_does_not_decode_as_bound(self):
        old = attest_observation("a", 1.0, 2.0, decision(), 3.0, KEY_A)
        with self.assertRaises(ValueError):
            BoundAttestedObservation.from_bytes(old.to_bytes())


class LocateBoundAttestedTest(unittest.TestCase):
    def test_basic_consensus(self):
        consensus = locate_bound_attested(triangle(), POINT, CONTEXT, KEYS)
        self.assertIsInstance(consensus, Consensus)
        self.assertEqual((consensus.total, consensus.support), (3, 3))
        self.assertEqual(consensus.rejected, ())
        self.assertTrue(consensus.accepted)

    def test_mixed_objects_and_bytes(self):
        records = triangle()
        mixed = [records[0].to_bytes(), records[1], records[2].to_bytes()]
        consensus = locate_bound_attested(mixed, POINT, CONTEXT, KEYS)
        self.assertEqual(consensus.support, 3)

    def test_locate_rules_apply(self):
        # Records bound to a far-away query point: quorum not reached there is
        # accepted False with sorted rejected ids, not an exception.
        consensus = locate_bound_attested(
            triangle(point=(100.0, 100.0)), (100.0, 100.0), CONTEXT, KEYS
        )
        self.assertEqual(consensus.support, 0)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        self.assertFalse(consensus.accepted)
        with self.assertRaises(ValueError):
            locate_bound_attested(triangle(), POINT, CONTEXT, KEYS, quorum=4)
        with self.assertRaises(ValueError):
            locate_bound_attested(triangle()[:2], POINT, CONTEXT, KEYS)

    def test_tolerance_applies(self):
        # Point (9, 0): distance 6 from a (bound 5), ~9.85 from b (bound 5),
        # 9 from c (bound 0). Records must be bound to that same query point.
        records = triangle(point=(9.0, 0.0))
        consensus = locate_bound_attested(records, (9.0, 0.0), CONTEXT, KEYS)
        self.assertEqual(consensus.rejected, ("a", "b", "c"))
        consensus = locate_bound_attested(
            records, (9.0, 0.0), CONTEXT, KEYS, tolerance=1.0
        )
        self.assertEqual(consensus.rejected, ("b", "c"))

    def test_bound_point_must_match_itemwise(self):
        # Generous bounds so every disk covers the bound point (1, 2).
        records = [
            attest("a", 3.0, 0.0, 100.0, point=(1.0, 2.0)),
            attest("b", 0.0, 4.0, 100.0, point=(1.0, 2.0)),
            attest("c", 0.0, 0.0, 100.0, point=(1.0, 2.0)),
        ]
        # Exact itemwise match works.
        consensus = locate_bound_attested(records, (1.0, 2.0), CONTEXT, KEYS)
        self.assertEqual(consensus.support, 3)
        # ints compare equal to floats item by item.
        consensus = locate_bound_attested(records, (1, 2), CONTEXT, KEYS)
        self.assertEqual(consensus.support, 3)
        for queried in ((1.0, 2.5), (0.0, 2.0), (-1.0, 2.0), (1.0000001, 2.0)):
            with self.assertRaises(ValueError, msg=repr(queried)):
                locate_bound_attested(records, queried, CONTEXT, KEYS)

    def test_context_must_match_exactly(self):
        records = triangle()
        with self.assertRaises(ValueError):
            locate_bound_attested(records, POINT, "room-8", KEYS)
        with self.assertRaises(ValueError):
            locate_bound_attested(records, POINT, "room-7 ", KEYS)
        with self.assertRaises(ValueError):
            locate_bound_attested(records, POINT, "", KEYS)

    def test_query_point_contract(self):
        records = triangle()
        for bad in ((0.0,), (0.0, 0.0, 0.0), [0.0, 0.0], (True, 0.0),
                    (math.nan, 0.0), (0.0, math.inf), None, 0.0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_bound_attested(records, bad, CONTEXT, KEYS)

    def test_query_context_contract(self):
        records = triangle()
        for bad in (None, 7, b"room-7", True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_bound_attested(records, POINT, bad, KEYS)

    def test_unknown_id_rejected(self):
        records = triangle()
        with self.assertRaises(ValueError):
            locate_bound_attested(records, POINT, CONTEXT, {"a": KEY_A, "b": KEY_B})

    def test_duplicate_id_rejected(self):
        records = triangle()
        records.append(attest("a", 1.0, 1.0))
        with self.assertRaises(ValueError):
            locate_bound_attested(records, POINT, CONTEXT, KEYS)

    def test_wrong_key_rejected(self):
        records = triangle()
        with self.assertRaises(ValueError):
            locate_bound_attested(
                records, POINT, CONTEXT, dict(KEYS, b=KEY_C)
            )

    def test_tampered_record_rejected(self):
        record = attest("a", 3.0, 0.0)
        tampered = dataclasses.replace(record, context="other")
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [tampered, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
                POINT, CONTEXT, KEYS,
            )

    def test_tampered_bytes_rejected(self):
        blob = attest("a", 3.0, 0.0).to_bytes()
        # Move the signed point inside the blob without recomputing the mac.
        tampered = blob.replace(b'"point":[0.0,0.0]', b'"point":[1.0,0.0]')
        self.assertNotEqual(tampered, blob)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [tampered, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
                POINT, CONTEXT, KEYS,
            )

    def test_record_bound_to_other_point_rejected_even_under_geometry(self):
        # a's record is bound to a different point; its disk still covers the
        # origin, but the binding mismatch must reject the whole call.
        records = [attest("a", 3.0, 0.0, point=(9.0, 0.0)),
                   attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)]
        with self.assertRaises(ValueError):
            locate_bound_attested(records, POINT, CONTEXT, KEYS)

    def test_old_record_type_rejected(self):
        old = attest_observation("a", 3.0, 0.0, decision(), 0.0, KEY_A)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                [old, attest("b", 0.0, 4.0), attest("c", 0.0, 0.0, 0.0)],
                POINT, CONTEXT, KEYS,
            )

    def test_keys_contract(self):
        records = triangle()
        for bad in ({}, None, [], "keys"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_bound_attested(records, POINT, CONTEXT, bad)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                records, POINT, CONTEXT, dict(KEYS, a=b"")
            )
        with self.assertRaises(ValueError):
            locate_bound_attested(
                records, POINT, CONTEXT, dict(KEYS, a="not-bytes")
            )

    def test_invalid_items_rejected(self):
        with self.assertRaises(ValueError):
            locate_bound_attested([1, 2, 3], POINT, CONTEXT, KEYS)
        with self.assertRaises(ValueError):
            locate_bound_attested(None, POINT, CONTEXT, KEYS)

    def test_max_age_freshness(self):
        consensus = locate_bound_attested(
            triangle(issued_at=100.0), POINT, CONTEXT, KEYS,
            now=120.0, max_age=20.0,
        )
        self.assertEqual(consensus.support, 3)
        with self.assertRaises(ValueError):
            locate_bound_attested(
                triangle(issued_at=100.0), POINT, CONTEXT, KEYS,
                now=121.0, max_age=20.0,
            )
        with self.assertRaises(ValueError):
            locate_bound_attested(
                triangle(issued_at=100.0), POINT, CONTEXT, KEYS,
                now=99.0, max_age=20.0,
            )

    def test_revocations_apply(self):
        records = triangle(issued_at=10.0)
        # Issued strictly after the revocation: accepted.
        consensus = locate_bound_attested(
            records, POINT, CONTEXT, KEYS,
            revocations=[revoke_observation("a", 5.0, KEY_A)], now=20.0,
        )
        self.assertEqual(consensus.support, 3)
        # Issued at/before revocation: rejected.
        with self.assertRaises(ValueError):
            locate_bound_attested(
                triangle(issued_at=5.0), POINT, CONTEXT, KEYS,
                revocations=[revoke_observation("a", 5.0, KEY_A)], now=20.0,
            )

    def test_revocation_bytes_mixed(self):
        records = triangle(issued_at=10.0)
        revocations = [
            revoke_observation("a", 5.0, KEY_A).to_bytes(),
            revoke_observation("b", 6.0, KEY_B),
        ]
        consensus = locate_bound_attested(
            records, POINT, CONTEXT, KEYS, revocations=revocations, now=20.0
        )
        self.assertEqual(consensus.support, 3)

    def test_call_shape_errors_raise_type_error(self):
        records = triangle()
        # Keyword-only option passed positionally.
        with self.assertRaises(TypeError):
            locate_bound_attested(records, POINT, CONTEXT, KEYS, 3)
        # Missing context argument (keys shift into its slot by name check,
        # but the call itself is missing one positional argument).
        with self.assertRaises(TypeError):
            locate_bound_attested(records, POINT, KEYS)
        # Unexpected keyword.
        with self.assertRaises(TypeError):
            locate_bound_attested(records, POINT, CONTEXT, KEYS, bogus=1)


if __name__ == "__main__":
    unittest.main()
