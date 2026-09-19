import dataclasses
import hashlib
import hmac
import json
import math
import time
import unittest

from nearproof import (
    AttestedObservation,
    Consensus,
    Observation,
    RangeDecision,
    attest_observation,
    locate,
    locate_attested,
)

KEY_A = b"key-alpha"
KEY_B = b"key-bravo"
KEY_C = b"key-charlie"
KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}


def attested(ident="a", x=3.0, y=0.0, upper_bound=5.0, issued_at=100.0,
             *, accepted=True, key=KEY_A, sample_count=1):
    return attest_observation(
        ident,
        x,
        y,
        RangeDecision(sample_count, upper_bound, accepted),
        issued_at,
        key,
    )


def triangle(issued_at=100.0):
    # Same 3-4-5 geometry as the plain locate tests.
    return [
        attested("a", 3.0, 0.0, 5.0, issued_at, key=KEY_A),
        attested("b", 0.0, 4.0, 5.0, issued_at, key=KEY_B, accepted=False),
        attested("c", 0.0, 0.0, 0.0, issued_at, key=KEY_C),
    ]


def plain_triangle():
    return [
        Observation("a", 3.0, 0.0, RangeDecision(1, 5.0, True)),
        Observation("b", 0.0, 4.0, RangeDecision(1, 5.0, False)),
        Observation("c", 0.0, 0.0, RangeDecision(1, 0.0, True)),
    ]


def payload_of(observation):
    obj = json.loads(observation.to_bytes())
    del obj["mac"]
    return obj


def mac_of(observation, key):
    blob = json.dumps(
        payload_of(observation), separators=(",", ":"), allow_nan=False
    ).encode()
    return hmac.new(key, blob, hashlib.sha256).digest()


class AttestedObservationContractTest(unittest.TestCase):
    def test_is_frozen(self):
        observation = attested()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.x = 1.0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.decision = RangeDecision(1, 1.0, True)

    def test_decision_is_frozen(self):
        observation = attested()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.decision.accepted = False

    def test_numeric_fields_normalized_to_float(self):
        observation = attested(x=3, y=0, upper_bound=5, issued_at=100)
        self.assertIsInstance(observation.x, float)
        self.assertIsInstance(observation.y, float)
        self.assertIsInstance(observation.issued_at, float)
        self.assertIsInstance(observation.decision.upper_bound, float)
        self.assertEqual(observation, attested(x=3.0, y=0.0, upper_bound=5.0,
                                               issued_at=100.0))

    def test_fields(self):
        observation = attested("v1", 1.5, 2.5, 3.5, 42.0,
                               accepted=False, sample_count=9, key=b"k")
        self.assertEqual(observation.version, 1)
        self.assertEqual(observation.id, "v1")
        self.assertEqual((observation.x, observation.y), (1.5, 2.5))
        self.assertEqual(observation.decision,
                         RangeDecision(9, 3.5, False))
        self.assertEqual(observation.issued_at, 42.0)
        self.assertEqual(len(observation.mac), 32)
        self.assertEqual(observation.mac, mac_of(observation, b"k"))

    def test_invalid_version(self):
        for version in (0, 2, -1, 1.0, True, False, "1", None):
            with self.assertRaises(ValueError, msg=version):
                AttestedObservation(
                    version, "a", 0.0, 0.0,
                    RangeDecision(1, 1.0, True), 0.0, b"\x00" * 32
                )

    def test_invalid_id(self):
        for ident in ("", b"a", 1, None, True, object()):
            with self.assertRaises(ValueError, msg=ident):
                AttestedObservation(
                    1, ident, 0.0, 0.0,
                    RangeDecision(1, 1.0, True), 0.0, b"\x00" * 32
                )

    def test_invalid_coordinates_and_time(self):
        for field, value in (
            ("x", True), ("x", False), ("x", math.nan), ("x", math.inf),
            ("x", -math.inf), ("x", -0.1), ("x", -1), ("x", "1"), ("x", None),
            ("y", True), ("y", math.nan), ("y", math.inf), ("y", -1.0),
            ("issued_at", True), ("issued_at", math.nan),
            ("issued_at", math.inf), ("issued_at", -0.0001),
        ):
            with self.assertRaises(ValueError, msg=(field, value)):
                AttestedObservation(
                    1, "a",
                    value if field == "x" else 0.0,
                    value if field == "y" else 0.0,
                    RangeDecision(1, 1.0, True),
                    value if field == "issued_at" else 0.0,
                    b"\x00" * 32,
                )

    def test_zero_coordinates_and_time_allowed(self):
        observation = AttestedObservation(
            1, "a", 0, 0, RangeDecision(1, 0, True), 0, b"\x00" * 32
        )
        self.assertEqual((observation.x, observation.y, observation.issued_at),
                         (0.0, 0.0, 0.0))

    def test_decision_wrong_type(self):
        for decision in (object(), None, 5, (1, 1.0, True),
                         {"sample_count": 1, "upper_bound": 1.0,
                          "accepted": True}):
            with self.assertRaises(ValueError, msg=decision):
                AttestedObservation(1, "a", 0.0, 0.0, decision, 0.0,
                                    b"\x00" * 32)

    def test_invalid_sample_count(self):
        for count in (0, -1, True, False, 1.0, 1.5, "1", None):
            with self.assertRaises(ValueError, msg=count):
                AttestedObservation(
                    1, "a", 0.0, 0.0,
                    RangeDecision(count, 1.0, True), 0.0, b"\x00" * 32
                )

    def test_invalid_upper_bound(self):
        for bound in (True, False, -0.1, -1, math.nan, math.inf, -math.inf,
                      "1", None):
            with self.assertRaises(ValueError, msg=bound):
                AttestedObservation(
                    1, "a", 0.0, 0.0,
                    RangeDecision(1, bound, True), 0.0, b"\x00" * 32
                )

    def test_invalid_accepted(self):
        for flag in (1, 0, "true", None, 1.0, object()):
            with self.assertRaises(ValueError, msg=flag):
                AttestedObservation(
                    1, "a", 0.0, 0.0,
                    RangeDecision(1, 1.0, flag), 0.0, b"\x00" * 32
                )

    def test_invalid_mac(self):
        for mac in (b"", b"\x00" * 31, b"\x00" * 33, None,
                    bytearray(32), "00" * 32):
            with self.assertRaises(ValueError, msg=mac):
                AttestedObservation(
                    1, "a", 0.0, 0.0,
                    RangeDecision(1, 1.0, True), 0.0, mac
                )


class SerializationTest(unittest.TestCase):
    def test_to_bytes_exact_encoding(self):
        observation = AttestedObservation(
            version=1,
            id="a",
            x=3.0,
            y=0.0,
            decision=RangeDecision(1, 5.0, False),
            issued_at=100.0,
            mac=b"\xff" * 32,
        )
        expected = (
            b'{"version":1,"id":"a","x":3.0,"y":0.0,'
            b'"decision":{"sample_count":1,"upper_bound":5.0,'
            b'"accepted":false},'
            b'"issued_at":100.0,"mac":"' + b"ff" * 32 + b'"}'
        )
        self.assertEqual(observation.to_bytes(), expected)

    def test_to_bytes_has_no_whitespace(self):
        blob = attested().to_bytes()
        self.assertNotIn(b" ", blob)
        self.assertNotIn(b"\n", blob)

    def test_top_level_key_order(self):
        self.assertEqual(
            list(json.loads(attested().to_bytes()).keys()),
            ["version", "id", "x", "y", "decision", "issued_at", "mac"],
        )

    def test_decision_key_order(self):
        self.assertEqual(
            list(json.loads(attested().to_bytes())["decision"].keys()),
            ["sample_count", "upper_bound", "accepted"],
        )

    def test_round_trip(self):
        observation = attested("a", 3, 0, 5, 100, accepted=False)
        decoded = AttestedObservation.from_bytes(observation.to_bytes())
        self.assertEqual(decoded, observation)

    def test_from_bytes_rejects_non_bytes(self):
        blob = attested().to_bytes()
        for bad in (blob.decode(), 123, None, object(), bytearray(blob), ["x"]):
            with self.assertRaises(ValueError, msg=bad):
                AttestedObservation.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"not json", b"[1,2,3]", b"{}", b"\xff\xfe",
                    b"null", b'"x"'):
            with self.assertRaises(ValueError, msg=bad):
                AttestedObservation.from_bytes(bad)

    def test_from_bytes_rejects_contract_violations(self):
        good = json.loads(attested().to_bytes())

        def mutated(**changes):
            obj = json.loads(json.dumps(good))
            obj.update(changes)
            return json.dumps(obj).encode()

        def mutate_decision(**changes):
            obj = json.loads(json.dumps(good))
            obj["decision"].update(changes)
            return json.dumps(obj).encode()

        cases = [
            mutated(version=2), mutated(version=0),
            mutated(version=True), mutated(version=1.0),
            mutated(id=""), mutated(id=7), mutated(id=True),
            mutated(x=-1.0), mutated(x=True), mutated(x="0"),
            mutated(x=None),
            mutated(y=math.nan), mutated(y=math.inf),
            mutated(issued_at=-0.5), mutated(issued_at=False),
            mutate_decision(sample_count=0),
            mutate_decision(sample_count=-2),
            mutate_decision(sample_count=True),
            mutate_decision(sample_count=2.0),
            mutate_decision(upper_bound=-0.01),
            mutate_decision(upper_bound=True),
            mutate_decision(upper_bound=math.inf),
            mutate_decision(accepted="true"),
            mutate_decision(accepted=1),
            mutate_decision(accepted=None),
            mutated(decision=5),
            mutated(decision=None),
            mutated(mac="AA" * 32),
            mutated(mac="zz" * 32),
            mutated(mac=123),
            mutated(mac="00" * 31),
            mutated(mac="00" * 33),
        ]

        missing = dict(good)
        del missing["id"]
        cases.append(json.dumps(missing).encode())
        extra = dict(good)
        extra["extra"] = 1
        cases.append(json.dumps(extra).encode())
        decision_extra = json.loads(json.dumps(good))
        decision_extra["decision"]["extra"] = 1
        cases.append(json.dumps(decision_extra).encode())
        decision_missing = json.loads(json.dumps(good))
        del decision_missing["decision"]["accepted"]
        cases.append(json.dumps(decision_missing).encode())

        for blob in cases:
            with self.assertRaises(ValueError, msg=blob):
                AttestedObservation.from_bytes(blob)

    def test_from_bytes_rejects_reordered_keys(self):
        good = json.loads(attested().to_bytes())

        reordered = {"id": good["id"], "version": good["version"],
                     **{k: v for k, v in good.items() if k not in ("id", "version")}}
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(json.dumps(reordered).encode())

        decision = good["decision"]
        good["decision"] = {
            "upper_bound": decision["upper_bound"],
            "sample_count": decision["sample_count"],
            "accepted": decision["accepted"],
        }
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(json.dumps(good).encode())

    def test_from_bytes_rejects_duplicate_keys(self):
        blob = attested().to_bytes()
        duplicated = blob.replace(b'"version":1,', b'"version":1,"version":1,', 1)
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(duplicated)
        duplicated = blob.replace(
            b'"mac":"', b'"mac":"00","mac":"', 1
        )
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(duplicated)
        duplicated = blob.replace(
            b'"accepted":true}',
            b'"accepted":true,"accepted":true}',
            1,
        )
        with self.assertRaises(ValueError):
            AttestedObservation.from_bytes(duplicated)

    def test_from_bytes_accepts_whitespace(self):
        # Only the key contract is strict; JSON whitespace parses normally.
        observation = attested()
        pretty = json.dumps(json.loads(observation.to_bytes()), indent=2).encode()
        self.assertEqual(AttestedObservation.from_bytes(pretty), observation)


class AttestObservationTest(unittest.TestCase):
    def test_mac_matches_definition(self):
        observation = attested(key=KEY_A)
        self.assertEqual(observation.mac, mac_of(observation, KEY_A))
        self.assertNotEqual(observation.mac, mac_of(observation, KEY_B))

    def test_empty_key_rejected(self):
        for key in (b"", "", bytearray()):
            with self.assertRaises(ValueError, msg=key):
                attest_observation("a", 0.0, 0.0,
                                   RangeDecision(1, 1.0, True), 0.0, key)

    def test_fields_validated(self):
        with self.assertRaises(ValueError):
            attest_observation("", 0.0, 0.0,
                               RangeDecision(1, 1.0, True), 0.0, KEY_A)
        with self.assertRaises(ValueError):
            attest_observation("a", -1.0, 0.0,
                               RangeDecision(1, 1.0, True), 0.0, KEY_A)
        with self.assertRaises(ValueError):
            attest_observation("a", 0.0, 0.0,
                               RangeDecision(0, 1.0, True), 0.0, KEY_A)

    def test_bytearray_key_accepted(self):
        observation = attest_observation(
            "a", 0.0, 0.0, RangeDecision(1, 1.0, True), 0.0, bytearray(KEY_A)
        )
        self.assertEqual(observation.mac, mac_of(observation, KEY_A))


class LocateAttestedHappyPathTest(unittest.TestCase):
    def test_matches_plain_locate(self):
        self.assertEqual(
            locate_attested(triangle(), (0.0, 0.0), KEYS),
            locate(plain_triangle(), (0.0, 0.0)),
        )

    def test_geometry_and_rejected_ids(self):
        consensus = locate_attested(triangle(), (3.0, 4.0), KEYS)
        self.assertIsInstance(consensus, Consensus)
        self.assertEqual(consensus.total, 3)
        self.assertEqual(consensus.support, 2)
        self.assertEqual(consensus.rejected, ("c",))
        self.assertFalse(consensus.accepted)
        self.assertTrue(
            locate_attested(triangle(), (3.0, 4.0), KEYS, quorum=2).accepted
        )

    def test_mixed_objects_and_bytes(self):
        observations = triangle()
        mixed = [
            observations[0],
            observations[1].to_bytes(),
            observations[2].to_bytes(),
        ]
        self.assertEqual(
            locate_attested(mixed, (0.0, 0.0), KEYS),
            locate_attested(observations, (0.0, 0.0), KEYS),
        )

    def test_all_bytes(self):
        observations = triangle()
        blobs = [item.to_bytes() for item in observations]
        consensus = locate_attested(blobs, (0.0, 0.0), KEYS)
        self.assertTrue(consensus.accepted)

    def test_accepted_flag_ignored(self):
        # b's decision says accepted=False; its disk still covers the origin.
        consensus = locate_attested(triangle(), (0.0, 0.0), KEYS)
        self.assertEqual(consensus.support, 3)

    def test_tolerance_and_quorum(self):
        observations = [
            attested("a", 5.0, 0.0, 5.0, key=KEY_A),
            attested("b", 0.0, 5.0, 100.0, key=KEY_B),
            attested("c", 0.0, 0.0, 100.0, key=KEY_C),
        ]
        self.assertEqual(
            locate_attested(observations, (10.5, 0.0), KEYS).rejected,
            ("a",),
        )
        self.assertEqual(
            locate_attested(observations, (10.5, 0.0), KEYS,
                            tolerance=0.5).support,
            3,
        )

    def test_extra_keys_mapping_entries_are_fine(self):
        keys = dict(KEYS)
        keys["unused"] = b"other"
        consensus = locate_attested(triangle(), (0.0, 0.0), keys)
        self.assertTrue(consensus.accepted)

    def test_generator_input(self):
        consensus = locate_attested(iter(triangle()), (0.0, 0.0), KEYS)
        self.assertEqual(consensus.total, 3)


class LocateAttestedVerificationTest(unittest.TestCase):
    def test_unknown_id_rejected(self):
        observations = triangle()
        observations[0] = dataclasses.replace(observations[0], id="stranger")
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS)

    def test_duplicate_id_rejected(self):
        observations = triangle()
        observations[1] = dataclasses.replace(observations[1], id="a")
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS)

    def test_duplicate_id_across_mixed_encodings(self):
        observations = triangle()
        observations[1] = dataclasses.replace(observations[1], id="a")
        mixed = [observations[0].to_bytes(), observations[1], observations[2]]
        with self.assertRaises(ValueError):
            locate_attested(mixed, (0.0, 0.0), KEYS)

    def test_wrong_key_rejected(self):
        observations = triangle()
        keys = dict(KEYS)
        keys["a"] = KEY_B
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), keys)

    def test_empty_registered_key_rejected(self):
        for empty in (b"", bytearray()):
            keys = dict(KEYS)
            keys["a"] = empty
            with self.assertRaises(ValueError, msg=empty):
                locate_attested(triangle(), (0.0, 0.0), keys)

    def test_keys_must_be_mapping(self):
        for bad in ([("a", KEY_A)], None, 123, True):
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(triangle(), (0.0, 0.0), bad)

    def test_tampered_fields_rejected(self):
        base = attested()
        tampered_cases = [
            dataclasses.replace(base, x=2.0),
            dataclasses.replace(base, y=1.0),
            dataclasses.replace(base, id="b"),
            dataclasses.replace(base, issued_at=99.0),
            dataclasses.replace(base, decision=RangeDecision(1, 4.0, True)),
            dataclasses.replace(
                base, decision=RangeDecision(1, 5.0, False)
            ),
            dataclasses.replace(base, version=1),  # identical, control
        ]
        for index, observation in enumerate(tampered_cases):
            observations = [observation] + triangle()[1:]
            if index == len(tampered_cases) - 1:
                # The control case is a: id a, key a, unchanged values.
                consensus = locate_attested(observations, (0.0, 0.0), KEYS)
                self.assertTrue(consensus.accepted)
            else:
                with self.assertRaises(ValueError, msg=index):
                    locate_attested(observations, (0.0, 0.0), KEYS)

    def test_tampered_bytes_rejected(self):
        blob = attested().to_bytes()
        tampered = blob.replace(b'"x":3.0', b'"x":2.0', 1)
        self.assertNotEqual(tampered, blob)
        observations = [tampered] + [o.to_bytes() for o in triangle()[1:]]
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS)

    def test_mac_checked_for_every_observation(self):
        # A wrong key for the last verifier must still be detected.
        keys = dict(KEYS)
        keys["c"] = b"not-the-charlie-key"
        with self.assertRaises(ValueError):
            locate_attested(triangle(), (0.0, 0.0), keys)

    def test_resign_with_correct_key_verifies(self):
        # A holder of the real key can re-sign a modified record and pass the
        # MAC check (the geometry then reflects the modified upper_bound).
        base = triangle()[0]
        resigned = attest_observation(
            base.id, base.x, base.y,
            RangeDecision(1, 100.0, True), base.issued_at, KEY_A
        )
        observations = [resigned] + triangle()[1:]
        consensus = locate_attested(observations, (0.0, 0.0), KEYS)
        self.assertEqual(consensus.support, 3)


class LocateAttestedInputValidationTest(unittest.TestCase):
    def test_non_iterable_observations(self):
        for bad in (123, None, 5.0, object(), True):
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(bad, (0.0, 0.0), KEYS)

    def test_element_wrong_type(self):
        observations = triangle()
        for bad in ("x", 123, None, object(), bytearray(),
                    plain_triangle()[0], RangeDecision(1, 1.0, True)):
            with self.assertRaises(ValueError, msg=bad):
                locate_attested([bad] + observations[1:], (0.0, 0.0), KEYS)

    def test_malformed_bytes_element(self):
        observations = [b"not json"] + triangle()[1:]
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS)

    def test_too_few_observations_delegated_to_locate(self):
        for count in (0, 1, 2):
            with self.assertRaises(ValueError, msg=count):
                locate_attested(triangle()[:count], (0.0, 0.0), KEYS)

    def test_invalid_point_delegated(self):
        for bad in ((0.0,), [0.0, 0.0], (True, 0.0), (math.nan, 0.0), None):
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(triangle(), bad, KEYS)

    def test_invalid_quorum_delegated(self):
        for bad in (0, True, 2.5, 4):
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(triangle(), (0.0, 0.0), KEYS, quorum=bad)

    def test_invalid_tolerance_delegated(self):
        for bad in (True, -0.1, math.nan, math.inf, "1"):
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(triangle(), (0.0, 0.0), KEYS, tolerance=bad)

    def test_options_are_keyword_only(self):
        with self.assertRaises(TypeError):
            locate_attested(triangle(), (0.0, 0.0), KEYS, 3, 0.0)
        with self.assertRaises(TypeError):
            locate_attested(triangle(), (0.0, 0.0), KEYS, 3, 0.0, 100.0, 10.0)


class FreshnessTest(unittest.TestCase):
    def test_max_age_none_skips_freshness(self):
        old = [
            attested("a", 3.0, 0.0, 5.0, 0.0, key=KEY_A),
            attested("b", 0.0, 4.0, 5.0, 0.0, key=KEY_B),
            attested("c", 0.0, 0.0, 0.0, 0.0, key=KEY_C),
        ]
        consensus = locate_attested(old, (0.0, 0.0), KEYS, now=9_999_999.0)
        self.assertTrue(consensus.accepted)

    def test_closed_age_window_boundaries(self):
        observations = triangle(issued_at=100.0)
        self.assertTrue(
            locate_attested(observations, (0.0, 0.0), KEYS,
                            now=100.0, max_age=1.0).accepted
        )
        self.assertTrue(
            locate_attested(observations, (0.0, 0.0), KEYS,
                            now=101.0, max_age=1.0).accepted
        )
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS,
                            now=101.0 + 1e-12, max_age=1.0)

    def test_future_issued_at_rejected(self):
        with self.assertRaises(ValueError):
            locate_attested(triangle(100.0), (0.0, 0.0), KEYS,
                            now=99.0, max_age=10.0)

    def test_stale_observation_rejected(self):
        observations = [
            attested("a", 3.0, 0.0, 5.0, 90.0, key=KEY_A),
            attested("b", 0.0, 4.0, 5.0, 100.0, key=KEY_B),
            attested("c", 0.0, 0.0, 0.0, 100.0, key=KEY_C),
        ]
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS,
                            now=100.0, max_age=5.0)

    def test_zero_max_age_requires_exact_age(self):
        observations = triangle(issued_at=100.0)
        self.assertTrue(
            locate_attested(observations, (0.0, 0.0), KEYS,
                            now=100.0, max_age=0.0).accepted
        )
        with self.assertRaises(ValueError):
            locate_attested(observations, (0.0, 0.0), KEYS,
                            now=100.0 + 1e-9, max_age=0.0)

    def test_invalid_max_age(self):
        for bad in (-0.1, -1, True, False, math.nan, math.inf, -math.inf,
                    "1", None):
            # None is the "no freshness check" sentinel, not an error.
            if bad is None:
                locate_attested(triangle(), (0.0, 0.0), KEYS, max_age=None)
                continue
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(triangle(), (0.0, 0.0), KEYS,
                                now=100.0, max_age=bad)

    def test_invalid_now(self):
        for bad in (True, False, math.nan, math.inf, "100", None):
            if bad is None:
                # None falls back to time.time(); use a fresh observation.
                observations = triangle(issued_at=time.time())
                consensus = locate_attested(
                    observations, (0.0, 0.0), KEYS, max_age=60.0
                )
                self.assertTrue(consensus.accepted)
                continue
            with self.assertRaises(ValueError, msg=bad):
                locate_attested(triangle(), (0.0, 0.0), KEYS,
                                now=bad, max_age=10.0)

    def test_default_now_uses_wall_clock(self):
        fresh = [
            attested("a", 3.0, 0.0, 5.0, time.time() - 1.0, key=KEY_A),
            attested("b", 0.0, 4.0, 5.0, time.time() - 1.0, key=KEY_B),
            attested("c", 0.0, 0.0, 0.0, time.time() - 1.0, key=KEY_C),
        ]
        self.assertTrue(
            locate_attested(fresh, (0.0, 0.0), KEYS, max_age=60.0).accepted
        )
        stale = [
            attested(n, 0.0, 0.0, 100.0, time.time() - 3600.0, key=k)
            for n, k in (("a", KEY_A), ("b", KEY_B), ("c", KEY_C))
        ]
        with self.assertRaises(ValueError):
            locate_attested(stale, (0.0, 0.0), KEYS, max_age=1.0)


if __name__ == "__main__":
    unittest.main()
