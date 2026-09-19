import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    Challenge,
    ChallengeStateError,
    Evidence,
    Measurement,
    Prover,
    Verifier,
    audit,
    keyed_response,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


class SteppedClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class ListClock:
    """Records every reading so tests can count clock calls."""

    def __init__(self) -> None:
        self.readings = []

    def __call__(self) -> float:
        self.readings.append(len(self.readings) * 0.5)
        return self.readings[-1]


def issue(clock=None, **verifier_kwargs):
    clock = clock or SteppedClock()
    verifier_kwargs.setdefault("replay_protection", True)
    prover = Prover(KEY)
    verifier = Verifier(KEY, clock=clock, **verifier_kwargs)
    challenge = verifier.new_challenge()
    started = clock.now
    response = prover.respond(challenge)
    return verifier, challenge, response, started


def make_evidence(**verifier_kwargs):
    clock = SteppedClock()
    verifier, challenge, response, started = issue(clock, **verifier_kwargs)
    clock.now += 1e-6
    evidence = verifier.verify_evidence(challenge, response, started)
    return evidence


def payload_of(evidence):
    obj = json.loads(evidence.to_bytes())
    del obj["mac"]
    return obj


def mac_of(evidence, key):
    blob = json.dumps(payload_of(evidence), separators=(",", ":"), allow_nan=False).encode()
    return hmac.new(key, blob, hashlib.sha256).digest()


class EvidenceRecordTest(unittest.TestCase):
    def test_fields_of_accepted_round(self):
        evidence = make_evidence()
        self.assertEqual(evidence.version, 1)
        self.assertEqual(evidence.result, "accepted")
        self.assertEqual(evidence.round_index, 1)
        self.assertIsInstance(evidence.nonce, bytes)
        self.assertIsInstance(evidence.response, bytes)
        self.assertEqual(evidence.response, keyed_response(KEY, evidence.nonce))
        self.assertEqual(evidence.elapsed, evidence.end - evidence.start)
        self.assertEqual(evidence.distance, evidence.elapsed * evidence.speed / 2.0)
        self.assertEqual(evidence.speed, 299_792_458.0)
        self.assertEqual(len(evidence.mac), 32)

    def test_is_frozen(self):
        evidence = make_evidence()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            evidence.result = "rejected"

    def test_start_is_float_of_started_at(self):
        clock = SteppedClock()
        verifier, challenge, response, _started = issue(clock)
        clock.now = 2.0
        evidence = verifier.verify_evidence(challenge, response, 1)
        self.assertEqual(evidence.start, 1.0)
        self.assertIsInstance(evidence.start, float)
        self.assertEqual(evidence.end, 2.0)

    def test_end_is_the_single_clock_reading(self):
        clock = ListClock()
        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        challenge = verifier.new_challenge()
        self.assertEqual(clock.readings, [])
        evidence = verifier.verify_evidence(challenge, prover.respond(challenge), 0.0)
        self.assertEqual(len(clock.readings), 1)
        self.assertEqual(evidence.end, clock.readings[0])

    def test_custom_speed_is_recorded(self):
        evidence = make_evidence(speed_mps=100.0)
        self.assertEqual(evidence.speed, 100.0)
        self.assertEqual(evidence.distance, evidence.elapsed * 100.0 / 2.0)


class VerifyEvidenceStateTest(unittest.TestCase):
    """verify_evidence reuses verify's state/TTL/consumption semantics."""

    def test_success_consumes_challenge(self):
        verifier, challenge, response, started = issue()
        verifier.verify_evidence(challenge, response, started)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, response, started)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, started)

    def test_verify_then_verify_evidence_is_rejected(self):
        verifier, challenge, response, started = issue()
        verifier.verify(challenge, response, started)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, response, started)

    def test_bad_response_does_not_consume(self):
        verifier, challenge, response, started = issue()
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, b"\x00" * 32, started)
        evidence = verifier.verify_evidence(challenge, response, started)
        self.assertIsInstance(evidence, Evidence)

    def test_unknown_challenge_rejected(self):
        verifier, _challenge, _response, started = issue()
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(Challenge(1, b"x" * 16), b"\x00" * 32, started)

    def test_revoked_challenge_rejected(self):
        verifier, challenge, response, started = issue()
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, response, started)

    def test_expired_challenge_rejected(self):
        clock = SteppedClock()
        verifier, challenge, response, started = issue(clock, challenge_ttl_seconds=1.0)
        clock.now = 2.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, response, started)

    def test_non_challenge_rejected(self):
        verifier, _challenge, _response, started = issue()
        with self.assertRaises(TypeError):
            verifier.verify_evidence(object(), b"\x00" * 32, started)

    def test_legacy_mode_without_replay_protection(self):
        verifier = Verifier(KEY, replay_protection=False)
        challenge = Challenge(7, b"n" * 16)
        evidence = verifier.verify_evidence(
            challenge, keyed_response(KEY, challenge.nonce), 0.0
        )
        self.assertEqual(evidence.round_index, 7)
        audit(evidence, KEY)


class NonFiniteTest(unittest.TestCase):
    def test_nan_started_at_rejected_without_consuming(self):
        verifier, challenge, response, _started = issue()
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, math.nan)
        # challenge is still pending
        verifier.verify_evidence(challenge, response, 0.0)

    def test_inf_started_at_rejected_without_consuming(self):
        verifier, challenge, response, _started = issue()
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, math.inf)
        verifier.verify_evidence(challenge, response, 0.0)

    def test_nan_clock_reading_rejected_without_consuming(self):
        clock = SteppedClock()
        verifier, challenge, response, started = issue(clock)
        clock.now = math.nan
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, started)
        clock.now = 1.0
        verifier.verify_evidence(challenge, response, started)

    def test_legacy_verify_unchanged_by_finite_rule(self):
        # The old interface keeps its previous behaviour for non-finite input.
        verifier, challenge, response, _started = issue()
        measurement = verifier.verify(challenge, response, math.nan)
        self.assertTrue(math.isnan(measurement.elapsed_seconds))


class SerializationTest(unittest.TestCase):
    def test_to_bytes_exact_encoding(self):
        evidence = Evidence(
            version=1,
            round_index=3,
            nonce=b"\xab" * 16,
            response=b"\x01" * 32,
            start=1.0,
            end=2.5,
            speed=100.0,
            elapsed=1.5,
            distance=75.0,
            result="accepted",
            mac=b"\xff" * 32,
        )
        expected = (
            b'{"version":1,"round_index":3,'
            b'"nonce":"' + b"ab" * 16 + b'",'
            b'"response":"' + b"01" * 32 + b'",'
            b'"start":1.0,"end":2.5,"speed":100.0,'
            b'"elapsed":1.5,"distance":75.0,'
            b'"result":"accepted",'
            b'"mac":"' + b"ff" * 32 + b'"}'
        )
        self.assertEqual(evidence.to_bytes(), expected)

    def test_to_bytes_key_order(self):
        evidence = make_evidence()
        keys = list(json.loads(evidence.to_bytes()).keys())
        self.assertEqual(
            keys,
            ["version", "round_index", "nonce", "response", "start", "end",
             "speed", "elapsed", "distance", "result", "mac"],
        )

    def test_mac_definition(self):
        evidence = make_evidence()
        self.assertEqual(evidence.mac, mac_of(evidence, KEY))
        self.assertNotEqual(evidence.mac, mac_of(evidence, OTHER_KEY))

    def test_round_trip(self):
        evidence = make_evidence()
        self.assertEqual(Evidence.from_bytes(evidence.to_bytes()), evidence)

    def test_from_bytes_rejects_non_bytes(self):
        evidence = make_evidence()
        for bad in (evidence.to_bytes().decode(), 123, None, object(), ["x"]):
            with self.assertRaises(ValueError):
                Evidence.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (b"", b"not json", b"[1,2,3]", b"{}", b"\xff\xfe"):
            with self.assertRaises(ValueError):
                Evidence.from_bytes(bad)

    def test_from_bytes_rejects_contract_violations(self):
        evidence = make_evidence()
        good = json.loads(evidence.to_bytes())

        def mutated(**changes):
            obj = dict(good)
            obj.update(changes)
            return json.dumps(obj).encode()

        cases = [
            mutated(version=2),
            mutated(version=True),
            mutated(version=1.0),
            mutated(round_index=True),
            mutated(round_index=1.5),
            mutated(start="1.0"),
            mutated(start=True),
            mutated(end=None),
            mutated(nonce=good["nonce"].upper()),
            mutated(nonce="zz"),
            mutated(nonce=123),
            mutated(response="0"),  # odd-length hex
            mutated(mac="AA" * 32),
            mutated(result="rejected"),
            mutated(result=1),
        ]
        # missing and extra keys
        obj = dict(good)
        del obj["mac"]
        cases.append(json.dumps(obj).encode())
        obj = dict(good)
        obj["extra"] = 1
        cases.append(json.dumps(obj).encode())
        # NaN/Infinity tokens (json.loads accepts them by default)
        obj = dict(good)
        obj["elapsed"] = float("nan")
        cases.append(json.dumps(obj).encode())
        obj = dict(good)
        obj["distance"] = float("inf")
        cases.append(json.dumps(obj).encode())

        for blob in cases:
            with self.assertRaises(ValueError, msg=blob):
                Evidence.from_bytes(blob)


class AuditTest(unittest.TestCase):
    def test_audit_returns_measurement(self):
        evidence = make_evidence()
        measurement = audit(evidence, KEY)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.round_index, evidence.round_index)
        self.assertEqual(measurement.nonce, evidence.nonce)
        self.assertEqual(measurement.response, evidence.response)
        self.assertEqual(measurement.elapsed_seconds, evidence.elapsed)
        self.assertEqual(measurement.distance_meters, evidence.distance)

    def test_audit_accepts_bytes(self):
        evidence = make_evidence()
        self.assertEqual(audit(evidence.to_bytes(), KEY), audit(evidence, KEY))

    def test_audit_rejects_empty_key(self):
        evidence = make_evidence()
        for bad in (b"", "", bytearray()):
            with self.assertRaises(ValueError):
                audit(evidence, bad)

    def test_audit_rejects_bad_evidence_type(self):
        for bad in ("x", 123, None, {"version": 1}):
            with self.assertRaises(ValueError):
                audit(bad, KEY)

    def test_audit_rejects_wrong_key(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit(evidence, OTHER_KEY)

    def test_audit_rejects_tampered_fields(self):
        evidence = make_evidence()
        for field, value in (
            ("round_index", evidence.round_index + 1),
            ("nonce", b"\x00" * 16),
            ("start", evidence.start + 1.0),
            ("distance", evidence.distance + 1.0),
            ("result", "accepted "),  # caught before mac check
        ):
            tampered = dataclasses.replace(evidence, **{field: value})
            with self.assertRaises(ValueError, msg=field):
                audit(tampered, KEY)

    def test_audit_recomputes_elapsed_and_distance(self):
        # Even with a valid MAC (attacker knows the key), the recomputed
        # elapsed/distance must match the recorded ones.
        evidence = make_evidence()
        tampered = dataclasses.replace(evidence, elapsed=evidence.elapsed + 1.0)
        tampered = dataclasses.replace(tampered, mac=mac_of(tampered, KEY))
        with self.assertRaises(ValueError):
            audit(tampered, KEY)

        tampered = dataclasses.replace(evidence, distance=evidence.distance + 1.0)
        tampered = dataclasses.replace(tampered, mac=mac_of(tampered, KEY))
        with self.assertRaises(ValueError):
            audit(tampered, KEY)

    def test_audit_recomputes_response(self):
        evidence = make_evidence()
        tampered = dataclasses.replace(evidence, response=b"\x00" * 32)
        tampered = dataclasses.replace(tampered, mac=mac_of(tampered, KEY))
        with self.assertRaises(ValueError):
            audit(tampered, KEY)

    def test_audit_validates_in_memory_evidence(self):
        evidence = make_evidence()
        for bad in (
            dataclasses.replace(evidence, version=2),
            dataclasses.replace(evidence, result="rejected"),
            dataclasses.replace(evidence, elapsed=math.inf),
            dataclasses.replace(evidence, start=True),
        ):
            with self.assertRaises(ValueError):
                audit(bad, KEY)


if __name__ == "__main__":
    unittest.main()
