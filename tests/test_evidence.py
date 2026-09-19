import hashlib
import hmac
import json
import math
import unittest
from dataclasses import replace

from nearproof import (
    SPEED_OF_LIGHT_MPS,
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


def fixture(**kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


def make_evidence(verifier, prover, clock, trip=1e-6, **verify_kwargs):
    challenge = verifier.new_challenge()
    started = clock.now
    response = prover.respond(challenge)
    clock.now += trip
    method = verify_kwargs.pop("method", verifier.verify_evidence)
    return method(challenge, response, started, **verify_kwargs)


class VerifyEvidenceTest(unittest.TestCase):
    def test_fields(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock, trip=2e-6)
        self.assertIsInstance(evidence, Evidence)
        self.assertEqual(evidence.version, 1)
        self.assertEqual(evidence.result, "accepted")
        self.assertEqual(evidence.round_index, 1)
        self.assertEqual(evidence.start, 0.0)
        self.assertEqual(evidence.end, 2e-6)
        self.assertEqual(evidence.speed, SPEED_OF_LIGHT_MPS)
        self.assertEqual(evidence.elapsed, 2e-6)
        self.assertEqual(evidence.distance, 2e-6 * SPEED_OF_LIGHT_MPS / 2.0)
        self.assertEqual(evidence.response, keyed_response(KEY, evidence.nonce))
        self.assertEqual(len(evidence.mac), 32)

    def test_mac_is_keyed_hmac_over_fields_without_mac(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        obj = json.loads(evidence.to_bytes().decode("utf-8"))
        del obj["mac"]
        signed = json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(
            evidence.mac, hmac.new(KEY, signed, hashlib.sha256).digest()
        )

    def test_matches_verify_measurement(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock, trip=3e-6)
        clock2, prover2, verifier2 = fixture()
        measurement = make_evidence(
            verifier2, prover2, clock2, trip=3e-6, method=verifier2.verify
        )
        self.assertEqual(evidence.elapsed, measurement.elapsed_seconds)
        self.assertEqual(evidence.distance, measurement.distance_meters)

    def test_replay_protection_consumes_atomically(self):
        clock, prover, verifier = fixture(replay_protection=True)
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        verifier.verify_evidence(challenge, response, clock.now)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, response, clock.now)

    def test_failed_validation_does_not_consume(self):
        clock, prover, verifier = fixture(replay_protection=True)
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, b"\x00" * 32, clock.now)
        evidence = verifier.verify_evidence(challenge, prover.respond(challenge), clock.now)
        self.assertEqual(evidence.round_index, challenge.round_index)

    def test_ttl_expiry_is_terminal(self):
        clock, prover, verifier = fixture(
            replay_protection=True, challenge_ttl_seconds=0.05
        )
        challenge = verifier.new_challenge()
        clock.now += 0.05
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, prover.respond(challenge), 0.0)
        clock.now = 0.0  # rolling the clock back must not revive it
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, prover.respond(challenge), 0.0)

    def test_non_finite_start_rejected_without_consuming(self):
        clock, prover, verifier = fixture(replay_protection=True)
        for bad in (math.nan, math.inf, -math.inf):
            challenge = verifier.new_challenge()
            with self.assertRaises(ValueError):
                verifier.verify_evidence(challenge, prover.respond(challenge), bad)
            # still pending: a valid retry succeeds
            verifier.verify_evidence(challenge, prover.respond(challenge), clock.now)

    def test_non_finite_clock_reading_rejected(self):
        class NanClock:
            def __call__(self):
                return math.nan

        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=NanClock())
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, prover.respond(challenge), 0.0)

    def test_old_verify_still_accepts_non_finite(self):
        # verify is unchanged: only verify_evidence rejects non-finite numbers.
        prover = Prover(KEY)
        verifier = Verifier(KEY)
        challenge = verifier.new_challenge()
        measurement = verifier.verify(challenge, prover.respond(challenge), math.nan)
        self.assertTrue(math.isnan(measurement.elapsed_seconds))

    def test_type_checks_match_verify(self):
        clock, prover, verifier = fixture()
        with self.assertRaises(TypeError):
            verifier.verify_evidence(b"not-a-challenge", b"\x00" * 32, clock.now)


class EvidenceEncodingTest(unittest.TestCase):
    def test_to_bytes_canonical_form(self):
        evidence = Evidence(
            version=1,
            round_index=7,
            nonce=b"\x01" * 16,
            response=b"\x02" * 32,
            start=1.5,
            end=2.5,
            speed=100.0,
            elapsed=1.0,
            distance=50.0,
            result="accepted",
            mac=b"\x03" * 32,
        )
        self.assertEqual(
            evidence.to_bytes(),
            b'{"version":1,"round_index":7,'
            b'"nonce":"' + b"01" * 16 + b'",'
            b'"response":"' + b"02" * 32 + b'",'
            b'"start":1.5,"end":2.5,"speed":100.0,'
            b'"elapsed":1.0,"distance":50.0,'
            b'"result":"accepted",'
            b'"mac":"' + b"03" * 32 + b'"}',
        )

    def test_round_trip(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        self.assertEqual(Evidence.from_bytes(evidence.to_bytes()), evidence)
        self.assertEqual(
            Evidence.from_bytes(evidence.to_bytes()).to_bytes(), evidence.to_bytes()
        )

    def test_frozen(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        with self.assertRaises(AttributeError):
            evidence.distance = 1.0

    def test_from_bytes_rejects_non_bytes(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        for bad in (evidence.to_bytes().decode(), bytearray(evidence.to_bytes()), 42, None):
            with self.assertRaises(ValueError):
                Evidence.from_bytes(bad)

    def test_from_bytes_rejects_invalid_json_and_shapes(self):
        for bad in (
            b"",
            b"not json",
            b"\xff\xfe",
            b"[]",
            b"null",
            b"{}",
            b'{"version":1}',
        ):
            with self.assertRaises(ValueError):
                Evidence.from_bytes(bad)

    def _mutated(self, evidence, **changes):
        obj = json.loads(evidence.to_bytes().decode("utf-8"))
        obj.update(changes)
        return json.dumps(obj, separators=(",", ":")).encode()

    def test_from_bytes_rejects_contract_violations(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        cases = [
            self._mutated(evidence, version=2),
            self._mutated(evidence, version=True),
            self._mutated(evidence, round_index=True),
            self._mutated(evidence, round_index=1.5),
            self._mutated(evidence, nonce="012"),  # odd length
            self._mutated(evidence, nonce="AB" * 16),  # uppercase
            self._mutated(evidence, nonce="zz" * 16),
            self._mutated(evidence, nonce=16),
            self._mutated(evidence, mac="ab" * 16),  # wrong length
            self._mutated(evidence, result="rejected"),
            self._mutated(evidence, start=True),
            self._mutated(evidence, start="0.0"),
            self._mutated(evidence, start=float("nan")),
            self._mutated(evidence, end=float("inf")),
            self._mutated(evidence, speed=None),
        ]
        # missing and extra keys
        obj = json.loads(evidence.to_bytes().decode("utf-8"))
        del obj["distance"]
        cases.append(json.dumps(obj, separators=(",", ":")).encode())
        cases.append(self._mutated(evidence, extra=1))
        for bad in cases:
            with self.assertRaises(ValueError, msg=bad):
                Evidence.from_bytes(bad)

    def test_from_bytes_rejects_out_of_order_keys(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        obj = json.loads(evidence.to_bytes().decode("utf-8"))
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            Evidence.from_bytes(json.dumps(reordered).encode())


class AuditTest(unittest.TestCase):
    def test_audit_returns_measurement(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock, trip=4e-6)
        measurement = audit(evidence, KEY)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.round_index, evidence.round_index)
        self.assertEqual(measurement.nonce, evidence.nonce)
        self.assertEqual(measurement.response, evidence.response)
        self.assertEqual(measurement.elapsed_seconds, evidence.elapsed)
        self.assertEqual(measurement.distance_meters, evidence.distance)

    def test_audit_accepts_bytes(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        self.assertEqual(audit(evidence.to_bytes(), KEY), audit(evidence, KEY))

    def test_audit_rejects_empty_key(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        with self.assertRaises(ValueError):
            audit(evidence, b"")

    def test_audit_rejects_wrong_key(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        with self.assertRaises(ValueError):
            audit(evidence, OTHER_KEY)

    def test_audit_rejects_tampering(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        tampered = [
            replace(evidence, distance=evidence.distance * 2),
            replace(evidence, elapsed=evidence.elapsed * 2),
            replace(evidence, start=evidence.start + 1.0),
            replace(evidence, speed=evidence.speed * 2),
            replace(evidence, nonce=b"\x00" * 16),
            replace(evidence, response=b"\x00" * 32),
            replace(evidence, mac=b"\x00" * 32),
            replace(evidence, round_index=evidence.round_index + 1),
        ]
        for bad in tampered:
            with self.assertRaises(ValueError):
                audit(bad, KEY)

    def test_audit_rejects_inconsistent_encoding(self):
        clock, prover, verifier = fixture()
        evidence = make_evidence(verifier, prover, clock)
        obj = json.loads(evidence.to_bytes().decode("utf-8"))
        obj["distance"] = obj["distance"] * 2
        with self.assertRaises(ValueError):
            audit(json.dumps(obj, separators=(",", ":")).encode(), KEY)

    def test_audit_rejects_bad_types(self):
        with self.assertRaises(TypeError):
            audit("not evidence", KEY)

    def test_audit_does_not_touch_verifier_state(self):
        clock, prover, verifier = fixture(replay_protection=True)
        challenge = verifier.new_challenge()
        evidence = verifier.verify_evidence(challenge, prover.respond(challenge), clock.now)
        for _ in range(3):
            audit(evidence, KEY)
        # auditing never consumes anything; the challenge was consumed exactly
        # once by verify_evidence itself
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, prover.respond(challenge), clock.now)


if __name__ == "__main__":
    unittest.main()
