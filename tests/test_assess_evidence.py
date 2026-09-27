import dataclasses
import hashlib
import hmac
import json as jsonlib
import math
import unittest

from nearproof import (
    AssessEvidence,
    Evidence,
    Measurement,
    Prover,
    RangeDecision,
    Verifier,
    assess,
    audit_assess_evidence,
    seal_assess_evidence,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


class AutoClock:
    """Two readings per round, ``step`` apart, giving deterministic RTTs."""

    def __init__(self, step=1e-7):
        self.readings = 0
        self.step = step

    def __call__(self):
        value = self.readings * self.step
        self.readings += 1
        return value


def make_evidence_list(count, key=KEY):
    prover = Prover(key)
    verifier = Verifier(key, clock=AutoClock(), replay_protection=True)
    records = []
    for _i in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, records


def mac_payload(payload_bytes):
    return hmac.new(KEY, b"NPAE1" + payload_bytes, hashlib.sha256).digest()


class AssessEvidenceRecordTest(unittest.TestCase):
    def test_is_frozen(self):
        record = seal_assess_evidence(
            make_evidence_list(5)[1], 30.0, KEY
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.accepted = False

    def test_fields_match_assess_decision(self):
        _verifier, records = make_evidence_list(6)
        record = seal_assess_evidence(records, 20.0, KEY)
        decision = assess(records, limit=20.0, key=KEY)
        self.assertEqual(record.version, 1)
        self.assertEqual(record.limit, 20.0)
        self.assertEqual(record.min_samples, 5)
        self.assertEqual(record.sample_count, decision.sample_count)
        self.assertEqual(record.upper_bound, decision.upper_bound)
        self.assertIs(record.accepted, decision.accepted)
        self.assertEqual(len(record.mac), 32)
        # The samples are carried as canonical evidence bytes, one per input.
        self.assertEqual(len(record.samples), len(records))
        self.assertEqual(
            list(record.samples),
            sorted(item.to_bytes() for item in records),
        )
        for blob in record.samples:
            self.assertIsInstance(blob, bytes)
            Evidence.from_bytes(blob)  # every carried blob parses as evidence

    def test_accepted_false_recorded(self):
        _verifier, records = make_evidence_list(6)
        record = seal_assess_evidence(records, 10.0, KEY)
        self.assertFalse(record.accepted)
        self.assertGreater(record.upper_bound, 10.0)

    def test_custom_min_samples(self):
        _verifier, records = make_evidence_list(3)
        record = seal_assess_evidence(records, 30.0, KEY, 3)
        self.assertEqual(record.min_samples, 3)
        self.assertEqual(record.sample_count, 3)


class SealAssessEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_measurement_samples_rejected(self):
        samples = [
            Measurement(
                round_index=record.round_index,
                nonce=record.nonce,
                response=record.response,
                elapsed_seconds=record.elapsed,
                distance_meters=record.distance,
            )
            for record in self.records
        ]
        for bad in (samples, samples[:1] + self.blobs[1:], [123]):
            with self.assertRaises(TypeError, msg=bad):
                seal_assess_evidence(bad, 20.0, KEY)

    def test_non_iterable_samples_rejected(self):
        for bad in (123, None, 5.0, object()):
            with self.assertRaises(TypeError, msg=bad):
                seal_assess_evidence(bad, 20.0, KEY)

    def test_key_type_and_value(self):
        for bad in ("", None, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                seal_assess_evidence(self.records, 20.0, bad)
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records, 20.0, b"")

    def test_limit_and_min_samples_violations_are_value_errors(self):
        for bad in (True, False, -0.1, math.nan, math.inf, "10", None):
            with self.assertRaises(ValueError, msg=bad):
                seal_assess_evidence(self.records, bad, KEY)
        for bad in (0, -1, True, 1.0, "5", None):
            with self.assertRaises(ValueError, msg=bad):
                seal_assess_evidence(self.records, 20.0, KEY, bad)

    def test_too_few_samples_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records[:3], 30.0, KEY)

    def test_duplicate_samples_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence([self.records[0]] * 5, 30.0, KEY)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records, 20.0, OTHER_KEY)

    def test_tampered_sample_rejected(self):
        tampered = bytearray(self.blobs[0])
        tampered[20] ^= 0xFF
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.blobs[:5] + [bytes(tampered)], 20.0, KEY)

    def test_malformed_sample_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.blobs[:5] + [b"not json"], 20.0, KEY)

    def test_non_canonical_sample_rejected(self):
        # Whitespace inside an otherwise valid evidence encoding is a
        # non-canonical spelling and must not enter the record.
        spaced = b" " + self.blobs[0]
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.blobs[:5] + [spaced], 20.0, KEY)

    def test_seal_failure_produces_nothing(self):
        # The only side effect possible is a returned record; the call must
        # raise rather than hand back evidence for an unacceptable batch.
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records[:1], 20.0, KEY)

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        seal_assess_evidence(self.records, 20.0, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class AssessEvidenceOrderTest(unittest.TestCase):
    def test_sample_order_does_not_change_bytes(self):
        _verifier, records = make_evidence_list(6)
        blobs = [record.to_bytes() for record in records]
        first = seal_assess_evidence(records, 20.0, KEY)
        permutations = [
            list(reversed(records)),
            [records[i] for i in (0, 2, 4, 1, 3, 5)],
            list(reversed(blobs)),
            [blobs[i] for i in (5, 0, 4, 1, 3, 2)],
        ]
        for samples in permutations:
            other = seal_assess_evidence(samples, 20.0, KEY)
            self.assertEqual(other.to_bytes(), first.to_bytes())
            self.assertEqual(other, first)

    def test_objects_and_bytes_seal_identically(self):
        _verifier, records = make_evidence_list(6)
        blobs = [record.to_bytes() for record in records]
        mixed = [
            records[0],
            blobs[1],
            records[2],
            blobs[3],
            records[4],
            blobs[5],
        ]
        self.assertEqual(
            seal_assess_evidence(mixed, 20.0, KEY).to_bytes(),
            seal_assess_evidence(records, 20.0, KEY).to_bytes(),
        )


class AuditAssessEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.record = seal_assess_evidence(self.records, 20.0, KEY)
        self.blob = self.record.to_bytes()

    def test_round_trip_object_and_bytes(self):
        expected = assess(self.records, limit=20.0, key=KEY)
        decision = audit_assess_evidence(self.record, KEY)
        self.assertEqual(decision, expected)
        decision_from_bytes = audit_assess_evidence(self.blob, KEY)
        self.assertEqual(decision_from_bytes, expected)
        self.assertIsInstance(decision, RangeDecision)

    def test_from_bytes_round_trip(self):
        parsed = AssessEvidence.from_bytes(self.blob)
        self.assertEqual(parsed, self.record)
        self.assertEqual(parsed.to_bytes(), self.blob)

    def test_wrong_evidence_argument_type(self):
        for bad in ("x", 123, None, object(), []):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence(bad, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence(b"", KEY)

    def test_key_type_and_value(self):
        for bad in ("", None, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence(self.record, bad)
        with self.assertRaises(ValueError):
            audit_assess_evidence(self.record, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence(self.record, OTHER_KEY)

    def test_malformed_outer_encoding_rejected(self):
        for bad in (b"not json", b" " + self.blob, self.blob + b"\n"):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence(bad, KEY)

    def test_inner_sample_tampering_rejected(self):
        outer = jsonlib.loads(self.blob)
        sample = bytearray(bytes.fromhex(outer["samples"][0]))
        sample[20] ^= 0xFF
        outer["samples"][0] = bytes(sample).hex()
        # Re-serialize canonically but with no access to the key: the outer
        # MAC now mismatches.
        encoded = jsonlib.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence(encoded, KEY)

    def test_non_canonical_inner_sample_rejected_even_with_mac(self):
        # An attacker with the key rewraps the record but inserts whitespace
        # into one carried evidence encoding; parsing the inner sample must
        # reject it before the decision is recomputed.
        outer = jsonlib.loads(self.blob)
        spaced = b" " + bytes.fromhex(outer["samples"][0])
        outer["samples"][0] = spaced.hex()
        body = jsonlib.dumps(
            {k: v for k, v in outer.items() if k != "mac"},
            separators=(",", ":"),
        ).encode()
        outer["mac"] = mac_payload(body).hex()
        encoded = jsonlib.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence(encoded, KEY)

    def test_conclusion_tampering_rejected(self):
        def rewrap(mutator):
            outer = jsonlib.loads(self.blob)
            mutator(outer)
            body = jsonlib.dumps(
                {k: v for k, v in outer.items() if k != "mac"},
                separators=(",", ":"),
            ).encode()
            outer["mac"] = mac_payload(body).hex()
            return jsonlib.dumps(outer, separators=(",", ":")).encode()

        # The outer MAC is recomputed correctly with the key, so these only
        # fail if the auditor recomputes the decision and compares fields.
        flip_accepted = rewrap(lambda outer: outer.__setitem__("accepted", False))
        with self.assertRaises(ValueError):
            audit_assess_evidence(flip_accepted, KEY)
        wrong_bound = rewrap(
            lambda outer: outer.__setitem__("upper_bound", outer["upper_bound"] + 1.0)
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence(wrong_bound, KEY)
        wrong_count = rewrap(lambda outer: outer.__setitem__("sample_count", 99))
        with self.assertRaises(ValueError):
            audit_assess_evidence(wrong_count, KEY)
        # A changed threshold changes the verdict; the recorded accepted flag
        # then disagrees with the recomputed one.
        wrong_limit = rewrap(lambda outer: outer.__setitem__("limit", 1.0))
        with self.assertRaises(ValueError):
            audit_assess_evidence(wrong_limit, KEY)

    def test_duplicate_inner_samples_rejected_even_with_mac(self):
        outer = jsonlib.loads(self.blob)
        outer["samples"][-1] = outer["samples"][0]
        body = jsonlib.dumps(
            {k: v for k, v in outer.items() if k != "mac"},
            separators=(",", ":"),
        ).encode()
        outer["mac"] = mac_payload(body).hex()
        encoded = jsonlib.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence(encoded, KEY)

    def test_min_samples_tampering_rejected(self):
        outer = jsonlib.loads(self.blob)
        outer["min_samples"] = 7  # more than the carried six samples
        body = jsonlib.dumps(
            {k: v for k, v in outer.items() if k != "mac"},
            separators=(",", ":"),
        ).encode()
        outer["mac"] = mac_payload(body).hex()
        encoded = jsonlib.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence(encoded, KEY)

    def test_dropped_sample_rejected(self):
        outer = jsonlib.loads(self.blob)
        outer["samples"] = outer["samples"][:-1]  # five carried, six recorded
        body = jsonlib.dumps(
            {k: v for k, v in outer.items() if k != "mac"},
            separators=(",", ":"),
        ).encode()
        outer["mac"] = mac_payload(body).hex()
        encoded = jsonlib.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence(encoded, KEY)

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        audit_assess_evidence(self.record, KEY)
        audit_assess_evidence(self.blob, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
