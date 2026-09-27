import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    AssessEvidence,
    Evidence,
    Measurement,
    Prover,
    RangeDecision,
    Verifier,
    _ASSESS_EVIDENCE_PREFIX,
    _assess_evidence_content_bytes,
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


def make_evidence_list(count, key=KEY, step=1e-7):
    prover = Prover(key)
    verifier = Verifier(key, clock=AutoClock(step), replay_protection=True)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, records


def make_measurement(round_index, distance, *, elapsed=None, nonce=None):
    if nonce is None:
        nonce = bytes([round_index & 0xFF]) * 16
    if elapsed is None:
        elapsed = distance / 100.0
    return Measurement(
        round_index=round_index,
        nonce=nonce,
        response=b"r" * 32,
        elapsed_seconds=elapsed,
        distance_meters=float(distance),
    )


def resign(record_bytes, changes=None, *, key=KEY):
    """Decode an AssessEvidence, apply index->value changes and re-MAC it."""
    outer = json.loads(record_bytes)
    for index, value in (changes or {}).items():
        outer[index] = value
    content = json.dumps(outer[:7], separators=(",", ":")).encode()
    outer[7] = hmac.new(
        key, _ASSESS_EVIDENCE_PREFIX + content, hashlib.sha256
    ).digest().hex()
    return json.dumps(outer, separators=(",", ":")).encode()


class AssessEvidenceRecordTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_assess_evidence(self.records, 100.0, KEY)
        self.data = self.evidence.to_bytes()

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.evidence.accepted = False

    def test_fields(self):
        decision = assess(self.records, 100.0, key=KEY)
        self.assertIsInstance(self.evidence, AssessEvidence)
        self.assertEqual(self.evidence.version, 1)
        self.assertEqual(self.evidence.limit, 100.0)
        self.assertEqual(self.evidence.min_samples, 5)
        self.assertEqual(self.evidence.sample_count, decision.sample_count)
        self.assertEqual(self.evidence.upper_bound, decision.upper_bound)
        self.assertIs(self.evidence.accepted, decision.accepted)
        self.assertEqual(len(self.evidence.mac), 32)
        self.assertIsInstance(self.evidence.samples, tuple)
        self.assertEqual(
            self.evidence.samples,
            tuple(sorted(record.to_bytes() for record in self.records)),
        )

    def test_no_key_material_stored(self):
        self.assertNotIn(KEY, self.evidence.to_bytes())

    def test_round_trip_bytes(self):
        data = self.evidence.to_bytes()
        self.assertEqual(AssessEvidence.from_bytes(data), self.evidence)

    def test_encoding_is_compact_array(self):
        data = self.evidence.to_bytes()
        self.assertNotIn(b" ", data)
        outer = json.loads(data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 8)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[2], 100.0)
        self.assertEqual(outer[3], 5)
        self.assertEqual(len(outer[1]), len(self.records))
        self.assertEqual(outer[7], self.evidence.mac.hex())

    def test_mac_uses_domain_prefix_over_content_without_mac(self):
        expected = hmac.new(
            KEY,
            _ASSESS_EVIDENCE_PREFIX
            + _assess_evidence_content_bytes(self.evidence),
            hashlib.sha256,
        ).digest()
        self.assertEqual(expected, self.evidence.mac)

    def test_from_bytes_does_not_verify_mac(self):
        outer = json.loads(self.evidence.to_bytes())
        outer[7] = "00" * 32
        data = json.dumps(outer, separators=(",", ":")).encode()
        record = AssessEvidence.from_bytes(data)
        self.assertEqual(record.mac, b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_assess_evidence(data, KEY)

    def test_from_bytes_requires_bytes(self):
        for bad in (self.evidence.to_bytes().decode(), None, 123, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                AssessEvidence.from_bytes(bad)

    def test_from_bytes_structural_type_errors(self):
        good = json.loads(self.data)
        cases = {
            "version string": lambda o: o.__setitem__(0, "1"),
            "samples object": lambda o: o.__setitem__(1, {}),
            "sample non-string": lambda o: o[1].__setitem__(0, 1),
            "mac non-string": lambda o: o.__setitem__(7, 1),
        }
        for label, mutate in cases.items():
            outer = json.loads(self.data)
            mutate(outer)
            with self.assertRaises(TypeError, msg=label):
                AssessEvidence.from_bytes(
                    json.dumps(outer).encode()
                )

    def test_from_bytes_value_errors(self):
        # Wrong array length, bad version and non-canonical spacing.
        for bad in (
            json.dumps(json.loads(self.data)[:7]).encode(),
            json.dumps([2] + json.loads(self.data)[1:]).encode(),
            self.data.replace(b",", b", ", 1),
        ):
            with self.assertRaises(ValueError, msg=bad[:12]):
                AssessEvidence.from_bytes(bad)

    def test_positional_construction_and_equality(self):
        other = AssessEvidence(
            self.evidence.version,
            self.evidence.samples,
            self.evidence.limit,
            self.evidence.min_samples,
            self.evidence.sample_count,
            self.evidence.upper_bound,
            self.evidence.accepted,
            self.evidence.mac,
        )
        self.assertEqual(other, self.evidence)
        self.assertEqual(hash(other), hash(self.evidence))


class AssessEvidenceSealTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_seal_matches_assess_decision(self):
        for limit in (100.0, 1):
            sealed = seal_assess_evidence(self.records, limit, KEY)
            self.assertEqual(
                audit_assess_evidence(sealed, KEY),
                assess(self.records, limit, key=KEY),
            )

    def test_seal_accepts_objects_and_bytes(self):
        sealed_objects = seal_assess_evidence(self.records, 100.0, KEY)
        sealed_bytes = seal_assess_evidence(self.blobs, 100.0, KEY)
        self.assertEqual(sealed_bytes, sealed_objects)

    def test_seal_accepts_mixed_objects_and_bytes(self):
        mixed = [
            self.records[0],
            self.blobs[1],
            self.records[2],
            self.blobs[3],
            self.records[4],
            self.blobs[5],
        ]
        sealed = seal_assess_evidence(mixed, 100.0, KEY)
        self.assertEqual(
            audit_assess_evidence(sealed, KEY),
            assess(self.records, 100.0, key=KEY),
        )

    def test_sample_order_does_not_change_artifact_bytes(self):
        first = seal_assess_evidence(self.records, 100.0, KEY)
        second = seal_assess_evidence(list(reversed(self.records)), 100.0, KEY)
        self.assertEqual(second.to_bytes(), first.to_bytes())

    def test_default_min_samples_is_five(self):
        sealed = seal_assess_evidence(self.records, 100.0, KEY)
        self.assertEqual(sealed.min_samples, 5)

    def test_custom_min_samples(self):
        sealed = seal_assess_evidence(
            self.records[:3], 100.0, KEY, min_samples=3
        )
        self.assertEqual(sealed.sample_count, 3)
        self.assertEqual(
            audit_assess_evidence(sealed, KEY),
            assess(self.records[:3], 100.0, key=KEY, min_samples=3),
        )

    def test_integer_limit_preserved(self):
        sealed = seal_assess_evidence(self.records, 100, KEY)
        self.assertEqual(sealed.limit, 100.0)

    def test_zero_limit(self):
        verifier, records = make_evidence_list(5, step=0.0)
        # Zero-step rounds measure zero distance, so a zero limit accepts.
        sealed = seal_assess_evidence(records, 0, KEY)
        self.assertEqual(sealed.upper_bound, 0.0)
        self.assertIs(sealed.accepted, True)
        self.assertEqual(
            audit_assess_evidence(sealed, KEY),
            assess(records, 0, key=KEY),
        )

    def test_rejected_conclusion_seals_and_round_trips(self):
        sealed = seal_assess_evidence(self.records, 1.0, KEY)
        self.assertIs(sealed.accepted, False)
        decision = audit_assess_evidence(sealed, KEY)
        self.assertIs(decision.accepted, False)

    def test_measurement_samples_rejected_with_type_error(self):
        samples = [make_measurement(i, 10.0) for i in range(1, 6)]
        with self.assertRaises(TypeError):
            seal_assess_evidence(samples, 100.0, KEY)

    def test_mixed_measurement_and_evidence_rejected_with_type_error(self):
        with self.assertRaises(TypeError):
            seal_assess_evidence(
                [make_measurement(1, 10.0)] + self.records[1:], 100.0, KEY
            )

    def test_non_iterable_samples_raises_type_error(self):
        for bad in (123, None, 5.0, object()):
            with self.assertRaises(TypeError, msg=bad):
                seal_assess_evidence(bad, 100.0, KEY)

    def test_wrong_element_type_raises_type_error(self):
        for bad in ("x", 123, None, object()):
            with self.assertRaises(TypeError, msg=bad):
                seal_assess_evidence([bad] + self.records[1:], 100.0, KEY)

    def test_non_bytes_key_raises_type_error(self):
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                seal_assess_evidence(self.records, 100.0, bad)

    def test_empty_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records, 100.0, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records, 100.0, OTHER_KEY)

    def test_too_few_samples(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records[:4], 100.0, KEY)
        with self.assertRaises(ValueError):
            seal_assess_evidence([], 100.0, KEY)

    def test_duplicate_pair_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence([self.records[0]] * 5, 100.0, KEY)

    def test_too_few_inliers_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(self.records, 100.0, KEY, min_samples=7)

    def test_tampered_sample_bytes_rejected(self):
        tampered = bytearray(self.blobs[0])
        tampered[20] ^= 0xFF
        with self.assertRaises(ValueError):
            seal_assess_evidence(
                self.blobs[:5] + [bytes(tampered)], 100.0, KEY
            )

    def test_malformed_sample_bytes_rejected(self):
        with self.assertRaises(ValueError):
            seal_assess_evidence(
                self.blobs[:5] + [b"not json"], 100.0, KEY
            )

    def test_non_canonical_sample_bytes_rejected(self):
        # Whitespace around the canonical Evidence JSON is not canonical.
        with self.assertRaises(ValueError):
            seal_assess_evidence(
                self.blobs[:5] + [b" " + self.blobs[5]], 100.0, KEY
            )

    def test_limit_validation_matches_assess(self):
        for bad in (True, False, -0.1, math.nan, math.inf, "10", None):
            with self.assertRaises(ValueError, msg=bad):
                seal_assess_evidence(self.records, bad, KEY)

    def test_min_samples_validation_matches_assess(self):
        for bad in (0, -1, True, False, 1.0, "5", None):
            with self.assertRaises(ValueError, msg=bad):
                seal_assess_evidence(self.records, 100.0, KEY, min_samples=bad)

    def test_sealing_touches_no_verifier_state(self):
        before = self.verifier.round_count
        seal_assess_evidence(self.records, 100.0, KEY)
        seal_assess_evidence(self.blobs, 100.0, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class AssessEvidenceAuditTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_assess_evidence(self.records, 100.0, KEY)
        self.data = self.evidence.to_bytes()

    def test_audit_returns_recorded_decision(self):
        decision = audit_assess_evidence(self.evidence, KEY)
        self.assertIsInstance(decision, RangeDecision)
        self.assertEqual(decision.sample_count, self.evidence.sample_count)
        self.assertEqual(decision.upper_bound, self.evidence.upper_bound)
        self.assertIs(decision.accepted, self.evidence.accepted)

    def test_audit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_assess_evidence(self.data, KEY),
            audit_assess_evidence(self.evidence, KEY),
        )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence(self.evidence, OTHER_KEY)

    def test_empty_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence(self.evidence, b"")

    def test_non_bytes_key_raises_type_error(self):
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence(self.evidence, bad)

    def test_evidence_argument_wrong_type_raises_type_error(self):
        for bad in ("x", 123, None, object(), [self.data], 7, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence(bad, KEY)

    def test_malformed_bytes_raise_value_error(self):
        for bad in (b"not json", b"{}", b"[1]"):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence(bad, KEY)

    def test_non_canonical_outer_encoding_rejected(self):
        for bad in (b" " + self.data, self.data + b"\n"):
            with self.assertRaises(ValueError, msg=bad[:6]):
                audit_assess_evidence(bad, KEY)

    def test_outer_mac_mismatch_rejected(self):
        outer = json.loads(self.data)
        outer[6] = not outer[6]
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence(tampered, KEY)

    def _other_key_records(self):
        _verifier, records = make_evidence_list(6, key=OTHER_KEY)
        return records

    def test_foreign_signed_sample_rejected(self):
        # A validly signed but foreign-key sample swapped into the record
        # (with the outer MAC re-made under KEY) must be rejected per sample.
        foreign = self._other_key_records()[0].to_bytes().hex()
        outer = json.loads(self.data)
        outer[1][0] = foreign
        outer[1].sort()
        forged = resign(json.dumps(outer, separators=(",", ":")).encode())
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_tampered_sample_body_rejected(self):
        outer = json.loads(self.data)
        sample = bytearray(bytes.fromhex(outer[1][0]))
        sample[20] ^= 0xFF
        outer[1][0] = bytes(sample).hex()
        outer[1].sort()
        forged = resign(json.dumps(outer, separators=(",", ":")).encode())
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_duplicate_carried_sample_rejected(self):
        outer = json.loads(self.data)
        outer[1][1] = outer[1][0]
        forged = resign(json.dumps(outer, separators=(",", ":")).encode())
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_sample_count_mismatch_rejected(self):
        forged = resign(self.data, {4: self.evidence.sample_count + 1})
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_upper_bound_mismatch_rejected(self):
        forged = resign(self.data, {5: self.evidence.upper_bound + 1.0})
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_accepted_mismatch_rejected(self):
        forged = resign(self.data, {6: not self.evidence.accepted})
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_limit_mismatch_rejected(self):
        # The record was sealed with accepted=True under limit 100; lowering
        # the carried limit below the upper bound flips the recomputed
        # conclusion, disagreeing with the recorded accepted field.
        forged = resign(self.data, {2: 1.0})
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_min_samples_mismatch_rejected(self):
        forged = resign(self.data, {3: self.evidence.min_samples + 100})
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_dropped_sample_rejected(self):
        # Drop one of six samples: five still clear min_samples=5, so the
        # recomputed count 5 reaches the field-equality check vs recorded 6.
        outer = json.loads(self.data)
        outer[1] = outer[1][:5]
        forged = resign(json.dumps(outer, separators=(",", ":")).encode())
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_assess_evidence(self.evidence, KEY)
        audit_assess_evidence(self.data, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
