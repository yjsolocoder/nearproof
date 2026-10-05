import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    ConfidenceEvidence,
    Evidence,
    Measurement,
    Prover,
    ReliabilityDecision,
    ReliabilityEvidence,
    Verifier,
    _RELIABILITY_EVIDENCE_PREFIX,
    _evidence_mac,
    _evidence_payload,
    _reliability_evidence_content_bytes,
    assess_reliability,
    audit_reliability,
    seal_reliability,
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


class ListClock:
    """Serves a fixed list of readings: two per round, so the per-round
    elapsed times (and hence distances) are the odd-even gaps."""

    def __init__(self, readings):
        self.readings = iter(readings)

    def __call__(self):
        return next(self.readings)


def varied_clock(gaps):
    """A clock whose rounds take the given distinct elapsed times."""
    readings = []
    now = 0.0
    for gap in gaps:
        readings.append(now)
        now += gap
        readings.append(now)
        now += 1e-8
    return ListClock(readings)


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


def make_varied_evidence_list(key=KEY):
    """Six records with distinct distances (~15.0 m to ~22.5 m), so the
    exceedance count is sensitive to both the sample set and the limit."""
    gaps = [1.0e-7, 1.1e-7, 1.2e-7, 1.3e-7, 1.4e-7, 1.5e-7]
    prover = Prover(key)
    verifier = Verifier(key, clock=varied_clock(gaps), replay_protection=True)
    records = []
    for _ in gaps:
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


def make_boundary_evidence(distances, key=KEY):
    """Craft validly signed records carrying exactly the given distances.

    The audit recomputation is exact — ``elapsed == end - start`` and
    ``distance == elapsed * speed / 2.0`` — so each record carries
    ``start=0.0``, ``end=elapsed=1.0`` and ``speed=2.0*distance``, which
    makes the halved product exactly the requested distance in binary
    floating point.
    """
    _, records = make_evidence_list(len(distances), key=key)
    crafted = []
    for record, distance in zip(records, distances):
        moved = dataclasses.replace(
            record,
            start=0.0,
            end=1.0,
            speed=2.0 * float(distance),
            elapsed=1.0,
            distance=float(distance),
        )
        crafted.append(
            dataclasses.replace(
                moved, mac=_evidence_mac(key, _evidence_payload(moved))
            )
        )
    return crafted


def resign(record_bytes, changes=None, *, key=KEY):
    """Decode a ReliabilityEvidence, apply index->value changes and re-MAC it."""
    outer = json.loads(record_bytes)
    for index, value in (changes or {}).items():
        outer[index] = value
    content = json.dumps(outer[:6], separators=(",", ":")).encode()
    outer[6] = hmac.new(
        key, _RELIABILITY_EVIDENCE_PREFIX + content, hashlib.sha256
    ).digest().hex()
    return json.dumps(outer, separators=(",", ":")).encode()


class ReliabilityEvidenceRecordTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_reliability(
            self.records, 100.0, KEY, max_exceedance=0.5
        )
        self.data = self.evidence.to_bytes()

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.evidence.limit = 1.0

    def test_fields(self):
        decision = assess_reliability(
            self.records, 100.0, max_exceedance=0.5, key=KEY
        )
        self.assertIsInstance(self.evidence, ReliabilityEvidence)
        self.assertEqual(self.evidence.version, 1)
        self.assertEqual(self.evidence.limit, 100.0)
        self.assertIsInstance(self.evidence.limit, float)
        self.assertEqual(self.evidence.min_samples, 5)
        self.assertEqual(self.evidence.max_exceedance, 0.5)
        self.assertIsInstance(self.evidence.max_exceedance, float)
        self.assertEqual(self.evidence.decision, decision)
        self.assertIsInstance(self.evidence.decision, ReliabilityDecision)
        self.assertEqual(len(self.evidence.mac), 32)
        self.assertIsInstance(self.evidence.samples, tuple)
        self.assertEqual(
            self.evidence.samples,
            tuple(sorted(record.to_bytes() for record in self.records)),
        )

    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ReliabilityEvidence)],
            [
                "version",
                "samples",
                "limit",
                "min_samples",
                "max_exceedance",
                "decision",
                "mac",
            ],
        )

    def test_equality_covers_every_field(self):
        other = seal_reliability(self.records, 100.0, KEY, max_exceedance=0.5)
        self.assertEqual(self.evidence, other)
        base = dict(
            version=1,
            samples=self.evidence.samples,
            limit=100.0,
            min_samples=5,
            max_exceedance=0.5,
            decision=self.evidence.decision,
            mac=self.evidence.mac,
        )
        for name, value in (
            ("samples", self.evidence.samples[:5] + self.evidence.samples[4:]),
            ("limit", 101.0),
            ("min_samples", 4),
            ("max_exceedance", 0.6),
            (
                "decision",
                dataclasses.replace(self.evidence.decision, accepted=False),
            ),
            ("mac", b"\xff" * 32),
        ):
            changed = ReliabilityEvidence(**{**base, name: value})
            self.assertNotEqual(self.evidence, changed, name)

    def test_limit_and_tolerance_canonicalized_to_float(self):
        record = ReliabilityEvidence(
            1,
            self.evidence.samples,
            100,
            5,
            0.5,
            self.evidence.decision,
            b"\x00" * 32,
        )
        self.assertIsInstance(record.limit, float)
        self.assertEqual(record.limit, 100.0)
        self.assertEqual(record.to_bytes(), record.to_bytes())

    def test_encoding_shape(self):
        outer = json.loads(self.data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 7)
        self.assertEqual(outer[0], 1)
        self.assertEqual(
            outer[1],
            [sample.hex() for sample in self.evidence.samples],
        )
        self.assertEqual(outer[2], 100.0)
        self.assertEqual(outer[3], 5)
        self.assertEqual(outer[4], 0.5)
        decision = self.evidence.decision
        self.assertEqual(
            outer[5],
            [
                decision.sample_count,
                decision.exceedance_count,
                decision.upper_probability,
                decision.confidence,
                decision.accepted,
            ],
        )
        self.assertEqual(outer[6], self.evidence.mac.hex())
        # Compact: no whitespace outside strings.
        self.assertNotIn(b" ", self.data)

    def test_mac_is_hmac_with_prefix(self):
        expected = hmac.new(
            KEY,
            _RELIABILITY_EVIDENCE_PREFIX
            + _reliability_evidence_content_bytes(self.evidence),
            hashlib.sha256,
        ).digest()
        self.assertEqual(self.evidence.mac, expected)

    def test_mac_prefix_distinct_from_other_evidence_types(self):
        confidence = ConfidenceEvidence.from_bytes(
            __import__("nearproof").seal_confidence(
                self.records, 100.0, KEY
            ).to_bytes()
        )
        self.assertNotEqual(self.evidence.mac, confidence.mac)
        self.assertNotEqual(
            _RELIABILITY_EVIDENCE_PREFIX,
            __import__("nearproof")._CONFIDENCE_EVIDENCE_PREFIX,
        )
        self.assertNotEqual(
            _RELIABILITY_EVIDENCE_PREFIX,
            __import__("nearproof")._ASSESS_EVIDENCE_PREFIX,
        )

    def test_round_trip(self):
        decoded = ReliabilityEvidence.from_bytes(self.data)
        self.assertEqual(decoded, self.evidence)
        self.assertEqual(decoded.to_bytes(), self.data)

    def test_from_bytes_does_not_verify_mac(self):
        data = resign(self.data, key=OTHER_KEY)
        decoded = ReliabilityEvidence.from_bytes(data)
        self.assertNotEqual(decoded.mac, self.evidence.mac)

    def test_from_bytes_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            ReliabilityEvidence.from_bytes("not bytes")
        with self.assertRaises(TypeError):
            ReliabilityEvidence.from_bytes(bytearray(self.data))
        # Extra field.
        outer = json.loads(self.data)
        outer.append("extra")
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        # Missing field.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(
                json.dumps(outer[:6], separators=(",", ":")).encode()
            )
        # Not an array.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(b'{"version":1}')
        # Not JSON at all.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(b"not json")
        # Non-canonical: whitespace.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(
                json.dumps(json.loads(self.data)).encode()
            )
        # Non-canonical: uppercase hex sample.
        outer = json.loads(self.data)
        outer[1][0] = outer[1][0].upper()
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        # Unsorted samples.
        outer = json.loads(self.data)
        outer[1] = list(reversed(outer[1]))
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        # Bad version.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(resign(self.data, {0: 2}))
        # Bad decision shape.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(resign(self.data, {5: [1, 2, 3]}))
        # Bad max_exceedance.
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(resign(self.data, {4: 1.0}))
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(resign(self.data, {4: 0.0}))
        # Bad mac length (tampered directly: resign would recompute it).
        outer = json.loads(self.data)
        outer[6] = "ab" * 31
        with self.assertRaises(ValueError):
            ReliabilityEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )

    def test_direct_construction_value_errors(self):
        samples = self.evidence.samples
        decision = self.evidence.decision
        mac = b"\x00" * 32
        good = dict(
            version=1,
            samples=samples,
            limit=100.0,
            min_samples=5,
            max_exceedance=0.5,
            decision=decision,
            mac=mac,
        )
        bad = [
            {"version": 2},
            {"version": "1"},
            {"samples": list(samples)},
            {"samples": ()},
            {"samples": samples + (b"\x00",)},
            {"samples": tuple(reversed(samples))},
            {"limit": -1.0},
            {"limit": True},
            {"limit": float("nan")},
            {"min_samples": 0},
            {"min_samples": 1.5},
            {"max_exceedance": 0},
            {"max_exceedance": 1},
            {"max_exceedance": 1.0},
            {"max_exceedance": True},
            {"max_exceedance": float("nan")},
            {"max_exceedance": -0.1},
            {"decision": None},
            {"decision": dataclasses.replace(decision, sample_count=0)},
            {"decision": dataclasses.replace(decision, exceedance_count=-1)},
            {
                "decision": dataclasses.replace(
                    decision, exceedance_count=decision.sample_count + 1
                )
            },
            {
                "decision": dataclasses.replace(
                    decision, upper_probability=1.5
                )
            },
            {
                "decision": dataclasses.replace(
                    decision, upper_probability=-0.1
                )
            },
            {"decision": dataclasses.replace(decision, confidence=1.0)},
            {"decision": dataclasses.replace(decision, confidence=0.0)},
            {"decision": dataclasses.replace(decision, accepted=1)},
            {"mac": b"\x00" * 31},
            {"mac": "00" * 32},
        ]
        for change in bad:
            with self.assertRaises(
                ValueError, msg=next(iter(change))
            ):
                ReliabilityEvidence(**{**good, **change})


class SealReliabilityTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)

    def test_matches_assess_reliability(self):
        record = seal_reliability(
            self.records,
            100.0,
            KEY,
            max_exceedance=0.4,
            confidence=0.9,
            min_samples=3,
        )
        decision = assess_reliability(
            self.records,
            100.0,
            max_exceedance=0.4,
            confidence=0.9,
            key=KEY,
            min_samples=3,
        )
        self.assertEqual(record.decision, decision)
        self.assertEqual(record.min_samples, 3)
        self.assertEqual(record.max_exceedance, 0.4)

    def test_keyword_defaults_match_assess_reliability(self):
        record = seal_reliability(self.records, 100.0, KEY, max_exceedance=0.5)
        self.assertEqual(record.decision.confidence, 0.95)
        self.assertEqual(record.min_samples, 5)

    def test_rejected_decision_seals(self):
        # Every sample exceeds a tiny limit: the upper bound is 1.0.
        record = seal_reliability(self.records, 1e-9, KEY, max_exceedance=0.9)
        self.assertIs(record.decision.accepted, False)
        self.assertEqual(record.decision.upper_probability, 1.0)
        self.assertEqual(audit_reliability(record, KEY), record.decision)

    def test_distance_equal_to_limit_is_no_exceedance(self):
        records = make_boundary_evidence([10.0] * 5 + [5.0])
        record = seal_reliability(records, 10.0, KEY, max_exceedance=0.9)
        self.assertEqual(record.decision.sample_count, 6)
        self.assertEqual(record.decision.exceedance_count, 0)

    def test_outliers_still_count(self):
        records = make_boundary_evidence([5.0] * 5 + [1000.0])
        record = seal_reliability(records, 10.0, KEY, max_exceedance=0.9)
        self.assertEqual(record.decision.sample_count, 6)
        self.assertEqual(record.decision.exceedance_count, 1)

    def test_upper_probability_equal_to_tolerance_accepts(self):
        decision = assess_reliability(
            self.records, 100.0, max_exceedance=0.5, key=KEY
        )
        record = seal_reliability(
            self.records,
            100.0,
            KEY,
            max_exceedance=decision.upper_probability,
        )
        self.assertEqual(
            record.decision.upper_probability, decision.upper_probability
        )
        self.assertIs(record.decision.accepted, True)
        self.assertEqual(audit_reliability(record, KEY), record.decision)

    def test_order_and_form_do_not_change_artifact(self):
        base = seal_reliability(self.records, 100.0, KEY, max_exceedance=0.5)
        shuffled = seal_reliability(
            list(reversed(self.records)), 100.0, KEY, max_exceedance=0.5
        )
        as_bytes = seal_reliability(
            [record.to_bytes() for record in self.records],
            100.0,
            KEY,
            max_exceedance=0.5,
        )
        mixed = seal_reliability(
            [
                record if index % 2 else record.to_bytes()
                for index, record in enumerate(self.records)
            ],
            100.0,
            KEY,
            max_exceedance=0.5,
        )
        for other in (shuffled, as_bytes, mixed):
            self.assertEqual(other.to_bytes(), base.to_bytes())

    def test_one_shot_iterable(self):
        record = seal_reliability(
            iter(self.records), 100.0, KEY, max_exceedance=0.5
        )
        self.assertEqual(
            record.to_bytes(),
            seal_reliability(
                self.records, 100.0, KEY, max_exceedance=0.5
            ).to_bytes(),
        )
        generator = (record for record in self.records)
        self.assertEqual(
            seal_reliability(
                generator, 100.0, KEY, max_exceedance=0.5
            ).to_bytes(),
            record.to_bytes(),
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            seal_reliability(42, 100.0, KEY, max_exceedance=0.5)
        with self.assertRaises(TypeError):
            seal_reliability(
                self.records, 100.0, "not-bytes", max_exceedance=0.5
            )
        # Measurement objects are not acceptable samples.
        with self.assertRaises(TypeError):
            seal_reliability(
                [make_measurement(i, 10.0) for i in range(6)],
                100.0,
                KEY,
                max_exceedance=0.5,
            )
        with self.assertRaises(TypeError):
            seal_reliability(
                list(self.records) + [make_measurement(7, 10.0)],
                100.0,
                KEY,
                max_exceedance=0.5,
            )
        with self.assertRaises(TypeError):
            seal_reliability(
                list(self.records) + [42], 100.0, KEY, max_exceedance=0.5
            )

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            seal_reliability(self.records, 100.0, b"", max_exceedance=0.5)
        with self.assertRaises(ValueError):
            seal_reliability(self.records, -1.0, KEY, max_exceedance=0.5)
        with self.assertRaises(ValueError):
            seal_reliability(self.records, True, KEY, max_exceedance=0.5)
        with self.assertRaises(ValueError):
            seal_reliability(
                self.records, 100.0, KEY, max_exceedance=0.5, min_samples=0
            )
        for bad in (0, 1, 0.0, 1.0, -0.1, 1.1, True, float("nan")):
            with self.assertRaises(ValueError, msg=bad):
                seal_reliability(
                    self.records, 100.0, KEY, max_exceedance=bad
                )
        for bad in (0, 1, 0.0, 1.0, -0.1, 1.1, True, float("nan")):
            with self.assertRaises(ValueError, msg=bad):
                seal_reliability(
                    self.records,
                    100.0,
                    KEY,
                    max_exceedance=0.5,
                    confidence=bad,
                )
        # Too few samples.
        with self.assertRaises(ValueError):
            seal_reliability(
                self.records[:4], 100.0, KEY, max_exceedance=0.5
            )
        # Duplicate (round_index, nonce) pair.
        with self.assertRaises(ValueError):
            seal_reliability(
                [self.records[0]] + list(self.records),
                100.0,
                KEY,
                max_exceedance=0.5,
            )
        # A sample signed under another key fails its audit.
        _, other_records = make_evidence_list(1, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            seal_reliability(
                list(self.records) + other_records,
                100.0,
                KEY,
                max_exceedance=0.5,
            )
        # Non-canonical sample bytes.
        record = self.records[0]
        outer = json.loads(record.to_bytes())
        bad_blob = json.dumps(outer).encode()  # whitespace -> non-canonical
        with self.assertRaises(ValueError):
            seal_reliability(
                [bad_blob] + list(self.records[1:]),
                100.0,
                KEY,
                max_exceedance=0.5,
            )

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        challenges = len(self.verifier._challenges)
        seal_reliability(self.records, 100.0, KEY, max_exceedance=0.5)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), challenges)


class AuditReliabilityTest(unittest.TestCase):
    def setUp(self):
        # Varied distances (~15.0 m to ~22.5 m) with a 20.0 m limit make
        # the exceedance count (2 of 6) sensitive to the sample set, so
        # any tampering is detectable by recomputation.
        self.verifier, self.records = make_varied_evidence_list()
        self.evidence = seal_reliability(
            self.records, 20.0, KEY, max_exceedance=0.9
        )
        self.data = self.evidence.to_bytes()

    def test_returns_reliability_decision(self):
        decision = audit_reliability(self.evidence, KEY)
        self.assertIsInstance(decision, ReliabilityDecision)
        self.assertEqual(decision, self.evidence.decision)
        self.assertEqual(
            decision,
            assess_reliability(
                self.records, 20.0, max_exceedance=0.9, key=KEY
            ),
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_reliability(self.data, KEY), self.evidence.decision
        )

    def test_rejected_decision_audits(self):
        evidence = seal_reliability(
            self.records, 1e-9, KEY, max_exceedance=0.9
        )
        self.assertIs(evidence.decision.accepted, False)
        self.assertEqual(audit_reliability(evidence, KEY), evidence.decision)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            audit_reliability("nope", KEY)
        with self.assertRaises(TypeError):
            audit_reliability(42, KEY)
        with self.assertRaises(TypeError):
            audit_reliability(self.records[0], KEY)
        with self.assertRaises(TypeError):
            audit_reliability(self.evidence, "not-bytes")

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            audit_reliability(self.evidence, b"")
        with self.assertRaises(ValueError):
            audit_reliability(self.evidence, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_reliability(self.data[:-2] + b"00", KEY)

    def test_tampered_fields_fail_even_when_resigned(self):
        outer = json.loads(self.data)
        # Tamper with each statistical field of the carried decision and
        # re-sign with the right key: the recomputation must still fail.
        decision = self.evidence.decision
        self.assertEqual(decision.sample_count, 6)
        self.assertGreater(decision.exceedance_count, 0)
        tampered_decisions = [
            [decision.sample_count + 1] + list(outer[5][1:]),
            [outer[5][0], decision.exceedance_count + 1] + list(outer[5][2:]),
            list(outer[5][:2]) + [0.5] + list(outer[5][3:]),
            list(outer[5][:3]) + [0.5] + list(outer[5][4:]),
            list(outer[5][:4]) + [not decision.accepted],
        ]
        for tampered in tampered_decisions:
            with self.assertRaises(ValueError, msg=tampered):
                audit_reliability(resign(self.data, {5: tampered}), KEY)
        # Tampered threshold, minimum sample count and tolerance, re-signed.
        with self.assertRaises(ValueError):
            audit_reliability(resign(self.data, {2: 100.0}), KEY)
        with self.assertRaises(ValueError):
            audit_reliability(resign(self.data, {3: 7}), KEY)
        # A tolerance below the recorded upper probability flips accepted.
        self.assertIs(decision.accepted, True)
        with self.assertRaises(ValueError):
            audit_reliability(
                resign(self.data, {4: decision.upper_probability / 2.0}), KEY
            )

    def test_tampered_samples_fail_even_when_resigned(self):
        # Swap the ~15.0 m (non-exceeding) record for a ~30.0 m one: the
        # recomputed exceedance count no longer matches the recorded
        # decision, even with a valid re-signature.
        _, other_records = make_evidence_list(1, key=KEY, step=2e-7)
        swapped = sorted(
            (
                other_records[0].to_bytes()
                if sample == self.records[0].to_bytes()
                else sample
            )
            for sample in self.evidence.samples
        )
        with self.assertRaises(ValueError):
            audit_reliability(
                resign(self.data, {1: [sample.hex() for sample in swapped]}),
                KEY,
            )
        # Drop a sample: the recomputed sample count disagrees.
        dropped = list(self.evidence.samples[:5])
        with self.assertRaises(ValueError):
            audit_reliability(
                resign(self.data, {1: [sample.hex() for sample in dropped]}),
                KEY,
            )

    def test_duplicate_sample_fails_even_when_resigned(self):
        samples = list(self.evidence.samples)
        samples[1] = samples[0]
        with self.assertRaises(ValueError):
            audit_reliability(
                resign(self.data, {1: [sample.hex() for sample in samples]}),
                KEY,
            )

    def test_no_partial_result(self):
        try:
            audit_reliability(resign(self.data, {3: 7}), KEY)
        except ValueError:
            pass
        else:
            self.fail("expected ValueError")

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        challenges = len(self.verifier._challenges)
        audit_reliability(self.evidence, KEY)
        audit_reliability(self.data, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), challenges)


if __name__ == "__main__":
    unittest.main()
