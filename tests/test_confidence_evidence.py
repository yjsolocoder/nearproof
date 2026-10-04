import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    ConfidenceEvidence,
    Evidence,
    Measurement,
    NoiseDecision,
    Prover,
    Verifier,
    _CONFIDENCE_EVIDENCE_PREFIX,
    _confidence_evidence_content_bytes,
    assess_confidence,
    audit_confidence,
    seal_confidence,
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
    """Six records with distinct distances, so every statistical field of
    the decision (including the coverage-bracketed bounds) is sensitive to
    the sample set and the coverage level."""
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


def resign(record_bytes, changes=None, *, key=KEY):
    """Decode a ConfidenceEvidence, apply index->value changes and re-MAC it."""
    outer = json.loads(record_bytes)
    for index, value in (changes or {}).items():
        outer[index] = value
    content = json.dumps(outer[:5], separators=(",", ":")).encode()
    outer[5] = hmac.new(
        key, _CONFIDENCE_EVIDENCE_PREFIX + content, hashlib.sha256
    ).digest().hex()
    return json.dumps(outer, separators=(",", ":")).encode()


class ConfidenceEvidenceRecordTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_confidence(self.records, 100.0, KEY)
        self.data = self.evidence.to_bytes()

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.evidence.limit = 1.0

    def test_fields(self):
        decision = assess_confidence(self.records, 100.0, key=KEY)
        self.assertIsInstance(self.evidence, ConfidenceEvidence)
        self.assertEqual(self.evidence.version, 1)
        self.assertEqual(self.evidence.limit, 100.0)
        self.assertIsInstance(self.evidence.limit, float)
        self.assertEqual(self.evidence.min_samples, 5)
        self.assertEqual(self.evidence.decision, decision)
        self.assertIsInstance(self.evidence.decision, NoiseDecision)
        self.assertEqual(len(self.evidence.mac), 32)
        self.assertIsInstance(self.evidence.samples, tuple)
        self.assertEqual(
            self.evidence.samples,
            tuple(sorted(record.to_bytes() for record in self.records)),
        )

    def test_fields_in_order(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(ConfidenceEvidence)],
            ["version", "samples", "limit", "min_samples", "decision", "mac"],
        )

    def test_equality_covers_every_field(self):
        other = seal_confidence(self.records, 100.0, KEY)
        self.assertEqual(self.evidence, other)
        base = dict(
            version=1,
            samples=self.evidence.samples,
            limit=100.0,
            min_samples=5,
            decision=self.evidence.decision,
            mac=self.evidence.mac,
        )
        for name, value in (
            ("samples", self.evidence.samples[:5] + self.evidence.samples[4:]),
            ("limit", 101.0),
            ("min_samples", 4),
            (
                "decision",
                dataclasses.replace(self.evidence.decision, accepted=False),
            ),
            ("mac", b"\xff" * 32),
        ):
            changed = ConfidenceEvidence(**{**base, name: value})
            self.assertNotEqual(self.evidence, changed, name)

    def test_limit_canonicalized_to_float(self):
        record = ConfidenceEvidence(
            1, self.evidence.samples, 100, 5, self.evidence.decision, b"\x00" * 32
        )
        self.assertIsInstance(record.limit, float)
        self.assertEqual(record.limit, 100.0)
        self.assertEqual(record.to_bytes(), record.to_bytes())

    def test_encoding_shape(self):
        outer = json.loads(self.data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 6)
        self.assertEqual(outer[0], 1)
        self.assertEqual(
            outer[1],
            [sample.hex() for sample in self.evidence.samples],
        )
        self.assertEqual(outer[2], 100.0)
        self.assertEqual(outer[3], 5)
        decision = self.evidence.decision
        self.assertEqual(
            outer[4],
            [
                decision.sample_count,
                decision.inlier_count,
                decision.center,
                decision.mad,
                decision.coverage,
                decision.lower_bound,
                decision.upper_bound,
                decision.accepted,
            ],
        )
        self.assertEqual(outer[5], self.evidence.mac.hex())
        # Compact: no whitespace outside strings.
        self.assertNotIn(b" ", self.data)

    def test_mac_is_hmac_with_prefix(self):
        expected = hmac.new(
            KEY,
            _CONFIDENCE_EVIDENCE_PREFIX
            + _confidence_evidence_content_bytes(self.evidence),
            hashlib.sha256,
        ).digest()
        self.assertEqual(self.evidence.mac, expected)

    def test_round_trip(self):
        decoded = ConfidenceEvidence.from_bytes(self.data)
        self.assertEqual(decoded, self.evidence)
        self.assertEqual(decoded.to_bytes(), self.data)

    def test_from_bytes_does_not_verify_mac(self):
        data = resign(self.data, key=OTHER_KEY)
        decoded = ConfidenceEvidence.from_bytes(data)
        self.assertNotEqual(decoded.mac, self.evidence.mac)

    def test_from_bytes_type_and_value_errors(self):
        with self.assertRaises(TypeError):
            ConfidenceEvidence.from_bytes("not bytes")
        with self.assertRaises(TypeError):
            ConfidenceEvidence.from_bytes(bytearray(self.data))
        # Extra field.
        outer = json.loads(self.data)
        outer.append("extra")
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        # Missing field.
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(
                json.dumps(outer[:5], separators=(",", ":")).encode()
            )
        # Not an array.
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(b'{"version":1}')
        # Non-canonical: whitespace.
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(
                json.dumps(json.loads(self.data)).encode()
            )
        # Non-canonical: uppercase hex sample.
        outer = json.loads(self.data)
        outer[1][0] = outer[1][0].upper()
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        # Unsorted samples.
        outer = json.loads(self.data)
        outer[1] = list(reversed(outer[1]))
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        # Bad version.
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(resign(self.data, {0: 2}))
        # Bad decision shape.
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(resign(self.data, {4: [1, 2, 3]}))
        # Bad mac length (tampered directly: resign would recompute it).
        outer = json.loads(self.data)
        outer[5] = "ab" * 31
        with self.assertRaises(ValueError):
            ConfidenceEvidence.from_bytes(
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
            {"decision": None},
            {"decision": dataclasses.replace(decision, sample_count=0)},
            {"decision": dataclasses.replace(decision, inlier_count=1.5)},
            {"decision": dataclasses.replace(decision, center=-1.0)},
            {"decision": dataclasses.replace(decision, mad=float("inf"))},
            {"decision": dataclasses.replace(decision, coverage=1.0)},
            {"decision": dataclasses.replace(decision, lower_bound=-0.5)},
            {"decision": dataclasses.replace(decision, accepted=1)},
            {"mac": b"\x00" * 31},
            {"mac": "00" * 32},
        ]
        for change in bad:
            with self.assertRaises(
                ValueError, msg=next(iter(change))
            ):
                ConfidenceEvidence(**{**good, **change})


class SealConfidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)

    def test_matches_assess_confidence(self):
        record = seal_confidence(self.records, 100.0, KEY, coverage=0.9)
        decision = assess_confidence(self.records, 100.0, key=KEY, coverage=0.9)
        self.assertEqual(record.decision, decision)
        self.assertEqual(record.min_samples, 5)

    def test_keyword_defaults_match_assess_confidence(self):
        record = seal_confidence(self.records, 100.0, KEY)
        self.assertEqual(record.decision.coverage, 0.95)
        self.assertEqual(record.min_samples, 5)

    def test_rejected_decision_seals(self):
        record = seal_confidence(self.records, 1e-9, KEY)
        self.assertIs(record.decision.accepted, False)
        self.assertEqual(audit_confidence(record, KEY), record.decision)

    def test_order_and_form_do_not_change_artifact(self):
        base = seal_confidence(self.records, 100.0, KEY)
        shuffled = seal_confidence(
            list(reversed(self.records)), 100.0, KEY
        )
        as_bytes = seal_confidence(
            [record.to_bytes() for record in self.records], 100.0, KEY
        )
        mixed = seal_confidence(
            [
                record if index % 2 else record.to_bytes()
                for index, record in enumerate(self.records)
            ],
            100.0,
            KEY,
        )
        for other in (shuffled, as_bytes, mixed):
            self.assertEqual(other.to_bytes(), base.to_bytes())

    def test_one_shot_iterable(self):
        record = seal_confidence(iter(self.records), 100.0, KEY)
        self.assertEqual(
            record.to_bytes(), seal_confidence(self.records, 100.0, KEY).to_bytes()
        )
        generator = (record for record in self.records)
        self.assertEqual(
            seal_confidence(generator, 100.0, KEY).to_bytes(), record.to_bytes()
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            seal_confidence(42, 100.0, KEY)
        with self.assertRaises(TypeError):
            seal_confidence(self.records, 100.0, "not-bytes")
        with self.assertRaises(TypeError):
            seal_confidence(
                [make_measurement(i, 10.0) for i in range(6)], 100.0, KEY
            )
        with self.assertRaises(TypeError):
            seal_confidence(self.records + [42], 100.0, KEY)

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            seal_confidence(self.records, 100.0, b"")
        with self.assertRaises(ValueError):
            seal_confidence(self.records, -1.0, KEY)
        with self.assertRaises(ValueError):
            seal_confidence(self.records, True, KEY)
        with self.assertRaises(ValueError):
            seal_confidence(self.records, 100.0, KEY, min_samples=0)
        with self.assertRaises(ValueError):
            seal_confidence(self.records, 100.0, KEY, coverage=1.0)
        with self.assertRaises(ValueError):
            seal_confidence(self.records, 100.0, KEY, coverage=0.0)
        with self.assertRaises(ValueError):
            seal_confidence(self.records, 100.0, KEY, coverage=True)
        # Too few samples.
        with self.assertRaises(ValueError):
            seal_confidence(self.records[:4], 100.0, KEY)
        # Duplicate (round_index, nonce) pair.
        with self.assertRaises(ValueError):
            seal_confidence(
                [self.records[0]] + list(self.records), 100.0, KEY
            )
        # A sample signed under another key fails its audit.
        _, other_records = make_evidence_list(1, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            seal_confidence(
                list(self.records) + other_records, 100.0, KEY
            )
        # Non-canonical sample bytes.
        record = self.records[0]
        outer = json.loads(record.to_bytes())
        bad_blob = json.dumps(outer).encode()  # whitespace -> non-canonical
        with self.assertRaises(ValueError):
            seal_confidence([bad_blob] + list(self.records[1:]), 100.0, KEY)


class AuditConfidenceTest(unittest.TestCase):
    def setUp(self):
        # Varied distances make every statistical field — including the
        # coverage-bracketed bounds — sensitive to the sample set and the
        # coverage level, so any tampering is detectable by recomputation.
        self.verifier, self.records = make_varied_evidence_list()
        self.evidence = seal_confidence(self.records, 100.0, KEY)
        self.data = self.evidence.to_bytes()

    def test_returns_noise_decision(self):
        decision = audit_confidence(self.evidence, KEY)
        self.assertIsInstance(decision, NoiseDecision)
        self.assertEqual(decision, self.evidence.decision)
        self.assertEqual(
            decision, assess_confidence(self.records, 100.0, key=KEY)
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_confidence(self.data, KEY), self.evidence.decision
        )

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            audit_confidence("nope", KEY)
        with self.assertRaises(TypeError):
            audit_confidence(42, KEY)
        with self.assertRaises(TypeError):
            audit_confidence(self.evidence, "not-bytes")

    def test_value_errors(self):
        with self.assertRaises(ValueError):
            audit_confidence(self.evidence, b"")
        with self.assertRaises(ValueError):
            audit_confidence(self.evidence, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_confidence(self.data[:-2] + b"00", KEY)

    def test_tampered_fields_fail_even_when_resigned(self):
        outer = json.loads(self.data)
        # Tamper with each statistical field of the carried decision and
        # re-sign with the right key: the recomputation must still fail.
        decision = self.evidence.decision
        self.assertEqual(decision.inlier_count, 6)
        tampered_decisions = [
            [decision.sample_count + 1] + list(outer[4][1:]),
            [outer[4][0], decision.inlier_count + 1] + list(outer[4][2:]),
            list(outer[4][:2]) + [decision.center + 1.0] + list(outer[4][3:]),
            list(outer[4][:3]) + [decision.mad + 1.0] + list(outer[4][4:]),
            list(outer[4][:4]) + [0.5] + list(outer[4][5:]),
            list(outer[4][:5]) + [decision.lower_bound + 1.0] + list(outer[4][6:]),
            list(outer[4][:6]) + [decision.upper_bound + 1.0, outer[4][7]],
            list(outer[4][:7]) + [not decision.accepted],
        ]
        for tampered in tampered_decisions:
            with self.assertRaises(ValueError, msg=tampered):
                audit_confidence(resign(self.data, {4: tampered}), KEY)
        # Tampered threshold and minimum sample count, re-signed.
        with self.assertRaises(ValueError):
            audit_confidence(resign(self.data, {2: 0.0}), KEY)
        with self.assertRaises(ValueError):
            audit_confidence(resign(self.data, {3: 7}), KEY)

    def test_tampered_samples_fail_even_when_resigned(self):
        # Swap one carried sample for a different valid record: the
        # recomputed statistics no longer match the recorded decision.
        _, other_records = make_evidence_list(1, key=KEY, step=2e-7)
        swapped = sorted(
            list(self.evidence.samples[:5]) + [other_records[0].to_bytes()]
        )
        with self.assertRaises(ValueError):
            audit_confidence(
                resign(self.data, {1: [sample.hex() for sample in swapped]}),
                KEY,
            )
        # Drop a sample: the recomputed sample count disagrees.
        dropped = list(self.evidence.samples[:5])
        with self.assertRaises(ValueError):
            audit_confidence(
                resign(self.data, {1: [sample.hex() for sample in dropped]}),
                KEY,
            )

    def test_duplicate_sample_fails_even_when_resigned(self):
        samples = list(self.evidence.samples)
        samples[1] = samples[0]
        with self.assertRaises(ValueError):
            audit_confidence(
                resign(self.data, {1: [sample.hex() for sample in samples]}),
                KEY,
            )

    def test_no_partial_result(self):
        try:
            audit_confidence(resign(self.data, {3: 7}), KEY)
        except ValueError:
            pass
        else:
            self.fail("expected ValueError")


if __name__ == "__main__":
    unittest.main()
