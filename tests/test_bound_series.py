"""Tests for the bound-series evidence extension.

Covers seal_bound_series / audit_bound_series and the BoundSeriesEvidence
record: canonical bytes, the NPBS1 chain digest over the session, round
range and ordered samples, the NPBS2 MAC, continuous-round and
shared-commitment enforcement and the reruns of the assess decision.
Existing entry points must be unaffected, so the last section pins a few
compatibility facts.
"""

import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BoundEvidence,
    BoundSeriesEvidence,
    Prover,
    RangeDecision,
    Verifier,
    _BOUND_SERIES_CHAIN_PREFIX,
    _BOUND_SERIES_MAC_PREFIX,
    _bound_series_chain_digest,
    _bound_series_payload,
    assess,
    audit_bound,
    audit_bound_series,
    context_digest,
    seal_bound_series,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
CONTEXT = b"c" * 32
OTHER_CONTEXT = b"x" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)
OTHER_DIGEST = context_digest(OTHER_CONTEXT, OPENING)
SESSION_ID = b"s" * 32
OTHER_SESSION_ID = b"t" * 32
TRIP = 0.5
DISTANCE = TRIP * 299_792_458.0 / 2.0
LIMIT = 75_000_000.0


class SteppedClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def fixture(context=CONTEXT, digest=DIGEST):
    clock = SteppedClock()
    prover = Prover(KEY)
    verifier = Verifier(KEY, clock=clock, replay_protection=True)
    return clock, prover, verifier


def bound_round(verifier, prover, clock, context=CONTEXT, opening=OPENING,
                digest=DIGEST, trip=TRIP):
    """Run one successful bound round and return its BoundEvidence."""
    challenge = verifier.new_challenge(context=context, digest=digest)
    started = clock.now
    response = prover.reveal(challenge, context, opening)
    clock.now += trip
    return verifier.verify_bound(challenge, response, started, opening=opening)


def make_series(count=6, *, context=CONTEXT, digest=DIGEST, trip=TRIP):
    clock, prover, verifier = fixture()
    samples = [
        bound_round(verifier, prover, clock, context=context, digest=digest,
                    trip=trip)
        for _ in range(count)
    ]
    return samples


def sealed(samples=None, *, session_id=SESSION_ID, first=None, limit=LIMIT,
           min_samples=3, key=KEY):
    if samples is None:
        samples = make_series()
    if first is None:
        head = samples[0]
        if isinstance(head, bytes):
            head = BoundEvidence.from_bytes(head)
        first = head.evidence.round_index
    return seal_bound_series(
        samples, session_id, first, len(samples), limit, min_samples, key
    )


def resign(record, **changes):
    """Apply field changes to a record and recompute the chain digest and
    MAC, so the tampered record is correctly signed for its new content."""
    record = dataclasses.replace(record, **changes)
    if "chain_digest" not in changes:
        record = dataclasses.replace(
            record,
            chain_digest=_bound_series_chain_digest(
                record.session_id,
                record.first_round_index,
                record.expected_rounds,
                record.samples,
            ),
        )
    return dataclasses.replace(
        record,
        mac=hmac.new(
            KEY,
            _BOUND_SERIES_MAC_PREFIX
            + json.dumps(
                _bound_series_payload(record), separators=(",", ":")
            ).encode("utf-8"),
            hashlib.sha256,
        ).digest(),
    )


class BoundSeriesRecordTest(unittest.TestCase):
    def setUp(self):
        self.samples = make_series()
        self.record = sealed(self.samples)
        self.data = self.record.to_bytes()

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.record.accepted = False

    def test_fields(self):
        decision = assess(
            [audit_bound(sample, KEY) for sample in self.samples],
            LIMIT,
            min_samples=3,
        )
        self.assertIsInstance(self.record, BoundSeriesEvidence)
        self.assertEqual(self.record.version, 1)
        self.assertEqual(self.record.session_id, SESSION_ID)
        self.assertEqual(self.record.first_round_index, 1)
        self.assertEqual(self.record.expected_rounds, 6)
        self.assertEqual(self.record.limit, LIMIT)
        self.assertEqual(self.record.min_samples, 3)
        self.assertEqual(self.record.sample_count, decision.sample_count)
        self.assertEqual(self.record.upper_bound, decision.upper_bound)
        self.assertIs(self.record.accepted, decision.accepted)
        self.assertEqual(len(self.record.chain_digest), 32)
        self.assertEqual(len(self.record.mac), 32)

    def test_samples_keep_input_order(self):
        self.assertEqual(
            self.record.samples,
            tuple(sample.to_bytes() for sample in self.samples),
        )

    def test_no_key_material_stored(self):
        self.assertNotIn(KEY, self.record.to_bytes())

    def test_round_trip_bytes(self):
        self.assertEqual(BoundSeriesEvidence.from_bytes(self.data), self.record)

    def test_encoding_is_compact_object_in_field_order(self):
        self.assertNotIn(b" ", self.data)
        outer = json.loads(self.data)
        self.assertEqual(
            list(outer),
            [
                "version",
                "session_id",
                "first_round_index",
                "expected_rounds",
                "samples",
                "limit",
                "min_samples",
                "sample_count",
                "upper_bound",
                "accepted",
                "chain_digest",
                "mac",
            ],
        )
        self.assertEqual(outer["version"], 1)
        self.assertEqual(outer["session_id"], SESSION_ID.hex())
        self.assertEqual(
            outer["samples"],
            [sample.to_bytes().hex() for sample in self.samples],
        )
        self.assertEqual(outer["chain_digest"], self.record.chain_digest.hex())
        self.assertEqual(outer["mac"], self.record.mac.hex())

    def test_chain_digest_binds_session_range_and_ordered_samples(self):
        blobs = tuple(sample.to_bytes() for sample in self.samples)
        expected = hashlib.sha256(
            _BOUND_SERIES_CHAIN_PREFIX
            + SESSION_ID
            + (1).to_bytes(8, byteorder="big")
            + (6).to_bytes(8, byteorder="big")
            + b"".join(blobs)
        ).digest()
        self.assertEqual(self.record.chain_digest, expected)

    def test_chain_digest_is_order_sensitive(self):
        blobs = tuple(sample.to_bytes() for sample in self.samples)
        forward = _bound_series_chain_digest(SESSION_ID, 1, 6, blobs)
        backward = _bound_series_chain_digest(
            SESSION_ID, 1, 6, tuple(reversed(blobs))
        )
        self.assertNotEqual(forward, backward)

    def test_chain_digest_binds_session_and_range(self):
        blobs = tuple(sample.to_bytes() for sample in self.samples)
        base = _bound_series_chain_digest(SESSION_ID, 1, 6, blobs)
        self.assertNotEqual(
            base, _bound_series_chain_digest(OTHER_SESSION_ID, 1, 6, blobs)
        )
        self.assertNotEqual(
            base, _bound_series_chain_digest(SESSION_ID, 2, 6, blobs)
        )
        self.assertNotEqual(
            base, _bound_series_chain_digest(SESSION_ID, 1, 5, blobs)
        )

    def test_mac_uses_domain_prefix_over_fields_without_mac(self):
        payload = _bound_series_payload(self.record)
        expected = hmac.new(
            KEY,
            _BOUND_SERIES_MAC_PREFIX
            + json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        self.assertEqual(self.record.mac, expected)

    def test_from_bytes_does_not_verify_mac_or_chain(self):
        outer = json.loads(self.data)
        outer["mac"] = "00" * 32
        outer["chain_digest"] = "00" * 32
        data = json.dumps(outer, separators=(",", ":")).encode()
        record = BoundSeriesEvidence.from_bytes(data)
        self.assertEqual(record.mac, b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_bound_series(data, KEY)


class BoundSeriesFromBytesTest(unittest.TestCase):
    def setUp(self):
        self.record = sealed()
        self.data = self.record.to_bytes()

    def decode_with(self, **changes):
        outer = json.loads(self.data)
        outer.update(changes)
        return json.dumps(outer, separators=(",", ":")).encode()

    def test_non_bytes_raises_type_error(self):
        with self.assertRaises(TypeError):
            BoundSeriesEvidence.from_bytes(self.data.decode("utf-8"))

    def test_invalid_json(self):
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(b"{not json")

    def test_whitespace_is_not_canonical(self):
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.data.replace(b",", b", ", 1)
            )

    def test_missing_extra_duplicate_and_reordered_keys(self):
        outer = json.loads(self.data)
        del outer["mac"]
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        outer = json.loads(self.data)
        outer["extra"] = 1
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode()
            )
        raw = self.data.decode("utf-8")
        duplicated = raw[:-1] + ',"version":1}'
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(duplicated.encode())
        items = list(json.loads(self.data).items())
        items[1], items[2] = items[2], items[1]
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                json.dumps(dict(items), separators=(",", ":")).encode()
            )

    def test_version_must_be_one(self):
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(version=2))

    def test_hex_fields_must_be_lowercase_and_32_bytes(self):
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(session_id=(b"\xab" * 32).hex().upper())
            )
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(session_id=(b"s" * 31).hex())
            )
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(chain_digest=(b"d" * 31).hex())
            )
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(mac=(b"m" * 33).hex())
            )

    def test_numeric_and_flag_contracts(self):
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(first_round_index=-1)
            )
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(first_round_index=True)
            )
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(expected_rounds=0))
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(min_samples=0))
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(limit=-1.0))
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(upper_bound=-0.5))
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(accepted=1))

    def test_samples_must_be_canonical_bound_evidence(self):
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(samples=[]))
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(self.decode_with(samples=["00"]))
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(
                self.decode_with(samples=[b"not hex!!".hex()])
            )

    def test_constructor_field_contract(self):
        base = dict(
            version=1,
            session_id=SESSION_ID,
            first_round_index=1,
            expected_rounds=1,
            samples=self.record.samples[:1],
            limit=LIMIT,
            min_samples=1,
            sample_count=1,
            upper_bound=DISTANCE,
            accepted=True,
            chain_digest=b"d" * 32,
            mac=b"m" * 32,
        )
        with self.assertRaises(TypeError):
            BoundSeriesEvidence(**{**base, "version": "1"})
        with self.assertRaises(TypeError):
            BoundSeriesEvidence(**{**base, "session_id": SESSION_ID.hex()})
        with self.assertRaises(TypeError):
            BoundSeriesEvidence(**{**base, "samples": list(base["samples"])})
        with self.assertRaises(TypeError):
            BoundSeriesEvidence(**{**base, "mac": "m" * 64})
        with self.assertRaises(ValueError):
            BoundSeriesEvidence(**{**base, "version": 2})
        with self.assertRaises(ValueError):
            BoundSeriesEvidence(**{**base, "session_id": b"s" * 31})
        with self.assertRaises(ValueError):
            BoundSeriesEvidence(**{**base, "first_round_index": -1})
        with self.assertRaises(ValueError):
            BoundSeriesEvidence(**{**base, "expected_rounds": 0})


class SealBoundSeriesTest(unittest.TestCase):
    def test_accepts_instances_bytes_and_mixed(self):
        samples = make_series()
        as_bytes = [sample.to_bytes() for sample in samples]
        from_instances = sealed(samples)
        from_bytes = sealed(as_bytes)
        mixed = sealed(
            [
                sample if index % 2 else sample.to_bytes()
                for index, sample in enumerate(samples)
            ]
        )
        self.assertEqual(from_instances, from_bytes)
        self.assertEqual(from_instances, mixed)

    def test_nonzero_first_round_index(self):
        clock, prover, verifier = fixture()
        for _ in range(2):
            bound_round(verifier, prover, clock)
        samples = [bound_round(verifier, prover, clock) for _ in range(4)]
        record = seal_bound_series(
            samples, SESSION_ID, 3, 4, LIMIT, 3, KEY
        )
        self.assertEqual(record.first_round_index, 3)
        self.assertEqual(record.expected_rounds, 4)
        decision = audit_bound_series(record, KEY)
        self.assertEqual(decision.sample_count, 4)

    def test_statistics_follow_assess(self):
        clock, prover, verifier = fixture()
        trips = [0.5, 0.5, 0.5, 0.5, 0.5, 2.0]
        samples = [
            bound_round(verifier, prover, clock, trip=trip) for trip in trips
        ]
        record = seal_bound_series(samples, SESSION_ID, 1, 6, LIMIT, 3, KEY)
        decision = assess(
            [audit_bound(sample, KEY) for sample in samples],
            LIMIT,
            min_samples=3,
        )
        self.assertEqual(record.sample_count, decision.sample_count)
        self.assertEqual(record.upper_bound, decision.upper_bound)
        self.assertIs(record.accepted, decision.accepted)
        # The outlier is counted but does not raise the bound.
        self.assertEqual(record.sample_count, 6)
        self.assertEqual(record.upper_bound, DISTANCE)
        self.assertTrue(record.accepted)

    def test_rejected_when_bound_exceeds_limit(self):
        record = sealed(limit=DISTANCE / 2)
        self.assertFalse(record.accepted)
        decision = audit_bound_series(record, KEY)
        self.assertFalse(decision.accepted)

    def test_type_errors(self):
        samples = make_series()
        with self.assertRaises(TypeError):
            seal_bound_series(42, SESSION_ID, 1, 6, LIMIT, 3, KEY)
        with self.assertRaises(TypeError):
            seal_bound_series(
                [samples[0], 42], SESSION_ID, 1, 2, LIMIT, 1, KEY
            )
        with self.assertRaises(TypeError):
            seal_bound_series(samples, SESSION_ID.hex(), 1, 6, LIMIT, 3, KEY)
        with self.assertRaises(TypeError):
            seal_bound_series(
                samples, SESSION_ID, 1, 6, LIMIT, 3, KEY.decode()
            )

    def test_value_errors_on_shape_arguments(self):
        samples = make_series()
        with self.assertRaises(ValueError):
            seal_bound_series(samples, b"s" * 31, 1, 6, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 6, LIMIT, 3, b"")
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, -1, 6, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1.5, 6, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 0, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, -2, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 6, -1.0, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 6, LIMIT, 0, KEY)

    def test_sample_count_must_equal_expected_rounds(self):
        samples = make_series()
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 5, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 7, LIMIT, 3, KEY)
        with self.assertRaises(ValueError):
            seal_bound_series([], SESSION_ID, 1, 1, LIMIT, 1, KEY)

    def test_rounds_must_be_consecutive_from_first(self):
        samples = make_series()
        # A gap: drop the third round but keep the declared count honest.
        gapped = samples[:2] + samples[3:]
        with self.assertRaises(ValueError):
            seal_bound_series(gapped, SESSION_ID, 1, 5, LIMIT, 3, KEY)
        # A duplicate round in place of the missing one.
        duplicated = samples[:2] + [samples[1]] + samples[3:]
        with self.assertRaises(ValueError):
            seal_bound_series(duplicated, SESSION_ID, 1, 6, LIMIT, 3, KEY)
        # A permutation of a valid series breaks the consecutive order.

        # and would chain to a different digest anyway.
        with self.assertRaises(ValueError):
            seal_bound_series(
                list(reversed(samples)), SESSION_ID, 1, 6, LIMIT, 3, KEY
            )
        # A wrong first_round_index shifts the whole expected sequence.
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 2, 6, LIMIT, 3, KEY)

    def test_contexts_must_not_be_mixed(self):
        own = make_series()
        foreign = make_series(context=OTHER_CONTEXT, digest=OTHER_DIGEST)
        mixed = own[:3] + foreign[3:]
        with self.assertRaises(ValueError):
            seal_bound_series(mixed, SESSION_ID, 1, 6, LIMIT, 3, KEY)

    def test_tampered_sample_is_rejected(self):
        samples = make_series()
        outer = json.loads(samples[2].to_bytes())
        outer["context"] = OTHER_CONTEXT.hex()
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            seal_bound_series(
                samples[:2] + [tampered] + samples[3:],
                SESSION_ID,
                1,
                6,
                LIMIT,
                3,
                KEY,
            )

    def test_foreign_key_sample_is_rejected(self):
        clock = SteppedClock()
        foreign_prover = Prover(OTHER_KEY)
        foreign_verifier = Verifier(
            OTHER_KEY, clock=clock, replay_protection=True
        )
        samples = make_series()
        challenge = foreign_verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        started = clock.now
        response = foreign_prover.reveal(challenge, CONTEXT, OPENING)
        clock.now += TRIP
        foreign = foreign_verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        with self.assertRaises(ValueError):
            seal_bound_series(
                samples[:5] + [foreign], SESSION_ID, 1, 6, LIMIT, 3, KEY
            )

    def test_too_few_samples_or_inliers(self):
        samples = make_series(3)
        with self.assertRaises(ValueError):
            seal_bound_series(samples, SESSION_ID, 1, 3, LIMIT, 5, KEY)
        clock, prover, verifier = fixture()
        trips = [0.5, 0.5, 0.5, 1.0, 1.0]
        spread = [
            bound_round(verifier, prover, clock, trip=trip) for trip in trips
        ]
        with self.assertRaises(ValueError):
            seal_bound_series(spread, SESSION_ID, 1, 5, LIMIT, 4, KEY)


class AuditBoundSeriesTest(unittest.TestCase):
    def setUp(self):
        self.samples = make_series()
        self.record = sealed(self.samples)
        self.data = self.record.to_bytes()

    def test_accepts_record_and_bytes(self):
        expected = RangeDecision(
            sample_count=6, upper_bound=DISTANCE, accepted=True
        )
        self.assertEqual(audit_bound_series(self.record, KEY), expected)
        self.assertEqual(audit_bound_series(self.data, KEY), expected)

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            audit_bound_series(42, KEY)
        with self.assertRaises(TypeError):
            audit_bound_series(self.data.decode("utf-8"), KEY)
        with self.assertRaises(TypeError):
            audit_bound_series(self.record, KEY.decode())

    def test_empty_key_and_bad_encoding(self):
        with self.assertRaises(ValueError):
            audit_bound_series(self.record, b"")
        with self.assertRaises(ValueError):
            audit_bound_series(b"{not json", KEY)

    def test_wrong_key_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(self.record, OTHER_KEY)

    def test_tampered_mac_is_rejected(self):
        record = dataclasses.replace(self.record, mac=b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_tampered_chain_digest_is_rejected(self):
        record = dataclasses.replace(self.record, chain_digest=b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_tampered_field_breaks_mac(self):
        record = dataclasses.replace(self.record, limit=LIMIT * 2)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)
        record = dataclasses.replace(self.record, session_id=OTHER_SESSION_ID)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_resigned_statistics_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.record, upper_bound=self.record.upper_bound + 1),
                KEY,
            )
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.record, accepted=not self.record.accepted), KEY
            )
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.record, sample_count=self.record.sample_count + 1),
                KEY,
            )

    def test_resigned_permutation_is_rejected(self):
        record = resign(
            self.record, samples=tuple(reversed(self.record.samples))
        )
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_resigned_duplicate_round_is_rejected(self):
        samples = self.record.samples[:2] + self.record.samples[1:2] + self.record.samples[3:]
        record = resign(self.record, samples=samples)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_resigned_count_mismatch_is_rejected(self):
        record = resign(self.record, expected_rounds=7)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_resigned_mixed_context_is_rejected(self):
        foreign = make_series(context=OTHER_CONTEXT, digest=OTHER_DIGEST)
        samples = self.record.samples[:3] + tuple(
            sample.to_bytes() for sample in foreign[3:]
        )
        record = resign(self.record, samples=samples)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_resigned_wrong_sample_key_is_rejected(self):
        clock = SteppedClock()
        foreign_prover = Prover(OTHER_KEY)
        foreign_verifier = Verifier(
            OTHER_KEY, clock=clock, replay_protection=True
        )
        foreign = bound_round(
            foreign_verifier, foreign_prover, clock
        )
        samples = self.record.samples[:5] + (foreign.to_bytes(),)
        record = resign(self.record, samples=samples)
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_audit_matches_assess_over_inner_evidence(self):
        decision = audit_bound_series(self.record, KEY)
        expected = assess(
            [audit_bound(sample, KEY) for sample in self.record.samples],
            LIMIT,
            min_samples=3,
        )
        self.assertEqual(decision, expected)
        for sample in self.record.samples:
            measurement = audit_bound(sample, KEY)
            self.assertEqual(measurement.distance_meters, DISTANCE)


class CompatibilityTest(unittest.TestCase):
    """The new entry points must not disturb the existing ones."""

    def test_existing_bound_api_unchanged(self):
        samples = make_series()
        record = samples[0]
        self.assertEqual(
            BoundEvidence.from_bytes(record.to_bytes()), record
        )
        measurement = audit_bound(record, KEY)
        self.assertEqual(measurement.round_index, record.evidence.round_index)
        decision = assess(
            [audit_bound(sample, KEY) for sample in samples],
            LIMIT,
            min_samples=3,
        )
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.upper_bound, DISTANCE)
        self.assertTrue(decision.accepted)


if __name__ == "__main__":
    unittest.main()
