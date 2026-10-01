import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    AssessEvidence,
    BoundEvidence,
    BoundSeriesEvidence,
    Measurement,
    Prover,
    RangeDecision,
    Verifier,
    _BOUND_SERIES_CHAIN_PREFIX,
    _BOUND_SERIES_MAC_PREFIX,
    _assess_measurements,
    _bound_series_chain_digest,
    _encode_payload,
    assess,
    audit_bound,
    audit_bound_series,
    context_digest,
    seal_bound_series,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret-key!"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)
OTHER_CONTEXT = b"d" * 32
OTHER_OPENING = b"p" * 32
OTHER_DIGEST = context_digest(OTHER_CONTEXT, OTHER_OPENING)
SESSION = b"s" * 32
OTHER_SESSION = b"t" * 32

# A 1e-7 s RTT at light speed halves to ~15 m, so a 100 m limit accepts and
# a 1 m limit rejects these fixtures deterministically.
DEFAULT_STEP = 1e-7


class SteppedClock:
    def __init__(self, start: float = 0.0, step: float = DEFAULT_STEP) -> None:
        self.now = start
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


def bound_decision(records, limit, min_samples=5):
    """The assess median/MAD decision over bound evidences.

    Bound evidences carry commitment-bound responses, so they are re-verified
    with audit_bound (not audit) before feeding the exact assess statistics
    helper the sealer uses.
    """
    measurements = [audit_bound(record, KEY) for record in records]
    return _assess_measurements(measurements, float(limit), min_samples)



def make_bounds(count, *, key=KEY, context=CONTEXT, opening=OPENING,
                digest=DIGEST, step=DEFAULT_STEP, start=0.0):
    prover = Prover(key)
    clock = SteppedClock(start=start, step=step)
    verifier = Verifier(key, clock=clock, replay_protection=True)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge(context=context, digest=digest)
        started = clock.now
        response = prover.reveal(challenge, context, opening)
        clock.now += step
        records.append(
            verifier.verify_bound(
                challenge, response, started, opening=opening
            )
        )
    return verifier, records


def make_mixed_commitment_bounds(count, switch_at, *, key=KEY,
                                 step=DEFAULT_STEP):
    """Consecutive rounds, the first ``switch_at`` under the primary
    commitment and the rest under a genuinely different commitment.

    Every record passes :func:`audit_bound` individually and the round
    indices run consecutively, but the series mixes contexts/digests.
    """
    prover = Prover(key)
    clock = SteppedClock(step=step)
    verifier = Verifier(key, clock=clock, replay_protection=True)
    records = []
    for index in range(count):
        if index < switch_at:
            context, opening, digest = CONTEXT, OPENING, DIGEST
        else:
            context, opening, digest = (
                OTHER_CONTEXT, OTHER_OPENING, OTHER_DIGEST
            )
        challenge = verifier.new_challenge(context=context, digest=digest)
        started = clock.now
        response = prover.reveal(challenge, context, opening)
        clock.now += step
        records.append(
            verifier.verify_bound(
                challenge, response, started, opening=opening
            )
        )
    return verifier, records


def make_bounds_starting_at(first_index, count, **kwargs):
    """Bound rounds whose verifier round indices begin at ``first_index``."""
    verifier, burn = make_bounds(first_index - 1, **kwargs)
    key = kwargs.get("key", KEY)
    context = kwargs.get("context", CONTEXT)
    opening = kwargs.get("opening", OPENING)
    digest = kwargs.get("digest", DIGEST)
    step = kwargs.get("step", DEFAULT_STEP)
    prover = Prover(key)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge(context=context, digest=digest)
        started = verifier.clock.now
        response = prover.reveal(challenge, context, opening)
        verifier.clock.now += step
        records.append(
            verifier.verify_bound(
                challenge, response, started, opening=opening
            )
        )
    return verifier, records


def resign(data, *, key=KEY, mutate=None):
    """Decode a BoundSeriesEvidence, mutate the outer object, re-MAC it.

    The new MAC is computed over the canonical encoding of every field but
    ``mac`` under ``NPBS2``, so tampered fields survive the outer MAC check
    and reach the structural/chain/statistics re-checks.
    """
    outer = json.loads(data)
    if mutate is not None:
        mutate(outer)
    payload = dict(outer)
    payload.pop("mac")
    outer["mac"] = hmac.new(
        key,
        _BOUND_SERIES_MAC_PREFIX + _encode_payload(payload),
        hashlib.sha256,
    ).digest().hex()
    return _encode_payload(outer)


class BoundSeriesEvidenceRecordTest(unittest.TestCase):
    def setUp(self):
        _verifier, self.records = make_bounds(6)
        self.first = self.records[0].evidence.round_index
        self.evidence = seal_bound_series(
            self.records, SESSION, self.first, 6, 100.0, 5, KEY
        )
        self.data = self.evidence.to_bytes()

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.evidence.accepted = False

    def test_fields(self):
        decision = bound_decision(self.records, 100.0)
        self.assertIsInstance(self.evidence, BoundSeriesEvidence)
        self.assertEqual(self.evidence.version, 1)
        self.assertEqual(self.evidence.session_id, SESSION)
        self.assertEqual(
            self.evidence.first_round_index, self.records[0].evidence.round_index
        )
        self.assertEqual(
            self.evidence.last_round_index, self.records[-1].evidence.round_index
        )
        self.assertEqual(self.evidence.limit, 100.0)
        self.assertEqual(self.evidence.min_samples, 5)
        self.assertEqual(self.evidence.sample_count, decision.sample_count)
        self.assertEqual(self.evidence.upper_bound, decision.upper_bound)
        self.assertIs(self.evidence.accepted, decision.accepted)
        self.assertEqual(len(self.evidence.chain_digest), 32)
        self.assertEqual(len(self.evidence.mac), 32)
        self.assertIsInstance(self.evidence.samples, tuple)
        self.assertEqual(
            self.evidence.samples,
            tuple(record.to_bytes() for record in self.records),
        )

    def test_samples_kept_in_measurement_order(self):
        # Unlike AssessEvidence the input order is preserved verbatim.
        self.assertEqual(
            self.evidence.samples[0], self.records[0].to_bytes()
        )
        self.assertEqual(
            self.evidence.samples[-1], self.records[-1].to_bytes()
        )

    def test_no_key_material_stored(self):
        self.assertNotIn(KEY, self.evidence.to_bytes())

    def test_round_trip_bytes(self):
        self.assertEqual(
            BoundSeriesEvidence.from_bytes(self.data), self.evidence
        )

    def test_encoding_is_compact_ordered_object(self):
        data = self.data
        self.assertNotIn(b" ", data)
        outer = json.loads(data)
        self.assertIsInstance(outer, dict)
        self.assertEqual(
            list(outer),
            [
                "version",
                "session_id",
                "first_round_index",
                "last_round_index",
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
        self.assertEqual(outer["session_id"], SESSION.hex())
        self.assertEqual(outer["limit"], 100.0)
        self.assertEqual(outer["min_samples"], 5)
        self.assertEqual(len(outer["samples"]), 6)
        self.assertEqual(outer["chain_digest"], self.evidence.chain_digest.hex())
        self.assertEqual(outer["mac"], self.evidence.mac.hex())
        # Samples are lowercase hex strings of canonical BoundEvidence bytes.
        first = BoundEvidence.from_bytes(bytes.fromhex(outer["samples"][0]))
        self.assertEqual(first, self.records[0])

    def test_mac_uses_npbs2_over_content_without_mac(self):
        payload = json.loads(self.data)
        payload.pop("mac")
        expected = hmac.new(
            KEY,
            _BOUND_SERIES_MAC_PREFIX + _encode_payload(payload),
            hashlib.sha256,
        ).digest()
        self.assertEqual(expected, self.evidence.mac)

    def test_chain_digest_uses_npbs1_over_session_range_and_ordered_samples(self):
        expected = _bound_series_chain_digest(
            SESSION,
            self.evidence.first_round_index,
            self.evidence.last_round_index,
            self.evidence.samples,
        )
        self.assertEqual(expected, self.evidence.chain_digest)

    def test_chain_digest_binding_details(self):
        # Independent recomputation of the folded chain, byte by byte.
        first = self.evidence.first_round_index
        last = self.evidence.last_round_index
        digest = hashlib.sha256(
            _BOUND_SERIES_CHAIN_PREFIX
            + SESSION
            + first.to_bytes(8, "big")
            + last.to_bytes(8, "big")
        ).digest()
        for blob in self.evidence.samples:
            digest = hashlib.sha256(
                _BOUND_SERIES_CHAIN_PREFIX + digest + blob
            ).digest()
        self.assertEqual(digest, self.evidence.chain_digest)

    def test_permutations_change_chain_digest(self):
        ordered = self.evidence.samples
        permuted = (ordered[1],) + ordered[:1] + ordered[2:]
        other = _bound_series_chain_digest(
            SESSION,
            self.evidence.first_round_index,
            self.evidence.last_round_index,
            permuted,
        )
        self.assertNotEqual(other, self.evidence.chain_digest)

    def test_session_and_range_change_chain_digest(self):
        base = dict(
            first_round_index=self.evidence.first_round_index,
            last_round_index=self.evidence.last_round_index,
            samples=self.evidence.samples,
        )
        self.assertNotEqual(
            _bound_series_chain_digest(OTHER_SESSION, **base),
            self.evidence.chain_digest,
        )
        self.assertNotEqual(
            _bound_series_chain_digest(
                SESSION,
                self.evidence.first_round_index + 1,
                self.evidence.last_round_index,
                self.evidence.samples,
            ),
            self.evidence.chain_digest,
        )

    def test_from_bytes_does_not_verify_mac_or_chain(self):
        outer = json.loads(self.data)
        outer["mac"] = "00" * 32
        outer["chain_digest"] = "11" * 32
        data = _encode_payload(outer)
        record = BoundSeriesEvidence.from_bytes(data)
        self.assertEqual(record.mac, b"\x00" * 32)
        self.assertEqual(record.chain_digest, b"\x11" * 32)
        with self.assertRaises(ValueError):
            audit_bound_series(data, KEY)

    def test_from_bytes_requires_bytes(self):
        for bad in (self.data.decode(), None, 123, bytearray()):
            with self.assertRaises(ValueError, msg=bad):
                BoundSeriesEvidence.from_bytes(bad)

    def test_from_bytes_rejects_bad_key_sets_and_order(self):
        good = json.loads(self.data)
        # Missing field, extra field, duplicated key and reordered key.
        cases = {
            "missing": lambda o: o.pop("mac"),
            "extra": lambda o: o.update({"bogus": 1}),
            "reordered": lambda o: (
                o.__setitem__("version", o.pop("version"))
            ),
        }
        for label, mutate in cases.items():
            outer = json.loads(self.data)
            mutate(outer)
            with self.assertRaises(ValueError, msg=label):
                BoundSeriesEvidence.from_bytes(_encode_payload(outer))

    def test_from_bytes_value_errors(self):
        for bad in (
            b"not json",
            b"{}",
            b"[]",
            self.data.replace(b",", b", ", 1),
            b" " + self.data,
            self.data + b"\n",
        ):
            with self.assertRaises(ValueError, msg=bad[:12]):
                BoundSeriesEvidence.from_bytes(bad)

    def test_from_bytes_field_contract_violations(self):
        def build(mutate):
            outer = json.loads(self.data)
            mutate(outer)
            return _encode_payload(outer)

        bads = [
            build(lambda o: o.__setitem__("version", 2)),
            build(lambda o: o.__setitem__("session_id", "ab")),
            build(lambda o: o.__setitem__("first_round_index", -1)),
            build(lambda o: o.__setitem__("last_round_index", 0)),
            build(lambda o: o.__setitem__("samples", [])),
            build(lambda o: o.__setitem__("samples", o["samples"][:5])),
            build(lambda o: o.__setitem__("limit", -1.0)),
            build(lambda o: o.__setitem__("min_samples", 0)),
            build(lambda o: o.__setitem__("sample_count", 7)),
            build(lambda o: o.__setitem__("upper_bound", -1.0)),
            build(lambda o: o.__setitem__("accepted", "yes")),
            build(lambda o: o.__setitem__("chain_digest", "00" * 31)),
            build(lambda o: o.__setitem__("mac", "00" * 31)),
        ]
        for bad in bads:
            with self.assertRaises(ValueError, msg=bad[:20]):
                BoundSeriesEvidence.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_sample(self):
        outer = json.loads(self.data)
        blob = bytes.fromhex(outer["samples"][0])
        outer["samples"][0] = (b" " + blob).hex()
        with self.assertRaises(ValueError):
            BoundSeriesEvidence.from_bytes(_encode_payload(outer))

    def test_positional_construction_and_equality(self):
        other = BoundSeriesEvidence(
            self.evidence.version,
            self.evidence.session_id,
            self.evidence.first_round_index,
            self.evidence.last_round_index,
            self.evidence.samples,
            self.evidence.limit,
            self.evidence.min_samples,
            self.evidence.sample_count,
            self.evidence.upper_bound,
            self.evidence.accepted,
            self.evidence.chain_digest,
            self.evidence.mac,
        )
        self.assertEqual(other, self.evidence)
        self.assertEqual(hash(other), hash(self.evidence))

    def test_construction_type_errors(self):
        good = self.evidence
        kwargs = dict(
            version=1,
            session_id=SESSION,
            first_round_index=good.first_round_index,
            last_round_index=good.last_round_index,
            samples=good.samples,
            limit=good.limit,
            min_samples=good.min_samples,
            sample_count=good.sample_count,
            upper_bound=good.upper_bound,
            accepted=good.accepted,
            chain_digest=good.chain_digest,
            mac=good.mac,
        )
        for field, bad in (
            ("version", "1"),
            ("session_id", "s" * 32),
            ("samples", list(good.samples)),
            ("chain_digest", "00" * 32),
            ("mac", "00" * 32),
        ):
            changed = dict(kwargs)
            changed[field] = bad
            with self.assertRaises(TypeError, msg=field):
                BoundSeriesEvidence(**changed)

        # A tuple containing a non-bytes entry is also a structural error.
        changed = dict(kwargs)
        changed["samples"] = ("not-bytes",) + good.samples[1:]
        with self.assertRaises(TypeError):
            BoundSeriesEvidence(**changed)

    def test_construction_value_errors(self):
        good = self.evidence
        kwargs = dict(
            version=1,
            session_id=SESSION,
            first_round_index=good.first_round_index,
            last_round_index=good.last_round_index,
            samples=good.samples,
            limit=good.limit,
            min_samples=good.min_samples,
            sample_count=good.sample_count,
            upper_bound=good.upper_bound,
            accepted=good.accepted,
            chain_digest=good.chain_digest,
            mac=good.mac,
        )
        variants = [
            ("version", 2),
            ("session_id", b"short"),
            ("first_round_index", -1),
            ("first_round_index", True),
            ("last_round_index", good.first_round_index - 1),
            ("limit", -0.1),
            ("min_samples", 0),
            ("sample_count", 5),
            ("upper_bound", float("nan")),
            ("accepted", 1),
            ("chain_digest", b"x" * 31),
            ("mac", b"x" * 31),
        ]
        for field, bad in variants:
            changed = dict(kwargs)
            changed[field] = bad
            with self.assertRaises(ValueError, msg=field):
                BoundSeriesEvidence(**changed)


class SealBoundSeriesTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_bounds(6)
        self.first = self.records[0].evidence.round_index

    def seal(self, records=None, **kwargs):
        records = self.records if records is None else records
        kwargs.setdefault("limit", 100.0)
        kwargs.setdefault("min_samples", 5)
        return seal_bound_series(
            records,
            kwargs.pop("session_id", SESSION),
            kwargs.pop("first_round_index", self.first),
            kwargs.pop("expected_rounds", len(records)),
            kwargs["limit"],
            kwargs["min_samples"],
            kwargs.pop("key", KEY),
        )

    def test_seal_matches_assess_decision(self):
        sealed = self.seal()
        decision = bound_decision(self.records, 100.0)
        self.assertEqual(audit_bound_series(sealed, KEY), decision)

    def test_seal_accepts_objects_bytes_and_mixtures(self):
        blobs = [r.to_bytes() for r in self.records]
        sealed_objects = self.seal()
        sealed_bytes = self.seal(blobs)
        mixed = [
            self.records[0],
            blobs[1],
            self.records[2],
            blobs[3],
            self.records[4],
            blobs[5],
        ]
        sealed_mixed = self.seal(mixed)
        self.assertEqual(sealed_bytes, sealed_objects)
        self.assertEqual(sealed_mixed.to_bytes(), sealed_objects.to_bytes())

    def test_round_range_is_recorded(self):
        sealed = self.seal()
        self.assertEqual(sealed.first_round_index, self.first)
        self.assertEqual(sealed.last_round_index, self.first + 5)

    def test_first_round_index_need_not_be_one(self):
        _verifier, records = make_bounds_starting_at(100, 4)
        self.assertEqual(records[0].evidence.round_index, 100)
        sealed = seal_bound_series(records, SESSION, 100, 4, 100.0, 4, KEY)
        self.assertEqual(sealed.first_round_index, 100)
        self.assertEqual(sealed.last_round_index, 103)
        self.assertEqual(audit_bound_series(sealed, KEY).sample_count, 4)

    def test_u64_range_boundary(self):
        from nearproof import _check_bound_series_round_params

        # The largest representable range is accepted by the parameter
        # contract; one more round overflows the unsigned 64-bit bound.
        self.assertEqual(
            _check_bound_series_round_params(2**64 - 2, 2),
            (2**64 - 2, 2**64 - 1),
        )
        with self.assertRaises(ValueError):
            _check_bound_series_round_params(2**64 - 1, 2)
        with self.assertRaises(ValueError):
            _check_bound_series_round_params(2**64, 1)

    def test_integer_limit_preserved_as_float(self):
        sealed = self.seal(limit=100)
        self.assertEqual(sealed.limit, 100.0)

    def test_zero_limit_round_trips(self):
        _verifier, records = make_bounds(5, step=0.0)
        first = records[0].evidence.round_index
        sealed = seal_bound_series(records, SESSION, first, 5, 0, 5, KEY)
        self.assertEqual(sealed.upper_bound, 0.0)
        self.assertIs(sealed.accepted, True)
        self.assertEqual(
            audit_bound_series(sealed, KEY),
            bound_decision(records, 0, 5),
        )

    def test_rejected_conclusion_seals_and_round_trips(self):
        sealed = self.seal(limit=1.0)
        self.assertIs(sealed.accepted, False)
        decision = audit_bound_series(sealed, KEY)
        self.assertIsInstance(decision, RangeDecision)
        self.assertIs(decision.accepted, False)

    def test_non_iterable_samples_raises_type_error(self):
        for bad in (123, None, 5.0, object()):
            with self.assertRaises(TypeError, msg=bad):
                seal_bound_series(bad, SESSION, self.first, 6, 100.0, 5, KEY)

    def test_wrong_element_type_raises_type_error(self):
        # Only non-BoundEvidence/non-bytes elements are structural errors.
        for bad in ("x", 123, None, object()):
            with self.assertRaises(TypeError, msg=bad):
                seal_bound_series(
                    [bad] + self.records[1:], SESSION, self.first, 6,
                    100.0, 5, KEY,
                )

    def test_bytes_element_wrong_content_raises_value_error(self):
        # bytes that are not a canonical BoundEvidence are a value error.
        for bad in (b"bytes-but-not-evidence", b"not json"):
            with self.assertRaises(ValueError, msg=bad):
                seal_bound_series(
                    [bad] + self.records[1:], SESSION, self.first, 6,
                    100.0, 5, KEY,
                )

    def test_malformed_sample_bytes_raise_value_error(self):
        blobs = [r.to_bytes() for r in self.records]
        with self.assertRaises(ValueError):
            seal_bound_series(
                blobs[:5] + [b"not json"], SESSION, self.first, 6,
                100.0, 5, KEY,
            )

    def test_non_canonical_sample_bytes_raise_value_error(self):
        blobs = [r.to_bytes() for r in self.records]
        with self.assertRaises(ValueError):
            seal_bound_series(
                blobs[:5] + [b" " + blobs[5]], SESSION, self.first, 6,
                100.0, 5, KEY,
            )

    def test_session_id_type_and_length(self):
        for bad in ("s" * 32, None, 123, bytearray(SESSION)):
            with self.assertRaises(TypeError, msg=bad):
                self.seal(session_id=bad)
        for bad in (b"", b"short", b"x" * 31, b"x" * 33):
            with self.assertRaises(ValueError, msg=bad):
                self.seal(session_id=bad)

    def test_key_type_and_emptiness(self):
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                self.seal(key=bad)
        with self.assertRaises(ValueError):
            self.seal(key=b"")

    def test_wrong_key_rejected_at_seal(self):
        with self.assertRaises(ValueError):
            self.seal(key=OTHER_KEY)

    def test_first_round_index_validation(self):
        for bad in (-1, 1.0, True, False, "1", None):
            with self.assertRaises(ValueError, msg=bad):
                self.seal(first_round_index=bad)

    def test_expected_rounds_validation(self):
        for bad in (0, -1, 1.0, True, False, "6", None):
            with self.assertRaises(ValueError, msg=bad):
                self.seal(expected_rounds=bad)

    def test_limit_validation_matches_assess(self):
        for bad in (True, False, -0.1, math.nan, math.inf, "10", None):
            with self.assertRaises(ValueError, msg=bad):
                self.seal(limit=bad)

    def test_min_samples_validation_matches_assess(self):
        for bad in (0, -1, True, False, 1.0, "5", None):
            with self.assertRaises(ValueError, msg=bad):
                self.seal(min_samples=bad)

    def test_sample_count_must_equal_expected_rounds(self):
        with self.assertRaises(ValueError):
            self.seal(expected_rounds=5)
        with self.assertRaises(ValueError):
            self.seal(expected_rounds=7)
        with self.assertRaises(ValueError):
            self.seal(records=[], expected_rounds=0)

    def test_round_indices_must_be_consecutive(self):
        # Wrong declared start while the samples start at self.first.
        with self.assertRaises(ValueError):
            self.seal(first_round_index=self.first + 1)
        # A gap (rounds 1,3,4,5,6, missing 2).
        gapped = [self.records[0]] + self.records[2:]
        with self.assertRaises(ValueError):
            seal_bound_series(
                gapped, SESSION, self.first, 5, 100.0, 5, KEY
            )
        # A repeat (rounds 1,1,3,4,5,6).
        repeated = (
            [self.records[0], self.records[0]] + self.records[2:]
        )
        with self.assertRaises(ValueError):
            seal_bound_series(
                repeated, SESSION, self.first, 6, 100.0, 5, KEY
            )

    def test_context_mixing_rejected(self):
        # Five rounds under the primary commitment, the sixth under a
        # genuinely different one. Each record audits on its own and the
        # round indices are consecutive, so only the shared-context rule
        # rejects the series.
        _verifier, mixed = make_mixed_commitment_bounds(6, switch_at=5)
        first = mixed[0].evidence.round_index
        with self.assertRaises(ValueError):
            seal_bound_series(mixed, SESSION, first, 6, 100.0, 5, KEY)

    def test_shared_context_but_distinct_session_seals(self):
        # The same commitment can back many sessions; session_id is free.
        one = self.seal(session_id=SESSION)
        two = self.seal(session_id=OTHER_SESSION)
        self.assertNotEqual(one.to_bytes(), two.to_bytes())
        self.assertEqual(audit_bound_series(one, KEY), audit_bound_series(two, KEY))

    def test_too_few_samples_and_inliers(self):
        with self.assertRaises(ValueError):
            seal_bound_series(
                self.records[:4], SESSION, self.first, 4, 100.0, 5, KEY
            )
        with self.assertRaises(ValueError):
            self.seal(min_samples=7)

    def test_sealing_touches_no_verifier_state(self):
        before = self.verifier.round_count
        self.seal()
        self.seal(records=[r.to_bytes() for r in self.records])
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class AuditBoundSeriesTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_bounds(6)
        self.first = self.records[0].evidence.round_index
        self.evidence = seal_bound_series(
            self.records, SESSION, self.first, 6, 100.0, 5, KEY
        )
        self.data = self.evidence.to_bytes()

    def test_audit_returns_recorded_decision(self):
        decision = audit_bound_series(self.evidence, KEY)
        self.assertIsInstance(decision, RangeDecision)
        self.assertEqual(decision.sample_count, self.evidence.sample_count)
        self.assertEqual(decision.upper_bound, self.evidence.upper_bound)
        self.assertIs(decision.accepted, self.evidence.accepted)

    def test_audit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_bound_series(self.data, KEY),
            audit_bound_series(self.evidence, KEY),
        )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(self.evidence, OTHER_KEY)

    def test_empty_key_raises_value_error(self):
        with self.assertRaises(ValueError):
            audit_bound_series(self.evidence, b"")

    def test_non_bytes_key_raises_type_error(self):
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                audit_bound_series(self.evidence, bad)

    def test_argument_wrong_type_raises_type_error(self):
        for bad in (
            "x", 123, None, object(), [self.data], 7, bytearray(),
        ):
            with self.assertRaises(TypeError, msg=bad):
                audit_bound_series(bad, KEY)

    def test_malformed_bytes_raise_value_error(self):
        for bad in (b"not json", b"{}", b"[]", b'{"version":1}'):
            with self.assertRaises(ValueError, msg=bad):
                audit_bound_series(bad, KEY)

    def test_non_canonical_outer_encoding_rejected(self):
        for bad in (b" " + self.data, self.data + b"\n"):
            with self.assertRaises(ValueError, msg=bad[:6]):
                audit_bound_series(bad, KEY)

    def test_outer_mac_mismatch_rejected(self):
        raw = bytearray(self.data)
        raw[-3] = ord("0") if raw[-3] != ord("0") else ord("1")
        with self.assertRaises(ValueError):
            audit_bound_series(bytes(raw), KEY)

    def test_chain_digest_mismatch_rejected(self):
        # Re-MAC so the outer NPBS2 MAC is valid over a wrong chain digest.
        def mutate(outer):
            outer["chain_digest"] = "00" * 32
        with self.assertRaises(ValueError):
            audit_bound_series(resign(self.data, mutate=mutate), KEY)

    def test_session_swap_rejected_via_chain(self):
        def mutate(outer):
            outer["session_id"] = OTHER_SESSION.hex()
        with self.assertRaises(ValueError):
            audit_bound_series(resign(self.data, mutate=mutate), KEY)

    def test_range_swap_rejected_via_chain_or_count(self):
        def mutate(outer):
            outer["first_round_index"] = outer["first_round_index"] + 1
        with self.assertRaises(ValueError):
            audit_bound_series(resign(self.data, mutate=mutate), KEY)

    def test_sample_permutation_rejected(self):
        # Re-fold a correct chain digest over the swapped sample order and
        # re-MAC, so the continuity (round-order) check is what rejects it.
        outer = json.loads(self.data)
        outer["samples"][0], outer["samples"][1] = (
            outer["samples"][1], outer["samples"][0],
        )
        blobs = [bytes.fromhex(x) for x in outer["samples"]]
        outer["chain_digest"] = _bound_series_chain_digest(
            SESSION, self.first, self.first + 5, tuple(blobs)
        ).hex()
        payload = dict(outer)
        payload.pop("mac")
        outer["mac"] = hmac.new(
            KEY,
            _BOUND_SERIES_MAC_PREFIX + _encode_payload(payload),
            hashlib.sha256,
        ).digest().hex()
        with self.assertRaises(ValueError):
            audit_bound_series(_encode_payload(outer), KEY)

    def test_tampered_sample_body_rejected(self):
        outer = json.loads(self.data)
        blob = bytearray(bytes.fromhex(outer["samples"][0]))
        blob[20] ^= 0xFF
        outer["samples"][0] = bytes(blob).hex()
        # The corrupted sample breaks the canonical BoundEvidence contract
        # (and the chain/outer MAC); decoding rejects it as a value error.
        with self.assertRaises(ValueError):
            audit_bound_series(_encode_payload(outer), KEY)

    def test_foreign_key_sample_rejected(self):
        _verifier, foreign = make_bounds(1, key=OTHER_KEY, start=50.0)
        outer = json.loads(self.data)
        blobs = [bytes.fromhex(x) for x in outer["samples"]]
        # Replace the first sample with a foreign-key bound record with the
        # same round index; re-fold the chain and re-MAC under KEY.
        replacement = foreign[0]
        # Force the foreign evidence's round index onto the expected one by
        # re-issuing is not possible; instead just drop in its bytes and
        # expect the per-sample audit to fail on its MAC/response.
        blobs[0] = replacement.to_bytes()
        outer["samples"] = [b.hex() for b in blobs]
        outer["chain_digest"] = _bound_series_chain_digest(
            SESSION, self.first, self.first + 5, tuple(blobs)
        ).hex()
        payload = dict(outer)
        payload.pop("mac")
        outer["mac"] = hmac.new(
            KEY,
            _BOUND_SERIES_MAC_PREFIX + _encode_payload(payload),
            hashlib.sha256,
        ).digest().hex()
        with self.assertRaises(ValueError):
            audit_bound_series(_encode_payload(outer), KEY)

    def test_sample_count_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.data, mutate=lambda o: o.__setitem__(
                    "sample_count", o["sample_count"] + 1)),
                KEY,
            )

    def test_upper_bound_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.data, mutate=lambda o: o.__setitem__(
                    "upper_bound", o["upper_bound"] + 1.0)),
                KEY,
            )

    def test_accepted_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.data, mutate=lambda o: o.__setitem__(
                    "accepted", not o["accepted"])),
                KEY,
            )

    def test_limit_mismatch_rejected(self):
        # Lowering the carried limit below the measured bound flips the
        # recomputed conclusion, disagreeing with the recorded accepted.
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.data, mutate=lambda o: o.__setitem__(
                    "limit", 1.0)),
                KEY,
            )

    def test_min_samples_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series(
                resign(self.data, mutate=lambda o: o.__setitem__(
                    "min_samples", o["min_samples"] + 100)),
                KEY,
            )

    def test_dropped_sample_rejected(self):
        outer = json.loads(self.data)
        outer["samples"] = outer["samples"][:5]
        # The field contract (range vs sample count) already rejects this.
        with self.assertRaises(ValueError):
            audit_bound_series(_encode_payload(outer), KEY)

    def test_context_mixing_rejected_at_audit(self):
        # Five rounds under one commitment then a sixth genuinely under a
        # different one: every record audits individually and the round
        # indices are consecutive, so seal refuses this. Hand-build an
        # otherwise-valid BoundSeriesEvidence (correct chain digest folded
        # over the mixed samples and a valid NPBS2 MAC) and confirm the
        # independent auditor rejects the context/digest mixing itself.
        _verifier, mixed = make_mixed_commitment_bounds(6, switch_at=5)
        first = mixed[0].evidence.round_index
        blobs = tuple(record.to_bytes() for record in mixed)
        decision = bound_decision(mixed, 100.0)
        chain_digest = _bound_series_chain_digest(
            SESSION, first, first + 5, blobs
        )
        record = BoundSeriesEvidence(
            version=1,
            session_id=SESSION,
            first_round_index=first,
            last_round_index=first + 5,
            samples=blobs,
            limit=100.0,
            min_samples=5,
            sample_count=decision.sample_count,
            upper_bound=decision.upper_bound,
            accepted=decision.accepted,
            chain_digest=chain_digest,
            mac=b"\x00" * 32,
        )
        from dataclasses import replace
        from nearproof import _bound_series_mac, _bound_series_payload
        record = replace(
            record,
            mac=_bound_series_mac(KEY, _bound_series_payload(record)),
        )
        with self.assertRaises(ValueError):
            audit_bound_series(record, KEY)

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_bound_series(self.evidence, KEY)
        audit_bound_series(self.data, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class ExistingBehaviourUnchangedTest(unittest.TestCase):
    def test_bound_evidence_bytes_unchanged(self):
        _verifier, records = make_bounds(2)
        # A single BoundEvidence still round-trips through audit_bound and
        # keeps its exact encoding.
        blob = records[0].to_bytes()
        self.assertEqual(BoundEvidence.from_bytes(blob), records[0])

    def test_assess_evidence_unaffected(self):
        # The existing AssessEvidence entry point and encoding still exist.
        self.assertTrue(hasattr(AssessEvidence, "from_bytes"))
        _verifier, records = make_bounds(6)
        decision = bound_decision(records, 100.0)
        self.assertEqual(decision.sample_count, 6)


if __name__ == "__main__":
    unittest.main()
