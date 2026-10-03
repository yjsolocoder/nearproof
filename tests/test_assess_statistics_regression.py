"""Regression tests linking the ranging statistics across entries.

One batch of measurements is followed from the immediate decision
(:func:`nearproof.assess` / :func:`nearproof.assess_confidence`) through
sealing (:func:`nearproof.seal_assess_evidence`) and independent review
(:func:`nearproof.audit_assess_evidence`). The tests only call public
entries, use repeatable data and a controllable clock, and never rely on
real network timing.

Every statistical expectation below was computed by hand from the documented
median/MAD and order-statistic rules (the arithmetic is spelled out in the
family comments); no product-internal statistics helper is used to derive an
expected value.
"""

import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    AssessEvidence,
    Measurement,
    NoiseDecision,
    Prover,
    RangeDecision,
    Verifier,
    assess,
    assess_confidence,
    audit_assess_evidence,
    seal_assess_evidence,
)

KEY = b"shared-secret-key"

# Documented outer-MAC domain prefix of the AssessEvidence encoding; used
# only to build test inputs that carry a *valid outer signature* but a wrong
# statistical conclusion.
ASSESS_EVIDENCE_PREFIX = b"NPAE1"

SPEED_MPS = 2.0  # distance == elapsed_seconds exactly, so distances are exact


# ---------------------------------------------------------------------------
# Repeatable fixtures
# ---------------------------------------------------------------------------


def make_measurement(round_index, distance, *, nonce=None):
    if nonce is None:
        nonce = bytes([round_index & 0xFF]) * 16
    return Measurement(
        round_index=round_index,
        nonce=nonce,
        response=b"r" * 32,
        elapsed_seconds=float(distance) / 100.0,
        distance_meters=float(distance),
    )


def measurements(distances):
    """Measurements with a distinct (round_index, nonce) identity per row."""
    return [
        make_measurement(index, distance)
        for index, distance in enumerate(distances, start=1)
    ]


class ScriptedClock:
    """Plays back fixed readings: two per round, start then end."""

    def __init__(self, readings):
        self._readings = list(readings)
        self._next = 0

    def __call__(self):
        value = self._readings[self._next]
        self._next += 1
        return value


def make_evidence_for_distances(distances, *, key=KEY, extra_readings=0):
    """Legitimately signed evidence with scripted, exact distances.

    With speed 2 m/s each round takes ``distance`` seconds; rounds are spaced
    one second apart so every ``end - start`` recomputation is exact. Returns
    ``(verifier, records)``; ``extra_readings`` extra clock readings are
    preloaded after the real rounds so callers can drive further rounds.
    """
    schedule = []
    cursor = 0.0
    for distance in distances:
        elapsed = float(distance)  # speed 2 -> distance = elapsed * 2 / 2
        schedule.extend((cursor, cursor + elapsed))
        cursor += elapsed + 1.0
    for _ in range(extra_readings):
        schedule.append(cursor)
        cursor += 1.0
    clock = ScriptedClock(schedule)
    verifier = Verifier(
        key, speed_mps=SPEED_MPS, clock=clock, replay_protection=True
    )
    prover = Prover(key)
    records = []
    for _ in distances:
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, records


def run_one_more_round(verifier):
    """The verifier still serves a normal challenge/response round."""
    prover = Prover(KEY)
    before = verifier.round_count
    challenge = verifier.new_challenge()
    started = verifier.clock()
    record = verifier.verify_evidence(
        challenge, prover.respond(challenge), started
    )
    return before, record


def resign_outer(data, changes=None):
    """Decode sealed bytes, change content indices and re-MAC the envelope.

    The outer signature stays valid under KEY; only the carried content moves.
    """
    outer = json.loads(data)
    for index, value in (changes or {}).items():
        outer[index] = value
    content = json.dumps(outer[:7], separators=(",", ":")).encode()
    outer[7] = hmac.new(
        KEY, ASSESS_EVIDENCE_PREFIX + content, hashlib.sha256
    ).digest().hex()
    return json.dumps(outer, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# Sample families, with expectations worked out independently
# ---------------------------------------------------------------------------

# Integer-valued families keep every median/MAD/endpoint arithmetic exact in
# binary floating point.

# Even total with one far outlier.
# [10..14, 1000]: median 12.5, MAD 1.5, interval [8, 17] keeps five, drops
# 1000. assess upper bound 14; confidence n=5, p=.95 order ranks 1 and 5.
G_EVEN_OUTLIER = [10, 11, 12, 13, 14, 1000]

# Odd total with one far outlier.
# [10..15, 1000]: median 13, MAD 2, interval [7, 19] keeps six, drops 1000.
# confidence n=6, p=.95 ranks 1 and 6.
G_ODD_OUTLIER = [10, 11, 12, 13, 14, 15, 1000]

# Repeated distances with six distinct round identities; no outlier.
# median 11, MAD 1, interval [8, 14] keeps all six.
G_TIES = [10, 10, 10, 12, 12, 12]

# Zero MAD (odd total): median 5, MAD 0 -> only the three exact 5s survive.
G_ZERO_MAD_ODD = [5, 5, 5, 9, 10]

# Zero MAD (even total): median 5, MAD 0 -> four exact 5s survive.
G_ZERO_MAD_EVEN = [5, 5, 5, 5, 9, 10]

# Zero distance, odd and even totals.
G_ZERO_ODD = [0, 0, 0, 0, 0]
G_ZERO_EVEN = [0, 0, 0, 0, 0, 0]


class IndependentFamilyExpectationsTest(unittest.TestCase):
    """Literal expectations for assess/assess_confidence per sample family."""

    def test_even_total_with_outlier(self):
        # median 12.5; deviations sorted .5,.5,1.5,1.5,2.5,987.5 ->
        # MAD = (1.5+1.5)/2 = 1.5; five inliers, upper bound 14.
        decision = assess(measurements(G_EVEN_OUTLIER), limit=14)
        self.assertEqual(decision, RangeDecision(6, 14.0, True))
        confident = assess_confidence(
            measurements(G_EVEN_OUTLIER), limit=14
        )
        self.assertEqual(
            confident,
            NoiseDecision(6, 5, 12.5, 1.5, 0.95, 10.0, 14.0, True),
        )

    def test_odd_total_with_outlier(self):
        # median 13; deviations sorted 0,1,1,2,2,3,987 -> MAD 2; six
        # inliers 10..15, interval [7,19] drops 1000.
        decision = assess(measurements(G_ODD_OUTLIER), limit=15)
        self.assertEqual(decision, RangeDecision(7, 15.0, True))
        confident = assess_confidence(measurements(G_ODD_OUTLIER), limit=15)
        self.assertEqual(
            confident,
            NoiseDecision(7, 6, 13.0, 2.0, 0.95, 10.0, 15.0, True),
        )

    def test_repeated_distances_distinct_round_identities(self):
        # Same distance values are legal as long as round identities differ;
        # all six rows count once each.
        samples = measurements(G_TIES)
        self.assertEqual(assess(samples, limit=12), RangeDecision(6, 12.0, True))
        self.assertEqual(
            assess_confidence(samples, limit=12),
            NoiseDecision(6, 6, 11.0, 1.0, 0.95, 10.0, 12.0, True),
        )

    def test_zero_mad_odd_and_even_totals(self):
        odd = assess(measurements(G_ZERO_MAD_ODD), limit=5, min_samples=3)
        self.assertEqual(odd, RangeDecision(5, 5.0, True))
        self.assertEqual(
            assess_confidence(
                measurements(G_ZERO_MAD_ODD), limit=5, min_samples=3
            ),
            NoiseDecision(5, 3, 5.0, 0.0, 0.95, 5.0, 5.0, True),
        )
        even = assess(measurements(G_ZERO_MAD_EVEN), limit=5, min_samples=4)
        self.assertEqual(even, RangeDecision(6, 5.0, True))
        self.assertEqual(
            assess_confidence(
                measurements(G_ZERO_MAD_EVEN), limit=5, min_samples=4
            ),
            NoiseDecision(6, 4, 5.0, 0.0, 0.95, 5.0, 5.0, True),
        )

    def test_zero_distance_odd_and_even_totals(self):
        for total, family in ((5, G_ZERO_ODD), (6, G_ZERO_EVEN)):
            samples = measurements(family)
            self.assertEqual(
                assess(samples, limit=0), RangeDecision(total, 0.0, True)
            )
            self.assertEqual(
                assess_confidence(samples, limit=0),
                NoiseDecision(total, total, 0.0, 0.0, 0.95, 0.0, 0.0, True),
            )

    def test_sample_count_includes_the_outlier(self):
        decision = assess(measurements(G_EVEN_OUTLIER), limit=14)
        confident = assess_confidence(measurements(G_EVEN_OUTLIER), limit=14)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(confident.sample_count, 6)
        self.assertEqual(confident.inlier_count, 5)


# ---------------------------------------------------------------------------
# Order, iterator and representation invariance on one legal batch
# ---------------------------------------------------------------------------


class InvarianceTest(unittest.TestCase):
    def setUp(self):
        self.distances = G_EVEN_OUTLIER
        self.verifier, self.records = make_evidence_for_distances(self.distances)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_permutation_iterator_and_bytes_agree_for_assess(self):
        expected = RangeDecision(6, 14.0, True)
        variants = [
            self.records,
            list(reversed(self.records)),
            iter(list(self.records)),
            (record for record in self.records),
            self.blobs,
            list(reversed(self.blobs)),
            iter(self.blobs),
            [
                self.records[0],
                self.blobs[1],
                self.records[2],
                self.blobs[3],
                self.records[4],
                self.blobs[5],
            ],
        ]
        for samples in variants:
            self.assertEqual(assess(samples, limit=14, key=KEY), expected)

    def test_permutation_iterator_and_bytes_agree_for_confidence(self):
        expected = NoiseDecision(6, 5, 12.5, 1.5, 0.95, 10.0, 14.0, True)
        variants = [
            self.records,
            list(reversed(self.records)),
            iter(list(self.records)),
            self.blobs,
            (blob for blob in self.blobs),
            [
                self.records[0],
                self.blobs[1],
                self.records[2],
                self.blobs[3],
                self.records[4],
                self.blobs[5],
            ],
        ]
        for samples in variants:
            self.assertEqual(
                assess_confidence(samples, limit=14, key=KEY), expected
            )

    def test_measurement_path_is_order_and_iterator_invariant(self):
        samples = measurements(self.distances)
        expected = assess(samples, limit=14)
        self.assertEqual(assess(list(reversed(samples)), limit=14), expected)
        self.assertEqual(assess(iter(samples), limit=14), expected)
        expected_conf = assess_confidence(samples, limit=14)
        self.assertEqual(
            assess_confidence(list(reversed(samples)), limit=14), expected_conf
        )
        self.assertEqual(
            assess_confidence(iter(samples), limit=14), expected_conf
        )

    def test_sealed_canonical_bytes_ignore_sample_order(self):
        sealed = seal_assess_evidence(self.records, 14, KEY)
        permutations = [
            seal_assess_evidence(list(reversed(self.records)), 14, KEY),
            seal_assess_evidence(self.blobs, 14, KEY),
            seal_assess_evidence(list(reversed(self.blobs)), 14, KEY),
            seal_assess_evidence(iter(self.blobs), 14, KEY),
            seal_assess_evidence(
                [
                    self.records[0],
                    self.blobs[1],
                    self.records[2],
                    self.blobs[3],
                    self.records[4],
                    self.blobs[5],
                ],
                14,
                KEY,
            ),
        ]
        for other in permutations:
            self.assertEqual(other, sealed)
            self.assertEqual(other.to_bytes(), sealed.to_bytes())

    def test_sealed_object_and_canonical_bytes_round_trip(self):
        sealed = seal_assess_evidence(self.records, 14, KEY)
        self.assertEqual(AssessEvidence.from_bytes(sealed.to_bytes()), sealed)
        self.assertEqual(
            audit_assess_evidence(sealed.to_bytes(), KEY),
            audit_assess_evidence(sealed, KEY),
        )

    def test_inputs_untouched_by_every_read_only_call(self):
        records_snapshot = list(self.records)
        blobs_snapshot = list(self.blobs)
        assess(self.records, 14, key=KEY)
        assess(iter(self.blobs), 14, key=KEY)
        assess_confidence(list(reversed(self.records)), 14, key=KEY)
        sealed = seal_assess_evidence(self.records, 14, KEY)
        seal_assess_evidence(self.blobs, 14, KEY)
        audit_assess_evidence(sealed, KEY)
        audit_assess_evidence(sealed.to_bytes(), KEY)
        self.assertEqual(self.records, records_snapshot)
        self.assertEqual(self.blobs, blobs_snapshot)


# ---------------------------------------------------------------------------
# Relationship between sample statistics and parameter changes
# ---------------------------------------------------------------------------


class ParameterMonotonicityTest(unittest.TestCase):
    def setUp(self):
        # Five inliers 10..14 plus the dropped 1000: coverage moves only the
        # order-statistic window over the unchanged inlier set.
        self.samples = measurements(G_EVEN_OUTLIER)

    def test_raising_coverage_widens_the_interval_without_moving_inliers(self):
        # n=5 inliers 10,11,12,13,14:
        # p=.05 -> alpha=.95 ranks 3,3 -> [12,12]
        # p=.50 -> ranks 2,4 -> [11,13]
        # p=.95 -> ranks 1,5 -> [10,14]
        narrow = assess_confidence(self.samples, 100.0, coverage=0.05)
        middle = assess_confidence(self.samples, 100.0, coverage=0.5)
        wide = assess_confidence(self.samples, 100.0, coverage=0.95)
        self.assertEqual(
            (narrow.lower_bound, narrow.upper_bound), (12.0, 12.0)
        )
        self.assertEqual(
            (middle.lower_bound, middle.upper_bound), (11.0, 13.0)
        )
        self.assertEqual((wide.lower_bound, wide.upper_bound), (10.0, 14.0))
        for decision in (narrow, middle, wide):
            self.assertEqual(decision.inlier_count, 5)
            self.assertEqual(decision.sample_count, 6)
        # Higher coverage must never shrink the interval.
        self.assertLessEqual(middle.lower_bound, narrow.lower_bound)
        self.assertGreaterEqual(middle.upper_bound, narrow.upper_bound)
        self.assertLessEqual(wide.lower_bound, middle.lower_bound)
        self.assertGreaterEqual(wide.upper_bound, middle.upper_bound)

    def test_raising_coverage_widens_six_inlier_interval(self):
        # n=6 inliers 10..15: ranks at .05 -> 3,4; .5 -> 2,5; .95 -> 1,6.
        samples = measurements(G_ODD_OUTLIER)
        narrow = assess_confidence(samples, 100.0, coverage=0.05)
        middle = assess_confidence(samples, 100.0, coverage=0.5)
        wide = assess_confidence(samples, 100.0, coverage=0.95)
        self.assertEqual(
            (narrow.lower_bound, narrow.upper_bound), (12.0, 13.0)
        )
        self.assertEqual(
            (middle.lower_bound, middle.upper_bound), (11.0, 14.0)
        )
        self.assertEqual((wide.lower_bound, wide.upper_bound), (10.0, 15.0))

    def test_raising_limit_never_turns_accept_into_reject(self):
        limits = (9, 13, 13.5, 14, 15, 100)
        assess_flags = [
            assess(self.samples, limit=limit).accepted for limit in limits
        ]
        confidence_flags = [
            assess_confidence(self.samples, limit=limit).accepted
            for limit in limits
        ]
        self.assertEqual(
            assess_flags,
            [False, False, False, True, True, True],
        )
        self.assertEqual(assess_flags, confidence_flags)
        for flags in (assess_flags, confidence_flags):
            self.assertEqual(flags, sorted(flags))  # never True -> False

    def test_limit_equal_to_upper_bound_accepts(self):
        boundary_assess = assess(self.samples, limit=14)
        boundary_conf = assess_confidence(self.samples, limit=14)
        self.assertIs(boundary_assess.accepted, True)
        self.assertIs(boundary_conf.accepted, True)
        self.assertEqual(boundary_assess.upper_bound, 14.0)
        self.assertEqual(boundary_conf.upper_bound, 14.0)
        just_below = assess(self.samples, limit=13.9)
        self.assertIs(just_below.accepted, False)

    def test_sealed_evidence_shares_limit_boundary_behaviour(self):
        _verifier, records = make_evidence_for_distances(G_EVEN_OUTLIER)
        rejected = seal_assess_evidence(records, 13, KEY)
        accepted = seal_assess_evidence(records, 14, KEY)
        self.assertIs(rejected.accepted, False)
        self.assertIs(accepted.accepted, True)
        self.assertIs(audit_assess_evidence(rejected, KEY).accepted, False)
        self.assertIs(audit_assess_evidence(accepted, KEY).accepted, True)


# ---------------------------------------------------------------------------
# Exact power-of-two scaling
# ---------------------------------------------------------------------------


class PowerOfTwoScalingTest(unittest.TestCase):
    def test_distances_and_limit_scaled_together_keep_conclusion(self):
        # Family 10..14 + 1000: median 12.5, MAD 1.5, interval [8,17].
        for exponent in (0, 1, 4, 40, 48):
            factor = 2.0 ** exponent
            scaled = [distance * factor for distance in G_EVEN_OUTLIER]
            samples = measurements(scaled)
            limit = 14.0 * factor
            decision = assess(samples, limit=limit)
            confident = assess_confidence(samples, limit=limit)
            self.assertEqual(decision.sample_count, 6, exponent)
            self.assertEqual(confident.inlier_count, 5, exponent)
            self.assertIs(decision.accepted, True, exponent)
            self.assertIs(confident.accepted, True, exponent)
            # Exact equality, not isclose: every operation is power-of-two.
            self.assertEqual(decision.upper_bound, 14.0 * factor, exponent)
            self.assertEqual(confident.center, 12.5 * factor, exponent)
            self.assertEqual(confident.mad, 1.5 * factor, exponent)
            self.assertEqual(confident.lower_bound, 10.0 * factor, exponent)
            self.assertEqual(confident.upper_bound, 14.0 * factor, exponent)
            for value in (
                decision.upper_bound,
                confident.center,
                confident.mad,
                confident.lower_bound,
                confident.upper_bound,
            ):
                self.assertTrue(math.isfinite(value), (exponent, value))

    def test_scaled_ties_family_scales_center_mad_and_endpoints(self):
        # [10,10,10,12,12,12]: center 11, MAD 1, endpoints 10 and 12.
        for exponent in (1, 4, 40):
            factor = 2.0 ** exponent
            samples = measurements([d * factor for d in G_TIES])
            confident = assess_confidence(samples, limit=12.0 * factor)
            self.assertEqual(confident.center, 11.0 * factor)
            self.assertEqual(confident.mad, 1.0 * factor)
            self.assertEqual(confident.lower_bound, 10.0 * factor)
            self.assertEqual(confident.upper_bound, 12.0 * factor)
            self.assertEqual(
                assess(samples, limit=12.0 * factor),
                RangeDecision(6, 12.0 * factor, True),
            )

    def test_scaling_carries_through_seal_and_audit(self):
        # Same family times four: elapsed values 20..28 and 2000 stay exact.
        scaled = [distance * 4 for distance in G_EVEN_OUTLIER]
        verifier, records = make_evidence_for_distances(scaled)
        expected = RangeDecision(6, 56.0, True)
        self.assertEqual(assess(records, 56, key=KEY), expected)
        sealed = seal_assess_evidence(records, 56, KEY)
        self.assertEqual(audit_assess_evidence(sealed, KEY), expected)
        confident = assess_confidence(records, 56, key=KEY)
        self.assertEqual(
            (confident.center, confident.mad, confident.lower_bound,
             confident.upper_bound),
            (50.0, 6.0, 40.0, 56.0),
        )


# ---------------------------------------------------------------------------
# The two upper bounds are not interchangeable
# ---------------------------------------------------------------------------


class EntryBoundDistinctionTest(unittest.TestCase):
    def setUp(self):
        # Five inliers 10..14; max-inlier upper bound is 14, but the 50%
        # coverage window ends at the fourth inlier, 13.
        self.samples = measurements(G_EVEN_OUTLIER)

    def test_max_inlier_bound_differs_from_coverage_bound(self):
        plain = assess(self.samples, limit=100.0)
        confident = assess_confidence(self.samples, limit=100.0, coverage=0.5)
        self.assertEqual(plain.upper_bound, 14.0)
        self.assertEqual(confident.upper_bound, 13.0)
        self.assertEqual(confident.lower_bound, 11.0)
        self.assertNotEqual(plain.upper_bound, confident.upper_bound)
        self.assertNotEqual(plain, confident)

    def test_entries_may_oppose_on_the_same_limit(self):
        # limit 13.5 lies between the coverage bound (13) and the max-inlier
        # bound (14): one entry accepts, the other rejects.
        plain = assess(self.samples, limit=13.5)
        confident = assess_confidence(self.samples, limit=13.5, coverage=0.5)
        self.assertIs(plain.accepted, False)
        self.assertIs(confident.accepted, True)

    def test_entries_agree_at_default_wide_coverage(self):
        # At p=.95 over five inliers the coverage window reaches the extreme
        # inlier, so the two bounds coincide there by construction even
        # though the entries stay distinct objects.
        plain = assess(self.samples, limit=14)
        confident = assess_confidence(self.samples, limit=14)
        self.assertEqual(plain.upper_bound, confident.upper_bound)
        self.assertIs(plain.accepted, confident.accepted)
        self.assertNotEqual(plain, confident)


# ---------------------------------------------------------------------------
# One legal batch through immediate decision, seal and audit
# ---------------------------------------------------------------------------


class CrossEntryConsistencyTest(unittest.TestCase):
    def _family(self, distances, limit):
        verifier, records = make_evidence_for_distances(distances)
        blobs = [record.to_bytes() for record in records]
        return verifier, records, blobs

    def test_accepted_conclusion_is_the_same_at_all_three_entries(self):
        verifier, records, blobs = self._family(G_EVEN_OUTLIER, 14)
        expected = RangeDecision(6, 14.0, True)
        immediate = assess(records, 14, key=KEY)
        sealed = seal_assess_evidence(records, 14, KEY)
        reviewed = audit_assess_evidence(sealed, KEY)
        reviewed_bytes = audit_assess_evidence(sealed.to_bytes(), KEY)
        self.assertEqual(immediate, expected)
        self.assertIs(sealed.accepted, True)
        self.assertEqual(reviewed, expected)
        self.assertEqual(reviewed_bytes, expected)
        # Bytes/mixed representations at each entry give the same decision.
        self.assertEqual(assess(blobs, 14, key=KEY), expected)
        self.assertEqual(
            seal_assess_evidence(blobs, 14, KEY).to_bytes(),
            sealed.to_bytes(),
        )

    def test_rejected_conclusion_seals_and_reviews_to_rejection(self):
        verifier, records, blobs = self._family(G_EVEN_OUTLIER, 9)
        expected = RangeDecision(6, 14.0, False)
        immediate = assess(records, 9, key=KEY)
        sealed = seal_assess_evidence(records, 9, KEY)
        reviewed = audit_assess_evidence(sealed, KEY)
        self.assertEqual(immediate, expected)
        self.assertIs(sealed.accepted, False)
        self.assertEqual(reviewed, expected)
        self.assertEqual(audit_assess_evidence(sealed.to_bytes(), KEY), expected)
        self.assertEqual(
            assess_confidence(records, 9, key=KEY).accepted, False
        )

    def test_ties_family_consistency(self):
        verifier, records, _blobs = self._family(G_TIES, 12)
        expected = RangeDecision(6, 12.0, True)
        sealed = seal_assess_evidence(records, 12, KEY)
        self.assertEqual(assess(records, 12, key=KEY), expected)
        self.assertEqual(audit_assess_evidence(sealed, KEY), expected)

    def test_zero_distance_family_consistency(self):
        verifier, records, _blobs = self._family(G_ZERO_EVEN, 0)
        expected = RangeDecision(6, 0.0, True)
        sealed = seal_assess_evidence(records, 0, KEY)
        self.assertEqual(assess(records, 0, key=KEY), expected)
        self.assertEqual(audit_assess_evidence(sealed, KEY), expected)


# ---------------------------------------------------------------------------
# Public rejection behaviour
# ---------------------------------------------------------------------------


class PublicRejectionTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_for_distances(
            G_EVEN_OUTLIER, extra_readings=2
        )
        self.blobs = [record.to_bytes() for record in self.records]
        self.outlier_index = next(
            i
            for i, record in enumerate(self.records)
            if record.distance == 1000.0
        )

    def test_broken_outlier_signature_rejected_before_statistics(self):
        # The 1000 m sample would be dropped as a statistical outlier;
        # corrupting its signature must still fail verification rather than
        # being silently discarded.
        bad = bytearray(self.blobs[self.outlier_index])
        bad[20] ^= 0xFF
        samples = self.blobs[: self.outlier_index] + [bytes(bad)]
        samples += self.blobs[self.outlier_index + 1 :]
        for operation in (
            lambda: assess(samples, 14, key=KEY),
            lambda: assess_confidence(samples, 14, key=KEY),
            lambda: seal_assess_evidence(samples, 14, KEY),
        ):
            with self.assertRaises(ValueError):
                operation()

    def test_broken_signature_rejected_in_resealed_record(self):
        sealed = seal_assess_evidence(self.records, 14, KEY)
        outer = json.loads(sealed.to_bytes())
        bad = bytearray(bytes.fromhex(outer[1][self.outlier_index]))
        bad[20] ^= 0xFF
        outer[1][self.outlier_index] = bytes(bad).hex()
        outer[1].sort()
        forged = resign_outer(
            json.dumps(outer, separators=(",", ":")).encode()
        )
        # Outer signature is valid; the carried sample is not.
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_duplicate_round_identity_rejected(self):
        repeated = [self.records[0]] * 5
        for operation in (
            lambda: assess(repeated, 14, key=KEY),
            lambda: assess_confidence(repeated, 14, key=KEY),
            lambda: seal_assess_evidence(repeated, 14, KEY),
        ):
            with self.assertRaises(ValueError):
                operation()

    def test_too_few_total_samples_rejected(self):
        for operation in (
            lambda: assess(self.records[:4], 14, key=KEY),
            lambda: assess_confidence(self.records[:4], 14, key=KEY),
            lambda: seal_assess_evidence(self.records[:4], 14, KEY),
        ):
            with self.assertRaises(ValueError):
                operation()

    def test_too_few_inliers_rejected(self):
        # [0, 0, 100, 100, 100]: median 100, MAD 0 -> three inliers only.
        verifier, records = make_evidence_for_distances([0, 0, 100, 100, 100])
        samples = measurements([0, 0, 100, 100, 100])
        with self.assertRaises(ValueError):
            assess(records, 1000.0, key=KEY, min_samples=4)
        with self.assertRaises(ValueError):
            assess_confidence(records, 1000.0, key=KEY, min_samples=4)
        with self.assertRaises(ValueError):
            seal_assess_evidence(records, 1000.0, KEY, min_samples=4)
        with self.assertRaises(ValueError):
            assess(samples, 1000.0, min_samples=4)

    def test_outer_signature_valid_but_wrong_conclusion_rejected(self):
        # Review must recompute the conclusion, not trust the carried fields.
        sealed = seal_assess_evidence(self.records, 14, KEY)
        data = sealed.to_bytes()
        cases = {
            "accepted flipped": resign_outer(data, {6: False}),
            "upper bound raised": resign_outer(data, {5: 15.0}),
            "sample count raised": resign_outer(data, {4: 7}),
            "limit lowered to flip conclusion": resign_outer(data, {2: 9.0}),
        }
        for label, forged in cases.items():
            with self.assertRaises(ValueError, msg=label):
                audit_assess_evidence(forged, KEY)

    def test_inputs_and_future_challenges_unchanged_after_calls(self):
        records_snapshot = [record.to_bytes() for record in self.records]
        blobs_snapshot = list(self.blobs)
        rounds_before = self.verifier.round_count

        bad = bytearray(self.blobs[self.outlier_index])
        bad[20] ^= 0xFF
        tampered = (
            self.blobs[: self.outlier_index]
            + [bytes(bad)]
            + self.blobs[self.outlier_index + 1 :]
        )

        def fail(fn):
            with self.assertRaises(ValueError):
                fn()

        fail(lambda: assess(tampered, 14, key=KEY))
        fail(lambda: assess_confidence(tampered, 14, key=KEY))
        fail(lambda: seal_assess_evidence(tampered, 14, KEY))
        fail(lambda: assess([self.records[0]] * 5, 14, key=KEY))
        fail(lambda: seal_assess_evidence(self.records[:4], 14, KEY))
        sealed = seal_assess_evidence(self.records, 14, KEY)
        fail(
            lambda: audit_assess_evidence(
                resign_outer(sealed.to_bytes(), {6: False}), KEY
            )
        )
        # Successful read-only calls as well.
        assess(self.records, 14, key=KEY)
        assess_confidence(self.blobs, 14, key=KEY)
        audit_assess_evidence(sealed, KEY)

        # Inputs are untouched...
        self.assertEqual(
            [record.to_bytes() for record in self.records], records_snapshot
        )
        self.assertEqual(self.blobs, blobs_snapshot)
        # ...no verifier rounds were consumed by assess/seal/audit...
        self.assertEqual(self.verifier.round_count, rounds_before)
        # ...and a subsequent challenge behaves exactly as a normal round.
        before, record = run_one_more_round(self.verifier)
        self.assertEqual(self.verifier.round_count, before + 1)
        self.assertEqual(
            audit_assess_evidence(
                seal_assess_evidence(
                    self.records + [record], 1000.0, KEY, min_samples=5
                ),
                KEY,
            ).sample_count,
            7,
        )


if __name__ == "__main__":
    unittest.main()
