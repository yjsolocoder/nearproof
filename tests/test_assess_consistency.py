"""Regression tests linking instant ranging decisions to sealed evidence.

These tests treat the public ``assess`` / ``assess_confidence`` /
``seal_assess_evidence`` / ``audit_assess_evidence`` entries as a black box:
the expected statistics below are hand-derived medians, MADs and coverage
ranks over named sample families (never calls into the package's statistical
helpers), and every round is produced through the normal
``Prover``/``Verifier`` flow under a controllable, deterministic clock.

The themes are:

* odd/even sample counts, repeated distances with distinct round identities,
  zero-bias families and families containing an outlier, each with
  independently computed expectations;
* order, iterator and Evidence/canonical-bytes representation invariance,
  including the sealed canonical bytes;
* monotonicity in coverage and limit (same inliers, boundary acceptance);
* exact invariance under positive power-of-two scaling of distances and
  limits, without overflow;
* the largest-inlier upper bound (``assess``) is not assumed to equal the
  coverage interval upper bound (``assess_confidence``);
* one and the same batch of single-round evidence yields the same
  ``RangeDecision`` through the instant decision, sealing and audit entries,
  for both accepted and rejected conclusions;
* tampering (even with a sample the robust rule would drop as an outlier),
  duplicate round identities, too few samples or inliers and records with a
  valid outer MAC but wrong statistics are all rejected;
* none of the read-only entries mutate their inputs or the verifier's later
  challenge behaviour.
"""

import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    AssessEvidence,
    Evidence,
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

KEY = b"regression-shared-secret-key"
# Documented domain separator for the assess-evidence MAC (see
# AssessEvidence's docstring); used only to re-sign deliberately forged
# records so the audit entry's recomputation can be tested.
ASSESS_DOMAIN = b"NPAE1"

# Named distance families. The expected statistics written in the tests are
# derived from these raw values by hand, not by the package internals:
#
#   A      [1, 2, 3, 4, 5]              odd count, no outlier
#   B      [1, 2, 3, 4, 5, 6]           even count, no outlier
#   C      [10, 10, 10, 12, 12, 12]     even count, repeated distances,
#                                       distinct round identities
#   Z      [0, 0, 0, 0, 0]              zero bias
#   Z9     [5, 5, 5, 5, 5, 9]           zero MAD over the inlier cluster
#   E      [8, 10, 10, 12, 12, 1000]    even total, odd inlier count (5),
#                                       one obvious outlier
#   Eodd   [10, 10, 12, 12, 1000]       odd total, four inliers, one outlier
#   F      [8, 9, 10, 11, 12, 1000]     five inliers whose coverage bracket
#                                       can sit strictly inside the assess
#                                       [min inlier, max inlier] span
FAMILY_A = [1.0, 2.0, 3.0, 4.0, 5.0]
FAMILY_B = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
FAMILY_C = [10.0, 10.0, 10.0, 12.0, 12.0, 12.0]
FAMILY_Z = [0.0, 0.0, 0.0, 0.0, 0.0]
FAMILY_Z9 = [5.0, 5.0, 5.0, 5.0, 5.0, 9.0]
FAMILY_E = [8.0, 10.0, 10.0, 12.0, 12.0, 1000.0]
FAMILY_EODD = [10.0, 10.0, 12.0, 12.0, 1000.0]
FAMILY_F = [8.0, 9.0, 10.0, 11.0, 12.0, 1000.0]


class ScriptedClock:
    """A deterministic controllable clock, reset to zero before each round.

    ``Verifier`` calls it once on issue and once on verification. Every round
    therefore starts at 0 and ends after an explicit advance of exactly the
    desired round-trip time, so no real network delay is involved.
    """

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def reset(self):
        self.now = 0.0

    def advance(self, seconds):
        self.now += seconds


def make_measurement(index, distance):
    return Measurement(
        round_index=index,
        nonce=bytes([index & 0xFF]) * 16,
        response=b"r" * 32,
        elapsed_seconds=float(distance) / 100.0,
        distance_meters=float(distance),
    )


def measurements(distances):
    return [
        make_measurement(index, distance)
        for index, distance in enumerate(distances, start=1)
    ]


def build_rounds(distances, *, speed=1.0, replay_protection=True):
    """Run one normal challenge/response round per distance under the clock.

    With ``speed == 1`` a distance ``d`` needs an RTT of ``2d`` seconds; the
    whole ``elapsed * speed / 2`` chain is then an exact power-of-two
    scaling, so evidence distances equal the requested values bit for bit.
    """
    prover = Prover(KEY)
    verifier = Verifier(
        KEY,
        clock=ScriptedClock(),
        speed_mps=speed,
        replay_protection=replay_protection,
    )
    records = []
    for distance in distances:
        verifier.clock.reset()
        challenge = verifier.new_challenge()
        started = verifier.clock()
        verifier.clock.advance(2.0 * float(distance) / speed)
        records.append(
            verifier.verify_evidence(
                challenge, prover.respond(challenge), started
            )
        )
    return verifier, prover, records


def resign_assess(record_bytes, changes):
    """Decode assess-evidence bytes, patch field indices and re-MAC them.

    Produces a record with a valid outer MAC carrying deliberately wrong
    statistics, so the audit entry can be shown to recompute the conclusion
    rather than trusting the sealed fields.
    """
    outer = json.loads(record_bytes)
    for index, value in changes.items():
        outer[index] = value
    content = json.dumps(outer[:7], separators=(",", ":")).encode()
    outer[7] = hmac.new(
        KEY, ASSESS_DOMAIN + content, hashlib.sha256
    ).digest().hex()
    return json.dumps(outer, separators=(",", ":")).encode()


class IndependentExpectationsTest(unittest.TestCase):
    """Hand-derived statistics for each family, via Measurement samples."""

    def assert_decision(self, decision, sample_count, upper_bound, accepted):
        self.assertIsInstance(decision, RangeDecision)
        self.assertEqual(
            decision,
            RangeDecision(sample_count, upper_bound, accepted),
        )

    def assert_noise(
        self, decision, sample_count, inlier_count, center, mad,
        coverage, lower_bound, upper_bound, accepted,
    ):
        self.assertIsInstance(decision, NoiseDecision)
        self.assertEqual(
            decision,
            NoiseDecision(
                sample_count, inlier_count, center, mad, coverage,
                lower_bound, upper_bound, accepted,
            ),
        )

    def test_odd_family_a(self):
        # Sorted 1..5: median 3, deviations 0,1,1,2,2 give MAD 1 and the
        # closed interval [0, 6] keeps all five. Coverage .95 brackets the
        # extremes; limit 5 equals the largest inlier.
        samples = measurements(FAMILY_A)
        self.assert_decision(assess(samples, 5.0), 5, 5.0, True)
        self.assert_noise(
            assess_confidence(samples, 5.0),
            5, 5, 3.0, 1.0, 0.95, 1.0, 5.0, True,
        )

    def test_even_family_b(self):
        # Sorted 1..6: median (3+4)/2 = 3.5, the six deviations sorted are
        # .5,.5,1.5,1.5,2.5,2.5 for MAD 1.5 and interval [-1, 8] keeps all.
        samples = measurements(FAMILY_B)
        self.assert_decision(assess(samples, 6.0), 6, 6.0, True)
        self.assert_noise(
            assess_confidence(samples, 6.0),
            6, 6, 3.5, 1.5, 0.95, 1.0, 6.0, True,
        )

    def test_repeated_distances_distinct_identities_family_c(self):
        # Three 10s and three 12s, each from its own round: median 11,
        # every deviation is exactly 1, so MAD 1 and interval [8, 14] keeps
        # all six despite the duplicate distances.
        _verifier, _prover, records = build_rounds(FAMILY_C)
        identities = {(record.round_index, record.nonce) for record in records}
        self.assertEqual(len(identities), 6)
        self.assertEqual(
            [record.distance for record in records], FAMILY_C
        )

        samples = measurements(FAMILY_C)
        self.assert_decision(assess(samples, 12.0), 6, 12.0, True)
        self.assert_noise(
            assess_confidence(samples, 12.0),
            6, 6, 11.0, 1.0, 0.95, 10.0, 12.0, True,
        )
        # The same conclusion through audited evidence.
        self.assertEqual(
            assess(records, 12.0, key=KEY), RangeDecision(6, 12.0, True)
        )

    def test_zero_bias_family_z(self):
        # All distances zero: median and MAD are zero, the exact-equality
        # inlier rule keeps every sample and a zero limit is an acceptance.
        samples = measurements(FAMILY_Z)
        self.assert_decision(assess(samples, 0), 5, 0.0, True)
        self.assert_noise(
            assess_confidence(samples, 0),
            5, 5, 0.0, 0.0, 0.95, 0.0, 0.0, True,
        )

    def test_zero_mad_cluster_with_neighbour_family_z9(self):
        # Median 5 with five 5s and one 9: MAD 0 makes the inlier rule exact
        # equality, so the 9 is an outlier even though the sample total is 6.
        samples = measurements(FAMILY_Z9)
        self.assert_decision(assess(samples, 5.0), 6, 5.0, True)
        self.assert_noise(
            assess_confidence(samples, 5.0),
            6, 5, 5.0, 0.0, 0.95, 5.0, 5.0, True,
        )

    def test_even_total_outlier_family_e(self):
        # Median (10+12)/2 = 11; deviations of the cluster are all 1 while
        # the 1000 sample deviates by 989, so MAD 1, interval [8, 14] keeps
        # exactly the five cluster members and drops 1000.
        samples = measurements(FAMILY_E)
        self.assert_decision(assess(samples, 12.0), 6, 12.0, True)
        self.assert_noise(
            assess_confidence(samples, 12.0),
            6, 5, 11.0, 1.0, 0.95, 8.0, 12.0, True,
        )
        # sample_count counts the outlier; inlier_count does not.
        decision = assess_confidence(samples, 12.0)
        self.assertEqual(decision.sample_count - decision.inlier_count, 1)

    def test_odd_total_outlier_family_eodd(self):
        # Five samples: median 12, deviations 0,0,2,2,988 give MAD 2 and the
        # interval [6, 18] keeps four samples, dropping 1000. min_samples=4
        # is met by inliers alone.
        samples = measurements(FAMILY_EODD)
        self.assert_decision(
            assess(samples, 12.0, min_samples=4), 5, 12.0, True
        )
        # p=.95 over four inliers: ranks ceil(.1)=1 and ceil(3.9)=4.
        self.assert_noise(
            assess_confidence(samples, 12.0, min_samples=4),
            5, 4, 12.0, 2.0, 0.95, 10.0, 12.0, True,
        )

    def test_outlier_family_f_hand_statistics(self):
        # Median over all six distances is (10+11)/2 = 10.5; the full
        # deviation set 0.5,0.5,1.5,1.5,2.5,989.5 has median MAD 1.5, so
        # interval [6, 15] keeps 8..12 and drops 1000.
        samples = measurements(FAMILY_F)
        self.assert_decision(assess(samples, 12.0), 6, 12.0, True)
        # p=.5: ranks ceil(1.25)=2 and ceil(3.75)=4 -> 9 and 11.
        self.assert_noise(
            assess_confidence(samples, 12.0, coverage=0.5),
            6, 5, 10.5, 1.5, 0.5, 9.0, 11.0, True,
        )
        # p=.8: ranks ceil(.5)=1 and ceil(4.5)=5 -> 8 and 12.
        self.assert_noise(
            assess_confidence(samples, 12.0, coverage=0.8),
            6, 5, 10.5, 1.5, 0.8, 8.0, 12.0, True,
        )


class OrderIteratorEncodingTest(unittest.TestCase):
    """The same legal batch gives the same answer however it is presented."""

    def setUp(self):
        self._verifier, _prover, self.records = build_rounds(FAMILY_E)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_assess_permutation_iterator_and_encoding_invariance(self):
        expected = RangeDecision(6, 12.0, True)
        orderings = (
            self.records,
            list(reversed(self.records)),
            [self.records[3], self.records[5], self.records[0],
             self.records[4], self.records[2], self.records[1]],
            self.blobs,
            list(reversed(self.blobs)),
            [Evidence.from_bytes(blob) for blob in self.blobs],
            [self.records[0], self.blobs[1], self.records[2],
             self.blobs[3], self.records[4], self.blobs[5]],
        )
        for presented in orderings:
            self.assertEqual(assess(presented, 12.0, key=KEY), expected)
        # One-shot iterators and generators are consumed exactly once.
        self.assertEqual(
            assess(iter(self.records), 12.0, key=KEY), expected
        )
        self.assertEqual(
            assess(iter(self.blobs), 12.0, key=KEY), expected
        )
        self.assertEqual(
            assess((item for item in reversed(self.records)), 12.0, key=KEY),
            expected,
        )

    def test_confidence_permutation_iterator_and_encoding_invariance(self):
        expected = assess_confidence(self.records, 12.0, key=KEY)
        self.assertEqual(
            expected,
            NoiseDecision(6, 5, 11.0, 1.0, 0.95, 8.0, 12.0, True),
        )
        presentations = (
            list(reversed(self.records)),
            self.blobs,
            list(reversed(self.blobs)),
            [self.records[0], self.blobs[1], self.records[2],
             self.blobs[3], self.records[4], self.blobs[5]],
            [Evidence.from_bytes(blob) for blob in self.blobs],
        )
        for presented in presentations:
            self.assertEqual(
                assess_confidence(presented, 12.0, key=KEY), expected
            )
        self.assertEqual(
            assess_confidence(iter(self.records), 12.0, key=KEY), expected
        )
        self.assertEqual(
            assess_confidence(
                (item for item in self.records), 12.0, key=KEY
            ),
            expected,
        )

    def test_sealed_bytes_invariant_under_order_iterator_and_encoding(self):
        canonical = seal_assess_evidence(self.records, 12.0, KEY).to_bytes()
        presentations = (
            list(reversed(self.records)),
            [self.records[4], self.records[0], self.records[5],
             self.records[1], self.records[3], self.records[2]],
            self.blobs,
            list(reversed(self.blobs)),
            [self.records[0], self.blobs[1], self.records[2],
             self.blobs[3], self.records[4], self.blobs[5]],
        )
        for presented in presentations:
            sealed = seal_assess_evidence(presented, 12.0, KEY)
            self.assertEqual(sealed.to_bytes(), canonical)
        self.assertEqual(
            seal_assess_evidence(iter(self.records), 12.0, KEY).to_bytes(),
            canonical,
        )
        # Evidence object <-> canonical bytes conversion of the artifact
        # itself leaves the audited decision unchanged.
        sealed = AssessEvidence.from_bytes(canonical)
        self.assertEqual(sealed.to_bytes(), canonical)
        self.assertEqual(
            audit_assess_evidence(sealed, KEY),
            audit_assess_evidence(canonical, KEY),
        )

    def test_inputs_are_not_modified(self):
        records_snapshot = list(self.records)
        blobs_snapshot = list(self.blobs)
        assess(self.records, 12.0, key=KEY)
        assess(iter(self.blobs), 12.0, key=KEY)
        assess_confidence(list(reversed(self.records)), 12.0, key=KEY)
        sealed = seal_assess_evidence(self.blobs, 12.0, KEY)
        audit_assess_evidence(sealed.to_bytes(), KEY)
        self.assertEqual(self.records, records_snapshot)
        self.assertEqual(self.blobs, blobs_snapshot)
        self.assertEqual(
            [record.to_bytes() for record in self.records], blobs_snapshot
        )


class ParameterMonotonicityTest(unittest.TestCase):
    """Relations between sample changes and parameter changes."""

    def _ladder(self, distances, coverages, *, min_samples=5):
        samples = measurements(distances)
        decisions = [
            assess_confidence(samples, 10000.0, coverage=coverage,
                              min_samples=min_samples)
            for coverage in coverages
        ]
        return decisions

    def assert_interval_does_not_shrink(self, lower, higher):
        # Same inlier set; widening coverage only moves ranks outward.
        self.assertEqual(lower.inlier_count, higher.inlier_count)
        self.assertLessEqual(higher.lower_bound, lower.lower_bound)
        self.assertGreaterEqual(higher.upper_bound, lower.upper_bound)

    def test_raising_coverage_never_shrinks_the_interval(self):
        ladder = [0.01, 0.5, 0.8, 0.95]
        for distances, min_samples in (
            (FAMILY_E, 5),
            (FAMILY_F, 5),
            (FAMILY_B, 5),
            (FAMILY_EODD, 4),
        ):
            decisions = self._ladder(
                distances, ladder, min_samples=min_samples
            )
            for lower_level, higher_level in zip(decisions, decisions[1:]):
                self.assert_interval_does_not_shrink(
                    lower_level, higher_level
                )

    def test_raising_coverage_can_leave_interval_unchanged_with_ties(self):
        # Family C's six inliers are three 10s and three 12s, so every
        # coverage level brackets exactly [10, 12]: "does not shrink"
        # includes staying identical.
        decisions = self._ladder(FAMILY_C, [0.01, 0.5, 0.8, 0.95])
        for decision in decisions:
            self.assertEqual(
                (decision.inlier_count, decision.lower_bound,
                 decision.upper_bound),
                (6, 10.0, 12.0),
            )

    def test_raising_limit_never_turns_acceptance_into_rejection(self):
        # Family E: largest inlier is 12, so 10 and 11.9 reject and 12 and
        # every larger limit accept.
        samples = measurements(FAMILY_E)
        flags = [
            (limit, assess(samples, limit).accepted)
            for limit in (10.0, 11.9, 12.0, 13.0, 1000.0)
        ]
        self.assertEqual([flag for _limit, flag in flags],
                         [False, False, True, True, True])
        accepted_once = False
        for _limit, accepted in flags:
            if accepted:
                accepted_once = True
            if accepted_once:
                self.assertTrue(accepted)
        # Explicit cross-entry implication for the coverage upper bound too:
        # family F at coverage .5 has interval upper bound 11.
        confident = [
            (limit, assess_confidence(
                measurements(FAMILY_F), limit, coverage=0.5).accepted)
            for limit in (10.9, 11.0, 12.0)
        ]
        self.assertEqual([flag for _limit, flag in confident],
                         [False, True, True])

    def test_limit_equal_to_upper_bound_is_accepted(self):
        # assess: exact equality is acceptance (closed comparison).
        decision = assess(measurements(FAMILY_E), 12.0)
        self.assertEqual(decision.upper_bound, 12.0)
        self.assertTrue(decision.accepted)
        # confidence: equality against the coverage interval upper bound.
        bracketed = assess_confidence(
            measurements(FAMILY_F), 11.0, coverage=0.5
        )
        self.assertEqual(bracketed.upper_bound, 11.0)
        self.assertTrue(bracketed.accepted)
        just_below = assess_confidence(
            measurements(FAMILY_F), 10.9, coverage=0.5
        )
        self.assertFalse(just_below.accepted)

    def test_inlier_set_independent_of_coverage(self):
        # Coverage only chooses ranks among the same median/MAD inliers.
        samples = measurements(FAMILY_E)
        counts = {
            assess_confidence(samples, 12.0, coverage=coverage).inlier_count
            for coverage in (0.01, 0.25, 0.5, 0.8, 0.95, 0.99)
        }
        self.assertEqual(counts, {5})


class UpperBoundDistinctionTest(unittest.TestCase):
    """The two entry points' upper bounds must not be conflated."""

    def test_coverage_interval_upper_below_largest_inlier(self):
        # assess reports the largest inlier distance (12); at coverage .5
        # the interval upper bound is the 4th of five inliers (11).
        decision = assess(measurements(FAMILY_F), 12.0)
        confident = assess_confidence(
            measurements(FAMILY_F), 12.0, coverage=0.5
        )
        self.assertEqual(decision.upper_bound, 12.0)
        self.assertEqual(confident.upper_bound, 11.0)
        self.assertLess(confident.upper_bound, decision.upper_bound)
        # Different result types never compare equal either.
        self.assertNotIsInstance(confident, RangeDecision)
        self.assertNotEqual(confident, decision)

    def test_bounds_do_coincide_at_high_coverage(self):
        # With five inliers at .95 the coverage rank reaches the largest
        # inlier, so the bounds coincide here — but only because of the
        # ranks, not because the entries are interchangeable.
        decision = assess(measurements(FAMILY_E), 12.0)
        confident = assess_confidence(measurements(FAMILY_E), 12.0)
        self.assertEqual(confident.upper_bound, decision.upper_bound)
        self.assertEqual(confident.lower_bound, 8.0)
        self.assertEqual(confident.accepted, decision.accepted)
        self.assertEqual(confident.sample_count, decision.sample_count)
        self.assertNotEqual(confident, decision)


class PowerOfTwoScalingTest(unittest.TestCase):
    """Distances and limits scaled by 2**k keep counts and conclusions;
    center, MAD and interval endpoints scale exactly without overflow."""

    SCALES = (0, 1, 2, 4, 8, 16, 24, 32)

    def test_confidence_statistics_scale_exactly(self):
        base = measurements(FAMILY_E)
        baseline = assess_confidence(base, 12.0)
        self.assertEqual(
            (baseline.sample_count, baseline.inlier_count), (6, 5)
        )
        for k in self.SCALES:
            factor = 2.0 ** k
            samples = measurements(
                [distance * factor for distance in FAMILY_E]
            )
            # Acceptance at the scaled accepted limit ...
            accepted = assess_confidence(
                samples, 12.0 * factor
            )
            # ... and rejection at a limit below the scaled upper bound.
            rejected = assess_confidence(
                samples, 10.0 * factor
            )
            for decision in (accepted, rejected):
                self.assertEqual(
                    (decision.sample_count, decision.inlier_count), (6, 5)
                )
                self.assertEqual(decision.center, 11.0 * factor)
                self.assertEqual(decision.mad, 1.0 * factor)
                self.assertEqual(decision.lower_bound, 8.0 * factor)
                self.assertEqual(decision.upper_bound, 12.0 * factor)
                for value in (
                    decision.center, decision.mad,
                    decision.lower_bound, decision.upper_bound,
                ):
                    self.assertTrue(value == value)  # not NaN
                    self.assertLess(abs(value), float("inf"))
            self.assertTrue(accepted.accepted)
            self.assertFalse(rejected.accepted)

    def test_assess_and_evidence_chain_scale_exactly(self):
        for k in self.SCALES:
            factor = 2.0 ** k
            scaled_distances = [
                distance * factor for distance in FAMILY_E
            ]
            # Speed 1 makes the verifier's elapsed*speed/2 chain an exact
            # power-of-two scaling of the requested distances.
            _verifier, _prover, records = build_rounds(
                scaled_distances, speed=1.0
            )
            self.assertEqual(
                [record.distance for record in records], scaled_distances
            )
            instant = assess(records, 12.0 * factor, key=KEY)
            sealed = seal_assess_evidence(records, 12.0 * factor, KEY)
            audited = audit_assess_evidence(sealed, KEY)
            self.assertEqual(
                instant, RangeDecision(6, 12.0 * factor, True)
            )
            self.assertEqual(audited, instant)
            self.assertIs(sealed.accepted, True)
            # The rejection conclusion survives scaling and sealing too.
            rejected_now = assess(records, 10.0 * factor, key=KEY)
            rejected_sealed = seal_assess_evidence(
                records, 10.0 * factor, KEY
            )
            self.assertFalse(rejected_now.accepted)
            self.assertEqual(
                audit_assess_evidence(rejected_sealed, KEY), rejected_now
            )
            self.assertEqual(rejected_now.upper_bound, 12.0 * factor)

    def test_scaling_invariance_at_largest_chosen_scale(self):
        # The largest factor still leaves every arithmetic result finite
        # and exactly representable; this guards the chosen magnitudes.
        factor = 2.0 ** self.SCALES[-1]
        decision = assess_confidence(
            measurements([d * factor for d in FAMILY_E]), 12.0 * factor
        )
        self.assertEqual(decision.center, 11.0 * factor)
        self.assertEqual(decision.upper_bound, 12.0 * factor)
        self.assertTrue(decision.accepted)


class AssessEvidenceParityTest(unittest.TestCase):
    """One evidence batch through all three entries gives one RangeDecision,
    for both conclusions."""

    def setUp(self):
        self.verifier, _prover, self.records = build_rounds(FAMILY_E)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_accepted_conclusion_parity(self):
        expected = RangeDecision(6, 12.0, True)
        instant_objects = assess(self.records, 12.0, key=KEY)
        instant_bytes = assess(self.blobs, 12.0, key=KEY)
        sealed = seal_assess_evidence(self.records, 12.0, KEY)
        sealed_from_bytes = seal_assess_evidence(self.blobs, 12.0, KEY)
        self.assertEqual(sealed, sealed_from_bytes)
        audited_object = audit_assess_evidence(sealed, KEY)
        audited_bytes = audit_assess_evidence(sealed.to_bytes(), KEY)
        for decision in (
            instant_objects, instant_bytes, audited_object, audited_bytes,
        ):
            self.assertEqual(decision, expected)
        self.assertIs(sealed.accepted, True)

    def test_rejected_conclusion_parity(self):
        expected = RangeDecision(6, 12.0, False)
        instant_objects = assess(self.records, 10.0, key=KEY)
        instant_bytes = assess(self.blobs, 10.0, key=KEY)
        sealed = seal_assess_evidence(self.records, 10.0, KEY)
        audited_object = audit_assess_evidence(sealed, KEY)
        audited_bytes = audit_assess_evidence(sealed.to_bytes(), KEY)
        for decision in (
            instant_objects, instant_bytes, audited_object, audited_bytes,
        ):
            self.assertEqual(decision, expected)
        self.assertIs(sealed.accepted, False)

    def test_resealing_same_batch_is_byte_stable(self):
        first = seal_assess_evidence(self.records, 12.0, KEY).to_bytes()
        second = seal_assess_evidence(
            list(reversed(self.blobs)), 12.0, KEY
        ).to_bytes()
        self.assertEqual(first, second)


class ForgedEvidenceTest(unittest.TestCase):
    """Signatures and statistics are independently enforced."""

    def setUp(self):
        self.verifier, _prover, self.records = build_rounds(FAMILY_E)
        self.blobs = [record.to_bytes() for record in self.records]
        self.sealed = seal_assess_evidence(self.records, 12.0, KEY)
        self.data = self.sealed.to_bytes()
        # The 1000 m sample is precisely the one the robust rule drops;
        # locate it solely through public attributes.
        self.outlier_index = next(
            index
            for index, record in enumerate(self.records)
            if record.distance == 1000.0
        )

    def test_breaking_outlier_sample_signature_rejected(self):
        outlier = self.records[self.outlier_index]
        # Flip the final MAC byte to a provably different value (nonces are
        # random per run, so the actual last byte is not assumed).
        broken = dataclasses.replace(
            outlier,
            mac=outlier.mac[:-1]
            + (b"\x00" if outlier.mac[-1] else b"\x01"),
        )
        batch = [
            broken if index == self.outlier_index else record
            for index, record in enumerate(self.records)
        ]
        with self.assertRaises(ValueError):
            assess(batch, 12.0, key=KEY)
        with self.assertRaises(ValueError):
            assess_confidence(batch, 12.0, key=KEY)
        with self.assertRaises(ValueError):
            seal_assess_evidence(batch, 12.0, KEY)
        # As raw canonical bytes through the instant entry as well.
        blob_batch = [
            broken.to_bytes() if index == self.outlier_index else blob
            for index, blob in enumerate(self.blobs)
        ]
        with self.assertRaises(ValueError):
            assess(blob_batch, 12.0, key=KEY)

    def test_duplicate_round_identity_rejected(self):
        for entry in (
            lambda: assess([self.records[0]] * 5, 12.0, key=KEY),
            lambda: assess_confidence(
                [self.records[0]] * 5, 12.0, key=KEY
            ),
            lambda: seal_assess_evidence(
                [self.records[0]] * 5, 12.0, KEY
            ),
        ):
            with self.assertRaises(ValueError):
                entry()

    def test_too_few_total_samples_rejected(self):
        for entry in (
            lambda: assess(self.records[:4], 12.0, key=KEY),
            lambda: assess_confidence(self.records[:4], 12.0, key=KEY),
            lambda: seal_assess_evidence(self.records[:4], 12.0, KEY),
        ):
            with self.assertRaises(ValueError):
                entry()

    def test_too_few_inliers_rejected(self):
        # Six samples but only five inliers (1000 dropped); demanding six
        # inliers must fail at every entry.
        for entry in (
            lambda: assess(self.records, 12.0, key=KEY, min_samples=6),
            lambda: assess_confidence(
                self.records, 12.0, key=KEY, min_samples=6
            ),
            lambda: seal_assess_evidence(
                self.records, 12.0, KEY, min_samples=6
            ),
        ):
            with self.assertRaises(ValueError):
                entry()

    def test_audit_recomputes_conclusion_with_valid_outer_mac(self):
        # Every artifact below passes the outer MAC check but carries a
        # statistic the audit recomputation must disagree with.
        sealed_rejected = seal_assess_evidence(self.records, 10.0, KEY)
        forged_cases = {
            "accepted flipped on accepted record":
                resign_assess(self.data, {6: False}),
            "accepted flipped on rejected record":
                resign_assess(sealed_rejected.to_bytes(), {6: True}),
            "upper bound inflated":
                resign_assess(self.data, {5: 13.0}),
            "sample count inflated":
                resign_assess(self.data, {4: 7}),
            "limit lowered below the bound":
                resign_assess(self.data, {2: 10.0}),
            "min samples raised past the inliers":
                resign_assess(self.data, {3: 6}),
        }
        for label, forged in forged_cases.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    audit_assess_evidence(forged, KEY)

    def test_audit_rejects_tampered_sample_with_valid_outer_mac(self):
        outer = json.loads(self.data)
        outlier_hex = next(
            sample_hex
            for sample_hex in outer[1]
            if Evidence.from_bytes(bytes.fromhex(sample_hex)).distance
            == 1000.0
        )
        broken_hex = _with_broken_mac(
            Evidence.from_bytes(bytes.fromhex(outlier_hex))
        ).to_bytes().hex()
        outer[1] = sorted(
            broken_hex if sample_hex == outlier_hex else sample_hex
            for sample_hex in outer[1]
        )
        forged = resign_assess(
            json.dumps(outer, separators=(",", ":")).encode(), {}
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence(forged, KEY)

    def test_audit_rejects_restructured_samples_with_valid_outer_mac(self):
        # Dropping a sample and duplicating a carried sample both keep the
        # outer MAC valid over the patched content and must be caught.
        dropped = json.loads(self.data)
        dropped[1] = dropped[1][:4]
        with self.assertRaises(ValueError):
            audit_assess_evidence(
                resign_assess(
                    json.dumps(dropped, separators=(",", ":")).encode(), {}
                ),
                KEY,
            )
        duplicated = json.loads(self.data)
        duplicated[1][1] = duplicated[1][0]
        with self.assertRaises(ValueError):
            audit_assess_evidence(
                resign_assess(
                    json.dumps(
                        duplicated, separators=(",", ":")
                    ).encode(),
                    {},
                ),
                KEY,
            )


def _with_broken_mac(record):
    """Return an Evidence copy whose final MAC byte is flipped."""
    replacement = b"\x00" if record.mac[-1] else b"\x01"
    return dataclasses.replace(record, mac=record.mac[:-1] + replacement)


class NoSideEffectsTest(unittest.TestCase):
    """Read-only assess entries leave inputs and verifier behaviour alone."""

    def test_verifier_challenges_continue_normally(self):
        verifier, prover, records = build_rounds(FAMILY_E)
        # Issue a seventh challenge and leave it pending across all the
        # read-only assess calls.
        verifier.clock.reset()
        pending = verifier.new_challenge()
        pending_started = verifier.clock()

        assess(records, 12.0, key=KEY)
        assess(iter(records), 10.0, key=KEY)
        assess_confidence(records, 12.0, key=KEY)
        sealed = seal_assess_evidence(records, 12.0, KEY)
        audit_assess_evidence(sealed, KEY)
        audit_assess_evidence(sealed.to_bytes(), KEY)

        # The pending challenge was not consumed: it still verifies once.
        verifier.clock.reset()
        verifier.clock.advance(2.0 * 7.0)
        seventh = verifier.verify_evidence(
            pending, prover.respond(pending), pending_started
        )
        self.assertEqual(seventh.round_index, 7)
        self.assertEqual(seventh.distance, 7.0)

        # And issuance continues with the next round index.
        verifier.clock.reset()
        eighth_challenge = verifier.new_challenge()
        started = verifier.clock()
        verifier.clock.advance(2.0 * 8.0)
        eighth = verifier.verify_evidence(
            eighth_challenge, prover.respond(eighth_challenge), started
        )
        self.assertEqual(eighth.round_index, 8)
        self.assertEqual(verifier.round_count, 8)

    def test_round_counter_unchanged_by_read_only_calls(self):
        verifier, _prover, records = build_rounds(FAMILY_E)
        rounds_before = verifier.round_count
        assess(records, 12.0, key=KEY)
        assess_confidence(records, 12.0, key=KEY)
        sealed = seal_assess_evidence(records, 12.0, KEY)
        audit_assess_evidence(sealed, KEY)
        audit_assess_evidence(sealed.to_bytes(), KEY)
        self.assertEqual(verifier.round_count, rounds_before)
        # A verifier that never sees an assess call behaves identically:
        # the next issued round index is 7 either way.
        plain, _prover, _records = build_rounds(FAMILY_E)
        self.assertEqual(plain.round_count, rounds_before)
        self.assertEqual(plain.new_challenge().round_index, 7)


if __name__ == "__main__":
    unittest.main()
