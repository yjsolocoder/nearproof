import unittest

from nearproof import (
    Prover,
    RangeDecision,
    Verifier,
    audit_bound_series,
    audit_bound_series_policy,
    context_digest,
    revoke_bound,
    revoke_context,
    seal_bound_series,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"other-secret-key!"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)
OTHER_CONTEXT = b"d" * 32
SESSION = b"s" * 32

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


def make_records(trips, *, key=KEY, context=CONTEXT, opening=OPENING,
                 digest=DIGEST):
    """One bound round per trip length, all under one commitment."""
    prover = Prover(key)
    clock = SteppedClock()
    verifier = Verifier(key, clock=clock, replay_protection=True)
    records = []
    for trip in trips:
        challenge = verifier.new_challenge(context=context, digest=digest)
        started = clock.now
        response = prover.reveal(challenge, context, opening)
        clock.now += trip
        records.append(
            verifier.verify_bound(challenge, response, started, opening=opening)
        )
    return records


def make_series(trips, limit=100.0, min_samples=5, key=KEY):
    records = make_records(trips)
    evidence = seal_bound_series(
        records,
        SESSION,
        records[0].evidence.round_index,
        len(records),
        limit,
        min_samples,
        key,
    )
    return records, evidence


def ends_of(records):
    return [record.evidence.end for record in records]


class AuditBoundSeriesPolicyBaselineTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series([DEFAULT_STEP] * 6)
        self.ends = ends_of(self.records)
        self.now = max(self.ends)

    def test_no_policy_ignores_now(self):
        for now in (None, 0.0, 1e9, "junk", object()):
            with self.subTest(now=now):
                decision = audit_bound_series_policy(self.evidence, KEY, now=now)
                self.assertIsInstance(decision, RangeDecision)

    def test_no_policy_matches_audit_bound_series(self):
        expected = audit_bound_series(self.evidence, KEY)
        self.assertEqual(audit_bound_series_policy(self.evidence, KEY), expected)

    def test_accepts_canonical_bytes(self):
        decision = audit_bound_series_policy(
            self.evidence.to_bytes(), KEY, now=self.now, max_age=10.0
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_returns_recorded_decision(self):
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, max_age=10.0
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))
        self.assertTrue(decision.accepted)

    def test_rejected_statistics_still_return_decision(self):
        # A 1 m limit rejects the ~15 m fixtures, but the decision is a
        # recorded conclusion, not an audit failure.
        records, evidence = make_series([DEFAULT_STEP] * 6, limit=1.0)
        now = max(ends_of(records))
        decision = audit_bound_series_policy(
            evidence, KEY, now=now, max_age=10.0, revocations=[]
        )
        self.assertIsInstance(decision, RangeDecision)
        self.assertFalse(decision.accepted)

    def test_baseline_type_error_precedes_policy_errors(self):
        with self.assertRaises(TypeError):
            audit_bound_series_policy(123, KEY, max_age="junk")
        with self.assertRaises(TypeError):
            audit_bound_series_policy(self.evidence, "not-bytes", max_age=1.0)

    def test_baseline_value_error_precedes_policy_errors(self):
        # The outer-MAC failure of the baseline review surfaces before the
        # missing-`now` policy error.
        with self.assertRaisesRegex(ValueError, "mac"):
            audit_bound_series_policy(self.evidence, OTHER_KEY, max_age=1.0)


class AuditBoundSeriesPolicyParameterTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series([DEFAULT_STEP] * 6)
        self.ends = ends_of(self.records)
        self.now = max(self.ends)

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(self.evidence, KEY, max_age=10.0)

    def test_now_required_when_revocations_set(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(self.evidence, KEY, revocations=[])

    def test_now_must_be_finite_non_bool_number(self):
        for bad in (True, False, "1.0", None, float("inf"), float("-inf"),
                    float("nan")):
            with self.subTest(now=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=bad, max_age=10.0
                    )

    def test_max_age_must_be_finite_non_negative_non_bool_number(self):
        for bad in (True, False, "1.0", -1.0, -1, float("inf"),
                    float("-inf"), float("nan")):
            with self.subTest(max_age=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, max_age=bad
                    )

    def test_int_now_and_max_age_accepted(self):
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=10, max_age=10
        )
        self.assertIsInstance(decision, RangeDecision)


class AuditBoundSeriesPolicyFreshnessTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series([DEFAULT_STEP] * 6)
        self.ends = ends_of(self.records)
        self.now = max(self.ends)

    def test_all_rounds_within_age_passes(self):
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, max_age=self.now - min(self.ends)
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_boundary_ages_are_valid(self):
        # now == newest end gives age 0 for the last round; max_age exactly
        # the oldest age keeps the oldest round valid too.
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, max_age=self.now - min(self.ends)
        )
        self.assertIsInstance(decision, RangeDecision)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=self.now - min(self.ends) - 1e-9,
            )

    def test_oldest_round_over_age_rejects(self):
        # Only the oldest round is over age; checking the last round alone
        # would pass, so the whole call must fail.
        max_age = (self.now - min(self.ends)) / 2
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, max_age=max_age
            )

    def test_future_round_rejects(self):
        # now equals the oldest end: every later round is future-dated.
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=min(self.ends), max_age=10.0
            )

    def test_zero_max_age_accepts_only_instant_series(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, max_age=0.0
            )

    def test_outlier_round_is_checked(self):
        # The first round is a statistical outlier (a ~1 s RTT) excluded by
        # the robust decision, but freshness still covers it.
        records, evidence = make_series([1.0] + [DEFAULT_STEP] * 5)
        ends = ends_of(records)
        now = max(ends)
        # Every inlier round is exactly within age; only the older outlier
        # is over age, so the whole call must fail.
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                evidence, KEY, now=now, max_age=now - ends[1]
            )
        # And with the outlier covered the same series passes.
        decision = audit_bound_series_policy(
            evidence, KEY, now=now, max_age=now - min(ends)
        )
        self.assertIsInstance(decision, RangeDecision)


class AuditBoundSeriesPolicyRevocationShapeTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series([DEFAULT_STEP] * 6)
        self.ends = ends_of(self.records)
        self.now = max(self.ends)
        self.revocation = revoke_bound(self.records[0], self.ends[0], KEY)

    def test_empty_iterables_are_valid(self):
        for empty in ([], (), iter([])):
            with self.subTest(empty=empty):
                decision = audit_bound_series_policy(
                    self.evidence, KEY, now=self.now, revocations=empty
                )
                self.assertIsInstance(decision, RangeDecision)

    def test_one_shot_iterable_accepted(self):
        foreign_records = make_records([DEFAULT_STEP])
        foreign = revoke_bound(
            foreign_records[0], foreign_records[0].evidence.end, KEY
        )
        decision = audit_bound_series_policy(
            self.evidence,
            KEY,
            now=self.now,
            revocations=(entry for entry in [foreign]),
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_single_record_not_accepted(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=self.revocation
            )
        context_revocation = revoke_context(CONTEXT, self.now, KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=context_revocation
            )

    def test_bare_bytes_not_accepted(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=self.revocation.to_bytes(),
            )
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=b""
            )

    def test_non_iterable_not_accepted(self):
        for bad in (42, 1.5, object()):
            with self.subTest(revocations=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=bad
                    )

    def test_illegal_elements_rejected(self):
        for bad in (None, 42, "junk", object(), b"junk", b"{}"):
            with self.subTest(entry=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=[bad]
                    )

    def test_mixed_objects_and_bytes_accepted(self):
        foreign_records = make_records([DEFAULT_STEP])
        foreign = revoke_bound(
            foreign_records[0], foreign_records[0].evidence.end, KEY
        )
        other_context = revoke_context(OTHER_CONTEXT, self.now, KEY)
        decision = audit_bound_series_policy(
            self.evidence,
            KEY,
            now=self.now,
            revocations=[foreign, other_context.to_bytes()],
        )
        self.assertIsInstance(decision, RangeDecision)


class AuditBoundSeriesPolicyRevocationCheckTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series([DEFAULT_STEP] * 6)
        self.ends = ends_of(self.records)
        self.now = max(self.ends)

    def foreign_revocation(self):
        records = make_records([DEFAULT_STEP])
        return revoke_bound(records[0], records[0].evidence.end, KEY)

    def test_duplicate_round_identity_rejected(self):
        revocation = self.foreign_revocation()
        for pair in (
            [revocation, revocation],
            [revocation, revocation.to_bytes()],
        ):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=pair
                    )

    def test_duplicate_context_rejected(self):
        revocation = revoke_context(OTHER_CONTEXT, self.now, KEY)
        for pair in (
            [revocation, revocation],
            [revocation, revocation.to_bytes()],
        ):
            with self.subTest(pair=pair):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=pair
                    )

    def test_round_and_context_identity_do_not_collide(self):
        decision = audit_bound_series_policy(
            self.evidence,
            KEY,
            now=self.now,
            revocations=[
                self.foreign_revocation(),
                revoke_context(OTHER_CONTEXT, self.now, KEY),
            ],
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_bad_signature_rejected(self):
        for bad in (
            revoke_bound(self.records[0], self.ends[0], OTHER_KEY),
            revoke_context(OTHER_CONTEXT, self.now, OTHER_KEY),
        ):
            with self.subTest(entry=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=[bad]
                    )

    def test_future_revocation_rejected_even_when_unrelated(self):
        foreign_records = make_records([DEFAULT_STEP])
        future = self.now + 100.0
        for bad in (
            revoke_bound(foreign_records[0], future, KEY),
            revoke_context(OTHER_CONTEXT, future, KEY),
        ):
            with self.subTest(entry=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=[bad]
                    )

    def test_unrelated_entries_do_not_affect_result(self):
        revocations = [
            self.foreign_revocation(),
            revoke_context(OTHER_CONTEXT, self.now, KEY),
        ]
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, revocations=revocations
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))

    def test_round_hit_at_completion_rejects(self):
        revocation = revoke_bound(self.records[2], self.ends[2], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_round_hit_after_completion_rejects(self):
        revocation = revoke_bound(self.records[2], self.ends[2] + 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now + 2.0, revocations=[revocation]
            )

    def test_round_completed_after_revocation_survives(self):
        revocation = revoke_bound(self.records[2], self.ends[2] - 1e-9, KEY)
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, revocations=[revocation]
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_context_hit_rejects(self):
        revocation = revoke_context(CONTEXT, self.now, KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_context_revocation_before_all_rounds_survives(self):
        revocation = revoke_context(CONTEXT, min(self.ends) - 1e-9, KEY)
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, revocations=[revocation]
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_both_kinds_may_hit_together(self):
        revocations = [
            revoke_bound(self.records[1], self.ends[1], KEY),
            revoke_context(CONTEXT, self.now, KEY),
        ]
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            )

    def test_revoked_outlier_round_rejects_series(self):
        # The outlier is excluded from the robust statistics, but its
        # revocation still voids the whole series: voided samples are never
        # dropped for a re-run of the statistics.
        records, evidence = make_series([1.0] + [DEFAULT_STEP] * 5)
        ends = ends_of(records)
        now = max(ends)
        decision = audit_bound_series(evidence, KEY)
        self.assertTrue(decision.accepted)
        revocation = revoke_bound(records[0], ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                evidence, KEY, now=now, revocations=[revocation]
            )


class AuditBoundSeriesPolicyCombinedTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series([DEFAULT_STEP] * 6)
        self.ends = ends_of(self.records)
        self.now = max(self.ends)

    def test_both_policies_pass(self):
        decision = audit_bound_series_policy(
            self.evidence,
            KEY,
            now=self.now,
            max_age=self.now - min(self.ends),
            revocations=[revoke_context(OTHER_CONTEXT, self.now, KEY)],
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_freshness_failure_beats_clean_revocations(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=0.0,
                revocations=[revoke_context(OTHER_CONTEXT, self.now, KEY)],
            )

    def test_revocation_hit_beats_clean_freshness(self):
        revocation = revoke_bound(self.records[0], self.ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[revocation],
            )


if __name__ == "__main__":
    unittest.main()
