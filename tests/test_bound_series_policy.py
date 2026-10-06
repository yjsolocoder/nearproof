import dataclasses
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    Prover,
    RangeDecision,
    Verifier,
    _bound_revocation_mac,
    _bound_revocation_payload,
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

DEFAULT_STEP = 1e-7


class SteppedClock:
    def __init__(self, start: float = 0.0, step: float = DEFAULT_STEP) -> None:
        self.now = start
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


def make_bounds(count, *, key=KEY, context=CONTEXT, opening=OPENING,
                digest=DIGEST, step=DEFAULT_STEP, start=0.0, first_step=None):
    """Consecutive bound rounds; ``first_step`` overrides the round-0 delay."""
    prover = Prover(key)
    clock = SteppedClock(start=start, step=step)
    verifier = Verifier(key, clock=clock, replay_protection=True)
    records = []
    for index in range(count):
        challenge = verifier.new_challenge(context=context, digest=digest)
        started = clock.now
        response = prover.reveal(challenge, context, opening)
        clock.now += first_step if index == 0 and first_step is not None else step
        records.append(
            verifier.verify_bound(challenge, response, started, opening=opening)
        )
    return verifier, records


def make_series(count=6, *, limit=100.0, min_samples=5, key=KEY, **kwargs):
    _verifier, records = make_bounds(count, key=key, **kwargs)
    first = records[0].evidence.round_index
    evidence = seal_bound_series(
        records, SESSION, first, count, limit, min_samples, key
    )
    return records, evidence


def ends_of(records):
    return [record.evidence.end for record in records]


class NoPolicyTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series()

    def test_matches_plain_audit(self):
        self.assertEqual(
            audit_bound_series_policy(self.evidence, KEY),
            audit_bound_series(self.evidence, KEY),
        )

    def test_now_is_ignored(self):
        decision = audit_bound_series(self.evidence, KEY)
        for junk in (None, object(), "later", float("nan"), True):
            with self.subTest(now=junk):
                self.assertEqual(
                    audit_bound_series_policy(self.evidence, KEY, now=junk),
                    decision,
                )

    def test_bytes_input(self):
        self.assertEqual(
            audit_bound_series_policy(self.evidence.to_bytes(), KEY),
            audit_bound_series(self.evidence, KEY),
        )

    def test_baseline_type_error_preserved(self):
        with self.assertRaises(TypeError):
            audit_bound_series_policy(42, KEY, now=1.0, max_age=1.0)

    def test_baseline_failure_precedes_policy_errors(self):
        # Wrong key and a policy that would also fail: the baseline
        # ValueError surfaces first.
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, OTHER_KEY, now=None, max_age=-1.0
            )
        # A non-canonical encoding fails before the missing-now error.
        with self.assertRaises(ValueError):
            audit_bound_series_policy(b"{}", KEY, max_age=1.0)


class FreshnessTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series()
        self.ends = ends_of(self.records)

    def test_max_age_contract(self):
        now = max(self.ends)
        for bad in (True, -1.0, float("nan"), float("inf"), "1"):
            with self.subTest(max_age=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=now, max_age=bad
                    )

    def test_now_required_and_contract(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(self.evidence, KEY, max_age=1.0)
        for bad in (True, float("nan"), float("inf"), "1"):
            with self.subTest(now=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=bad, max_age=1.0
                    )

    def test_int_now_and_max_age_accepted(self):
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=10, max_age=10
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_boundaries_are_closed(self):
        # Oldest round exactly max_age old, newest exactly age zero.
        now = max(self.ends)
        max_age = now - min(self.ends)
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=now, max_age=max_age
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))

    def test_oldest_round_over_age_rejects(self):
        now = max(self.ends)
        max_age = now - min(self.ends)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=now, max_age=max_age - 1e-9
            )

    def test_future_round_rejects_even_when_last_round_is_fresh(self):
        # now lands on the third round's end: the later rounds are
        # future-dated even though age would be measured fine for the rest.
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.ends[2], max_age=1.0
            )

    def test_outlier_round_is_checked(self):
        # Round 0 is a huge-delay outlier the robust statistics discard;
        # it is still carried and still has to satisfy the age window.
        records, evidence = make_series(first_step=10.0)
        self.assertTrue(evidence.accepted)
        ends = ends_of(records)
        now = max(ends)
        # Every round but the outlier fits the window.
        max_age = now - ends[1]
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                evidence, KEY, now=now, max_age=max_age
            )
        # Widening the window to cover the outlier passes.
        decision = audit_bound_series_policy(
            evidence, KEY, now=now, max_age=now - ends[0]
        )
        self.assertTrue(decision.accepted)


class RevocationInputTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series()
        self.ends = ends_of(self.records)
        self.now = max(self.ends) + 1.0

    def test_empty_iterable_is_valid(self):
        for empty in ((), [], iter(()), (x for x in ())):
            with self.subTest(empty=empty):
                decision = audit_bound_series_policy(
                    self.evidence, KEY, now=self.now, revocations=empty
                )
                self.assertEqual(
                    decision, audit_bound_series(self.evidence, KEY)
                )

    def test_single_object_or_bare_bytes_rejected(self):
        revocation = revoke_bound(self.records[0], self.ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=revocation
            )
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now,
                revocations=revocation.to_bytes(),
            )
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=b""
            )

    def test_non_iterable_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=42
            )

    def test_bad_element_rejected(self):
        for bad in (42, "x", object(), None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=[bad]
                    )

    def test_non_canonical_bytes_rejected(self):
        revocation = revoke_bound(self.records[0], self.ends[0], KEY)
        for bad in (b"{}", b"not json", revocation.to_bytes() + b" "):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    audit_bound_series_policy(
                        self.evidence, KEY, now=self.now, revocations=[bad]
                    )

    def test_now_required_with_revocations(self):
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, revocations=[]
            )

    def test_wrong_key_rejected(self):
        revocation = revoke_bound(self.records[0], self.ends[0], OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_future_revoked_at_rejected_even_when_unrelated(self):
        unrelated = BoundEvidenceRevocation(
            version=1,
            round_index=self.records[0].evidence.round_index + 1000,
            nonce=b"\x01" * 16,
            revoked_at=self.now + 1.0,
            mac=b"\x00" * 32,
        )
        unrelated = dataclasses.replace(
            unrelated,
            mac=_bound_revocation_mac(KEY, _bound_revocation_payload(unrelated)),
        )
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[unrelated]
            )

    def test_duplicate_round_identity_rejected(self):
        revocation = revoke_bound(self.records[0], self.ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now,
                revocations=[revocation, revocation.to_bytes()],
            )

    def test_duplicate_context_rejected(self):
        revocation = revoke_context(OTHER_CONTEXT, 0.0, KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now,
                revocations=[revocation, revocation.to_bytes()],
            )

    def test_unrelated_entries_pass(self):
        round_revocation = BoundEvidenceRevocation(
            version=1,
            round_index=self.records[0].evidence.round_index + 1000,
            nonce=b"\x01" * 16,
            revoked_at=self.now,
            mac=b"\x00" * 32,
        )
        round_revocation = dataclasses.replace(
            round_revocation,
            mac=_bound_revocation_mac(
                KEY, _bound_revocation_payload(round_revocation)
            ),
        )
        context_revocation = revoke_context(OTHER_CONTEXT, self.now, KEY)
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now,
            revocations=[round_revocation, context_revocation.to_bytes()],
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))

    def test_one_shot_iterable_and_mixed_forms(self):
        round_revocation = revoke_bound(
            self.records[0], self.ends[0] - DEFAULT_STEP, KEY
        )
        context_revocation = revoke_context(OTHER_CONTEXT, 0.0, KEY)
        entries = iter([round_revocation.to_bytes(), context_revocation])
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, revocations=entries
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))


class RevocationHitTest(unittest.TestCase):
    def setUp(self):
        self.records, self.evidence = make_series()
        self.ends = ends_of(self.records)
        self.now = max(self.ends) + 1.0

    def test_round_hit_at_end_rejects(self):
        revocation = revoke_bound(self.records[2], self.ends[2], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_round_hit_after_end_rejects(self):
        revocation = revoke_bound(
            self.records[2], self.ends[2] + DEFAULT_STEP, KEY
        )
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_round_revocation_strictly_before_end_survives(self):
        revocation = revoke_bound(
            self.records[2], self.ends[2] - DEFAULT_STEP, KEY
        )
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, revocations=[revocation]
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))

    def test_context_hit_rejects(self):
        revocation = revoke_context(CONTEXT, min(self.ends), KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_context_revocation_before_all_ends_survives(self):
        revocation = revoke_context(
            CONTEXT, min(self.ends) - DEFAULT_STEP, KEY
        )
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=self.now, revocations=[revocation]
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))

    def test_outlier_round_hit_rejects(self):
        # The outlier is excluded from the statistics but still voids the
        # series when revoked at its completion time.
        records, evidence = make_series(first_step=10.0)
        self.assertTrue(evidence.accepted)
        ends = ends_of(records)
        now = max(ends) + 1.0
        revocation = revoke_bound(records[0], ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                evidence, KEY, now=now, revocations=[revocation]
            )

    def test_both_policies_together(self):
        now = max(self.ends)
        max_age = now - min(self.ends)
        revocation = revoke_context(OTHER_CONTEXT, 0.0, KEY)
        decision = audit_bound_series_policy(
            self.evidence, KEY, now=now, max_age=max_age,
            revocations=[revocation],
        )
        self.assertEqual(decision, audit_bound_series(self.evidence, KEY))
        # Each policy still bites when the other passes.
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=now, max_age=max_age - 1e-9,
                revocations=[revocation],
            )
        hit = revoke_bound(self.records[0], self.ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                self.evidence, KEY, now=now, max_age=max_age,
                revocations=[hit],
            )


class RejectedStatisticsTest(unittest.TestCase):
    def test_rejected_series_still_returns_decision(self):
        # A 1 m limit rejects these ~15 m fixtures statistically; the
        # policy checks still run and the negative decision is returned.
        records, evidence = make_series(limit=1.0, min_samples=5)
        self.assertFalse(evidence.accepted)
        ends = ends_of(records)
        now = max(ends)
        decision = audit_bound_series_policy(
            evidence, KEY, now=now, max_age=now - min(ends)
        )
        self.assertIsInstance(decision, RangeDecision)
        self.assertFalse(decision.accepted)
        # A revocation hit still rejects a statistically rejected series.
        hit = revoke_bound(records[0], ends[0], KEY)
        with self.assertRaises(ValueError):
            audit_bound_series_policy(
                evidence, KEY, now=now, revocations=[hit]
            )


if __name__ == "__main__":
    unittest.main()
