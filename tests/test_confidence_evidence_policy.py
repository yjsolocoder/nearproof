import json
import math
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    NoiseDecision,
    Prover,
    Verifier,
    assess_confidence,
    audit_confidence,
    audit_confidence_policy,
    make_evidence_revocation_list,
    revoke_evidence,
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
    """Serves a fixed list of readings: two per round."""

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
    return verifier, prover, records


def make_outlier_evidence(key=KEY):
    """Six records, the last a far-distance MAD outlier.

    The decision carries six samples but only five inliers, so the outlier
    is both excluded from the statistics and the latest-completed round; it
    still participates in every policy check.
    """
    gaps = [1.0e-7, 1.1e-7, 1.2e-7, 1.3e-7, 1.4e-7, 1.0e-5]
    prover = Prover(key)
    verifier = Verifier(key, clock=varied_clock(gaps), replay_protection=True)
    records = []
    for _ in gaps:
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    evidence = seal_confidence(records, 100.0, key)
    assert evidence.decision.sample_count == 6
    assert evidence.decision.inlier_count == 5
    return verifier, prover, records, evidence


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        self.verifier, self.prover, self.records = make_evidence_list(6)
        self.evidence = seal_confidence(self.records, 100.0, KEY)
        self.data = self.evidence.to_bytes()
        self.latest_end = max(record.end for record in self.records)
        self.now = self.latest_end + 1.0
        self.decision = audit_confidence(self.evidence, KEY)


class ConfidencePolicyDefaultTest(PolicyFixture):
    def test_default_matches_existing_review_item_for_item(self):
        for artifact in (self.evidence, self.data):
            self.assertEqual(
                audit_confidence_policy(artifact, KEY),
                audit_confidence(artifact, KEY),
            )

    def test_default_returns_recorded_noise_decision(self):
        decision = audit_confidence_policy(self.evidence, KEY)
        self.assertIsInstance(decision, NoiseDecision)
        self.assertEqual(decision, self.evidence.decision)
        self.assertEqual(
            decision, assess_confidence(self.records, 100.0, key=KEY)
        )

    def test_default_ignores_now_entirely(self):
        # No clock is read and a garbage/absurd now changes nothing.
        self.assertEqual(
            audit_confidence_policy(self.evidence, KEY, now="garbage"),
            self.decision,
        )
        self.assertEqual(
            audit_confidence_policy(self.evidence, KEY, now=math.nan),
            self.decision,
        )
        self.assertEqual(
            audit_confidence_policy(
                self.data, KEY, now=None, max_age=None, revocations=None
            ),
            self.decision,
        )

    def test_default_rejected_conclusion_still_returned(self):
        rejected = seal_confidence(self.records, 1e-9, KEY)
        self.assertIs(rejected.decision.accepted, False)
        decision = audit_confidence_policy(rejected, KEY)
        self.assertIs(decision.accepted, False)
        self.assertEqual(decision, rejected.decision)

    def test_shape_errors_precede_policy(self):
        for bad in ("x", 123, None, object(), [self.data], 7, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_confidence_policy(bad, KEY, now=self.now, max_age=1.0)
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                audit_confidence_policy(
                    self.evidence, bad, now=self.now, max_age=1.0
                )

    def test_crypto_and_conclusion_failures_precede_policy(self):
        # Wrong key, empty key and tampered bytes all fail the baseline
        # review before any policy argument is consulted.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, OTHER_KEY, now=self.now, max_age=1.0
            )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, b"", now=self.now, max_age=1.0
            )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.data + b" ", KEY, now=self.now, max_age=1.0
            )
        with self.assertRaises(ValueError):
            audit_confidence_policy(self.evidence, OTHER_KEY, now=self.now,
                                    revocations=[])

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_confidence_policy(self.evidence, KEY)
        audit_confidence_policy(
            self.data, KEY, now=self.now, max_age=10.0, revocations=[]
        )
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)
        # Repeated audits of the same artifact all succeed.
        audit_confidence_policy(self.evidence, KEY, now=self.now, max_age=10.0)
        audit_confidence_policy(self.evidence, KEY, now=self.now, max_age=10.0)


class ConfidencePolicyAgeTest(PolicyFixture):
    def test_closed_interval_boundaries_are_valid(self):
        # now == latest_end with max_age 0 and now == latest_end + max_age.
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.latest_end, max_age=0.0
            ),
            self.decision,
        )
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, max_age=1.0
            ),
            self.decision,
        )

    def test_future_baseline_rejected(self):
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.latest_end - 1e-12,
                max_age=100.0,
            )

    def test_over_age_rejected(self):
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, max_age=0.5
            )

    def test_baseline_is_the_latest_completed_sample(self):
        subset = self.records[:5]
        sealed = seal_confidence(subset, 100.0, KEY)
        latest = max(record.end for record in subset)
        self.assertEqual(
            audit_confidence_policy(sealed, KEY, now=latest, max_age=0.0),
            audit_confidence(sealed, KEY),
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                sealed, KEY, now=latest - 1e-12, max_age=100.0
            )

    def test_outlier_participates_in_age_baseline(self):
        _verifier, _prover, records, evidence = make_outlier_evidence()
        outlier = records[-1]
        latest = max(record.end for record in records)
        self.assertEqual(latest, outlier.end)
        # The outlier's end anchors freshness even though it is no inlier.
        self.assertEqual(
            audit_confidence_policy(evidence, KEY, now=latest, max_age=0.0),
            audit_confidence(evidence, KEY),
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                evidence, KEY, now=latest - 1e-9, max_age=100.0
            )

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_confidence_policy(self.evidence, KEY, max_age=1.0)

    def test_bad_now_rejected(self):
        for bad in ("1", None, True, False, math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError, msg=bad):
                audit_confidence_policy(
                    self.evidence, KEY, now=bad, max_age=1.0
                )

    def test_bad_max_age_rejected(self):
        for bad in ("1", True, False, -0.1, math.nan, math.inf):
            with self.assertRaises(ValueError, msg=bad):
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, max_age=bad
                )

    def test_integer_now_and_max_age(self):
        latest = self.latest_end
        decision = audit_confidence_policy(
            self.evidence, KEY, now=math.ceil(latest), max_age=1
        )
        self.assertEqual(decision, self.decision)

    def test_bytes_input_runs_full_review_and_policy(self):
        self.assertEqual(
            audit_confidence_policy(
                self.data, KEY, now=self.now, max_age=1.0
            ),
            self.decision,
        )


class ConfidencePolicyRevocationTest(PolicyFixture):
    def test_sample_completed_after_revocation_survives(self):
        target = self.records[0]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            ),
            self.decision,
        )

    def test_sample_completed_at_revocation_moment_voids(self):
        target = self.records[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_sample_completed_before_revocation_moment_voids(self):
        target = self.records[0]
        revocation = revoke_evidence(target, target.end + 10.0, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=target.end + 20.0,
                revocations=[revocation],
            )

    def test_strictly_later_samples_unaffected_by_other_revocation(self):
        # A revocation after one carried round but strictly before the
        # others voids the evidence carrying that round; an evidence whose
        # samples all post-date the revocation survives.
        early = self.records[0]
        later = seal_confidence(self.records[2:], 100.0, KEY, min_samples=3)
        revoked_at = (self.records[0].end + self.records[1].end) / 2.0
        revocation = revoke_evidence(early, revoked_at, KEY)
        self.assertEqual(
            audit_confidence_policy(
                later, KEY, now=self.now, revocations=[revocation]
            ),
            audit_confidence(later, KEY),
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_outlier_revocation_voids_whole_evidence(self):
        # The hit outlier is not dropped and the conclusion is not
        # recomputed: the whole evidence is rejected.
        _verifier, _prover, records, evidence = make_outlier_evidence()
        outlier = records[-1]
        revocation = revoke_evidence(outlier, outlier.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                evidence,
                KEY,
                now=max(record.end for record in records),
                revocations=[revocation],
            )
        # A strictly later-completed outlier would survive: the matching
        # rule is end <= revoked_at, not an inlier rule.
        surviving = revoke_evidence(outlier, outlier.end - 1e-9, KEY)
        self.assertEqual(
            audit_confidence_policy(
                evidence,
                KEY,
                now=max(record.end for record in records),
                revocations=[surviving],
            ),
            audit_confidence(evidence, KEY),
        )

    def test_bytes_entries_accepted_and_match_objects(self):
        target = self.records[2]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[revocation.to_bytes()],
            ),
            self.decision,
        )

    def test_mixed_objects_and_bytes(self):
        revocations = [
            revoke_evidence(self.records[0], 0.0, KEY),
            revoke_evidence(self.records[1], 0.0, KEY).to_bytes(),
        ]
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            ),
            self.decision,
        )

    def test_one_shot_iterable_consumed_once(self):
        target = self.records[0]
        revocation = revoke_evidence(target, 0.0, KEY)

        def one_shot():
            yield revocation

        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=one_shot()
            ),
            self.decision,
        )

    def test_non_matching_entry_is_ignored(self):
        _verifier, _prover, other = make_evidence_list(1, key=KEY, step=2e-7)
        foreign = revoke_evidence(other[0], 0.0, KEY)
        for artifact in (foreign, foreign.to_bytes()):
            self.assertEqual(
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[artifact]
                ),
                self.decision,
            )

    def test_duplicate_pair_rejected_even_when_non_matching(self):
        _verifier, _prover, other = make_evidence_list(1, key=KEY, step=2e-7)
        foreign = revoke_evidence(other[0], 0.0, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[foreign, foreign.to_bytes()],
            )

    def test_future_revocation_rejected_even_when_non_matching(self):
        _verifier, _prover, other = make_evidence_list(1, key=KEY, step=2e-7)
        foreign = revoke_evidence(other[0], self.now + 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[foreign]
            )

    def test_bad_mac_rejected(self):
        _verifier, _prover, other = make_evidence_list(1, key=KEY, step=2e-7)
        revocation = revoke_evidence(other[0], 0.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_tampered_revocation_object_rejected(self):
        import dataclasses

        target = self.records[0]
        tampered = dataclasses.replace(
            revoke_evidence(target, 0.0, KEY), revoked_at=self.now
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[tampered]
            )

    def test_tampered_bytes_rejected(self):
        _verifier, _prover, other = make_evidence_list(1, key=KEY, step=2e-7)
        blob = bytearray(revoke_evidence(other[0], 0.0, KEY).to_bytes())
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[bytes(blob)]
            )

    def test_malformed_revocation_bytes_rejected(self):
        for bad in (b"not json", b"{}", b"[]", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[bad]
                )

    def test_wrong_element_type_rejected(self):
        for bad in ("x", 123, None, object(), b""):
            with self.assertRaises(ValueError, msg=bad):
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[bad]
                )

    def test_non_iterable_revocations_rejected(self):
        for bad in (7, 1.5, object()):
            with self.assertRaises(ValueError, msg=bad):
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_single_record_rejected_even_when_it_would_match(self):
        target = self.records[0]
        revocation = revoke_evidence(target, 0.0, KEY)
        # A bare record is not an iterable of records.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=revocation
            )
        # Its bare bytes iterate as ints and fail the entry contract too.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now,
                revocations=revocation.to_bytes(),
            )

    def test_snapshot_rejected_in_either_form(self):
        target = self.records[0]
        revocation = revoke_evidence(target, 0.0, KEY)
        snapshot = make_evidence_revocation_list(
            [revocation], 0, self.now, KEY
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=snapshot
            )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now,
                revocations=snapshot.to_bytes(),
            )

    def test_empty_revocation_set_enables_check_and_requires_now(self):
        with self.assertRaises(ValueError):
            audit_confidence_policy(self.evidence, KEY, revocations=[])
        with self.assertRaises(ValueError):
            audit_confidence_policy(self.evidence, KEY, revocations=())
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[]
            ),
            self.decision,
        )
        self.assertEqual(
            audit_confidence_policy(
                self.data, KEY, now=self.now, revocations=()
            ),
            self.decision,
        )

    def test_now_contract_with_revocations(self):
        revocation = revoke_evidence(self.records[0], 0.0, KEY)
        for bad in (None, math.inf, math.nan, True, False, "now"):
            with self.assertRaises(ValueError, msg=bad):
                audit_confidence_policy(
                    self.evidence, KEY, now=bad, revocations=[revocation]
                )

    def test_revocation_bytes_input_decision(self):
        target = self.records[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.data, KEY, now=self.now, revocations=[revocation]
            )

    def test_age_and_revocation_enforced_together(self):
        target = self.records[0]
        latest = self.latest_end
        surviving = revoke_evidence(target, target.end - 1e-9, KEY)
        # Both satisfied.
        self.assertEqual(
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[surviving],
            ),
            self.decision,
        )
        # Over-age decision fails even though every revocation survives.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=latest + 11.0,
                max_age=10.0,
                revocations=[surviving],
            )
        # Revocation voids even within the age window.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[revoke_evidence(target, target.end, KEY)],
            )


if __name__ == "__main__":
    unittest.main()
