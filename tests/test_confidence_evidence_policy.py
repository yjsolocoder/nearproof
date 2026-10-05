import json
import math
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    EvidenceRevocationList,
    Prover,
    Verifier,
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


def make_outlier_evidence_list(key=KEY):
    """Five clustered rounds plus one far-outlier round (created last, so
    it also carries the latest completion time)."""
    gaps = [1.0e-7, 1.1e-7, 1.2e-7, 1.3e-7, 1.4e-7, 1.0e-3]
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


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(7)
        self.used = self.records[:6]
        self.evidence = seal_confidence(self.used, 100.0, KEY)
        self.data = self.evidence.to_bytes()
        self.latest_end = max(record.end for record in self.used)
        self.now = self.latest_end + 1.0
        self.decision = audit_confidence(self.evidence, KEY)


class ConfidenceEvidencePolicyDefaultTest(PolicyFixture):
    def test_default_matches_plain_review_item_for_item(self):
        for artifact in (self.evidence, self.data):
            self.assertEqual(
                audit_confidence_policy(artifact, KEY),
                audit_confidence(artifact, KEY),
            )

    def test_default_returns_recorded_decision(self):
        decision = audit_confidence_policy(self.evidence, KEY)
        self.assertEqual(decision.sample_count, self.evidence.decision.sample_count)
        self.assertEqual(decision.inlier_count, self.evidence.decision.inlier_count)
        self.assertIs(decision.accepted, self.evidence.decision.accepted)

    def test_rejected_conclusion_still_returns(self):
        rejected = seal_confidence(self.used, 1e-9, KEY)
        self.assertIs(rejected.decision.accepted, False)
        decision = audit_confidence_policy(rejected, KEY)
        self.assertIs(decision.accepted, False)
        self.assertEqual(decision, audit_confidence(rejected, KEY))

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

    def test_shape_errors_precede_policy(self):
        for bad in ("x", 123, None, object(), [self.data], 7, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_confidence_policy(bad, KEY, now=self.now, max_age=1.0)
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                audit_confidence_policy(
                    self.evidence, bad, now=self.now, max_age=1.0
                )

    def test_crypto_failure_precedes_policy(self):
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, OTHER_KEY, now=self.now, max_age=1.0
            )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, b"", now=self.now, max_age=1.0
            )
        outer = json.loads(self.data)
        outer[4][7] = not outer[4][7]
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_confidence_policy(tampered, KEY, now=self.now, max_age=1.0)

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_confidence_policy(self.evidence, KEY)
        audit_confidence_policy(
            self.data, KEY, now=self.now, max_age=10.0, revocations=[]
        )
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class ConfidenceEvidencePolicyAgeTest(PolicyFixture):
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
        # A sealed subset without the last round moves the baseline back.
        subset = self.records[:5]
        sealed = seal_confidence(subset, 100.0, KEY)
        latest = max(record.end for record in subset)
        self.assertLess(latest, self.latest_end)
        self.assertEqual(
            audit_confidence_policy(sealed, KEY, now=latest, max_age=0.0),
            audit_confidence(sealed, KEY),
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                sealed, KEY, now=latest - 1e-12, max_age=100.0
            )

    def test_outlier_participates_in_baseline(self):
        _, records = make_outlier_evidence_list()
        evidence = seal_confidence(records, 100.0, KEY)
        self.assertLess(evidence.decision.inlier_count, 6)
        outlier_end = max(record.end for record in records)
        inlier_end = max(record.end for record in records[:-1])
        self.assertLess(inlier_end, outlier_end)
        # The baseline is the outlier's end, not the latest inlier's.
        self.assertEqual(
            audit_confidence_policy(evidence, KEY, now=outlier_end, max_age=0.0),
            audit_confidence(evidence, KEY),
        )
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                evidence,
                KEY,
                now=(inlier_end + outlier_end) / 2.0,
                max_age=100.0,
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


class ConfidenceEvidencePolicyRevocationTest(PolicyFixture):
    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            ),
            self.decision,
        )

    def test_sample_completed_at_revocation_moment_voids(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_sample_completed_before_revocation_moment_voids(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end + 10.0, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=target.end + 20.0,
                revocations=[revocation],
            )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_revoked_outlier_voids_the_whole_evidence(self):
        _, records = make_outlier_evidence_list()
        evidence = seal_confidence(records, 100.0, KEY)
        self.assertLess(evidence.decision.inlier_count, 6)
        outlier = max(records, key=lambda record: record.end)
        revocation = revoke_evidence(outlier, outlier.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                evidence,
                KEY,
                now=outlier.end + 1.0,
                revocations=[revocation],
            )

    def test_bytes_entries_accepted_and_match_objects(self):
        target = self.used[2]
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
            revoke_evidence(self.used[0], 0.0, KEY),
            revoke_evidence(self.used[1], 0.0, KEY).to_bytes(),
        ]
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            ),
            self.decision,
        )

    def test_one_shot_iterable(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=iter([revocation]),
            ),
            self.decision,
        )

    def test_non_matching_entry_is_ignored(self):
        # records[6] is not carried by the sealed decision.
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        for artifact in (foreign, foreign.to_bytes()):
            self.assertEqual(
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[artifact]
                ),
                self.decision,
            )

    def test_duplicate_pair_rejected_even_when_non_matching(self):
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[foreign, foreign.to_bytes()],
            )

    def test_future_revocation_rejected_even_when_non_matching(self):
        foreign = revoke_evidence(self.records[6], self.now + 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[foreign]
            )

    def test_bad_mac_rejected(self):
        revocation = revoke_evidence(self.records[6], 0.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_tampered_bytes_rejected(self):
        blob = bytearray(revoke_evidence(self.records[6], 0.0, KEY).to_bytes())
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
        for bad in ("x", 123, None, object(), b"x"[0:0]):
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

    def test_single_record_or_bytes_passed_directly_rejected(self):
        revocation = revoke_evidence(self.used[0], 0.0, KEY)
        for bad in (revocation, revocation.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_snapshot_form_rejected(self):
        snapshot = make_evidence_revocation_list(
            [revoke_evidence(self.used[0], 0.0, KEY)], 1, self.now, KEY
        )
        self.assertIsInstance(snapshot, EvidenceRevocationList)
        for bad in (snapshot, snapshot.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_confidence_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_empty_revocation_set_requires_now(self):
        with self.assertRaises(ValueError):
            audit_confidence_policy(self.evidence, KEY, revocations=[])

    def test_empty_revocation_set_passes_with_now(self):
        self.assertEqual(
            audit_confidence_policy(
                self.evidence, KEY, now=self.now, revocations=[]
            ),
            self.decision,
        )

    def test_revocation_bytes_input_decision(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.data, KEY, now=self.now, revocations=[revocation]
            )

    def test_age_and_revocation_enforced_together(self):
        target = self.used[0]
        surviving = revoke_evidence(target, target.end - 1e-9, KEY)
        # Freshness fails regardless of the surviving revocation.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=0.5,
                revocations=[surviving],
            )
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
        # Revocation voids even within the age window.
        with self.assertRaises(ValueError):
            audit_confidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[revoke_evidence(target, target.end, KEY)],
            )

    def test_revocation_record_type_is_bound_evidence_revocation(self):
        revocation = revoke_evidence(self.used[0], 1.0, KEY)
        self.assertIsInstance(revocation, BoundEvidenceRevocation)


if __name__ == "__main__":
    unittest.main()
