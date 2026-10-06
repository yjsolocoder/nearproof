import json
import math
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    Prover,
    Verifier,
    _reliability_evidence_mac,
    assess_reliability,
    audit_reliability,
    audit_reliability_policy,
    make_evidence_revocation_list,
    revoke_evidence,
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


def resign(record_bytes, changes, *, key=KEY):
    """Decode a ReliabilityEvidence, apply index->value changes and re-MAC it."""
    outer = json.loads(record_bytes)
    for index, value in changes.items():
        outer[index] = value
    content = json.dumps(outer[:6], separators=(",", ":")).encode()
    outer[6] = _reliability_evidence_mac(key, content).hex()
    return json.dumps(outer, separators=(",", ":")).encode()


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(7)
        self.used = self.records[:6]
        self.evidence = seal_reliability(
            self.used, 100.0, KEY, max_exceedance=0.5
        )
        self.data = self.evidence.to_bytes()
        self.latest_end = max(record.end for record in self.used)
        self.now = self.latest_end + 1.0
        self.decision = audit_reliability(self.evidence, KEY)


class ReliabilityPolicyDefaultTest(PolicyFixture):
    def test_default_matches_existing_review_item_for_item(self):
        for artifact in (self.evidence, self.data):
            self.assertEqual(
                audit_reliability_policy(artifact, KEY),
                audit_reliability(artifact, KEY),
            )

    def test_default_returns_recorded_decision(self):
        decision = audit_reliability_policy(self.evidence, KEY)
        recorded = self.evidence.decision
        self.assertEqual(decision.sample_count, recorded.sample_count)
        self.assertEqual(decision.exceedance_count, recorded.exceedance_count)
        self.assertEqual(decision.upper_probability, recorded.upper_probability)
        self.assertEqual(decision.confidence, recorded.confidence)
        self.assertIs(decision.accepted, recorded.accepted)
        self.assertEqual(
            decision,
            assess_reliability(
                self.used, 100.0, max_exceedance=0.5, key=KEY
            ),
        )

    def test_default_ignores_now_and_min_entirely(self):
        # No clock is read and garbage now/min values change nothing.
        self.assertEqual(
            audit_reliability_policy(self.evidence, KEY, now="garbage"),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(self.evidence, KEY, now=math.nan, min="x"),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(
                self.data, KEY, now=None, max_age=None, revocations=None, min=True
            ),
            self.decision,
        )

    def test_default_rejected_conclusion_still_round_trips(self):
        rejected = seal_reliability(self.used, 1e-9, KEY, max_exceedance=0.9)
        decision = audit_reliability_policy(rejected, KEY)
        self.assertIs(decision.accepted, False)

    def test_shape_errors_precede_policy(self):
        for bad in ("x", 123, None, object(), [self.data], 7, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_reliability_policy(bad, KEY, now=self.now, max_age=1.0)
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                audit_reliability_policy(
                    self.evidence, bad, now=self.now, max_age=1.0
                )

    def test_crypto_failure_precedes_policy(self):
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, OTHER_KEY, now=self.now, max_age=1.0
            )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, b"", now=self.now, max_age=1.0
            )
        outer = json.loads(self.data)
        outer[2] = 1.0
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_reliability_policy(tampered, KEY, now=self.now, max_age=1.0)

    def test_statistics_mismatch_precedes_policy(self):
        # Re-signed under the right key but the recorded exceedance count
        # disagrees with the carried samples.
        outer = json.loads(self.data)
        decision = outer[5]
        decision[1] = decision[1] + 1
        mismatched = resign(self.data, {5: decision})
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                mismatched, KEY, now=self.now, max_age=10.0
            )

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_reliability_policy(self.evidence, KEY)
        audit_reliability_policy(
            self.data, KEY, now=self.now, max_age=10.0, revocations=[]
        )
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class ReliabilityPolicyAgeTest(PolicyFixture):
    def test_closed_interval_boundaries_are_valid(self):
        # now == latest_end with max_age 0 and now == latest_end + max_age.
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.latest_end, max_age=0.0
            ),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, max_age=1.0
            ),
            self.decision,
        )

    def test_future_baseline_rejected(self):
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.latest_end - 1e-12,
                max_age=100.0,
            )

    def test_over_age_rejected(self):
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, max_age=0.5
            )

    def test_baseline_is_the_latest_completed_sample(self):
        subset = self.records[:5]
        sealed = seal_reliability(
            subset, 100.0, KEY, max_exceedance=0.5, min_samples=5
        )
        latest = max(record.end for record in subset)
        self.assertEqual(
            audit_reliability_policy(sealed, KEY, now=latest, max_age=0.0),
            audit_reliability(sealed, KEY),
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                sealed, KEY, now=latest - 1e-12, max_age=100.0
            )

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_reliability_policy(self.evidence, KEY, max_age=1.0)

    def test_bad_now_rejected(self):
        for bad in ("1", None, True, False, math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError, msg=bad):
                audit_reliability_policy(
                    self.evidence, KEY, now=bad, max_age=1.0
                )

    def test_bad_max_age_rejected(self):
        for bad in ("1", True, False, -0.1, math.nan, math.inf):
            with self.assertRaises(ValueError, msg=bad):
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now, max_age=bad
                )

    def test_integer_now_and_max_age(self):
        latest = self.latest_end
        decision = audit_reliability_policy(
            self.evidence, KEY, now=math.ceil(latest), max_age=1
        )
        self.assertEqual(decision, self.decision)


class ReliabilityPolicyRevocationTest(PolicyFixture):
    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            ),
            self.decision,
        )

    def test_sample_completed_at_revocation_moment_voids(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_sample_completed_before_revocation_moment_voids(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end + 10.0, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=target.end + 20.0,
                revocations=[revocation],
            )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_revoked_sample_is_never_dropped(self):
        # The whole evidence is voided; the decision is never recomputed
        # without the revoked sample.
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_bytes_entries_accepted_and_match_objects(self):
        target = self.used[2]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_reliability_policy(
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
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            ),
            self.decision,
        )

    def test_one_shot_iterable_accepted(self):
        target = self.used[0]
        revocations = (
            entry
            for entry in [revoke_evidence(target, target.end - 1e-9, KEY)]
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            ),
            self.decision,
        )

    def test_non_matching_entry_is_ignored(self):
        # records[6] is not carried by the sealed decision.
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        for artifact in (foreign, foreign.to_bytes()):
            self.assertEqual(
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now, revocations=[artifact]
                ),
                self.decision,
            )

    def test_duplicate_pair_rejected_even_when_non_matching(self):
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[foreign, foreign.to_bytes()],
            )

    def test_future_revocation_rejected_even_when_non_matching(self):
        foreign = revoke_evidence(self.records[6], self.now + 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[foreign]
            )

    def test_bad_mac_rejected(self):
        revocation = revoke_evidence(self.records[6], 0.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_tampered_bytes_rejected(self):
        blob = bytearray(revoke_evidence(self.records[6], 0.0, KEY).to_bytes())
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[bytes(blob)]
            )

    def test_malformed_revocation_bytes_rejected(self):
        for bad in (b"not json", b"{}", b"[]", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now, revocations=[bad]
                )

    def test_wrong_element_type_rejected(self):
        for bad in ("x", 123, None, object(), b"x"[0:0]):
            with self.assertRaises(ValueError, msg=bad):
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now, revocations=[bad]
                )

    def test_non_iterable_revocations_rejected(self):
        for bad in (7, 1.5, object()):
            with self.assertRaises(ValueError, msg=bad):
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_empty_revocation_set_enables_the_check(self):
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[]
            ),
            self.decision,
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(self.evidence, KEY, revocations=[])

    def test_min_ignored_in_per_round_form(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[revocation],
                min="not-an-integer",
            ),
            self.decision,
        )

    def test_revocation_bytes_input_decision(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.data, KEY, now=self.now, revocations=[revocation]
            )

    def test_age_and_revocation_enforced_together(self):
        target = self.used[0]
        surviving = revoke_evidence(target, target.end - 1e-9, KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=0.5,
                revocations=[surviving],
            )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[surviving],
            ),
            self.decision,
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[revoke_evidence(target, target.end, KEY)],
            )


class ReliabilityPolicySnapshotTest(PolicyFixture):
    def _snapshot(self, entries, *, sequence=0, issued_at=None, key=KEY):
        return make_evidence_revocation_list(
            entries, sequence, self.now if issued_at is None else issued_at, key
        )

    def test_empty_snapshot_leaves_decision_unchanged(self):
        erl = self._snapshot([], issued_at=0.0)
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(
                self.data, KEY, now=self.now, revocations=erl.to_bytes()
            ),
            self.decision,
        )

    def test_snapshot_requires_now(self):
        erl = self._snapshot([], issued_at=0.0)
        with self.assertRaises(ValueError):
            audit_reliability_policy(self.evidence, KEY, revocations=erl)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, revocations=erl.to_bytes()
            )

    def test_hit_voids_object_and_bytes(self):
        target = self.used[0]
        erl = self._snapshot([revoke_evidence(target, target.end, KEY)])
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl.to_bytes()
            )

    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        erl = self._snapshot(
            [revoke_evidence(target, target.end - 1e-9, KEY)]
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )

    def test_non_matching_entries_are_ignored(self):
        erl = self._snapshot(
            [revoke_evidence(self.records[6], 0.0, KEY)], issued_at=0.0
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )

    def test_future_entry_rejected_even_when_non_matching(self):
        erl = self._snapshot(
            [revoke_evidence(self.records[6], self.now + 1.0, KEY)]
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_min_floor_enforced_default_zero(self):
        erl = self._snapshot([], sequence=3)
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl, min=3
            ),
            self.decision,
        )
        # The floor defaults to 0.
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl, min=4
            )

    def test_bad_min_rejected_only_in_snapshot_form(self):
        erl = self._snapshot([], issued_at=0.0)
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=bad):
                audit_reliability_policy(
                    self.evidence,
                    KEY,
                    now=self.now,
                    revocations=erl,
                    min=bad,
                )

    def test_future_snapshot_rejected(self):
        erl = self._snapshot([], issued_at=self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_wrong_key_snapshot_rejected(self):
        erl = self._snapshot([], key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_tampered_snapshot_entry_rejected(self):
        target = self.used[0]
        entry = revoke_evidence(target, target.end - 1e-9, KEY)
        forged = BoundEvidenceRevocation(
            1, entry.round_index, entry.nonce, entry.revoked_at, b"\x00" * 32
        )
        erl = self._snapshot([forged])
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_malformed_snapshot_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=b"not json"
            )

    def test_snapshot_and_age_enforced_together(self):
        target = self.used[0]
        erl = self._snapshot(
            [revoke_evidence(target, target.end - 1e-9, KEY)]
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=erl,
                min=0,
            ),
            self.decision,
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=0.5,
                revocations=erl,
            )


if __name__ == "__main__":
    unittest.main()
