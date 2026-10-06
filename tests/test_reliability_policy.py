import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    EvidenceRevocationList,
    Prover,
    Verifier,
    _RELIABILITY_EVIDENCE_PREFIX,
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


def revocation(record, revoked_at=0.0, key=KEY):
    return revoke_evidence(record, revoked_at, key)


def resign(record_bytes, changes=None, *, key=KEY):
    """Decode a ReliabilityEvidence, apply index->value changes and re-MAC it."""
    outer = json.loads(record_bytes)
    for index, value in (changes or {}).items():
        outer[index] = value
    content = json.dumps(outer[:6], separators=(",", ":")).encode()
    outer[6] = hmac.new(
        key, _RELIABILITY_EVIDENCE_PREFIX + content, hashlib.sha256
    ).digest().hex()
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
        self.assertEqual(decision, self.evidence.decision)
        self.assertEqual(
            decision,
            assess_reliability(
                self.used, 100.0, max_exceedance=0.5, key=KEY
            ),
        )

    def test_default_ignores_now_and_min_entirely(self):
        # No clock is read and garbage/absurd policy inputs change nothing.
        self.assertEqual(
            audit_reliability_policy(self.evidence, KEY, now="garbage"),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(self.evidence, KEY, now=math.nan),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(
                self.data, KEY, now=None, max_age=None, revocations=None,
                min="junk",
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
        outer[5][4] = not outer[5][4]
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_reliability_policy(tampered, KEY, now=self.now, max_age=1.0)

    def test_resigned_statistics_mismatch_rejected(self):
        # Re-signed under the right key but the recorded decision disagrees
        # with the carried samples: still a ValueError, before policy.
        outer = json.loads(self.data)
        outer[5][1] = outer[5][1] + 1
        tampered = resign(self.data, {5: outer[5]})
        with self.assertRaises(ValueError):
            audit_reliability_policy(tampered, KEY, now=self.now, max_age=1.0)

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

    def test_rejected_decision_returned_when_policy_passes(self):
        rejected = seal_reliability(self.used, 1e-9, KEY, max_exceedance=0.9)
        decision = audit_reliability_policy(
            rejected, KEY, now=self.now, max_age=1.0
        )
        self.assertIs(decision.accepted, False)
        self.assertEqual(decision, audit_reliability(rejected, KEY))


class ReliabilityPolicyRevocationTest(PolicyFixture):
    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        entry = revocation(target, target.end - 1e-9)
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[entry]
            ),
            self.decision,
        )

    def test_sample_completed_at_revocation_moment_voids(self):
        target = self.used[0]
        entry = revocation(target, target.end)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[entry]
            )

    def test_sample_completed_before_revocation_moment_voids(self):
        target = self.used[0]
        entry = revocation(target, target.end + 10.0)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=target.end + 20.0,
                revocations=[entry],
            )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        entry = revocation(target, target.end)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[entry]
            )

    def test_revoked_sample_is_never_dropped_and_rejudged(self):
        # The whole evidence is voided; the statistics are never recomputed
        # without the revoked sample.
        target = self.used[0]
        entry = revocation(target, target.end)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.data, KEY, now=self.now, revocations=[entry]
            )

    def test_bytes_entries_accepted_and_match_objects(self):
        target = self.used[2]
        entry = revocation(target, target.end - 1e-9)
        self.assertEqual(
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[entry.to_bytes()],
            ),
            self.decision,
        )

    def test_mixed_objects_and_bytes(self):
        revocations = [
            revocation(self.used[0], 0.0),
            revocation(self.used[1], 0.0).to_bytes(),
        ]
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            ),
            self.decision,
        )

    def test_one_shot_iterable_accepted(self):
        entries = (
            revocation(record, 0.0) for record in self.used[:2]
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=entries
            ),
            self.decision,
        )

    def test_non_matching_entry_is_ignored(self):
        # records[6] is not carried by the sealed decision.
        foreign = revocation(self.records[6], 0.0)
        for artifact in (foreign, foreign.to_bytes()):
            self.assertEqual(
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now, revocations=[artifact]
                ),
                self.decision,
            )

    def test_duplicate_pair_rejected_even_when_non_matching(self):
        foreign = revocation(self.records[6], 0.0)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[foreign, foreign.to_bytes()],
            )

    def test_future_revocation_rejected_even_when_non_matching(self):
        foreign = revocation(self.records[6], self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[foreign]
            )

    def test_bad_mac_rejected(self):
        entry = revocation(self.records[6], 0.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[entry]
            )

    def test_tampered_bytes_rejected(self):
        blob = bytearray(revocation(self.records[6], 0.0).to_bytes())
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

    def test_empty_revocation_set_still_enables_the_check(self):
        # An empty set enables revocation checking: now is required and
        # validated, and the decision passes unchanged.
        with self.assertRaises(ValueError):
            audit_reliability_policy(self.evidence, KEY, revocations=[])
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=math.nan, revocations=[]
            )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[]
            ),
            self.decision,
        )

    def test_min_ignored_on_iterable_form(self):
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[], min=999
            ),
            self.decision,
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=[], min="junk"
            ),
            self.decision,
        )

    def test_age_and_revocation_enforced_together(self):
        target = self.used[0]
        surviving = revocation(target, target.end - 1e-9)
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
                revocations=[revocation(target, target.end)],
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
        erl = self._snapshot([revocation(target, target.end)])
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
        erl = self._snapshot([revocation(target, target.end - 1e-9)])
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        erl = self._snapshot([revocation(target, target.end)])
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_non_matching_entries_are_ignored(self):
        erl = self._snapshot(
            [revocation(self.records[6], 0.0)], issued_at=0.0
        )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            ),
            self.decision,
        )

    def test_future_entry_rejected_even_when_non_matching(self):
        erl = self._snapshot(
            [revocation(self.records[6], self.now + 1.0)]
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl.to_bytes()
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

    def test_bad_min_rejected(self):
        erl = self._snapshot([], issued_at=0.0)
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_reliability_policy(
                    self.evidence, KEY, now=self.now,
                    revocations=erl, min=bad,
                )

    def test_future_snapshot_rejected(self):
        erl = self._snapshot([], issued_at=self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_wrong_key_rejected(self):
        erl = self._snapshot([], key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=erl
            )

    def test_malformed_snapshot_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=b"not json"
            )

    def test_inner_entry_mac_checked(self):
        target = self.used[0]
        bogus = BoundEvidenceRevocation(
            1, target.round_index, target.nonce, 0.0, b"\x01" * 32
        )
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": float(self.now),
            "entries": [
                {
                    "version": 1,
                    "round_index": bogus.round_index,
                    "nonce": bogus.nonce.hex(),
                    "revoked_at": 0.0,
                    "mac": "01" * 32,
                }
            ],
        }
        outer = hmac.new(
            KEY,
            b"NPERL1"
            + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = EvidenceRevocationList(
            1, 0, float(self.now), (bogus,), outer
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, revocations=forged
            )

    def test_age_and_snapshot_enforced_together(self):
        target = self.used[0]
        surviving = self._snapshot(
            [revocation(target, target.end - 1e-9)], issued_at=0.0
        )
        with self.assertRaises(ValueError):
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, max_age=0.5,
                revocations=surviving,
            )
        self.assertEqual(
            audit_reliability_policy(
                self.evidence, KEY, now=self.now, max_age=10.0,
                revocations=surviving,
            ),
            self.decision,
        )

    def test_snapshot_check_touches_no_state(self):
        erl = self._snapshot([], issued_at=0.0)
        before = self.verifier.round_count
        audit_reliability_policy(
            self.evidence, KEY, now=self.now, revocations=erl
        )
        audit_reliability_policy(
            self.evidence, KEY, now=self.now, revocations=erl
        )
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
