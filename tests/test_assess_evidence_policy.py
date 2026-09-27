import json
import math
import unittest

from nearproof import (
    AssessEvidence,
    BoundEvidenceRevocation,
    Measurement,
    Prover,
    Verifier,
    assess,
    audit_assess_evidence,
    audit_assess_evidence_policy,
    audit_bound_policy,
    context_digest,
    revoke_bound,
    revoke_evidence,
    seal_assess_evidence,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


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
    return verifier, prover, records


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        self.verifier, self.prover, self.records = make_evidence_list(7)
        self.used = self.records[:6]
        self.evidence = seal_assess_evidence(self.used, 100.0, KEY)
        self.data = self.evidence.to_bytes()
        self.latest_end = max(record.end for record in self.used)
        self.now = self.latest_end + 1.0
        self.decision = audit_assess_evidence(self.evidence, KEY)


class AssessEvidencePolicyDefaultTest(PolicyFixture):
    def test_default_matches_existing_review_item_for_item(self):
        for artifact in (self.evidence, self.data):
            self.assertEqual(
                audit_assess_evidence_policy(artifact, KEY),
                audit_assess_evidence(artifact, KEY),
            )

    def test_default_returns_recorded_decision(self):
        decision = audit_assess_evidence_policy(self.evidence, KEY)
        self.assertEqual(decision.sample_count, self.evidence.sample_count)
        self.assertEqual(decision.upper_bound, self.evidence.upper_bound)
        self.assertIs(decision.accepted, self.evidence.accepted)
        self.assertEqual(decision, assess(self.used, 100.0, key=KEY))

    def test_default_ignores_now_entirely(self):
        # No clock is read and a garbage/absurd now changes nothing.
        self.assertEqual(
            audit_assess_evidence_policy(self.evidence, KEY, now="garbage"),
            self.decision,
        )
        self.assertEqual(
            audit_assess_evidence_policy(self.evidence, KEY, now=math.nan),
            self.decision,
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.data, KEY, now=None, max_age=None, revocations=None
            ),
            self.decision,
        )

    def test_default_rejected_conclusion_still_round_trips(self):
        rejected = seal_assess_evidence(self.used, 1.0, KEY)
        decision = audit_assess_evidence_policy(rejected, KEY)
        self.assertIs(decision.accepted, False)

    def test_shape_errors_precede_policy(self):
        for bad in ("x", 123, None, object(), [self.data], 7, bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence_policy(bad, KEY, now=self.now, max_age=1.0)
        for bad in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence_policy(self.evidence, bad, now=self.now, max_age=1.0)

    def test_crypto_failure_precedes_policy(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, OTHER_KEY, now=self.now, max_age=1.0
            )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, b"", now=self.now, max_age=1.0
            )
        outer = json.loads(self.data)
        outer[6] = not outer[6]
        tampered = json.dumps(outer, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(tampered, KEY, now=self.now, max_age=1.0)

    def test_audit_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_assess_evidence_policy(self.evidence, KEY)
        audit_assess_evidence_policy(
            self.data, KEY, now=self.now, max_age=10.0, revocations=[]
        )
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class AssessEvidencePolicyAgeTest(PolicyFixture):
    def test_closed_interval_boundaries_are_valid(self):
        # now == latest_end with max_age 0 and now == latest_end + max_age.
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.latest_end, max_age=0.0
            ),
            self.decision,
        )
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, max_age=1.0
            ),
            self.decision,
        )

    def test_future_baseline_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence,
                KEY,
                now=self.latest_end - 1e-12,
                max_age=100.0,
            )

    def test_over_age_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, max_age=0.5
            )

    def test_baseline_is_the_latest_completed_sample(self):
        # Revoking/removing the latest sample via a smaller sealed set moves
        # the baseline: seal over records[:6] without records[5].
        subset = self.records[:5]
        sealed = seal_assess_evidence(subset, 100.0, KEY, min_samples=5)
        latest = max(record.end for record in subset)
        self.assertEqual(
            audit_assess_evidence_policy(sealed, KEY, now=latest, max_age=0.0),
            audit_assess_evidence(sealed, KEY),
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                sealed, KEY, now=latest - 1e-12, max_age=100.0
            )

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(self.evidence, KEY, max_age=1.0)

    def test_bad_now_rejected(self):
        for bad in ("1", None, True, False, math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=bad, max_age=1.0
                )

    def test_bad_max_age_rejected(self):
        for bad in ("1", True, False, -0.1, math.nan, math.inf):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, max_age=bad
                )

    def test_integer_now_and_max_age(self):
        latest = self.latest_end
        decision = audit_assess_evidence_policy(
            self.evidence, KEY, now=math.ceil(latest), max_age=1
        )
        self.assertEqual(decision, self.decision)


class AssessEvidencePolicyRevocationTest(PolicyFixture):
    def test_sample_completed_after_revocation_survives(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            ),
            self.decision,
        )

    def test_sample_completed_at_revocation_moment_voids(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_sample_completed_before_revocation_moment_voids(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end + 10.0, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=target.end + 20.0,
                revocations=[revocation],
            )

    def test_latest_completed_sample_voids_too(self):
        target = max(self.used, key=lambda record: record.end)
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_strictly_later_samples_unaffected_by_other_revocation(self):
        # Revoke an early round at an instant after it completed but before
        # the later rounds did: rounds completed strictly after that instant
        # are unaffected, while the decision still carrying the early round
        # is voided.
        early = self.used[0]
        later_records = self.used[2:]
        later_sealed = seal_assess_evidence(
            later_records, 100.0, KEY, min_samples=3
        )
        revoked_at = (early.end + self.used[1].end) / 2.0
        revocation = revoke_evidence(early, revoked_at, KEY)
        self.assertEqual(
            audit_assess_evidence_policy(
                later_sealed, KEY, now=self.now, revocations=[revocation]
            ),
            audit_assess_evidence(later_sealed, KEY),
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_bytes_entries_accepted_and_match_objects(self):
        target = self.used[2]
        revocation = revoke_evidence(target, target.end - 1e-9, KEY)
        self.assertEqual(
            audit_assess_evidence_policy(
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
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=revocations
            ),
            self.decision,
        )

    def test_non_matching_entry_is_ignored(self):
        # records[6] is not carried by the sealed decision.
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        for artifact in (foreign, foreign.to_bytes()):
            self.assertEqual(
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[artifact]
                ),
                self.decision,
            )

    def test_duplicate_pair_rejected_even_when_non_matching(self):
        foreign = revoke_evidence(self.records[6], 0.0, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                revocations=[foreign, foreign.to_bytes()],
            )

    def test_future_revocation_rejected_even_when_non_matching(self):
        foreign = revoke_evidence(self.records[6], self.now + 1.0, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[foreign]
            )

    def test_bad_mac_rejected(self):
        revocation = revoke_evidence(self.records[6], 0.0, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_tampered_bytes_rejected(self):
        blob = bytearray(revoke_evidence(self.records[6], 0.0, KEY).to_bytes())
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[bytes(blob)]
            )

    def test_malformed_revocation_bytes_rejected(self):
        for bad in (b"not json", b"{}", b"[]", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[bad]
                )

    def test_wrong_element_type_rejected(self):
        for bad in ("x", 123, None, object(), b"x"[0:0]):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=[bad]
                )

    def test_non_iterable_revocations_rejected(self):
        for bad in (7, 1.5, object()):
            with self.assertRaises(ValueError, msg=bad):
                audit_assess_evidence_policy(
                    self.evidence, KEY, now=self.now, revocations=bad
                )

    def test_empty_revocation_set_requires_now(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, revocations=[]
            )

    def test_revocation_bytes_input_decision(self):
        target = self.used[0]
        revocation = revoke_evidence(target, target.end, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.data, KEY, now=self.now, revocations=[revocation]
            )

    def test_age_and_revocation_enforced_together(self):
        target = self.used[0]
        surviving = revoke_evidence(target, target.end - 1e-9, KEY)
        # Freshness fails first/last regardless of order: over-age decision.
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=0.5,
                revocations=[surviving],
            )
        # Both satisfied.
        self.assertEqual(
            audit_assess_evidence_policy(
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
            audit_assess_evidence_policy(
                self.evidence,
                KEY,
                now=self.now,
                max_age=10.0,
                revocations=[revoke_evidence(target, target.end, KEY)],
            )


class RevokeEvidenceTest(PolicyFixture):
    def test_returns_bound_evidence_revocation_record(self):
        target = self.used[0]
        revocation = revoke_evidence(target, 12.5, KEY)
        self.assertIsInstance(revocation, BoundEvidenceRevocation)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.round_index, target.round_index)
        self.assertEqual(revocation.nonce, target.nonce)
        self.assertEqual(revocation.revoked_at, 12.5)
        self.assertEqual(len(revocation.mac), 32)

    def test_accepts_object_and_canonical_bytes(self):
        target = self.used[0]
        self.assertEqual(
            revoke_evidence(target, 3.0, KEY),
            revoke_evidence(target.to_bytes(), 3.0, KEY),
        )

    def test_bytes_round_trip_through_bound_revocation_encoding(self):
        revocation = revoke_evidence(self.used[0], 7.0, KEY)
        self.assertEqual(
            BoundEvidenceRevocation.from_bytes(revocation.to_bytes()),
            revocation,
        )

    def test_integer_revoked_at_preserved(self):
        revocation = revoke_evidence(self.used[0], 3, KEY)
        self.assertEqual(revocation.revoked_at, 3)
        self.assertEqual(
            BoundEvidenceRevocation.from_bytes(revocation.to_bytes()),
            revocation,
        )

    def test_equivalent_to_revoke_bound_for_same_round(self):
        # The signed NPBR1 record depends only on (round_index, nonce,
        # revoked_at), so the two signing entries interoperate.
        challenge = self.verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        started = self.verifier.clock()
        bound = self.verifier.verify_bound(
            challenge,
            self.prover.reveal(challenge, CONTEXT, OPENING),
            started,
            opening=OPENING,
        )
        self.assertEqual(
            revoke_evidence(bound.evidence, 4.0, KEY),
            revoke_bound(bound, 4.0, KEY),
        )

    def test_signed_record_works_against_existing_bound_policy(self):
        challenge = self.verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        started = self.verifier.clock()
        bound = self.verifier.verify_bound(
            challenge,
            self.prover.reveal(challenge, CONTEXT, OPENING),
            started,
            opening=OPENING,
        )
        revocation = revoke_evidence(bound.evidence, bound.evidence.end, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                bound,
                KEY,
                now=bound.evidence.end + 1.0,
                revocations=[revocation],
            )
        surviving = revoke_evidence(
            bound.evidence, bound.evidence.end - 1e-9, KEY
        )
        measurement = audit_bound_policy(
            bound,
            KEY,
            now=bound.evidence.end + 1.0,
            revocations=[surviving],
        )
        self.assertEqual(measurement.round_index, bound.evidence.round_index)

    def test_signed_record_enters_new_policy_entry(self):
        revocation = revoke_evidence(self.used[0], self.used[0].end, KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_shape_and_value_violations_all_value_errors(self):
        good = self.used[0]
        measurement = Measurement(
            round_index=1,
            nonce=b"n" * 16,
            response=b"r" * 32,
            elapsed_seconds=0.1,
            distance_meters=1.0,
        )
        for bad_sample in (
            "x",
            123,
            None,
            object(),
            [good],
            (good,),
            measurement,
            self.evidence,
            b"not json",
            b"{}",
            b" " + good.to_bytes(),
        ):
            with self.assertRaises(ValueError, msg=repr(bad_sample)):
                revoke_evidence(bad_sample, 0.0, KEY)
        for bad_key in ("key", None, 123, bytearray(b"x"), b""):
            with self.assertRaises(ValueError, msg=repr(bad_key)):
                revoke_evidence(good, 0.0, bad_key)
        for bad_time in (True, False, -0.1, math.nan, math.inf, "1", None):
            with self.assertRaises(ValueError, msg=repr(bad_time)):
                revoke_evidence(good, bad_time, KEY)

    def test_signing_touches_no_verifier_state(self):
        before = self.verifier.round_count
        revoke_evidence(self.used[0], 0.0, KEY)
        revoke_evidence(self.used[0].to_bytes(), 1.0, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
