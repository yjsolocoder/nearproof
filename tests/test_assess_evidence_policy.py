import unittest

from nearproof import (
    BoundEvidenceRevocation,
    Prover,
    RangeDecision,
    Verifier,
    _bound_revocation_mac,
    _bound_revocation_payload,
    audit_assess_evidence,
    audit_assess_evidence_policy,
    audit_bound_policy,
    context_digest,
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
    return verifier, records


class AuditAssessEvidencePolicyDefaultTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_assess_evidence(self.records, 100.0, KEY)
        self.data = self.evidence.to_bytes()

    def test_defaults_match_plain_audit(self):
        expected = audit_assess_evidence(self.evidence, KEY)
        decision = audit_assess_evidence_policy(self.evidence, KEY)
        self.assertIsInstance(decision, RangeDecision)
        self.assertEqual(decision, expected)

    def test_defaults_match_plain_audit_for_bytes(self):
        self.assertEqual(
            audit_assess_evidence_policy(self.data, KEY),
            audit_assess_evidence(self.data, KEY),
        )

    def test_now_ignored_when_no_policy_enabled(self):
        for now in (None, 0.0, 1e9, "junk", object()):
            with self.subTest(now=now):
                decision = audit_assess_evidence_policy(
                    self.evidence, KEY, now=now
                )
                self.assertEqual(
                    decision, audit_assess_evidence(self.evidence, KEY)
                )

    def test_wrong_shape_arguments_raise_type_error(self):
        for bad in ("x", 123, None, object(), [self.data], bytearray()):
            with self.assertRaises(TypeError, msg=bad):
                audit_assess_evidence_policy(bad, KEY)
        for bad_key in ("key", None, 123, bytearray(b"x")):
            with self.assertRaises(TypeError, msg=bad_key):
                audit_assess_evidence_policy(self.evidence, bad_key)

    def test_cryptographic_failure_surfaces_before_policy(self):
        tampered = bytearray(self.data)
        tampered[-3] = ord("0") if tampered[-3] != ord("0") else ord("1")
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                bytes(tampered), KEY, now=1.0, max_age=10.0
            )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, OTHER_KEY, now=1.0, max_age=10.0
            )

    def test_policy_touches_no_verifier_state(self):
        before = self.verifier.round_count
        audit_assess_evidence_policy(self.evidence, KEY)
        audit_assess_evidence_policy(self.data, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


class AuditAssessEvidencePolicyAgeTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_assess_evidence(self.records, 100.0, KEY)
        self.baseline = max(record.end for record in self.records)

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(self.evidence, KEY, max_age=10.0)

    def test_invalid_max_age_rejected(self):
        for value in (True, False, -1.0, float("inf"), float("nan"), "10"):
            with self.subTest(max_age=value):
                with self.assertRaises(ValueError):
                    audit_assess_evidence_policy(
                        self.evidence, KEY, now=self.baseline, max_age=value
                    )

    def test_invalid_now_rejected(self):
        for value in (True, False, float("inf"), float("nan"), "10"):
            with self.subTest(now=value):
                with self.assertRaises(ValueError):
                    audit_assess_evidence_policy(
                        self.evidence, KEY, now=value, max_age=10.0
                    )

    def test_baseline_is_latest_sample_end(self):
        # The newest sample ends at self.baseline; an earlier sample's end
        # must not be the baseline, so now just before the newest end but
        # after every older end is still a future-dated decision.
        earlier = max(record.end for record in self.records[:-1])
        self.assertLess(earlier, self.baseline)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=earlier, max_age=10.0
            )

    def test_closed_interval_boundaries_valid(self):
        for now in (self.baseline, self.baseline + 10.0):
            with self.subTest(now=now):
                decision = audit_assess_evidence_policy(
                    self.evidence, KEY, now=now, max_age=10.0
                )
                self.assertEqual(
                    decision, audit_assess_evidence(self.evidence, KEY)
                )

    def test_zero_max_age_accepts_only_exact_baseline(self):
        decision = audit_assess_evidence_policy(
            self.evidence, KEY, now=self.baseline, max_age=0.0
        )
        self.assertIsInstance(decision, RangeDecision)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.baseline + 1e-9, max_age=0.0
            )

    def test_future_baseline_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.baseline - 1e-9, max_age=10.0
            )

    def test_over_age_decision_rejected(self):
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY,
                now=self.baseline + 10.0 + 1e-9,
                max_age=10.0,
            )

    def test_accepts_canonical_bytes(self):
        decision = audit_assess_evidence_policy(
            self.evidence.to_bytes(), KEY, now=self.baseline, max_age=10.0
        )
        self.assertIsInstance(decision, RangeDecision)


class AuditAssessEvidencePolicyRevocationTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.evidence = seal_assess_evidence(self.records, 100.0, KEY)
        self.now = max(record.end for record in self.records) + 1.0
        self.target = self.records[2]

    def revoke(self, record, revoked_at, key=KEY):
        return revoke_evidence(record, revoked_at, key)

    def test_now_required_when_revocations_set(self):
        revocation = self.revoke(self.target, self.target.end)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, revocations=[revocation]
            )
        # An empty revocation set still enables the option.
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(self.evidence, KEY, revocations=[])

    def test_revoked_sample_voids_decision(self):
        # Completion at exactly the revocation time is not "after" it.
        revocation = self.revoke(self.target, self.target.end)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_sample_completed_after_revocation_survives(self):
        revocation = self.revoke(self.target, self.target.end - 1e-9)
        decision = audit_assess_evidence_policy(
            self.evidence, KEY, now=self.now, revocations=[revocation]
        )
        self.assertEqual(decision, audit_assess_evidence(self.evidence, KEY))

    def test_unrelated_revocation_ignored(self):
        _verifier, foreign = make_evidence_list(1, key=KEY, step=1e-5)
        revocation = self.revoke(foreign[0], self.now)
        decision = audit_assess_evidence_policy(
            self.evidence, KEY, now=self.now, revocations=[revocation]
        )
        self.assertEqual(decision, audit_assess_evidence(self.evidence, KEY))

    def test_mixed_objects_and_bytes_entries(self):
        first = self.revoke(self.records[0], self.records[0].end - 1e-9)
        second = self.revoke(self.target, self.target.end - 1e-9).to_bytes()
        decision = audit_assess_evidence_policy(
            self.evidence, KEY, now=self.now, revocations=[first, second]
        )
        self.assertIsInstance(decision, RangeDecision)

    def test_bytes_entry_voids_decision(self):
        blob = self.revoke(self.target, self.target.end).to_bytes()
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[blob]
            )

    def test_duplicate_round_entries_rejected(self):
        first = self.revoke(self.target, self.target.end - 1e-9)
        second = self.revoke(self.target, self.target.end - 2e-9).to_bytes()
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[first, second]
            )

    def test_future_revocation_rejected(self):
        revocation = self.revoke(self.target, self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )
        # Even an unrelated future-dated entry is rejected.
        _verifier, foreign = make_evidence_list(1, key=KEY, step=1e-5)
        revocation = self.revoke(foreign[0], self.now + 1.0)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_wrong_key_revocation_rejected(self):
        revocation = self.revoke(self.target, self.target.end, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[revocation]
            )

    def test_tampered_revocation_rejected(self):
        revocation = self.revoke(self.target, self.target.end)
        tampered = BoundEvidenceRevocation(
            version=1,
            round_index=revocation.round_index,
            nonce=revocation.nonce,
            revoked_at=revocation.revoked_at,
            mac=bytes(b ^ 0xFF for b in revocation.mac),
        )
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY, now=self.now, revocations=[tampered]
            )

    def test_invalid_revocation_items_rejected(self):
        for bad in ("x", 123, None, object(), b"not json"):
            with self.subTest(item=bad):
                with self.assertRaises(ValueError):
                    audit_assess_evidence_policy(
                        self.evidence, KEY, now=self.now, revocations=[bad]
                    )

    def test_non_iterable_revocations_rejected(self):
        for bad in (123, 5.0, object()):
            with self.subTest(revocations=bad):
                with self.assertRaises(ValueError):
                    audit_assess_evidence_policy(
                        self.evidence, KEY, now=self.now, revocations=bad
                    )

    def test_revocation_and_max_age_compose(self):
        revocation = self.revoke(self.target, self.target.end - 1e-9)
        decision = audit_assess_evidence_policy(
            self.evidence, KEY,
            now=self.now,
            max_age=10.0,
            revocations=[revocation],
        )
        self.assertIsInstance(decision, RangeDecision)
        with self.assertRaises(ValueError):
            audit_assess_evidence_policy(
                self.evidence, KEY,
                now=self.now,
                max_age=0.1,
                revocations=[revocation],
            )

    def test_signed_record_enters_existing_policy_entry(self):
        # A record signed by revoke_evidence for one round of a bound
        # evidence is accepted by audit_bound_policy's revocations option.
        clock = AutoClock()
        prover = Prover(KEY)
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        started = clock()
        response = prover.reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(challenge, response, started, opening=OPENING)
        revocation = revoke_evidence(bound.evidence, bound.evidence.end, KEY)
        with self.assertRaises(ValueError):
            audit_bound_policy(
                bound, KEY,
                now=bound.evidence.end,
                revocations=[revocation],
            )


class RevokeEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.record = self.records[2]

    def test_signs_per_round_record(self):
        revocation = revoke_evidence(self.record, 10.0, KEY)
        self.assertIsInstance(revocation, BoundEvidenceRevocation)
        self.assertEqual(revocation.version, 1)
        self.assertEqual(revocation.round_index, self.record.round_index)
        self.assertEqual(revocation.nonce, self.record.nonce)
        self.assertEqual(revocation.revoked_at, 10.0)
        self.assertEqual(len(revocation.mac), 32)
        expected = _bound_revocation_mac(
            KEY, _bound_revocation_payload(revocation)
        )
        self.assertEqual(revocation.mac, expected)

    def test_accepts_canonical_bytes(self):
        from_object = revoke_evidence(self.record, 10.0, KEY)
        from_bytes = revoke_evidence(self.record.to_bytes(), 10.0, KEY)
        self.assertEqual(from_bytes, from_object)

    def test_signed_record_round_trips(self):
        revocation = revoke_evidence(self.record, 10, KEY)
        self.assertEqual(
            BoundEvidenceRevocation.from_bytes(revocation.to_bytes()),
            revocation,
        )

    def test_all_violations_raise_value_error(self):
        bad_samples = ("x", 123, None, object(), b"not json", b"{}")
        for bad in bad_samples:
            with self.subTest(sample=bad):
                with self.assertRaises(ValueError):
                    revoke_evidence(bad, 10.0, KEY)
        for bad_key in ("key", None, 123, b"", bytearray(b"x")):
            with self.subTest(key=bad_key):
                with self.assertRaises(ValueError):
                    revoke_evidence(self.record, 10.0, bad_key)
        bad_times = (True, False, -1.0, float("inf"), float("nan"), "10", None)
        for bad in bad_times:
            with self.subTest(revoked_at=bad):
                with self.assertRaises(ValueError):
                    revoke_evidence(self.record, bad, KEY)

    def test_signing_touches_no_verifier_state(self):
        before = self.verifier.round_count
        revoke_evidence(self.record, 10.0, KEY)
        revoke_evidence(self.record.to_bytes(), 10.0, KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
