import unittest

from nearproof import (
    BoundEvidence,
    Challenge,
    ChallengeStateError,
    Measurement,
    Prover,
    Verifier,
    audit_bound,
    audit_bound_policy,
    context_digest,
)

KEY = b"shared-secret-key"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def fixture(**kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    kwargs.setdefault("replay_protection", True)
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


def bound_round(verifier, prover, clock, trip=0.5):
    """Run one successful bound round and return its BoundEvidence."""
    challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
    started = clock.now
    response = prover.reveal(challenge, CONTEXT, OPENING)
    clock.now += trip
    return verifier.verify_bound(challenge, response, started, opening=OPENING)


class VerifyBoundOrderingTest(unittest.TestCase):
    def test_unknown_challenge_state_error_precedes_opening_type_error(self):
        _, _, verifier = fixture()
        foreign = Challenge(round_index=1, nonce=b"n" * 16)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(foreign, b"r" * 32, 0.0, opening=None)

    def test_consumed_challenge_state_error_precedes_opening_type_error(self):
        clock, prover, verifier = fixture()
        bound_round(verifier, prover, clock)
        # The challenge object registered above was consumed by the round;
        # issue and consume another to test with a live reference.
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        started = clock.now
        response = prover.reveal(challenge, CONTEXT, OPENING)
        verifier.verify_bound(challenge, response, started, opening=OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(challenge, response, started, opening=None)

    def test_revoked_challenge_state_error_precedes_opening_type_error(self):
        _, _, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(challenge, b"r" * 32, 0.0, opening=None)

    def test_expired_challenge_state_error_precedes_opening_type_error(self):
        clock, _, verifier = fixture(challenge_ttl_seconds=1.0)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        clock.now += 2.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(challenge, b"r" * 32, 0.0, opening=None)

    def test_none_opening_type_error_leaves_challenge_pending(self):
        clock, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        with self.assertRaises(TypeError):
            verifier.verify_bound(challenge, b"r" * 32, clock.now, opening=None)
        # Still pending: a correct reveal verifies afterwards.
        started = clock.now
        response = prover.reveal(challenge, CONTEXT, OPENING)
        record = verifier.verify_bound(challenge, response, started, opening=OPENING)
        self.assertIsInstance(record, BoundEvidence)

    def test_bad_opening_leaves_challenge_pending(self):
        clock, prover, verifier = fixture()
        for bad_opening in (b"short", b"x" * 32):
            with self.subTest(opening=bad_opening):
                challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
                with self.assertRaises(ValueError):
                    verifier.verify_bound(
                        challenge, b"r" * 32, clock.now, opening=bad_opening
                    )
                started = clock.now
                response = prover.reveal(challenge, CONTEXT, OPENING)
                record = verifier.verify_bound(
                    challenge, response, started, opening=OPENING
                )
                self.assertIsInstance(record, BoundEvidence)

    def test_legacy_verifier_none_opening_still_type_error(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=False)
        challenge = Challenge(round_index=1, nonce=b"n" * 16)
        with self.assertRaises(TypeError):
            verifier.verify_bound(challenge, b"r" * 32, 0.0, opening=None)

    def test_success_path_unchanged(self):
        clock, prover, verifier = fixture()
        record = bound_round(verifier, prover, clock)
        self.assertEqual(record.context, CONTEXT)
        self.assertEqual(record.digest, DIGEST)
        self.assertEqual(record.opening, OPENING)
        measurement = audit_bound(record, KEY)
        self.assertIsInstance(measurement, Measurement)
        self.assertAlmostEqual(measurement.elapsed_seconds, 0.5)


class AuditBoundPolicyTest(unittest.TestCase):
    def setUp(self):
        self.clock, self.prover, self.verifier = fixture()
        self.record = bound_round(self.verifier, self.prover, self.clock)
        self.end = self.record.evidence.end

    def test_max_age_none_ignores_now(self):
        for now in (None, 0.0, 1e9, "junk", object()):
            with self.subTest(now=now):
                measurement = audit_bound_policy(self.record, KEY, now=now)
                self.assertIsInstance(measurement, Measurement)

    def test_max_age_none_matches_audit_bound(self):
        expected = audit_bound(self.record, KEY)
        self.assertEqual(audit_bound_policy(self.record, KEY), expected)

    def test_accepts_canonical_bytes(self):
        blob = self.record.to_bytes()
        measurement = audit_bound_policy(
            blob, KEY, now=self.end, max_age=10.0
        )
        self.assertIsInstance(measurement, Measurement)

    def test_now_required_when_max_age_set(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(self.record, KEY, max_age=10.0)

    def test_invalid_max_age_rejected(self):
        for value in (True, False, -1.0, float("inf"), float("nan"), "10"):
            with self.subTest(max_age=value):
                with self.assertRaises(ValueError):
                    audit_bound_policy(
                        self.record, KEY, now=self.end, max_age=value
                    )

    def test_invalid_now_rejected(self):
        for value in (True, False, float("inf"), float("nan"), "10"):
            with self.subTest(now=value):
                with self.assertRaises(ValueError):
                    audit_bound_policy(
                        self.record, KEY, now=value, max_age=10.0
                    )

    def test_closed_interval_boundaries_valid(self):
        for now in (self.end, self.end + 10.0):
            with self.subTest(now=now):
                measurement = audit_bound_policy(
                    self.record, KEY, now=now, max_age=10.0
                )
                self.assertIsInstance(measurement, Measurement)

    def test_zero_max_age_accepts_only_exact_end(self):
        measurement = audit_bound_policy(self.record, KEY, now=self.end, max_age=0.0)
        self.assertIsInstance(measurement, Measurement)
        with self.assertRaises(ValueError):
            audit_bound_policy(self.record, KEY, now=self.end + 1e-9, max_age=0.0)

    def test_future_evidence_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(self.record, KEY, now=self.end - 1e-9, max_age=10.0)

    def test_over_age_evidence_rejected(self):
        with self.assertRaises(ValueError):
            audit_bound_policy(
                self.record, KEY, now=self.end + 10.0 + 1e-9, max_age=10.0
            )

    def test_cryptographic_failure_surfaces_first(self):
        tampered = bytearray(self.record.to_bytes())
        tampered[-3] = ord("0") if tampered[-3] != ord("0") else ord("1")
        with self.assertRaises(ValueError):
            audit_bound_policy(bytes(tampered), KEY, max_age=10.0)
        with self.assertRaises(ValueError):
            audit_bound_policy(self.record, b"wrong-key", now=self.end, max_age=10.0)

    def test_audit_is_pure(self):
        # Auditing consumes nothing: the same record verifies repeatedly and
        # the verifier can still run new rounds.
        for _ in range(2):
            audit_bound_policy(self.record, KEY, now=self.end, max_age=10.0)
        bound_round(self.verifier, self.prover, self.clock)


if __name__ == "__main__":
    unittest.main()
