"""Lifecycle combination tests for the delay-bound challenge extension.

These tests exercise the challenge lifecycle end to end — issue, fail,
retry, verify, revoke — only through the public entry points
(``new_delay_challenge``, ``verify``, ``verify_bound``, ``verify_evidence``,
``verify_delay_bound``, ``revoke`` and ``audit_delay_bound``) with a
controllable clock. The focus is on combinations the single-shot tests do
not pin down:

* a challenge may see any number of failed attempts (``ValueError``) and
  still be verified successfully inside its validity window;
* the delay bound and the TTL deadline interact at their boundaries for
  TTL shorter than, equal to and longer than the delay bound;
* expiry is terminal, even if the clock is rolled backwards;
* verify/revoke and verify/verify races settle exactly one winner and the
  observable result matches one of the two serial orders.

No private registry or internal signing helpers are touched.
"""

import threading
import unittest

from nearproof import (
    ChallengeStateError,
    DelayBoundEvidence,
    Measurement,
    Prover,
    Verifier,
    audit_delay_bound,
    context_digest,
)

KEY = b"shared-secret-key"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
OTHER_OPENING = b"p" * 32
DIGEST = context_digest(CONTEXT, OPENING)

# Exactly representable time points so boundary comparisons are exact.
START = 100.0


class SteppedClock:
    """A clock the test moves by hand; never advances on its own."""

    def __init__(self, start: float = START) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def make_verifier(*, ttl=None, clock=None):
    clock = clock or SteppedClock()
    verifier = Verifier(
        KEY,
        clock=clock,
        replay_protection=True,
        challenge_ttl_seconds=ttl,
    )
    return clock, verifier


def issue_delay_challenge(verifier, *, max_delay=0.5):
    return verifier.new_delay_challenge(
        CONTEXT, DIGEST, max_delay_seconds=max_delay
    )


class FailureThenSuccessLifecycleTest(unittest.TestCase):
    """Failed attempts never consume; the challenge stays retryable."""

    def setUp(self):
        self.clock, self.verifier = make_verifier(ttl=10.0)
        self.prover = Prover(KEY)
        self.challenge, self.issued_at = issue_delay_challenge(
            self.verifier, max_delay=0.5
        )
        self.response = self.prover.reveal(self.challenge, CONTEXT, OPENING)

    def verify(self, **overrides):
        args = dict(
            challenge=self.challenge,
            response=self.response,
            started_at=self.issued_at,
            opening=OPENING,
        )
        args.update(overrides)
        return self.verifier.verify_delay_bound(
            args["challenge"],
            args["response"],
            args["started_at"],
            opening=args["opening"],
        )

    def test_interleaved_failures_then_success_then_terminal(self):
        # 1. Wrong response bytes.
        self.clock.now = self.issued_at + 0.1
        forged = bytes(255 - b for b in bytearray(self.response))
        with self.assertRaises(ValueError):
            self.verify(response=forged)
        # 2. Wrong opening (commitment mismatch).
        with self.assertRaises(ValueError):
            self.verify(opening=OTHER_OPENING)
        # 3. started_at not equal to the issued_at returned at issue time.
        with self.assertRaises(ValueError):
            self.verify(started_at=self.issued_at + 0.1)
        # 4. Delay beyond the bound but still inside the TTL.
        self.clock.now = self.issued_at + 0.75
        with self.assertRaises(ValueError):
            self.verify()
        # None of the above consumed the challenge: back inside the delay
        # bound (and well inside the TTL) the correct round succeeds.
        self.clock.now = self.issued_at + 0.2
        record = self.verify()
        self.assertIsInstance(record, DelayBoundEvidence)
        self.assertEqual(record.evidence.start, self.issued_at)
        self.assertEqual(record.evidence.end, self.clock.now)
        self.assertAlmostEqual(record.evidence.elapsed, 0.2)
        # Success is terminal: every entry point now refuses the challenge.
        with self.assertRaises(ChallengeStateError):
            self.verify()
        with self.assertRaises(ChallengeStateError):
            self.verifier.revoke(self.challenge)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify(
                self.challenge, self.response, self.issued_at, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_bound(
                self.challenge, self.response, self.issued_at, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_evidence(
                self.challenge, self.response, self.issued_at
            )

    def test_failure_then_revoke_then_no_verify(self):
        # A failed attempt leaves the challenge pending, so revoke is still
        # available; after revoke, verification is refused.
        self.clock.now = self.issued_at + 0.1
        with self.assertRaises(ValueError):
            self.verify(response=b"r" * 32)
        self.verifier.revoke(self.challenge)
        with self.assertRaises(ChallengeStateError):
            self.verify()
        with self.assertRaises(ChallengeStateError):
            self.verifier.revoke(self.challenge)


class DelayAndTtlBoundaryTest(unittest.TestCase):
    """The delay bound and the TTL deadline are independent limits."""

    def _round(self, *, ttl, max_delay, verify_at):
        clock, verifier = make_verifier(ttl=ttl)
        prover = Prover(KEY)
        challenge, issued_at = issue_delay_challenge(
            verifier, max_delay=max_delay
        )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = verify_at
        return verifier, challenge, response, issued_at

    def test_ttl_longer_than_bound_delay_equal_to_bound_succeeds(self):
        # delay == max_delay exactly, and the TTL deadline is still ahead.
        verifier, challenge, response, issued_at = self._round(
            ttl=1.0, max_delay=0.5, verify_at=START + 0.5
        )
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertEqual(record.evidence.elapsed, 0.5)
        self.assertEqual(record.max_delay_seconds, 0.5)

    def test_ttl_longer_than_bound_past_bound_is_value_error_not_expiry(self):
        # Inside the TTL but past the delay bound: ValueError, and the
        # challenge is not consumed by the failed attempt.
        verifier, challenge, response, issued_at = self._round(
            ttl=1.0, max_delay=0.5, verify_at=START + 0.75
        )
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        verifier.clock.now = START + 0.25
        self.assertIsInstance(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ),
            DelayBoundEvidence,
        )

    def test_ttl_equal_to_bound_deadline_moment_is_state_error(self):
        # At verify time the delay would equal the bound, but the clock has
        # also reached the TTL deadline: expiry wins as ChallengeStateError.
        verifier, challenge, response, issued_at = self._round(
            ttl=0.5, max_delay=0.5, verify_at=START + 0.5
        )
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_ttl_equal_to_bound_just_before_deadline_succeeds(self):
        verifier, challenge, response, issued_at = self._round(
            ttl=0.5, max_delay=0.5, verify_at=START + 0.25
        )
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertEqual(record.evidence.elapsed, 0.25)

    def test_ttl_shorter_than_bound_deadline_moment_is_state_error(self):
        # The delay is still inside the bound, but the TTL deadline comes
        # first and is terminal.
        verifier, challenge, response, issued_at = self._round(
            ttl=0.25, max_delay=0.5, verify_at=START + 0.25
        )
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_ttl_shorter_than_bound_before_deadline_succeeds(self):
        verifier, challenge, response, issued_at = self._round(
            ttl=0.25, max_delay=0.5, verify_at=START + 0.125
        )
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertEqual(record.evidence.elapsed, 0.125)

    def test_expired_challenge_stays_expired_when_clock_rolls_back(self):
        clock, verifier = make_verifier(ttl=0.5)
        prover = Prover(KEY)
        challenge, issued_at = issue_delay_challenge(verifier, max_delay=1.0)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        # Reach the deadline: the failed call pins the expired state.
        clock.now = issued_at + 0.5
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        # Rolling the clock back into the validity window revives nothing.
        clock.now = issued_at
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_expiry_pinned_by_revoke_attempt_is_terminal_too(self):
        clock, verifier = make_verifier(ttl=0.5)
        prover = Prover(KEY)
        challenge, issued_at = issue_delay_challenge(verifier, max_delay=1.0)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 0.75
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)
        clock.now = issued_at + 0.1
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class ModeMixingLifecycleTest(unittest.TestCase):
    """Legacy entry points refuse a live delay-bound challenge."""

    def test_mode_mixing_failures_leave_challenge_verifiable(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge, issued_at = issue_delay_challenge(verifier, max_delay=1.0)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 0.002
        # Every legacy verification mode is a ValueError, not consumption.
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, issued_at)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, issued_at, opening=OPENING)
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            )
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, issued_at)
        # The proper delay-bound verification still succeeds afterwards.
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        self.assertIsInstance(record, DelayBoundEvidence)


class IndependentChallengeIsolationTest(unittest.TestCase):
    """Failures and revocation on one challenge never leak into another."""

    def test_failure_on_one_challenge_does_not_affect_another(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        first, first_issued = issue_delay_challenge(verifier, max_delay=1.0)
        second, second_issued = issue_delay_challenge(verifier, max_delay=1.0)
        self.assertNotEqual(first.round_index, second.round_index)
        first_response = prover.reveal(first, CONTEXT, OPENING)
        second_response = prover.reveal(second, CONTEXT, OPENING)

        clock.now = START + 0.1
        # Repeated failures on the first challenge...
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                first, b"f" * 32, first_issued, opening=OPENING
            )
        with self.assertRaises(ValueError):
            verifier.verify_delay_bound(
                first, first_response, first_issued, opening=OTHER_OPENING
            )
        # ...leave the second one fully verifiable...
        clock.now = START + 0.2
        second_record = verifier.verify_delay_bound(
            second, second_response, second_issued, opening=OPENING
        )
        self.assertIsInstance(second_record, DelayBoundEvidence)
        # ...and the first one retryable with the correct parameters.
        clock.now = START + 0.3
        first_record = verifier.verify_delay_bound(
            first, first_response, first_issued, opening=OPENING
        )
        self.assertIsInstance(first_record, DelayBoundEvidence)
        self.assertNotEqual(
            first_record.evidence.nonce, second_record.evidence.nonce
        )

    def test_revoke_on_one_challenge_does_not_affect_another(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        first, _ = issue_delay_challenge(verifier, max_delay=1.0)
        second, second_issued = issue_delay_challenge(verifier, max_delay=1.0)
        verifier.revoke(first)
        clock.now = START + 0.1
        record = verifier.verify_delay_bound(
            second,
            prover.reveal(second, CONTEXT, OPENING),
            second_issued,
            opening=OPENING,
        )
        self.assertIsInstance(record, DelayBoundEvidence)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                first,
                prover.reveal(first, CONTEXT, OPENING),
                second_issued,
                opening=OPENING,
            )


class RaceTestBase(unittest.TestCase):
    """Helpers to run public entry points concurrently and check health."""

    def run_concurrently(self, calls):
        """Run every callable from a barrier release; return outcomes.

        Each outcome is ``("ok", value)`` or ``("error", exception)``. A
        thread that fails to finish is a test failure, never a pass.
        """
        barrier = threading.Barrier(len(calls))
        outcomes = [None] * len(calls)

        def run(index, call):
            barrier.wait()
            try:
                outcomes[index] = ("ok", call())
            except Exception as exc:  # deliberately broad: re-asserted below
                outcomes[index] = ("error", exc)

        threads = [
            threading.Thread(target=run, args=(index, call))
            for index, call in enumerate(calls)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10.0)
        for thread in threads:
            self.assertFalse(thread.is_alive(), "worker thread did not finish")
        self.assertNotIn(None, outcomes)
        return outcomes

    def split(self, outcomes):
        oks = [value for tag, value in outcomes if tag == "ok"]
        errors = [value for tag, value in outcomes if tag == "error"]
        for error in errors:
            self.assertIsInstance(
                error,
                ChallengeStateError,
                msg=f"unexpected exception from worker: {error!r}",
            )
        return oks, errors

    def assert_terminal(self, verifier, challenge, response, issued_at):
        with self.assertRaises(ChallengeStateError):
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class VerifyRevokeRaceTest(RaceTestBase):
    """A correct verify and a revoke racing on one challenge: one winner."""

    def setUp(self):
        self.clock, self.verifier = make_verifier()
        self.prover = Prover(KEY)
        self.challenge, self.issued_at = issue_delay_challenge(
            self.verifier, max_delay=1.0
        )
        self.response = self.prover.reveal(self.challenge, CONTEXT, OPENING)
        self.clock.now = self.issued_at + 0.001

    def test_serial_revoke_then_verify(self):
        self.verifier.revoke(self.challenge)
        with self.assertRaises(ChallengeStateError):
            self.verifier.verify_delay_bound(
                self.challenge, self.response, self.issued_at, opening=OPENING
            )
        self.assert_terminal(
            self.verifier, self.challenge, self.response, self.issued_at
        )

    def test_serial_verify_then_revoke(self):
        record = self.verifier.verify_delay_bound(
            self.challenge, self.response, self.issued_at, opening=OPENING
        )
        self.assertIsInstance(record, DelayBoundEvidence)
        with self.assertRaises(ChallengeStateError):
            self.verifier.revoke(self.challenge)
        self.assert_terminal(
            self.verifier, self.challenge, self.response, self.issued_at
        )

    def test_concurrent_verify_and_revoke_exactly_one_winner(self):
        for _ in range(4):
            clock, verifier = make_verifier()
            prover = Prover(KEY)
            challenge, issued_at = issue_delay_challenge(verifier, max_delay=1.0)
            response = prover.reveal(challenge, CONTEXT, OPENING)
            clock.now = issued_at + 0.001
            calls = [
                (lambda c=challenge, r=response, t=issued_at, v=verifier:
                 v.verify_delay_bound(c, r, t, opening=OPENING))
                for _ in range(8)
            ] + [
                (lambda c=challenge, v=verifier: v.revoke(c))
                for _ in range(8)
            ]
            oks, errors = self.split(self.run_concurrently(calls))
            # Exactly one call succeeds; everyone else gets
            # ChallengeStateError. Which side won is not specified.
            self.assertEqual(len(oks), 1)
            self.assertEqual(len(errors), 15)
            winner = oks[0]
            if winner is None:
                # The revoke won: no proof may exist for this challenge.
                records = [
                    value for value in oks
                    if isinstance(value, DelayBoundEvidence)
                ]
                self.assertEqual(records, [])
            else:
                # The verify won: exactly one auditable proof exists.
                self.assertIsInstance(winner, DelayBoundEvidence)
                measurement = audit_delay_bound(winner, KEY)
                self.assertIsInstance(measurement, Measurement)
                self.assertEqual(
                    measurement.elapsed_seconds, winner.evidence.elapsed
                )
            self.assert_terminal(verifier, challenge, response, issued_at)


class ConcurrentVerifyRaceTest(RaceTestBase):
    """Many correct verifies racing on one challenge: one proof only."""

    def test_at_most_one_proof_and_it_audits(self):
        clock, verifier = make_verifier()
        prover = Prover(KEY)
        challenge, issued_at = issue_delay_challenge(verifier, max_delay=1.0)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 0.001
        calls = [
            (lambda: verifier.verify_delay_bound(
                challenge, response, issued_at, opening=OPENING
            ))
            for _ in range(16)
        ]
        oks, errors = self.split(self.run_concurrently(calls))
        self.assertEqual(len(oks), 1)
        self.assertEqual(len(errors), 15)
        record = oks[0]
        self.assertIsInstance(record, DelayBoundEvidence)
        # The single winning proof audits clean, as object and as bytes.
        measurement = audit_delay_bound(record, KEY)
        self.assertEqual(measurement, audit_delay_bound(record.to_bytes(), KEY))
        self.assert_terminal(verifier, challenge, response, issued_at)


class AuditConsistencyTest(unittest.TestCase):
    """The success evidence agrees with the clock and the bound."""

    def test_record_and_bytes_audit_to_the_issued_window(self):
        clock, verifier = make_verifier(ttl=10.0)
        prover = Prover(KEY)
        challenge, issued_at = issue_delay_challenge(verifier, max_delay=0.5)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = issued_at + 0.25
        record = verifier.verify_delay_bound(
            challenge, response, issued_at, opening=OPENING
        )
        # Object and canonical bytes give the same measurement.
        from_object = audit_delay_bound(record, KEY)
        from_bytes = audit_delay_bound(record.to_bytes(), KEY)
        self.assertEqual(from_object, from_bytes)
        # The measurement matches the issue-time reading, the actual
        # verify-time clock reading and the registered delay bound.
        self.assertEqual(record.issued_at, issued_at)
        self.assertEqual(record.evidence.start, issued_at)
        self.assertEqual(record.evidence.end, clock.now)
        self.assertEqual(from_object.elapsed_seconds, clock.now - issued_at)
        self.assertEqual(
            from_object.elapsed_seconds, record.evidence.elapsed
        )
        self.assertLessEqual(
            from_object.elapsed_seconds, record.max_delay_seconds
        )
        self.assertEqual(record.max_delay_seconds, 0.5)
        self.assertEqual(from_object.response, record.evidence.response)
        self.assertEqual(from_object.round_index, challenge.round_index)
        self.assertEqual(from_object.nonce, challenge.nonce)


if __name__ == "__main__":
    unittest.main()
