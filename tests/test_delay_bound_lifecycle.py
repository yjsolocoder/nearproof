"""Lifecycle combination tests for the delay-bound challenge extension.

Where ``test_delay_bound.py`` pins single-round contracts, these tests drive
one challenge through *interleaved* lifecycles: failed retries, the
delay/TTL boundary matrix, revocation, mode mixing on the legacy entry
points and concurrent verify/revoke contention. The delayed constraint
(``issued_at`` plus ``max_delay_seconds``) and the no-replay semantics
(exactly one terminal outcome, exactly one audit-able proof) must hold
across every ordering.

Everything here goes through the public surface only: Verifier issuance /
verify_delay_bound / revoke / legacy entries, Prover.reveal and
audit_delay_bound. The private registry and internal MAC helpers are never
read or called. A single stepped clock makes every outcome deterministic:
nothing depends on real waiting or on thread scheduling speed.

Failure taxonomy: a retryable validation failure (bad response, bad
opening, started_at mismatch, delay over bound) is a plain ValueError that
must *not* be a ChallengeStateError; a terminal state (consumed, revoked,
expired, unknown) is a ChallengeStateError. Because ChallengeStateError
subclasses ValueError, the tests assert the exact type whenever the two
must be distinguished.

Concurrency strategy: the two possible winners of a verify/revoke race are
each pinned with a deterministic serial interleaving (serial semantics,
both orders), and the threaded tests assert only winner-independent
invariants - exactly one terminal outcome, the loser sees
ChallengeStateError, both entries reject the challenge afterwards, and a
verify win audits to exactly one proof whose reading is the verification
clock. No thread is required to win and the tests never depend on which
lock acquisition order occurs.
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

# Round numbers chosen so the boundaries are exact in binary floating
# point: 0.25, 0.5 and 1.5 represent exactly, making "equal to the bound"
# unambiguous.
MAX_DELAY = 0.5


class SteppedClock:
    """A controllable clock: time only moves when a test moves it."""

    def __init__(self, start: float = 100.0) -> None:
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


def issue(verifier, *, max_delay=MAX_DELAY):
    """Issue one delay-bound challenge and bind a prover response to it."""
    challenge, issued_at = verifier.new_delay_challenge(
        CONTEXT, DIGEST, max_delay_seconds=max_delay
    )
    response = Prover(KEY).reveal(challenge, CONTEXT, OPENING)
    return challenge, issued_at, response


def verify(verifier, challenge, response, issued_at, *, opening=OPENING):
    return verifier.verify_delay_bound(
        challenge, response, issued_at, opening=opening
    )


def assert_plain_value_error(test_case, callable_obj, *, msg=None):
    """A failed attempt must be ValueError but never a terminal state error.

    ChallengeStateError is a ValueError subclass, so assertRaises(ValueError)
    alone cannot tell "validation failed, still pending" from "terminal
    state": assert the exact type.
    """
    try:
        callable_obj()
    except ChallengeStateError:
        test_case.fail(msg or "unexpected terminal ChallengeStateError")
    except ValueError as error:
        test_case.assertIs(type(error), ValueError, msg=msg)
    else:
        test_case.fail(msg or "expected ValueError")


class RetryLifecycleTest(unittest.TestCase):
    """Repeated validation failures on one challenge, then one success."""

    def _setup(self, **kwargs):
        clock, verifier = make_verifier(**kwargs)
        challenge, issued_at, good = issue(verifier)
        return clock, verifier, challenge, issued_at, good

    def test_failures_then_success_on_same_challenge(self):
        # One and the same challenge survives, in order: a wrong response, a
        # wrong opening and a started_at mismatch. Each failure is a plain
        # ValueError (never a state error), none of them consumes the
        # challenge, and a correct round still succeeds inside the window.
        clock, verifier, challenge, issued_at, good = self._setup()
        forged = bytes(255 - b for b in bytearray(good))

        clock.now = issued_at + 0.1
        assert_plain_value_error(
            self,
            lambda: verify(verifier, challenge, forged, issued_at),
        )
        assert_plain_value_error(
            self,
            lambda: verify(
                verifier, challenge, good, issued_at, opening=OTHER_OPENING
            ),
        )
        assert_plain_value_error(
            self,
            lambda: verify(verifier, challenge, good, issued_at + 1e-9),
        )

        # Still pending and within the window: the correct round wins once.
        clock.now = issued_at + 0.2
        record = verify(verifier, challenge, good, issued_at)
        self.assertIsInstance(record, DelayBoundEvidence)

        # After that success, every entry point treats it as terminal.
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, good, issued_at)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_delay_over_bound_then_success_does_not_consume(self):
        # Over the delay bound is a plain ValueError and, crucially, must
        # not consume the challenge: winding back inside the window and
        # retrying succeeds exactly on the boundary.
        clock, verifier, challenge, issued_at, good = self._setup()
        clock.now = issued_at + MAX_DELAY + 0.25
        assert_plain_value_error(
            self, lambda: verify(verifier, challenge, good, issued_at)
        )
        clock.now = issued_at + MAX_DELAY
        record = verify(verifier, challenge, good, issued_at)
        self.assertEqual(
            audit_delay_bound(record, KEY).elapsed_seconds, MAX_DELAY
        )

    def test_failures_keep_original_issued_at_and_deadline(self):
        # A retry does not refresh the issue time: passing a later
        # started_at is rejected as a mismatch even after failed calls, and
        # the TTL deadline stays anchored to the original issuance.
        clock, verifier, challenge, issued_at, good = self._setup(ttl=1.0)
        clock.now = issued_at + 0.1
        assert_plain_value_error(
            self, lambda: verify(verifier, challenge, good, issued_at + 0.1)
        )
        # Original deadline reached: expired is terminal even though the
        # only prior call happened at issued_at + 0.1 (deadline not moved).
        clock.now = issued_at + 1.0
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, good, issued_at)
        # Terminal expiry survives clock rollback, and revoke agrees.
        clock.now = issued_at + 0.2
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, good, issued_at)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class DelayTTLBoundaryTest(unittest.TestCase):
    """The delay upper bound and the TTL deadline are independent gates."""

    def test_delay_equal_to_bound_before_ttl_succeeds(self):
        # Closed interval on the delay side: delay == max_delay accepted.
        clock, verifier = make_verifier(ttl=1.0)
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + MAX_DELAY
        record = verify(verifier, challenge, response, issued_at)
        self.assertEqual(record.evidence.end, issued_at + MAX_DELAY)
        measurement = audit_delay_bound(record, KEY)
        self.assertEqual(measurement.elapsed_seconds, MAX_DELAY)

    def test_at_ttl_deadline_is_state_error_even_inside_delay(self):
        # Half-open interval on the TTL side: end == deadline expires.
        clock, verifier = make_verifier(ttl=MAX_DELAY)
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + MAX_DELAY
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)

    def test_ttl_shorter_equal_longer_than_delay_bound_distinguished(self):
        # The three orderings of ttl vs max_delay must behave differently
        # at the shared boundary value:
        #   ttl <  bound  -> state error (expired)
        #   ttl == bound  -> state error (deadline reached)
        #   ttl >  bound  -> success (still inside both windows)
        # with the verification clock set to issued_at + max_delay in all
        # three cases, so only the TTL ordering decides the outcome.
        for ttl, expect in (
            (0.25, ChallengeStateError),
            (MAX_DELAY, ChallengeStateError),
            (1.5, DelayBoundEvidence),
        ):
            with self.subTest(ttl=ttl):
                clock, verifier = make_verifier(ttl=ttl)
                challenge, issued_at, response = issue(verifier)
                clock.now = issued_at + MAX_DELAY
                if expect is ChallengeStateError:
                    with self.assertRaises(ChallengeStateError):
                        verify(verifier, challenge, response, issued_at)
                else:
                    record = verify(verifier, challenge, response, issued_at)
                    self.assertIsInstance(record, DelayBoundEvidence)

    def test_delay_failure_vs_ttl_failure_are_distinct_outcomes(self):
        # Same clock offset (beyond both gates): with no TTL the delay
        # breach is a plain ValueError and leaves the challenge pending;
        # with a short TTL the TTL check runs first and is a terminal
        # ChallengeStateError.
        offset = MAX_DELAY + 0.5

        clock, verifier = make_verifier()  # no TTL
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + offset
        assert_plain_value_error(
            self, lambda: verify(verifier, challenge, response, issued_at)
        )
        # Still pending: roll inside the window and succeed.
        clock.now = issued_at + 0.1
        self.assertIsInstance(
            verify(verifier, challenge, response, issued_at),
            DelayBoundEvidence,
        )

        clock2, verifier2 = make_verifier(ttl=0.25)
        challenge2, issued_at2, response2 = issue(verifier2)
        clock2.now = issued_at2 + offset
        with self.assertRaises(ChallengeStateError):
            verify(verifier2, challenge2, response2, issued_at2)
        # The expired challenge can never be consumed or revoked.
        clock2.now = issued_at2 + 0.1
        with self.assertRaises(ChallengeStateError):
            verify(verifier2, challenge2, response2, issued_at2)
        with self.assertRaises(ChallengeStateError):
            verifier2.revoke(challenge2)

    def test_expired_state_pinned_even_after_clock_rollback(self):
        clock, verifier = make_verifier(ttl=1.0)
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + 1.0
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        # Wind the clock well inside both windows: expiry is terminal.
        clock.now = issued_at + 0.1
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_expired_via_revoke_path_pinned_then_verify_also_fails(self):
        # Revocation reads the clock under the same lock and pins expiry
        # the same way; touching the revoke entry first must leave the
        # challenge dead to the verify entry even after rollback.
        clock, verifier = make_verifier(ttl=1.0)
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)
        clock.now = issued_at + 0.1
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class LegacyEntryModeMixingTest(unittest.TestCase):
    """A still-valid delay challenge rejects the legacy entry points."""

    def test_legacy_mode_mix_is_value_error_then_delay_verify_succeeds(self):
        # While the challenge is pending and inside the window, the old
        # entries must refuse it (plain ValueError - the mode mix must not
        # be mistaken for a terminal state) and must not consume it: the
        # proper delay verification still succeeds afterwards.
        clock, verifier = make_verifier(ttl=1.0)
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + 0.1

        def legacy_without_opening():
            verifier.verify(challenge, response, issued_at)

        def legacy_with_opening():
            verifier.verify(challenge, response, issued_at, opening=OPENING)

        def legacy_bound():
            verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            )

        def legacy_evidence():
            verifier.verify_evidence(challenge, response, issued_at)

        for call in (
            legacy_without_opening,
            legacy_with_opening,
            legacy_bound,
            legacy_evidence,
        ):
            assert_plain_value_error(self, call)

        record = verify(verifier, challenge, response, issued_at)
        self.assertIsInstance(record, DelayBoundEvidence)
        # Once consumed, the legacy entries report the terminal state too.
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            )

    def test_mode_mix_at_far_future_clock_still_does_not_consume(self):
        # Even a legacy call whose clock reading would breach max_delay
        # must refuse and leave the challenge pending; winding back and
        # using the proper entry succeeds.
        clock, verifier = make_verifier()
        challenge, issued_at, response = issue(verifier)
        clock.now = issued_at + 100.0
        assert_plain_value_error(
            self,
            lambda: verifier.verify(
                challenge, response, issued_at, opening=OPENING
            ),
        )
        clock.now = issued_at + 0.1
        self.assertIsInstance(
            verify(verifier, challenge, response, issued_at),
            DelayBoundEvidence,
        )

    def test_revoke_then_legacy_entries_report_state_error(self):
        # Revocation is the terminal state through every entry, legacy
        # included - state checks precede mode validation.
        clock, verifier = make_verifier()
        challenge, issued_at, response = issue(verifier)
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, issued_at, opening=OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)


class IndependentChallengesTest(unittest.TestCase):
    """Failure on one challenge must never affect an independent one."""

    def test_failed_round_leaves_sibling_verifiable(self):
        clock, verifier = make_verifier(ttl=1.0)
        first, issued_first, response_first = issue(verifier)
        second, issued_second, response_second = issue(verifier)

        # Every flavour of failure lands on the first challenge only, and
        # the first is then revoked; the sibling must stay verifiable.
        clock.now = issued_first + 0.1
        assert_plain_value_error(
            self, lambda: verify(verifier, first, b"\x00" * 32, issued_first)
        )
        assert_plain_value_error(
            self,
            lambda: verify(
                verifier, first, response_first, issued_first,
                opening=OTHER_OPENING,
            ),
        )
        assert_plain_value_error(
            self,
            lambda: verify(
                verifier, first, response_first, issued_first + 1e-9
            ),
        )
        verifier.revoke(first)
        with self.assertRaises(ChallengeStateError):
            verify(verifier, first, response_first, issued_first)

        # The sibling is untouched and verifies on its own issued_at.
        clock.now = issued_second + 0.2
        record = verify(verifier, second, response_second, issued_second)
        self.assertIsInstance(record, DelayBoundEvidence)
        self.assertEqual(record.evidence.nonce, second.nonce)
        # And the first stays dead.
        with self.assertRaises(ChallengeStateError):
            verify(verifier, first, response_first, issued_first)

    def test_sibling_started_at_does_not_cross_verify(self):
        # A started_at belonging to the other challenge is a mismatch, not
        # a cross-binding success; the sibling works only with its own.
        clock, verifier = make_verifier()
        first, issued_first, response_first = issue(verifier)
        clock.now = issued_first + 0.05
        second, issued_second, response_second = issue(verifier)
        self.assertGreater(issued_second, issued_first)
        clock.now = issued_second + 0.1
        assert_plain_value_error(
            self,
            lambda: verify(
                verifier, second, response_second, issued_first
            ),
        )
        record = verify(verifier, second, response_second, issued_second)
        self.assertEqual(record.issued_at, issued_second)
        # First is still pending and independently consumable.
        clock.now = issued_first + 0.1
        self.assertIsInstance(
            verify(verifier, first, response_first, issued_first),
            DelayBoundEvidence,
        )


class SerialOutcomeSemanticsTest(unittest.TestCase):
    """Deterministic serial interleavings pin both contention winners.

    A verify/revoke race can only end in one of two serial states; each
    ordering is driven here step by step with the stepped clock, so both
    winner outcomes are checked against serial semantics without relying on
    thread scheduling at all.
    """

    def _fresh(self, *, ttl=1.0):
        clock, verifier = make_verifier(ttl=ttl)
        challenge, issued_at, response = issue(verifier)
        return clock, verifier, challenge, issued_at, response

    def _assert_dead_to_both_entries(self, verifier, challenge, response, issued_at):
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_verify_wins_then_revoke_is_rejected(self):
        clock, verifier, challenge, issued_at, response = self._fresh()
        clock.now = issued_at + MAX_DELAY  # on the delay bound, inside TTL

        record = verify(verifier, challenge, response, issued_at)
        self.assertIsInstance(record, DelayBoundEvidence)

        # The loser entry now reports the consumed terminal state.
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

        # Verify winner serial semantics: exactly one proof, audit-able
        # from either the object or its canonical bytes.
        measurement = audit_delay_bound(record, KEY)
        self.assertEqual(measurement, audit_delay_bound(record.to_bytes(), KEY))
        self.assertEqual(record.evidence.start, issued_at)
        self.assertEqual(record.evidence.end, issued_at + MAX_DELAY)
        self.assertEqual(measurement.elapsed_seconds, MAX_DELAY)

        self._assert_dead_to_both_entries(
            verifier, challenge, response, issued_at
        )

    def test_revoke_wins_then_verify_is_rejected_and_no_proof_exists(self):
        clock, verifier, challenge, issued_at, response = self._fresh()
        clock.now = issued_at + 0.1

        verifier.revoke(challenge)  # returns None: no proof is produced

        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        # A second revoke is rejected as well.
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_failed_verify_then_revoke_wins(self):
        # A retryable failure must not lock the challenge into the verify
        # side: revoke can still win afterwards.
        clock, verifier, challenge, issued_at, response = self._fresh()
        clock.now = issued_at + MAX_DELAY + 0.25
        assert_plain_value_error(
            self, lambda: verify(verifier, challenge, response, issued_at)
        )
        clock.now = issued_at + 0.1
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)

    def test_failed_verify_then_verify_still_wins_over_later_revoke(self):
        # The symmetric order: failures, then a successful verify, and a
        # subsequent revoke loses - the failed calls granted no early
        # terminal state to either side.
        clock, verifier, challenge, issued_at, response = self._fresh()
        clock.now = issued_at + MAX_DELAY + 0.25
        assert_plain_value_error(
            self, lambda: verify(verifier, challenge, response, issued_at)
        )
        clock.now = issued_at + 0.2
        record = verify(verifier, challenge, response, issued_at)
        self.assertIsInstance(record, DelayBoundEvidence)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_revoke_after_ttl_deadline_loses_to_expiry(self):
        # Near the deadline neither side can win: expiry beats both revoke
        # and verify, deterministically and terminally.
        clock, verifier, challenge, issued_at, response = self._fresh(ttl=1.0)
        clock.now = issued_at + 1.0
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        # Rollback changes nothing.
        clock.now = issued_at + 0.1
        self._assert_dead_to_both_entries(
            verifier, challenge, response, issued_at
        )


class VerifyRevokeContentionTest(unittest.TestCase):
    """Concurrent entry points preserve the exactly-one-outcome invariant.

    These tests never name a required winner: whichever lock acquisition
    order occurs, the outcome must match one of the two serial states
    pinned in SerialOutcomeSemanticsTest. Time is fixed for all contenders
    (inside both windows), so scheduling speed cannot change any clock
    reading.
    """

    def _contend(self, verifier, challenge, response, issued_at, *,
                 n_verify, n_revoke):
        records = []
        revocations = []
        state_errors = []
        anomalies = []
        total = n_verify + n_revoke
        barrier = threading.Barrier(total)

        def do_verify():
            barrier.wait()
            try:
                records.append(
                    verify(verifier, challenge, response, issued_at)
                )
            except ChallengeStateError as error:
                state_errors.append(("verify", error))
            except BaseException as error:  # pragma: no cover - must be empty
                anomalies.append(("verify", repr(error)))

        def do_revoke():
            barrier.wait()
            try:
                verifier.revoke(challenge)
                revocations.append(True)
            except ChallengeStateError as error:
                state_errors.append(("revoke", error))
            except BaseException as error:  # pragma: no cover - must be empty
                anomalies.append(("revoke", repr(error)))

        threads = (
            [threading.Thread(target=do_verify) for _ in range(n_verify)]
            + [threading.Thread(target=do_revoke) for _ in range(n_revoke)]
        )
        for thread in threads:
            thread.start()
        for thread in threads:
            # Unbounded join: a contender that never finishes fails the
            # run by hanging instead of being silently counted as a pass.
            thread.join()
            self.assertFalse(
                thread.is_alive(), "contender thread did not finish"
            )
        return records, revocations, state_errors, anomalies

    def test_verify_and_revoke_contend_exactly_one_wins(self):
        # Repeat the race: every run must satisfy the invariant regardless
        # of which ordering the scheduler picks this time.
        for _ in range(50):
            clock, verifier = make_verifier(ttl=10.0)
            challenge, issued_at, response = issue(verifier)
            end_reading = issued_at + 0.1
            clock.now = end_reading

            records, revocations, state_errors, anomalies = self._contend(
                verifier, challenge, response, issued_at,
                n_verify=1, n_revoke=1,
            )
            self.assertEqual(anomalies, [])
            self.assertEqual(len(records) + len(revocations), 1)
            self.assertEqual(len(state_errors), 1)

            if records:
                # Verify winner: one proof matching the fixed verification
                # reading; the loser is the revoker.
                self.assertEqual([role for role, _ in state_errors], ["revoke"])
                record = records[0]
                self.assertEqual(record.evidence.end, end_reading)
                self.assertEqual(record.evidence.start, issued_at)
                measurement = audit_delay_bound(record, KEY)
                self.assertEqual(
                    measurement, audit_delay_bound(record.to_bytes(), KEY)
                )
                self.assertEqual(measurement.elapsed_seconds, 0.1)
                self.assertEqual(measurement.response, response)
            else:
                # Revoke winner: no proof, the verifier lost.
                self.assertEqual(revocations, [True])
                self.assertEqual([role for role, _ in state_errors], ["verify"])

            # Afterwards both entries reject the challenge and no second
            # proof can ever be produced.
            with self.assertRaises(ChallengeStateError):
                verify(verifier, challenge, response, issued_at)
            with self.assertRaises(ChallengeStateError):
                verifier.revoke(challenge)

    def test_multiple_correct_verifies_only_one_succeeds(self):
        clock, verifier = make_verifier(ttl=10.0)
        challenge, issued_at, response = issue(verifier)
        end_reading = issued_at + 0.1
        clock.now = end_reading

        records, revocations, state_errors, anomalies = self._contend(
            verifier, challenge, response, issued_at,
            n_verify=16, n_revoke=0,
        )
        self.assertEqual(anomalies, [])
        self.assertEqual(revocations, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(state_errors), 15)
        self.assertEqual(
            {role for role, _ in state_errors}, {"verify"}
        )
        # The single proof audits to the shared reading and response.
        record = records[0]
        self.assertEqual(record.evidence.response, response)
        self.assertEqual(record.evidence.end, end_reading)
        self.assertEqual(
            audit_delay_bound(record, KEY),
            audit_delay_bound(record.to_bytes(), KEY),
        )
        with self.assertRaises(ChallengeStateError):
            verify(verifier, challenge, response, issued_at)
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_revoke_against_many_verifiers_still_one_outcome(self):
        # A revoke racing many correct verifies: either one proof or one
        # revocation, never both; repeated to remove scheduling luck.
        for _ in range(25):
            clock, verifier = make_verifier(ttl=10.0)
            challenge, issued_at, response = issue(verifier)
            clock.now = issued_at + 0.1

            records, revocations, state_errors, anomalies = self._contend(
                verifier, challenge, response, issued_at,
                n_verify=8, n_revoke=1,
            )
            self.assertEqual(anomalies, [])
            self.assertEqual(len(records) + len(revocations), 1)
            self.assertEqual(len(state_errors), 8)
            if records:
                self.assertEqual(len(records), 1)
                self.assertEqual(revocations, [])
            else:
                self.assertEqual(revocations, [True])
                self.assertEqual(
                    {role for role, _ in state_errors}, {"verify"}
                )
            with self.assertRaises(ChallengeStateError):
                verify(verifier, challenge, response, issued_at)
            with self.assertRaises(ChallengeStateError):
                verifier.revoke(challenge)


class WinningEvidenceAuditTest(unittest.TestCase):
    """The proof surviving a full lifecycle matches issuance and readings."""

    def test_audit_agrees_on_object_and_bytes_with_issuance_readings(self):
        # Failure, then a legacy-mode mix, then success exactly on the
        # delay bound: the winner's proof is pinned against the issuance
        # reading, the actual completion reading and the upper bound.
        ttl = 1.5
        clock, verifier = make_verifier(ttl=ttl)
        challenge, issued_at, response = issue(verifier, max_delay=MAX_DELAY)

        clock.now = issued_at + MAX_DELAY + 0.25
        assert_plain_value_error(
            self, lambda: verify(verifier, challenge, response, issued_at)
        )
        clock.now = issued_at + 0.1
        assert_plain_value_error(
            self,
            lambda: verifier.verify_bound(
                challenge, response, issued_at, opening=OPENING
            ),
        )

        end_reading = issued_at + MAX_DELAY  # exactly on the bound
        clock.now = end_reading
        record = verify(verifier, challenge, response, issued_at)

        # Same measurement from the object and from canonical bytes, and
        # the bytes round-trip to the same record.
        from_object = audit_delay_bound(record, KEY)
        from_bytes = audit_delay_bound(record.to_bytes(), KEY)
        self.assertIsInstance(from_object, Measurement)
        self.assertEqual(from_object, from_bytes)
        self.assertEqual(
            DelayBoundEvidence.from_bytes(record.to_bytes()), record
        )

        evidence = record.evidence
        self.assertEqual(record.issued_at, issued_at)
        self.assertEqual(record.max_delay_seconds, MAX_DELAY)
        self.assertEqual(evidence.start, issued_at)
        self.assertEqual(evidence.end, end_reading)
        self.assertEqual(from_object.elapsed_seconds, end_reading - issued_at)
        self.assertEqual(from_object.elapsed_seconds, MAX_DELAY)
        self.assertEqual(
            from_object.distance_meters,
            MAX_DELAY * evidence.speed / 2.0,
        )
        self.assertEqual(from_object.response, response)
        self.assertEqual(from_object.round_index, challenge.round_index)
        self.assertEqual(from_object.nonce, challenge.nonce)
        # Measured delay is within the registered bound and the completion
        # reading is still before the TTL deadline.
        self.assertLessEqual(
            from_object.elapsed_seconds, record.max_delay_seconds
        )
        self.assertLess(end_reading, issued_at + ttl)


class CompatibilityTest(unittest.TestCase):
    """The new lifecycle coverage leaves the older modes untouched."""

    def test_replay_protection_off_round_unchanged(self):
        # Delay features never touch the protection-off verifier: an
        # externally built challenge still verifies repeatedly.
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=False)
        prover = Prover(KEY)
        from nearproof import Challenge, keyed_response

        challenge = Challenge(1, b"0" * 16)
        response = keyed_response(KEY, challenge.nonce)
        self.assertIsInstance(
            verifier.verify(challenge, response, clock.now), Measurement
        )
        clock.now += 1.0
        self.assertIsInstance(
            verifier.verify(challenge, response, clock.now), Measurement
        )

    def test_plain_bound_challenge_lifecycle_unchanged(self):
        # A normal (non-delay) bound challenge follows the consume/revoke
        # lifecycle through verify_bound exactly as before the extension.
        clock, verifier = make_verifier(ttl=1.0)
        prover = Prover(KEY)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now += 0.1
        record = verifier.verify_bound(
            challenge, response, clock.now - 0.1, opening=OPENING
        )
        self.assertEqual(record.context, CONTEXT)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, clock.now, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            verifier.revoke(challenge)

    def test_delay_and_plain_challenges_coexist(self):
        # Issuing and consuming a delay challenge changes nothing for a
        # plain bound challenge on the same verifier, in both directions.
        clock, verifier = make_verifier(ttl=10.0)
        prover = Prover(KEY)

        delay_challenge, delay_issued, delay_response = issue(verifier)
        plain = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        plain_response = prover.reveal(plain, CONTEXT, OPENING)

        clock.now = delay_issued + 0.1
        delay_record = verify(
            verifier, delay_challenge, delay_response, delay_issued
        )
        self.assertIsInstance(delay_record, DelayBoundEvidence)
        plain_started = clock.now
        clock.now += 0.1
        plain_record = verifier.verify_bound(
            plain, plain_response, plain_started, opening=OPENING
        )
        self.assertEqual(plain_record.digest, DIGEST)
        # Each is independently terminal.
        with self.assertRaises(ChallengeStateError):
            verify(verifier, delay_challenge, delay_response, delay_issued)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                plain, plain_response, plain_started, opening=OPENING
            )


if __name__ == "__main__":
    unittest.main()
