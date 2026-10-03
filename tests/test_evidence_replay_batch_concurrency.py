"""Concurrency contract tests for EvidenceReplayAuditor.audit_batch.

Complements test_evidence_replay.py: the single-record race is already
covered there; here the batch consumption path is exercised under
concurrent contention. The promises under test are the public ones:

* two batches sharing any evidence (by object or canonical bytes, across
  evidence kinds via the same ``(round_index, nonce)`` pair) commit at
  most once — exactly one succeeds, the loser raises ``ValueError`` and
  leaves no partial ledger entries behind;
* a single-record ``audit`` racing a batch containing that record also
  commits at most once, and the final ledger equals what the winning
  operation alone would have produced;
* disjoint concurrent batches all commit, the ledger loses no entry and
  ``sequence`` always equals the number of consumed entries;
* a checkpoint exported after the race restores (as object and as
  canonical bytes) into a new instance with the identical ledger;
* a forged batch racing a legitimate one fails wholesale while the
  legitimate batch commits.

No test assumes which thread wins and none sleeps: workers are released
together by a barrier, every thread outcome (return value or exception)
is collected, and unfinished threads or unexpected exception types fail
the test explicitly.
"""

import threading
import unittest
from dataclasses import replace

from nearproof import (
    BoundEvidence,
    DelayBoundEvidence,
    EvidenceReplayAuditor,
    Measurement,
    Prover,
    Verifier,
    _bound_evidence_mac,
    _bound_evidence_payload,
    _delay_bound_evidence_mac,
    _delay_bound_evidence_payload,
    _evidence_mac,
    _evidence_payload,
    audit,
    audit_bound,
    audit_delay_bound,
    bound_response,
    context_digest,
)

KEY = b"shared-secret-key"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)

KIND_EVIDENCE = 1
KIND_BOUND = 2
KIND_DELAY_BOUND = 3

JOIN_TIMEOUT = 10.0


class SteppedClock:
    def __init__(self, start=0.0, step=1e-7):
        self.now = start
        self.step = step

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


def make_evidence_records(count, *, key=KEY, start=0.0, step=1e-7):
    prover = Prover(key)
    clock = SteppedClock(start=start, step=step)
    verifier = Verifier(key, clock=clock)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return records


def make_bound_records(count, *, key=KEY, context=CONTEXT, opening=OPENING,
                       digest=DIGEST, start=0.0, step=1e-7):
    prover = Prover(key)
    clock = SteppedClock(start=start, step=step)
    verifier = Verifier(key, clock=clock, replay_protection=True)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge(context=context, digest=digest)
        started = clock.now
        response = prover.reveal(challenge, context, opening)
        clock.now += step
        records.append(
            verifier.verify_bound(challenge, response, started, opening=opening)
        )
    return records


def make_delay_records(count, *, key=KEY, context=CONTEXT, opening=OPENING,
                       max_delay=1.0, start=100.0, step=0.005):
    prover = Prover(key)
    clock = SteppedClock(start=start, step=step)
    verifier = Verifier(key, clock=clock, replay_protection=True)
    digest = context_digest(context, opening)
    records = []
    for _ in range(count):
        challenge, issued_at = verifier.new_delay_challenge(
            context, digest, max_delay_seconds=max_delay
        )
        response = prover.reveal(challenge, context, opening)
        clock.now += step
        records.append(
            verifier.verify_delay_bound(
                challenge, response, issued_at, opening=opening
            )
        )
    return records


def rebind(evidence, key=KEY):
    """Recompute the inner evidence MAC after a response swap."""
    return replace(
        evidence, mac=_evidence_mac(key, _evidence_payload(evidence))
    )


def bound_twin(evidence, *, key=KEY, context=CONTEXT, opening=OPENING):
    """A valid BoundEvidence consuming the same round_index and nonce."""
    digest = context_digest(context, opening)
    inner = rebind(
        replace(
            evidence,
            response=bound_response(
                key, digest, evidence.round_index, evidence.nonce
            ),
        ),
        key=key,
    )
    bound = BoundEvidence(
        version=1,
        evidence=inner,
        context=context,
        digest=digest,
        opening=opening,
        mac=b"\x00" * 32,
    )
    return replace(
        bound, mac=_bound_evidence_mac(key, _bound_evidence_payload(bound))
    )


def delay_twin(evidence, *, key=KEY, context=CONTEXT, opening=OPENING):
    """A valid DelayBoundEvidence consuming the same round_index and nonce."""
    digest = context_digest(context, opening)
    inner = rebind(
        replace(
            evidence,
            response=bound_response(
                key, digest, evidence.round_index, evidence.nonce
            ),
        ),
        key=key,
    )
    record = DelayBoundEvidence(
        version=1,
        evidence=inner,
        context=context,
        digest=digest,
        opening=opening,
        issued_at=inner.start,
        max_delay_seconds=1.0,
        mac=b"\x00" * 32,
    )
    return replace(
        record,
        mac=_delay_bound_evidence_mac(
            key, _delay_bound_evidence_payload(record)
        ),
    )


def entry_of(record):
    """The ledger consumption identifier of an evidence record."""
    if isinstance(record, BoundEvidence):
        return (
            KIND_BOUND,
            record.evidence.round_index,
            record.evidence.nonce,
        )
    if isinstance(record, DelayBoundEvidence):
        return (
            KIND_DELAY_BOUND,
            record.evidence.round_index,
            record.evidence.nonce,
        )
    return (KIND_EVIDENCE, record.round_index, record.nonce)


def stateless_measurement(record, key=KEY):
    """The Measurement the matching public stateless audit returns."""
    if isinstance(record, BoundEvidence):
        return audit_bound(record, key)
    if isinstance(record, DelayBoundEvidence):
        return audit_delay_bound(record, key)
    return audit(record, key)


class ConcurrentRace:
    """Run zero-argument callables concurrently and collect every outcome.

    Each callable runs in its own thread, all released by one barrier.
    The result is a list of ``("ok", value)`` or ``("error", exception)``
    per callable, in input order — thread exceptions are captured, not
    lost, and unfinished threads are reported by ``assert_finished``.
    """

    def __init__(self, calls):
        self._calls = list(calls)
        self.outcomes = [None] * len(self._calls)
        self._threads = []

    def run(self):
        barrier = threading.Barrier(len(self._calls))

        def worker(index):
            barrier.wait()
            try:
                self.outcomes[index] = ("ok", self._calls[index]())
            except Exception as error:  # surfaced to the assertions below
                self.outcomes[index] = ("error", error)

        self._threads = [
            threading.Thread(target=worker, args=(index,))
            for index in range(len(self._calls))
        ]
        for thread in self._threads:
            thread.start()
        for thread in self._threads:
            thread.join(timeout=JOIN_TIMEOUT)
        return self.outcomes

    def assert_finished(self, test_case):
        for thread in self._threads:
            test_case.assertFalse(
                thread.is_alive(), "a worker thread did not finish"
            )
        for outcome in self.outcomes:
            test_case.assertIsNotNone(
                outcome, "a worker thread produced no outcome"
            )


class ConcurrentBatchRaceTest(unittest.TestCase):
    def run_race(self, calls):
        race = ConcurrentRace(calls)
        outcomes = race.run()
        race.assert_finished(self)
        for tag, payload in outcomes:
            if tag == "error":
                self.assertIsInstance(
                    payload,
                    ValueError,
                    f"worker raised an unexpected exception: {payload!r}",
                )
        return outcomes

    def assert_exactly_one_success(self, outcomes):
        successes = [payload for tag, payload in outcomes if tag == "ok"]
        failures = [payload for tag, payload in outcomes if tag == "error"]
        self.assertEqual(
            len(successes) + len(failures),
            len(outcomes),
            "every worker must have produced an outcome",
        )
        self.assertEqual(
            len(successes),
            1,
            f"expected exactly one committed call, got {outcomes!r}",
        )
        return successes[0]

    def assert_ledger(self, auditor, expected_entries):
        checkpoint = auditor.checkpoint
        self.assertIsNotNone(checkpoint)
        self.assertEqual(
            checkpoint.sequence,
            len(expected_entries),
            "sequence must equal the number of consumed entries",
        )
        self.assertEqual(len(checkpoint.entries), checkpoint.sequence)
        self.assertEqual(set(checkpoint.entries), set(expected_entries))
        # The exported checkpoint authenticates under the auditor key.
        EvidenceReplayAuditor(KEY, checkpoint)

    def test_overlapping_batches_commit_exactly_once(self):
        shared, unique_a1, unique_a2, unique_b1 = make_evidence_records(4)
        batch_a = [shared, unique_a1, unique_a2]
        batch_b = [shared, unique_b1]
        auditor = EvidenceReplayAuditor(KEY)

        outcomes = self.run_race([
            lambda: auditor.audit_batch(batch_a),
            lambda: auditor.audit_batch(batch_b),
        ])

        winner_index = [tag for tag, _ in outcomes].index("ok")
        result = self.assert_exactly_one_success(outcomes)
        winner_batch = (batch_a, batch_b)[winner_index]
        # The winner gets the stateless Measurements in input order.
        self.assertIsInstance(result, tuple)
        self.assertEqual(
            result,
            tuple(stateless_measurement(record) for record in winner_batch),
        )
        for measurement in result:
            self.assertIsInstance(measurement, Measurement)
        # The ledger gained exactly the winner's entries — no partial
        # records from the losing batch.
        self.assert_ledger(auditor, [entry_of(r) for r in winner_batch])
        # The shared evidence is consumed now, whichever batch won.
        with self.assertRaises(ValueError):
            auditor.audit(shared)
        # The losing batch's unique evidence is still consumable.
        loser_batch = (batch_a, batch_b)[1 - winner_index]
        for record in loser_batch:
            if record is shared:
                continue
            self.assertEqual(
                auditor.audit(record), stateless_measurement(record)
            )
        self.assert_ledger(
            auditor,
            [entry_of(r) for r in batch_a] + [entry_of(unique_b1)],
        )

    def test_object_against_canonical_bytes_conflict(self):
        (shared,) = make_evidence_records(1)
        unique_a, unique_b = make_evidence_records(2, start=10.0)
        auditor = EvidenceReplayAuditor(KEY)
        # Same evidence, once as an object and once as canonical bytes.
        batch_a = [shared, unique_a]
        batch_b = [shared.to_bytes(), unique_b.to_bytes()]

        outcomes = self.run_race([
            lambda: auditor.audit_batch(batch_a),
            lambda: auditor.audit_batch(batch_b),
        ])

        winner_index = [tag for tag, _ in outcomes].index("ok")
        self.assert_exactly_one_success(outcomes)
        winner_entries = (
            [entry_of(shared), entry_of(unique_a)]
            if winner_index == 0
            else [entry_of(shared), entry_of(unique_b)]
        )
        self.assert_ledger(auditor, winner_entries)
        with self.assertRaises(ValueError):
            auditor.audit(shared.to_bytes())

    def test_cross_kind_conflict_across_batches(self):
        (record,) = make_evidence_records(1)
        bound = bound_twin(record)
        delay = delay_twin(record)
        unique = make_evidence_records(2, start=10.0)
        # The cross-kind twins are genuine records: each passes its own
        # stateless audit, so a later rejection is replay protection, not
        # an authentication failure.
        self.assertEqual(audit_bound(bound, KEY), audit_bound(bound, KEY))
        self.assertEqual(
            audit_delay_bound(delay, KEY), audit_delay_bound(delay, KEY)
        )
        auditor = EvidenceReplayAuditor(KEY)

        outcomes = self.run_race([
            lambda: auditor.audit_batch([record, unique[0]]),
            lambda: auditor.audit_batch([bound, unique[1]]),
        ])

        winner_index = [tag for tag, _ in outcomes].index("ok")
        self.assert_exactly_one_success(outcomes)
        if winner_index == 0:
            expected = [entry_of(record), entry_of(unique[0])]
        else:
            expected = [entry_of(bound), entry_of(unique[1])]
        self.assert_ledger(auditor, expected)
        # Whichever kind won, the other kind's twin of the same
        # (round_index, nonce) pair is replay now.
        with self.assertRaises(ValueError):
            auditor.audit(delay)
        with self.assertRaises(ValueError):
            auditor.audit(record if winner_index == 1 else bound)

    def test_single_audit_races_batch(self):
        shared, unique = make_evidence_records(2)
        auditor = EvidenceReplayAuditor(KEY)

        outcomes = self.run_race([
            lambda: auditor.audit(shared),
            lambda: auditor.audit_batch([shared, unique]),
        ])

        winner_index = [tag for tag, _ in outcomes].index("ok")
        result = self.assert_exactly_one_success(outcomes)
        if winner_index == 0:
            # The single audit won: the state equals audit(shared) alone.
            self.assertEqual(result, audit(shared, KEY))
            self.assert_ledger(auditor, [entry_of(shared)])
            # The batch's unique record was never consumed.
            auditor.audit(unique)
            self.assert_ledger(
                auditor, [entry_of(shared), entry_of(unique)]
            )
        else:
            # The batch won: the state equals the batch alone.
            self.assertEqual(
                result, (audit(shared, KEY), audit(unique, KEY))
            )
            self.assert_ledger(
                auditor, [entry_of(shared), entry_of(unique)]
            )
            with self.assertRaises(ValueError):
                auditor.audit(shared)

    def test_disjoint_batches_all_commit(self):
        records = make_evidence_records(6)
        bounds = make_bound_records(2)
        delays = make_delay_records(2)
        batches = [
            records[0:3],
            records[3:6],
            list(bounds),
            list(delays),
        ]
        auditor = EvidenceReplayAuditor(KEY)

        outcomes = self.run_race([
            (lambda batch=batch: auditor.audit_batch(batch))
            for batch in batches
        ])

        for (tag, payload), batch in zip(outcomes, batches):
            self.assertEqual(tag, "ok", f"unexpected failure: {payload!r}")
            self.assertEqual(
                payload,
                tuple(stateless_measurement(record) for record in batch),
            )
        expected = [entry_of(r) for batch in batches for r in batch]
        self.assert_ledger(auditor, expected)

    def test_forged_batch_fails_wholesale_against_legit_batch(self):
        legit_records = make_evidence_records(2)
        honest, forged = make_evidence_records(2, start=10.0)
        forged = replace(forged, mac=b"\x00" * 32)
        auditor = EvidenceReplayAuditor(KEY)

        outcomes = self.run_race([
            lambda: auditor.audit_batch([honest, forged]),
            lambda: auditor.audit_batch(legit_records),
        ])

        forged_tag, forged_error = outcomes[0]
        legit_tag, legit_result = outcomes[1]
        # The forged batch fails wholesale in every interleaving.
        self.assertEqual(forged_tag, "error")
        self.assertIsInstance(forged_error, ValueError)
        # The legitimate batch commits in full.
        self.assertEqual(legit_tag, "ok")
        self.assertEqual(
            legit_result,
            tuple(stateless_measurement(r) for r in legit_records),
        )
        # The ledger holds exactly the legitimate batch — nothing from
        # the forged batch, not even its honest prefix record.
        self.assert_ledger(auditor, [entry_of(r) for r in legit_records])
        # The honest prefix of the forged batch was never consumed.
        auditor.audit(honest)
        self.assert_ledger(
            auditor, [entry_of(r) for r in legit_records] + [entry_of(honest)]
        )


class ConcurrentCheckpointRestoreTest(unittest.TestCase):
    def test_post_race_checkpoint_restores_as_object_and_bytes(self):
        shared, unique_a, unique_b = make_evidence_records(3)
        auditor = EvidenceReplayAuditor(KEY)
        race = ConcurrentRace([
            lambda: auditor.audit_batch([shared, unique_a]),
            lambda: auditor.audit_batch([shared, unique_b]),
        ])
        outcomes = race.run()
        race.assert_finished(self)
        winner_index = [tag for tag, _ in outcomes].index("ok")
        loser_unique = (unique_a, unique_b)[1 - winner_index]

        checkpoint = auditor.checkpoint
        checkpoint_bytes = checkpoint.to_bytes()
        restored_from_object = EvidenceReplayAuditor(KEY, checkpoint)
        restored_from_bytes = EvidenceReplayAuditor(KEY, checkpoint_bytes)
        for restored in (restored_from_object, restored_from_bytes):
            # The restored ledger is identical to the post-race ledger.
            self.assertEqual(restored.checkpoint, checkpoint)
            self.assertEqual(restored.checkpoint.sequence, 2)
            # Evidence consumed by the winning batch stays consumed.
            with self.assertRaises(ValueError):
                restored.audit(shared)
            with self.assertRaises(ValueError):
                restored.audit(shared.to_bytes())
            with self.assertRaises(ValueError):
                restored.audit_batch([shared, loser_unique])
            # Evidence the losing batch never committed is still fresh.
            self.assertEqual(
                restored.audit(loser_unique),
                stateless_measurement(loser_unique),
            )
            self.assertEqual(restored.checkpoint.sequence, 3)


if __name__ == "__main__":
    unittest.main()
