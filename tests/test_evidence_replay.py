"""Tests for the evidence-replay consumption ledger.

Covers the EvidenceReplayState checkpoint (contract, canonical bytes) and
the stateful EvidenceReplayAuditor (single and batch consumption, replay
and cross-kind rejection, checkpoint restore across instances, atomic
failure semantics and concurrency). The stateless audit/audit_bound/
audit_delay_bound entry points must remain unchanged.
"""

import dataclasses
import hashlib
import hmac
import json
import threading
import unittest
from dataclasses import replace

from nearproof import (
    BoundEvidence,
    DelayBoundEvidence,
    Evidence,
    EvidenceReplayAuditor,
    EvidenceReplayState,
    Measurement,
    Prover,
    Verifier,
    _encode_payload,
    _evidence_mac,
    _evidence_payload,
    _evidence_replay_state_mac,
    _evidence_replay_state_payload,
    _bound_evidence_mac,
    _bound_evidence_payload,
    _delay_bound_evidence_mac,
    _delay_bound_evidence_payload,
    audit,
    audit_bound,
    audit_delay_bound,
    bound_response,
    context_digest,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


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


def state_mac(key, state):
    return _evidence_replay_state_mac(key, _evidence_replay_state_payload(state))


def make_state(entries, *, key=KEY, mac=None):
    entries = tuple(sorted(entries))
    placeholder = EvidenceReplayState(1, len(entries), entries, b"\x00" * 32)
    if mac is None:
        mac = state_mac(key, placeholder)
    return EvidenceReplayState(1, len(entries), entries, mac)


ENTRY_A = (1, 1, b"\x0a" * 16)
ENTRY_B = (2, 2, b"\x0b" * 16)
ENTRY_C = (3, 3, b"\x0c" * 16)


class EvidenceReplayStateContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        first = make_state([ENTRY_B, ENTRY_A])
        second = EvidenceReplayState(1, 2, first.entries, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(first.entries, (ENTRY_A, ENTRY_B))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 9

    def test_positional_field_order(self):
        mac = b"\x02" * 32
        state = EvidenceReplayState(1, 1, (ENTRY_A,), mac)
        self.assertEqual(
            (state.version, state.sequence, state.entries, state.mac),
            (1, 1, (ENTRY_A,), mac),
        )

    def test_field_type_errors(self):
        mac = b"\x00" * 32
        with self.assertRaises(TypeError):
            EvidenceReplayState("1", 0, (), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, True, (), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, "0", (), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, 0, [], mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, 1, ([1, 2, b"n"],), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, 1, ((True, 2, b"n"),), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, 1, ((1, True, b"n"),), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, 1, ((1, 2, "n"),), mac)
        with self.assertRaises(TypeError):
            EvidenceReplayState(1, 0, (), "m" * 32)

    def test_field_value_errors(self):
        mac = b"\x00" * 32
        with self.assertRaises(ValueError):
            EvidenceReplayState(2, 0, (), mac)
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, -1, (), mac)
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 0x10000000000000000, (), mac)
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 1, ((9, 2, b"n"),), mac)
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 0, (), b"\x00" * 31)
        # sequence must equal the entry count.
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 2, (ENTRY_A,), mac)
        # entries must be sorted without duplicates.
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 2, (ENTRY_B, ENTRY_A), mac)
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 2, (ENTRY_A, ENTRY_A), mac)
        # the same (round_index, nonce) pair must not span kinds.
        twin = (2, ENTRY_A[1], ENTRY_A[2])
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 2, (ENTRY_A, twin), mac)

    def test_round_trip(self):
        state = make_state([ENTRY_C, ENTRY_A, ENTRY_B])
        data = state.to_bytes()
        self.assertIsInstance(data, bytes)
        self.assertEqual(EvidenceReplayState.from_bytes(data), state)
        empty = make_state([])
        self.assertEqual(EvidenceReplayState.from_bytes(empty.to_bytes()), empty)

    def test_to_bytes_is_canonical(self):
        state = make_state([ENTRY_A])
        self.assertEqual(
            state.to_bytes(),
            b'{"version":1,"sequence":1,"entries":[{"kind":1,'
            b'"round_index":1,"nonce":"' + ENTRY_A[2].hex().encode()
            + b'"}],"mac":"' + state.mac.hex().encode() + b'"}',
        )

    def test_from_bytes_rejects_non_bytes(self):
        with self.assertRaises(TypeError):
            EvidenceReplayState.from_bytes(make_state([]).to_bytes().decode())
        with self.assertRaises(TypeError):
            EvidenceReplayState.from_bytes(42)

    def test_from_bytes_rejects_bad_structure(self):
        good = make_state([ENTRY_A]).to_bytes()
        # Not JSON / not an object.
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(b"{")
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(b"[1,2,3]")
        # Missing, extra, duplicated and out-of-order keys.
        obj = json.loads(good)
        for key in ("version", "sequence", "entries", "mac"):
            broken = dict(obj)
            del broken[key]
            with self.assertRaises(ValueError):
                EvidenceReplayState.from_bytes(_encode_payload(broken))
        broken = dict(obj)
        broken["extra"] = 1
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(
                good.replace(b'"version":1', b'"version":1,"version":1', 1)
            )
        reordered = {
            "sequence": obj["sequence"],
            "version": obj["version"],
            "entries": obj["entries"],
            "mac": obj["mac"],
        }
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(reordered))
        # Entries must be an array of field-ordered objects.
        broken = dict(obj)
        broken["entries"] = {}
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        broken = dict(obj)
        broken["entries"] = [{"round_index": 1, "kind": 1, "nonce": "00"}]
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        broken = dict(obj)
        broken["entries"] = [["kind", 1, "00"]]
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))

    def test_from_bytes_rejects_noncanonical_and_bad_values(self):
        state = make_state([ENTRY_A])
        good = state.to_bytes()
        # Whitespace and pretty-printing are not canonical.
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(b" " + good)
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(
                json.dumps(json.loads(good), indent=2).encode()
            )
        obj = json.loads(good)
        # Uppercase hex is rejected.
        broken = dict(obj)
        broken["mac"] = obj["mac"].upper()
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        # A mac that does not decode to exactly 32 bytes.
        broken = dict(obj)
        broken["mac"] = "00"
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        # version must be 1, sequence must match the entry count.
        broken = dict(obj)
        broken["version"] = 2
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        broken = dict(obj)
        broken["sequence"] = 5
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        # Unsorted entries and cross-kind pairs are rejected.
        broken = dict(obj)
        broken["sequence"] = 2
        broken["entries"] = [
            {"kind": 2, "round_index": 2, "nonce": "ab" * 16},
            {"kind": 1, "round_index": 1, "nonce": "cd" * 16},
        ]
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))
        broken = dict(obj)
        broken["sequence"] = 2
        broken["entries"] = [
            {"kind": 1, "round_index": 1, "nonce": "ab" * 16},
            {"kind": 2, "round_index": 1, "nonce": "ab" * 16},
        ]
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(_encode_payload(broken))

    def test_from_bytes_does_not_verify_mac(self):
        state = make_state([ENTRY_A], mac=b"\xff" * 32)
        decoded = EvidenceReplayState.from_bytes(state.to_bytes())
        self.assertEqual(decoded.mac, b"\xff" * 32)


class EvidenceReplayAuditorInitTest(unittest.TestCase):
    def test_key_contract(self):
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor("shared-secret-key")
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor(bytearray(KEY))
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(b"")

    def test_checkpoint_contract(self):
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, 42)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, "checkpoint")
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, b"not json")
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, b'{"version":1}')

    def test_checkpoint_mac_is_verified(self):
        state = make_state([ENTRY_A])
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(OTHER_KEY, state)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(OTHER_KEY, state.to_bytes())
        auditor = EvidenceReplayAuditor(KEY, state)
        self.assertEqual(auditor.checkpoint, state)
        auditor = EvidenceReplayAuditor(KEY, state.to_bytes())
        self.assertEqual(auditor.checkpoint, state)

    def test_forged_checkpoint_is_rejected(self):
        state = make_state([ENTRY_A], mac=b"\xff" * 32)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, state)
        tampered = make_state([ENTRY_A, ENTRY_B])
        auditor = EvidenceReplayAuditor(KEY, tampered)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_default_checkpoint_is_none(self):
        self.assertIsNone(EvidenceReplayAuditor(KEY).checkpoint)


class EvidenceReplayAuditorAuditTest(unittest.TestCase):
    def setUp(self):
        self.records = make_evidence_records(3)
        self.bounds = make_bound_records(2)
        self.delays = make_delay_records(2)
        self.auditor = EvidenceReplayAuditor(KEY)

    def test_audit_matches_stateless_audit(self):
        record = self.records[0]
        self.assertEqual(self.auditor.audit(record), audit(record, KEY))
        bound = self.bounds[0]
        self.assertEqual(self.auditor.audit(bound), audit_bound(bound, KEY))
        delay = self.delays[0]
        self.assertEqual(
            self.auditor.audit(delay), audit_delay_bound(delay, KEY)
        )

    def test_audit_accepts_canonical_bytes(self):
        auditor = EvidenceReplayAuditor(KEY)
        for record in (self.records[0], self.bounds[0], self.delays[0]):
            measurement = auditor.audit(record.to_bytes())
            self.assertIsInstance(measurement, Measurement)
        self.assertEqual(auditor.checkpoint.sequence, 3)

    def test_checkpoint_advances_per_record(self):
        self.assertIsNone(self.auditor.checkpoint)
        self.auditor.audit(self.records[0])
        first = self.auditor.checkpoint
        self.assertEqual(first.sequence, 1)
        self.assertEqual(
            first.entries,
            ((1, self.records[0].round_index, self.records[0].nonce),),
        )
        self.auditor.audit(self.bounds[0])
        second = self.auditor.checkpoint
        self.assertEqual(second.sequence, 2)
        self.assertEqual(len(second.entries), 2)
        # The checkpoint MAC authenticates under the auditor key.
        self.assertEqual(second.mac, state_mac(KEY, second))
        EvidenceReplayState.from_bytes(second.to_bytes())

    def test_replay_is_rejected_and_state_untouched(self):
        record = self.records[0]
        self.auditor.audit(record)
        before = self.auditor.checkpoint
        with self.assertRaises(ValueError):
            self.auditor.audit(record)
        with self.assertRaises(ValueError):
            self.auditor.audit(record.to_bytes())
        self.assertIs(self.auditor.checkpoint, before)

    def test_cross_kind_replay_is_rejected(self):
        record = self.records[0]
        self.auditor.audit(record)
        before = self.auditor.checkpoint
        with self.assertRaises(ValueError):
            self.auditor.audit(bound_twin(record))
        with self.assertRaises(ValueError):
            self.auditor.audit(delay_twin(record))
        self.assertIs(self.auditor.checkpoint, before)
        # The other direction too: bound first, plain evidence second.
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(bound_twin(record))
        with self.assertRaises(ValueError):
            auditor.audit(record)

    def test_wrong_key_and_forgery_are_rejected(self):
        record = self.records[0]
        forged = replace(record, mac=hmac.new(
            OTHER_KEY, _encode_payload(_evidence_payload(record)),
            hashlib.sha256,
        ).digest())
        with self.assertRaises(ValueError):
            self.auditor.audit(forged)
        wrong_response = rebind(
            replace(record, response=b"\x00" * 32)
        )
        with self.assertRaises(ValueError):
            self.auditor.audit(wrong_response)
        auditor = EvidenceReplayAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.audit(record)
        self.assertIsNone(self.auditor.checkpoint)
        self.assertIsNone(auditor.checkpoint)

    def test_record_contract_errors(self):
        for bad in (42, "record", 3.5, None, object()):
            with self.assertRaises(ValueError):
                self.auditor.audit(bad)
        with self.assertRaises(ValueError):
            self.auditor.audit(bytearray(self.records[0].to_bytes()))
        with self.assertRaises(ValueError):
            self.auditor.audit(b"{}")
        with self.assertRaises(ValueError):
            self.auditor.audit(b"not json")
        self.assertIsNone(self.auditor.checkpoint)

    def test_concurrent_audit_succeeds_at_most_once(self):
        record = self.records[0]
        auditor = EvidenceReplayAuditor(KEY)
        barrier = threading.Barrier(8)
        successes = []
        failures = []

        def worker():
            barrier.wait()
            try:
                auditor.audit(record)
            except ValueError:
                failures.append(1)
            else:
                successes.append(1)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 7)
        self.assertEqual(auditor.checkpoint.sequence, 1)


class EvidenceReplayAuditorBatchTest(unittest.TestCase):
    def setUp(self):
        self.records = make_evidence_records(4)
        self.bounds = make_bound_records(2)
        self.delays = make_delay_records(2)
        self.auditor = EvidenceReplayAuditor(KEY)

    def test_batch_returns_measurements_in_order(self):
        batch = [self.records[0], self.bounds[0], self.delays[0],
                 self.records[1]]
        expected = (
            audit(self.records[0], KEY),
            audit_bound(self.bounds[0], KEY),
            audit_delay_bound(self.delays[0], KEY),
            audit(self.records[1], KEY),
        )
        result = self.auditor.audit_batch(batch)
        self.assertIsInstance(result, tuple)
        self.assertEqual(result, expected)
        self.assertEqual(self.auditor.checkpoint.sequence, 4)

    def test_batch_accepts_bytes_and_tuples(self):
        batch = (self.records[0].to_bytes(), self.bounds[0].to_bytes())
        result = self.auditor.audit_batch(batch)
        self.assertEqual(len(result), 2)
        self.assertEqual(self.auditor.checkpoint.sequence, 2)

    def test_empty_batch_keeps_state(self):
        self.assertEqual(self.auditor.audit_batch([]), ())
        self.assertIsNone(self.auditor.checkpoint)
        self.auditor.audit(self.records[0])
        before = self.auditor.checkpoint
        self.assertEqual(self.auditor.audit_batch(()), ())
        self.assertIs(self.auditor.checkpoint, before)

    def test_batch_contract_errors(self):
        for bad in (42, "batch", b"bytes", {1: 2}):
            with self.assertRaises(ValueError):
                self.auditor.audit_batch(bad)
        with self.assertRaises(ValueError):
            self.auditor.audit_batch([self.records[0], 42])
        self.assertIsNone(self.auditor.checkpoint)

    def test_batch_internal_conflict_rejects_all(self):
        record = self.records[0]
        with self.assertRaises(ValueError):
            self.auditor.audit_batch([record, self.records[1], record])
        with self.assertRaises(ValueError):
            self.auditor.audit_batch([record, bound_twin(record)])
        with self.assertRaises(ValueError):
            self.auditor.audit_batch(
                [bound_twin(record), delay_twin(record)]
            )
        self.assertIsNone(self.auditor.checkpoint)

    def test_batch_failure_is_atomic(self):
        forged = replace(self.records[2], mac=b"\x00" * 32)
        with self.assertRaises(ValueError):
            self.auditor.audit_batch(
                [self.records[0], self.records[1], forged]
            )
        self.assertIsNone(self.auditor.checkpoint)
        # A conflict with the already-consumed ledger also rejects all.
        self.auditor.audit(self.records[0])
        before = self.auditor.checkpoint
        with self.assertRaises(ValueError):
            self.auditor.audit_batch([self.records[1], self.records[0]])
        self.assertIs(self.auditor.checkpoint, before)
        # The un-consumed prefix records are still acceptable afterwards.
        self.auditor.audit(self.records[1])
        self.assertEqual(self.auditor.checkpoint.sequence, 2)

    def test_batch_replay_rejected(self):
        batch = [self.records[0], self.records[1]]
        self.auditor.audit_batch(batch)
        before = self.auditor.checkpoint
        with self.assertRaises(ValueError):
            self.auditor.audit_batch(batch)
        self.assertIs(self.auditor.checkpoint, before)


def expected_measurement(record, *, key=KEY):
    """The stateless public audit result for one record object."""
    if isinstance(record, BoundEvidence):
        return audit_bound(record, key)
    if isinstance(record, DelayBoundEvidence):
        return audit_delay_bound(record, key)
    return audit(record, key)


def ledger_entry(record):
    """The (kind, round_index, nonce) ledger entry of one record object."""
    if isinstance(record, BoundEvidence):
        evidence = record.evidence
        return (2, evidence.round_index, evidence.nonce)
    if isinstance(record, DelayBoundEvidence):
        evidence = record.evidence
        return (3, evidence.round_index, evidence.nonce)
    return (1, record.round_index, record.nonce)


def run_concurrently(testcase, calls):
    """Run zero-argument calls on separate threads released together.

    Returns one ("ok", value), ("value-error", error) or
    ("error", error) triple per call, in call order. Anything that is
    not a ValueError and any call that fails to finish is surfaced to
    the calling test instead of being lost inside the thread.
    """
    barrier = threading.Barrier(len(calls))
    outcomes = [None] * len(calls)

    def make_worker(index, call):
        def worker():
            try:
                barrier.wait(timeout=10)
                outcomes[index] = ("ok", call())
            except ValueError as error:
                outcomes[index] = ("value-error", error)
            except BaseException as error:
                outcomes[index] = ("error", error)
        return worker

    threads = [
        threading.Thread(target=make_worker(index, call), name=f"race-{index}")
        for index, call in enumerate(calls)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    for index, thread in enumerate(threads):
        testcase.assertFalse(
            thread.is_alive(), f"concurrent call {index} did not finish"
        )
    return outcomes


def split_outcomes(testcase, outcomes):
    """Partition run_concurrently output into (values, ValueErrors)."""
    values = []
    failures = []
    for index, (status, payload) in enumerate(outcomes):
        if status == "ok":
            values.append(payload)
        elif status == "value-error":
            failures.append(payload)
        else:
            testcase.fail(f"concurrent call {index} raised {payload!r}")
    return values, failures


class EvidenceReplayAuditorConcurrentBatchTest(unittest.TestCase):
    """Concurrent audit_batch races against the shared ledger.

    Every race is decided by the auditor, never by the test: the
    assertions hold for any legal winner, and no test assumes a
    particular thread runs first or waits a fixed amount of time.
    """

    def test_identical_batches_race(self):
        records = make_evidence_records(2)
        auditor = EvidenceReplayAuditor(KEY)
        outcomes = run_concurrently(self, [
            lambda: auditor.audit_batch(records),
            lambda: auditor.audit_batch(records),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(
            values[0],
            tuple(expected_measurement(record) for record in records),
        )
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_overlapping_batches_exactly_one_succeeds(self):
        records = make_evidence_records(3)
        common, unique_a, unique_b = records
        auditor = EvidenceReplayAuditor(KEY)
        batch_a = [unique_a, common]
        batch_b = [common, unique_b]
        outcomes = run_concurrently(self, [
            lambda: auditor.audit_batch(batch_a),
            lambda: auditor.audit_batch(batch_b),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 1)
        winner = batch_a if outcomes[0][0] == "ok" else batch_b
        loser_unique = unique_b if outcomes[0][0] == "ok" else unique_a
        # The winner returns the stateless measurements in input order.
        self.assertEqual(
            values[0],
            tuple(expected_measurement(record) for record in winner),
        )
        # The ledger gained exactly the winner batch's entries.
        checkpoint = auditor.checkpoint
        self.assertEqual(checkpoint.sequence, len(winner))
        self.assertEqual(
            checkpoint.entries,
            tuple(sorted(ledger_entry(record) for record in winner)),
        )
        # The shared record stays consumed for the loser as well.
        with self.assertRaises(ValueError):
            auditor.audit(common)
        # The loser's unique evidence was not partially consumed.
        auditor.audit(loser_unique)
        self.assertEqual(auditor.checkpoint.sequence, 3)

    def test_single_audit_races_batch(self):
        records = make_evidence_records(2)
        auditor = EvidenceReplayAuditor(KEY)
        outcomes = run_concurrently(self, [
            lambda: auditor.audit(records[0]),
            lambda: auditor.audit_batch([records[0], records[1]]),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 1)
        # The final state equals the winning operation run alone.
        reference = EvidenceReplayAuditor(KEY)
        if outcomes[0][0] == "ok":
            expected = reference.audit(records[0])
        else:
            expected = reference.audit_batch([records[0], records[1]])
        self.assertEqual(values[0], expected)
        self.assertEqual(auditor.checkpoint, reference.checkpoint)
        # The shared evidence is consumed no matter who won.
        with self.assertRaises(ValueError):
            auditor.audit(records[0])

    def test_object_and_canonical_bytes_conflict(self):
        records = make_evidence_records(3)
        auditor = EvidenceReplayAuditor(KEY)
        # The canonical bytes decode to the same evidence and pass the
        # same stateless audit before the race.
        decoded = Evidence.from_bytes(records[0].to_bytes())
        self.assertEqual(decoded, records[0])
        self.assertEqual(audit(decoded, KEY), audit(records[0], KEY))
        batch_objects = [records[0], records[1]]
        batch_bytes = [records[0].to_bytes(), records[2].to_bytes()]
        outcomes = run_concurrently(self, [
            lambda: auditor.audit_batch(batch_objects),
            lambda: auditor.audit_batch(batch_bytes),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 1)
        winner = (
            [records[0], records[1]]
            if outcomes[0][0] == "ok"
            else [records[0], records[2]]
        )
        checkpoint = auditor.checkpoint
        self.assertEqual(checkpoint.sequence, 2)
        self.assertEqual(
            checkpoint.entries,
            tuple(sorted(ledger_entry(record) for record in winner)),
        )
        with self.assertRaises(ValueError):
            auditor.audit(records[0].to_bytes())

    def test_cross_kind_twin_batches_race(self):
        records = make_evidence_records(4)
        record = records[0]
        bound = bound_twin(record)
        delay = delay_twin(record)
        # Each kind passes its own stateless audit before the race, so a
        # rejection below is replay protection, not an authentication
        # failure.
        audit(record, KEY)
        audit_bound(bound, KEY)
        audit_delay_bound(delay, KEY)
        auditor = EvidenceReplayAuditor(KEY)
        batches = [
            [record, records[1]],
            [bound, records[2]],
            [delay, records[3]],
        ]
        outcomes = run_concurrently(self, [
            lambda batch=batch: auditor.audit_batch(batch)
            for batch in batches
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 2)
        winner_index = next(
            index
            for index, (status, _payload) in enumerate(outcomes)
            if status == "ok"
        )
        winner = batches[winner_index]
        self.assertEqual(
            values[0],
            tuple(expected_measurement(record) for record in winner),
        )
        checkpoint = auditor.checkpoint
        self.assertEqual(checkpoint.sequence, 2)
        self.assertEqual(
            checkpoint.entries,
            tuple(sorted(ledger_entry(record) for record in winner)),
        )
        # The shared (round_index, nonce) pair stays consumed under
        # every evidence kind.
        with self.assertRaises(ValueError):
            auditor.audit(record)
        with self.assertRaises(ValueError):
            auditor.audit(bound)
        with self.assertRaises(ValueError):
            auditor.audit(delay)
        # Neither losing batch was partially consumed.
        for index, batch in enumerate(batches):
            if index != winner_index:
                auditor.audit(batch[1])
        self.assertEqual(auditor.checkpoint.sequence, 4)

    def test_disjoint_batches_all_succeed(self):
        records = make_evidence_records(8)
        batches = [records[index:index + 2] for index in range(0, 8, 2)]
        auditor = EvidenceReplayAuditor(KEY)
        outcomes = run_concurrently(self, [
            lambda batch=batch: auditor.audit_batch(list(batch))
            for batch in batches
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(failures, [])
        self.assertEqual(len(values), len(batches))
        # Each batch got its own measurements back in input order.
        for batch, (status, payload) in zip(batches, outcomes):
            self.assertEqual(status, "ok")
            self.assertEqual(
                payload,
                tuple(expected_measurement(record) for record in batch),
            )
        # No record was lost: sequence equals the consumed entry count.
        checkpoint = auditor.checkpoint
        self.assertEqual(checkpoint.sequence, len(records))
        self.assertEqual(
            checkpoint.entries,
            tuple(sorted(ledger_entry(record) for record in records)),
        )

    def test_empty_batch_races_without_consuming(self):
        records = make_evidence_records(2)
        auditor = EvidenceReplayAuditor(KEY)
        outcomes = run_concurrently(self, [
            lambda: auditor.audit_batch([]),
            lambda: auditor.audit_batch(records),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(failures, [])
        self.assertEqual(outcomes[0], ("ok", ()))
        self.assertEqual(
            outcomes[1][1],
            tuple(expected_measurement(record) for record in records),
        )
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_forged_batch_races_legal_batch(self):
        records = make_evidence_records(4)
        forged = replace(records[3], mac=b"\x00" * 32)
        auditor = EvidenceReplayAuditor(KEY)
        legal_batch = [records[0], records[1]]
        forged_batch = [records[2], forged]
        outcomes = run_concurrently(self, [
            lambda: auditor.audit_batch(legal_batch),
            lambda: auditor.audit_batch(forged_batch),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(
            values[0],
            tuple(expected_measurement(record) for record in legal_batch),
        )
        # The legal batch committed in full. The judgment is the final
        # state, not an unchanged checkpoint across the forged call —
        # the legal call legitimately advances the ledger.
        reference = EvidenceReplayAuditor(KEY)
        reference.audit_batch(legal_batch)
        self.assertEqual(auditor.checkpoint, reference.checkpoint)
        # The forged batch left nothing behind, not even its valid
        # prefix record.
        auditor.audit_batch([records[2], records[3]])
        self.assertEqual(auditor.checkpoint.sequence, 4)

    def test_checkpoint_after_race_restores_as_object_and_bytes(self):
        records = make_evidence_records(4)
        auditor = EvidenceReplayAuditor(KEY)
        outcomes = run_concurrently(self, [
            lambda: auditor.audit_batch([records[0], records[1]]),
            lambda: auditor.audit_batch([records[1], records[2]]),
        ])
        values, failures = split_outcomes(self, outcomes)
        self.assertEqual(len(values), 1)
        self.assertEqual(len(failures), 1)
        checkpoint = auditor.checkpoint
        consumed = set(checkpoint.entries)
        self.assertEqual(len(consumed), 2)
        for restored in (
            EvidenceReplayAuditor(KEY, checkpoint),
            EvidenceReplayAuditor(KEY, checkpoint.to_bytes()),
        ):
            self.assertEqual(restored.checkpoint, checkpoint)
            # Every consumed evidence stays consumed after the restart,
            # as an object, as canonical bytes and across kinds.
            for record in records[:3]:
                if ledger_entry(record) in consumed:
                    with self.assertRaises(ValueError):
                        restored.audit(record)
                    with self.assertRaises(ValueError):
                        restored.audit(record.to_bytes())
                    with self.assertRaises(ValueError):
                        restored.audit(bound_twin(record))
            # The evidence no batch consumed is still accepted.
            measurement = restored.audit(records[3])
            self.assertEqual(measurement, audit(records[3], KEY))
            self.assertEqual(
                restored.checkpoint.sequence, checkpoint.sequence + 1
            )


class EvidenceReplayAuditorRestartTest(unittest.TestCase):
    def test_checkpoint_bytes_resume_across_instances(self):
        records = make_evidence_records(3)
        first = EvidenceReplayAuditor(KEY)
        first.audit(records[0])
        first.audit(records[1])
        checkpoint_bytes = first.checkpoint.to_bytes()

        resumed = EvidenceReplayAuditor(KEY, checkpoint_bytes)
        self.assertEqual(resumed.checkpoint, first.checkpoint)
        # Already-consumed evidence stays consumed after the restart.
        with self.assertRaises(ValueError):
            resumed.audit(records[0])
        with self.assertRaises(ValueError):
            resumed.audit(bound_twin(records[1]))
        # New evidence is consumed from the current ledger sequence.
        measurement = resumed.audit(records[2])
        self.assertEqual(measurement, audit(records[2], KEY))
        self.assertEqual(resumed.checkpoint.sequence, 3)

    def test_checkpoint_object_resume(self):
        records = make_evidence_records(2)
        first = EvidenceReplayAuditor(KEY)
        first.audit(records[0])
        resumed = EvidenceReplayAuditor(KEY, first.checkpoint)
        with self.assertRaises(ValueError):
            resumed.audit(records[0])
        resumed.audit(records[1])
        self.assertEqual(resumed.checkpoint.sequence, 2)

    def test_out_of_order_checkpoint_is_rejected(self):
        entries = ((2, 2, b"\x0b" * 16), (1, 1, b"\x0a" * 16))
        mac = hmac.new(
            KEY,
            b"NPRS1" + _encode_payload({
                "version": 1,
                "sequence": 2,
                "entries": [
                    {"kind": 2, "round_index": 2, "nonce": "0b" * 16},
                    {"kind": 1, "round_index": 1, "nonce": "0a" * 16},
                ],
            }),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            EvidenceReplayState(1, 2, entries, mac)


class StatelessAuditCompatibilityTest(unittest.TestCase):
    def test_stateless_audits_stay_pure(self):
        records = make_evidence_records(2)
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(records[0])
        # The public stateless audits neither know nor change the ledger.
        self.assertEqual(audit(records[0], KEY), audit(records[0], KEY))
        with self.assertRaises(ValueError):
            audit(records[0], OTHER_KEY)


if __name__ == "__main__":
    unittest.main()
