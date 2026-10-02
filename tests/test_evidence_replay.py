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
