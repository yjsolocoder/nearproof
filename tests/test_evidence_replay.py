"""Tests for the cross-instance evidence-consumption ledger.

EvidenceReplayState / EvidenceReplayAuditor wrap the three pure audits
(audit, audit_bound, audit_delay_bound) with a restartable ledger keyed
on (round_index, nonce). The single-record result and error behaviour of
the three public audits is unchanged; these tests cover consumption,
replay rejection, cross-kind collision, restart, batching, concurrency
and the checkpoint encoding.
"""

import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BoundEvidence,
    DelayBoundEvidence,
    Evidence,
    EvidenceReplayAuditor,
    EvidenceReplayState,
    Measurement,
    Prover,
    Verifier,
    audit,
    audit_bound,
    audit_delay_bound,
    context_digest,
    keyed_response,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
CONTEXT = b"c" * 32
OPENING = b"o" * 32
DIGEST = context_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def make_evidence(*, key=KEY, round_index=1):
    clock = SteppedClock()
    verifier = Verifier(key, clock=clock, replay_protection=True)
    challenge = verifier.new_challenge()
    response = Prover(key).respond(challenge)
    clock.now += 1e-6
    record = verifier.verify_evidence(challenge, response, clock.now - 1e-6)
    assert record.round_index == round_index
    return record


def make_bound_evidence():
    clock = SteppedClock()
    verifier = Verifier(KEY, clock=clock, replay_protection=True)
    prover = Prover(KEY)
    challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
    response = prover.reveal(challenge, CONTEXT, OPENING)
    clock.now += 1e-6
    return verifier.verify_bound(challenge, response, 0.0, opening=OPENING)


def make_delay_evidence(*, trip=0.005, max_delay=0.01):
    clock = SteppedClock(start=100.0)
    verifier = Verifier(KEY, clock=clock, replay_protection=True)
    prover = Prover(KEY)
    challenge, issued_at = verifier.new_delay_challenge(
        CONTEXT, DIGEST, max_delay_seconds=max_delay
    )
    response = prover.reveal(challenge, CONTEXT, OPENING)
    clock.now += trip
    return verifier.verify_delay_bound(
        challenge, response, issued_at, opening=OPENING
    )


def plain_replica(record, key=KEY):
    """A valid plain Evidence over the same (round_index, nonce) slot.

    A key holder can always mint a well-formed plain record for any
    round/nonce; its response is the plain keyed response rather than the
    bound response, so this passes audit() and reaches the ledger check.
    """
    inner = record.evidence
    response = keyed_response(key, inner.nonce)
    payload = {
        "version": 1,
        "round_index": inner.round_index,
        "nonce": inner.nonce.hex(),
        "response": response.hex(),
        "start": inner.start,
        "end": inner.end,
        "speed": inner.speed,
        "elapsed": inner.elapsed,
        "distance": inner.distance,
        "result": "accepted",
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    payload["mac"] = hmac.new(key, body, hashlib.sha256).hexdigest()
    return Evidence.from_bytes(
        json.dumps(payload, separators=(",", ":")).encode()
    )


def payload_of(state):
    obj = json.loads(state.to_bytes())
    del obj[-1]
    return obj


class StateContractTest(unittest.TestCase):
    def test_empty_state_encoding(self):
        auditor = EvidenceReplayAuditor(KEY)
        state = auditor.checkpoint
        root = hashlib.sha256(b"NPER2").hexdigest().encode()
        self.assertEqual(
            state.to_bytes(),
            b'[1,0,[],' + b'"' + root + b'","' + state.mac.hex().encode() + b'"]',
        )
        # MAC definition: NPER1 over the canonical array without the mac.
        content = b'[1,0,[],' + b'"' + root + b'"]'
        self.assertEqual(
            state.mac, hmac.new(KEY, b"NPER1" + content, hashlib.sha256).digest()
        )

    def test_state_is_frozen(self):
        state = EvidenceReplayAuditor(KEY).checkpoint
        with self.assertRaises(dataclasses.FrozenInstanceError):
            state.sequence = 1

    def test_state_construction_contract(self):
        digest = b"\x01" * 32
        good_kwargs = dict(
            version=1,
            sequence=1,
            entries=((1, 5, b"n" * 16),),
            digest=digest,
            mac=b"\x02" * 32,
        )
        state = EvidenceReplayState(**good_kwargs)
        self.assertEqual(state.entries, ((1, 5, b"n" * 16),))
        # wrong shape
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "version": True})
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "sequence": True})
        with self.assertRaises(ValueError):
            EvidenceReplayState(**{**good_kwargs, "version": 2})
        with self.assertRaises(ValueError):
            EvidenceReplayState(**{**good_kwargs, "sequence": -1})
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "entries": 42})
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "entries": ((1,),)})
        with self.assertRaises(ValueError):
            EvidenceReplayState(**{**good_kwargs, "entries": ((9, 5, b"n"),)})
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "entries": ((1, 1.5, b"n"),)})
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "entries": ((1, 5, "n"),)})
        with self.assertRaises(TypeError):
            EvidenceReplayState(**{**good_kwargs, "digest": "x"})
        with self.assertRaises(ValueError):
            EvidenceReplayState(**{**good_kwargs, "digest": b"\x01" * 31})

    def test_state_list_entries_normalized_to_tuple(self):
        state = EvidenceReplayState(
            version=1,
            sequence=1,
            entries=[[2, 7, b"z"]],
            digest=b"\x01" * 32,
            mac=b"\x02" * 32,
        )
        self.assertEqual(state.entries, ((2, 7, b"z"),))

    def test_from_bytes_round_trip_and_rejections(self):
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(make_evidence())
        state = auditor.checkpoint
        self.assertEqual(EvidenceReplayState.from_bytes(state.to_bytes()), state)
        # non-bytes
        for bad in (state.to_bytes().decode(), 1, None, object()):
            with self.assertRaises(TypeError):
                EvidenceReplayState.from_bytes(bad)
        # malformed / contract violations
        for bad in (
            b"",
            b"not json",
            b"{}",
            b"[1,0,[]," + b'"' + b"00" * 32 + b'"]',  # four fields
            b'[2,0,[],"' + b"00" * 32 + b'","' + b"00" * 32 + b'"]',
            b'[1,0,[[1]],"' + b"00" * 32 + b'","' + b"00" * 32 + b'"]',
            b'[1,0,[[9,1,"00"]],"' + b"00" * 32 + b'","' + b"00" * 32 + b'"]',
            b'[1,0,[[1,1,"zz"]],"' + b"00" * 32 + b'","' + b"00" * 32 + b'"]',
        ):
            with self.assertRaises(ValueError, msg=bad):
                EvidenceReplayState.from_bytes(bad)
        # entries field of the wrong JSON type is a field-shape TypeError
        with self.assertRaises(TypeError):
            EvidenceReplayState.from_bytes(
                b'[1,0,{},"' + b"00" * 32 + b'","' + b"00" * 32 + b'"]'
            )
        # non-canonical spelling
        obj = json.loads(state.to_bytes())
        with self.assertRaises(ValueError):
            EvidenceReplayState.from_bytes(json.dumps(obj, indent=2).encode())
        # from_bytes does not verify the digest chain or MAC
        forged = json.loads(state.to_bytes())
        forged[-1] = "00" * 32
        forged_blob = json.dumps(forged, separators=(",", ":")).encode()
        parsed = EvidenceReplayState.from_bytes(forged_blob)
        self.assertEqual(parsed.mac, b"\x00" * 32)


class AuditorConstructorTest(unittest.TestCase):
    def test_key_must_be_nonempty_bytes(self):
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor("key")
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor(None)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(b"")

    def test_checkpoint_wrong_type(self):
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor(KEY, checkpoint={"x": 1})
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor(KEY, checkpoint="state")
        with self.assertRaises(TypeError):
            EvidenceReplayAuditor(KEY, checkpoint=42)

    def test_checkpoint_bad_bytes_is_value_error(self):
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, checkpoint=b"not-a-state")

    def test_checkpoint_wrong_key_rejected(self):
        state = EvidenceReplayAuditor(KEY).checkpoint
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(OTHER_KEY, checkpoint=state)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(OTHER_KEY, checkpoint=state.to_bytes())

    def test_checkpoint_inconsistent_sequence_rejected(self):
        state = EvidenceReplayAuditor(KEY).checkpoint
        tampered = dataclasses.replace(state, sequence=1)
        # MAC fails first
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, checkpoint=tampered)

    def test_checkpoint_forged_after_valid_mac(self):
        # A checkpoint re-MAC'd with the key but with a tampered digest
        # must be rejected as out-of-order/inconsistent state.
        state = EvidenceReplayAuditor(KEY).checkpoint
        tampered = dataclasses.replace(state, digest=b"\x00" * 32)
        content = json.loads(tampered.to_bytes())[:-1]
        remac = hmac.new(
            KEY,
            b"NPER1" + json.dumps(content, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        tampered = dataclasses.replace(tampered, mac=remac)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, checkpoint=tampered)


class AuditSingleTest(unittest.TestCase):
    def test_audit_plain_object_and_bytes(self):
        auditor = EvidenceReplayAuditor(KEY)
        evidence = make_evidence()
        measurement = auditor.audit(evidence)
        self.assertEqual(measurement, audit(evidence, KEY))
        self.assertIsInstance(measurement, Measurement)
        # a second round, fed as canonical bytes, is accepted too
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        ch1 = verifier.new_challenge()
        r1 = prover.respond(ch1)
        clock.now += 1e-6
        ev1 = verifier.verify_evidence(ch1, r1, 0.0)
        ch2 = verifier.new_challenge()
        r2 = prover.respond(ch2)
        clock.now += 1e-6
        ev2 = verifier.verify_evidence(ch2, r2, clock.now - 1e-6)
        self.assertEqual((ev1.round_index, ev2.round_index), (1, 2))
        a2 = EvidenceReplayAuditor(KEY)
        self.assertEqual(a2.audit(ev1), audit(ev1, KEY))
        self.assertEqual(a2.audit(ev2.to_bytes()), audit(ev2, KEY))

    def test_replay_same_evidence_rejected(self):
        auditor = EvidenceReplayAuditor(KEY)
        evidence = make_evidence()
        auditor.audit(evidence)
        for form in (evidence, evidence.to_bytes()):
            with self.assertRaises(ValueError):
                auditor.audit(form)

    def test_audit_bound(self):
        auditor = EvidenceReplayAuditor(KEY)
        record = make_bound_evidence()
        measurement = auditor.audit(record)
        self.assertEqual(measurement, audit_bound(record, KEY))
        with self.assertRaises(ValueError):
            auditor.audit(record.to_bytes())

    def test_audit_delay_bound(self):
        auditor = EvidenceReplayAuditor(KEY)
        record = make_delay_evidence()
        measurement = auditor.audit(record)
        self.assertEqual(measurement, audit_delay_bound(record, KEY))
        with self.assertRaises(ValueError):
            auditor.audit(record.to_bytes())

    def test_cross_kind_replay_rejected(self):
        # The same round_index and nonce under another evidence kind must
        # not be consumable twice, even when the second record is itself
        # cryptographically valid for the key.
        bound = make_bound_evidence()
        replica = plain_replica(bound)
        self.assertEqual(
            (replica.round_index, replica.nonce),
            (bound.evidence.round_index, bound.evidence.nonce),
        )
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(bound)
        with self.assertRaises(ValueError):
            auditor.audit(replica)
        # reverse order too
        auditor2 = EvidenceReplayAuditor(KEY)
        auditor2.audit(replica)
        with self.assertRaises(ValueError):
            auditor2.audit(bound)
        # delay-bound kind participates as well
        delay = make_delay_evidence()
        delay_replica = plain_replica(delay)
        auditor3 = EvidenceReplayAuditor(KEY)
        auditor3.audit(delay_replica)
        with self.assertRaises(ValueError):
            auditor3.audit(delay)

    def test_wrong_key_rejected_without_progress(self):
        evidence = make_evidence()
        auditor = EvidenceReplayAuditor(OTHER_KEY)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(evidence)
        self.assertEqual(auditor.checkpoint, before)

    def test_bad_record_type(self):
        auditor = EvidenceReplayAuditor(KEY)
        for bad in ("x", 1, None, [1], {}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertEqual(auditor.checkpoint.sequence, 0)

    def test_garbage_bytes_rejected(self):
        auditor = EvidenceReplayAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(b"not any evidence")

    def test_tampered_evidence_checks_unchanged(self):
        # A valid-MAC but tampered elapsed is rejected by the underlying
        # audit and must not consume the slot.
        evidence = make_evidence()
        obj = json.loads(evidence.to_bytes())
        del obj["mac"]
        obj["elapsed"] = evidence.elapsed + 1.0
        blob = json.dumps(obj, separators=(",", ":")).encode()
        obj["mac"] = hmac.new(KEY, blob, hashlib.sha256).hexdigest()
        tampered = Evidence.from_bytes(
            json.dumps(obj, separators=(",", ":")).encode()
        )
        auditor = EvidenceReplayAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        # the original still consumes
        self.assertIsInstance(auditor.audit(evidence), Measurement)

    def test_checkpoint_advances(self):
        auditor = EvidenceReplayAuditor(KEY)
        self.assertEqual(auditor.checkpoint.sequence, 0)
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        for expected in (1, 2, 3):
            challenge = verifier.new_challenge()
            response = prover.respond(challenge)
            clock.now += 1e-6
            evidence = verifier.verify_evidence(challenge, response, 0.0)
            auditor.audit(evidence)
        state = auditor.checkpoint
        self.assertEqual(state.sequence, 3)
        self.assertEqual([entry[0] for entry in state.entries], [1, 1, 1])
        self.assertEqual([entry[1] for entry in state.entries], [1, 2, 3])


class RestartTest(unittest.TestCase):
    def test_resume_from_state_and_bytes(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        auditor = EvidenceReplayAuditor(KEY)
        consumed = []
        for _ in range(3):
            challenge = verifier.new_challenge()
            response = prover.respond(challenge)
            clock.now += 1e-6
            evidence = verifier.verify_evidence(challenge, response, 0.0)
            consumed.append(evidence)
            auditor.audit(evidence)
        checkpoint = auditor.checkpoint
        # old entries still rejected after restart
        resumed = EvidenceReplayAuditor(KEY, checkpoint=checkpoint)
        with self.assertRaises(ValueError):
            resumed.audit(consumed[0])
        # and from canonical bytes, with identical state
        resumed_bytes = EvidenceReplayAuditor(
            KEY, checkpoint=checkpoint.to_bytes()
        )
        self.assertEqual(resumed_bytes.checkpoint, checkpoint)
        with self.assertRaises(ValueError):
            resumed_bytes.audit(consumed[2].to_bytes())
        # a fresh round continues at sequence 4
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        clock.now += 1e-6
        new_evidence = verifier.verify_evidence(challenge, response, 0.0)
        resumed.audit(new_evidence)
        self.assertEqual(resumed.checkpoint.sequence, 4)
        self.assertEqual(resumed.checkpoint.entries[3][1], 4)

    def test_mixed_kinds_survive_restart(self):
        auditor = EvidenceReplayAuditor(KEY)
        bound = make_bound_evidence()
        delay = make_delay_evidence()
        auditor.audit(bound)
        auditor.audit(delay)
        checkpoint = auditor.checkpoint
        self.assertEqual([e[0] for e in checkpoint.entries], [2, 3])
        resumed = EvidenceReplayAuditor(KEY, checkpoint=checkpoint)
        self.assertEqual(resumed.checkpoint, checkpoint)
        with self.assertRaises(ValueError):
            resumed.audit(delay)
        with self.assertRaises(ValueError):
            resumed.audit(plain_replica(bound))

    def test_reordered_checkpoint_rejected(self):
        # A checkpoint whose carried entries do not match their digest
        # chain (entries reordered, digest and MAC kept/forged) is an
        # out-of-order state and must be rejected on adoption.
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        auditor = EvidenceReplayAuditor(KEY)
        records = []
        for _ in range(2):
            challenge = verifier.new_challenge()
            response = prover.respond(challenge)
            clock.now += 1e-6
            evidence = verifier.verify_evidence(challenge, response, 0.0)
            records.append(evidence)
            auditor.audit(evidence)
        original = auditor.checkpoint
        reordered = (original.entries[1], original.entries[0])
        # Keep the genuinely-produced digest, which chains the entries in
        # their ORIGINAL order, while presenting them swapped: the replay
        # diverges from the carried head.
        candidate = EvidenceReplayState(
            version=1,
            sequence=2,
            entries=reordered,
            digest=original.digest,
            mac=b"\x00" * 32,
        )
        content = [
            1,
            2,
            [[k, r, n.hex()] for k, r, n in reordered],
            original.digest.hex(),
        ]
        mac = hmac.new(
            KEY,
            b"NPER1" + json.dumps(content, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(candidate, mac=mac)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, checkpoint=forged)
        # the untouched checkpoint still adopts cleanly
        EvidenceReplayAuditor(KEY, checkpoint=original)

    def test_sequence_mismatch_checkpoint_rejected(self):
        # A structurally valid, MAC-forged state whose sequence disagrees
        # with its entry count is rejected as an out-of-order state.
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(make_evidence())
        state = auditor.checkpoint
        candidate = dataclasses.replace(state, sequence=9)
        content = [
            1,
            9,
            [
                [k, r, n.hex()]
                for k, r, n in candidate.entries
            ],
            candidate.digest.hex(),
        ]
        mac = hmac.new(
            KEY,
            b"NPER1" + json.dumps(content, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(candidate, mac=mac)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, checkpoint=forged)

    def test_duplicate_entry_checkpoint_rejected(self):
        import hashlib
        import hmac

        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(make_evidence())
        kind, round_index, nonce = auditor.checkpoint.entries[0]
        digest = hashlib.sha256(b"NPER2").digest()
        entries = (
            (kind, round_index, nonce),
            (kind, round_index, nonce),
        )
        for index, (k, r, n) in enumerate(entries, start=1):
            identity = json.dumps(
                [k, r, n.hex()], separators=(",", ":")
            ).encode()
            digest = hashlib.sha256(
                b"NPER3" + digest + index.to_bytes(8, "big") + identity
            ).digest()
        candidate = EvidenceReplayState(
            version=1, sequence=2, entries=entries, digest=digest, mac=b"\x00" * 32
        )
        content = json.dumps(
            [1, 2, [[k, r, n.hex()] for k, r, n in entries], digest.hex()],
            separators=(",", ":"),
        ).encode()
        mac = hmac.new(KEY, b"NPER1" + content, hashlib.sha256).digest()
        forged = dataclasses.replace(candidate, mac=mac)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, checkpoint=forged)


class AuditBatchTest(unittest.TestCase):
    def _two_evidences(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        out = []
        for _ in range(2):
            challenge = verifier.new_challenge()
            response = prover.respond(challenge)
            clock.now += 1e-6
            out.append(verifier.verify_evidence(challenge, response, 0.0))
        return out

    def test_batch_returns_measurements_in_order(self):
        evidences = self._two_evidences()
        auditor = EvidenceReplayAuditor(KEY)
        measurements = auditor.audit_batch(
            [evidences[0], evidences[1].to_bytes()]
        )
        self.assertIsInstance(measurements, tuple)
        self.assertEqual(
            measurements,
            (audit(evidences[0], KEY), audit(evidences[1], KEY)),
        )
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_empty_batch_keeps_state(self):
        auditor = EvidenceReplayAuditor(KEY)
        self.assertEqual(auditor.audit_batch(()), ())
        self.assertEqual(auditor.audit_batch([]), ())
        self.assertEqual(auditor.checkpoint.sequence, 0)
        # generator is fine too
        self.assertEqual(auditor.audit_batch(_ for _ in ()), ())

    def test_intra_batch_duplicate_rejected_atomically(self):
        evidences = self._two_evidences()
        auditor = EvidenceReplayAuditor(KEY)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch([evidences[0], evidences[0]])
        self.assertEqual(auditor.checkpoint, before)
        # the first is still consumable afterwards
        auditor.audit(evidences[0])

    def test_batch_failure_after_prior_commit_is_atomic(self):
        evidences = self._two_evidences()
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(evidences[0])
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_batch([evidences[1], evidences[0]])
        self.assertEqual(auditor.checkpoint, before)
        # mixed valid + wrong key in the batch rolls back too
        with self.assertRaises(ValueError):
            auditor.audit_batch([evidences[1].to_bytes(), b"garbage"])
        self.assertEqual(auditor.checkpoint, before)
        auditor.audit(evidences[1])
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_non_iterable_is_type_error(self):
        auditor = EvidenceReplayAuditor(KEY)
        with self.assertRaises(TypeError):
            auditor.audit_batch(42)

    def test_batch_mixed_kinds(self):
        plain = make_evidence(round_index=1)
        bound = make_bound_evidence()
        delay = make_delay_evidence()
        # plain fixture and bound fixture share round 1 nonce? no — they
        # are independent verifiers with random nonces, so all distinct.
        auditor = EvidenceReplayAuditor(KEY)
        measurements = auditor.audit_batch([plain, bound.to_bytes(), delay])
        self.assertEqual(len(measurements), 3)
        self.assertEqual(
            [e[0] for e in auditor.checkpoint.entries], [1, 2, 3]
        )


class ConcurrentAuditTest(unittest.TestCase):
    def test_same_slot_succeeds_at_most_once(self):
        evidence = make_evidence()
        auditor = EvidenceReplayAuditor(KEY)
        successes = []
        errors = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()
            try:
                successes.append(auditor.audit(evidence))
            except ValueError as error:
                errors.append(error)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 15)
        self.assertEqual(auditor.checkpoint.sequence, 1)

    def test_distinct_slots_all_consumed_once(self):
        clock = SteppedClock()
        verifier = Verifier(KEY, clock=clock, replay_protection=True)
        prover = Prover(KEY)
        records = []
        for _ in range(32):
            challenge = verifier.new_challenge()
            response = prover.respond(challenge)
            clock.now += 1e-6
            records.append(
                verifier.verify_evidence(challenge, response, 0.0)
            )
        auditor = EvidenceReplayAuditor(KEY)

        def worker(batch):
            for record in batch:
                try:
                    auditor.audit(record)
                except ValueError:
                    pass

        chunks = [records[i::4] for i in range(4)]
        threads = [threading.Thread(target=worker, args=(chunk,)) for chunk in chunks]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(auditor.checkpoint.sequence, 32)


if __name__ == "__main__":
    unittest.main()
