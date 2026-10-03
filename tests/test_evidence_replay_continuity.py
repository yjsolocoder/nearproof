"""State-regression tests for continuous evidence consumption and recovery.

Complements ``test_evidence_replay.py``: instead of single, batch and
concurrent operations in isolation, this module drives one long, fully
deterministic script that interleaves ``audit``, ``audit_batch``,
checkpoint exports and restarts on fresh instances, covering all three
ranging evidence kinds submitted alternately as objects and canonical
bytes. Every expectation is derived from an independent in-test oracle —
the stateless public audits plus a local set of accepted consumption
identifiers — never from the result of another ``EvidenceReplayAuditor``.

No real clock or thread scheduling is involved: the evidence is minted
with a stepped clock and every failure message lists the operation that
first deviated together with the prior consumption history, so each
regression is reproducible step by step.
"""

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
    _bound_evidence_mac,
    _bound_evidence_payload,
    _delay_bound_evidence_mac,
    _delay_bound_evidence_payload,
    _evidence_mac,
    _evidence_payload,
    _evidence_replay_state_mac,
    _evidence_replay_state_payload,
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

_HEX = b"0123456789abcdef"

ENTRY_A = (1, 1, b"\x0a" * 16)


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


def as_object(record):
    """Decode canonical bytes to the matching record; objects pass through."""
    if isinstance(record, (Evidence, BoundEvidence, DelayBoundEvidence)):
        return record
    for cls in (DelayBoundEvidence, BoundEvidence, Evidence):
        try:
            return cls.from_bytes(record)
        except ValueError:
            continue
    raise ValueError(
        "canonical bytes match none of the three evidence record encodings"
    )


def stateless_measurement(record, *, key=KEY):
    """The expected Measurement, recomputed via the matching public audit."""
    record = as_object(record)
    if isinstance(record, BoundEvidence):
        return audit_bound(record, key)
    if isinstance(record, DelayBoundEvidence):
        return audit_delay_bound(record, key)
    return audit(record, key)


def ledger_entry(record):
    """The (kind, round_index, nonce) ledger identifier of one record."""
    record = as_object(record)
    if isinstance(record, BoundEvidence):
        evidence = record.evidence
        return (2, evidence.round_index, evidence.nonce)
    if isinstance(record, DelayBoundEvidence):
        evidence = record.evidence
        return (3, evidence.round_index, evidence.nonce)
    return (1, record.round_index, record.nonce)


def state_mac(key, state):
    return _evidence_replay_state_mac(key, _evidence_replay_state_payload(state))


def make_state(entries, *, key=KEY, mac=None):
    entries = tuple(sorted(entries))
    placeholder = EvidenceReplayState(1, len(entries), entries, b"\x00" * 32)
    if mac is None:
        mac = state_mac(key, placeholder)
    return EvidenceReplayState(1, len(entries), entries, mac)


class ScriptedSession:
    """Drive one auditor through a named, deterministic operation script.

    The expected state is maintained independently here: accepted
    identifiers live in ``self.entries`` and expected results come from
    the stateless public audits. The auditor under test is never used as
    its own oracle, and every restart swaps in a brand-new instance.
    """

    def __init__(self, case, key=KEY):
        self.case = case
        self.key = key
        self.auditor = EvidenceReplayAuditor(key)
        self.entries = set()
        self.history = []

    # -- diagnostics ----------------------------------------------------

    def _why(self, label):
        lines = [
            f"first deviation at operation: {label}",
            "successful consumption history so far:",
        ]
        if self.history:
            lines.extend(
                f"  {index}. {item}" for index, item in enumerate(self.history, 1)
            )
        else:
            lines.append("  <none>")
        return "\n".join(lines)

    # -- checkpoint expectations ---------------------------------------

    def _snapshot(self):
        checkpoint = self.auditor.checkpoint
        return None if checkpoint is None else checkpoint.to_bytes()

    def expect_none(self, label):
        self.case.assertIsNone(self.auditor.checkpoint, self._why(label))

    def expect_checkpoint(self, label, *, before=None, committed=()):
        checkpoint = self.auditor.checkpoint
        self.case.assertIsNotNone(checkpoint, self._why(label))
        expected_entries = tuple(sorted(self.entries))
        self.case.assertEqual(
            checkpoint.sequence, len(expected_entries), self._why(label)
        )
        self.case.assertEqual(
            checkpoint.sequence,
            len(checkpoint.entries),
            self._why(label),
        )
        self.case.assertEqual(
            checkpoint.entries, expected_entries, self._why(label)
        )
        if before is not None:
            # A successful operation adds exactly its own identifiers.
            self.case.assertEqual(
                set(checkpoint.entries) - before,
                set(committed),
                self._why(label),
            )
            self.case.assertTrue(
                before.issubset(set(checkpoint.entries)), self._why(label)
            )
        self.case.assertEqual(
            checkpoint.mac,
            state_mac(self.key, checkpoint),
            self._why(label),
        )
        self.case.assertEqual(
            EvidenceReplayState.from_bytes(checkpoint.to_bytes()),
            checkpoint,
            self._why(label),
        )

    def expect_unchanged(self, label, snapshot):
        checkpoint = self.auditor.checkpoint
        if snapshot is None:
            self.case.assertIsNone(checkpoint, self._why(label))
        else:
            self.case.assertIsNotNone(checkpoint, self._why(label))
            self.case.assertEqual(
                checkpoint.to_bytes(), snapshot, self._why(label)
            )

    # -- successful operations -----------------------------------------

    def accept_single(self, label, record):
        expected = stateless_measurement(record, key=self.key)
        entry = ledger_entry(record)
        try:
            actual = self.auditor.audit(record)
        except ValueError as error:
            self.case.fail(
                f"{self._why(label)}\nexpected audit success,"
                f" got ValueError: {error!r}"
            )
        self.case.assertIsInstance(actual, Measurement, self._why(label))
        self.case.assertEqual(actual, expected, self._why(label))
        before = set(self.entries)
        self.entries.add(entry)
        self.expect_checkpoint(label, before=before, committed=[entry])
        self.history.append(f"audit -> entry {entry} ({label})")
        return actual

    def accept_batch(self, label, records):
        expected = tuple(
            stateless_measurement(record, key=self.key) for record in records
        )
        entries = [ledger_entry(record) for record in records]
        self.case.assertTrue(records, self._why(label))
        try:
            actual = self.auditor.audit_batch(records)
        except ValueError as error:
            self.case.fail(
                f"{self._why(label)}\nexpected audit_batch success,"
                f" got ValueError: {error!r}"
            )
        self.case.assertIsInstance(actual, tuple, self._why(label))
        self.case.assertEqual(
            list(actual), list(expected), self._why(label)
        )
        before = set(self.entries)
        self.entries.update(entries)
        self.expect_checkpoint(label, before=before, committed=entries)
        self.history.append(
            f"audit_batch ({len(entries)} records) -> entries {entries} ({label})"
        )
        return actual

    def accept_empty(self, label, records):
        self.case.assertEqual(len(records), 0, self._why(label))
        snapshot = self._snapshot()
        self.case.assertEqual(
            self.auditor.audit_batch(records), (), self._why(label)
        )
        self.expect_unchanged(label, snapshot)

    # -- rejected operations -------------------------------------------

    def reject_used_single(self, label, variants):
        """Replay/cross-kind rejection of statelessly valid records.

        Every variant first passes its matching stateless public audit,
        so the auditor's rejection can only come from the consumption
        conflict. Nothing is consumed, variant by variant.
        """
        for variant in variants:
            self.case.assertIsInstance(
                stateless_measurement(variant, key=self.key),
                Measurement,
                self._why(label),
            )
        snapshot = self._snapshot()
        for variant in variants:
            try:
                self.auditor.audit(variant)
            except ValueError:
                pass
            else:
                self.case.fail(
                    f"{self._why(label)}\nconsumption conflict record was"
                    f" accepted: {variant!r}"
                )
            self.expect_unchanged(label, snapshot)

    def reject_used_batch(self, label, records):
        """A batch that is statelessly valid but conflicts on consumption."""
        for record in records:
            self.case.assertIsInstance(
                stateless_measurement(record, key=self.key),
                Measurement,
                self._why(label),
            )
        snapshot = self._snapshot()
        try:
            self.auditor.audit_batch(records)
        except ValueError:
            pass
        else:
            self.case.fail(
                f"{self._why(label)}\nconflicting batch was accepted: {records!r}"
            )
        self.expect_unchanged(label, snapshot)

    def reject_invalid_single(self, label, record):
        """A tampered record fails the stateless audit and is not consumed."""
        with self.case.assertRaises(ValueError, msg=self._why(label)):
            stateless_measurement(record, key=self.key)
        snapshot = self._snapshot()
        with self.case.assertRaises(ValueError, msg=self._why(label)):
            self.auditor.audit(record)
        self.expect_unchanged(label, snapshot)

    def reject_invalid_batch(self, label, records, invalid_index):
        """A batch carrying one tampered record rejects wholesale."""
        with self.case.assertRaises(ValueError, msg=self._why(label)):
            stateless_measurement(records[invalid_index], key=self.key)
        for index, record in enumerate(records):
            if index != invalid_index:
                self.case.assertIsInstance(
                    stateless_measurement(record, key=self.key),
                    Measurement,
                    self._why(label),
                )
        snapshot = self._snapshot()
        with self.case.assertRaises(ValueError, msg=self._why(label)):
            self.auditor.audit_batch(records)
        self.expect_unchanged(label, snapshot)

    # -- recovery -------------------------------------------------------

    def restart(self, label, form):
        checkpoint = self.auditor.checkpoint
        self.case.assertIsNotNone(checkpoint, self._why(label))
        exported = checkpoint if form == "object" else checkpoint.to_bytes()
        self.auditor = EvidenceReplayAuditor(self.key, exported)
        self.history.append(
            f"restart on a new instance from checkpoint {form}"
            f" (sequence {len(self.entries)})"
        )
        self.expect_checkpoint(label)


class EvidenceReplayContinuityScriptTest(unittest.TestCase):
    """One long interleaved script with several restarts.

    The anti-replay invariant must hold throughout: the checkpoint only
    ever gains the identifiers of a fully successful operation, its
    sequence always equals the accumulated entry count, and every failed
    operation leaves its bytes unchanged.
    """

    def test_interleaved_consumption_with_repeated_recovery(self):
        plain = make_evidence_records(17)
        bound = make_bound_records(2)
        delay = make_delay_records(2)
        session = ScriptedSession(self)

        # --- fresh instance: empty batch exports nothing ---------------
        session.expect_none("fresh auditor before any consumption")
        session.accept_empty("empty tuple on a fresh ledger", ())
        session.expect_none("empty tuple must not create a checkpoint")

        # --- first mixes of objects and canonical bytes -----------------
        session.accept_single("single plain p0 as object", plain[0])
        session.reject_used_single("replay plain p0 as object", [plain[0]])
        session.accept_batch(
            "batch: plain p1 object, bound b0 bytes, delay d0 object",
            [plain[1], bound[0].to_bytes(), delay[0]],
        )
        session.accept_single("single plain p2 as bytes", plain[2].to_bytes())
        session.reject_used_single(
            "replay plain p1 as bytes", [plain[1].to_bytes()]
        )

        # --- restart 1: canonical bytes ----------------------------------
        session.restart("restart 1 from canonical bytes", "bytes")

        # Cross-kind conflicts on the oldest pair, in both directions,
        # one twin submitted as bytes; each twin is independently valid.
        session.reject_used_single(
            "bound twin of consumed plain p0", [bound_twin(plain[0])]
        )
        session.reject_used_single(
            "delay twin of consumed plain p0 as bytes",
            [delay_twin(plain[0]).to_bytes()],
        )
        session.accept_single("single bound b1 as object", bound[1])
        session.accept_batch(
            "batch: plain p3 object, delay d1 bytes",
            [plain[3], delay[1].to_bytes()],
        )
        session.reject_used_batch(
            "replay of the whole p3/d1 batch", [plain[3], delay[1]]
        )

        # --- restart 2: state object -------------------------------------
        session.restart("restart 2 from a state object", "object")

        # In-batch duplicate: nothing is consumed, p4 stays fresh.
        session.reject_used_batch(
            "in-batch duplicate p4, p4", [plain[4], plain[4]]
        )
        session.accept_single(
            "plain p4 still consumable after the duplicate batch", plain[4]
        )

        # Cross-kind collision inside one batch rejects the whole batch.
        session.reject_used_batch(
            "in-batch cross-kind pair p5 plus its bound twin",
            [plain[5], bound_twin(plain[5])],
        )
        session.accept_single(
            "plain p5 still consumable after the cross-kind batch", plain[5]
        )

        # A conflict with history smuggled next to a fresh legal record.
        # Consumed-first ordering: nothing before it could be left behind.
        session.reject_used_batch(
            "batch replaying consumed p0 while smuggling fresh p6",
            [plain[0], plain[6]],
        )
        # Fresh-first ordering: a non-atomic implementation would leave
        # the fresh prefix record consumed before the conflict raises.
        session.reject_used_batch(
            "batch with fresh p7 first then the consumed p0",
            [plain[7], plain[0]],
        )
        session.accept_single(
            "plain p6 still consumable after the conflict batches", plain[6]
        )

        # A signature-tampered record rides along after a legal prefix.
        forged8 = replace(plain[8], mac=b"\x00" * 32)
        session.reject_invalid_batch(
            "batch: legal p7 followed by signature-tampered p8",
            [plain[7], forged8],
            invalid_index=1,
        )
        session.accept_batch(
            "p7 and p8 both still consumable after the forged batch",
            [plain[7], plain[8]],
        )

        # The same guarantee for a single tampered submission.
        forged9 = replace(plain[9], mac=b"\x00" * 32)
        session.reject_invalid_single(
            "single signature-tampered p9", forged9
        )
        session.accept_single(
            "plain p9 still consumable after the forged attempt", plain[9]
        )

        # --- restart 3: canonical bytes ----------------------------------
        session.restart("restart 3 from canonical bytes", "bytes")

        # The pair is first consumed under kind 2 (bound); plain and
        # delay variants must then be rejected as cross-kind replays.
        session.accept_single(
            "bound twin of p10 first consumes the pair under kind 2",
            bound_twin(plain[10]),
        )
        session.reject_used_single(
            "p10 pair now owned by kind 2",
            [plain[10], delay_twin(plain[10])],
        )

        # First consumption under kind 3, submitted as bytes in a batch.
        session.accept_batch(
            "delay twin of p11 consumes the pair under kind 3 as bytes",
            [delay_twin(plain[11]).to_bytes()],
        )
        session.reject_used_single(
            "p11 pair now owned by kind 3",
            [bound_twin(plain[11]), plain[11]],
        )

        # Two twins of a fresh pair collide with each other in a batch.
        session.reject_used_batch(
            "batch of bound and delay twins sharing the p12 pair",
            [bound_twin(plain[12]), delay_twin(plain[12])],
        )
        session.accept_single(
            "plain p12 still consumable after the twin batch, as bytes",
            plain[12].to_bytes(),
        )

        # An empty batch in the middle of a long ledger changes nothing.
        session.accept_empty("empty list mid-ledger", [])

        # --- restart 4: state object -------------------------------------
        session.restart("restart 4 from a state object", "object")

        session.accept_batch(
            "final advance batch p13, p14, p15",
            [plain[13], plain[14], plain[15]],
        )
        session.reject_used_single("replay plain p14", [plain[14]])
        session.reject_used_batch(
            "batch replaying consumed p14 while smuggling fresh p16",
            [plain[14], plain[16]],
        )
        session.reject_used_batch(
            "batch with fresh p16 first then the consumed p14",
            [plain[16], plain[14]],
        )
        session.accept_single(
            "plain p16 still consumable after the replay batches", plain[16]
        )

        # --- final invariant check ---------------------------------------
        checkpoint = session.auditor.checkpoint
        session.expect_checkpoint("final checkpoint")
        # Plain p0..p9 and p12..p16 (15 kind-1 identifiers), the two
        # bound and two delay records, and pairs p10/p11 first taken
        # under kind 2 and kind 3: 21 entries in all.
        expected_entries = set()
        expected_entries.update(
            ledger_entry(record) for record in plain[0:10]
        )
        expected_entries.update(
            ledger_entry(record) for record in plain[12:17]
        )
        expected_entries.add(ledger_entry(bound[0]))
        expected_entries.add(ledger_entry(bound[1]))
        expected_entries.add(ledger_entry(delay[0]))
        expected_entries.add(ledger_entry(delay[1]))
        expected_entries.add(ledger_entry(bound_twin(plain[10])))
        expected_entries.add(ledger_entry(delay_twin(plain[11])))
        self.assertEqual(checkpoint.sequence, 21)
        self.assertEqual(len(session.entries), 21)
        self.assertEqual(set(checkpoint.entries), expected_entries)
        self.assertEqual(session.entries, expected_entries)
        # Restarting yet another instance preserves the whole history:
        # consumed evidence stays consumed under every kind.
        restored = EvidenceReplayAuditor(KEY, checkpoint.to_bytes())
        self.assertEqual(restored.checkpoint, checkpoint)
        with self.assertRaises(ValueError):
            restored.audit(plain[0])
        with self.assertRaises(ValueError):
            restored.audit(plain[0].to_bytes())
        with self.assertRaises(ValueError):
            restored.audit(bound_twin(plain[0]))
        with self.assertRaises(ValueError):
            restored.audit(delay_twin(plain[0]))


def play_followup_tail(auditor, plain, bound, delay):
    """Run a fixed mixed operation tail on ``auditor``.

    Returns ``("ok", value)`` for each success and ``("rejected",)`` for
    each ValueError, in execution order. Fully deterministic — the same
    tail on two auditors restored from the same checkpoint must match.
    """
    log = []

    def consume(record):
        try:
            value = auditor.audit(record)
        except ValueError:
            log.append(("rejected",))
        else:
            log.append(("ok", value))

    def consume_batch(records):
        try:
            value = auditor.audit_batch(records)
        except ValueError:
            log.append(("rejected",))
        else:
            log.append(("ok", value))

    consume(plain[2])
    consume(bound[1].to_bytes())
    consume(plain[0])
    consume(bound_twin(plain[0]))
    consume_batch([delay[1], plain[3]])
    consume_batch([plain[1], plain[4]])
    consume_batch([plain[4], plain[4]])
    consume_batch(())
    consume(plain[4])
    consume_batch([plain[5].to_bytes()])
    return log


class EvidenceReplayRecoveryEquivalenceTest(unittest.TestCase):
    def setUp(self):
        self.plain = make_evidence_records(6)
        self.bound = make_bound_records(2)
        self.delay = make_delay_records(2)
        seed = EvidenceReplayAuditor(KEY)
        seed.audit_batch(
            [self.plain[0], self.bound[0], self.delay[0], self.plain[1]]
        )
        self.checkpoint = seed.checkpoint
        self.checkpoint_bytes = self.checkpoint.to_bytes()

    def test_object_and_bytes_restore_behave_identically(self):
        from_object = EvidenceReplayAuditor(KEY, self.checkpoint)
        from_bytes = EvidenceReplayAuditor(KEY, self.checkpoint_bytes)
        self.assertEqual(from_object.checkpoint, self.checkpoint)
        self.assertEqual(from_bytes.checkpoint, self.checkpoint)

        # Conflict samples are independently valid before the tail runs.
        self.assertIsInstance(
            audit_bound(bound_twin(self.plain[0]), KEY), Measurement
        )
        self.assertIsInstance(audit(self.plain[1], KEY), Measurement)

        log_object = play_followup_tail(
            from_object, self.plain, self.bound, self.delay
        )
        log_bytes = play_followup_tail(
            from_bytes, self.plain, self.bound, self.delay
        )
        self.assertEqual(log_object, log_bytes)
        self.assertEqual(from_object.checkpoint, from_bytes.checkpoint)
        self.assertEqual(
            from_object.checkpoint.to_bytes(),
            from_bytes.checkpoint.to_bytes(),
        )
        # Seed history: 4 entries; the tail successfully adds p2, b1,
        # d1, p3, p4 and a bytes-only p5 -> sequence 10.
        self.assertEqual(from_object.checkpoint.sequence, 10)
        self.assertEqual(
            from_object.checkpoint.entries,
            tuple(sorted(
                ledger_entry(record)
                for record in (
                    self.plain[0], self.bound[0], self.delay[0], self.plain[1],
                    self.plain[2], self.bound[1], self.delay[1], self.plain[3],
                    self.plain[4], self.plain[5],
                )
            )),
        )

    def test_exported_checkpoint_represents_only_its_own_history(self):
        # Long ledgers built after the export do not reach an instance
        # restored from the older checkpoint; nothing is shared.
        moved_on = EvidenceReplayAuditor(KEY, self.checkpoint_bytes)
        play_followup_tail(moved_on, self.plain, self.bound, self.delay)
        self.assertEqual(moved_on.checkpoint.sequence, 10)

        old = EvidenceReplayAuditor(KEY, self.checkpoint_bytes)
        self.assertEqual(old.checkpoint, self.checkpoint)
        # Everything covered by the exported history stays rejected.
        for consumed in (
            self.plain[0],
            self.plain[0].to_bytes(),
            self.bound[0],
            self.delay[0],
            self.plain[1],
            bound_twin(self.plain[0]),
        ):
            with self.assertRaises(ValueError):
                old.audit(consumed)
        # p2 was consumed only after the export elsewhere, so this
        # instance, presented with just the old checkpoint, accepts it.
        self.assertEqual(old.audit(self.plain[2]), audit(self.plain[2], KEY))
        self.assertEqual(old.checkpoint.sequence, 5)
        # The restored instance does not silently catch up with the
        # longer ledger, and the exported bytes stay immutable.
        self.assertNotEqual(old.checkpoint, moved_on.checkpoint)
        self.assertEqual(self.checkpoint.to_bytes(), self.checkpoint_bytes)
        self.assertEqual(
            EvidenceReplayAuditor(KEY, self.checkpoint).checkpoint,
            self.checkpoint,
        )


class EvidenceReplayCheckpointIntegrityTest(unittest.TestCase):
    def test_tampered_and_wrong_key_checkpoints_rejected_but_instance_lives(self):
        plain = make_evidence_records(3)
        auditor = EvidenceReplayAuditor(KEY)
        auditor.audit(plain[0])
        auditor.audit(plain[1])
        good = auditor.checkpoint.to_bytes()

        # Flip one nonce nibble: the structure still parses and the
        # entry contract still holds, but the MAC no longer authenticates.
        marker = b'"nonce":"'
        position = good.index(marker) + len(marker)
        nibble = good[position]
        flipped_nonce = (
            good[:position]
            + bytes([_HEX[(_HEX.index(nibble) + 1) % len(_HEX)]])
            + good[position + 1:]
        )
        EvidenceReplayState.from_bytes(flipped_nonce)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, flipped_nonce)

        # Flip one MAC nibble instead.
        marker = b'"mac":"'
        position = good.index(marker) + len(marker)
        nibble = good[position]
        flipped_mac = (
            good[:position]
            + bytes([_HEX[(_HEX.index(nibble) + 1) % len(_HEX)]])
            + good[position + 1:]
        )
        EvidenceReplayState.from_bytes(flipped_mac)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, flipped_mac)

        # Restore under the wrong key, as object and as canonical bytes.
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(OTHER_KEY, auditor.checkpoint)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(OTHER_KEY, good)

        # A checkpoint MAC'd by the holder of a different key is a forgery.
        forged = make_state([ENTRY_A], key=OTHER_KEY)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, forged)
        with self.assertRaises(ValueError):
            EvidenceReplayAuditor(KEY, forged.to_bytes())

        # None of the failed restores touched the running instance.
        self.assertEqual(auditor.checkpoint.to_bytes(), good)
        self.assertEqual(auditor.audit(plain[2]), audit(plain[2], KEY))
        self.assertEqual(auditor.checkpoint.sequence, 3)

    def test_failed_operations_on_fresh_instance_keep_checkpoint_none(self):
        plain = make_evidence_records(2)
        auditor = EvidenceReplayAuditor(KEY)
        self.assertEqual(auditor.audit_batch(()), ())
        self.assertIsNone(auditor.checkpoint)

        forged = replace(plain[0], mac=b"\x00" * 32)
        with self.assertRaises(ValueError):
            auditor.audit(forged)
        with self.assertRaises(ValueError):
            auditor.audit(42)
        with self.assertRaises(ValueError):
            auditor.audit_batch([plain[0], plain[0]])
        with self.assertRaises(ValueError):
            auditor.audit_batch([plain[0], bound_twin(plain[0])])
        self.assertIsNone(auditor.checkpoint)
        # The legal records involved in the failed batches are untouched.
        auditor.audit(plain[0])
        self.assertEqual(auditor.checkpoint.sequence, 1)


if __name__ == "__main__":
    unittest.main()
