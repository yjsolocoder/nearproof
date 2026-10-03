"""State-regression scenarios for the evidence-replay consumption ledger.

The existing tests cover single, batch and concurrent consumption. This
module exercises the anti-replay invariant over a *long* interleaved
lifecycle: a fixed, reproducible script of operations spanning all three
ranging evidence kinds (Evidence, BoundEvidence, DelayBoundEvidence),
alternating record objects with their canonical ``to_bytes()`` encodings,
exporting checkpoints several times and resuming consumption on brand new
auditor instances in the middle of the sequence.

Every expectation is derived independently from the script's own record
of prior successful consumption -- the stateless public audits for the
Measurement values and a shadow multiset of consumed identifiers for the
checkpoint shape. A second stateful auditor is never used as the oracle
for the main sequence; restored instances are compared with each other
only in the dedicated restoration-equivalence scenario, where that
comparison is the property under test and both sides are additionally
checked against the independent oracle.

No real clock and no thread scheduling are involved: records are minted
with the same stepped-clock fixtures the rest of the suite uses and the
operation order is fixed in advance. When an assertion fails the message
names the first operation that deviated and lists the consumption history
that preceded it, so every failure can be reproduced directly.
"""

import unittest
from collections import namedtuple
from dataclasses import replace

from nearproof import (
    BoundEvidence,
    DelayBoundEvidence,
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


def stateless_measurement(record, *, key=KEY):
    """The result the matching stateless public audit gives for a record."""
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


Card = namedtuple("Card", ["name", "record", "entry", "measurement"])


def card(name, record):
    """Bundle a record with the independently derived expectations.

    The Measurement comes straight from the stateless public audit and
    the canonical bytes are asserted to round-trip to the same record,
    so submitting the bytes form has the same independently computed
    expectation as submitting the object.
    """
    packed = Card(name, record, ledger_entry(record), stateless_measurement(record))
    assert isinstance(packed.measurement, Measurement)
    assert type(record).from_bytes(record.to_bytes()) == record
    return packed


def twin_card(name, record, *, bound):
    record = bound_twin(record) if bound else delay_twin(record)
    return card(name, record)


def build_pool():
    """Five plain, four context-bound and four delay-bound rounds.

    The three batches come from independent verifiers, so their round
    indices overlap while their nonces differ; cross-kind collisions are
    only ever the deliberately forged twins that share a pair.
    """
    evidence = [card(f"E{i}", record)
                for i, record in enumerate(make_evidence_records(5))]
    bounds = [card(f"B{i}", record)
              for i, record in enumerate(make_bound_records(4))]
    delays = [card(f"D{i}", record)
              for i, record in enumerate(make_delay_records(4))]
    return {c.name: c for c in evidence + bounds + delays}


class ReplayScript:
    """Run a labelled, fixed operation sequence against one auditor.

    The shadow ledger (``self.consumed`` maps an entry to the card name
    that consumed it; ``self.history`` lists card names in consumption
    order) is the only source of expectations. Exports are snapshotted as
    both the frozen state object and its canonical bytes. A failed
    assertion names the step and the consumption history before it.
    """

    def __init__(self, test, auditor=None, consumed=()):
        self.test = test
        self.auditor = (
            EvidenceReplayAuditor(KEY) if auditor is None else auditor
        )
        self.consumed = dict(consumed)
        self.history = list(self.consumed.values())
        self.log = []
        self.exports = {}

    # -- failure reporting -------------------------------------------------

    def _context(self, label):
        eaten = ", ".join(self.history) if self.history else "<none>"
        return f"step {label!r}; consumption history before this step: [{eaten}]"

    def _fail(self, label, detail):
        self.test.fail(f"{self._context(label)}: {detail}")

    def _assert(self, condition, label, detail):
        if not condition:
            self._fail(label, detail)

    # -- presentation ------------------------------------------------------

    @staticmethod
    def _present(card_or_record, as_bytes):
        record = (
            card_or_record.record
            if isinstance(card_or_record, Card)
            else card_or_record
        )
        return record.to_bytes() if as_bytes else record

    # -- checkpoint oracle -------------------------------------------------

    def _snapshot(self):
        state = self.auditor.checkpoint
        return state, (None if state is None else state.to_bytes())

    def _check_checkpoint(self, label, new_cards):
        """The checkpoint must add exactly this step's identifiers, and
        nothing else; sequence must equal the cumulative entry count."""
        state = self.auditor.checkpoint
        if not self.consumed and not new_cards:
            self._assert(state is None, label,
                         "checkpoint must stay None with no successes")
            return
        self._assert(state is not None, label,
                     "checkpoint must exist after a successful consumption")
        expected_entries = tuple(sorted(self.consumed))
        self._assert(
            state.entries == expected_entries,
            label,
            f"checkpoint entries {state.entries!r} != oracle {expected_entries!r}",
        )
        self._assert(
            state.sequence == len(expected_entries),
            label,
            f"sequence {state.sequence} != cumulative entry count"
            f" {len(expected_entries)}",
        )
        self._assert(
            state.mac == state_mac(KEY, state),
            label,
            "checkpoint MAC does not authenticate under the auditor key",
        )
        self._assert(
            EvidenceReplayState.from_bytes(state.to_bytes()) == state,
            label,
            "checkpoint bytes do not round-trip to the exported state",
        )

    def _check_growth(self, label, before, new_cards):
        state = self.auditor.checkpoint
        before_entries = set(before)
        after_entries = set(state.entries) if state is not None else set()
        new_entries = [c.entry for c in new_cards]
        self._assert(
            before_entries.issubset(after_entries),
            label,
            "a successful step removed identifiers from the checkpoint",
        )
        self._assert(
            after_entries - before_entries == set(new_entries),
            label,
            "checkpoint did not add exactly the identifiers consumed by"
            " this step",
        )

    def _book(self, label, cards, value):
        for c in cards:
            self._assert(
                c.entry not in self.consumed,
                label,
                f"oracle card {c.name} was already marked consumed",
            )
            self.consumed[c.entry] = c.name
            self.history.append(c.name)
        self.log.append((label, "ok", value))

    # -- operations --------------------------------------------------------

    def single(self, label, c, as_bytes):
        record = self._present(c, as_bytes)
        before_state, _before_bytes = self._snapshot()
        try:
            value = self.auditor.audit(record)
        except ValueError as error:
            self._fail(label, f"expected Measurement, got ValueError {error!r}")
        self._assert(
            value == c.measurement,
            label,
            f"returned Measurement {value!r} != stateless audit"
            f" {c.measurement!r}",
        )
        before_entries = (
            () if before_state is None else before_state.entries
        )
        self._check_growth(label, before_entries, [c])
        self._book(label, [c], value)
        self._check_checkpoint(label, [c])
        return value

    def single_fail(self, label, c, as_bytes):
        self._fail_record(label, self._present(c, as_bytes), batch=False)

    def single_fail_record(self, label, record, as_bytes):
        self._fail_record(
            label, self._present(record, as_bytes), batch=False
        )

    def batch(self, label, presented):
        """``presented`` is a list of (Card, as_bytes) pairs."""
        records = [self._present(c, as_bytes) for c, as_bytes in presented]
        cards = [c for c, _ in presented]
        before_state, _ = self._snapshot()
        try:
            value = self.auditor.audit_batch(records)
        except ValueError as error:
            self._fail(label, f"expected success tuple, got ValueError {error!r}")
        expected = tuple(c.measurement for c in cards)
        self._assert(
            isinstance(value, tuple),
            label,
            f"successful batch must return a tuple, got {type(value).__name__}",
        )
        self._assert(
            value == expected,
            label,
            f"batch measurements {value!r} != stateless audits in input"
            f" order {expected!r}",
        )
        before_entries = (
            () if before_state is None else before_state.entries
        )
        self._check_growth(label, before_entries, cards)
        self._book(label, cards, value)
        self._check_checkpoint(label, cards)
        return value

    def batch_fail(self, label, presented):
        records = [self._present(c, as_bytes) for c, as_bytes in presented]
        self._fail_record(label, records, batch=True)

    def batch_fail_raw(self, label, records):
        """A failing batch mixing cards and ad-hoc forged record objects."""
        self._fail_record(label, records, batch=True)

    def _fail_record(self, label, argument, *, batch):
        before_state, before_bytes = self._snapshot()
        try:
            if batch:
                self.auditor.audit_batch(argument)
            else:
                self.auditor.audit(argument)
        except ValueError:
            pass
        except BaseException as error:  # noqa: BLE001 - report the real type
            self._fail(
                label,
                f"expected ValueError, got {type(error).__name__}: {error!r}",
            )
        else:
            self._fail(label, "expected ValueError but the call succeeded")
        after_state, after_bytes = self._snapshot()
        # The failed call must leave exactly the same checkpoint object
        # and therefore exactly the same checkpoint bytes behind.
        self._assert(
            self.auditor.checkpoint is before_state,
            label,
            "a failed call replaced the checkpoint object",
        )
        self._assert(
            after_bytes == before_bytes,
            label,
            "checkpoint bytes changed across a failed call",
        )
        self.log.append((label, "value-error", None))

    def empty(self, label, use_list=True):
        before_state, before_bytes = self._snapshot()
        value = self.auditor.audit_batch([] if use_list else ())
        self._assert(
            value == (),
            label,
            f"empty batch must return (), got {value!r}",
        )
        self._assert(
            self.auditor.checkpoint is before_state,
            label,
            "empty batch replaced the checkpoint object",
        )
        _state, after_bytes = self._snapshot()
        self._assert(
            after_bytes == before_bytes,
            label,
            "empty batch changed checkpoint bytes",
        )
        self.log.append((label, "empty", ()))
        return value

    # -- checkpoint export / restore --------------------------------------

    def export(self, label):
        state, data = self._snapshot()
        self._assert(state is not None, label,
                     "cannot export a checkpoint before any consumption")
        self._assert(
            EvidenceReplayState.from_bytes(data) == state,
            label,
            "exported checkpoint bytes do not round-trip",
        )
        self.exports[label] = (state, data)
        return state, data

    def restore(self, label, export_label, as_bytes):
        """Resume on a new auditor instance from an earlier export."""
        state, data = self.exports[export_label]
        checkpoint = data if as_bytes else state
        try:
            new_auditor = EvidenceReplayAuditor(KEY, checkpoint)
        except ValueError as error:
            self._fail(label, f"valid checkpoint rejected: {error!r}")
        self._assert(
            new_auditor.checkpoint == state,
            label,
            "restored checkpoint differs from the exported one",
        )
        self._assert(
            new_auditor.checkpoint.entries == tuple(sorted(self.consumed)),
            label,
            "restored checkpoint does not match the shadow consumption"
            " history",
        )
        self.auditor = new_auditor
        self.log.append((label, "restore", export_label))


def continuation_tail(script, pool, label):
    """The fixed suffix replayed after an object/bytes restoration.

    Consumed records stay rejected (as object, as bytes and across
    kinds), an empty batch is a no-op, a batch that conflicts with
    history is rejected wholesale, and then its one genuinely new
    record advances the ledger normally.
    """
    e0, e1, b0, b3 = pool["E0"], pool["E1"], pool["B0"], pool["B3"]
    # The cross-kind conflict sample must pass its own stateless audit;
    # its later rejection must come from the consumption conflict.
    twin = twin_card(f"{label}:twin(E1)", e1.record, bound=True)
    script.test.assertIsInstance(
        audit_bound(twin.record, KEY), Measurement,
        f"{label}: bound twin must pass the stateless audit first",
    )

    script.single_fail(f"{label}:replay-E0-object", e0, False)
    script.single_fail(f"{label}:replay-B0-bytes", b0, True)
    script.single_fail(f"{label}:cross-kind-twin-bytes", twin, True)
    script.empty(f"{label}:empty-list")
    script.batch_fail(
        f"{label}:batch-conflicts-with-history",
        [(b3, True), (twin, False)],
    )
    # Nothing in the rejected batch was consumed: the new bound record
    # is now submitted on its own and succeeds.
    script.single(f"{label}:B3-bytes-after-rejected-batch", b3, True)


class EvidenceReplayInterleavedLifecycleTest(unittest.TestCase):
    """One long script: consume, fail, export, restore, repeat."""

    def test_interleaved_consumption_and_restorations(self):
        pool = build_pool()
        script = ReplayScript(self)

        # --- first segment: objects and bytes, three kinds ---------------
        script.single("s0-audit-E0-object", pool["E0"], False)
        script.single("s1-audit-B0-bytes", pool["B0"], True)
        script.batch("s2-batch-D0-object-E1-bytes", [
            (pool["D0"], False),
            (pool["E1"], True),
        ])

        # Same round_index+nonce is rejected even under a different kind.
        # Every twin first passes its own stateless audit, so the
        # rejection below is purely the consumption conflict.
        self.assertIsInstance(audit(pool["E0"].record, KEY), Measurement)
        bound_e0 = twin_card("s4:bound-twin(E0)", pool["E0"].record, bound=True)
        delay_e0 = twin_card("s5:delay-twin(E0)", pool["E0"].record, bound=False)
        self.assertIsInstance(audit_bound(bound_e0.record, KEY), Measurement)
        self.assertIsInstance(audit_delay_bound(delay_e0.record, KEY), Measurement)
        script.single_fail("s3-replay-E0-bytes", pool["E0"], True)
        script.single_fail_record("s4-cross-kind-bound-object", bound_e0, False)
        script.single_fail_record("s5-cross-kind-delay-bytes", delay_e0, True)

        # An in-batch duplicate (same identifier, object vs bytes) rejects
        # the whole batch; neither legal record is consumed.
        script.batch_fail("s6-batch-duplicate-E2-with-B1", [
            (pool["E2"], False),
            (pool["B1"], True),
            (pool["E2"], True),
        ])

        # --- first export and object-form restoration --------------------
        script.export("CP_A")
        self.assertEqual(
            script.auditor.checkpoint.sequence, 4,
            "CP_A must cover E0, B0, D0, E1",
        )
        script.restore("s7-restore-from-CP_A-object", "CP_A", as_bytes=False)

        # The legal records carried by the rejected s6 batch are still
        # unconsumed and succeed now, on the restored instance.
        script.batch("s8-batch-B1-object-D1-bytes", [
            (pool["B1"], False),
            (pool["D1"], True),
        ])
        script.single("s9-audit-E2-bytes", pool["E2"], True)
        script.empty("s10-empty-tuple", use_list=False)

        # A batch smuggling a record whose signature was tampered: the
        # whole batch fails, including its two otherwise-legal records.
        forged_e4 = replace(pool["E4"].record, mac=b"\x00" * 32)
        script.batch_fail_raw("s11-batch-with-forged-E4", [
            pool["E3"].record,
            forged_e4.to_bytes(),
            pool["D2"].record,
        ])

        # --- second export and bytes-form restoration --------------------
        cp_b_state, cp_b_bytes = script.export("CP_B")
        self.assertEqual(cp_b_state.sequence, 7,
                         "CP_B must cover seven consumed identifiers")
        script.restore("s12-restore-from-CP_B-bytes", "CP_B", as_bytes=True)

        # The two legal records smuggled by the forged batch survive it.
        script.single("s13-audit-E3-object", pool["E3"], False)
        script.single("s14-audit-D2-bytes", pool["D2"], True)

        # Restoring from a bad checkpoint always raises ValueError, via
        # object or bytes, and never damages the running instance: the
        # successful batch right after proves the original keeps working.
        forged_state = replace(cp_b_state, mac=b"\xff" * 32)
        forged_state_bytes = forged_state.to_bytes()
        tampered_bytes = self._flip_last_mac_nibble(cp_b_bytes)
        for description, factory in (
            ("restore with wrong key, object checkpoint",
             lambda: EvidenceReplayAuditor(OTHER_KEY, cp_b_state)),
            ("restore with wrong key, canonical bytes",
             lambda: EvidenceReplayAuditor(OTHER_KEY, cp_b_bytes)),
            ("restore with forged checkpoint MAC, object",
             lambda: EvidenceReplayAuditor(KEY, forged_state)),
            ("restore with forged checkpoint MAC, bytes",
             lambda: EvidenceReplayAuditor(KEY, forged_state_bytes)),
            ("restore with one checkpoint MAC byte flipped",
             lambda: EvidenceReplayAuditor(KEY, tampered_bytes)),
        ):
            with self.assertRaises(ValueError, msg=description):
                factory()
        script.batch("s15-batch-E4-object-B2-bytes-D3-object", [
            (pool["E4"], False),
            (pool["B2"], True),
            (pool["D3"], False),
        ])

        # --- third export: object and bytes restorations are equivalent --
        cp_c_state, cp_c_bytes = script.export("CP_C")
        self.assertEqual(cp_c_state.sequence, 12,
                         "CP_C must cover twelve consumed identifiers")

        from_object = ReplayScript(
            self,
            EvidenceReplayAuditor(KEY, cp_c_state),
            consumed=script.consumed.items(),
        )
        from_bytes = ReplayScript(
            self,
            EvidenceReplayAuditor(KEY, cp_c_bytes),
            consumed=script.consumed.items(),
        )
        continuation_tail(from_object, pool, "obj")
        continuation_tail(from_bytes, pool, "bytes")

        # Same inputs from both restoration forms: identical outcomes and
        # identical final checkpoints. The labels carry an obj/bytes tag
        # purely for failure messages, so compare on operation kind and
        # outcome with the tag stripped.
        def normalized_log(script):
            return [
                (label.split(":", 1)[1], status, value)
                for label, status, value in script.log
            ]

        self.assertEqual(
            normalized_log(from_object),
            normalized_log(from_bytes),
            "object and canonical-bytes restorations diverged on the same"
            " subsequent operations",
        )
        self.assertEqual(
            from_object.auditor.checkpoint,
            from_bytes.auditor.checkpoint,
        )
        self.assertEqual(
            from_object.auditor.checkpoint.to_bytes(),
            from_bytes.auditor.checkpoint.to_bytes(),
        )
        final_state = from_object.auditor.checkpoint
        self.assertEqual(final_state.sequence, 13)
        self.assertEqual(
            final_state.entries,
            tuple(sorted(c.entry for c in pool.values())),
        )

        # Old exports do not change as later instances keep consuming:
        # their bytes restore to exactly what was exported.
        cp_a_state, cp_a_bytes = script.exports["CP_A"]
        self.assertEqual(EvidenceReplayState.from_bytes(cp_a_bytes), cp_a_state)
        self.assertEqual(
            EvidenceReplayAuditor(KEY, cp_a_bytes).checkpoint, cp_a_state
        )
        self.assertEqual(
            EvidenceReplayState.from_bytes(cp_b_bytes), cp_b_state
        )
        self.assertEqual(
            EvidenceReplayState.from_bytes(cp_c_bytes), cp_c_state
        )

        # --- the linear instance finishes too, via an object restore -----
        script.restore("s16-restore-from-CP_C-object", "CP_C", as_bytes=False)
        script.single("s17-audit-B3-object", pool["B3"], False)
        self.assertEqual(
            script.auditor.checkpoint, final_state,
            "the linear chain and the restoration tails must converge on"
            " the same final checkpoint",
        )
        self.assertEqual(script.auditor.checkpoint.sequence, 13)

    @staticmethod
    def _flip_last_mac_nibble(data):
        """Flip the final MAC hex nibble by one.

        Checkpoint bytes end with ``...mac":"<64 hex>"}`` so the last MAC
        nibble sits three bytes from the end. Flipping it keeps the
        encoding canonical JSON with a valid-length MAC: the bytes parse
        but MAC verification during restoration must fail.
        """
        cycle = {
            ord("0"): ord("1"), ord("1"): ord("2"), ord("2"): ord("3"),
            ord("3"): ord("4"), ord("4"): ord("5"), ord("5"): ord("6"),
            ord("6"): ord("7"), ord("7"): ord("8"), ord("8"): ord("9"),
            ord("9"): ord("0"),
            ord("a"): ord("b"), ord("b"): ord("c"), ord("c"): ord("d"),
            ord("d"): ord("e"), ord("e"): ord("f"), ord("f"): ord("e"),
        }
        return data[:-3] + bytes([cycle[data[-3]]]) + data[-2:]


class FreshInstanceExportTest(unittest.TestCase):
    def test_nothing_consumed_exports_none_through_failures_and_empties(self):
        auditor = EvidenceReplayAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        # Rejected records and empty batches must not mint a checkpoint.
        records = make_evidence_records(2)
        with self.assertRaises(ValueError):
            auditor.audit(replace(records[0], mac=b"\x00" * 32))
        with self.assertRaises(ValueError):
            auditor.audit(b"{}")
        with self.assertRaises(ValueError):
            auditor.audit(b"not json")
        self.assertEqual(auditor.audit_batch([]), ())
        self.assertEqual(auditor.audit_batch(()), ())
        self.assertIsNone(auditor.checkpoint)
        # The first real success creates the checkpoint and the empty
        # batch afterwards keeps that exact object in place.
        auditor.audit(records[0])
        first = auditor.checkpoint
        self.assertEqual(first.sequence, 1)
        self.assertEqual(auditor.audit_batch(()), ())
        self.assertIs(auditor.checkpoint, first)


if __name__ == "__main__":
    unittest.main()
