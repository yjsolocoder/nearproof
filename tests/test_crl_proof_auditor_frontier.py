"""Regression coverage for the shared CrlProofAuditor/WeightedCrlProofAuditor
checkpoint lifecycle after the focused refactor onto one frontier rule.

The two auditors keep their own proof formats, signatures, tallies and
consensus types (Consensus vs WeightedConsensus); what is shared is the
MAC-verified CrlState restore path and the monotone compare-and-update.
These tests pin that contract from the public interfaces, in particular:

* checkpoints exported by either auditor restore into the other kind,
  including an alternating restart chain that keeps receiving proofs;
* an identical CRL snapshot at the same sequence is a replay even when the
  two proofs carry different consensus results;
* a legal but accepted=False result is returned and advances;
* every failing audit (corrupt bytes, bad MAC, revoked participant or
  consensus mismatch) is a ValueError that never commits, even at a higher
  sequence;
* concurrent audits correspond to some serial ordering and never roll the
  checkpoint back; independent instances keep independent state;
* the proof-type boundary holds in both directions;
* restore rejects the wrong root, corrupted/non-canonical encodings and
  illegal checkpoints; non-bytes root is TypeError, empty root ValueError.
"""

import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    Consensus,
    ConsensusPolicy,
    CrlProof,
    CrlProofAuditor,
    CrlState,
    RangeDecision,
    WeightedCrlProof,
    WeightedCrlProofAuditor,
    WeightedConsensus,
    _crl_proof_mac,
    _crl_state_mac,
    _crl_state_payload,
    _weighted_crl_proof_mac,
    attest_observation_for_point,
    cert,
    make_crl,
    prove_crl,
    prove_weighted_crl,
    revoke_trust,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEYS = {
    "a": b"\xaa" * 32,
    "b": b"\xbb" * 32,
    "c": b"\xcc" * 32,
    "d": b"\xdd" * 32,
    "e": b"\xee" * 32,
}
POSITIONS = {
    "a": (3.0, 0.0),
    "b": (0.0, 4.0),
    "c": (0.0, 0.0),
    "d": (50.0, 50.0),
    "e": (60.0, 60.0),
}
WEIGHTS = {"a": 1, "b": 2, "c": 4, "d": 8}
WEIGHTED_POSITIONS = {
    "a": (3.0, 0.0),
    "b": (0.0, 4.0),
    "c": (0.0, 0.0),
    "d": (50.0, 50.0),
}
# Only a and b cover the query, so a 3-quorum plain tally comes out not
# accepted; used for the accepted=False / differing-consensus proofs.
SPREAD_POSITIONS = {
    "a": (3.0, 0.0),
    "b": (0.0, 4.0),
    "c": (50.0, 50.0),
    "d": (60.0, 60.0),
    "e": (70.0, 70.0),
}
POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True):
    return RangeDecision(
        sample_count=1, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, positions=POSITIONS):
    return cert(ident, positions[ident][0], positions[ident][1],
                KEYS[ident], ROOT)


def record(ident, *, positions=POSITIONS):
    x, y = positions[ident]
    return attest_observation_for_point(
        ident, x, y, decision(), POINT, CONTEXT, 0.0, KEYS[ident]
    )


def crl(sequence, *, issued_at=0.0, entries=()):
    return make_crl(list(entries), sequence, issued_at, ROOT)


CRL1 = crl(1)
CRL2 = crl(2, issued_at=5.0)
CRL3 = crl(3, issued_at=9.0)
# Same sequence as CRL1 but different content -> different digest.
CRL1_OTHER = crl(1, issued_at=9.0)


# --- plain proofs -----------------------------------------------------------

def plain(ids, a_crl, *, now=10.0, positions=POSITIONS):
    return prove_crl(
        [record(i, positions=positions) for i in ids], POINT, CONTEXT,
        [trust(i, positions=positions) for i in ids], ROOT, a_crl, now=now,
    )


P1_TRUE = plain(["a", "b", "c"], CRL1)
P1_FALSE = plain(["a", "b", "c", "d", "e"], CRL1, positions=SPREAD_POSITIONS)
P2_FALSE = plain(["a", "b", "c", "d", "e"], CRL2, positions=SPREAD_POSITIONS)
P3_TRUE = plain(["a", "b", "c"], CRL3)
P1_OTHER = plain(["a", "b", "c"], CRL1_OTHER)

PLAIN_TRUE = Consensus(total=3, support=3, rejected=(), accepted=True)
PLAIN_FALSE = Consensus(
    total=5, support=2, rejected=("c", "d", "e"), accepted=False
)


def plain_resigned(ids, a_crl, *, mutate):
    """Rebuild a plain proof over ``a_crl`` from a clean same-sequence body
    and re-MAC it under ROOT, so parsing/MAC pass but the replay rejects."""
    clean = plain(ids, a_crl)
    body = json.loads(clean.body)
    mutate(body)
    raw = json.dumps(body, separators=(",", ":")).encode()
    return CrlProof(1, raw, _crl_proof_mac(ROOT, raw))


def plain_revoked(ids, revoked_trust, a_crl):
    revoked_crl = make_crl([revoke_trust(revoked_trust, ROOT)], a_crl.sequence,
                           0.0, ROOT)
    # Build over a valid same-sequence snapshot, then swap in the revoked CRL
    # and re-MAC: parsing and MAC pass, but the stateless audit rejects it.
    return plain_resigned(
        ids, crl(a_crl.sequence),
        mutate=lambda body: body.__setitem__(4, revoked_crl.to_bytes().hex()),
    )


# --- weighted proofs --------------------------------------------------------

def weighted(ids, a_crl, *, threshold=7, now=10.0):
    return prove_weighted_crl(
        [record(i, positions=WEIGHTED_POSITIONS) for i in ids],
        POINT, CONTEXT,
        [trust(i, positions=WEIGHTED_POSITIONS) for i in ids],
        ROOT, a_crl, ConsensusPolicy(
            {ident: WEIGHTS[ident] for ident in ids}, threshold
        ),
        now=now,
    )


W1_TRUE = weighted(["a", "b", "c", "d"], CRL1, threshold=7)
W1_FALSE = weighted(["a", "b", "c", "d"], CRL1, threshold=8)
W2_FALSE = weighted(["a", "b", "c", "d"], CRL2, threshold=8)
W3_TRUE = weighted(["a", "b", "c", "d"], CRL3, threshold=7)
W1_OTHER = weighted(["a", "b", "c", "d"], CRL1_OTHER, threshold=7)

WEIGHTED_TRUE = WeightedConsensus(
    total_weight=15, support_weight=7, rejected=("d",), accepted=True
)
WEIGHTED_FALSE = WeightedConsensus(
    total_weight=15, support_weight=7, rejected=("d",), accepted=False
)


def weighted_resigned(a_crl, *, mutate):
    clean = weighted(["a", "b", "c", "d"], a_crl)
    body = json.loads(clean.body)
    mutate(body)
    raw = json.dumps(body, separators=(",", ":")).encode()
    return WeightedCrlProof(
        1, raw, _weighted_crl_proof_mac(ROOT, raw)
    )


def weighted_revoked(revoked_trust, a_crl):
    revoked_crl = make_crl([revoke_trust(revoked_trust, ROOT)], a_crl.sequence,
                           0.0, ROOT)
    # Same swap trick on the weighted side: valid same-sequence body, revoked
    # CRL spliced in, outer proof re-MAC'd so only the replay rejects.
    return weighted_resigned(
        crl(a_crl.sequence),
        mutate=lambda body: body.__setitem__(4, revoked_crl.to_bytes().hex()),
    )


def expected_state(a_crl):
    placeholder = CrlState(
        1, a_crl.sequence, hashlib.sha256(a_crl.to_bytes()).digest(),
        b"\x00" * 32,
    )
    return dataclasses.replace(
        placeholder,
        mac=_crl_state_mac(ROOT, _crl_state_payload(placeholder)),
    )


class CrossAuditorRestoreTest(unittest.TestCase):
    def test_alternating_restart_chain_keeps_one_frontier(self):
        # Weighted advances to 1, plain resumes and advances to 2, weighted
        # resumes and advances to 3, handing both bytes and objects across.
        wa = WeightedCrlProofAuditor(ROOT)
        self.assertEqual(wa.audit(W1_TRUE), WEIGHTED_TRUE)
        saved1 = wa.checkpoint.to_bytes()

        pa = CrlProofAuditor(ROOT, checkpoint=saved1)
        self.assertEqual(pa.checkpoint, wa.checkpoint)
        # Plain resumes at the weighted frontier: an exact replay returns the
        # plain consensus while leaving the shared checkpoint bytes alone.
        self.assertEqual(pa.audit(plain(["a", "b", "c"], CRL1)), PLAIN_TRUE)
        self.assertEqual(pa.checkpoint.to_bytes(), saved1)
        # A genuinely lower sequence is refused across the type boundary.
        with self.assertRaises(ValueError):
            pa.audit(plain(["a", "b", "c"], crl(0)))
        pa.audit(plain(["a", "b", "c"], CRL2))
        self.assertEqual(pa.checkpoint, expected_state(CRL2))
        saved2 = pa.checkpoint  # hand over the frozen object itself

        wb = WeightedCrlProofAuditor(ROOT, checkpoint=saved2)
        self.assertEqual(wb.checkpoint, pa.checkpoint)
        # Weighted replay of its own seq-2 proof at the resumed frontier.
        self.assertEqual(
            wb.audit(weighted(["a", "b", "c", "d"], CRL2)), WEIGHTED_TRUE
        )
        with self.assertRaises(ValueError):
            wb.audit(W1_TRUE)  # rollback across restart
        self.assertEqual(wb.audit(W3_TRUE), WEIGHTED_TRUE)
        self.assertEqual(wb.checkpoint, expected_state(CRL3))

        # The whole chain survives a final bytes round trip into plain.
        pb = CrlProofAuditor(ROOT, checkpoint=wb.checkpoint.to_bytes())
        self.assertEqual(pb.checkpoint, wb.checkpoint)
        self.assertEqual(pb.checkpoint.to_bytes(), wb.checkpoint.to_bytes())

    def test_checkpoint_is_independent_of_which_auditor_minted_it(self):
        # Keyed only on sequence and CRL digest under the same root.
        pa = CrlProofAuditor(ROOT)
        pa.audit(plain(["a", "b", "c"], CRL2))
        wa = WeightedCrlProofAuditor(ROOT)
        wa.audit(weighted(["a", "b", "c", "d"], CRL2))
        self.assertEqual(pa.checkpoint, wa.checkpoint)
        self.assertEqual(pa.checkpoint.to_bytes(), wa.checkpoint.to_bytes())

    def test_empty_state_start_for_both(self):
        self.assertIsNone(CrlProofAuditor(ROOT).checkpoint)
        self.assertIsNone(WeightedCrlProofAuditor(ROOT).checkpoint)


class ProofTypeBoundaryTest(unittest.TestCase):
    def test_auditors_reject_each_others_proofs(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(P1_TRUE)
        wa = WeightedCrlProofAuditor(ROOT)
        wa.audit(W1_TRUE)
        for bad in (W1_TRUE, W1_TRUE.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                pa.audit(bad)
        for bad in (P1_TRUE, P1_TRUE.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                wa.audit(bad)
        # Rejected cross-type proofs committed nothing.
        self.assertEqual(pa.checkpoint, expected_state(CRL1))
        self.assertEqual(wa.checkpoint, expected_state(CRL1))


class AdvanceReplayConflictTest(unittest.TestCase):
    def _assert_replay_differs_but_bytes_unchanged(
        self, auditor, first, replay, first_result, replay_result
    ):
        self.assertEqual(auditor.audit(first), first_result)
        before = auditor.checkpoint.to_bytes()
        # Same sequence, same CRL digest, different consensus result: this is
        # a replay returning THIS proof's result, never a conflict, and the
        # checkpoint bytes are untouched.
        self.assertEqual(auditor.audit(replay), replay_result)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        # Bytes-encoded form behaves identically.
        self.assertEqual(auditor.audit(replay.to_bytes()), replay_result)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)

    def test_plain_replay_with_different_consensus_is_not_conflict(self):
        auditor = CrlProofAuditor(ROOT)
        self._assert_replay_differs_but_bytes_unchanged(
            auditor, P1_TRUE, P1_FALSE, PLAIN_TRUE, PLAIN_FALSE
        )

    def test_weighted_replay_with_different_consensus_is_not_conflict(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        self._assert_replay_differs_but_bytes_unchanged(
            auditor, W1_TRUE, W1_FALSE, WEIGHTED_TRUE, WEIGHTED_FALSE
        )

    def test_accepted_false_still_advances(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(P1_TRUE)
        self.assertEqual(pa.audit(P2_FALSE), PLAIN_FALSE)
        self.assertFalse(pa.audit(P2_FALSE).accepted)
        self.assertEqual(pa.checkpoint, expected_state(CRL2))

        wa = WeightedCrlProofAuditor(ROOT)
        wa.audit(W1_TRUE)
        self.assertEqual(wa.audit(W2_FALSE), WEIGHTED_FALSE)
        self.assertFalse(wa.audit(W2_FALSE).accepted)
        self.assertEqual(wa.checkpoint, expected_state(CRL2))

    def test_same_sequence_different_digest_conflicts_and_does_not_commit(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(P1_TRUE)
        with self.assertRaises(ValueError):
            pa.audit(P1_OTHER)
        self.assertEqual(pa.checkpoint, expected_state(CRL1))
        pa.audit(plain(["a", "b", "c"], CRL2))
        # Now the conflicting snapshot is also a rollback; still rejected.
        with self.assertRaises(ValueError):
            pa.audit(P1_OTHER)
        self.assertEqual(pa.checkpoint, expected_state(CRL2))

        wa = WeightedCrlProofAuditor(ROOT)
        wa.audit(W1_TRUE)
        with self.assertRaises(ValueError):
            wa.audit(W1_OTHER)
        self.assertEqual(wa.checkpoint, expected_state(CRL1))

    def test_lower_sequence_never_advances(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(plain(["a", "b", "c"], CRL2))
        with self.assertRaises(ValueError):
            pa.audit(P1_TRUE)
        self.assertEqual(pa.checkpoint, expected_state(CRL2))
        wa = WeightedCrlProofAuditor(ROOT)
        wa.audit(weighted(["a", "b", "c", "d"], CRL2))
        with self.assertRaises(ValueError):
            wa.audit(W1_TRUE)
        self.assertEqual(wa.checkpoint, expected_state(CRL2))


class FailureDoesNotCommitTest(unittest.TestCase):
    def setUp(self):
        self.plain = CrlProofAuditor(ROOT)
        self.plain.audit(plain(["a", "b", "c"], CRL1))
        self.weighted = WeightedCrlProofAuditor(ROOT)
        self.weighted.audit(W1_TRUE)
        self.triangle_trust = trust("b")
        self.weighted_trust = trust("b", positions=WEIGHTED_POSITIONS)

    def _no_commit(self, auditor, failing):
        before = auditor.checkpoint.to_bytes()
        for proof in failing:
            with self.assertRaises(ValueError, msg=repr(proof)):
                auditor.audit(proof)
            self.assertEqual(auditor.checkpoint.to_bytes(), before)

    def test_plain_failures_carrying_higher_sequences_do_not_commit(self):
        revoked = plain_revoked(
            ["a", "b", "c"], self.triangle_trust, CRL3
        )
        consensus_mismatch = plain_resigned(
            ["a", "b", "c"], CRL3,
            mutate=lambda body: body[7].__setitem__(3, False),
        )
        tampered_mac = dataclasses.replace(
            P3_TRUE, mac=bytes(b ^ 1 for b in P3_TRUE.mac)
        )
        self._no_commit(
            self.plain,
            (revoked, consensus_mismatch, tampered_mac,
             b"not json", b"", None, 42),
        )
        # A valid higher proof still advances straight after the failures.
        self.assertEqual(self.plain.audit(P3_TRUE), PLAIN_TRUE)
        self.assertEqual(self.plain.checkpoint, expected_state(CRL3))

    def test_weighted_failures_carrying_higher_sequences_do_not_commit(self):
        revoked = weighted_revoked(self.weighted_trust, CRL3)
        consensus_mismatch = weighted_resigned(
            CRL3, mutate=lambda body: body[9].__setitem__(3, False)
        )
        tampered_mac = dataclasses.replace(
            W3_TRUE, mac=bytes(b ^ 1 for b in W3_TRUE.mac)
        )
        self._no_commit(
            self.weighted,
            (revoked, consensus_mismatch, tampered_mac,
             b"not json", b"", None, 42),
        )
        self.assertEqual(self.weighted.audit(W3_TRUE), WEIGHTED_TRUE)
        self.assertEqual(self.weighted.checkpoint, expected_state(CRL3))

    def test_failures_against_a_restored_checkpoint_do_not_commit(self):
        saved = self.plain.checkpoint.to_bytes()
        restored = CrlProofAuditor(ROOT, checkpoint=saved)
        revoked = plain_revoked(["a", "b", "c"], self.triangle_trust, CRL2)
        with self.assertRaises(ValueError):
            restored.audit(revoked)
        # The exported bytes are exactly what the caller passed back in.
        self.assertIsNotNone(restored.checkpoint)
        self.assertEqual(restored.checkpoint.to_bytes(), saved)


class InstanceIsolationTest(unittest.TestCase):
    def test_instances_hold_independent_state(self):
        a = CrlProofAuditor(ROOT)
        b = CrlProofAuditor(ROOT)
        a.audit(plain(["a", "b", "c"], CRL2))
        self.assertEqual(a.checkpoint, expected_state(CRL2))
        self.assertIsNone(b.checkpoint)
        b.audit(P1_TRUE)
        self.assertEqual(b.checkpoint, expected_state(CRL1))
        self.assertEqual(a.checkpoint, expected_state(CRL2))

        wa = WeightedCrlProofAuditor(ROOT)
        wb = WeightedCrlProofAuditor(ROOT)
        wa.audit(weighted(["a", "b", "c", "d"], CRL3))
        self.assertIsNone(wb.checkpoint)
        wb.audit(W1_TRUE)
        self.assertEqual(wb.checkpoint, expected_state(CRL1))
        self.assertEqual(wa.checkpoint, expected_state(CRL3))


class MixedConcurrencyTest(unittest.TestCase):
    def _run(self, auditor, advance, replay, conflict):
        # Frontier starts at the replay sequence. One advance, several exact
        # replays and one same-sequence/different-digest conflict race under
        # a barrier. Whatever the interleaving, each outcome must correspond
        # to some serial ordering: the advance (and any repeat of it after it
        # wins, which is then an identical-digest replay) always succeeds;
        # the conflict always rejects (same-seq clash before the win,
        # rollback after it); a seq-1 replay succeeds only if it lands before
        # the advance and is a rollback afterwards. The only hard invariant is
        # that the frontier never moves backwards.
        start = threading.Barrier(8)
        tallies = {"ok": 0, "rejected": 0, "errors": []}
        lock = threading.Lock()

        def run(proof, *, may_succeed, may_reject):
            start.wait()
            try:
                auditor.audit(proof)
                outcome = "ok"
            except ValueError:
                outcome = "rejected"
            except Exception as error:  # pragma: no cover - surfaced below
                with lock:
                    tallies["errors"].append(repr(error))
                return
            with lock:
                tallies[outcome] += 1
            self.assertTrue(
                (outcome == "ok" and may_succeed)
                or (outcome == "rejected" and may_reject),
                f"unexpected {outcome} for {proof!r}",
            )

        threads = [
            # The advance and its repeats are a higher (then identical)
            # snapshot: succeed in every serial position.
            threading.Thread(target=run, args=(advance,),
                             kwargs={"may_succeed": True, "may_reject": False}),
            threading.Thread(target=run, args=(advance,),
                             kwargs={"may_succeed": True, "may_reject": False}),
            threading.Thread(target=run, args=(advance.to_bytes(),),
                             kwargs={"may_succeed": True, "may_reject": False}),
            threading.Thread(target=run, args=(advance.to_bytes(),),
                             kwargs={"may_succeed": True, "may_reject": False}),
            threading.Thread(target=run, args=(advance.to_bytes(),),
                             kwargs={"may_succeed": True, "may_reject": False}),
            # Exact replays at the starting frontier: succeed only before the
            # advance commits, roll back afterwards — both are serial orders.
            threading.Thread(target=run, args=(replay,),
                             kwargs={"may_succeed": True, "may_reject": True}),
            threading.Thread(target=run, args=(replay.to_bytes(),),
                             kwargs={"may_succeed": True, "may_reject": True}),
            # A clashing digest at the same starting sequence never succeeds.
            threading.Thread(target=run, args=(conflict,),
                             kwargs={"may_succeed": False, "may_reject": True}),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(tallies["errors"], [])
        # At least one advance had to commit for the run to make progress.
        self.assertGreaterEqual(tallies["ok"], 1)
        return tallies

    def test_plain_mixed_advance_replay_conflict(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(P1_TRUE)
        advance = plain(["a", "b", "c"], CRL2)
        tallies = self._run(auditor, advance, P1_TRUE, P1_OTHER)
        # Five advance attempts always succeed (the first advances, the rest
        # are identical-digest replays); the conflict never does.
        self.assertGreaterEqual(tallies["ok"], 5)
        self.assertGreaterEqual(tallies["rejected"], 1)
        # No interleaving can move the frontier past or below the advance.
        self.assertEqual(auditor.checkpoint, expected_state(CRL2))
        self.assertEqual(
            auditor.checkpoint.to_bytes(), expected_state(CRL2).to_bytes()
        )

    def test_weighted_mixed_advance_replay_conflict(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(W1_TRUE)
        advance = weighted(["a", "b", "c", "d"], CRL2)
        tallies = self._run(auditor, advance, W1_TRUE, W1_OTHER)
        self.assertGreaterEqual(tallies["ok"], 5)
        self.assertGreaterEqual(tallies["rejected"], 1)
        self.assertEqual(auditor.checkpoint, expected_state(CRL2))


class RestoreRejectionTest(unittest.TestCase):
    def test_wrong_root_rejected(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(P1_TRUE)
        saved = pa.checkpoint.to_bytes()
        with self.assertRaises(ValueError):
            CrlProofAuditor(OTHER_ROOT, checkpoint=saved)
        with self.assertRaises(ValueError):
            WeightedCrlProofAuditor(OTHER_ROOT, checkpoint=saved)
        with self.assertRaises(ValueError):
            CrlProofAuditor(
                OTHER_ROOT,
                checkpoint=CrlState(
                    1, 1, hashlib.sha256(CRL1.to_bytes()).digest(),
                    pa.checkpoint.mac,
                ),
            )

    def test_corrupted_or_noncanonical_encoding_rejected(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(P1_TRUE)
        saved = bytearray(pa.checkpoint.to_bytes())
        saved[len(saved) // 2] ^= 0x01
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            for bad in (bytes(saved), b"not json", b"{}", b"[]", b"",
                        saved + b" "):
                with self.assertRaises(ValueError, msg=(auditor_cls, bad)):
                    auditor_cls(ROOT, checkpoint=bad)

    def test_illegal_checkpoint_object_rejected(self):
        zero_mac = CrlState(
            1, 1, hashlib.sha256(CRL1.to_bytes()).digest(), b"\x00" * 32
        )
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            with self.assertRaises(ValueError):
                auditor_cls(ROOT, checkpoint=zero_mac)
            for bad in ("x", 1, [], {}, object()):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    auditor_cls(ROOT, checkpoint=bad)

    def test_root_contracts(self):
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            with self.assertRaises(ValueError):
                auditor_cls(b"")
            for bad in (bytearray(ROOT), "", None, 0, object()):
                with self.assertRaises(TypeError, msg=repr(bad)):
                    auditor_cls(bad)

    def test_checkpoint_remains_read_only_and_frozen(self):
        pa = CrlProofAuditor(ROOT)
        pa.audit(P1_TRUE)
        with self.assertRaises(AttributeError):
            pa.checkpoint = None
        with self.assertRaises(dataclasses.FrozenInstanceError):
            pa.checkpoint.sequence = 2
        wa = WeightedCrlProofAuditor(ROOT)
        wa.audit(W1_TRUE)
        with self.assertRaises(AttributeError):
            wa.checkpoint = None
        with self.assertRaises(dataclasses.FrozenInstanceError):
            wa.checkpoint.digest = b"\x00" * 32


if __name__ == "__main__":
    unittest.main()
