"""Regression tests for the shared checkpoint lifecycle of the CRL proof
auditors.

Everything here goes through the public interface: proofs are produced
with :func:`prove_crl`/:func:`prove_weighted_crl`, audited through
:class:`CrlProofAuditor`/:class:`WeightedCrlProofAuditor`, and checkpoints
are carried between auditors only as exported :class:`CrlState` objects or
their canonical ``to_bytes`` bytes. Forged proofs are built by re-encoding
a tampered body and re-signing it with the root key, exactly as a caller
with the root could.
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
    _encode_payload,
    attest_observation_for_point,
    audit_proof,
    audit_weighted_crl_proof,
    cert,
    make_crl,
    prove_crl,
    prove_weighted_crl,
    revoke_trust,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
KEY_D = b"\xdd" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C, "d": KEY_D}
POSITIONS = {
    "a": (3.0, 0.0),
    "b": (0.0, 4.0),
    "c": (0.0, 0.0),
    "d": (50.0, 50.0),
}
WEIGHTS = {"a": 1, "b": 2, "c": 4, "d": 8}
THRESHOLD = 7

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, root=ROOT, key=None):
    px, py = POSITIONS[ident]
    return cert(ident, px, py, key or KEYS[ident], root)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), point, context, 0.0,
        key or KEYS[ident],
    )


def empty_crl(sequence, *, issued_at=0.0, root=ROOT):
    return make_crl([], sequence, issued_at, root)


def plain_proof(crl, uppers=None, *, now=10.0, min=0):
    uppers = uppers or {}
    records = [record(ident, uppers.get(ident, 5.0)) for ident in "abc"]
    return prove_crl(
        records, POINT, CONTEXT, [trust(i) for i in "abc"], ROOT,
        crl, now=now, min=min,
    )


def weighted_proof(crl, uppers=None, *, now=10.0, min=0):
    uppers = uppers or {}
    records = [record(ident, uppers.get(ident, 5.0)) for ident in "abcd"]
    return prove_weighted_crl(
        records, POINT, CONTEXT, [trust(i) for i in "abcd"], ROOT,
        crl, ConsensusPolicy(WEIGHTS, THRESHOLD), now=now, min=min,
    )


def crl_digest(crl):
    return hashlib.sha256(crl.to_bytes()).digest()


def forge_plain(proof, mutate, *, root=ROOT):
    """Re-sign a mutated copy of a plain proof body with the root key."""
    body = json.loads(proof.body)
    mutate(body)
    new_body = _encode_payload(body)
    return CrlProof(
        1, new_body, hmac.new(root, b"NPCCE2" + new_body, hashlib.sha256).digest()
    )


def forge_weighted(proof, mutate, *, root=ROOT):
    """Re-sign a mutated copy of a weighted proof body with the root key."""
    body = json.loads(proof.body)
    mutate(body)
    new_body = _encode_payload(body)
    return WeightedCrlProof(
        1, new_body, hmac.new(root, b"NPWCP1" + new_body, hashlib.sha256).digest()
    )


def flip_one_byte(blob):
    data = bytearray(blob)
    data[len(data) // 2] ^= 0x01
    return bytes(data)


class Fixtures:
    """The CRLs and proofs shared by the lifecycle tests."""

    def __init__(self):
        self.crl1 = empty_crl(1)
        self.crl2 = make_crl([], 2, 5.0, ROOT)
        self.crl3 = make_crl([], 3, 9.0, ROOT)
        # Same sequences with different content -> different digests.
        self.crl1_other = make_crl([], 1, 9.0, ROOT)
        self.crl2_other = make_crl([], 2, 7.0, ROOT)
        self.p1 = plain_proof(self.crl1)
        self.p2 = plain_proof(self.crl2)
        self.p3 = plain_proof(self.crl3)
        self.p1_other = plain_proof(self.crl1_other)
        self.p2_other = plain_proof(self.crl2_other)
        self.w1 = weighted_proof(self.crl1)
        self.w2 = weighted_proof(self.crl2)
        self.w3 = weighted_proof(self.crl3)
        self.w1_other = weighted_proof(self.crl1_other)
        self.w2_other = weighted_proof(self.crl2_other)


PLAIN_EXPECTED = Consensus(total=3, support=3, rejected=(), accepted=True)
WEIGHTED_EXPECTED = WeightedConsensus(
    total_weight=15, support_weight=7, rejected=("d",), accepted=True
)


class CrossAuditorRestoreTest(unittest.TestCase):
    """A checkpoint exported by one auditor kind restores into the other."""

    def setUp(self):
        self.fx = Fixtures()

    def test_alternating_restore_follows_one_frontier(self):
        fx = self.fx
        plain = CrlProofAuditor(ROOT)
        self.assertEqual(plain.audit(fx.p1), PLAIN_EXPECTED)
        state1 = plain.checkpoint

        # Bytes form crosses into the weighted auditor.
        weighted = WeightedCrlProofAuditor(ROOT, checkpoint=state1.to_bytes())
        self.assertEqual(weighted.checkpoint, state1)
        self.assertEqual(weighted.audit(fx.w2), WEIGHTED_EXPECTED)
        state2 = weighted.checkpoint
        self.assertEqual(state2.sequence, 2)
        self.assertEqual(state2.digest, crl_digest(fx.crl2))

        # Object form crosses back into the plain auditor.
        plain2 = CrlProofAuditor(ROOT, checkpoint=state2)
        self.assertIs(plain2.checkpoint, state2)
        # Rollback and frontier conflict are refused across the handoff.
        with self.assertRaises(ValueError):
            plain2.audit(fx.p1)
        with self.assertRaises(ValueError):
            plain2.audit(fx.p2_other)
        self.assertEqual(plain2.checkpoint, state2)
        # Progress past the restored frontier still advances.
        self.assertEqual(plain2.audit(fx.p3), PLAIN_EXPECTED)
        state3 = plain2.checkpoint
        self.assertEqual(state3.digest, crl_digest(fx.crl3))

        # And back into the weighted auditor once more.
        weighted2 = WeightedCrlProofAuditor(ROOT, checkpoint=state3.to_bytes())
        with self.assertRaises(ValueError):
            weighted2.audit(fx.w2)
        # A replay of the frontier snapshot returns its own consensus and
        # leaves the checkpoint bytes untouched.
        saved = weighted2.checkpoint.to_bytes()
        self.assertEqual(weighted2.audit(fx.w3), WEIGHTED_EXPECTED)
        self.assertEqual(weighted2.checkpoint.to_bytes(), saved)

    def test_same_sequence_replay_across_kinds_keeps_checkpoint_bytes(self):
        fx = self.fx
        plain = CrlProofAuditor(ROOT)
        plain.audit(fx.p1)
        exported = plain.checkpoint.to_bytes()
        weighted = WeightedCrlProofAuditor(ROOT, checkpoint=exported)
        # The weighted proof over the same CRL is a replay, not a conflict,
        # even though its consensus shape differs from the plain one.
        self.assertEqual(weighted.audit(fx.w1), WEIGHTED_EXPECTED)
        self.assertEqual(weighted.checkpoint.to_bytes(), exported)

    def test_same_sequence_conflict_across_kinds(self):
        fx = self.fx
        weighted = WeightedCrlProofAuditor(ROOT)
        weighted.audit(fx.w1)
        exported = weighted.checkpoint.to_bytes()
        plain = CrlProofAuditor(ROOT, checkpoint=exported)
        self.assertNotEqual(
            crl_digest(fx.crl1), crl_digest(fx.crl1_other)
        )
        with self.assertRaises(ValueError):
            plain.audit(fx.p1_other)
        self.assertEqual(plain.checkpoint.to_bytes(), exported)

    def test_restore_accepts_object_and_canonical_bytes_in_both_kinds(self):
        fx = self.fx
        plain = CrlProofAuditor(ROOT)
        plain.audit(fx.p2)
        state = plain.checkpoint
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            with self.subTest(auditor=auditor_cls.__name__):
                self.assertIs(
                    auditor_cls(ROOT, checkpoint=state).checkpoint, state
                )
                restored = auditor_cls(ROOT, checkpoint=state.to_bytes())
                self.assertEqual(restored.checkpoint, state)


class MixedLifecycleTest(unittest.TestCase):
    """One instance interleaving advances, replays and conflicts."""

    def setUp(self):
        self.fx = Fixtures()

    def _check_lifecycle(self, auditor, proofs, expected):
        p1, p1_other, p2 = proofs
        self.assertEqual(auditor.audit(p1), expected)
        self.assertIsInstance(auditor.audit(p1.to_bytes()), type(expected))
        saved = auditor.checkpoint.to_bytes()
        # Replay at the frontier: same result, checkpoint bytes unchanged.
        self.assertEqual(auditor.audit(p1), expected)
        self.assertEqual(auditor.checkpoint.to_bytes(), saved)
        # Same sequence, different CRL digest: rejected, state untouched.
        with self.assertRaises(ValueError):
            auditor.audit(p1_other)
        self.assertEqual(auditor.checkpoint.to_bytes(), saved)
        # Higher sequence advances; the old frontier is then unreachable.
        self.assertEqual(auditor.audit(p2), expected)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        with self.assertRaises(ValueError):
            auditor.audit(p1)
        with self.assertRaises(ValueError):
            auditor.audit(p1_other)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.digest, crl_digest(self.fx.crl2))

    def test_plain_auditor(self):
        self._check_lifecycle(
            CrlProofAuditor(ROOT),
            (self.fx.p1, self.fx.p1_other, self.fx.p2),
            PLAIN_EXPECTED,
        )

    def test_weighted_auditor(self):
        self._check_lifecycle(
            WeightedCrlProofAuditor(ROOT),
            (self.fx.w1, self.fx.w1_other, self.fx.w2),
            WEIGHTED_EXPECTED,
        )

    def test_same_sequence_different_consensus_is_not_a_conflict(self):
        # Two valid proofs over the same CRL whose recomputed consensuses
        # differ: the second is a replay of the frontier, not a fork.
        crl = self.fx.crl1
        rejected_proof = plain_proof(crl, {"a": 1.0, "b": 1.0})
        rejected = Consensus(
            total=3, support=1, rejected=("a", "b"), accepted=False
        )
        self.assertEqual(audit_proof(rejected_proof, ROOT), rejected)

        auditor = CrlProofAuditor(ROOT)
        self.assertEqual(auditor.audit(self.fx.p1), PLAIN_EXPECTED)
        saved = auditor.checkpoint.to_bytes()
        self.assertEqual(auditor.audit(rejected_proof), rejected)
        self.assertEqual(auditor.checkpoint.to_bytes(), saved)

    def test_same_sequence_different_weighted_consensus_is_not_a_conflict(self):
        crl = self.fx.crl1
        rejected_proof = weighted_proof(crl, {"a": 1.0, "b": 1.0})
        rejected = WeightedConsensus(
            total_weight=15, support_weight=4,
            rejected=("a", "b", "d"), accepted=False,
        )
        self.assertEqual(audit_weighted_crl_proof(rejected_proof, ROOT), rejected)

        auditor = WeightedCrlProofAuditor(ROOT)
        self.assertEqual(auditor.audit(self.fx.w1), WEIGHTED_EXPECTED)
        saved = auditor.checkpoint.to_bytes()
        self.assertEqual(auditor.audit(rejected_proof), rejected)
        self.assertEqual(auditor.checkpoint.to_bytes(), saved)

    def test_unaccepted_consensus_still_advances_plain(self):
        # support 1 of 3 is below the quorum of three but the proof is
        # valid, so it is returned and advances the checkpoint as usual.
        proof = plain_proof(self.fx.crl2, {"a": 1.0, "b": 1.0})
        auditor = CrlProofAuditor(ROOT)
        result = auditor.audit(proof)
        self.assertEqual(
            result,
            Consensus(total=3, support=1, rejected=("a", "b"), accepted=False),
        )
        self.assertFalse(result.accepted)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.digest, crl_digest(self.fx.crl2))

    def test_unaccepted_consensus_still_advances_weighted(self):
        # Supporting weight 4 is below the threshold of 7 but the proof is
        # valid, so it is returned and advances the checkpoint as usual.
        proof = weighted_proof(self.fx.crl2, {"a": 1.0, "b": 1.0})
        auditor = WeightedCrlProofAuditor(ROOT)
        result = auditor.audit(proof)
        self.assertEqual(
            result,
            WeightedConsensus(
                total_weight=15, support_weight=4,
                rejected=("a", "b", "d"), accepted=False,
            ),
        )
        self.assertFalse(result.accepted)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint.digest, crl_digest(self.fx.crl2))


class FailureDoesNotCommitTest(unittest.TestCase):
    """Failed audits never commit, even when they carry a higher sequence."""

    def setUp(self):
        self.fx = Fixtures()

    def _check_failures_leave_state(self, auditor, first, cases):
        auditor.audit(first)
        saved = auditor.checkpoint.to_bytes()
        for name, bad in cases:
            with self.subTest(failure=name):
                with self.assertRaises(ValueError):
                    auditor.audit(bad)
                self.assertEqual(auditor.checkpoint.to_bytes(), saved)

    def test_plain_failures(self):
        fx = self.fx
        revoked_crl = make_crl([revoke_trust(trust("a"), ROOT)], 3, 9.0, ROOT)
        cases = [
            ("corrupted bytes", flip_one_byte(fx.p3.to_bytes())),
            ("truncated bytes", fx.p3.to_bytes()[:20]),
            ("tampered mac", dataclasses.replace(
                fx.p3, mac=bytes(b ^ 1 for b in fx.p3.mac))),
            ("wrong root mac", CrlProof(
                1, fx.p3.body,
                hmac.new(OTHER_ROOT, b"NPCCE2" + fx.p3.body,
                         hashlib.sha256).digest())),
            ("revoked participant", forge_plain(
                fx.p3, lambda body: body.__setitem__(
                    4, revoked_crl.to_bytes().hex()))),
            ("consensus mismatch", forge_plain(
                fx.p3, lambda body: body[7].__setitem__(
                    3, not body[7][3]))),
            ("wrong type", 42),
            ("none", None),
        ]
        auditor = CrlProofAuditor(ROOT)
        self._check_failures_leave_state(auditor, fx.p1, cases)
        # The auditor is still usable afterwards.
        self.assertEqual(auditor.audit(fx.p2), PLAIN_EXPECTED)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_weighted_failures(self):
        fx = self.fx
        revoked_crl = make_crl([revoke_trust(trust("a"), ROOT)], 3, 9.0, ROOT)
        cases = [
            ("corrupted bytes", flip_one_byte(fx.w3.to_bytes())),
            ("truncated bytes", fx.w3.to_bytes()[:20]),
            ("tampered mac", dataclasses.replace(
                fx.w3, mac=bytes(b ^ 1 for b in fx.w3.mac))),
            ("wrong root mac", WeightedCrlProof(
                1, fx.w3.body,
                hmac.new(OTHER_ROOT, b"NPWCP1" + fx.w3.body,
                         hashlib.sha256).digest())),
            ("revoked participant", forge_weighted(
                fx.w3, lambda body: body.__setitem__(
                    4, revoked_crl.to_bytes().hex()))),
            ("consensus mismatch", forge_weighted(
                fx.w3, lambda body: body[9].__setitem__(
                    3, not body[9][3]))),
            ("wrong type", 42),
            ("none", None),
        ]
        auditor = WeightedCrlProofAuditor(ROOT)
        self._check_failures_leave_state(auditor, fx.w1, cases)
        self.assertEqual(auditor.audit(fx.w2), WEIGHTED_EXPECTED)
        self.assertEqual(auditor.checkpoint.sequence, 2)


class ConcurrencyTest(unittest.TestCase):
    """Concurrent mixed workloads stay serializable and never roll back."""

    def setUp(self):
        self.fx = Fixtures()

    def _run_mixed_workload(self, auditor, items, expectations):
        """Run tagged proof items concurrently against one auditor.

        ``items`` is a list of ``(tag, payload)`` pairs; ``expectations``
        maps each tag to ``("ok", consensus)``, ``"fail"`` or ``"either"``.
        Returns the observed ``(tag, outcome)`` list.
        """
        outcomes = []
        errors = []
        lock = threading.Lock()

        def worker(tag, payload):
            try:
                result = auditor.audit(payload)
                outcome = ("ok", result)
            except ValueError:
                outcome = ("fail", None)
            except Exception as error:  # surfaced by the assertions below
                with lock:
                    errors.append(error)
                return
            with lock:
                outcomes.append((tag, outcome))

        threads = [
            threading.Thread(target=worker, args=(tag, payload))
            for tag, payload in items
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        for tag, outcome in outcomes:
            expectation = expectations[tag]
            with self.subTest(tag=tag, outcome=outcome):
                if expectation == "fail":
                    self.assertEqual(outcome[0], "fail")
                elif expectation == "either":
                    pass
                else:
                    self.assertEqual(outcome, ("ok", expectation[1]))
        return outcomes

    def _check_concurrent_audits(self, auditor, proofs, expected):
        p1, p1_other, p2, p2_other, p3 = proofs
        auditor.audit(p1)
        corrupted = flip_one_byte(p3.to_bytes())
        items = [
            ("p2", p2), ("p3", p3), ("p1-replay", p1),
            ("p2-bytes", p2.to_bytes()), ("p3-bytes", p3.to_bytes()),
            ("p1-conflict", p1_other), ("p2-conflict", p2_other),
            ("corrupted", corrupted),
        ] * 6
        expectations = {
            # The highest-sequence proof always lands; replays of it too.
            "p3": ("ok", expected),
            "p3-bytes": ("ok", expected),
            # The frontier conflict and the corrupt proof can never commit.
            "p1-conflict": "fail",
            "corrupted": "fail",
            # These race with the seq-2 advance and its conflicting twin:
            # each outcome is valid under some serial order.
            "p2": "either",
            "p2-bytes": "either",
            "p2-conflict": "either",
            "p1-replay": "either",
        }
        outcomes = self._run_mixed_workload(auditor, items, expectations)
        # Every serial order consistent with the gating rules commits the
        # unique seq-3 snapshot, so the final frontier is fully determined.
        final = auditor.checkpoint
        self.assertEqual(final.sequence, 3)
        self.assertEqual(final.digest, crl_digest(self.fx.crl3))
        # p3 appeared often enough that at least one success is certain.
        self.assertTrue(
            any(tag == "p3" and outcome[0] == "ok" for tag, outcome in outcomes)
        )

    def test_plain_auditor_concurrent_audits(self):
        self._check_concurrent_audits(
            CrlProofAuditor(ROOT),
            (self.fx.p1, self.fx.p1_other, self.fx.p2,
             self.fx.p2_other, self.fx.p3),
            PLAIN_EXPECTED,
        )

    def test_weighted_auditor_concurrent_audits(self):
        self._check_concurrent_audits(
            WeightedCrlProofAuditor(ROOT),
            (self.fx.w1, self.fx.w1_other, self.fx.w2,
             self.fx.w2_other, self.fx.w3),
            WEIGHTED_EXPECTED,
        )

    def test_checkpoint_never_moves_backwards_under_contention(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.fx.p1)
        stop = threading.Event()
        observed = []

        def reader():
            while not stop.is_set():
                checkpoint = auditor.checkpoint
                observed.append(checkpoint.sequence if checkpoint else 0)

        def advance(proof):
            auditor.audit(proof)

        sampler = threading.Thread(target=reader)
        sampler.start()
        workers = [
            threading.Thread(target=advance, args=(proof,))
            for proof in (self.fx.p2, self.fx.p3)
        ]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()
        stop.set()
        sampler.join()
        self.assertEqual(observed, sorted(observed))
        self.assertEqual(auditor.checkpoint.sequence, 3)

    def test_instances_hold_independent_state(self):
        fx = self.fx
        plain = CrlProofAuditor(ROOT)
        other_plain = CrlProofAuditor(ROOT)
        weighted = WeightedCrlProofAuditor(ROOT)
        plain.audit(fx.p2)
        # Advancing one instance touches neither the other instances nor
        # the other auditor kind.
        self.assertIsNone(other_plain.checkpoint)
        self.assertIsNone(weighted.checkpoint)
        self.assertEqual(other_plain.audit(fx.p1), PLAIN_EXPECTED)
        self.assertEqual(weighted.audit(fx.w1), WEIGHTED_EXPECTED)
        self.assertEqual(other_plain.checkpoint.sequence, 1)
        self.assertEqual(weighted.checkpoint.sequence, 1)
        self.assertEqual(plain.checkpoint.sequence, 2)


class CheckpointContractTest(unittest.TestCase):
    """The exported checkpoint stays frozen, canonical and root-bound."""

    def setUp(self):
        self.fx = Fixtures()
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.fx.p2)
        self.state = auditor.checkpoint
        self.blob = self.state.to_bytes()

    def test_checkpoint_is_frozen_and_the_property_read_only(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.state.sequence = 9
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            with self.subTest(auditor=auditor_cls.__name__):
                with self.assertRaises(AttributeError):
                    auditor_cls(ROOT).checkpoint = self.state

    def test_encoding_shape_and_mac_formula_unchanged(self):
        obj = json.loads(self.blob)
        self.assertEqual(list(obj), ["version", "sequence", "digest", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["sequence"], 2)
        self.assertEqual(obj["digest"], crl_digest(self.fx.crl2).hex())
        payload = _encode_payload(
            {"version": 1, "sequence": 2, "digest": obj["digest"]}
        )
        expected_mac = hmac.new(
            ROOT, b"NPCK1" + payload, hashlib.sha256
        ).hexdigest()
        self.assertEqual(obj["mac"], expected_mac)
        self.assertEqual(CrlState.from_bytes(self.blob), self.state)

    def test_restore_rejects_bad_roots_encodings_and_checkpoints(self):
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            with self.subTest(auditor=auditor_cls.__name__):
                # A checkpoint MAC'd under another root.
                with self.assertRaises(ValueError):
                    auditor_cls(OTHER_ROOT, checkpoint=self.state)
                with self.assertRaises(ValueError):
                    auditor_cls(OTHER_ROOT, checkpoint=self.blob)
                # Corrupted and non-canonical encodings.
                with self.assertRaises(ValueError):
                    auditor_cls(ROOT, checkpoint=flip_one_byte(self.blob))
                pretty = json.dumps(json.loads(self.blob), indent=2).encode()
                with self.assertRaises(ValueError):
                    auditor_cls(ROOT, checkpoint=pretty)
                with self.assertRaises(ValueError):
                    auditor_cls(ROOT, checkpoint=b"not json")
                # A well-formed state whose MAC does not match.
                forged = CrlState(
                    1, 2, crl_digest(self.fx.crl2), b"\x00" * 32
                )
                with self.assertRaises(ValueError):
                    auditor_cls(ROOT, checkpoint=forged)
                # Neither a state, its bytes, nor None.
                for bad in ("x", 1, [], {}, object()):
                    with self.assertRaises(ValueError, msg=repr(bad)):
                        auditor_cls(ROOT, checkpoint=bad)

    def test_root_contract_unchanged(self):
        for auditor_cls in (CrlProofAuditor, WeightedCrlProofAuditor):
            with self.subTest(auditor=auditor_cls.__name__):
                with self.assertRaises(ValueError):
                    auditor_cls(b"")
                for bad in (bytearray(ROOT), "", None, 0, object()):
                    with self.assertRaises(TypeError, msg=repr(bad)):
                        auditor_cls(bad)


class StatelessEntriesUnchangedTest(unittest.TestCase):
    """The stateless entries keep no state and stay proof-type separated."""

    def setUp(self):
        self.fx = Fixtures()

    def test_stateless_audits_accept_any_order(self):
        # No frontier is tracked: a lower sequence audits fine after a
        # higher one, and object/bytes forms agree.
        self.assertEqual(audit_proof(self.fx.p3, ROOT), PLAIN_EXPECTED)
        self.assertEqual(audit_proof(self.fx.p1, ROOT), PLAIN_EXPECTED)
        self.assertEqual(audit_proof(self.fx.p1.to_bytes(), ROOT), PLAIN_EXPECTED)
        self.assertEqual(
            audit_weighted_crl_proof(self.fx.w3, ROOT), WEIGHTED_EXPECTED
        )
        self.assertEqual(
            audit_weighted_crl_proof(self.fx.w1.to_bytes(), ROOT),
            WEIGHTED_EXPECTED,
        )

    def test_provers_are_pure(self):
        self.assertEqual(
            plain_proof(self.fx.crl1), plain_proof(self.fx.crl1)
        )
        self.assertEqual(
            weighted_proof(self.fx.crl1), weighted_proof(self.fx.crl1)
        )

    def test_proof_types_do_not_cross(self):
        # Each auditor and stateless entry rejects the other proof type.
        with self.assertRaises(ValueError):
            audit_proof(self.fx.w1, ROOT)
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(self.fx.p1, ROOT)
        with self.assertRaises(ValueError):
            CrlProofAuditor(ROOT).audit(self.fx.w1)
        with self.assertRaises(ValueError):
            WeightedCrlProofAuditor(ROOT).audit(self.fx.p1)


if __name__ == "__main__":
    unittest.main()
