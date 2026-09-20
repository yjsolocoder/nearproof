import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    Consensus,
    CrlProof,
    CrlProofAuditor,
    CrlState,
    RangeDecision,
    attest_observation_for_point,
    cert,
    make_crl,
    prove_crl,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"

DIGEST = b"\x01" * 32
MAC = b"\x02" * 32


def state_mac(root, sequence, digest):
    payload = {"version": 1, "sequence": sequence, "digest": digest.hex()}
    body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
    return hmac.new(root, b"NPCK1" + body, hashlib.sha256).digest()


def trust(ident):
    return cert(ident, *POSITIONS[ident], KEYS[ident], ROOT)


def record(ident):
    return attest_observation_for_point(
        ident, *POSITIONS[ident], RangeDecision(1, 5.0, True),
        POINT, CONTEXT, 0.0, KEYS[ident],
    )


def empty_crl(sequence, *, issued_at=0.0, root=ROOT):
    return make_crl([], sequence, issued_at, root)


def make_proof(crl, *, now=10.0):
    return prove_crl(
        [record(i) for i in "abc"], POINT, CONTEXT,
        [trust(i) for i in "abc"], ROOT, crl, now=now,
    )


class CrlStateContractTest(unittest.TestCase):
    def test_is_frozen_positional_and_equal_by_fields(self):
        first = CrlState(1, 7, DIGEST, MAC)
        second = CrlState(version=1, sequence=7, digest=DIGEST, mac=MAC)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 8

    def test_field_contract(self):
        with self.assertRaises(ValueError):
            CrlState(2, 7, DIGEST, MAC)
        with self.assertRaises(ValueError):
            CrlState(True, 7, DIGEST, MAC)
        for bad in (True, 1.5, "7", -1, 1 << 64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState(1, bad, DIGEST, MAC)
        for bad in (b"\x01" * 31, b"\x01" * 33, "01" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState(1, 7, bad, MAC)
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState(1, 7, DIGEST, bad)

    def test_round_trip(self):
        state = CrlState(1, 7, DIGEST, MAC)
        blob = state.to_bytes()
        self.assertEqual(
            json.loads(blob),
            {"version": 1, "sequence": 7,
             "digest": DIGEST.hex(), "mac": MAC.hex()},
        )
        self.assertEqual(CrlState.from_bytes(blob), state)

    def test_from_bytes_rejects_non_bytes_and_non_canonical(self):
        state = CrlState(1, 7, DIGEST, MAC)
        blob = state.to_bytes()
        with self.assertRaises(ValueError):
            CrlState.from_bytes(blob.decode())
        for bad in (b"", b"not json", blob + b" ", blob + b"\n",
                    blob.replace(b"7", b"7.0", 1),
                    blob.replace(b'"digest":"01',
                                 b'"digest":"AB', 1)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState.from_bytes(bad)
        # Missing, extra, duplicated and out-of-order keys are rejected.
        obj = json.loads(blob)
        for variant in (
            {"sequence": 7, "version": 1, "digest": DIGEST.hex(),
             "mac": MAC.hex()},
            {"version": 1, "sequence": 7, "digest": DIGEST.hex()},
            dict(obj, extra=0),
        ):
            with self.assertRaises(ValueError, msg=repr(variant)):
                CrlState.from_bytes(
                    json.dumps(variant, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_mac(self):
        state = CrlState(1, 7, DIGEST, b"\x03" * 32)
        self.assertEqual(CrlState.from_bytes(state.to_bytes()), state)


class CrlProofAuditorTest(unittest.TestCase):
    def test_root_contract(self):
        with self.assertRaises(TypeError):
            CrlProofAuditor("not bytes")
        with self.assertRaises(TypeError):
            CrlProofAuditor(bytearray(ROOT))
        with self.assertRaises(ValueError):
            CrlProofAuditor(b"")

    def test_starts_empty_and_advances(self):
        auditor = CrlProofAuditor(ROOT)
        self.assertIsNone(auditor.checkpoint)
        crl = empty_crl(1)
        consensus = auditor.audit(make_proof(crl))
        self.assertIsInstance(consensus, Consensus)
        state = auditor.checkpoint
        self.assertIsInstance(state, CrlState)
        self.assertEqual(state.version, 1)
        self.assertEqual(state.sequence, 1)
        self.assertEqual(
            state.digest, hashlib.sha256(crl.to_bytes()).digest()
        )
        self.assertEqual(
            state.mac, state_mac(ROOT, 1, hashlib.sha256(crl.to_bytes()).digest())
        )

    def test_same_sequence_same_hash_replays(self):
        auditor = CrlProofAuditor(ROOT)
        proof = make_proof(empty_crl(3))
        auditor.audit(proof)
        before = auditor.checkpoint
        # The same proof, as an object and as canonical bytes, replays.
        auditor.audit(proof)
        auditor.audit(proof.to_bytes())
        self.assertEqual(auditor.checkpoint, before)

    def test_higher_sequence_advances_and_lower_is_rejected(self):
        auditor = CrlProofAuditor(ROOT)
        low = make_proof(empty_crl(1))
        high = make_proof(empty_crl(2))
        auditor.audit(low)
        auditor.audit(high)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        with self.assertRaises(ValueError):
            auditor.audit(low)
        # A failed audit never changes the state.
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_same_sequence_different_hash_is_rejected(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(make_proof(empty_crl(2, issued_at=0.0)))
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit(make_proof(empty_crl(2, issued_at=1.0)))
        self.assertEqual(auditor.checkpoint, before)

    def test_unauthenticated_proof_never_changes_state(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(make_proof(empty_crl(1)))
        before = auditor.checkpoint
        forged = make_proof(empty_crl(9))
        forged = CrlProof(1, forged.body, b"\x00" * 32)
        with self.assertRaises(ValueError):
            auditor.audit(forged)
        with self.assertRaises(ValueError):
            auditor.audit(42)
        self.assertEqual(auditor.checkpoint, before)

    def test_checkpoint_round_trip_across_restart(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(make_proof(empty_crl(4)))
        exported = auditor.checkpoint.to_bytes()
        # A restarted auditor resumes from the caller-saved checkpoint,
        # whether handed the object or its canonical bytes.
        for checkpoint in (auditor.checkpoint, exported):
            resumed = CrlProofAuditor(ROOT, checkpoint=checkpoint)
            self.assertEqual(resumed.checkpoint, auditor.checkpoint)
            with self.assertRaises(ValueError):
                resumed.audit(make_proof(empty_crl(3)))
            resumed.audit(make_proof(empty_crl(5)))

    def test_checkpoint_mac_is_verified(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(make_proof(empty_crl(1)))
        state = auditor.checkpoint
        with self.assertRaises(ValueError):
            CrlProofAuditor(OTHER_ROOT, checkpoint=state)
        with self.assertRaises(ValueError):
            CrlProofAuditor(ROOT, checkpoint=state.to_bytes() + b" ")
        with self.assertRaises(ValueError):
            CrlProofAuditor(ROOT, checkpoint="not a state")

    def test_concurrent_audits_never_roll_back(self):
        auditor = CrlProofAuditor(ROOT)
        proofs = [make_proof(empty_crl(seq)) for seq in (1, 2, 3)]
        errors = []

        def run(proof):
            try:
                auditor.audit(proof)
            except ValueError as error:
                errors.append(error)

        threads = [
            threading.Thread(target=run, args=(proof,))
            for proof in proofs * 10
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(auditor.checkpoint.sequence, 3)


if __name__ == "__main__":
    unittest.main()
