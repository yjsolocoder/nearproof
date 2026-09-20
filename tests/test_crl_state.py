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
    _CRL_STATE_PREFIX,
    _crl_proof_mac,
    _crl_state_mac,
    _crl_state_payload,
    _encode_payload,
    _parse_crl_proof_hex,
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


def triangle_records():
    return [record("a"), record("b"), record("c")]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


def empty_crl(sequence, *, issued_at=0.0, root=ROOT):
    return make_crl([], sequence, issued_at, root)


def proof_for(crl, *, now=10.0, min=0):
    return prove_crl(
        triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
        crl, now=now, min=min,
    )


def body_of(proof):
    return json.loads(proof.body)


def crl_bytes_of(proof):
    return _parse_crl_proof_hex(body_of(proof)[4], "crl")


def state_mac(root, state):
    return _crl_state_mac(root, _crl_state_payload(state))


def make_state(sequence, crl, *, root=ROOT, mac=None):
    if mac is None:
        placeholder = CrlState(1, sequence, hashlib.sha256(crl.to_bytes()).digest(),
                               b"\x00" * 32)
        mac = state_mac(root, placeholder)
    return CrlState(
        1, sequence, hashlib.sha256(crl.to_bytes()).digest(), mac
    )


class CrlStateContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        crl = empty_crl(1)
        first = make_state(1, crl)
        second = CrlState(1, first.sequence, first.digest, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.sequence, first.digest, first.mac),
            (1, 1, hashlib.sha256(crl.to_bytes()).digest(), first.mac),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 2

    def test_version_must_be_one(self):
        digest = b"\x01" * 32
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState(bad, 1, digest, b"\x00" * 32)

    def test_sequence_is_non_bool_u64(self):
        digest = b"\x01" * 32
        for bad in (True, False, 1.0, "1", None, -1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState(1, bad, digest, b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            CrlState(1, good, digest, b"\x00" * 32)

    def test_digest_and_mac_must_be_exactly_32_bytes(self):
        for bad_digest in (b"\x00" * 31, b"\x00" * 33, "", "ab" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad_digest)):
                CrlState(1, 1, bad_digest, b"\x00" * 32)
        for bad_mac in (b"\x00" * 31, b"\x00" * 33, "", "ab" * 32, None):
            with self.assertRaises(ValueError, msg=repr(bad_mac)):
                CrlState(1, 1, b"\x00" * 32, bad_mac)


class CrlStateEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        state = make_state(7, empty_crl(7))
        obj = json.loads(state.to_bytes())
        self.assertEqual(list(obj), ["version", "sequence", "digest", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["sequence"], 7)
        self.assertEqual(obj["digest"], state.digest.hex())
        self.assertEqual(obj["mac"], state.mac.hex())
        self.assertNotIn(b" ", state.to_bytes())
        self.assertEqual(
            state.to_bytes(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 7,
                    "digest": state.digest.hex(),
                    "mac": state.mac.hex(),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def test_round_trip(self):
        for sequence in (0, 1, 2**64 - 1):
            state = make_state(sequence, empty_crl(sequence))
            self.assertEqual(CrlState.from_bytes(state.to_bytes()), state)

    def test_from_bytes_rejects_non_bytes(self):
        state = make_state(1, empty_crl(1))
        for bad in (state.to_bytes().decode(), None, 42, [1], bytearray(state.to_bytes())):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlState.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(make_state(1, empty_crl(1)).to_bytes())
        blobs = [
            json.dumps({"sequence": 1, "version": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"], "mac": good["mac"],
                        "extra": 1}, separators=(",", ":")).encode(),
            # A genuinely duplicated key cannot be built via a Python dict
            # literal (it would collapse pre-serialization).
            (
                b'{"version":1,"sequence":1,"digest":'
                + json.dumps(good["digest"]).encode()
                + b',"mac":'
                + json.dumps(good["mac"]).encode()
                + b',"version":1}'
            ),
            json.dumps({"version": 2, "sequence": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                CrlState.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(make_state(1, empty_crl(1)).to_bytes())
        blobs = [
            json.dumps({"version": 1, "sequence": True,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": -1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 2**64,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": "zz", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"].upper(),
                        "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": "00", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"], "mac": "ab" * 31},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                CrlState.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = make_state(1, empty_crl(1)).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json", b""):
            with self.assertRaises(ValueError, msg=blob):
                CrlState.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        state = make_state(1, empty_crl(1), mac=b"\x00" * 32)
        decoded = CrlState.from_bytes(state.to_bytes())
        self.assertEqual(decoded, state)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class CrlStateMacTest(unittest.TestCase):
    def test_digest_is_sha256_of_canonical_crl(self):
        crl = empty_crl(3, issued_at=4.5)
        proof = proof_for(crl)
        state = make_state(3, crl)
        canonical_crl = crl_bytes_of(proof)
        self.assertEqual(canonical_crl, crl.to_bytes())
        self.assertEqual(state.digest, hashlib.sha256(canonical_crl).digest())

    def test_mac_formula_direct_concatenation(self):
        crl = empty_crl(2)
        state = make_state(2, crl)
        encoding = _encode_payload(_crl_state_payload(state))
        self.assertEqual(
            state.mac,
            hmac.new(ROOT, _CRL_STATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            ROOT,
            _CRL_STATE_PREFIX + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(state.mac, forged)
        self.assertNotEqual(
            state.mac,
            hmac.new(OTHER_ROOT, _CRL_STATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )


class CrlProofAuditorInitTest(unittest.TestCase):
    def test_root_contract(self):
        with self.assertRaises(ValueError):
            CrlProofAuditor(b"")
        for bad in (bytearray(ROOT), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                CrlProofAuditor(bad)

    def test_checkpoint_is_keyword_only(self):
        state = make_state(1, empty_crl(1))
        with self.assertRaises(TypeError):
            CrlProofAuditor(ROOT, state)
        self.assertIsNone(CrlProofAuditor(ROOT).checkpoint)
        self.assertIs(CrlProofAuditor(ROOT, checkpoint=None).checkpoint, None)

    def test_checkpoint_must_be_state_bytes_or_none(self):
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlProofAuditor(ROOT, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            CrlProofAuditor(ROOT, checkpoint=b"not json")

    def test_checkpoint_mac_verified(self):
        crl = empty_crl(1)
        with self.assertRaises(ValueError):
            CrlProofAuditor(ROOT, checkpoint=make_state(1, crl, mac=b"\x00" * 32))
        with self.assertRaises(ValueError):
            CrlProofAuditor(
                ROOT, checkpoint=make_state(1, crl, root=OTHER_ROOT)
            )
        # Object and canonical bytes forms both accepted when the MAC is good.
        state = make_state(1, crl)
        self.assertIs(
            CrlProofAuditor(ROOT, checkpoint=state).checkpoint, state
        )
        restored = CrlProofAuditor(ROOT, checkpoint=state.to_bytes()).checkpoint
        self.assertEqual(restored, state)

    def test_checkpoint_property_is_read_only(self):
        auditor = CrlProofAuditor(ROOT)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = make_state(1, empty_crl(1))


class CrlProofAuditorGatingTest(unittest.TestCase):
    def setUp(self):
        self.crl1 = empty_crl(1)
        self.crl2 = make_crl([], 2, 5.0, ROOT)
        self.crl3 = make_crl([], 3, 9.0, ROOT)
        # Same sequence as crl1 but different content -> different digest.
        self.crl1_other = make_crl([], 1, 9.0, ROOT)
        self.p1 = proof_for(self.crl1)
        self.p2 = proof_for(self.crl2)
        self.p3 = proof_for(self.crl3)
        self.p1_other = proof_for(self.crl1_other)
        self.expected = Consensus(
            total=3, support=3, rejected=(), accepted=True
        )

    def test_first_audit_advances_from_empty(self):
        auditor = CrlProofAuditor(ROOT)
        self.assertEqual(auditor.audit(self.p1), self.expected)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))
        # Bytes input is accepted identically.
        auditor2 = CrlProofAuditor(ROOT)
        self.assertEqual(auditor2.audit(self.p1.to_bytes()), self.expected)
        self.assertEqual(auditor2.checkpoint, make_state(1, self.crl1))

    def test_higher_sequence_advances(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        auditor.audit(self.p2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.crl2))
        auditor.audit(self.p3)
        self.assertEqual(auditor.checkpoint, make_state(3, self.crl3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        with self.assertRaises(ValueError):
            auditor.audit(self.p1)
        self.assertEqual(auditor.checkpoint, make_state(2, self.crl2))

    def test_same_sequence_same_digest_is_a_replay(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        for _ in range(3):
            self.assertEqual(auditor.audit(self.p1), self.expected)
            self.assertEqual(auditor.audit(self.p1.to_bytes()), self.expected)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))

    def test_same_sequence_different_digest_rejected(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        self.assertNotEqual(
            hashlib.sha256(self.crl1.to_bytes()).digest(),
            hashlib.sha256(self.crl1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.p1_other)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        # A proof whose outer MAC uses another root never reaches the gate.
        with self.assertRaises(ValueError):
            auditor.audit(self._proof_under_other_root(self.crl3))
        # Tampered outer MAC.
        tampered = dataclasses.replace(
            self.p2, mac=bytes(b ^ 1 for b in self.p2.mac)
        )
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        # Malformed argument.
        for bad in (None, 42, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))

    @staticmethod
    def _proof_under_other_root(crl):
        # The body remains the ROOT-signed one; only the outer MAC uses the
        # other root, so audit_proof rejects it.
        body = proof_for(crl).body
        return CrlProof(1, body, _crl_proof_mac(OTHER_ROOT, body))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        saved = auditor.checkpoint.to_bytes()
        restarted = CrlProofAuditor(ROOT, checkpoint=saved)
        # The old frontier still replays.
        self.assertEqual(restarted.audit(self.p2), self.expected)
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.audit(self.p1)
        # Progress past the restored frontier still advances.
        restarted.audit(self.p3)
        self.assertEqual(restarted.checkpoint, make_state(3, self.crl3))

    def test_restored_checkpoint_uses_canonical_bytes_form(self):
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        blob = auditor.checkpoint.to_bytes()
        self.assertEqual(
            CrlProofAuditor(ROOT, checkpoint=blob).checkpoint,
            auditor.checkpoint,
        )


class CrlProofAuditorConcurrencyTest(unittest.TestCase):
    def test_concurrent_audits_never_roll_back(self):
        crl1 = empty_crl(1)
        crl2 = make_crl([], 2, 5.0, ROOT)
        p1 = proof_for(crl1)
        p2 = proof_for(crl2)
        auditor = CrlProofAuditor(ROOT)
        errors = []

        def worker(item):
            try:
                auditor.audit(item)
            except ValueError:
                # Lower-sequence audits after p2 has advanced must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        # Interleave replays of the low proof with the advancing one.
        items = [p1, p1.to_bytes(), p2, p1, p2.to_bytes(), p1] * 8
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint, make_state(2, crl2))

    def test_advance_wins_against_rejected_rollback(self):
        crl1 = empty_crl(1)
        crl2 = make_crl([], 2, 5.0, ROOT)
        p1 = proof_for(crl1)
        p2 = proof_for(crl2)
        start = threading.Barrier(2)
        auditor = CrlProofAuditor(ROOT)
        auditor.audit(p1)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    auditor.audit(p1)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            auditor.audit(p2)
            outcomes.append("advanced")

        threads = [threading.Thread(target=rollback),
                   threading.Thread(target=advance)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(auditor.checkpoint, make_state(2, crl2))


if __name__ == "__main__":
    unittest.main()
