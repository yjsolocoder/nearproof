import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BoundAttestedObservation,
    CertifiedConsensusEvidence,
    Consensus,
    CrlProof,
    RangeDecision,
    VerifierTrust,
    attest_observation_for_point,
    audit_cert_evidence,
    audit_proof,
    cert,
    locate_cert,
    locate_cert_evidence,
    make_crl,
    prove_crl,
    revoke_trust,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
KEY_D = b"\xdd" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C, "d": KEY_D}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0), "d": (50.0, 50.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, root=ROOT, key=None, x=None, y=None):
    px, py = POSITIONS[ident]
    return cert(ident, x if x is not None else px, y if y is not None else py,
                key or KEYS[ident], root)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), point, context, 0.0,
        key or KEYS[ident],
    )


def triangle_records(upper_bound=5.0, **kwargs):
    return [
        record("a", upper_bound, **kwargs),
        record("b", upper_bound, **kwargs),
        record("c", upper_bound, **kwargs),
    ]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


def empty_crl(*, sequence=1, issued_at=0.0, root=ROOT):
    return make_crl([], sequence, issued_at, root)


def make_proof(crl=None, *, now=10.0, min=0):
    return prove_crl(
        triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
        crl if crl is not None else empty_crl(), now=now, min=min,
    )


def outer_of(proof):
    return json.loads(proof.to_bytes())


def body_of(proof):
    return json.loads(bytes.fromhex(outer_of(proof)["body"]))


class CertifiedConsensusEvidenceToBytesTest(unittest.TestCase):
    def test_non_canonical_body_raises_and_is_not_rewritten(self):
        evidence = locate_cert_evidence(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )
        for bad_body in (b" []", evidence.body + b"\n", b"not json", b""):
            broken = CertifiedConsensusEvidence(1, bad_body, evidence.mac)
            with self.assertRaises(ValueError, msg=repr(bad_body)):
                broken.to_bytes()
            # A frozen instance is never replaced by the canonical spelling.
            self.assertEqual(broken.body, bad_body)

    def test_canonical_body_still_serializes(self):
        evidence = locate_cert_evidence(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )
        self.assertEqual(
            CertifiedConsensusEvidence.from_bytes(evidence.to_bytes()), evidence
        )
        self.assertEqual(
            audit_cert_evidence(evidence.to_bytes(), ROOT),
            locate_cert(triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT),
        )


class CrlProofContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        first = make_proof()
        second = CrlProof(1, first.body, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.mac = b"\x00" * 32

    def test_positional_field_order(self):
        proof = CrlProof(1, b"[]", b"\x01" * 32)
        self.assertEqual(
            (proof.version, proof.body, proof.mac),
            (1, b"[]", b"\x01" * 32),
        )

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlProof(bad, b"[]", b"\x00" * 32)

    def test_body_must_be_bytes(self):
        for bad in ("[]", bytearray(b"[]"), None, 0, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlProof(1, bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"\x00" * 31, b"\x00" * 33, "ab" * 32, None, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlProof(1, b"[]", bad)


class ProveCrlTest(unittest.TestCase):
    def test_wraps_the_snapshot_locate_cert_consensus(self):
        crl = empty_crl(sequence=4)
        records = triangle_records()
        trusts = triangle_trusts()
        expected = locate_cert(
            records, POINT, CONTEXT, trusts, ROOT, revocations=crl, now=10.0, min=2
        )
        proof = prove_crl(records, POINT, CONTEXT, trusts, ROOT, crl,
                          now=10.0, min=2)
        self.assertIsInstance(proof, CrlProof)
        self.assertEqual(proof.version, 1)
        self.assertEqual(len(proof.mac), 32)
        point, context, _, _, _, now, minimum, raw_consensus = body_of(proof)
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(now, 10.0)
        self.assertEqual(minimum, 2)
        self.assertEqual(raw_consensus, [3, 3, [], True])
        self.assertEqual(audit_proof(proof, ROOT), expected)

    def test_body_arrays_are_id_sorted_canonical_hex(self):
        proof = make_proof()
        _p, _c, raw_records, raw_trusts, raw_crl, _n, _m, _consensus = body_of(proof)
        record_ids = [
            BoundAttestedObservation.from_bytes(bytes.fromhex(blob)).id
            for blob in raw_records
        ]
        trust_ids = [
            VerifierTrust.from_bytes(bytes.fromhex(blob)).id
            for blob in raw_trusts
        ]
        self.assertEqual(record_ids, ["a", "b", "c"])
        self.assertEqual(trust_ids, ["a", "b", "c"])
        for blob, source in zip(raw_records, triangle_records()):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        for blob, source in zip(raw_trusts, triangle_trusts()):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        self.assertEqual(
            bytes.fromhex(raw_crl), empty_crl().to_bytes()
        )

    def test_body_is_eight_field_array(self):
        proof = make_proof()
        raw = proof.body
        self.assertNotIn(b" ", raw)
        decoded = json.loads(raw)
        self.assertIsInstance(decoded, list)
        self.assertEqual(len(decoded), 8)

    def test_mac_formula(self):
        proof = make_proof()
        body = bytes.fromhex(outer_of(proof)["body"])
        self.assertEqual(
            proof.mac, hmac.new(ROOT, b"NPCCE2" + body, hashlib.sha256).digest()
        )
        self.assertNotEqual(
            proof.mac,
            hmac.new(OTHER_ROOT, b"NPCCE2" + body, hashlib.sha256).digest(),
        )

    def test_no_delimiter_or_length_prefix(self):
        proof = make_proof()
        body = proof.body
        forged = hmac.new(
            ROOT, b"NPCCE2" + str(len(body)).encode() + body, hashlib.sha256
        ).digest()
        self.assertNotEqual(proof.mac, forged)

    def test_result_is_independent_of_input_order(self):
        crl = empty_crl()
        proof = make_proof(crl)
        shuffled_records = [record("c"), record("a"), record("b")]
        trusts = triangle_trusts()
        shuffled_trusts = [trusts[1], trusts[2], trusts[0]]
        again = prove_crl(
            shuffled_records, POINT, CONTEXT, shuffled_trusts, ROOT, crl, now=10.0
        )
        self.assertEqual(again, proof)

    def test_accepts_mixed_objects_bytes_and_generators(self):
        records = triangle_records()
        trusts = triangle_trusts()
        crl = empty_crl()
        proof = prove_crl(
            (r.to_bytes() if i % 2 else r for i, r in enumerate(records)),
            POINT,
            CONTEXT,
            (t.to_bytes() if i % 2 else t for i, t in enumerate(trusts)),
            ROOT,
            crl.to_bytes(),
            now=0,
        )
        self.assertEqual(proof, prove_crl(records, POINT, CONTEXT, trusts, ROOT,
                                          crl, now=0.0))

    def test_rejection_is_recorded(self):
        crl = empty_crl()
        records = triangle_records() + [record("d")]
        trusts = triangle_trusts() + [trust("d")]
        proof = prove_crl(records, POINT, CONTEXT, trusts, ROOT, crl, now=0.0)
        self.assertEqual(body_of(proof)[7], [4, 3, ["d"], True])
        self.assertEqual(
            audit_proof(proof, ROOT),
            Consensus(total=4, support=3, rejected=("d",), accepted=True),
        )

    def test_revoked_participant_rejected(self):
        trusts = triangle_trusts()
        crl = make_crl([revoke_trust(trusts[1], ROOT)], 1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            prove_crl(triangle_records(), POINT, CONTEXT, trusts, ROOT, crl,
                      now=0.0)

    def test_unrelated_snapshot_entry_is_ignored(self):
        foreign = cert("zzz", 50.0, 50.0, b"\x77" * 32, ROOT)
        crl = make_crl([revoke_trust(foreign, ROOT)], 1, 0.0, ROOT)
        expected = locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )
        self.assertEqual(
            audit_proof(
                prove_crl(triangle_records(), POINT, CONTEXT, triangle_trusts(),
                          ROOT, crl, now=0.0),
                ROOT,
            ),
            expected,
        )

    def test_future_snapshot_and_low_sequence_rejected(self):
        with self.assertRaises(ValueError):
            prove_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                empty_crl(issued_at=11.0), now=10.0,
            )
        with self.assertRaises(ValueError):
            prove_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                empty_crl(sequence=3), now=10.0, min=4,
            )

    def test_now_is_required_and_keyword_only(self):
        crl = empty_crl()
        with self.assertRaises(TypeError):
            prove_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT, crl
            )
        with self.assertRaises(TypeError):
            prove_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                crl, 10.0,
            )

    def test_now_and_min_contracts(self):
        crl = empty_crl()
        for bad_now in ("10", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                prove_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                    crl, now=bad_now,
                )
        for bad_min in (True, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                prove_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                    crl, now=0.0, min=bad_min,
                )

    def test_root_contract_matches_locate_cert(self):
        crl = empty_crl()
        with self.assertRaises(ValueError):
            prove_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), b"",
                crl, now=0.0,
            )
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                prove_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(), bad,
                    crl, now=0.0,
                )

    def test_bad_crl_argument(self):
        for bad in (None, 42, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                prove_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                    bad, now=0.0,
                )


class CrlProofEncodingTest(unittest.TestCase):
    def test_to_bytes_outer_shape(self):
        proof = make_proof()
        obj = outer_of(proof)
        self.assertEqual(list(obj), ["version", "body", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertIsInstance(obj["body"], str)
        self.assertIsInstance(obj["mac"], str)
        self.assertEqual(obj["body"], proof.body.hex())
        self.assertEqual(obj["mac"], proof.mac.hex())
        self.assertEqual(
            proof.to_bytes(),
            json.dumps(
                {
                    "version": 1,
                    "body": proof.body.hex(),
                    "mac": proof.mac.hex(),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def test_round_trip(self):
        proof = make_proof()
        self.assertEqual(CrlProof.from_bytes(proof.to_bytes()), proof)

    def test_from_bytes_rejects_non_bytes(self):
        proof = make_proof()
        for bad in (proof.to_bytes().decode("utf-8"), None, 42, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CrlProof.from_bytes(bad)

    def test_from_bytes_rejects_outer_key_violations(self):
        good = outer_of(make_proof())
        blobs = [
            json.dumps({"body": good["body"], "version": 1, "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"], "mac": good["mac"],
                        "extra": 1}, separators=(",", ":")).encode(),
            json.dumps({"version": 2, "body": good["body"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                CrlProof.from_bytes(blob)

    def test_from_bytes_rejects_bad_hex_and_mac_length(self):
        good = outer_of(make_proof())
        blobs = [
            json.dumps({"version": 1, "body": "zz", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"].upper(),
                        "mac": good["mac"]}, separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"], "mac": "0"},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                CrlProof.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_layers(self):
        data = make_proof().to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json"):
            with self.assertRaises(ValueError, msg=blob):
                CrlProof.from_bytes(blob)
        good = outer_of(make_proof())
        body = json.loads(bytes.fromhex(good["body"]))
        raw = (json.dumps(body, separators=(",", ":")) + " ").encode()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": good["mac"]},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            CrlProof.from_bytes(blob)

    def test_from_bytes_rejects_malformed_bodies(self):
        good = outer_of(make_proof())

        def with_body(body):
            return json.dumps(
                {"version": 1, "body": body.hex(), "mac": good["mac"]},
                separators=(",", ":"),
            ).encode()

        crl_hex = empty_crl().to_bytes().hex()
        bodies = [
            json.dumps([[0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, True], CONTEXT, [], [], crl_hex, 0.0, 0,
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], 7, [], [], crl_hex, 0.0, 0,
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], "not hex", 0.0, 0,
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, "now", 0,
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0.0,
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        [3, 3, ["b", "a"], True]],
                       separators=(",", ":")).encode(),
        ]
        for body in bodies:
            with self.assertRaises(ValueError, msg=body):
                CrlProof.from_bytes(with_body(body))

    def test_to_bytes_rejects_non_canonical_body_without_rewriting(self):
        proof = CrlProof(1, b" []", b"\x00" * 32)
        with self.assertRaises(ValueError):
            proof.to_bytes()
        self.assertEqual(proof.body, b" []")

    def test_from_bytes_does_not_verify_mac(self):
        good = outer_of(make_proof())
        forged = json.dumps(
            {"version": 1, "body": good["body"], "mac": "00" * 32},
            separators=(",", ":"),
        ).encode()
        decoded = CrlProof.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class AuditProofTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        proof = make_proof()
        expected = locate_cert(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
        )
        self.assertEqual(audit_proof(proof, ROOT), expected)
        self.assertEqual(audit_proof(proof.to_bytes(), ROOT), expected)

    def test_wrong_root_rejected(self):
        proof = make_proof()
        with self.assertRaises(ValueError):
            audit_proof(proof, OTHER_ROOT)

    def test_root_shape_contract(self):
        proof = make_proof()
        with self.assertRaises(ValueError):
            audit_proof(proof, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_proof(proof, bad)

    def test_bad_x_type_rejected(self):
        for bad in ("x", 123, None, {}, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_proof(bad, ROOT)

    def test_tampered_mac_rejected(self):
        proof = make_proof()
        tampered = dataclasses.replace(
            proof, mac=bytes(a ^ 1 for a in proof.mac)
        )
        with self.assertRaises(ValueError):
            audit_proof(tampered, ROOT)

    def test_resigned_consensus_mismatch_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        body[7][1] = 2
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE2" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_proof(CrlProof(1, raw, mac), ROOT)

    def test_resigned_min_tamper_rejected(self):
        proof = make_proof(empty_crl(sequence=5), min=5)
        body = json.loads(proof.body)
        body[6] = 999
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE2" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_proof(CrlProof(1, raw, mac), ROOT)

    def test_resigned_tampered_crl_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        crl_obj = json.loads(bytes.fromhex(body[4]))
        crl_obj["sequence"] = 999
        body[4] = json.dumps(crl_obj, separators=(",", ":")).encode().hex()
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE2" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_proof(CrlProof(1, raw, mac), ROOT)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_proof(b"not json", ROOT)


if __name__ == "__main__":
    unittest.main()
