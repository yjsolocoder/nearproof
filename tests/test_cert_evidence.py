import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BoundAttestedObservation,
    CertifiedConsensusEvidence,
    Consensus,
    RangeDecision,
    VerifierTrust,
    attest_observation_for_point,
    audit_cert_evidence,
    cert,
    locate_cert,
    locate_cert_evidence,
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


def make_evidence():
    return locate_cert_evidence(
        triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT
    )


def outer_of(evidence):
    return json.loads(evidence.to_bytes())


def body_of(evidence):
    return json.loads(bytes.fromhex(outer_of(evidence)["body"]))


class CertifiedConsensusEvidenceContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        first = make_evidence()
        second = CertifiedConsensusEvidence(1, first.body, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.mac = b"\x00" * 32

    def test_positional_field_order(self):
        evidence = CertifiedConsensusEvidence(1, b"[]", b"\x01" * 32)
        self.assertEqual(
            (evidence.version, evidence.body, evidence.mac),
            (1, b"[]", b"\x01" * 32),
        )

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence(bad, b"[]", b"\x00" * 32)

    def test_body_must_be_bytes(self):
        for bad in ("[]", bytearray(b"[]"), None, 0, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence(1, bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"\x00" * 31, b"\x00" * 33, "ab" * 32, None, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence(1, b"[]", bad)


class LocateCertEvidenceTest(unittest.TestCase):
    def test_wraps_the_locate_cert_consensus(self):
        records = triangle_records()
        trusts = triangle_trusts()
        expected = locate_cert(records, POINT, CONTEXT, trusts, ROOT)
        evidence = locate_cert_evidence(records, POINT, CONTEXT, trusts, ROOT)
        self.assertIsInstance(evidence, CertifiedConsensusEvidence)
        self.assertEqual(evidence.version, 1)
        self.assertEqual(len(evidence.mac), 32)
        point, context, raw_records, raw_trusts, raw_consensus = body_of(evidence)
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(raw_consensus, [3, 3, [], True])
        result = audit_cert_evidence(evidence, ROOT)
        self.assertIsInstance(result, Consensus)
        self.assertEqual(result, expected)

    def test_body_arrays_are_id_sorted_canonical_hex(self):
        evidence = make_evidence()
        _point, _context, raw_records, raw_trusts, _consensus = body_of(evidence)
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
        # The hex strings decode to the exact participating objects.
        for blob, source in zip(raw_records, triangle_records()):
            self.assertEqual(
                bytes.fromhex(blob), source.to_bytes()
            )
        for blob, source in zip(raw_trusts, triangle_trusts()):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())

    def test_mac_formula(self):
        evidence = make_evidence()
        body = bytes.fromhex(outer_of(evidence)["body"])
        expected = hmac.new(ROOT, b"NPCCE1" + body, hashlib.sha256).digest()
        self.assertEqual(evidence.mac, expected)
        self.assertNotEqual(
            evidence.mac,
            hmac.new(OTHER_ROOT, b"NPCCE1" + body, hashlib.sha256).digest(),
        )

    def test_result_is_independent_of_input_order(self):
        evidence = make_evidence()
        shuffled_records = [record("c"), record("a"), record("b")]
        shuffled_trusts = [trust("b"), trust("c"), trust("a")]
        again = locate_cert_evidence(
            shuffled_records, POINT, CONTEXT, shuffled_trusts, ROOT
        )
        self.assertEqual(again, evidence)

    def test_accepts_mixed_objects_bytes_and_generators(self):
        records = triangle_records()
        trusts = triangle_trusts()
        evidence = locate_cert_evidence(
            (r.to_bytes() if i % 2 else r for i, r in enumerate(records)),
            POINT,
            CONTEXT,
            (t.to_bytes() if i % 2 else t for i, t in enumerate(trusts)),
            ROOT,
        )
        self.assertEqual(evidence, make_evidence())

    def test_rejection_is_recorded(self):
        records = triangle_records() + [record("d")]
        trusts = triangle_trusts() + [trust("d")]
        evidence = locate_cert_evidence(records, POINT, CONTEXT, trusts, ROOT)
        _p, _c, _r, _t, raw_consensus = body_of(evidence)
        self.assertEqual(raw_consensus, [4, 3, ["d"], True])
        result = audit_cert_evidence(evidence, ROOT)
        self.assertEqual(
            result,
            Consensus(total=4, support=3, rejected=("d",), accepted=True),
        )

    def test_unsuccessful_consensus_is_recorded(self):
        # Bounds of 1.0 cover only the verifier at the origin: support is 1,
        # below the fixed quorum of 3, and that is carried, not raised.
        records = triangle_records(upper_bound=1.0)
        evidence = locate_cert_evidence(
            records, POINT, CONTEXT, triangle_trusts(), ROOT
        )
        _p, _c, _r, _t, raw_consensus = body_of(evidence)
        self.assertEqual(raw_consensus, [3, 1, ["a", "b"], False])

    def test_locate_cert_failures_propagate(self):
        records = triangle_records()
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, POINT, CONTEXT, trusts[:2], ROOT)
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, POINT, CONTEXT,
                                 trusts + [trusts[0]], ROOT)
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, (1.0, 0.0), CONTEXT, trusts, ROOT)
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, POINT, "room-8", trusts, ROOT)
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, POINT, CONTEXT, [42], ROOT)
        with self.assertRaises(ValueError):
            locate_cert_evidence([42], POINT, CONTEXT, trusts, ROOT)

    def test_root_contract_matches_locate_cert(self):
        records = triangle_records()
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, POINT, CONTEXT, trusts, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                locate_cert_evidence(records, POINT, CONTEXT, trusts, bad)
        with self.assertRaises(ValueError):
            locate_cert_evidence(records, POINT, CONTEXT, trusts, OTHER_ROOT)


class CertifiedConsensusEvidenceEncodingTest(unittest.TestCase):
    def test_to_bytes_outer_shape(self):
        evidence = make_evidence()
        obj = outer_of(evidence)
        self.assertEqual(list(obj), ["version", "body", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertIsInstance(obj["body"], str)
        self.assertIsInstance(obj["mac"], str)
        self.assertEqual(obj["body"], evidence.body.hex())
        self.assertEqual(obj["mac"], evidence.mac.hex())
        self.assertEqual(
            evidence.to_bytes(),
            json.dumps(
                {
                    "version": 1,
                    "body": evidence.body.hex(),
                    "mac": evidence.mac.hex(),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def test_body_is_compact_json_array_in_field_order(self):
        evidence = make_evidence()
        raw = evidence.body
        # No whitespace anywhere.
        self.assertNotIn(b" ", raw)
        decoded = json.loads(raw)
        self.assertIsInstance(decoded, list)
        self.assertEqual(len(decoded), 5)
        point, context, records_, trusts_, consensus = decoded
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertIsInstance(records_, list)
        self.assertIsInstance(trusts_, list)
        self.assertEqual(consensus, [3, 3, [], True])

    def test_round_trip(self):
        evidence = make_evidence()
        self.assertEqual(
            CertifiedConsensusEvidence.from_bytes(evidence.to_bytes()), evidence
        )

    def test_from_bytes_rejects_non_bytes(self):
        evidence = make_evidence()
        for bad in (evidence.to_bytes().decode("utf-8"), None, 42, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence.from_bytes(bad)

    def test_from_bytes_rejects_outer_key_violations(self):
        good = outer_of(make_evidence())
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
                CertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_bad_hex_and_mac_length(self):
        good = outer_of(make_evidence())
        blobs = [
            json.dumps({"version": 1, "body": "zz", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"].upper(),
                        "mac": good["mac"]}, separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"], "mac": "0"},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"],
                        "mac": "ab" + good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"],
                        "mac": good["mac"][:-2]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "body": good["body"],
                        "mac": good["mac"].upper()},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                CertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_outer(self):
        data = make_evidence().to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json"):
            with self.assertRaises(ValueError, msg=blob):
                CertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_malformed_bodies(self):
        good = outer_of(make_evidence())

        def with_body(body):
            return json.dumps(
                {"version": 1, "body": body.hex(), "mac": good["mac"]},
                separators=(",", ":"),
            ).encode()

        bodies = [
            json.dumps([[0.0], CONTEXT, [], [], [3, 3, [], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, True], CONTEXT, [], [], [3, 3, [], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, float("nan")], CONTEXT, [], [],
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], "", [], [], [3, 3, [], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], 7, [], [], [3, 3, [], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, ["zz"], ["zz"],
                        [3, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        [3, 3, [], True, 1]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        [3, 3, ["b", "a"], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        [3.0, 3, [], True]], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], [3, 3, [], 1]],
                       separators=(",", ":")).encode(),
        ]
        for body in bodies:
            with self.assertRaises(ValueError, msg=body):
                CertifiedConsensusEvidence.from_bytes(with_body(body))

    def test_from_bytes_rejects_non_canonical_inner_body(self):
        good = outer_of(make_evidence())
        body = json.loads(bytes.fromhex(good["body"]))
        raw = (json.dumps(body, separators=(",", ":")) + " ").encode()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": good["mac"]},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_misaligned_record_and_trust_ids(self):
        good = outer_of(make_evidence())
        body = json.loads(bytes.fromhex(good["body"]))
        body[3].reverse()
        raw = json.dumps(body, separators=(",", ":")).encode()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": good["mac"]},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(blob)

    def test_empty_arrays_parse_but_cannot_audit(self):
        # The body contract only demands id-ordered unique correspondence;
        # emptiness itself is for locate_cert (rerun during audit) to reject,
        # even when the body carries a valid root MAC.
        body = json.dumps(
            [[0.0, 0.0], CONTEXT, [], [], [0, 0, [], False]],
            separators=(",", ":"),
        ).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + body, hashlib.sha256).digest()
        blob = json.dumps(
            {"version": 1, "body": body.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        decoded = CertifiedConsensusEvidence.from_bytes(blob)
        self.assertEqual(decoded.body, body)
        with self.assertRaises(ValueError):
            audit_cert_evidence(blob, ROOT)

    def test_from_bytes_does_not_verify_mac(self):
        good = outer_of(make_evidence())
        forged = json.dumps(
            {"version": 1, "body": good["body"], "mac": "00" * 32},
            separators=(",", ":"),
        ).encode()
        decoded = CertifiedConsensusEvidence.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class AuditCertEvidenceTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        records = triangle_records()
        trusts = triangle_trusts()
        expected = locate_cert(records, POINT, CONTEXT, trusts, ROOT)
        evidence = locate_cert_evidence(records, POINT, CONTEXT, trusts, ROOT)
        self.assertEqual(audit_cert_evidence(evidence, ROOT), expected)
        self.assertEqual(
            audit_cert_evidence(evidence.to_bytes(), ROOT), expected
        )

    def test_wrong_root_rejected(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence(evidence, OTHER_ROOT)

    def test_root_shape_contract(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence(evidence, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_cert_evidence(evidence, bad)

    def test_bad_x_type_rejected(self):
        for bad in ("x", 123, None, {}, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence(bad, ROOT)

    def test_tampered_mac_rejected(self):
        evidence = make_evidence()
        tampered = dataclasses.replace(
            evidence, mac=bytes(a ^ 1 for a in evidence.mac)
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence(tampered, ROOT)

    def test_resigned_consensus_mismatch_rejected(self):
        # An attacker who knows the root rewrites the consensus and re-signs:
        # the MAC checks out, but rerunning locate_cert disagrees.
        evidence = make_evidence()
        outer = outer_of(evidence)
        body = json.loads(bytes.fromhex(outer["body"]))
        body[4][1] = 2
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + raw, hashlib.sha256).digest()
        forged = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_cert_evidence(forged, ROOT)

    def test_resigned_tampered_point_rejected(self):
        evidence = make_evidence()
        outer = outer_of(evidence)
        body = json.loads(bytes.fromhex(outer["body"]))
        body[0] = [1.0, 0.0]
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + raw, hashlib.sha256).digest()
        forged = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_cert_evidence(forged, ROOT)

    def test_resigned_swapped_trusts_rejected(self):
        evidence = make_evidence()
        outer = outer_of(evidence)
        body = json.loads(bytes.fromhex(outer["body"]))
        body[3].reverse()
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + raw, hashlib.sha256).digest()
        forged = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_cert_evidence(forged, ROOT)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_cert_evidence(b"not json", ROOT)


if __name__ == "__main__":
    unittest.main()
