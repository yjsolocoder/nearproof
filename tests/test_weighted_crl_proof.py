import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BoundAttestedObservation,
    Consensus,
    ConsensusPolicy,
    CrlProof,
    CrlProofAuditor,
    CrlState,
    RangeDecision,
    VerifierTrust,
    WeightedConsensus,
    WeightedCrlProof,
    WeightedCrlProofAuditor,
    _WEIGHTED_CRL_PROOF_PREFIX,
    _crl_state_mac,
    _crl_state_payload,
    _weighted_crl_proof_mac,
    attest_observation_for_point,
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
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0), "d": (50.0, 50.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"

# Distinct positive weights; a/b/c support POINT, d is far away.
WEIGHTS = {"a": 1, "b": 2, "c": 4, "d": 8}
THRESHOLD = 7
POLICY = ConsensusPolicy(WEIGHTS, THRESHOLD)


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


def records_for(ids, upper_bound=5.0):
    return [record(ident, upper_bound) for ident in ids]


def trusts_for(ids):
    return [trust(ident) for ident in ids]


TRIANGLE_IDS = ("a", "b", "c")
ALL_IDS = ("a", "b", "c", "d")


def triangle_records(upper_bound=5.0):
    return records_for(TRIANGLE_IDS, upper_bound)


def triangle_trusts():
    return trusts_for(TRIANGLE_IDS)


def triangle_policy():
    return ConsensusPolicy({ident: WEIGHTS[ident] for ident in TRIANGLE_IDS}, 7)


def empty_crl(*, sequence=1, issued_at=0.0, root=ROOT):
    return make_crl([], sequence, issued_at, root)


def make_proof(crl=None, *, now=10.0, min=0, ids=ALL_IDS,
               weights=None, threshold=THRESHOLD):
    if weights is None:
        weights = {ident: WEIGHTS[ident] for ident in ids}
    policy = ConsensusPolicy(weights, threshold)
    return prove_weighted_crl(
        records_for(ids), POINT, CONTEXT, trusts_for(ids), ROOT,
        crl if crl is not None else empty_crl(), policy, now=now, min=min,
    )


def outer_of(proof):
    return json.loads(proof.to_bytes())


def body_of(proof):
    return json.loads(bytes.fromhex(outer_of(proof)["body"]))


class WeightedCrlProofContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        first = make_proof()
        second = WeightedCrlProof(1, first.body, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.mac = b"\x00" * 32

    def test_positional_field_order(self):
        proof = WeightedCrlProof(1, b"[]", b"\x01" * 32)
        self.assertEqual(
            (proof.version, proof.body, proof.mac),
            (1, b"[]", b"\x01" * 32),
        )

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCrlProof(bad, b"[]", b"\x00" * 32)

    def test_body_must_be_bytes(self):
        for bad in ("[]", bytearray(b"[]"), None, 0, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCrlProof(1, bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"\x00" * 31, b"\x00" * 33, "ab" * 32, None, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCrlProof(1, b"[]", bad)


class ProveWeightedCrlTest(unittest.TestCase):
    def test_wraps_the_weighted_snapshot_consensus(self):
        crl = empty_crl(sequence=4)
        recs = records_for(ALL_IDS)
        trusts = trusts_for(ALL_IDS)
        proof = prove_weighted_crl(
            recs, POINT, CONTEXT, trusts, ROOT, crl, POLICY, now=10.0, min=2
        )
        self.assertIsInstance(proof, WeightedCrlProof)
        self.assertEqual(proof.version, 1)
        self.assertEqual(len(proof.mac), 32)
        body = body_of(proof)
        (point, context, _r, _t, _c, now, minimum, weights, threshold,
         raw_consensus) = body
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(now, 10.0)
        self.assertEqual(minimum, 2)
        self.assertEqual(weights, {"a": 1, "b": 2, "c": 4, "d": 8})
        self.assertEqual(threshold, 7)
        # a+b+c support (weight 7), d rejected (weight 8).
        self.assertEqual(raw_consensus, [15, 7, ["d"], True])
        self.assertEqual(
            audit_weighted_crl_proof(proof, ROOT),
            WeightedConsensus(15, 7, ("d",), True),
        )

    def test_body_arrays_are_id_sorted_canonical_hex(self):
        proof = make_proof()
        (_p, _c, raw_records, raw_trusts, raw_crl, _n, _m, weights,
         _threshold, _consensus) = body_of(proof)
        record_ids = [
            BoundAttestedObservation.from_bytes(bytes.fromhex(blob)).id
            for blob in raw_records
        ]
        trust_ids = [
            VerifierTrust.from_bytes(bytes.fromhex(blob)).id
            for blob in raw_trusts
        ]
        self.assertEqual(record_ids, list(ALL_IDS))
        self.assertEqual(trust_ids, list(ALL_IDS))
        self.assertEqual(list(weights), list(ALL_IDS))
        for blob, source in zip(raw_records, records_for(ALL_IDS)):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        for blob, source in zip(raw_trusts, trusts_for(ALL_IDS)):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        self.assertEqual(bytes.fromhex(raw_crl), empty_crl().to_bytes())

    def test_body_is_ten_field_array(self):
        proof = make_proof()
        raw = proof.body
        self.assertNotIn(b" ", raw)
        decoded = json.loads(raw)
        self.assertIsInstance(decoded, list)
        self.assertEqual(len(decoded), 10)

    def test_mac_formula(self):
        proof = make_proof()
        body = bytes.fromhex(outer_of(proof)["body"])
        self.assertEqual(
            proof.mac,
            hmac.new(ROOT, b"NPWCP1" + body, hashlib.sha256).digest(),
        )
        self.assertEqual(_WEIGHTED_CRL_PROOF_PREFIX, b"NPWCP1")
        self.assertNotEqual(
            proof.mac,
            hmac.new(OTHER_ROOT, b"NPWCP1" + body, hashlib.sha256).digest(),
        )
        # Domain-separated from the count-based CRL proof prefix.
        self.assertNotEqual(
            proof.mac,
            hmac.new(ROOT, b"NPCCE2" + body, hashlib.sha256).digest(),
        )

    def test_no_delimiter_or_length_prefix(self):
        proof = make_proof()
        body = proof.body
        forged = hmac.new(
            ROOT, b"NPWCP1" + str(len(body)).encode() + body, hashlib.sha256
        ).digest()
        self.assertNotEqual(proof.mac, forged)

    def test_result_is_independent_of_input_order(self):
        crl = empty_crl()
        proof = make_proof(crl)
        shuffled_records = list(reversed(records_for(ALL_IDS)))
        shuffled_trusts = list(reversed(trusts_for(ALL_IDS)))
        again = prove_weighted_crl(
            shuffled_records, POINT, CONTEXT, shuffled_trusts, ROOT, crl,
            POLICY, now=10.0,
        )
        self.assertEqual(again, proof)

    def test_accepts_mixed_objects_bytes_and_generators(self):
        recs = records_for(ALL_IDS)
        trusts = trusts_for(ALL_IDS)
        crl = empty_crl()
        proof = prove_weighted_crl(
            (r.to_bytes() if i % 2 else r for i, r in enumerate(recs)),
            POINT,
            CONTEXT,
            (t.to_bytes() if i % 2 else t for i, t in enumerate(trusts)),
            ROOT,
            crl.to_bytes(),
            POLICY,
            now=0,
        )
        self.assertEqual(
            proof,
            prove_weighted_crl(recs, POINT, CONTEXT, trusts, ROOT, crl,
                               POLICY, now=0.0),
        )

    def test_rejection_is_recorded_and_can_fail_threshold(self):
        crl = empty_crl()
        # Only a(1)+b(2)+c(4)=7 of 15 support; threshold 8 -> not accepted.
        proof = make_proof(crl, threshold=8)
        self.assertEqual(body_of(proof)[9], [15, 7, ["d"], False])
        self.assertEqual(
            audit_weighted_crl_proof(proof, ROOT),
            WeightedConsensus(15, 7, ("d",), False),
        )
        # All three triangle verifiers support with their own policy.
        tri = prove_weighted_crl(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT, crl,
            triangle_policy(), now=0.0,
        )
        self.assertEqual(body_of(tri)[9], [7, 7, [], True])

    def test_single_verifier_is_allowed(self):
        # Unlike the count-based locate_cert, the weighted tally has no
        # minimum observation count beyond the policy's id set.
        crl = empty_crl()
        policy = ConsensusPolicy({"c": 4}, 4)
        proof = prove_weighted_crl(
            records_for(("c",)), POINT, CONTEXT, trusts_for(("c",)), ROOT,
            crl, policy, now=0.0,
        )
        self.assertEqual(
            audit_weighted_crl_proof(proof, ROOT),
            WeightedConsensus(4, 4, (), True),
        )

    def test_boundary_counts_as_support(self):
        # Verifier a sits at (3, 0); a radius of exactly 3 reaches POINT on
        # the closed-disk boundary, so its weight must count.
        crl = empty_crl()
        policy = ConsensusPolicy({"a": 1}, 1)
        proof = prove_weighted_crl(
            records_for(("a",), upper_bound=3.0), POINT, CONTEXT,
            trusts_for(("a",)), ROOT, crl, policy, now=0.0,
        )
        self.assertEqual(body_of(proof)[9], [1, 1, [], True])

    def test_decision_accepted_flag_is_ignored(self):
        crl = empty_crl()
        # decision.accepted=False must not affect the weighted tally.
        recs = [
            attest_observation_for_point(
                "c", 0.0, 0.0,
                RangeDecision(sample_count=1, upper_bound=5.0, accepted=False),
                POINT, CONTEXT, 0.0, KEY_C,
            )
        ]
        policy = ConsensusPolicy({"c": 4}, 4)
        proof = prove_weighted_crl(
            recs, POINT, CONTEXT, trusts_for(("c",)), ROOT, crl, policy,
            now=0.0,
        )
        self.assertEqual(body_of(proof)[9], [4, 4, [], True])

    def test_revoked_participant_rejected(self):
        trusts = triangle_trusts()
        crl = make_crl([revoke_trust(trusts[1], ROOT)], 1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                triangle_records(), POINT, CONTEXT, trusts, ROOT, crl,
                triangle_policy(), now=0.0,
            )

    def test_unrelated_snapshot_entry_is_ignored(self):
        foreign = cert("zzz", 50.0, 50.0, b"\x77" * 32, ROOT)
        crl = make_crl([revoke_trust(foreign, ROOT)], 1, 0.0, ROOT)
        proof = prove_weighted_crl(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT, crl,
            triangle_policy(), now=0.0,
        )
        self.assertEqual(
            audit_weighted_crl_proof(proof, ROOT),
            WeightedConsensus(7, 7, (), True),
        )

    def test_future_snapshot_and_low_sequence_rejected(self):
        with self.assertRaises(ValueError):
            make_proof(empty_crl(issued_at=11.0), now=10.0)
        with self.assertRaises(ValueError):
            make_proof(empty_crl(sequence=3), now=10.0, min=4)

    def test_now_is_required_and_keyword_only(self):
        crl = empty_crl()
        with self.assertRaises(TypeError):
            prove_weighted_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                crl, triangle_policy(),
            )
        with self.assertRaises(TypeError):
            prove_weighted_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                crl, triangle_policy(), 10.0,
            )

    def test_now_and_min_contracts(self):
        crl = empty_crl()
        for bad_now in ("10", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                prove_weighted_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(),
                    ROOT, crl, triangle_policy(), now=bad_now,
                )
        for bad_min in (True, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                prove_weighted_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(),
                    ROOT, crl, triangle_policy(), now=0.0, min=bad_min,
                )

    def test_policy_contract(self):
        crl = empty_crl()
        recs = triangle_records()
        trusts = triangle_trusts()
        for bad in (None, 7, {"a": 1}, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                prove_weighted_crl(
                    recs, POINT, CONTEXT, trusts, ROOT, crl, bad, now=0.0
                )
        # Weight ids must align with the record ids exactly.
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                recs, POINT, CONTEXT, trusts, ROOT, crl,
                ConsensusPolicy({"a": 1, "b": 2, "x": 4}, 7), now=0.0,
            )
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                recs, POINT, CONTEXT, trusts, ROOT, crl,
                ConsensusPolicy({"a": 1, "b": 2}, 3), now=0.0,
            )

    def test_root_contract(self):
        crl = empty_crl()
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), b"",
                crl, triangle_policy(), now=0.0,
            )
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                prove_weighted_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(),
                    bad, crl, triangle_policy(), now=0.0,
                )

    def test_bad_crl_argument(self):
        for bad in (None, 42, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                prove_weighted_crl(
                    triangle_records(), POINT, CONTEXT, triangle_trusts(),
                    ROOT, bad, triangle_policy(), now=0.0,
                )


class WeightedCrlProofEncodingTest(unittest.TestCase):
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
        self.assertEqual(WeightedCrlProof.from_bytes(proof.to_bytes()), proof)

    def test_from_bytes_rejects_non_bytes(self):
        proof = make_proof()
        for bad in (proof.to_bytes().decode("utf-8"), None, 42, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCrlProof.from_bytes(bad)

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
                WeightedCrlProof.from_bytes(blob)

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
                WeightedCrlProof.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_layers(self):
        data = make_proof().to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json"):
            with self.assertRaises(ValueError, msg=blob):
                WeightedCrlProof.from_bytes(blob)
        good = outer_of(make_proof())
        body = json.loads(bytes.fromhex(good["body"]))
        raw = (json.dumps(body, separators=(",", ":")) + " ").encode()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": good["mac"]},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            WeightedCrlProof.from_bytes(blob)

    def test_from_bytes_rejects_malformed_bodies(self):
        good = outer_of(make_proof())
        crl_hex = empty_crl().to_bytes().hex()
        consensus = [15, 7, ["d"], True]

        def with_body(body):
            return json.dumps(
                {"version": 1, "body": body.hex(), "mac": good["mac"]},
                separators=(",", ":"),
            ).encode()

        weights = {"a": 1, "b": 2, "c": 4, "d": 8}
        heads = [[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0]
        tails = [weights, 7, consensus]
        bodies = [
            # Nine fields instead of ten.
            json.dumps(heads + [consensus], separators=(",", ":")).encode(),
            # Eleven fields.
            json.dumps(heads + [weights, 7, consensus, 1],
                       separators=(",", ":")).encode(),
            # Bad point shapes.
            json.dumps([[0.0], CONTEXT, [], [], crl_hex, 0.0, 0] + tails,
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, True], CONTEXT, [], [], crl_hex, 0.0, 0] + tails,
                       separators=(",", ":")).encode(),
            # Bad context.
            json.dumps([[0.0, 0.0], 7, [], [], crl_hex, 0.0, 0] + tails,
                       separators=(",", ":")).encode(),
            # Bad crl hex / now / min.
            json.dumps([[0.0, 0.0], CONTEXT, [], [], "not hex", 0.0, 0]
                       + tails, separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, "now", 0]
                       + tails, separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0.0]
                       + tails, separators=(",", ":")).encode(),
            # Weights not an object / wrong id set / out of order / bad value.
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        [], 7, consensus], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        {"a": 1, "b": 2, "c": 4}, 7, consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        {"a": 1, "b": 2, "x": 4, "d": 8}, 7, consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        {"a": 0, "b": 2, "c": 4, "d": 8}, 7, consensus],
                       separators=(",", ":")).encode(),
            # Threshold above total weight / non-positive / float.
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        weights, 16, consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        weights, 0, consensus],
                       separators=(",", ":")).encode(),
            # Unsorted / duplicated rejected ids; accepted not a bool.
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        weights, 7, [15, 7, ["b", "a"], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        weights, 7, [15, 7, ["a", "a"], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], crl_hex, 0.0, 0,
                        weights, 7, [15, 7, ["d"], 1]],
                       separators=(",", ":")).encode(),
        ]
        for body in bodies:
            with self.assertRaises(ValueError, msg=body):
                WeightedCrlProof.from_bytes(with_body(body))

    def test_from_bytes_rejects_records_not_sorted_or_unaligned(self):
        proof = make_proof()
        good = outer_of(proof)

        def with_body(body):
            return json.dumps(
                {"version": 1, "body": body.hex(), "mac": good["mac"]},
                separators=(",", ":"),
            ).encode()

        body = json.loads(bytes.fromhex(good["body"]))
        # Records sorted a,b,c,d; swap the first two record hex strings.
        reordered = list(body)
        reordered[2] = list(body[2])
        reordered[2][0], reordered[2][1] = body[2][1], body[2][0]
        with self.assertRaises(ValueError):
            WeightedCrlProof.from_bytes(
                with_body(json.dumps(reordered, separators=(",", ":")).encode())
            )
        # Trust misaligned against the record ids.
        misaligned = list(body)
        misaligned[3] = list(body[3])
        misaligned[3][0], misaligned[3][1] = body[3][1], body[3][0]
        with self.assertRaises(ValueError):
            WeightedCrlProof.from_bytes(
                with_body(json.dumps(misaligned, separators=(",", ":")).encode())
            )

    def test_to_bytes_rejects_non_canonical_body_without_rewriting(self):
        proof = WeightedCrlProof(1, b" []", b"\x00" * 32)
        with self.assertRaises(ValueError):
            proof.to_bytes()
        self.assertEqual(proof.body, b" []")

    def test_from_bytes_does_not_verify_mac(self):
        good = outer_of(make_proof())
        forged = json.dumps(
            {"version": 1, "body": good["body"], "mac": "00" * 32},
            separators=(",", ":"),
        ).encode()
        decoded = WeightedCrlProof.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class AuditWeightedCrlProofTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        proof = make_proof()
        expected = WeightedConsensus(15, 7, ("d",), True)
        self.assertEqual(audit_weighted_crl_proof(proof, ROOT), expected)
        self.assertEqual(audit_weighted_crl_proof(proof.to_bytes(), ROOT),
                         expected)

    def test_wrong_root_rejected(self):
        proof = make_proof()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(proof, OTHER_ROOT)

    def test_root_shape_contract(self):
        proof = make_proof()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(proof, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_weighted_crl_proof(proof, bad)

    def test_bad_x_type_rejected(self):
        for bad in ("x", 123, None, {}, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_weighted_crl_proof(bad, ROOT)

    def test_tampered_mac_rejected(self):
        proof = make_proof()
        tampered = dataclasses.replace(
            proof, mac=bytes(a ^ 1 for a in proof.mac)
        )
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(tampered, ROOT)

    def test_resigned_consensus_mismatch_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        body[9][1] = 2
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_weights_tamper_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        # Inflate c's weight; threshold still satisfiable but the carried
        # total/support no longer matches the recomputed tally.
        body[7]["c"] = 40
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_threshold_tamper_changes_acceptance(self):
        proof = make_proof(threshold=8)  # genuinely not accepted (7 < 8)
        body = json.loads(proof.body)
        self.assertEqual(body[9][3], False)
        # Lower the carried threshold without touching the carried verdict:
        # the replay recomputes accepted=True and must disagree.
        body[8] = 7
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_min_tamper_rejected(self):
        proof = make_proof(empty_crl(sequence=5), min=5)
        body = json.loads(proof.body)
        body[6] = 999
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_tampered_crl_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        crl_obj = json.loads(bytes.fromhex(body[4]))
        crl_obj["sequence"] = 999
        body[4] = json.dumps(crl_obj, separators=(",", ":")).encode().hex()
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_revocation_injection_rejected(self):
        # Take a valid empty-CRL proof and resign a body whose CRL actually
        # revokes a participating certificate: the list entry carries a
        # valid root MAC, but the replayed weighted run must reject it.
        trusts = triangle_trusts()
        recs = triangle_records()
        clean = make_crl([], 1, 0.0, ROOT)
        clean_proof = prove_weighted_crl(
            recs, POINT, CONTEXT, trusts, ROOT, clean, triangle_policy(),
            now=0.0,
        )
        revoked_crl = make_crl([revoke_trust(trusts[1], ROOT)], 1, 0.0, ROOT)
        body = json.loads(clean_proof.body)
        body[4] = revoked_crl.to_bytes().hex()
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(b"not json", ROOT)


class WeightedCrlProofAuditorInitTest(unittest.TestCase):
    def test_root_contract(self):
        with self.assertRaises(ValueError):
            WeightedCrlProofAuditor(b"")
        for bad in (bytearray(ROOT), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                WeightedCrlProofAuditor(bad)

    def test_checkpoint_is_keyword_only(self):
        state = _make_state(1, empty_crl(sequence=1))
        with self.assertRaises(TypeError):
            WeightedCrlProofAuditor(ROOT, state)
        self.assertIsNone(WeightedCrlProofAuditor(ROOT).checkpoint)
        self.assertIs(
            WeightedCrlProofAuditor(ROOT, checkpoint=None).checkpoint, None
        )

    def test_checkpoint_must_be_state_bytes_or_none(self):
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCrlProofAuditor(ROOT, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            WeightedCrlProofAuditor(ROOT, checkpoint=b"not json")

    def test_checkpoint_mac_verified(self):
        crl = empty_crl(sequence=1)
        with self.assertRaises(ValueError):
            WeightedCrlProofAuditor(
                ROOT, checkpoint=_make_state(1, crl, mac=b"\x00" * 32)
            )
        with self.assertRaises(ValueError):
            WeightedCrlProofAuditor(
                ROOT, checkpoint=_make_state(1, crl, root=OTHER_ROOT)
            )
        state = _make_state(1, crl)
        self.assertIs(
            WeightedCrlProofAuditor(ROOT, checkpoint=state).checkpoint, state
        )
        restored = WeightedCrlProofAuditor(
            ROOT, checkpoint=state.to_bytes()
        ).checkpoint
        self.assertEqual(restored, state)

    def test_checkpoint_property_is_read_only(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = _make_state(1, empty_crl(sequence=1))


def _state_mac(root, state):
    return _crl_state_mac(root, _crl_state_payload(state))


def _make_state(sequence, crl, *, root=ROOT, mac=None):
    if mac is None:
        placeholder = CrlState(
            1, sequence, hashlib.sha256(crl.to_bytes()).digest(), b"\x00" * 32
        )
        mac = _state_mac(root, placeholder)
    return CrlState(1, sequence, hashlib.sha256(crl.to_bytes()).digest(), mac)


class WeightedCrlProofAuditorGatingTest(unittest.TestCase):
    def setUp(self):
        self.crl1 = empty_crl(sequence=1)
        self.crl2 = make_crl([], 2, 5.0, ROOT)
        self.crl3 = make_crl([], 3, 9.0, ROOT)
        self.crl1_other = make_crl([], 1, 9.0, ROOT)
        self.p1 = make_proof(self.crl1)
        self.p2 = make_proof(self.crl2)
        self.p3 = make_proof(self.crl3)
        self.p1_other = make_proof(self.crl1_other)
        self.expected = WeightedConsensus(15, 7, ("d",), True)

    def test_first_audit_advances_from_empty(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        self.assertEqual(auditor.audit(self.p1), self.expected)
        self.assertEqual(auditor.checkpoint, _make_state(1, self.crl1))
        auditor2 = WeightedCrlProofAuditor(ROOT)
        self.assertEqual(auditor2.audit(self.p1.to_bytes()), self.expected)
        self.assertEqual(auditor2.checkpoint, _make_state(1, self.crl1))

    def test_higher_sequence_advances(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        auditor.audit(self.p2)
        self.assertEqual(auditor.checkpoint, _make_state(2, self.crl2))
        auditor.audit(self.p3)
        self.assertEqual(auditor.checkpoint, _make_state(3, self.crl3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        with self.assertRaises(ValueError):
            auditor.audit(self.p1)
        self.assertEqual(auditor.checkpoint, _make_state(2, self.crl2))

    def test_same_sequence_same_digest_is_a_replay(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        for _ in range(3):
            self.assertEqual(auditor.audit(self.p1), self.expected)
            self.assertEqual(auditor.audit(self.p1.to_bytes()), self.expected)
        self.assertEqual(auditor.checkpoint, _make_state(1, self.crl1))

    def test_same_sequence_different_digest_rejected(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        self.assertNotEqual(
            hashlib.sha256(self.crl1.to_bytes()).digest(),
            hashlib.sha256(self.crl1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.p1_other)
        self.assertEqual(auditor.checkpoint, _make_state(1, self.crl1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        body = self.p3.body
        other_root_proof = WeightedCrlProof(
            1, body, _weighted_crl_proof_mac(OTHER_ROOT, body)
        )
        with self.assertRaises(ValueError):
            auditor.audit(other_root_proof)
        tampered = dataclasses.replace(
            self.p2, mac=bytes(b ^ 1 for b in self.p2.mac)
        )
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        for bad in (None, 42, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertEqual(auditor.checkpoint, _make_state(1, self.crl1))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        saved = auditor.checkpoint.to_bytes()
        restarted = WeightedCrlProofAuditor(ROOT, checkpoint=saved)
        self.assertEqual(restarted.audit(self.p2), self.expected)
        with self.assertRaises(ValueError):
            restarted.audit(self.p1)
        restarted.audit(self.p3)
        self.assertEqual(restarted.checkpoint, _make_state(3, self.crl3))

    def test_checkpoint_interoperates_with_crl_proof_auditor(self):
        # The weighted auditor's checkpoint is a plain CrlState accepted by
        # the count-based auditor and vice versa, since both gate on the
        # same CRL sequence/digest frontier.
        weighted = WeightedCrlProofAuditor(ROOT)
        weighted.audit(self.p2)
        saved = weighted.checkpoint.to_bytes()
        plain = CrlProofAuditor(ROOT, checkpoint=saved)
        self.assertEqual(plain.checkpoint, weighted.checkpoint)
        with self.assertRaises(ValueError):
            plain.audit(prove_crl(
                triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
                self.crl1, now=10.0,
            ))
        plain_p3 = prove_crl(
            triangle_records(), POINT, CONTEXT, triangle_trusts(), ROOT,
            self.crl3, now=10.0,
        )
        self.assertEqual(
            plain.audit(plain_p3),
            Consensus(3, 3, (), True),
        )
        # Hand the advanced frontier back to the weighted auditor: the old
        # proof is a rollback, seq-3 stays a valid replay.
        advanced = CrlProofAuditor(
            ROOT, checkpoint=plain.checkpoint.to_bytes()
        )
        weighted2 = WeightedCrlProofAuditor(
            ROOT, checkpoint=advanced.checkpoint.to_bytes()
        )
        with self.assertRaises(ValueError):
            weighted2.audit(self.p2)
        self.assertEqual(weighted2.audit(self.p3), self.expected)
        self.assertEqual(weighted2.checkpoint, _make_state(3, self.crl3))


class WeightedCrlProofAuditorConcurrencyTest(unittest.TestCase):
    def test_concurrent_audits_never_roll_back(self):
        crl1 = empty_crl(sequence=1)
        crl2 = make_crl([], 2, 5.0, ROOT)
        p1 = make_proof(crl1)
        p2 = make_proof(crl2)
        auditor = WeightedCrlProofAuditor(ROOT)
        errors = []

        def worker(item):
            try:
                auditor.audit(item)
            except ValueError:
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [p1, p1.to_bytes(), p2, p1, p2.to_bytes(), p1] * 8
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint, _make_state(2, crl2))

    def test_advance_wins_against_rejected_rollback(self):
        crl1 = empty_crl(sequence=1)
        crl2 = make_crl([], 2, 5.0, ROOT)
        p1 = make_proof(crl1)
        p2 = make_proof(crl2)
        start = threading.Barrier(2)
        auditor = WeightedCrlProofAuditor(ROOT)
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
        self.assertEqual(auditor.checkpoint, _make_state(2, crl2))


if __name__ == "__main__":
    unittest.main()
