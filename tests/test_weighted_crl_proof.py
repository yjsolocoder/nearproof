import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BoundAttestedObservation,
    ConsensusPolicy,
    CrlProofAuditor,
    CrlState,
    RangeDecision,
    VerifierTrust,
    WeightedCrlProof,
    WeightedCrlProofAuditor,
    WeightedConsensus,
    _WEIGHTED_CRL_PROOF_PREFIX,
    _crl_state_mac,
    _crl_state_payload,
    attest_observation_for_point,
    audit_weighted_crl_proof,
    cert,
    make_crl,
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


def policy(weights=None, threshold=THRESHOLD):
    return ConsensusPolicy(WEIGHTS if weights is None else weights, threshold)


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


def all_records(upper_bound=5.0, **kwargs):
    return [record("a", upper_bound, **kwargs), record("b", upper_bound, **kwargs),
            record("c", upper_bound, **kwargs), record("d", upper_bound, **kwargs)]


def all_trusts():
    return [trust("a"), trust("b"), trust("c"), trust("d")]


def empty_crl(*, sequence=1, issued_at=0.0, root=ROOT):
    return make_crl([], sequence, issued_at, root)


def make_proof(crl=None, pol=None, *, now=10.0, min=0):
    return prove_weighted_crl(
        all_records(), POINT, CONTEXT, all_trusts(), ROOT,
        crl if crl is not None else empty_crl(), pol or policy(),
        now=now, min=min,
    )


def outer_of(proof):
    return json.loads(proof.to_bytes())


def body_of(proof):
    return json.loads(bytes.fromhex(outer_of(proof)["body"]))


def state_mac(root, state):
    return _crl_state_mac(root, _crl_state_payload(state))


def make_state(sequence, crl, *, root=ROOT):
    placeholder = CrlState(
        1, sequence, hashlib.sha256(crl.to_bytes()).digest(), b"\x00" * 32
    )
    return CrlState(
        1, sequence, hashlib.sha256(crl.to_bytes()).digest(),
        state_mac(root, placeholder),
    )


EXPECTED = WeightedConsensus(
    total_weight=15, support_weight=7, rejected=("d",), accepted=True
)


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
    def test_wraps_weighted_snapshot_consensus(self):
        crl = empty_crl(sequence=4)
        records = all_records()
        trusts = all_trusts()
        proof = prove_weighted_crl(
            records, POINT, CONTEXT, trusts, ROOT, crl, policy(), now=10.0, min=2
        )
        self.assertIsInstance(proof, WeightedCrlProof)
        self.assertEqual(proof.version, 1)
        self.assertEqual(len(proof.mac), 32)
        point, context, _, _, _, now, minimum, weights, threshold, raw_consensus = (
            body_of(proof)
        )
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(now, 10.0)
        self.assertEqual(minimum, 2)
        self.assertEqual(weights, WEIGHTS)
        self.assertEqual(threshold, THRESHOLD)
        self.assertEqual(raw_consensus, [15, 7, ["d"], True])
        self.assertEqual(audit_weighted_crl_proof(proof, ROOT), EXPECTED)

    def test_rejected_when_threshold_not_reached(self):
        # With upper_bound 0 only 'c' at the origin covers: weight 4 below
        # threshold 6 -> rejected; the others are reported sorted.
        pol = ConsensusPolicy({"a": 1, "b": 2, "c": 4, "d": 8}, threshold=6)
        proof = prove_weighted_crl(
            all_records(0.0), POINT, CONTEXT, all_trusts(), ROOT, empty_crl(),
            pol, now=10.0,
        )
        self.assertEqual(body_of(proof)[9], [15, 4, ["a", "b", "d"], False])
        self.assertEqual(
            audit_weighted_crl_proof(proof, ROOT),
            WeightedConsensus(15, 4, ("a", "b", "d"), False),
        )

    def test_body_arrays_are_id_sorted_canonical_hex(self):
        proof = make_proof()
        _p, _c, raw_records, raw_trusts, raw_crl, _n, _m, _w, _t, _cons = (
            body_of(proof)
        )
        record_ids = [
            BoundAttestedObservation.from_bytes(bytes.fromhex(blob)).id
            for blob in raw_records
        ]
        trust_ids = [
            VerifierTrust.from_bytes(bytes.fromhex(blob)).id
            for blob in raw_trusts
        ]
        self.assertEqual(record_ids, ["a", "b", "c", "d"])
        self.assertEqual(trust_ids, ["a", "b", "c", "d"])
        for blob, source in zip(raw_records, all_records()):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        for blob, source in zip(raw_trusts, all_trusts()):
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
            hmac.new(ROOT, _WEIGHTED_CRL_PROOF_PREFIX + body,
                     hashlib.sha256).digest(),
        )
        self.assertEqual(
            proof.mac,
            hmac.new(ROOT, b"NPWCP1" + body, hashlib.sha256).digest(),
        )
        self.assertNotEqual(
            proof.mac,
            hmac.new(OTHER_ROOT, b"NPWCP1" + body, hashlib.sha256).digest(),
        )

    def test_no_delimiter_or_length_prefix(self):
        proof = make_proof()
        body = proof.body
        forged = hmac.new(
            ROOT, b"NPWCP1" + str(len(body)).encode() + body, hashlib.sha256
        ).digest()
        self.assertNotEqual(proof.mac, forged)

    def test_domain_separated_from_plain_crl_proof(self):
        # The same body bytes under the CrlProof prefix must not authenticate.
        proof = make_proof()
        forged = hmac.new(ROOT, b"NPCCE2" + proof.body,
                          hashlib.sha256).digest()
        self.assertNotEqual(proof.mac, forged)

    def test_boundary_counts_as_support(self):
        # 'a' sits at (3, 0): distance exactly 5.0 from the origin, so with
        # upper_bound 5.0 its closed disk covers the boundary point.
        records = [record("a")]
        trusts = [trust("a")]
        pol = ConsensusPolicy({"a": 1}, threshold=1)
        proof = prove_weighted_crl(
            records, POINT, CONTEXT, trusts, ROOT, empty_crl(), pol, now=0.0
        )
        self.assertEqual(body_of(proof)[9], [1, 1, [], True])

    def test_single_verifier_may_participate(self):
        # No fixed quorum: one verifier can accept on its own weight.
        records = [record("c")]
        trusts = [trust("c")]
        pol = ConsensusPolicy({"c": 4}, threshold=4)
        proof = prove_weighted_crl(
            records, POINT, CONTEXT, trusts, ROOT, empty_crl(), pol, now=0.0
        )
        self.assertEqual(
            audit_weighted_crl_proof(proof, ROOT),
            WeightedConsensus(4, 4, (), True),
        )

    def test_result_is_independent_of_input_order(self):
        crl = empty_crl()
        proof = make_proof(crl)
        shuffled_records = [record("d"), record("b"), record("a"), record("c")]
        trusts = all_trusts()
        shuffled_trusts = [trusts[3], trusts[1], trusts[0], trusts[2]]
        again = prove_weighted_crl(
            shuffled_records, POINT, CONTEXT, shuffled_trusts, ROOT, crl,
            policy(), now=10.0,
        )
        self.assertEqual(again, proof)

    def test_accepts_mixed_objects_bytes_and_generators(self):
        records = all_records()
        trusts = all_trusts()
        crl = empty_crl()
        proof = prove_weighted_crl(
            (r.to_bytes() if i % 2 else r for i, r in enumerate(records)),
            POINT,
            CONTEXT,
            (t.to_bytes() if i % 2 else t for i, t in enumerate(trusts)),
            ROOT,
            crl.to_bytes(),
            policy(),
            now=0,
        )
        self.assertEqual(
            proof,
            prove_weighted_crl(records, POINT, CONTEXT, trusts, ROOT, crl,
                               policy(), now=0.0),
        )

    def test_revoked_participant_rejected(self):
        trusts = all_trusts()
        crl = make_crl([revoke_trust(trusts[1], ROOT)], 1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                all_records(), POINT, CONTEXT, trusts, ROOT, crl, policy(),
                now=0.0,
            )

    def test_unrelated_snapshot_entry_is_ignored(self):
        foreign = cert("zzz", 50.0, 50.0, b"\x77" * 32, ROOT)
        crl = make_crl([revoke_trust(foreign, ROOT)], 1, 0.0, ROOT)
        proof = make_proof(crl, now=0.0)
        self.assertEqual(audit_weighted_crl_proof(proof, ROOT), EXPECTED)

    def test_future_snapshot_and_low_sequence_rejected(self):
        with self.assertRaises(ValueError):
            make_proof(empty_crl(issued_at=11.0), now=10.0)
        with self.assertRaises(ValueError):
            make_proof(empty_crl(sequence=3), policy(), now=10.0, min=4)

    def test_now_is_required_and_keyword_only(self):
        crl = empty_crl()
        with self.assertRaises(TypeError):
            prove_weighted_crl(
                all_records(), POINT, CONTEXT, all_trusts(), ROOT, crl,
                policy(),
            )
        with self.assertRaises(TypeError):
            prove_weighted_crl(
                all_records(), POINT, CONTEXT, all_trusts(), ROOT, crl,
                policy(), 10.0,
            )

    def test_min_defaults_to_zero(self):
        proof = prove_weighted_crl(
            all_records(), POINT, CONTEXT, all_trusts(), ROOT, empty_crl(),
            policy(), now=0.0,
        )
        self.assertEqual(body_of(proof)[6], 0)

    def test_now_and_min_contracts(self):
        crl = empty_crl()
        for bad_now in ("10", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                prove_weighted_crl(
                    all_records(), POINT, CONTEXT, all_trusts(), ROOT, crl,
                    policy(), now=bad_now,
                )
        for bad_min in (True, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                prove_weighted_crl(
                    all_records(), POINT, CONTEXT, all_trusts(), ROOT, crl,
                    policy(), now=0.0, min=bad_min,
                )

    def test_policy_must_be_consensus_policy(self):
        crl = empty_crl()
        for bad in (None, WEIGHTS, 7, object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                prove_weighted_crl(
                    all_records(), POINT, CONTEXT, all_trusts(), ROOT, crl,
                    bad, now=0.0,
                )

    def test_weight_ids_must_match_record_ids(self):
        crl = empty_crl()
        cases = [
            ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 7),       # missing d
            ConsensusPolicy(
                {"a": 1, "b": 2, "c": 4, "d": 8, "e": 16}, 7
            ),                                                    # extra e
            ConsensusPolicy({"a": 1, "b": 2, "c": 4, "x": 8}, 7),  # wrong id
        ]
        for pol in cases:
            with self.assertRaises(ValueError, msg=repr(pol)):
                prove_weighted_crl(
                    all_records(), POINT, CONTEXT, all_trusts(), ROOT, crl,
                    pol, now=0.0,
                )

    def test_root_contract(self):
        crl = empty_crl()
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                all_records(), POINT, CONTEXT, all_trusts(), b"", crl,
                policy(), now=0.0,
            )
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                prove_weighted_crl(
                    all_records(), POINT, CONTEXT, all_trusts(), bad, crl,
                    policy(), now=0.0,
                )

    def test_bad_crl_argument(self):
        for bad in (None, 42, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                prove_weighted_crl(
                    all_records(), POINT, CONTEXT, all_trusts(), ROOT, bad,
                    policy(), now=0.0,
                )

    def test_bad_record_and_trust_arguments(self):
        crl = empty_crl()
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                [None], POINT, CONTEXT, all_trusts(), ROOT, crl, policy(),
                now=0.0,
            )
        with self.assertRaises(ValueError):
            prove_weighted_crl(
                all_records(), POINT, CONTEXT, [None], ROOT, crl, policy(),
                now=0.0,
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

        def with_body(body):
            return json.dumps(
                {"version": 1, "body": body.hex(), "mac": good["mac"]},
                separators=(",", ":"),
            ).encode()

        valid = json.loads(bytes.fromhex(good["body"]))
        (point, context, records, trusts, crl, now, minimum, weights,
         threshold, consensus) = valid

        def body_with(changes):
            values = [point, context, records, trusts, crl, now, minimum,
                      weights, threshold, consensus]
            for index, value in changes.items():
                values[index] = value
            return json.dumps(values, separators=(",", ":")).encode()

        bodies = [
            body_with({0: [0.0]}),                          # short point
            body_with({0: [0.0, True]}),                    # bool coordinate
            body_with({0: [0.0, float("inf")]}),            # infinite
            body_with({1: 7}),                              # context not str
            body_with({1: ""}),                             # empty context
            body_with({4: "not hex"}),                      # crl not hex
            body_with({5: "now"}),                          # now not number
            body_with({5: float("nan")}),                   # nan now
            body_with({6: 0.0}),                            # float min
            body_with({7: ["a", 1]}),                       # weights not object
            body_with({7: {}}),                             # weights ids missing
            body_with({7: {**weights, "e": 1}}),            # extra weight id
            body_with({7: {ident: (0 if ident == "a" else w)
                           for ident, w in weights.items()}}),  # zero weight
            body_with({8: threshold + 100}),                # threshold > total
            body_with({8: 0}),                              # threshold not positive
            body_with({9: [15, 7, ["b", "a"], True]}),      # unsorted rejected
            body_with({9: [15, 7, ["d"], "yes"]}),          # accepted not bool
        ]
        for body in bodies:
            with self.assertRaises(ValueError, msg=body):
                WeightedCrlProof.from_bytes(with_body(body))

    def test_from_bytes_rejects_misaligned_records_trusts(self):
        proof = make_proof()
        body = json.loads(proof.body)
        # Swap two trust entries so ids no longer align with the records.
        body[3][1], body[3][2] = body[3][2], body[3][1]
        raw = json.dumps(body, separators=(",", ":")).encode()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": proof.mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            WeightedCrlProof.from_bytes(blob)

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
        self.assertEqual(audit_weighted_crl_proof(proof, ROOT), EXPECTED)
        self.assertEqual(audit_weighted_crl_proof(proof.to_bytes(), ROOT),
                         EXPECTED)

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
        body[9][1] = 99
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_weight_tamper_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        body[7]["d"] = 80
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCP1" + raw, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_weighted_crl_proof(WeightedCrlProof(1, raw, mac), ROOT)

    def test_resigned_threshold_tamper_rejected(self):
        proof = make_proof()
        body = json.loads(proof.body)
        # Support is 7: raising the threshold to 8 flips accepted to False,
        # so the carried accepted=True no longer matches the replay.
        body[8] = 8
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

    def test_resigned_revoked_participant_rejected(self):
        trusts = all_trusts()
        clean = make_proof(now=0.0)
        crl = make_crl([revoke_trust(trusts[1], ROOT)], 1, 0.0, ROOT)
        body = json.loads(clean.body)
        body[4] = crl.to_bytes().hex()
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
        state = make_state(1, empty_crl(sequence=1))
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
                ROOT,
                checkpoint=CrlState(
                    1, 1, hashlib.sha256(crl.to_bytes()).digest(), b"\x00" * 32
                ),
            )
        state = make_state(1, crl)
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
            auditor.checkpoint = make_state(1, empty_crl(sequence=1))


class WeightedCrlProofAuditorGatingTest(unittest.TestCase):
    def setUp(self):
        self.crl1 = empty_crl(sequence=1)
        self.crl2 = make_crl([], 2, 5.0, ROOT)
        self.crl3 = make_crl([], 3, 9.0, ROOT)
        # Same sequence as crl1 but different content -> different digest.
        self.crl1_other = make_crl([], 1, 9.0, ROOT)
        self.p1 = make_proof(self.crl1)
        self.p2 = make_proof(self.crl2)
        self.p3 = make_proof(self.crl3)
        self.p1_other = make_proof(self.crl1_other)

    def test_first_audit_advances_from_empty(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        self.assertEqual(auditor.audit(self.p1), EXPECTED)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))
        auditor2 = WeightedCrlProofAuditor(ROOT)
        self.assertEqual(auditor2.audit(self.p1.to_bytes()), EXPECTED)
        self.assertEqual(auditor2.checkpoint, make_state(1, self.crl1))

    def test_higher_sequence_advances(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        auditor.audit(self.p2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.crl2))
        auditor.audit(self.p3)
        self.assertEqual(auditor.checkpoint, make_state(3, self.crl3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        with self.assertRaises(ValueError):
            auditor.audit(self.p1)
        self.assertEqual(auditor.checkpoint, make_state(2, self.crl2))

    def test_same_sequence_same_digest_is_a_replay_without_advance(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        before = auditor.checkpoint
        for _ in range(3):
            self.assertEqual(auditor.audit(self.p1), EXPECTED)
            self.assertEqual(auditor.audit(self.p1.to_bytes()), EXPECTED)
        self.assertEqual(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))

    def test_same_sequence_different_digest_rejected(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        self.assertNotEqual(
            hashlib.sha256(self.crl1.to_bytes()).digest(),
            hashlib.sha256(self.crl1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.p1_other)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p1)
        body = self.p3.body
        forged = WeightedCrlProof(
            1, body,
            hmac.new(OTHER_ROOT, b"NPWCP1" + body, hashlib.sha256).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(forged)
        tampered = dataclasses.replace(
            self.p2, mac=bytes(b ^ 1 for b in self.p2.mac)
        )
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        for bad in (None, 42, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad)
        self.assertEqual(auditor.checkpoint, make_state(1, self.crl1))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        saved = auditor.checkpoint.to_bytes()
        restarted = WeightedCrlProofAuditor(ROOT, checkpoint=saved)
        self.assertEqual(restarted.audit(self.p2), EXPECTED)
        with self.assertRaises(ValueError):
            restarted.audit(self.p1)
        restarted.audit(self.p3)
        self.assertEqual(restarted.checkpoint, make_state(3, self.crl3))

    def test_checkpoint_is_shared_with_plain_crl_proof_auditor(self):
        # The two auditors reuse the exact CrlState checkpoint format.
        auditor = WeightedCrlProofAuditor(ROOT)
        auditor.audit(self.p2)
        saved = auditor.checkpoint.to_bytes()
        plain = CrlProofAuditor(ROOT, checkpoint=saved)
        self.assertEqual(plain.checkpoint, auditor.checkpoint)
        # And a checkpoint the weighted auditor advances stays valid.
        auditor.audit(self.p3)
        plain2 = CrlProofAuditor(ROOT, checkpoint=auditor.checkpoint.to_bytes())
        self.assertEqual(plain2.checkpoint.sequence, 3)


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
        self.assertEqual(auditor.checkpoint, make_state(2, crl2))


if __name__ == "__main__":
    unittest.main()
