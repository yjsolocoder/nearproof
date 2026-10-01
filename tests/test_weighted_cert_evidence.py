import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BoundAttestedObservation,
    ConsensusPolicy,
    Observation,
    RangeDecision,
    VerifierTrust,
    WeightedCertifiedConsensusEvidence,
    WeightedConsensus,
    attest_observation_for_point,
    audit_weighted_cert_evidence,
    cert,
    locate_weighted,
    locate_weighted_cert_evidence,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
KEY_D = b"\xdd" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C, "d": KEY_D}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0), "d": (50.0, 50.0)}
WEIGHTS = {"a": 1, "b": 2, "c": 4}
THRESHOLD = 5

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


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT,
           accepted=True):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound, accepted=accepted), point, context,
        0.0, key or KEYS[ident],
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
    return locate_weighted_cert_evidence(
        triangle_records(), triangle_trusts(), POINT, CONTEXT, policy(), ROOT
    )


def outer_of(evidence):
    return json.loads(evidence.to_bytes())


def body_of(evidence):
    return json.loads(bytes.fromhex(outer_of(evidence)["body"]))


class WeightedCertifiedConsensusEvidenceContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        first = make_evidence()
        second = WeightedCertifiedConsensusEvidence(1, first.body, first.mac)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.mac = b"\x00" * 32

    def test_positional_field_order(self):
        evidence = WeightedCertifiedConsensusEvidence(1, b"[]", b"\x01" * 32)
        self.assertEqual(
            (evidence.version, evidence.body, evidence.mac),
            (1, b"[]", b"\x01" * 32),
        )

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCertifiedConsensusEvidence(bad, b"[]", b"\x00" * 32)

    def test_body_must_be_bytes(self):
        for bad in ("[]", bytearray(b"[]"), None, 0, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCertifiedConsensusEvidence(1, bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"\x00" * 31, b"\x00" * 33, "ab" * 32, None, b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCertifiedConsensusEvidence(1, b"[]", bad)


class LocateWeightedCertEvidenceTest(unittest.TestCase):
    def test_wraps_the_weighted_consensus(self):
        records = triangle_records()
        trusts = triangle_trusts()
        observations = [
            Observation(id=r.id, x=r.x, y=r.y, decision=r.decision)
            for r in records
        ]
        expected = locate_weighted(observations, POINT, policy())
        evidence = locate_weighted_cert_evidence(
            records, trusts, POINT, CONTEXT, policy(), ROOT
        )
        self.assertIsInstance(evidence, WeightedCertifiedConsensusEvidence)
        self.assertEqual(evidence.version, 1)
        self.assertEqual(len(evidence.mac), 32)
        point, context, raw_records, raw_trusts, weights, threshold, result = (
            body_of(evidence)
        )
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(weights, {"a": 1, "b": 2, "c": 4})
        self.assertEqual(threshold, THRESHOLD)
        self.assertEqual(result, [7, 7, [], True])
        audited = audit_weighted_cert_evidence(evidence, ROOT)
        self.assertIsInstance(audited, WeightedConsensus)
        self.assertEqual(audited, expected)

    def test_body_arrays_are_id_sorted_canonical_hex(self):
        evidence = make_evidence()
        _p, _c, raw_records, raw_trusts, _w, _t, _r = body_of(evidence)
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

    def test_mac_formula(self):
        evidence = make_evidence()
        body = bytes.fromhex(outer_of(evidence)["body"])
        expected = hmac.new(ROOT, b"NPWCE1" + body, hashlib.sha256).digest()
        self.assertEqual(evidence.mac, expected)
        self.assertNotEqual(
            evidence.mac,
            hmac.new(OTHER_ROOT, b"NPWCE1" + body, hashlib.sha256).digest(),
        )

    def test_result_is_independent_of_input_order(self):
        evidence = make_evidence()
        shuffled_records = [record("c"), record("a"), record("b")]
        shuffled_trusts = [trust("b"), trust("c"), trust("a")]
        shuffled_policy = ConsensusPolicy({"c": 4, "a": 1, "b": 2}, THRESHOLD)
        again = locate_weighted_cert_evidence(
            shuffled_records, shuffled_trusts, POINT, CONTEXT,
            shuffled_policy, ROOT,
        )
        self.assertEqual(again, evidence)

    def test_accepts_mixed_objects_bytes_and_generators(self):
        records = triangle_records()
        trusts = triangle_trusts()
        evidence = locate_weighted_cert_evidence(
            (r.to_bytes() if i % 2 else r for i, r in enumerate(records)),
            (t.to_bytes() if i % 2 else t for i, t in enumerate(trusts)),
            POINT,
            CONTEXT,
            policy(),
            ROOT,
        )
        self.assertEqual(evidence, make_evidence())

    def test_single_verifier_may_participate(self):
        evidence = locate_weighted_cert_evidence(
            [record("c")], [trust("c")], POINT, CONTEXT,
            ConsensusPolicy({"c": 4}, 4), ROOT,
        )
        _p, _c, _r, _t, weights, threshold, result = body_of(evidence)
        self.assertEqual(weights, {"c": 4})
        self.assertEqual(threshold, 4)
        self.assertEqual(result, [4, 4, [], True])
        self.assertEqual(
            audit_weighted_cert_evidence(evidence, ROOT),
            WeightedConsensus(
                total_weight=4, support_weight=4, rejected=(), accepted=True
            ),
        )

    def test_disk_boundary_counts_as_support(self):
        # "a" sits exactly 3.0 from the origin: a bound of exactly 3.0
        # closes the disk on the queried point.
        evidence = locate_weighted_cert_evidence(
            [record("a", 3.0)], [trust("a")], POINT, CONTEXT,
            ConsensusPolicy({"a": 2}, 2), ROOT,
        )
        *_head, result = body_of(evidence)
        self.assertEqual(result, [2, 2, [], True])

    def test_decision_accepted_flag_is_ignored(self):
        records = triangle_records(accepted=False)
        evidence = locate_weighted_cert_evidence(
            records, triangle_trusts(), POINT, CONTEXT, policy(), ROOT
        )
        *_head, result = body_of(evidence)
        self.assertEqual(result, [7, 7, [], True])

    def test_rejection_is_recorded(self):
        records = triangle_records() + [record("d")]
        trusts = triangle_trusts() + [trust("d")]
        weights = dict(WEIGHTS, d=3)
        evidence = locate_weighted_cert_evidence(
            records, trusts, POINT, CONTEXT,
            ConsensusPolicy(weights, 5), ROOT,
        )
        *_head, result = body_of(evidence)
        self.assertEqual(result, [10, 7, ["d"], True])
        self.assertEqual(
            audit_weighted_cert_evidence(evidence, ROOT),
            WeightedConsensus(
                total_weight=10, support_weight=7, rejected=("d",),
                accepted=True,
            ),
        )

    def test_unsuccessful_consensus_is_recorded(self):
        # Bounds of 1.0 cover only the verifier at the origin: the support
        # weight is 4 ("c"), below the threshold of 5, and that is carried,
        # not raised.
        records = triangle_records(upper_bound=1.0)
        evidence = locate_weighted_cert_evidence(
            records, triangle_trusts(), POINT, CONTEXT, policy(), ROOT
        )
        *_head, result = body_of(evidence)
        self.assertEqual(result, [7, 4, ["a", "b"], False])

    def test_cert_failures_propagate(self):
        records = triangle_records()
        trusts = triangle_trusts()
        # A missing trust, a duplicated trust, a duplicated record, a
        # tampered record MAC and a trust/observation coordinate mismatch.
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts[:2], POINT, CONTEXT, policy(), ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts + [trusts[0]], POINT, CONTEXT, policy(), ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records + [records[0]], trusts, POINT, CONTEXT, policy(), ROOT
            )
        tampered = dataclasses.replace(records[0], mac=b"\x00" * 32)
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                [tampered] + records[1:], trusts, POINT, CONTEXT, policy(),
                ROOT,
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, [trust("a", x=9.0)] + trusts[1:], POINT, CONTEXT,
                policy(), ROOT,
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts, (1.0, 0.0), CONTEXT, policy(), ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts, POINT, "room-8", policy(), ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, [42], POINT, CONTEXT, policy(), ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                [42], trusts, POINT, CONTEXT, policy(), ROOT
            )

    def test_policy_contract(self):
        records = triangle_records()
        trusts = triangle_trusts()
        # Weight ids must match the record ids exactly.
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts, POINT, CONTEXT,
                ConsensusPolicy({"a": 1, "b": 2}, 2), ROOT,
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts, POINT, CONTEXT,
                ConsensusPolicy(dict(WEIGHTS, d=1), 5), ROOT,
            )
        # The policy must be a ConsensusPolicy.
        for bad in (dict(WEIGHTS), (WEIGHTS, 5), None, 5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_weighted_cert_evidence(
                    records, trusts, POINT, CONTEXT, bad, ROOT
                )
        # Illegal weights and thresholds are rejected by ConsensusPolicy.
        for weights, threshold in (
            ({"a": 0, "b": 2, "c": 4}, 5),
            ({"a": 1.5, "b": 2, "c": 4}, 5),
            ({"a": True, "b": 2, "c": 4}, 5),
            (WEIGHTS, 0),
            (WEIGHTS, 8),
            (WEIGHTS, True),
        ):
            with self.assertRaises(ValueError, msg=(weights, threshold)):
                ConsensusPolicy(weights, threshold)

    def test_root_contract_matches_locate_cert(self):
        records = triangle_records()
        trusts = triangle_trusts()
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts, POINT, CONTEXT, policy(), b""
            )
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                locate_weighted_cert_evidence(
                    records, trusts, POINT, CONTEXT, policy(), bad
                )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, trusts, POINT, CONTEXT, policy(), OTHER_ROOT
            )


class WeightedCertifiedConsensusEvidenceEncodingTest(unittest.TestCase):
    def test_to_bytes_outer_shape(self):
        evidence = make_evidence()
        obj = outer_of(evidence)
        self.assertEqual(list(obj), ["version", "body", "mac"])
        self.assertEqual(obj["version"], 1)
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
        self.assertNotIn(b" ", raw)
        decoded = json.loads(raw)
        self.assertIsInstance(decoded, list)
        self.assertEqual(len(decoded), 7)
        point, context, records_, trusts_, weights, threshold, result = decoded
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertIsInstance(records_, list)
        self.assertIsInstance(trusts_, list)
        self.assertEqual(list(weights), ["a", "b", "c"])
        self.assertEqual(threshold, THRESHOLD)
        self.assertEqual(result, [7, 7, [], True])

    def test_round_trip(self):
        evidence = make_evidence()
        self.assertEqual(
            WeightedCertifiedConsensusEvidence.from_bytes(evidence.to_bytes()),
            evidence,
        )

    def test_from_bytes_rejects_non_bytes(self):
        evidence = make_evidence()
        for bad in (evidence.to_bytes().decode("utf-8"), None, 42, [1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                WeightedCertifiedConsensusEvidence.from_bytes(bad)

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
                WeightedCertifiedConsensusEvidence.from_bytes(blob)

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
                WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_outer(self):
        data = make_evidence().to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json"):
            with self.assertRaises(ValueError, msg=blob):
                WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def with_body(self, body, mac=None):
        good = outer_of(make_evidence())
        return json.dumps(
            {"version": 1, "body": body.hex(),
             "mac": good["mac"] if mac is None else mac},
            separators=(",", ":"),
        ).encode()

    def test_from_bytes_rejects_malformed_bodies(self):
        good_consensus = [7, 7, [], True]
        good_weights = {"a": 1, "b": 2, "c": 4}

        def body(point, context, records, trusts, weights, threshold,
                 consensus):
            return json.dumps(
                [point, context, records, trusts, weights, threshold,
                 consensus],
                separators=(",", ":"),
            ).encode()

        decoded = body_of(make_evidence())
        records_, trusts_ = decoded[2], decoded[3]
        bodies = [
            body([0.0], CONTEXT, records_, trusts_, good_weights, 5,
                 good_consensus),
            body([0.0, True], CONTEXT, records_, trusts_, good_weights, 5,
                 good_consensus),
            body([0.0, 0.0], "", records_, trusts_, good_weights, 5,
                 good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_, [1, 2, 4], 5,
                 good_consensus),
            # Weight ids reordered, mismatched, duplicated or of bad value.
            body([0.0, 0.0], CONTEXT, records_, trusts_,
                 {"b": 2, "a": 1, "c": 4}, 5, good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_,
                 {"a": 1, "b": 2}, 5, good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_,
                 {"a": 1, "b": 2, "c": 4, "d": 1}, 5, good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_,
                 {"a": 0, "b": 2, "c": 4}, 5, good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_,
                 {"a": True, "b": 2, "c": 4}, 5, good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_,
                 {"a": 1.5, "b": 2, "c": 4}, 5, good_consensus),
            # Illegal thresholds.
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 0,
                 good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 8,
                 good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, True,
                 good_consensus),
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 5.0,
                 good_consensus),
            # Malformed consensus arrays.
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 5,
                 [7, 7, [], True, 1]),
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 5,
                 [7, 7, ["b", "a"], True]),
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 5,
                 [7.0, 7, [], True]),
            body([0.0, 0.0], CONTEXT, records_, trusts_, good_weights, 5,
                 [7, 7, [], 1]),
        ]
        for body_ in bodies:
            with self.assertRaises(ValueError, msg=body_):
                WeightedCertifiedConsensusEvidence.from_bytes(
                    self.with_body(body_)
                )

    def test_from_bytes_rejects_non_canonical_inner_body(self):
        good = outer_of(make_evidence())
        body = json.loads(bytes.fromhex(good["body"]))
        raw = (json.dumps(body, separators=(",", ":")) + " ").encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(self.with_body(raw))

    def test_from_bytes_rejects_misaligned_record_and_trust_ids(self):
        decoded = body_of(make_evidence())
        decoded[3].reverse()
        raw = json.dumps(decoded, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(self.with_body(raw))

    def test_from_bytes_rejects_unsorted_records(self):
        decoded = body_of(make_evidence())
        decoded[2].reverse()
        decoded[3].reverse()
        raw = json.dumps(decoded, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(self.with_body(raw))

    def test_from_bytes_rejects_duplicate_weights_keys(self):
        # A duplicated id inside the weights object parses, but its
        # canonical re-encoding differs from the stored body bytes.
        body = make_evidence().body.decode()
        duplicated = body.replace('{"a":1,', '{"a":1,"a":1,', 1).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(
                self.with_body(duplicated)
            )

    def test_from_bytes_does_not_verify_mac(self):
        good = outer_of(make_evidence())
        forged = json.dumps(
            {"version": 1, "body": good["body"], "mac": "00" * 32},
            separators=(",", ":"),
        ).encode()
        decoded = WeightedCertifiedConsensusEvidence.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class AuditWeightedCertEvidenceTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        evidence = make_evidence()
        expected = WeightedConsensus(
            total_weight=7, support_weight=7, rejected=(), accepted=True
        )
        self.assertEqual(audit_weighted_cert_evidence(evidence, ROOT), expected)
        self.assertEqual(
            audit_weighted_cert_evidence(evidence.to_bytes(), ROOT), expected
        )

    def test_wrong_root_rejected(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(evidence, OTHER_ROOT)

    def test_root_shape_contract(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(evidence, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_weighted_cert_evidence(evidence, bad)

    def test_bad_x_type_rejected(self):
        for bad in ("x", 123, None, {}, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_weighted_cert_evidence(bad, ROOT)

    def test_tampered_mac_rejected(self):
        evidence = make_evidence()
        tampered = dataclasses.replace(
            evidence, mac=bytes(a ^ 1 for a in evidence.mac)
        )
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(tampered, ROOT)

    def resigned(self, mutate):
        evidence = make_evidence()
        body = body_of(evidence)
        mutate(body)
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCE1" + raw, hashlib.sha256).digest()
        return json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()

    def test_resigned_consensus_mismatch_rejected(self):
        # An attacker who knows the root rewrites the consensus and
        # re-signs: the MAC checks out, but the rerun disagrees.
        forged = self.resigned(lambda body: body[6].__setitem__(1, 6))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_tampered_point_rejected(self):
        forged = self.resigned(lambda body: body.__setitem__(0, [1.0, 0.0]))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_tampered_weights_rejected(self):
        forged = self.resigned(lambda body: body[4].__setitem__("c", 3))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_swapped_trusts_rejected(self):
        forged = self.resigned(lambda body: body[3].reverse())
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(b"not json", ROOT)


if __name__ == "__main__":
    unittest.main()
