import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    BoundAttestedObservation,
    ConsensusPolicy,
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

POINT = (0.0, 0.0)
CONTEXT = "room-7"

WEIGHTS = {"a": 1, "b": 2, "c": 4, "d": 8}


def decision(upper_bound=5.0, *, accepted=False, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, root=ROOT, key=None, x=None, y=None):
    px, py = POSITIONS[ident]
    return cert(ident, x if x is not None else px, y if y is not None else py,
                key or KEYS[ident], root)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT,
           accepted=False):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound, accepted=accepted), point, context,
        0.0, key or KEYS[ident],
    )


def all_records(upper_bound=5.0, **kwargs):
    return [record(i, upper_bound, **kwargs) for i in ("a", "b", "c", "d")]


def all_trusts():
    return [trust(i) for i in ("a", "b", "c", "d")]


def policy(weights=None, threshold=5):
    return ConsensusPolicy(WEIGHTS if weights is None else weights, threshold)


def make_evidence(pol=None):
    return locate_weighted_cert_evidence(
        all_records(), POINT, CONTEXT, all_trusts(), pol or policy(), ROOT
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
        records = all_records()
        trusts = all_trusts()
        pol = policy()
        evidence = locate_weighted_cert_evidence(
            records, POINT, CONTEXT, trusts, pol, ROOT
        )
        self.assertIsInstance(evidence, WeightedCertifiedConsensusEvidence)
        self.assertEqual(evidence.version, 1)
        self.assertEqual(len(evidence.mac), 32)
        point, context, raw_records, raw_trusts, raw_weights, raw_threshold, \
            raw_consensus = body_of(evidence)
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(raw_weights, WEIGHTS)
        self.assertEqual(raw_threshold, 5)
        self.assertEqual(raw_consensus, [15, 7, ["d"], True])
        result = audit_weighted_cert_evidence(evidence, ROOT)
        self.assertIsInstance(result, WeightedConsensus)
        # Same WeightedConsensus locate_weighted computes over the verified
        # observations.
        from nearproof import Observation

        observations = [
            Observation(id=item.id, x=item.x, y=item.y, decision=item.decision)
            for item in records
        ]
        self.assertEqual(result, locate_weighted(observations, POINT, pol))

    def test_body_arrays_are_id_sorted_canonical_hex(self):
        evidence = make_evidence()
        _p, _c, raw_records, raw_trusts, raw_weights, _t, _cons = body_of(
            evidence
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
        for blob, source in zip(raw_records, sorted(all_records(),
                                                    key=lambda r: r.id)):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        for blob, source in zip(raw_trusts, sorted(all_trusts(),
                                                   key=lambda t: t.id)):
            self.assertEqual(bytes.fromhex(blob), source.to_bytes())
        self.assertEqual(list(raw_weights), ["a", "b", "c", "d"])

    def test_mac_formula(self):
        evidence = make_evidence()
        body = bytes.fromhex(outer_of(evidence)["body"])
        expected = hmac.new(ROOT, b"NPWCE1" + body, hashlib.sha256).digest()
        self.assertEqual(evidence.mac, expected)
        self.assertNotEqual(
            evidence.mac,
            hmac.new(OTHER_ROOT, b"NPWCE1" + body, hashlib.sha256).digest(),
        )
        self.assertNotEqual(
            evidence.mac,
            hmac.new(ROOT, b"NPCCE1" + body, hashlib.sha256).digest(),
        )

    def test_result_is_independent_of_input_order(self):
        evidence = make_evidence()
        shuffled_records = [record(i) for i in ("d", "b", "a", "c")]
        shuffled_trusts = [trust(i) for i in ("b", "d", "c", "a")]
        shuffled_weights = {"d": 8, "b": 2, "a": 1, "c": 4}
        again = locate_weighted_cert_evidence(
            shuffled_records, POINT, CONTEXT, shuffled_trusts,
            ConsensusPolicy(shuffled_weights, 5), ROOT,
        )
        self.assertEqual(again, evidence)

    def test_accepts_mixed_objects_bytes_and_generators(self):
        records = all_records()
        trusts = all_trusts()
        evidence = locate_weighted_cert_evidence(
            (r.to_bytes() if i % 2 else r for i, r in enumerate(records)),
            POINT,
            CONTEXT,
            (t.to_bytes() if i % 2 else t for i, t in enumerate(trusts)),
            policy(),
            ROOT,
        )
        self.assertEqual(evidence, make_evidence())

    def test_single_verifier_allowed(self):
        # Unlike the fixed-three-person locate_cert path, one certified
        # verifier may carry a weighted consensus.
        solo_evidence = locate_weighted_cert_evidence(
            [record("c")], POINT, CONTEXT, [trust("c")],
            ConsensusPolicy({"c": 4}, 4), ROOT,
        )
        _p, _c, raw_records, raw_trusts, raw_weights, raw_threshold, \
            raw_consensus = body_of(solo_evidence)
        self.assertEqual(len(raw_records), 1)
        self.assertEqual(len(raw_trusts), 1)
        self.assertEqual(raw_weights, {"c": 4})
        self.assertEqual(raw_threshold, 4)
        self.assertEqual(raw_consensus, [4, 4, [], True])
        self.assertEqual(
            audit_weighted_cert_evidence(solo_evidence, ROOT),
            WeightedConsensus(4, 4, (), True),
        )

    def test_rejection_recorded_and_sorted(self):
        evidence = make_evidence()
        _p, _c, _r, _t, _w, _threshold, raw_consensus = body_of(evidence)
        self.assertEqual(raw_consensus, [15, 7, ["d"], True])

    def test_threshold_exactly_met_and_just_missed(self):
        # At (3, 4) c (weight 4) sits exactly on its closed 5-radius
        # boundary while a (weight 1) and b (weight 2) fall outside their
        # zero bounds (d never covers): support weight is exactly 4.
        query = (3.0, 4.0)

        def bound_for(ident):
            return {"a": 0.0, "b": 0.0, "c": 5.0, "d": 0.0}[ident]

        records = [
            record(i, bound_for(i), point=query) for i in ("a", "b", "c", "d")
        ]
        trusts = all_trusts()
        met = locate_weighted_cert_evidence(
            records, query, CONTEXT, trusts,
            ConsensusPolicy(WEIGHTS, 4), ROOT,
        )
        self.assertEqual(body_of(met)[6], [15, 4, ["a", "b", "d"], True])
        missed = locate_weighted_cert_evidence(
            records, query, CONTEXT, trusts,
            ConsensusPolicy(WEIGHTS, 5), ROOT,
        )
        self.assertEqual(body_of(missed)[6], [15, 4, ["a", "b", "d"], False])

    def test_boundary_counts_as_support(self):
        # a and b sit exactly on the 5-radius boundary, c on the centre:
        # the closed boundary carries every weight.
        records = [record(i) for i in ("a", "b", "c")]
        trusts = [trust(i) for i in ("a", "b", "c")]
        evidence = locate_weighted_cert_evidence(
            records, POINT, CONTEXT, trusts,
            ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 7), ROOT,
        )
        self.assertEqual(body_of(evidence)[6], [7, 7, [], True])

    def test_decision_accepted_flag_is_ignored(self):
        records = [record(i, accepted=False) for i in ("a", "b", "c")]
        trusts = [trust(i) for i in ("a", "b", "c")]
        pol = ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 7)
        evidence = locate_weighted_cert_evidence(
            records, POINT, CONTEXT, trusts, pol, ROOT
        )
        self.assertEqual(body_of(evidence)[6], [7, 7, [], True])

    def test_locate_cert_style_failures_propagate(self):
        records = all_records()
        trusts = all_trusts()
        pol = policy()
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts[:3], pol, ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts + [trusts[0]], pol, ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, (1.0, 0.0), CONTEXT, trusts, pol, ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, "room-8", trusts, pol, ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, [42], pol, ROOT
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                [42], POINT, CONTEXT, trusts, pol, ROOT
            )

    def test_bad_trust_root_rejected(self):
        records = all_records()
        trusts = all_trusts()
        trusts[1] = trust("b", root=OTHER_ROOT)
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts, policy(), ROOT
            )

    def test_bad_record_mac_rejected(self):
        records = all_records()
        bad = dataclasses.replace(
            records[0],
            mac=bytes(a ^ 1 for a in records[0].mac),
        )
        records = [bad] + records[1:]
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, all_trusts(), policy(), ROOT
            )

    def test_trust_position_mismatch_rejected(self):
        records = all_records()
        trusts = all_trusts()
        trusts[0] = trust("a", x=99.0, y=0.0)
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts, policy(), ROOT
            )

    def test_query_binding_mismatch_rejected(self):
        # A record signed for a different point or context is the same MAC
        # layer but fails the locate_cert query binding.
        other = [record(i, point=(1.0, 0.0)) for i in ("a", "b", "c")]
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                other, POINT, CONTEXT, [trust(i) for i in ("a", "b", "c")],
                ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 1), ROOT,
            )

    def test_duplicate_record_ids_rejected(self):
        records = [record("a"), record("a"), record("b"), record("c")]
        trusts = [trust(i) for i in ("a", "b", "c")]
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts,
                ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 1), ROOT,
            )

    def test_policy_must_be_consensus_policy(self):
        for bad in (None, 7, WEIGHTS, object(), True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                locate_weighted_cert_evidence(
                    all_records(), POINT, CONTEXT, all_trusts(), bad, ROOT
                )

    def test_policy_ids_must_match_records(self):
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                all_records(), POINT, CONTEXT, all_trusts(),
                ConsensusPolicy({"a": 1, "b": 2, "c": 4}, 1), ROOT,
            )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                all_records(), POINT, CONTEXT, all_trusts(),
                ConsensusPolicy(
                    {"a": 1, "b": 2, "c": 4, "x": 8}, 5
                ), ROOT,
            )

    def test_root_contract_matches_locate_cert(self):
        records = all_records()
        trusts = all_trusts()
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts, policy(), b""
            )
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                locate_weighted_cert_evidence(
                    records, POINT, CONTEXT, trusts, policy(), bad
                )
        with self.assertRaises(ValueError):
            locate_weighted_cert_evidence(
                records, POINT, CONTEXT, trusts, policy(), OTHER_ROOT
            )


class WeightedCertifiedConsensusEvidenceEncodingTest(unittest.TestCase):
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
        self.assertNotIn(b" ", raw)
        decoded = json.loads(raw)
        self.assertIsInstance(decoded, list)
        self.assertEqual(len(decoded), 7)
        point, context, records_, trusts_, weights, threshold, consensus = \
            decoded
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertIsInstance(records_, list)
        self.assertIsInstance(trusts_, list)
        self.assertEqual(weights, WEIGHTS)
        self.assertEqual(threshold, 5)
        self.assertEqual(consensus, [15, 7, ["d"], True])

    def test_round_trip(self):
        evidence = make_evidence()
        self.assertEqual(
            WeightedCertifiedConsensusEvidence.from_bytes(
                evidence.to_bytes()
            ),
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
            json.dumps(
                {"body": good["body"], "version": 1, "mac": good["mac"]},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"]},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"], "mac": good["mac"],
                 "extra": 1},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 2, "body": good["body"], "mac": good["mac"]},
                separators=(",", ":"),
            ).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_bad_hex_and_mac_length(self):
        good = outer_of(make_evidence())
        blobs = [
            json.dumps(
                {"version": 1, "body": "zz", "mac": good["mac"]},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"].upper(),
                 "mac": good["mac"]},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"], "mac": "0"},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"],
                 "mac": "ab" + good["mac"]},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"],
                 "mac": good["mac"][:-2]},
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {"version": 1, "body": good["body"],
                 "mac": good["mac"].upper()},
                separators=(",", ":"),
            ).encode(),
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

    def test_from_bytes_rejects_malformed_bodies(self):
        good = outer_of(make_evidence())

        def with_body(body):
            return json.dumps(
                {"version": 1, "body": body.hex(), "mac": good["mac"]},
                separators=(",", ":"),
            ).encode()

        good_consensus = [15, 7, ["d"], True]
        good_weights = {"a": 1, "b": 2, "c": 4, "d": 8}
        bodies = [
            # point violations
            json.dumps([[0.0], CONTEXT, [], [], {}, 1, good_consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, True], CONTEXT, [], [], {}, 1, good_consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, float("nan")], CONTEXT, [], [], {}, 1,
                        good_consensus], separators=(",", ":")).encode(),
            # context violations
            json.dumps([[0.0, 0.0], "", [], [], {}, 1, good_consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], 7, [], [], {}, 1, good_consensus],
                       separators=(",", ":")).encode(),
            # non-hex embedded items
            json.dumps([[0.0, 0.0], CONTEXT, ["zz"], ["zz"], {}, 1,
                        good_consensus], separators=(",", ":")).encode(),
            # weights shape
            json.dumps([[0.0, 0.0], CONTEXT, [], [], [], 1, good_consensus],
                       separators=(",", ":")).encode(),
            # weights ids mismatch
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {"a": 1}, 1,
                        good_consensus], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        {"a": 1, "b": 2, "c": 4, "d": 8, "e": 16}, 1,
                        good_consensus], separators=(",", ":")).encode(),
            # weights out of order
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        {"d": 8, "c": 4, "b": 2, "a": 1}, 1,
                        good_consensus], separators=(",", ":")).encode(),
            # illegal weight values
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        {"a": 0}, 1, good_consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [],
                        {"a": 1.5}, 1, good_consensus],
                       separators=(",", ":")).encode(),
            # illegal threshold
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 0, good_consensus],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 1.5,
                        good_consensus], separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, True,
                        good_consensus], separators=(",", ":")).encode(),
            # threshold above the total weight
            json.dumps([[0.0, 0.0], CONTEXT, [], [], good_weights, 16,
                        good_consensus], separators=(",", ":")).encode(),
            # consensus shape
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 1,
                        [15, 7, ["d"], True, 1]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 1,
                        [15.0, 7, ["d"], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 1,
                        [15, 7, ["d"], 1]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 1,
                        [15, 7, ["b", "a"], True]],
                       separators=(",", ":")).encode(),
            json.dumps([[0.0, 0.0], CONTEXT, [], [], {}, 1,
                        [15, 7, ["a", "a"], True]],
                       separators=(",", ":")).encode(),
        ]
        for body in bodies:
            with self.assertRaises(ValueError, msg=body):
                WeightedCertifiedConsensusEvidence.from_bytes(with_body(body))

    def test_from_bytes_rejects_duplicate_weight_keys(self):
        good = outer_of(make_evidence())
        body = bytes.fromhex(good["body"])
        tampered = body.replace(b'{"a":1,', b'{"a":9,"a":1,', 1)
        self.assertNotEqual(tampered, body)
        mac = hmac.new(ROOT, b"NPWCE1" + tampered, hashlib.sha256).digest()
        blob = json.dumps(
            {"version": 1, "body": tampered.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_negative_weight(self):
        good = outer_of(make_evidence())
        body = json.loads(bytes.fromhex(good["body"]))
        body[4]["d"] = -1
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCE1" + raw, hashlib.sha256).digest()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_inner_body(self):
        good = outer_of(make_evidence())
        body = json.loads(bytes.fromhex(good["body"]))
        raw = (json.dumps(body, separators=(",", ":")) + " ").encode()
        blob = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": good["mac"]},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(blob)

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
            WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_body_with_empty_records(self):
        # A signed body with no records cannot satisfy a positive threshold:
        # the body contract itself rejects it even with a valid root MAC.
        body = json.dumps(
            [[0.0, 0.0], CONTEXT, [], [], {}, 1, [0, 0, [], False]],
            separators=(",", ":"),
        ).encode()
        mac = hmac.new(ROOT, b"NPWCE1" + body, hashlib.sha256).digest()
        blob = json.dumps(
            {"version": 1, "body": body.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            WeightedCertifiedConsensusEvidence.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        good = outer_of(make_evidence())
        forged = json.dumps(
            {"version": 1, "body": good["body"], "mac": "00" * 32},
            separators=(",", ":"),
        ).encode()
        decoded = WeightedCertifiedConsensusEvidence.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)

    def test_to_bytes_rejects_non_canonical_body(self):
        evidence = WeightedCertifiedConsensusEvidence(
            1, b"[] ", b"\x00" * 32
        )
        with self.assertRaises(ValueError):
            evidence.to_bytes()


class AuditWeightedCertEvidenceTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        records = all_records()
        trusts = all_trusts()
        pol = policy()
        evidence = locate_weighted_cert_evidence(
            records, POINT, CONTEXT, trusts, pol, ROOT
        )
        expected = WeightedConsensus(15, 7, ("d",), True)
        self.assertEqual(audit_weighted_cert_evidence(evidence, ROOT),
                         expected)
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

    def _resigned(self, mutate):
        evidence = make_evidence()
        outer = outer_of(evidence)
        body = json.loads(bytes.fromhex(outer["body"]))
        mutate(body)
        raw = json.dumps(body, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPWCE1" + raw, hashlib.sha256).digest()
        return json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()

    def test_resigned_consensus_mismatch_rejected(self):
        forged = self._resigned(lambda body: body[6].__setitem__(1, 2))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_tampered_point_rejected(self):
        forged = self._resigned(lambda body: body.__setitem__(0, [1.0, 0.0]))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_tampered_context_rejected(self):
        forged = self._resigned(lambda body: body.__setitem__(1, "room-8"))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_swapped_trusts_rejected(self):
        forged = self._resigned(lambda body: body[3].reverse())
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_tampered_weights_rejected(self):
        # Re-signed with a changed weight mapping: the MAC verifies, but the
        # carried consensus cannot match the tally under the changed policy.
        def mutate(body):
            body[4]["c"] = 40
            body[4] = {key: body[4][key] for key in sorted(body[4])}
            body[5] = 51
        forged = self._resigned(mutate)
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_threshold_tamper_rejected(self):
        # Raising the threshold above the carried support weight flips the
        # recomputed decision even though the body MAC verifies: the carried
        # accepted flag can never be trusted on its own.
        forged = self._resigned(lambda body: body.__setitem__(5, 8))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_resigned_duplicate_weight_key_rejected(self):
        evidence = make_evidence()
        outer = outer_of(evidence)
        raw = bytes.fromhex(outer["body"]).replace(
            b'{"a":1,', b'{"a":9,"a":1,', 1
        )
        mac = hmac.new(ROOT, b"NPWCE1" + raw, hashlib.sha256).digest()
        forged = json.dumps(
            {"version": 1, "body": raw.hex(), "mac": mac.hex()},
            separators=(",", ":"),
        ).encode()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(forged, ROOT)

    def test_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence(b"not json", ROOT)


if __name__ == "__main__":
    unittest.main()
