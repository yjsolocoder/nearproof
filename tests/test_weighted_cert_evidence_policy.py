import unittest

from nearproof import (
    ConsensusPolicy,
    RangeDecision,
    WeightedConsensus,
    attest_observation_for_point,
    audit_weighted_cert_evidence,
    audit_weighted_cert_evidence_policy,
    cert,
    locate_weighted_cert_evidence,
    make_crl,
    make_observation_crl,
    revoke_observation,
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
WEIGHTS = {"a": 1, "b": 2, "c": 4}
THRESHOLD = 5

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0):
    return RangeDecision(sample_count=1, upper_bound=upper_bound, accepted=True)


def policy(weights=None, threshold=THRESHOLD):
    return ConsensusPolicy(WEIGHTS if weights is None else weights, threshold)


def trust(ident, *, root=ROOT, key=None):
    px, py = POSITIONS[ident]
    return cert(ident, px, py, key or KEYS[ident], root)


def record(ident, issued_at=0.0, *, key=None, upper_bound=5.0):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), POINT, CONTEXT, issued_at,
        key or KEYS[ident],
    )


def triangle_records(issued_at=0.0):
    return [record("a", issued_at), record("b", issued_at), record("c", issued_at)]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


def make_evidence(records=None, trusts=None, pol=None):
    return locate_weighted_cert_evidence(
        triangle_records() if records is None else records,
        triangle_trusts() if trusts is None else trusts,
        POINT,
        CONTEXT,
        policy() if pol is None else pol,
        ROOT,
    )


class NoPolicyParityTest(unittest.TestCase):
    def test_matches_the_baseline_audit(self):
        evidence = make_evidence()
        expected = audit_weighted_cert_evidence(evidence, ROOT)
        self.assertEqual(
            audit_weighted_cert_evidence_policy(evidence, ROOT), expected
        )
        self.assertEqual(
            audit_weighted_cert_evidence_policy(evidence.to_bytes(), ROOT),
            expected,
        )
        self.assertIsInstance(expected, WeightedConsensus)
        self.assertEqual(expected.total_weight, 7)
        self.assertEqual(expected.support_weight, 7)
        self.assertTrue(expected.accepted)

    def test_now_and_min_ignored_without_a_policy(self):
        evidence = make_evidence()
        self.assertEqual(
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now="garbage", min=object()
            ),
            audit_weighted_cert_evidence(evidence, ROOT),
        )

    def test_baseline_failures_raise_first(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(evidence, OTHER_ROOT)
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(evidence, b"")
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(b"not json", ROOT)
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(123, ROOT)

    def test_only_non_bytes_root_is_a_type_error(self):
        evidence = make_evidence()
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_weighted_cert_evidence_policy(
                    evidence, bad, now=1.0, max_age=1.0
                )


class FreshnessTest(unittest.TestCase):
    def test_boundaries_are_inclusive(self):
        evidence = make_evidence(triangle_records(issued_at=10.0))
        audit_weighted_cert_evidence_policy(
            evidence, ROOT, now=15.0, max_age=5.0
        )
        audit_weighted_cert_evidence_policy(
            evidence, ROOT, now=10.0, max_age=0.0
        )

    def test_stale_and_future_rejected(self):
        evidence = make_evidence(triangle_records(issued_at=10.0))
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=15.1, max_age=5.0
            )
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=9.9, max_age=5.0
            )

    def test_now_required_and_value_contract(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(evidence, ROOT, max_age=5.0)
        for bad_now in (True, "1", float("inf")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                audit_weighted_cert_evidence_policy(
                    evidence, ROOT, now=bad_now, max_age=5.0
                )
        for bad_age in (True, -0.1, float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_age)):
                audit_weighted_cert_evidence_policy(
                    evidence, ROOT, now=1.0, max_age=bad_age
                )


class RevocationsTest(unittest.TestCase):
    def test_trust_hit_permanently_rejects(self):
        evidence = make_evidence()
        revocation = revoke_trust(trust("c"), ROOT)
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=[revocation]
            )

    def test_trust_snapshot_unrelated_entry_is_ignored(self):
        evidence = make_evidence()
        snapshot = make_crl([revoke_trust(trust("d"), ROOT)], 1, 0.5, ROOT)
        result = audit_weighted_cert_evidence_policy(
            evidence, ROOT, now=1.0, trust_revocations=snapshot
        )
        self.assertEqual(result, audit_weighted_cert_evidence(evidence, ROOT))
        hit = make_crl([revoke_trust(trust("a"), ROOT)], 1, 0.5, ROOT)
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=hit
            )

    def test_legacy_unknown_certificate_rejected(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                trust_revocations=[revoke_trust(trust("d"), ROOT)],
            )

    def test_observation_hit_rejects_only_observations_at_or_before(self):
        evidence = make_evidence(triangle_records(issued_at=2.0))
        at_boundary = revoke_observation("c", 2.0, KEY_C)
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=3.0,
                observation_revocations=[at_boundary],
            )
        # Strictly later: c is kept and carries its full weight.
        later = make_evidence(
            [record("a", 2.0), record("b", 2.0), record("c", 2.0)]
        )
        result = audit_weighted_cert_evidence_policy(
            later, ROOT, now=3.0,
            observation_revocations=[revoke_observation("c", 1.0, KEY_C)],
        )
        self.assertEqual(result.support_weight, 7)
        self.assertTrue(result.accepted)

    def test_observation_revocation_key_and_list_checks(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocations=[
                    revoke_observation("a", 0.0, b"\x01" * 32)
                ],
            )
        snapshot = make_observation_crl(
            [revoke_observation("z", 0.0, b"\x02" * 32)], 1, 0.5, ROOT
        )
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocation_list=snapshot,
            )
        empty = make_observation_crl([], 0, 0.0, ROOT)
        audit_weighted_cert_evidence_policy(
            evidence, ROOT, now=1.0, observation_revocation_list=empty
        )
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocation_list=empty, min=1,
            )

    def test_sources_stack(self):
        records = [record("a", 2.0), record("b", 2.0), record("c", 2.0)]
        evidence = make_evidence(records)
        snapshot = make_observation_crl(
            [revoke_observation("b", 2.0, KEY_B)], 1, 2.5, ROOT
        )
        with self.assertRaises(ValueError):
            audit_weighted_cert_evidence_policy(
                evidence, ROOT, now=3.0,
                observation_revocations=[
                    revoke_observation("a", 1.0, KEY_A)
                ],
                observation_revocation_list=snapshot,
            )


if __name__ == "__main__":
    unittest.main()
