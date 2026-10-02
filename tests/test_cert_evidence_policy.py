import unittest

from nearproof import (
    CertifiedConsensusEvidence,
    Consensus,
    RangeDecision,
    TrustRevocationList,
    ObservationRevocationList,
    VerifierTrust,
    attest_observation_for_point,
    audit_cert_evidence,
    audit_cert_evidence_policy,
    cert,
    locate_cert_evidence,
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

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0):
    return RangeDecision(sample_count=1, upper_bound=upper_bound, accepted=True)


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


def make_evidence(records=None, trusts=None):
    return locate_cert_evidence(
        triangle_records() if records is None else records,
        POINT,
        CONTEXT,
        triangle_trusts() if trusts is None else trusts,
        ROOT,
    )


class NoPolicyParityTest(unittest.TestCase):
    def test_matches_the_baseline_audit_for_objects_and_bytes(self):
        evidence = make_evidence()
        expected = audit_cert_evidence(evidence, ROOT)
        self.assertEqual(audit_cert_evidence_policy(evidence, ROOT), expected)
        self.assertEqual(
            audit_cert_evidence_policy(evidence.to_bytes(), ROOT), expected
        )
        self.assertIsInstance(
            audit_cert_evidence_policy(evidence, ROOT), Consensus
        )

    def test_now_and_min_are_ignored_without_a_policy(self):
        evidence = make_evidence()
        expected = audit_cert_evidence(evidence, ROOT)
        # No clock is read and malformed now/min never surface.
        self.assertEqual(
            audit_cert_evidence_policy(
                evidence, ROOT, now="garbage", min=object()
            ),
            expected,
        )

    def test_baseline_failures_still_raise_first(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, OTHER_ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, b"")
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(b"not json", ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(123, ROOT)

    def test_only_non_bytes_root_is_a_type_error(self):
        evidence = make_evidence()
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_cert_evidence_policy(evidence, bad, now=1.0, max_age=1.0)


class FreshnessTest(unittest.TestCase):
    def test_boundaries_are_inclusive(self):
        evidence = make_evidence(triangle_records(issued_at=10.0))
        result = audit_cert_evidence_policy(
            evidence, ROOT, now=15.0, max_age=5.0
        )
        self.assertTrue(result.accepted)
        # now == issued_at is the lower boundary.
        audit_cert_evidence_policy(evidence, ROOT, now=10.0, max_age=0.0)

    def test_stale_and_future_records_rejected(self):
        evidence = make_evidence(triangle_records(issued_at=10.0))
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, now=15.1, max_age=5.0)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, now=9.9, max_age=5.0)

    def test_now_is_required_once_max_age_is_set(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, max_age=5.0)

    def test_now_and_max_age_contract(self):
        evidence = make_evidence()
        for bad_now in (True, "1", None, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                audit_cert_evidence_policy(
                    evidence, ROOT, now=bad_now, max_age=5.0
                )
        for bad_age in (True, -0.1, float("inf"), float("nan"), "5"):
            with self.assertRaises(ValueError, msg=repr(bad_age)):
                audit_cert_evidence_policy(
                    evidence, ROOT, now=1.0, max_age=bad_age
                )


class TrustRevocationsTest(unittest.TestCase):
    def test_legacy_hit_permanently_rejects(self):
        evidence = make_evidence()
        revocation = revoke_trust(trust("a"), ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=[revocation]
            )
        # The canonical bytes form behaves identically.
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence,
                ROOT,
                now=1.0,
                trust_revocations=[revocation.to_bytes()],
            )

    def test_now_required_for_legacy_revocations(self):
        evidence = make_evidence()
        revocation = revoke_trust(trust("a"), ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, trust_revocations=[revocation]
            )

    def test_unknown_certificate_rejected(self):
        evidence = make_evidence()
        # A validly signed revocation for a certificate the evidence does
        # not carry is itself a contract breach on the legacy path.
        unused = revoke_trust(trust("d"), ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=[unused]
            )
        # Same id but a different certificate MAC is rejected too.
        other_cert = cert("a", 3.0, 0.0, b"\x01" * 32, ROOT)
        other_revocation = revoke_trust(other_cert, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                trust_revocations=[other_revocation],
            )

    def test_wrong_root_and_duplicate_pair_rejected(self):
        evidence = make_evidence()
        revocation = revoke_trust(trust("a"), ROOT)
        forged = revoke_trust(trust("a"), OTHER_ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=[forged]
            )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                trust_revocations=[revocation, revocation],
            )

    def test_bad_item_shape_rejected(self):
        evidence = make_evidence()
        for bad in ([42], [b"not json"], "not-an-iterable-or-list"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence_policy(
                    evidence, ROOT, now=1.0, trust_revocations=bad
                )

    def test_snapshot_only_its_hits_apply(self):
        evidence = make_evidence()
        # A global snapshot carrying only an unrelated certificate passes.
        unrelated = make_crl([revoke_trust(trust("d"), ROOT)], 1, 0.5, ROOT)
        audit_cert_evidence_policy(
            evidence, ROOT, now=1.0, trust_revocations=unrelated
        )
        audit_cert_evidence_policy(
            evidence, ROOT, now=1.0, trust_revocations=unrelated.to_bytes()
        )
        hit = make_crl([revoke_trust(trust("b"), ROOT)], 1, 0.5, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=hit
            )

    def test_snapshot_now_freshness_and_min(self):
        evidence = make_evidence()
        empty = make_crl([], 0, 0.0, ROOT)
        audit_cert_evidence_policy(
            evidence, ROOT, now=1.0, trust_revocations=empty, min=0
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=empty, min=1
            )
        future = make_crl([], 2, 9.0, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=future
            )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, trust_revocations=empty)

    def test_tampered_snapshot_rejected(self):
        evidence = make_evidence()
        snapshot = make_crl([], 1, 0.5, ROOT)
        self.assertIsInstance(snapshot, TrustRevocationList)
        tampered = bytearray(snapshot.to_bytes())
        tampered[-1] ^= 1
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0, trust_revocations=bytes(tampered)
            )


class ObservationRevocationsTest(unittest.TestCase):
    def test_hit_at_or_before_revoked_at_rejects(self):
        evidence = make_evidence(triangle_records(issued_at=2.0))
        revocation = revoke_observation("a", 2.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=3.0,
                observation_revocations=[revocation],
            )

    def test_strictly_later_observation_is_kept(self):
        records = [record("a", 2.0), record("b", 2.0), record("c", 2.0)]
        evidence = make_evidence(records)
        revocation = revoke_observation("a", 1.0, KEY_A)
        result = audit_cert_evidence_policy(
            evidence, ROOT, now=3.0, observation_revocations=[revocation]
        )
        # The surviving observation participates normally: 3 supporters.
        self.assertEqual(result.support, 3)
        self.assertTrue(result.accepted)

    def test_wrong_key_duplicate_unknown_and_future_rejected(self):
        evidence = make_evidence()
        wrong_key = revoke_observation("a", 0.0, b"\x01" * 32)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocations=[wrong_key],
            )
        first = revoke_observation("a", 0.0, KEY_A)
        second = revoke_observation("a", 0.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocations=[first, second],
            )
        unknown = revoke_observation("z", 0.0, b"\x02" * 32)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocations=[unknown],
            )
        future = revoke_observation("a", 5.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocations=[future],
            )

    def test_mixed_objects_bytes_and_bad_shapes(self):
        evidence = make_evidence()
        revocation = revoke_observation("a", 0.0, KEY_A).to_bytes()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocations=[revocation],
            )
        for bad in ([42], [b"not json"], 7):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence_policy(
                    evidence, ROOT, now=1.0,
                    observation_revocations=bad,
                )

    def test_revocation_list_hit_and_min(self):
        evidence = make_evidence(triangle_records(issued_at=0.0))
        snapshot = make_observation_crl(
            [revoke_observation("c", 0.0, KEY_C)], 1, 0.5, ROOT
        )
        self.assertIsInstance(snapshot, ObservationRevocationList)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocation_list=snapshot,
            )
        empty = make_observation_crl([], 0, 0.0, ROOT)
        audit_cert_evidence_policy(
            evidence, ROOT, now=1.0, observation_revocation_list=empty
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocation_list=empty, min=1,
            )

    def test_revocation_list_unknown_id_rejected(self):
        evidence = make_evidence()
        snapshot = make_observation_crl(
            [revoke_observation("z", 0.0, b"\x02" * 32)], 1, 0.5, ROOT
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                observation_revocation_list=snapshot,
            )

    def test_two_observation_sources_stack(self):
        records = [record("a", 2.0), record("b", 2.0), record("c", 2.0)]
        evidence = make_evidence(records)
        per_call = [revoke_observation("a", 1.0, KEY_A)]
        snapshot = make_observation_crl(
            [revoke_observation("b", 1.0, KEY_B)], 1, 1.5, ROOT
        )
        # Both postdate their revocation: both sources checked, all kept.
        result = audit_cert_evidence_policy(
            evidence, ROOT, now=3.0,
            observation_revocations=per_call,
            observation_revocation_list=snapshot,
        )
        self.assertEqual(result.support, 3)
        # Move b's snapshot revocation to its issued_at: b is now rejected.
        later = make_observation_crl(
            [revoke_observation("b", 2.0, KEY_B)], 2, 2.5, ROOT
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=3.0,
                observation_revocations=per_call,
                observation_revocation_list=later,
            )

    def test_combined_trust_and_observation_revocations(self):
        evidence = make_evidence()
        # A trust hit rejects even though the observation would survive.
        trust_revocations = [revoke_trust(trust("c"), ROOT)]
        observation_revocations = [revoke_observation("a", 0.0, KEY_A)]
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=1.0,
                trust_revocations=trust_revocations,
                observation_revocations=observation_revocations,
            )


class PurityTest(unittest.TestCase):
    def test_verifier_trust_objects_are_not_mutated(self):
        trusts = triangle_trusts()
        evidence = make_evidence(trusts=trusts)
        before = [entry.to_bytes() for entry in trusts]
        snapshot = make_crl([], 1, 0.5, ROOT)
        audit_cert_evidence_policy(
            evidence, ROOT, now=1.0,
            max_age=9.0,
            trust_revocations=snapshot,
            observation_revocation_list=make_observation_crl([], 1, 0.5, ROOT),
        )
        self.assertEqual(before, [entry.to_bytes() for entry in trusts])
        # The evidence itself still audits exactly as before afterwards.
        self.assertEqual(
            audit_cert_evidence(evidence, ROOT),
            audit_cert_evidence_policy(evidence, ROOT),
        )


if __name__ == "__main__":
    unittest.main()
