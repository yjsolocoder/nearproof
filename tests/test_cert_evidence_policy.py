import dataclasses
import unittest

from nearproof import (
    Consensus,
    RangeDecision,
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


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident, *, root=ROOT, key=None, x=None, y=None):
    px, py = POSITIONS[ident]
    return cert(ident, x if x is not None else px, y if y is not None else py,
                key or KEYS[ident], root)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT,
           issued_at=0.0):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), point, context, issued_at,
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


def make_evidence(records=None, trusts=None):
    return locate_cert_evidence(
        triangle_records() if records is None else records,
        POINT, CONTEXT,
        triangle_trusts() if trusts is None else trusts,
        ROOT,
    )


class CertEvidencePolicyDefaultTest(unittest.TestCase):
    def test_matches_existing_audit_item_for_item(self):
        evidence = make_evidence()
        expected = Consensus(total=3, support=3, rejected=(), accepted=True)
        for artifact in (evidence, evidence.to_bytes()):
            result = audit_cert_evidence_policy(artifact, ROOT)
            self.assertIsInstance(result, Consensus)
            self.assertEqual(result, audit_cert_evidence(artifact, ROOT))
            self.assertEqual(result, expected)

    def test_now_and_min_are_ignored_without_a_policy(self):
        evidence = make_evidence()
        audit_cert_evidence_policy(evidence, ROOT, now="ignored")
        audit_cert_evidence_policy(evidence, ROOT, min=True)
        audit_cert_evidence_policy(
            evidence, ROOT, now=None, max_age=None, trust_revocations=None,
            observation_revocations=None, observation_revocation_list=None,
        )

    def test_baseline_review_runs_first(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, OTHER_ROOT)
        tampered = dataclasses.replace(
            evidence, mac=bytes(a ^ 1 for a in evidence.mac)
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(tampered, ROOT, now=0.0)

    def test_root_type_split_is_unchanged(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_cert_evidence_policy(evidence, bad)

    def test_x_must_be_evidence_or_bytes(self):
        for bad in ("x", 123, None, {}, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence_policy(bad, ROOT)


class CertEvidencePolicyClockTest(unittest.TestCase):
    def test_now_required_with_any_policy(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, max_age=1.0)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, trust_revocations=[])
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, observation_revocations=[]
            )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT,
                observation_revocation_list=make_observation_crl([], 0, 0.0, ROOT),
            )

    def test_now_contract(self):
        evidence = make_evidence()
        for bad in (True, "1", None, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence_policy(evidence, ROOT, now=bad, max_age=1.0)

    def test_max_age_contract(self):
        evidence = make_evidence()
        for bad in (True, "1", -0.1, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence_policy(evidence, ROOT, now=0.0, max_age=bad)

    def test_closed_freshness_interval_boundaries(self):
        evidence = make_evidence()  # every issued_at == 0.0
        self.assertEqual(
            audit_cert_evidence_policy(evidence, ROOT, now=0.0, max_age=0.0),
            audit_cert_evidence(evidence, ROOT),
        )
        result = audit_cert_evidence_policy(
            evidence, ROOT, now=5.0, max_age=5.0
        )
        self.assertTrue(result.accepted)

    def test_stale_observation_rejected(self):
        evidence = make_evidence()
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, now=5.0001, max_age=5.0)

    def test_future_dated_observation_rejected(self):
        records = [record("a", issued_at=2.0), record("b", issued_at=2.0),
                   record("c", issued_at=2.0)]
        evidence = make_evidence(records)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(evidence, ROOT, now=1.0, max_age=10.0)

    def test_check_runs_per_observation(self):
        records = [record("a", issued_at=0.0), record("b", issued_at=4.0),
                   record("c", issued_at=2.0)]
        evidence = make_evidence(records)
        with self.assertRaises(ValueError):
            # "a" is stale even if "b" and "c" are within the window.
            audit_cert_evidence_policy(evidence, ROOT, now=5.0, max_age=2.0)
        audit_cert_evidence_policy(evidence, ROOT, now=5.0, max_age=5.0)


class CertEvidencePolicyTrustTest(unittest.TestCase):
    def setUp(self):
        self.trusts = triangle_trusts()
        self.evidence = make_evidence(trusts=self.trusts)

    def test_matching_revocation_permanently_rejects(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=1000.0,
                trust_revocations=[revocation],
            )

    def test_accepts_canonical_bytes(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[revocation.to_bytes()],
            )

    def test_wrong_root_rejected(self):
        revocation = revoke_trust(self.trusts[0], OTHER_ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[revocation],
            )

    def test_tampered_revocation_rejected(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        tampered = dataclasses.replace(
            revocation, mac=bytes(a ^ 1 for a in revocation.mac)
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[tampered],
            )

    def test_duplicate_pair_rejected(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[revocation, revocation],
            )

    def test_target_for_other_certificate_same_id_rejected(self):
        other_cert = cert("a", 3.0, 0.0, b"\x01" * 32, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[revoke_trust(other_cert, ROOT)],
            )

    def test_unknown_id_rejected(self):
        other_cert = cert("zz", 1.0, 1.0, b"\x02" * 32, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[revoke_trust(other_cert, ROOT)],
            )

    def test_bad_items_and_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=[42]
            )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=[b"{}"]
            )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=42
            )

    def test_snapshot_object_and_bytes_reject(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        crl = make_crl([revocation], 1, 0.0, ROOT)
        for artifact in (crl, crl.to_bytes()):
            with self.assertRaises(ValueError, msg=type(artifact)):
                audit_cert_evidence_policy(
                    self.evidence, ROOT, now=0.0,
                    trust_revocations=artifact,
                )

    def test_snapshot_sequence_floor(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        crl = make_crl([revocation], 1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=crl, min=2
            )
        for bad in (True, 1.0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence_policy(
                    self.evidence, ROOT, now=0.0,
                    trust_revocations=crl, min=bad,
                )

    def test_future_dated_snapshot_rejected(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        crl = make_crl([revocation], 1, 5.0, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=crl
            )

    def test_snapshot_entry_for_unknown_certificate_rejected(self):
        other_cert = cert("zz", 1.0, 1.0, b"\x02" * 32, ROOT)
        crl = make_crl([revoke_trust(other_cert, ROOT)], 1, 0.0, ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=crl
            )

    def test_tampered_snapshot_mac_rejected(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        crl = make_crl([revocation], 1, 0.0, ROOT)
        tampered = dataclasses.replace(crl, mac=bytes(a ^ 1 for a in crl.mac))
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0, trust_revocations=tampered
            )

    def test_min_ignored_for_iterable_form(self):
        revocation = revoke_trust(self.trusts[0], ROOT)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                trust_revocations=[revocation], min=99,
            )


class CertEvidencePolicyObservationTest(unittest.TestCase):
    def setUp(self):
        self.trusts = triangle_trusts()
        self.evidence = make_evidence(trusts=self.trusts)

    def test_observation_at_or_before_revoked_at_rejected(self):
        revocation = revoke_observation("a", 0.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[revocation],
            )

    def test_observation_strictly_after_revocation_survives(self):
        records = [record("a", issued_at=2.0), record("b"), record("c")]
        evidence = make_evidence(records, self.trusts)
        revocation = revoke_observation("a", 1.0, KEY_A)
        result = audit_cert_evidence_policy(
            evidence, ROOT, now=2.0,
            observation_revocations=[revocation],
        )
        self.assertEqual(result, audit_cert_evidence(evidence, ROOT))

    def test_wrong_key_rejected(self):
        revocation = revoke_observation("a", 0.0, KEY_B)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[revocation],
            )

    def test_tampered_revocation_rejected(self):
        revocation = revoke_observation("a", 0.0, KEY_A)
        tampered = dataclasses.replace(
            revocation, mac=bytes(a ^ 1 for a in revocation.mac)
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[tampered],
            )

    def test_duplicate_id_rejected(self):
        revocation = revoke_observation("a", 0.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[revocation, revocation],
            )

    def test_unknown_id_rejected(self):
        revocation = revoke_observation("zz", 0.0, b"\x03" * 32)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[revocation],
            )

    def test_future_dated_revocation_rejected(self):
        revocation = revoke_observation("a", 1.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[revocation],
            )

    def test_bad_items_and_bytes_rejected(self):
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[42],
            )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[b"{}"],
            )

    def test_snapshot_object_and_bytes(self):
        snapshot = make_observation_crl(
            [revoke_observation("a", 0.0, KEY_A)], 1, 0.0, ROOT
        )
        for artifact in (snapshot, snapshot.to_bytes()):
            with self.assertRaises(ValueError, msg=type(artifact)):
                audit_cert_evidence_policy(
                    self.evidence, ROOT, now=0.0,
                    observation_revocation_list=artifact,
                )

    def test_snapshot_strictly_later_observation_survives(self):
        records = [record("a", issued_at=2.0), record("b"), record("c")]
        evidence = make_evidence(records, self.trusts)
        snapshot = make_observation_crl(
            [revoke_observation("a", 1.0, KEY_A)], 1, 2.0, ROOT
        )
        result = audit_cert_evidence_policy(
            evidence, ROOT, now=2.0,
            observation_revocation_list=snapshot,
        )
        self.assertEqual(result, audit_cert_evidence(evidence, ROOT))

    def test_snapshot_bad_type_rejected(self):
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocation_list=42,
            )

    def test_snapshot_sequence_floor(self):
        snapshot = make_observation_crl(
            [revoke_observation("a", 0.0, KEY_A)], 1, 0.0, ROOT
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocation_list=snapshot, min=2,
            )

    def test_snapshot_unknown_id_rejected(self):
        snapshot = make_observation_crl(
            [revoke_observation("zz", 0.0, b"\x03" * 32)], 1, 0.0, ROOT
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocation_list=snapshot,
            )

    def test_snapshot_wrong_root_rejected(self):
        snapshot = make_observation_crl(
            [revoke_observation("a", 0.0, KEY_A)], 1, 0.0, OTHER_ROOT
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocation_list=snapshot,
            )

    def test_iterable_and_snapshot_stack_with_latest_winning(self):
        records = [record("a", issued_at=1.0), record("b"), record("c")]
        evidence = make_evidence(records, self.trusts)
        older = revoke_observation("a", 0.5, KEY_A)
        snapshot = make_observation_crl(
            [revoke_observation("a", 1.5, KEY_A)], 1, 2.0, ROOT
        )
        audit_cert_evidence_policy(
            evidence, ROOT, now=2.0, observation_revocations=[older]
        )
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                evidence, ROOT, now=2.0,
                observation_revocations=[older],
                observation_revocation_list=snapshot,
            )

    def test_is_pure(self):
        revocation = revoke_observation("a", 0.0, KEY_A)
        with self.assertRaises(ValueError):
            audit_cert_evidence_policy(
                self.evidence, ROOT, now=0.0,
                observation_revocations=[revocation],
            )
        self.assertEqual(
            audit_cert_evidence_policy(self.evidence, ROOT),
            audit_cert_evidence(self.evidence, ROOT),
        )


if __name__ == "__main__":
    unittest.main()
