import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListAuditor,
    EvidenceRevocationListBundleReceipt,
    EvidenceRevocationListState,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_PREFIX,
    _encode_payload,
    _evidence_revocation_list_bundle_receipt_content_bytes,
    _evidence_revocation_list_bundle_receipt_signature,
    audit_evidence_revocation_list_bundle,
    audit_evidence_revocation_list_bundle_receipt,
    make_evidence_revocation_list,
    seal_evidence_revocation_list_bundle,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"
ZERO = b"\x00" * 32


def snapshot(entries=(), *, sequence, issued_at=100.0, key=KEY):
    return make_evidence_revocation_list(list(entries), sequence, issued_at, key)


def reencode(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def reseal_bundle(obj, key=KEY):
    """Re-sign a decoded bundle object with a fresh NPEB1 MAC over its
    first four fields, so one field can be tampered while the outer MAC
    stays valid."""
    payload = {
        field: obj[field]
        for field in ("version", "start", "snapshots", "end")
    }
    obj["mac"] = hmac.new(
        key,
        _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX + _encode_payload(payload),
        hashlib.sha256,
    ).digest().hex()
    return reencode(obj)


def receipt_for(bundle, key=KEY, *, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPEBR1 signature recomputed over
    the first four fields; ``start``/``end``/``digest`` default to the
    honest values."""
    placeholder = EvidenceRevocationListBundleReceipt(
        1,
        bundle.start if start is None else start,
        (
            hashlib.sha256(bundle.to_bytes()).digest()
            if digest is None
            else digest
        ),
        bundle.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        signature=_evidence_revocation_list_bundle_receipt_signature(
            key, placeholder
        ),
    )


class BundleReceiptContractTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1], KEY, 100.0
        )
        self.end = EvidenceRevocationListState.from_bytes(self.bundle.end)

    def make(self, **overrides):
        values = {
            "version": 1,
            "start": b"",
            "bundle_digest": hashlib.sha256(self.bundle.to_bytes()).digest(),
            "end": self.end.to_bytes(),
            "signature": b"\x09" * 32,
        }
        values.update(overrides)
        return EvidenceRevocationListBundleReceipt(
            values["version"],
            values["start"],
            values["bundle_digest"],
            values["end"],
            values["signature"],
        )

    def test_field_order_positionally_frozen_equal_by_fields(self):
        honest = receipt_for(self.bundle)
        self.assertEqual(
            [field.name for field in dataclasses.fields(honest)],
            ["version", "start", "bundle_digest", "end", "signature"],
        )
        self.assertFalse(hasattr(honest, "key"))
        self.assertNotIn("key", honest.__dict__)
        second = EvidenceRevocationListBundleReceipt(
            honest.version,
            bytes(honest.start),
            bytes(honest.bundle_digest),
            bytes(honest.end),
            bytes(honest.signature),
        )
        self.assertEqual(second, honest)
        self.assertEqual(hash(second), hash(honest))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            honest.signature = ZERO

    def test_version_shape_vs_value(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(version=bad)

    def test_start_empty_or_canonical_state_bytes(self):
        for bad in ("", [], None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(start=bad)
        for bad in (b"not-json", b"[]", self.end.to_bytes() + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(start=bad)
        # b"" and the canonical state bytes both work.
        self.make(start=b"")
        self.make(start=self.end.to_bytes())

    def test_bundle_digest_exactly_32_bytes(self):
        for bad in ("ab" * 32, None, 7, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(bundle_digest=bad)
        for bad in (b"", ZERO[:-1], ZERO + b"\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(bundle_digest=bad)

    def test_end_canonical_nonempty_state_bytes(self):
        for bad in ("", None, 7, bytearray(self.end.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(end=bad)
        for bad in (b"", b"not-json", b"[]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(end=bad)

    def test_signature_exactly_32_bytes(self):
        for bad in ("ab" * 32, None, 7, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(signature=bad)
        for bad in (b"", ZERO[:-1], ZERO + b"\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(signature=bad)


class BundleReceiptEncodingTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def test_compact_lowercase_hex_array_shape(self):
        raw = self.receipt.to_bytes()
        outer = json.loads(raw)
        self.assertIsInstance(outer, list)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], "")
        self.assertEqual(
            outer[2], hashlib.sha256(self.bundle.to_bytes()).hexdigest()
        )
        self.assertEqual(outer[3], self.bundle.end.hex())
        self.assertEqual(outer[4], self.receipt.signature.hex())
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode())

    def test_round_trip_byte_for_byte(self):
        raw = self.receipt.to_bytes()
        parsed = EvidenceRevocationListBundleReceipt.from_bytes(raw)
        self.assertEqual(parsed, self.receipt)
        self.assertEqual(parsed.to_bytes(), raw)

    def test_non_empty_start_round_trips(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle(
            seal_evidence_revocation_list_bundle([self.s1], KEY, 100.0),
            100.0,
        )
        cont = seal_evidence_revocation_list_bundle(
            [self.s2], KEY, 100.0, start=auditor.checkpoint
        )
        receipt = auditor.audit_bundle_receipt(cont, 100.0)
        raw = receipt.to_bytes()
        self.assertEqual(
            EvidenceRevocationListBundleReceipt.from_bytes(raw), receipt
        )
        self.assertEqual(
            EvidenceRevocationListBundleReceipt.from_bytes(raw).to_bytes(),
            raw,
        )
        self.assertEqual(json.loads(raw)[1], cont.start.hex())

    def test_parse_does_not_verify_signature(self):
        unsigned = dataclasses.replace(self.receipt, signature=ZERO)
        parsed = EvidenceRevocationListBundleReceipt.from_bytes(
            unsigned.to_bytes()
        )
        self.assertEqual(parsed, unsigned)

    def test_data_must_be_bytes(self):
        for bad in (
            1,
            "x",
            None,
            [self.receipt.to_bytes()],
            object(),
            True,
        ):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceipt.from_bytes(bad)

    def test_malformed_and_non_canonical_rejected(self):
        raw = self.receipt.to_bytes()
        for bad in (
            b"junk",
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
            b" " + raw,
            raw + b" ",
            raw.replace(b",", b", ", 1),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceipt.from_bytes(bad)

    def test_wrong_field_type_is_type_error(self):
        # A string version (right array shape, wrong field shape) surfaces
        # as TypeError from the parser itself.
        obj = json.loads(self.receipt.to_bytes())
        obj[0] = "1"
        with self.assertRaises(TypeError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))


class BundleReceiptSignatureTest(unittest.TestCase):
    def test_signature_is_npebr1_over_first_four_fields(self):
        s1 = snapshot(sequence=1)
        bundle = seal_evidence_revocation_list_bundle([s1], KEY, 100.0)
        receipt = receipt_for(bundle)
        self.assertEqual(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_PREFIX, b"NPEBR1"
        )
        expected = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_PREFIX
            + _evidence_revocation_list_bundle_receipt_content_bytes(receipt),
            hashlib.sha256,
        ).digest()
        self.assertEqual(receipt.signature, expected)
        self.assertEqual(
            receipt.signature,
            _evidence_revocation_list_bundle_receipt_signature(KEY, receipt),
        )
        self.assertEqual(len(receipt.signature), 32)
        # The label itself distinguishes the domain.
        wrong = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX
            + _evidence_revocation_list_bundle_receipt_content_bytes(receipt),
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(wrong, receipt.signature)


class AuditBundleReceiptMintingTest(unittest.TestCase):
    def setUp(self):
        self.snaps = [snapshot(sequence=n) for n in range(1, 4)]

    def test_mints_receipt_and_advances(self):
        bundle = seal_evidence_revocation_list_bundle(
            self.snaps[:2], KEY, 100.0
        )
        auditor = EvidenceRevocationListAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(bundle, 100.0)
        self.assertIsInstance(receipt, EvidenceRevocationListBundleReceipt)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, bundle.end)
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(bundle.to_bytes()).digest(),
        )
        self.assertEqual(
            receipt.signature,
            _evidence_revocation_list_bundle_receipt_signature(KEY, receipt),
        )

    def test_does_not_return_auditor(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        self.assertNotIsInstance(
            auditor.audit_bundle_receipt(bundle, 100.0),
            EvidenceRevocationListAuditor,
        )

    def test_accepts_canonical_bytes_and_chains(self):
        first = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        auditor = EvidenceRevocationListAuditor(KEY)
        r1 = auditor.audit_bundle_receipt(first.to_bytes(), 100.0)
        self.assertEqual(r1, receipt_for(first))
        cont = seal_evidence_revocation_list_bundle(
            [self.snaps[1], self.snaps[2]],
            KEY,
            100.0,
            start=auditor.checkpoint,
        )
        r2 = auditor.audit_bundle_receipt(cont, 100.0)
        self.assertEqual(auditor.checkpoint.sequence, 3)
        self.assertEqual(r2.start, first.end)
        self.assertEqual(r2, receipt_for(cont))
        # Restarting from the exported checkpoint yields the same receipt
        # for the continuation.
        restarted = EvidenceRevocationListAuditor(
            KEY, checkpoint=first.end
        )
        self.assertEqual(
            restarted.audit_bundle_receipt(cont, 100.0), r2
        )

    def test_replay_rejected_without_receipt_or_rollback(self):
        bundle = seal_evidence_revocation_list_bundle(
            self.snaps[:2], KEY, 100.0
        )
        auditor = EvidenceRevocationListAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(bundle, 100.0)
        checkpoint = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle, 100.0)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle.to_bytes(), 100.0)
        self.assertIs(auditor.checkpoint, checkpoint)
        # Nothing about the first receipt changed.
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                receipt, bundle, KEY
            ).sequence,
            2,
        )

    def test_failure_mints_nothing_and_keeps_state(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        good = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        auditor.audit_bundle(good, 100.0)
        checkpoint = auditor.checkpoint
        # A continuation whose carried snapshot was tampered: valid
        # starting point, broken body -> ValueError, no state change.
        obj = json.loads(
            seal_evidence_revocation_list_bundle(
                [self.snaps[1]], KEY, 100.0, start=checkpoint
            ).to_bytes()
        )
        obj["snapshots"][0] = self.snaps[0].to_bytes().hex()
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(reseal_bundle(obj), 100.0)
        self.assertIs(auditor.checkpoint, checkpoint)
        # A wrong-start bundle fails before anything is minted.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(
                seal_evidence_revocation_list_bundle(
                    [self.snaps[1], self.snaps[2]], KEY, 100.0
                ),
                100.0,
            )
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_type_and_value_split(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        for bad in (object(), 42, None, "x"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad, 100.0)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(b"junk", 100.0)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle, "100")
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(OTHER_KEY).audit_bundle_receipt(
                bundle, 100.0
            )

    def test_shares_lock_with_other_entry_points(self):
        forks = [
            seal_evidence_revocation_list_bundle([snap], KEY, 100.0)
            for snap in self.snaps
        ]
        auditor = EvidenceRevocationListAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(len(forks) + 1)

        def run(bundle, use_receipt):
            barrier.wait()
            try:
                if use_receipt:
                    auditor.audit_bundle_receipt(bundle, 100.0)
                else:
                    auditor.audit_bundle(bundle, 100.0)
                outcomes.append(True)
            except ValueError:
                outcomes.append(False)

        threads = [
            threading.Thread(target=run, args=(bundle, index % 2 == 0))
            for index, bundle in enumerate(forks)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        # Competing empty-start forks: exactly one commits.
        self.assertEqual(sum(outcomes), 1)
        self.assertIn(auditor.checkpoint.sequence, range(1, 4))


class AuditEvidenceRevocationListBundleReceiptTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def test_success_returns_end_frontier(self):
        end = audit_evidence_revocation_list_bundle_receipt(
            self.receipt, self.bundle, KEY
        )
        self.assertIsInstance(end, EvidenceRevocationListState)
        self.assertEqual(
            end, EvidenceRevocationListState.from_bytes(self.bundle.end)
        )
        self.assertEqual(
            end, audit_evidence_revocation_list_bundle(self.bundle, KEY, 100.0)
        )

    def test_accepts_objects_or_canonical_bytes(self):
        end = EvidenceRevocationListState.from_bytes(self.bundle.end)
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt.to_bytes(), self.bundle.to_bytes(), KEY
            ),
            end,
        )
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, self.bundle.to_bytes(), KEY
            ),
            end,
        )
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt.to_bytes(), self.bundle, KEY
            ),
            end,
        )

    def test_round_trip_then_review(self):
        produced = EvidenceRevocationListAuditor(KEY).audit_bundle_receipt(
            self.bundle, 100.0
        )
        transported = EvidenceRevocationListBundleReceipt.from_bytes(
            produced.to_bytes()
        )
        self.assertEqual(transported, produced)
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                transported, self.bundle, KEY
            ),
            EvidenceRevocationListState.from_bytes(self.bundle.end),
        )

    def test_stateless_touches_no_auditor(self):
        # An independent third party needs no auditor at all; and re-checking
        # the bundle cannot read or move any auditor's frontier.
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle_receipt(self.bundle, 100.0)
        first = seal_evidence_revocation_list_bundle([self.s1], KEY, 100.0)
        first_receipt = EvidenceRevocationListBundleReceipt.from_bytes(
            EvidenceRevocationListAuditor(KEY)
            .audit_bundle_receipt(first, 100.0)
            .to_bytes()
        )
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                first_receipt, first, KEY
            ),
            EvidenceRevocationListState.from_bytes(first.end),
        )
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_no_freshness_policy_without_a_clock(self):
        # The stateless review takes no now/min: a future-dated snapshot the
        # clocked entry points refuse still reviews on signature + chain.
        future_snap = snapshot(sequence=1, issued_at=400.0)
        future_bundle = seal_evidence_revocation_list_bundle(
            [future_snap], KEY, 400.0
        )
        future_receipt = receipt_for(future_bundle)
        end = audit_evidence_revocation_list_bundle_receipt(
            future_receipt, future_bundle, KEY
        )
        self.assertEqual(end, EvidenceRevocationListState.from_bytes(
            future_bundle.end
        ))


class ReceiptDigestBindingTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def test_digest_equals_sha256_of_canonical_bundle_bytes(self):
        s1 = snapshot(sequence=1)
        bundle = seal_evidence_revocation_list_bundle([s1], KEY, 100.0)
        receipt = receipt_for(bundle)
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(bundle.to_bytes()).digest(),
        )

    def test_receipt_binds_exactly_one_bundle(self):
        # Two individually valid, NPEB1-sealed bundles with the SAME empty
        # start and the SAME end frontier (the end state binds only the last
        # snapshot's sequence/digest) but different definite bodies: a
        # receipt minted over one must not admit the other, even though
        # every endpoint MAC verifies for both.
        s1 = snapshot(sequence=1)
        s1_alt = snapshot(sequence=1, issued_at=50.0)
        self.assertNotEqual(s1.to_bytes(), s1_alt.to_bytes())
        s2 = snapshot(sequence=2)
        bundle_a = seal_evidence_revocation_list_bundle(
            [s1, s2], KEY, 100.0
        )
        bundle_b = seal_evidence_revocation_list_bundle(
            [s1_alt, s2], KEY, 100.0
        )
        self.assertEqual(bundle_a.start, bundle_b.start)
        self.assertEqual(bundle_a.end, bundle_b.end)
        self.assertNotEqual(bundle_a.to_bytes(), bundle_b.to_bytes())
        # Both bundles verify fully on their own.
        self.assertEqual(
            audit_evidence_revocation_list_bundle(bundle_b, KEY, 100.0),
            EvidenceRevocationListState.from_bytes(bundle_b.end),
        )
        receipt = receipt_for(bundle_a)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt, bundle_b, KEY
            )

    def test_receipt_over_one_bundle_rejected_for_another(self):
        s1 = snapshot(sequence=1)
        s2 = snapshot(sequence=2)
        b1 = seal_evidence_revocation_list_bundle([s1], KEY, 100.0)
        b2 = seal_evidence_revocation_list_bundle([s1, s2], KEY, 100.0)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt_for(b1), b2, KEY
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt_for(b2), b1, KEY
            )

    def test_wrong_digest_field_rejected(self):
        bad = dataclasses.replace(
            self.receipt, bundle_digest=b"\x09" * 32
        )
        bad = dataclasses.replace(
            bad,
            signature=_evidence_revocation_list_bundle_receipt_signature(
                KEY, bad
            ),
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                bad, self.bundle, KEY
            )

    def test_endpoint_mismatch_rejected(self):
        s3 = snapshot(sequence=3)
        other = seal_evidence_revocation_list_bundle([s3], KEY, 100.0)
        # Receipt naming another bundle's end over this bundle's body.
        forged = receipt_for(self.bundle, end=other.end)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                forged, self.bundle, KEY
            )


class ReceiptReviewViolationTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def test_wrong_argument_kinds_are_type_errors(self):
        for bad in (1, "x", None, [self.receipt], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt(
                    bad, self.bundle, KEY
                )
        for bad in (1, "x", None, [self.bundle], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt(
                    self.receipt, bad, KEY
                )

    def test_key_shape_empty_and_wrong(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt(
                    self.receipt, self.bundle, bad
                )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, self.bundle, b""
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, self.bundle, OTHER_KEY
            )

    def test_non_canonical_bytes_are_value_errors(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt.to_bytes() + b" ", self.bundle, KEY
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, b"junk", KEY
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                b"junk", self.bundle, KEY
            )

    def test_tampered_signature_rejected(self):
        bad = dataclasses.replace(self.receipt, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                bad, self.bundle, KEY
            )

    def test_wrong_domain_signature_rejected(self):
        wrong = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX
            + _evidence_revocation_list_bundle_receipt_content_bytes(
                self.receipt
            ),
            hashlib.sha256,
        ).digest()
        bad = dataclasses.replace(self.receipt, signature=wrong)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                bad, self.bundle, KEY
            )

    def test_tampered_carried_snapshot_rejected_even_with_outer_mac(self):
        obj = json.loads(self.bundle.to_bytes())
        snap_obj = json.loads(bytes.fromhex(obj["snapshots"][0]))
        snap_obj["mac"] = "00" * 32
        obj["snapshots"][0] = reencode(snap_obj).hex()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, reseal_bundle(obj), KEY
            )

    def test_tampered_endpoint_rejected_even_with_outer_mac(self):
        s1 = snapshot(sequence=1)
        s2 = snapshot(sequence=2)
        bundle = seal_evidence_revocation_list_bundle(
            [s1, s2], KEY, 100.0
        )
        receipt = receipt_for(bundle)
        obj = json.loads(bundle.to_bytes())
        forged_end = EvidenceRevocationListState(
            1, 2, hashlib.sha256(s2.to_bytes()).digest(), b"\x08" * 32
        )
        obj["end"] = forged_end.to_bytes().hex()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt, reseal_bundle(obj), KEY
            )


class BundleReceiptExportsTest(unittest.TestCase):
    def test_api_is_exported(self):
        import nearproof

        for name in (
            "EvidenceRevocationListBundleReceipt",
            "audit_evidence_revocation_list_bundle_receipt",
        ):
            self.assertIn(name, nearproof.__all__)
            self.assertIs(getattr(nearproof, name), getattr(nearproof, name))
        self.assertTrue(
            hasattr(
                nearproof.EvidenceRevocationListAuditor,
                "audit_bundle_receipt",
            )
        )
        # No new alias attributes: the entry points are exactly these.
        self.assertFalse(
            hasattr(nearproof, "evidence_revocation_list_bundle_receipt")
        )


if __name__ == "__main__":
    unittest.main()
