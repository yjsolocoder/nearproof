import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationListAuditor,
    EvidenceRevocationListBundle,
    EvidenceRevocationListBundleReceipt,
    EvidenceRevocationListState,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_PREFIX,
    _encode_payload,
    _evidence_revocation_list_bundle_receipt_mac,
    _evidence_revocation_list_bundle_receipt_payload,
    audit_evidence_revocation_list_bundle,
    audit_evidence_revocation_list_bundle_receipt,
    make_evidence_revocation_list,
    seal_evidence_revocation_list_bundle,
)
from test_evidence_revocation_list_bundle import (
    KEY,
    OTHER_KEY,
    frontier_for,
    reseal,
    snapshot,
)

ZERO = b"\x00" * 32


def receipt_for(bundle, key=KEY, *, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPEBR1 mac recomputed over the
    first four fields; ``start``/``end``/``digest`` default to the honest
    bundle values."""
    placeholder = EvidenceRevocationListBundleReceipt(
        1,
        bundle.start if start is None else start,
        hashlib.sha256(bundle.to_bytes()).digest()
        if digest is None
        else digest,
        bundle.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        mac=_evidence_revocation_list_bundle_receipt_mac(key, placeholder),
    )


def reencode(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


class EvidenceRevocationListBundleReceiptContractTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def make(self, **overrides):
        values = {
            "version": 1,
            "start": b"",
            "bundle_digest": hashlib.sha256(self.bundle.to_bytes()).digest(),
            "end": self.bundle.end,
            "mac": b"\x09" * 32,
        }
        values.update(overrides)
        return EvidenceRevocationListBundleReceipt(
            values["version"],
            values["start"],
            values["bundle_digest"],
            values["end"],
            values["mac"],
        )

    def test_is_frozen_and_equal_by_fields(self):
        second = EvidenceRevocationListBundleReceipt(
            1,
            bytes(self.receipt.start),
            bytes(self.receipt.bundle_digest),
            bytes(self.receipt.end),
            bytes(self.receipt.mac),
        )
        self.assertEqual(self.receipt, second)
        self.assertEqual(hash(self.receipt), hash(second))
        self.assertFalse(hasattr(self.receipt, "key"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.receipt.end = b""

    def test_positional_field_order(self):
        receipt = self.make()
        self.assertEqual(
            (
                receipt.version,
                receipt.start,
                receipt.bundle_digest,
                receipt.end,
                receipt.mac,
            ),
            (
                1,
                b"",
                hashlib.sha256(self.bundle.to_bytes()).digest(),
                self.bundle.end,
                b"\x09" * 32,
            ),
        )

    def test_version_shape_vs_value(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError):
                self.make(version=bad)
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError):
                self.make(version=bad)

    def test_start_empty_or_canonical_state_bytes(self):
        for bad in ("", [], None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(start=bad)
        for bad in (b"not-json", b"[]", self.bundle.end + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(start=bad)
        # The empty start and a canonical non-empty frontier both fit.
        self.make(start=b"")
        self.make(start=self.bundle.end)

    def test_bundle_digest_exactly_32_bytes(self):
        for bad in ("ab" * 32, None, 7, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(bundle_digest=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(bundle_digest=bad)

    def test_end_canonical_nonempty_state_bytes(self):
        for bad in ("", None, 7, bytearray(self.bundle.end)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(end=bad)
        for bad in (b"", b"not-json", b"[]", self.bundle.end + b" "):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(end=bad)

    def test_mac_exactly_32_bytes(self):
        for bad in ("ab" * 32, None, 7, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(mac=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(mac=bad)


class EvidenceRevocationListBundleReceiptEncodingTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def test_to_bytes_shape(self):
        obj = json.loads(self.receipt.to_bytes())
        self.assertEqual(
            list(obj),
            ["version", "start", "bundle_digest", "end", "mac"],
        )
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["start"], "")
        self.assertEqual(
            obj["bundle_digest"], self.receipt.bundle_digest.hex()
        )
        self.assertEqual(obj["end"], self.receipt.end.hex())
        self.assertEqual(obj["mac"], self.receipt.mac.hex())
        # Compact JSON with no whitespace or length prefix.
        self.assertNotIn(b" ", self.receipt.to_bytes())

    def test_non_empty_start_encodes_as_lowercase_hex(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 100.0)
        cont = seal_evidence_revocation_list_bundle(
            [self.s2], KEY, 100.0, start=auditor.checkpoint
        )
        receipt = receipt_for(cont)
        self.assertEqual(receipt.start, auditor.checkpoint.to_bytes())
        obj = json.loads(receipt.to_bytes())
        self.assertEqual(obj["start"], receipt.start.hex())
        self.assertEqual(obj["end"], receipt.end.hex())

    def test_round_trip(self):
        blob = self.receipt.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(
            EvidenceRevocationListBundleReceipt.from_bytes(blob), self.receipt
        )
        self.assertEqual(
            EvidenceRevocationListBundleReceipt.from_bytes(blob).to_bytes(),
            blob,
        )

    def test_data_must_be_bytes(self):
        blob = self.receipt.to_bytes()
        for bad in (blob.decode(), None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundleReceipt.from_bytes(bad)

    def test_malformed_and_wrong_shape_rejected(self):
        for bad in (b"", b"junk", b"[]", b"[1,2,3,4,5]", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceipt.from_bytes(bad)

    def test_missing_extra_reordered_and_duplicate_keys_rejected(self):
        encoding = self.receipt.to_bytes()
        obj = json.loads(encoding)
        del obj["end"]
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        obj["extra"] = 0
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        reordered = {name: obj[name] for name in reversed(list(obj))}
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(reordered))
        duplicated = encoding.replace(b'"version":1', b'"version":1,"version":1')
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(duplicated)

    def test_non_canonical_spellings_rejected(self):
        encoding = self.receipt.to_bytes()
        for bad in (
            b" " + encoding,
            encoding + b" ",
            encoding.replace(b',"', b', "'),
            encoding.replace(
                self.receipt.mac.hex().encode(),
                self.receipt.mac.hex().upper().encode(),
            ),
            encoding.replace(b'{"version":1', b'{"version":2', 1),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundleReceipt.from_bytes(bad)

    def test_bad_field_values(self):
        obj = json.loads(self.receipt.to_bytes())
        # A non-canonical nested state in either endpoint.
        obj["end"] = self.receipt.end.hex() + "00"
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))
        obj = json.loads(self.receipt.to_bytes())
        obj["end"] = ""
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))
        obj = json.loads(self.receipt.to_bytes())
        obj["bundle_digest"] = "00"
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))
        obj = json.loads(self.receipt.to_bytes())
        obj["mac"] = "00"
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundleReceipt.from_bytes(reencode(obj))

    def test_from_bytes_does_not_verify_mac(self):
        tampered = dataclasses.replace(self.receipt, mac=ZERO)
        parsed = EvidenceRevocationListBundleReceipt.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_mac_scheme_is_npebr1_over_unsigned_encoding(self):
        unsigned = _encode_payload(
            _evidence_revocation_list_bundle_receipt_payload(self.receipt)
        )
        expected = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_PREFIX + unsigned,
            hashlib.sha256,
        ).digest()
        self.assertEqual(self.receipt.mac, expected)
        self.assertEqual(
            self.receipt.mac,
            _evidence_revocation_list_bundle_receipt_mac(KEY, self.receipt),
        )
        self.assertEqual(
            _EVIDENCE_REVOCATION_LIST_BUNDLE_RECEIPT_PREFIX, b"NPEBR1"
        )
        # The label itself distinguishes the domain from the bundle MAC.
        self.assertNotEqual(
            self.receipt.mac,
            hmac.new(KEY, b"NPEB1" + unsigned, hashlib.sha256).digest(),
        )


class AuditorAuditBundleReceiptTest(unittest.TestCase):
    def setUp(self):
        self.snaps = [snapshot(sequence=n) for n in range(1, 5)]

    def test_commit_returns_receipt_and_advances(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            self.snaps[:2], KEY, 100.0
        )
        receipt = auditor.audit_bundle_receipt(bundle, 100.0)
        self.assertIsInstance(receipt, EvidenceRevocationListBundleReceipt)
        self.assertEqual(receipt, receipt_for(bundle))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(bundle.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, bundle.end)
        self.assertEqual(receipt.mac, _evidence_revocation_list_bundle_receipt_mac(KEY, receipt))
        self.assertEqual(
            auditor.checkpoint,
            audit_evidence_revocation_list_bundle(bundle, KEY, 100.0),
        )
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        receipt = auditor.audit_bundle_receipt(bundle.to_bytes(), 100.0)
        self.assertEqual(receipt, receipt_for(bundle))

    def test_continues_from_non_empty_frontier(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle_receipt(
            seal_evidence_revocation_list_bundle([self.snaps[0]], KEY, 100.0),
            100.0,
        )
        prior = auditor.checkpoint.to_bytes()
        cont = seal_evidence_revocation_list_bundle(
            [self.snaps[1], self.snaps[2]],
            KEY,
            100.0,
            start=auditor.checkpoint,
        )
        receipt = auditor.audit_bundle_receipt(cont, 100.0)
        self.assertEqual(receipt, receipt_for(cont))
        self.assertEqual(receipt.start, prior)
        self.assertEqual(receipt.end, cont.end)

    def test_shares_lock_and_semantics_with_audit_and_audit_bundle(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        first = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        auditor.audit_bundle_receipt(first, 100.0)
        # The legacy per-snapshot and whole-bundle entries interleave with
        # receipt-minted commits on the same frontier.
        auditor.audit(self.snaps[1], 100.0)
        cont = seal_evidence_revocation_list_bundle(
            [self.snaps[2]], KEY, 100.0, start=auditor.checkpoint
        )
        self.assertIs(auditor.audit_bundle(cont, 100.0), auditor)
        last = seal_evidence_revocation_list_bundle(
            [self.snaps[3]], KEY, 100.0, start=auditor.checkpoint
        )
        receipt = auditor.audit_bundle_receipt(last.to_bytes(), 100.0)
        self.assertEqual(receipt.end, auditor.checkpoint.to_bytes())
        self.assertEqual(auditor.checkpoint.sequence, 4)

    def test_replay_of_committed_bundle_rejected_and_no_receipt(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0], self.snaps[1]], KEY, 100.0
        )
        receipt = auditor.audit_bundle_receipt(bundle, 100.0)
        checkpoint = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle, 100.0)
        self.assertIs(auditor.checkpoint, checkpoint)
        # The old fork fails the same start linkage as audit_bundle.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(
                seal_evidence_revocation_list_bundle(self.snaps, KEY, 100.0),
                100.0,
            )
        self.assertIs(auditor.checkpoint, checkpoint)
        # The minted receipt stays the only one and still verifies.
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                receipt, bundle, KEY
            ),
            checkpoint,
        )

    def test_failure_leaves_checkpoint_untouched(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle_receipt(
            seal_evidence_revocation_list_bundle([self.snaps[0]], KEY, 100.0),
            100.0,
        )
        checkpoint = auditor.checkpoint
        # A bundle starting right but carrying a tampered snapshot.
        obj = json.loads(
            seal_evidence_revocation_list_bundle(
                [self.snaps[1]], KEY, 100.0, start=checkpoint
            ).to_bytes()
        )
        obj["snapshots"][0] = self.snaps[0].to_bytes().hex()
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(reseal(obj), 100.0)
        self.assertIs(auditor.checkpoint, checkpoint)
        # A tampered bundle MAC is rejected before the start gate too.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(
                dataclasses.replace(
                    seal_evidence_revocation_list_bundle(
                        [self.snaps[1]], KEY, 100.0, start=checkpoint
                    ),
                    mac=ZERO,
                ),
                100.0,
            )
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_now_and_min_contract(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle, "100")
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle, float("inf"))
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(bundle, 100.0, min=1.5)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(
                seal_evidence_revocation_list_bundle(
                    [self.snaps[0]], KEY, 100.0, min=0
                ),
                100.0,
                min=2,
            )
        self.assertIsNone(auditor.checkpoint)

    def test_type_and_value_split(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        for bad in (object(), None, 7, self.snaps[0], [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad, 100.0)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(b"nonsense", 100.0)
        self.assertIsNone(auditor.checkpoint)

    def test_legacy_audit_bundle_unchanged(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0]], KEY, 100.0
        )
        self.assertIs(auditor.audit_bundle(bundle, 100.0), auditor)
        self.assertEqual(
            auditor.checkpoint,
            audit_evidence_revocation_list_bundle(bundle, KEY, 100.0),
        )

    def test_concurrent_commits_linearize_in_lock_order(self):
        # Competing one-snapshot forks all start from the empty ledger:
        # exactly one receipt is minted; every other fork fails the start
        # gate after the winner advances the checkpoint.
        forks = [
            seal_evidence_revocation_list_bundle([snap], KEY, 100.0)
            for snap in self.snaps
        ]
        auditor = EvidenceRevocationListAuditor(KEY)
        receipts, failures = [], []
        barrier = threading.Barrier(len(forks))

        def commit(bundle):
            barrier.wait()
            try:
                receipts.append(auditor.audit_bundle_receipt(bundle, 100.0))
            except ValueError:
                failures.append(bundle)

        threads = [threading.Thread(target=commit, args=(b,)) for b in forks]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 3)
        receipt = receipts[0]
        self.assertEqual(receipt.end, auditor.checkpoint.to_bytes())
        self.assertIn(auditor.checkpoint.sequence, range(1, 5))


class AuditEvidenceRevocationListBundleReceiptTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )
        self.receipt = receipt_for(self.bundle)

    def test_verifies_and_returns_end_frontier(self):
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

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt.to_bytes(), self.bundle.to_bytes(), KEY
            ),
            EvidenceRevocationListState.from_bytes(self.bundle.end),
        )

    def test_verifies_non_empty_start_continuation(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 100.0)
        cont = seal_evidence_revocation_list_bundle(
            [self.s2], KEY, 100.0, start=auditor.checkpoint
        )
        receipt = auditor.audit_bundle_receipt(cont, 100.0)
        self.assertEqual(
            audit_evidence_revocation_list_bundle_receipt(receipt, cont, KEY),
            auditor.checkpoint,
        )

    def test_round_trip_observation(self):
        # The observable contract: receipt bytes round-trip, the digest
        # binds that one bundle, and the review returns the end frontier.
        blob = self.receipt.to_bytes()
        parsed = EvidenceRevocationListBundleReceipt.from_bytes(blob)
        self.assertEqual(parsed.to_bytes(), blob)
        self.assertEqual(parsed, self.receipt)
        end = audit_evidence_revocation_list_bundle_receipt(
            parsed, self.bundle, KEY
        )
        self.assertEqual(end.to_bytes(), self.bundle.end)

    def test_type_contract(self):
        for bad in (1, "x", None, [self.receipt], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt(
                    bad, self.bundle, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt(
                    self.receipt, bad, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle_receipt(
                    self.receipt, self.bundle, bad
                )

    def test_value_contract(self):
        # Empty key, unparseable bytes and non-canonical bytes.
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, self.bundle, b""
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                b"junk", self.bundle, KEY
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, b"junk", KEY
            )
        blob = self.receipt.to_bytes()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                blob.replace(b",", b", "), self.bundle, KEY
            )

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(self.receipt, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                tampered, self.bundle, KEY
            )

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, self.bundle, OTHER_KEY
            )

    def test_bundle_digest_binds_one_bundle(self):
        # A one-snapshot bundle over s2 shares the exact empty start and
        # end frontier with the two-snapshot bundle: only the carried
        # bytes differ, so an honest receipt for one never attests the
        # other despite identical endpoints.
        solo = seal_evidence_revocation_list_bundle([self.s2], KEY, 200.0)
        self.assertEqual(solo.start, self.bundle.start)
        self.assertEqual(solo.end, self.bundle.end)
        self.assertNotEqual(solo.to_bytes(), self.bundle.to_bytes())
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                self.receipt, solo, KEY
            )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt_for(solo), self.bundle, KEY
            )

    def test_tampered_bundle_digest_field(self):
        forged = receipt_for(self.bundle, digest=ZERO)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                forged, self.bundle, KEY
            )

    def test_endpoint_mismatch(self):
        # Receipt mac and bundle digest both verify, but the receipt's
        # endpoints do not match the bundle's.
        s3 = snapshot(sequence=3)
        end3 = frontier_for(s3)
        mismatched = receipt_for(
            self.bundle,
            start=end3.to_bytes(),
            end=end3.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                mismatched, self.bundle, KEY
            )

    def test_invalid_bundle_still_rejected(self):
        # The receipt stays honest over the exact bundle bytes, but the
        # bundle itself does not hold together: its outer NPEB1 MAC and
        # both endpoint NPES1 MACs are valid, yet the claimed end
        # frontier encodes a sequence the carried snapshots never reach,
        # so whole-bundle verification rejects it on replay.
        obj = json.loads(self.bundle.to_bytes())
        obj["end"] = frontier_for(snapshot(sequence=9)).to_bytes().hex()
        bad_bytes = reseal(obj)
        bad_bundle = EvidenceRevocationListBundle.from_bytes(bad_bytes)
        receipt = receipt_for(bad_bundle)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt, bad_bundle, KEY
            )

    def test_tampered_endpoint_even_with_valid_bundle_mac_rejected(self):
        # The receipt stays honest over the exact bundle bytes, but the
        # bundle itself carries a forged end frontier: whole-bundle
        # verification must still reject it.
        obj = json.loads(self.bundle.to_bytes())
        forged_end = EvidenceRevocationListState(
            1, 2, hashlib.sha256(self.s2.to_bytes()).digest(), b"\x08" * 32
        )
        obj["end"] = forged_end.to_bytes().hex()
        bad_bytes = reseal(obj)
        bad_bundle = EvidenceRevocationListBundle.from_bytes(bad_bytes)
        receipt = receipt_for(bad_bundle)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle_receipt(
                receipt, bad_bundle, KEY
            )

    def test_no_freshness_policy_in_review(self):
        # The receipt review carries no now/min: a bundle honestly
        # sealed and committed at its own review time re-verifies here
        # purely on the MAC layers and the chain, with no clock.
        future_list = make_evidence_revocation_list(
            [], 1, 200.0, KEY
        )
        future_bundle = seal_evidence_revocation_list_bundle(
            [future_list], KEY, 200.0
        )
        end = audit_evidence_revocation_list_bundle_receipt(
            receipt_for(future_bundle), future_bundle, KEY
        )
        self.assertEqual(end.to_bytes(), future_bundle.end)


class EvidenceRevocationListBundleReceiptExportsTest(unittest.TestCase):
    def test_api_is_exported(self):
        import nearproof

        for name in (
            "EvidenceRevocationListBundleReceipt",
            "audit_evidence_revocation_list_bundle_receipt",
            # The previous task's whole-bundle entries, documented
            # alongside the new ones.
            "seal_evidence_revocation_list_bundle",
            "audit_evidence_revocation_list_bundle",
        ):
            self.assertIn(name, nearproof.__all__)
            self.assertIs(getattr(nearproof, name), getattr(nearproof, name))
        self.assertTrue(
            hasattr(
                nearproof.EvidenceRevocationListAuditor, "audit_bundle_receipt"
            )
        )


if __name__ == "__main__":
    unittest.main()
