import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationList,
    EvidenceRevocationListAuditor,
    EvidenceRevocationListBundle,
    EvidenceRevocationListState,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX,
    _encode_payload,
    _evidence_revocation_list_bundle_mac,
    _evidence_revocation_list_bundle_content,
    _evidence_revocation_list_state_mac,
    _evidence_revocation_list_state_payload,
    audit_evidence_revocation_list_bundle,
    make_evidence_revocation_list,
    seal_evidence_revocation_list_bundle,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


def snapshot(entries=(), *, sequence=1, issued_at=100.0, key=KEY):
    return make_evidence_revocation_list(list(entries), sequence, issued_at, key)


def state_mac(key, state):
    return _evidence_revocation_list_state_mac(
        key, _evidence_revocation_list_state_payload(state)
    )


def make_state(sequence, erl, *, key=KEY, mac=None):
    if mac is None:
        placeholder = EvidenceRevocationListState(
            1, sequence, hashlib.sha256(erl.to_bytes()).digest(), b"\x00" * 32
        )
        mac = state_mac(key, placeholder)
    return EvidenceRevocationListState(
        1, sequence, hashlib.sha256(erl.to_bytes()).digest(), mac
    )


def resign(bundle, *, key=KEY):
    """Recompute a bundle's NPEB1 MAC after tampering with its content."""
    return dataclasses.replace(
        bundle,
        mac=_evidence_revocation_list_bundle_mac(key, bundle),
    )


class EvidenceRevocationListBundleContractTest(unittest.TestCase):
    def setUp(self):
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2], KEY, 11.0
        )

    def test_is_frozen_and_equal_by_fields(self):
        first = self.bundle
        second = EvidenceRevocationListBundle(
            1, first.start, first.snapshots, first.end, first.mac
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.start, first.snapshots, first.end, first.mac),
            (1, b"", (self.e1.to_bytes(), self.e2.to_bytes()),
             first.end, first.mac),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.version = 2

    def test_positional_field_order(self):
        start = b""
        snapshots = (self.e1.to_bytes(),)
        end = make_state(1, self.e1).to_bytes()
        mac = b"\x02" * 32
        bundle = EvidenceRevocationListBundle(1, start, snapshots, end, mac)
        self.assertEqual(
            (bundle.version, bundle.start, bundle.snapshots, bundle.end,
             bundle.mac),
            (1, start, snapshots, end, mac),
        )

    def test_version_shape_vs_value(self):
        kwargs = dict(
            start=self.bundle.start,
            snapshots=self.bundle.snapshots,
            end=self.bundle.end,
            mac=self.bundle.mac,
        )
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundle(bad, **kwargs)
        for bad in ("1", 1.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundle(bad, **kwargs)

    def test_start_contract(self):
        for bad in ("", None, 7, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundle(
                    1, bad, self.bundle.snapshots, self.bundle.end,
                    self.bundle.mac,
                )
        for bad in (b"not json", b"[]", b"null"):
            with self.assertRaises(ValueError, msg=bad):
                EvidenceRevocationListBundle(
                    1, bad, self.bundle.snapshots, self.bundle.end,
                    self.bundle.mac,
                )

    def test_snapshots_contract(self):
        for bad in ([], None, "xx", self.e1):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                EvidenceRevocationListBundle(
                    1, self.bundle.start, bad, self.bundle.end,
                    self.bundle.mac,
                )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle(
                1, self.bundle.start, (), self.bundle.end, self.bundle.mac
            )
        with self.assertRaises(TypeError):
            EvidenceRevocationListBundle(
                1, self.bundle.start, (self.e1,), self.bundle.end,
                self.bundle.mac,
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle(
                1, self.bundle.start, (b"not json",), self.bundle.end,
                self.bundle.mac,
            )

    def test_end_contract(self):
        for bad in ("", None, 7, []):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundle(
                    1, self.bundle.start, self.bundle.snapshots, bad,
                    self.bundle.mac,
                )
        for bad in (b"", b"not json", b"[]"):
            with self.assertRaises(ValueError, msg=bad):
                EvidenceRevocationListBundle(
                    1, self.bundle.start, self.bundle.snapshots, bad,
                    self.bundle.mac,
                )

    def test_mac_shape_vs_value(self):
        for bad in ("ab" * 32, None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundle(
                    1, self.bundle.start, self.bundle.snapshots,
                    self.bundle.end, bad,
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundle(
                    1, self.bundle.start, self.bundle.snapshots,
                    self.bundle.end, bad,
                )


class EvidenceRevocationListBundleEncodingTest(unittest.TestCase):
    def setUp(self):
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)

    def test_to_bytes_shape_from_empty(self):
        bundle = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2], KEY, 11.0
        )
        blob = bundle.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        self.assertEqual(
            blob,
            json.dumps(
                [
                    1,
                    "",
                    [self.e1.to_bytes().hex(), self.e2.to_bytes().hex()],
                    bundle.end.hex(),
                    bundle.mac.hex(),
                ],
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        decoded = json.loads(blob)
        self.assertIsInstance(decoded, list)
        self.assertEqual(len(decoded), 5)

    def test_to_bytes_shape_with_frontier_start(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        bundle = seal_evidence_revocation_list_bundle(
            [self.e2], KEY, 11.0, start=auditor.checkpoint
        )
        decoded = json.loads(bundle.to_bytes())
        self.assertEqual(decoded[1], auditor.checkpoint.to_bytes().hex())
        self.assertEqual(decoded[2], [self.e2.to_bytes().hex()])

    def test_round_trip(self):
        bundle = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2], KEY, 11.0
        )
        self.assertEqual(
            EvidenceRevocationListBundle.from_bytes(bundle.to_bytes()),
            bundle,
        )
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        rooted = seal_evidence_revocation_list_bundle(
            [self.e2], KEY, 11.0, start=auditor.checkpoint.to_bytes()
        )
        self.assertEqual(
            EvidenceRevocationListBundle.from_bytes(rooted.to_bytes()),
            rooted,
        )

    def test_from_bytes_non_bytes_is_type_error(self):
        bundle = seal_evidence_revocation_list_bundle(
            [self.e1], KEY, 10.0
        )
        for bad in (bundle.to_bytes().decode(), None, 42, [1],
                    bytearray(bundle.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListBundle.from_bytes(bad)

    def test_from_bytes_rejects_bad_shapes(self):
        good = json.loads(
            seal_evidence_revocation_list_bundle(
                [self.e1, self.e2], KEY, 11.0
            ).to_bytes()
        )
        blobs = [
            b"{}",
            b"[]",
            json.dumps(good[:4], separators=(",", ":")).encode(),
            json.dumps(good + ["extra"], separators=(",", ":")).encode(),
            json.dumps(["1", good[1], good[2], good[3], good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([2, good[1], good[2], good[3], good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([1, None, good[2], good[3], good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([1, good[1], "nothex", good[3], good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([1, good[1], [], good[3], good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([1, good[1], good[2], None, good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([1, good[1], good[2], "", good[4]],
                       separators=(",", ":")).encode(),
            json.dumps([1, good[1], good[2], good[3], "ab" * 31],
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises((TypeError, ValueError), msg=blob):
                EvidenceRevocationListBundle.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = seal_evidence_revocation_list_bundle(
            [self.e1], KEY, 10.0
        ).to_bytes()
        for blob in (
            data + b" ",
            data.replace(b",", b", ", 1),
            b"not json",
            b"",
            b"\x00" + data,
        ):
            with self.assertRaises(ValueError, msg=blob):
                EvidenceRevocationListBundle.from_bytes(blob)

    def test_from_bytes_does_not_verify_any_mac(self):
        end = make_state(2, self.e2, mac=b"\x00" * 32)
        bundle = EvidenceRevocationListBundle(
            1, b"", (self.e1.to_bytes(), self.e2.to_bytes()),
            end.to_bytes(), b"\x00" * 32,
        )
        decoded = EvidenceRevocationListBundle.from_bytes(bundle.to_bytes())
        self.assertEqual(decoded, bundle)


class EvidenceRevocationListBundleMacTest(unittest.TestCase):
    def setUp(self):
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2], KEY, 11.0
        )

    def test_mac_formula_direct_concatenation(self):
        encoding = _encode_payload(
            _evidence_revocation_list_bundle_content(self.bundle)
        )
        self.assertEqual(_EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX, b"NPEB1")
        self.assertEqual(
            self.bundle.mac,
            hmac.new(
                KEY,
                _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX + encoding,
                hashlib.sha256,
            ).digest(),
        )
        # No delimiter or length prefix between the prefix and the encoding.
        forged = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX
            + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(self.bundle.mac, forged)
        self.assertNotEqual(
            self.bundle.mac,
            hmac.new(
                OTHER_KEY,
                _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX + encoding,
                hashlib.sha256,
            ).digest(),
        )

    def test_end_frontier_is_npes1_signed(self):
        end = EvidenceRevocationListState.from_bytes(self.bundle.end)
        self.assertEqual(
            end.mac,
            _evidence_revocation_list_state_mac(
                KEY, _evidence_revocation_list_state_payload(end)
            ),
        )


class SealEvidenceRevocationListBundleTest(unittest.TestCase):
    def setUp(self):
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)
        self.e3 = snapshot(sequence=3, issued_at=12.0)

    def test_seal_from_empty_mixes_objects_and_bytes(self):
        bundle = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2.to_bytes()], KEY, 11.0
        )
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(
            bundle.snapshots,
            (self.e1.to_bytes(), self.e2.to_bytes()),
        )
        end = EvidenceRevocationListState.from_bytes(bundle.end)
        self.assertEqual((end.version, end.sequence), (1, 2))
        self.assertEqual(end.digest, hashlib.sha256(self.e2.to_bytes()).digest())

    def test_seal_from_frontier_object_and_bytes(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        frontier = auditor.checkpoint
        from_object = seal_evidence_revocation_list_bundle(
            [self.e2, self.e3], KEY, 12.0, start=frontier
        )
        self.assertEqual(from_object.start, frontier.to_bytes())
        from_bytes = seal_evidence_revocation_list_bundle(
            [self.e2, self.e3], KEY, 12.0, start=frontier.to_bytes()
        )
        self.assertEqual(from_object, from_bytes)
        self.assertEqual(
            EvidenceRevocationListState.from_bytes(from_object.end).sequence,
            3,
        )

    def test_start_is_keyword_only(self):
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle(
                [self.e1], KEY, 10.0, 0, None
            )

    def test_sequence_must_strictly_increase(self):
        for chain in ([self.e1, self.e1], [self.e2, self.e1]):
            with self.assertRaises(ValueError, msg=repr(chain)):
                seal_evidence_revocation_list_bundle(chain, KEY, 12.0)
        # A snapshot at or below the starting frontier is a broken chain.
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e2, 11.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [self.e2], KEY, 12.0, start=auditor.checkpoint
            )
        # A gap is fine: sequences only need to be strictly increasing.
        bundle = seal_evidence_revocation_list_bundle(
            [self.e3], KEY, 12.0, start=auditor.checkpoint
        )
        self.assertEqual(
            EvidenceRevocationListState.from_bytes(bundle.end).sequence, 3
        )

    def test_freshness_and_floor_checked_per_snapshot(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [self.e1, self.e2], KEY, 10.5
            )  # e2 issued 11.0 > now
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [self.e1, self.e2], KEY, 11.0, min=2
            )  # e1 sequence 1 < 2
        # Boundary equality is allowed.
        bundle = seal_evidence_revocation_list_bundle(
            [self.e2], KEY, 11.0, min=2
        )
        self.assertEqual(
            EvidenceRevocationListState.from_bytes(bundle.end).sequence, 2
        )

    def test_now_and_min_shapes(self):
        for bad_now in ("11", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                seal_evidence_revocation_list_bundle(
                    [self.e1], KEY, bad_now
                )
        for bad_min in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                seal_evidence_revocation_list_bundle(
                    [self.e1], KEY, 10.0, min=bad_min
                )

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([self.e1], b"", 10.0)
        for bad in (bytearray(KEY), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle([self.e1], bad, 10.0)

    def test_snapshots_kind_contract(self):
        for bad in (42, 7, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle(bad, KEY, 10.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([], KEY, 10.0)
        for bad in (None, 42, object(), "not-it"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle([bad], KEY, 10.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [b"not json"], KEY, 10.0
            )

    def test_start_kind_contract(self):
        for bad in ("x", 1, [], {}):
            with self.assertRaises(TypeError, msg=repr(bad)):
                seal_evidence_revocation_list_bundle(
                    [self.e2], KEY, 11.0, start=bad
                )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [self.e2], KEY, 11.0, start=b"not json"
            )
        # A frontier MAC'd under another key fails verification.
        other = EvidenceRevocationListAuditor(OTHER_KEY)
        other.audit(
            snapshot(sequence=1, issued_at=10.0, key=OTHER_KEY), 10.0
        )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [self.e2], KEY, 11.0, start=other.checkpoint
            )

    def test_snapshot_signed_under_other_key_rejected(self):
        forged = snapshot(sequence=1, issued_at=10.0, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([forged], KEY, 10.0)

    def test_failed_seal_produces_nothing(self):
        before = len([1])
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [self.e1, self.e2, self.e1], KEY, 12.0
            )
        self.assertEqual(before, 1)


class AuditEvidenceRevocationListBundleTest(unittest.TestCase):
    def setUp(self):
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)
        self.e3 = snapshot(sequence=3, issued_at=12.0)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2], KEY, 11.0
        )

    def test_accepts_object_and_bytes_and_returns_end(self):
        end_object = audit_evidence_revocation_list_bundle(
            self.bundle, KEY, 11.0
        )
        end_bytes = audit_evidence_revocation_list_bundle(
            self.bundle.to_bytes(), KEY, 11.0
        )
        self.assertEqual(end_object, end_bytes)
        self.assertIsInstance(end_object, EvidenceRevocationListState)
        self.assertEqual(end_object.to_bytes(), self.bundle.end)

    def test_wrong_kind_is_type_error(self):
        for bad in (None, 42, object(), [], self.e1):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                audit_evidence_revocation_list_bundle(bad, KEY, 11.0)

    def test_malformed_bytes_are_value_error(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(b"not json", KEY, 11.0)

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(self.bundle, b"", 11.0)
        for bad in (bytearray(KEY), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle(self.bundle, bad, 11.0)

    def test_wrong_key_and_bundle_mac_tampering_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(
                self.bundle, OTHER_KEY, 11.0
            )
        bad_mac = dataclasses.replace(self.bundle, mac=b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(bad_mac, KEY, 11.0)
        raw = json.loads(self.bundle.to_bytes())
        raw[4] = "00" * 32
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(
                json.dumps(raw, separators=(",", ":")).encode(), KEY, 11.0
            )

    def test_endpoint_frontier_macs_verified(self):
        # Valid bundle MAC, but the carried end frontier carries a bad MAC.
        end = EvidenceRevocationListState(
            1, 2,
            hashlib.sha256(self.e2.to_bytes()).digest(),
            b"\x00" * 32,
        )
        bad_end = resign(dataclasses.replace(self.bundle, end=end.to_bytes()))
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(bad_end, KEY, 11.0)
        # A non-empty start frontier with a bad MAC is likewise rejected.
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        rooted = seal_evidence_revocation_list_bundle(
            [self.e2], KEY, 11.0, start=auditor.checkpoint
        )
        bad_start_state = make_state(
            1, self.e1, mac=b"\x00" * 32
        )
        bad_start = resign(
            dataclasses.replace(rooted, start=bad_start_state.to_bytes())
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(bad_start, KEY, 11.0)

    def test_snapshot_layer_must_verify(self):
        forged = snapshot(sequence=1, issued_at=10.0, key=OTHER_KEY)
        bundle = resign(dataclasses.replace(
            self.bundle,
            snapshots=(forged.to_bytes(), self.e2.to_bytes()),
        ))
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(bundle, KEY, 11.0)

    def test_strict_sequence_and_end_match_replayed(self):
        # Re-sign a structurally valid bundle whose snapshots repeat a
        # sequence: per-snapshot review passes, replay rejects it.
        repeated = resign(dataclasses.replace(
            self.bundle,
            snapshots=(self.e1.to_bytes(), self.e1.to_bytes()),
        ))
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(repeated, KEY, 11.0)
        # Snapshots valid and increasing but end bound to another frontier.
        wrong_end = make_state(3, self.e3)
        mismatched = resign(dataclasses.replace(
            self.bundle, end=wrong_end.to_bytes()
        ))
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(mismatched, KEY, 11.0)

    def test_freshness_floor_and_params(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(self.bundle, KEY, 10.5)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(
                self.bundle, KEY, 11.0, min=3
            )
        for bad_now in ("11", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                audit_evidence_revocation_list_bundle(
                    self.bundle, KEY, bad_now
                )
        for bad_min in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                audit_evidence_revocation_list_bundle(
                    self.bundle, KEY, 11.0, min=bad_min
                )

    def test_chain_starting_from_frontier_round_trips(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        bundle = seal_evidence_revocation_list_bundle(
            [self.e2, self.e3], KEY, 12.0, start=auditor.checkpoint
        )
        end = audit_evidence_revocation_list_bundle(bundle, KEY, 12.0)
        self.assertEqual(end.sequence, 3)
        self.assertEqual(end.to_bytes(), bundle.end)
        # A bundle sealed from that frontier cannot be replayed from the
        # empty ledger by the stateless auditor either: its first snapshot
        # duplicates the carried start's sequence only when replayed onto a
        # state; here the start is genuine, so verify it audits standalone.
        self.assertEqual(
            audit_evidence_revocation_list_bundle(
                bundle.to_bytes(), KEY, 12.0
            ),
            end,
        )


class AuditorAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)
        self.e3 = snapshot(sequence=3, issued_at=12.0)
        self.b012 = seal_evidence_revocation_list_bundle(
            [self.e1, self.e2], KEY, 11.0
        )

    def test_audit_bundle_from_empty(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        self.assertIs(auditor.audit_bundle(self.b012, 11.0), auditor)
        self.assertEqual(
            auditor.checkpoint.to_bytes(), self.b012.end
        )
        auditor2 = EvidenceRevocationListAuditor(KEY)
        self.assertIs(
            auditor2.audit_bundle(self.b012.to_bytes(), 11.0), auditor2
        )
        self.assertEqual(auditor2.checkpoint.to_bytes(), self.b012.end)

    def test_audit_bundle_continues_from_checkpoint(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        rooted = seal_evidence_revocation_list_bundle(
            [self.e2, self.e3], KEY, 12.0, start=auditor.checkpoint
        )
        self.assertIs(auditor.audit_bundle(rooted, 12.0), auditor)
        self.assertEqual(auditor.checkpoint.to_bytes(), rooted.end)
        self.assertEqual(auditor.checkpoint.sequence, 3)

    def test_empty_ledger_rejects_non_empty_start(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        rooted = seal_evidence_revocation_list_bundle(
            [self.e2], KEY, 11.0, start=auditor.checkpoint
        )
        fresh = EvidenceRevocationListAuditor(KEY)
        with self.assertRaises(ValueError):
            fresh.audit_bundle(rooted, 11.0)
        self.assertIsNone(fresh.checkpoint)

    def test_start_mismatch_leaves_checkpoint_untouched(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        saved = auditor.checkpoint
        # The bundle starts from the empty ledger; the ledger already has e1.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(self.b012, 11.0)
        self.assertIs(auditor.checkpoint, saved)

    def test_replay_of_committed_bundle_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle(self.b012, 11.0)
        saved = auditor.checkpoint
        for _ in range(3):
            with self.assertRaises(ValueError):
                auditor.audit_bundle(self.b012, 11.0)
            with self.assertRaises(ValueError):
                auditor.audit_bundle(self.b012.to_bytes(), 11.0)
        self.assertIs(auditor.checkpoint, saved)

    def test_failed_bundle_leaves_checkpoint_untouched(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        saved = auditor.checkpoint
        # Future snapshot inside an otherwise valid bundle.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(self.b012, 10.5)
        # Bundle sealed under another key (its snapshots too).
        other = seal_evidence_revocation_list_bundle(
            [
                snapshot(sequence=1, issued_at=10.0, key=OTHER_KEY),
                snapshot(sequence=2, issued_at=11.0, key=OTHER_KEY),
            ],
            OTHER_KEY, 11.0,
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(other, 11.0)
        # Tampered bytes.
        raw = json.loads(self.b012.to_bytes())
        raw[4] = "00" * 32
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                json.dumps(raw, separators=(",", ":")).encode(), 11.0
            )
        # Wrong kind.
        for bad in (None, 42, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad, 11.0)
        self.assertIs(auditor.checkpoint, saved)

    def test_same_sequence_snapshot_in_bundle_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        # Sealing refuses a repeated sequence, so construct the bundle with
        # a valid NPEB1 MAC by hand and let replay reject it instead.
        repeated = resign(
            EvidenceRevocationListBundle(
                1,
                b"",
                (self.e1.to_bytes(), self.e1.to_bytes()),
                make_state(1, self.e1).to_bytes(),
                b"\x00" * 32,
            )
        )
        with self.assertRaises(ValueError):
            auditor.audit_bundle(repeated, 11.0)
        self.assertIsNone(auditor.checkpoint)

    def test_min_floor_enforced(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(self.b012, 11.0, min=2)
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_bundle(self.b012, 11.0, min=1)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_restart_from_checkpoint_then_bundle(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle(self.b012, 11.0)
        restarted = EvidenceRevocationListAuditor(
            KEY, checkpoint=auditor.checkpoint.to_bytes()
        )
        rooted = seal_evidence_revocation_list_bundle(
            [self.e3], KEY, 12.0, start=restarted.checkpoint
        )
        restarted.audit_bundle(rooted, 12.0)
        self.assertEqual(restarted.checkpoint.sequence, 3)
        # The committed bundle replays via the single-snapshot entry too.
        self.assertIs(
            restarted.audit(self.e3.to_bytes(), 12.0), restarted
        )

    def test_concurrent_single_and_bundle_audits_linearize(self):
        # From the empty ledger: single e1/e2/e3 audits, the empty-start
        # bundle b012, and the frontier-rooted bundles b12 and b23. Every
        # schedule is monotone and converges on the e3 frontier.
        b12 = seal_evidence_revocation_list_bundle(
            [self.e2], KEY, 11.0, start=make_state(1, self.e1)
        )
        b23 = seal_evidence_revocation_list_bundle(
            [self.e3], KEY, 12.0, start=make_state(2, self.e2)
        )
        auditor = EvidenceRevocationListAuditor(KEY)
        errors = []
        singles = [self.e1, self.e1.to_bytes(), self.e2, self.e3] * 6
        bundles = [self.b012, self.b012.to_bytes(), b12, b23] * 6

        def audit_single(item):
            try:
                auditor.audit(item, 12.0)
            except ValueError:
                # Superseded/lower-sequence singles must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        def audit_bundle(item):
            try:
                auditor.audit_bundle(item, 12.0)
            except ValueError:
                # Start-mismatch replays and superseded bundles must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        threads = [
            *(threading.Thread(target=audit_single, args=(item,))
              for item in singles),
            *(threading.Thread(target=audit_bundle, args=(item,))
              for item in bundles),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 3)
        self.assertEqual(auditor.checkpoint, make_state(3, self.e3))

    def test_exactly_one_empty_start_bundle_wins_the_race(self):
        start = threading.Barrier(2)
        auditor = EvidenceRevocationListAuditor(KEY)
        outcomes = []

        def loser():
            start.wait()
            for _ in range(1000):
                try:
                    auditor.audit_bundle(self.b012, 11.0)
                except ValueError:
                    outcomes.append("rejected")

        def winner():
            start.wait()
            auditor.audit_bundle(self.b012, 11.0)
            outcomes.append("committed")

        threads = [
            threading.Thread(target=loser),
            threading.Thread(target=winner),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("committed"), 1)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(auditor.checkpoint.to_bytes(), self.b012.end)


if __name__ == "__main__":
    unittest.main()
