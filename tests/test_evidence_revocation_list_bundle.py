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
    Prover,
    Verifier,
    _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX,
    _encode_payload,
    _evidence_revocation_list_bundle_mac,
    _evidence_revocation_list_bundle_payload,
    _evidence_revocation_list_state_mac,
    _evidence_revocation_list_state_payload,
    audit_evidence_revocation_list_bundle,
    make_evidence_revocation_list,
    revoke_evidence,
    seal_evidence_revocation_list_bundle,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


class AutoClock:
    """Two readings per round, ``step`` apart, giving deterministic RTTs."""

    def __init__(self, step=1e-7):
        self.readings = 0
        self.step = step

    def __call__(self):
        value = self.readings * self.step
        self.readings += 1
        return value


def make_evidence_list(count, key=KEY, step=1e-7):
    prover = Prover(key)
    verifier = Verifier(key, clock=AutoClock(step), replay_protection=True)
    records = []
    for _ in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, prover, records


def snapshot(entries=(), *, sequence, issued_at=100.0, key=KEY):
    return make_evidence_revocation_list(list(entries), sequence, issued_at, key)


def frontier_for(erl, *, key=KEY, mac=None):
    placeholder = EvidenceRevocationListState(
        1, erl.sequence, hashlib.sha256(erl.to_bytes()).digest(), b"\x00" * 32
    )
    if mac is None:
        mac = _evidence_revocation_list_state_mac(
            key, _evidence_revocation_list_state_payload(placeholder)
        )
    return EvidenceRevocationListState(
        1, erl.sequence, hashlib.sha256(erl.to_bytes()).digest(), mac
    )


def reencode(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def reseal(obj, key=KEY):
    """Re-sign a decoded bundle dict with a fresh NPEB1 MAC over its first
    four fields, so a single field can be tampered while the outer MAC
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


class EvidenceRevocationListBundleContractTest(unittest.TestCase):
    def setUp(self):
        _v, _p, records = make_evidence_list(3)
        self.entry = revoke_evidence(records[0], 0.0, KEY)
        self.first = snapshot(sequence=1)
        self.end = frontier_for(self.first)

    def make(self, **overrides):
        values = {
            "version": 1,
            "start": b"",
            "snapshots": (self.first.to_bytes(),),
            "end": self.end.to_bytes(),
            "mac": b"\x09" * 32,
        }
        values.update(overrides)
        return EvidenceRevocationListBundle(
            values["version"],
            values["start"],
            values["snapshots"],
            values["end"],
            values["mac"],
        )

    def test_is_frozen_and_equal_by_fields(self):
        sealed = seal_evidence_revocation_list_bundle([self.first], KEY, 100.0)
        second = EvidenceRevocationListBundle(
            1,
            bytes(sealed.start),
            tuple(sealed.snapshots),
            bytes(sealed.end),
            bytes(sealed.mac),
        )
        self.assertEqual(sealed, second)
        self.assertEqual(hash(sealed), hash(second))
        self.assertFalse(hasattr(sealed, "key"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            sealed.end = b""

    def test_positional_field_order(self):
        bundle = self.make()
        self.assertEqual(
            (
                bundle.version,
                bundle.start,
                bundle.snapshots,
                bundle.end,
                bundle.mac,
            ),
            (1, b"", (self.first.to_bytes(),), self.end.to_bytes(), b"\x09" * 32),
        )

    def test_version_shape_vs_value(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError):
                self.make(version=bad)
        for bad in ("1", 1.0, True, False, None):
            with self.assertRaises(TypeError):
                self.make(version=bad)

    def test_start_must_be_empty_or_canonical_state_bytes(self):
        for bad in ("", [], None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(start=bad)
        # Non-canonical or malformed state bytes are a value violation.
        for bad in (b"", b"not-json", b"[]", self.end.to_bytes() + b" "):
            if bad == b"":
                continue
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(start=bad)

    def test_snapshots_must_be_nonempty_tuple_of_canonical_bytes(self):
        for bad in ([], None, self.first.to_bytes()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(snapshots=bad)
        with self.assertRaises(ValueError):
            self.make(snapshots=())
        with self.assertRaises(TypeError):
            self.make(snapshots=(self.first,))
        with self.assertRaises(ValueError):
            self.make(snapshots=(b"not-a-snapshot",))
        with self.assertRaises(ValueError):
            self.make(snapshots=(self.first.to_bytes() + b" ",))

    def test_end_must_be_canonical_nonempty_state_bytes(self):
        for bad in ("", None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(end=bad)
        for bad in (b"", b"not-json", b"[]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(end=bad)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in ("ab" * 32, None, 7):
            with self.assertRaises(TypeError):
                self.make(mac=bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(mac=bad)


class EvidenceRevocationListBundleEncodingTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )

    def test_to_bytes_shape(self):
        obj = json.loads(self.bundle.to_bytes())
        self.assertEqual(
            list(obj), ["version", "start", "snapshots", "end", "mac"]
        )
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["start"], "")
        self.assertEqual(
            obj["snapshots"],
            [self.s1.to_bytes().hex(), self.s2.to_bytes().hex()],
        )
        self.assertEqual(obj["end"], self.bundle.end.hex())
        self.assertEqual(obj["mac"], self.bundle.mac.hex())
        # Compact JSON with no whitespace or length prefix.
        self.assertNotIn(b" ", self.bundle.to_bytes())

    def test_round_trip(self):
        self.assertEqual(
            EvidenceRevocationListBundle.from_bytes(self.bundle.to_bytes()),
            self.bundle,
        )

    def test_data_must_be_bytes(self):
        with self.assertRaises(TypeError):
            EvidenceRevocationListBundle.from_bytes(self.bundle.to_bytes().decode())
        with self.assertRaises(TypeError):
            EvidenceRevocationListBundle.from_bytes(None)

    def test_malformed_and_non_canonical_encodings_rejected(self):
        encoding = self.bundle.to_bytes()
        for bad in (
            b"[]",
            b"{}",
            b" " + encoding,
            encoding + b" ",
            encoding.replace(b'{"version"', b'{ "version"'),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListBundle.from_bytes(bad)
        obj = json.loads(encoding)
        # Missing, extra and reordered keys.
        del obj["end"]
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        obj["extra"] = 0
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle.from_bytes(reencode(obj))
        obj = json.loads(encoding)
        reordered = {name: obj[name] for name in reversed(list(obj))}
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle.from_bytes(reencode(reordered))

    def test_inner_encodings_must_be_canonical(self):
        obj = json.loads(self.bundle.to_bytes())
        obj["snapshots"] = [self.s1.to_bytes().hex() + "00", obj["snapshots"][1]]
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle.from_bytes(reencode(obj))
        obj = json.loads(self.bundle.to_bytes())
        obj["start"] = self.bundle.end.hex().upper()
        with self.assertRaises(ValueError):
            EvidenceRevocationListBundle.from_bytes(reencode(obj))


class EvidenceRevocationListBundleMacTest(unittest.TestCase):
    def test_mac_is_npeb1_over_unsigned_encoding(self):
        s1 = snapshot(sequence=1)
        bundle = seal_evidence_revocation_list_bundle([s1], KEY, 100.0)
        unsigned = _encode_payload(_evidence_revocation_list_bundle_payload(bundle))
        expected = hmac.new(
            KEY, _EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX + unsigned, hashlib.sha256
        ).digest()
        self.assertEqual(bundle.mac, expected)
        self.assertEqual(
            bundle.mac,
            _evidence_revocation_list_bundle_mac(KEY, bundle),
        )
        # The label itself distinguishes the domain.
        self.assertEqual(_EVIDENCE_REVOCATION_LIST_BUNDLE_PREFIX, b"NPEB1")

    def test_mac_changes_with_carried_snapshots_and_end(self):
        s1 = snapshot(sequence=1)
        s2 = snapshot(sequence=2)
        two = seal_evidence_revocation_list_bundle([s1, s2], KEY, 100.0)
        one = seal_evidence_revocation_list_bundle([s1], KEY, 100.0)
        self.assertNotEqual(one.mac, two.mac)
        self.assertNotEqual(one.end, two.end)
        # The same unsigned body under another key yields another MAC.
        self.assertNotEqual(
            _evidence_revocation_list_bundle_mac(OTHER_KEY, two),
            two.mac,
        )


class SealEvidenceRevocationListBundleTest(unittest.TestCase):
    def test_seal_from_empty_start_round_trips(self):
        s1 = snapshot(sequence=1)
        s2 = snapshot(sequence=2)
        bundle = seal_evidence_revocation_list_bundle(
            [s1, s2.to_bytes()], KEY, 100.0
        )
        self.assertEqual(bundle.version, 1)
        self.assertEqual(bundle.start, b"")
        self.assertEqual(
            bundle.snapshots, (s1.to_bytes(), s2.to_bytes())
        )
        end = audit_evidence_revocation_list_bundle(bundle, KEY, 100.0)
        self.assertEqual(end, EvidenceRevocationListState.from_bytes(bundle.end))
        self.assertEqual(end.sequence, 2)
        self.assertEqual(end.digest, hashlib.sha256(s2.to_bytes()).digest())

    def test_seal_from_named_start_chains_frontiers(self):
        s1 = snapshot(sequence=1)
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(s1, 100.0)
        s2 = snapshot(sequence=2)
        bundle = seal_evidence_revocation_list_bundle(
            [s2], KEY, 100.0, start=auditor.checkpoint
        )
        self.assertEqual(bundle.start, auditor.checkpoint.to_bytes())
        end = audit_evidence_revocation_list_bundle(bundle, KEY, 100.0)
        self.assertEqual(end.sequence, 2)
        # The start may equally be supplied as canonical state bytes.
        bundle_bytes = seal_evidence_revocation_list_bundle(
            [s2], KEY, 100.0, start=auditor.checkpoint.to_bytes()
        )
        self.assertEqual(bundle_bytes, bundle)

    def test_seal_rechecks_both_mac_layers(self):
        _v, _p, records = make_evidence_list(1)
        entry = revoke_evidence(records[0], 0.0, KEY)
        good = snapshot([entry], sequence=1)
        # A list signed by another key is refused before sealing.
        foreign = snapshot([entry], sequence=1, key=OTHER_KEY)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([foreign], KEY, 100.0)
        # A snapshot with a tampered inner entry MAC is refused.
        obj = json.loads(good.to_bytes())
        obj["entries"][0]["mac"] = "00" * 32
        tampered = EvidenceRevocationList.from_bytes(reencode(obj))
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([tampered], KEY, 100.0)

    def test_seal_enforces_freshness_and_sequence_floor(self):
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [snapshot(sequence=1, issued_at=200.0)], KEY, 100.0
            )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [snapshot(sequence=1)], KEY, 100.0, min=5
            )
        # Issued exactly at now is accepted.
        seal_evidence_revocation_list_bundle(
            [snapshot(sequence=1, issued_at=100.0)], KEY, 100.0
        )

    def test_seal_requires_strictly_increasing_sequences(self):
        s1 = snapshot(sequence=1)
        s2 = snapshot(sequence=2)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([], KEY, 100.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([s1, s1], KEY, 100.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([s2, s1], KEY, 100.0)
        # The first snapshot must already be past the start frontier.
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(s2, 100.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [s1], KEY, 100.0, start=auditor.checkpoint
            )
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [s2], KEY, 100.0, start=auditor.checkpoint
            )

    def test_seal_start_is_keyword_only(self):
        s1 = snapshot(sequence=1)
        frontier = EvidenceRevocationListAuditor(KEY).audit(s1, 100.0).checkpoint
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle([s1], KEY, 100.0, 0, None)
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle([s1], KEY, 100.0, 0, frontier)

    def test_seal_type_and_value_split(self):
        s1 = snapshot(sequence=1)
        # Key shape.
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle([s1], "key", 100.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([s1], b"", 100.0)
        # Snapshots iterable/item shape.
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle(42, KEY, 100.0)
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle([object()], KEY, 100.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([b"nonsense"], KEY, 100.0)
        # Start shape.
        with self.assertRaises(TypeError):
            seal_evidence_revocation_list_bundle([s1], KEY, 100.0, start=42)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [s1], KEY, 100.0, start=b"nonsense"
            )
        # Now/min contracts.
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([s1], KEY, "100")
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([s1], KEY, float("inf"))
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle([s1], KEY, 100.0, min=1.5)

    def test_seal_verifies_start_frontier_mac(self):
        s1 = snapshot(sequence=1)
        forged = EvidenceRevocationListState(1, 1, b"\x05" * 32, b"\x06" * 32)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [s1], KEY, 100.0, start=forged
            )
        foreign_auditor = EvidenceRevocationListAuditor(OTHER_KEY)
        foreign_auditor.audit(snapshot(sequence=1, key=OTHER_KEY), 100.0)
        with self.assertRaises(ValueError):
            seal_evidence_revocation_list_bundle(
                [s1], KEY, 100.0, start=foreign_auditor.checkpoint
            )


class AuditEvidenceRevocationListBundleTest(unittest.TestCase):
    def setUp(self):
        self.s1 = snapshot(sequence=1)
        self.s2 = snapshot(sequence=2)
        self.bundle = seal_evidence_revocation_list_bundle(
            [self.s1, self.s2], KEY, 100.0
        )

    def test_success_returns_end_frontier(self):
        end = audit_evidence_revocation_list_bundle(
            self.bundle.to_bytes(), KEY, 100.0
        )
        self.assertIsInstance(end, EvidenceRevocationListState)
        self.assertEqual(end, EvidenceRevocationListState.from_bytes(self.bundle.end))
        self.assertEqual(end.sequence, 2)
        # Stateless: no auditor is involved.
        self.assertEqual(
            audit_evidence_revocation_list_bundle(self.bundle, KEY, 200.0), end
        )

    def test_wrong_kind_and_key_shape(self):
        for bad in (object(), None, 7, self.s1):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_evidence_revocation_list_bundle(bad, KEY, 100.0)
        with self.assertRaises(TypeError):
            audit_evidence_revocation_list_bundle(self.bundle, "key", 100.0)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(self.bundle, b"", 100.0)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(b"nonsense", KEY, 100.0)

    def test_wrong_key_and_tampering_rejected(self):
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(self.bundle, OTHER_KEY, 100.0)
        encoding = self.bundle.to_bytes()
        flipped = bytearray(encoding)
        flipped[-8] ^= 0x01
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(bytes(flipped), KEY, 100.0)

    def test_tampered_inner_snapshot_rejected(self):
        obj = json.loads(self.bundle.to_bytes())
        snap_obj = json.loads(bytes.fromhex(obj["snapshots"][0]))
        snap_obj["mac"] = "00" * 32
        obj["snapshots"][0] = reencode(snap_obj).hex()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(reseal(obj), KEY, 100.0)

    def test_tampered_endpoints_rejected_even_with_valid_outer_mac(self):
        obj = json.loads(self.bundle.to_bytes())
        forged_end = EvidenceRevocationListState(
            1, 2, hashlib.sha256(self.s2.to_bytes()).digest(), b"\x08" * 32
        )
        obj["end"] = forged_end.to_bytes().hex()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(reseal(obj), KEY, 100.0)

        s3 = snapshot(sequence=3)
        single = seal_evidence_revocation_list_bundle([s3], KEY, 100.0)
        obj = json.loads(single.to_bytes())
        # A validly MAC'd frontier at the same sequence as the carried
        # snapshot: the strict-increase replay gate rejects it even though
        # the outer NPEB1 MAC was recomputed over the tampered body.
        obj["start"] = frontier_for(s3).to_bytes().hex()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(reseal(obj), KEY, 100.0)

    def test_end_must_match_replayed_snapshots(self):
        # Valid outer MAC and a validly MAC'd but different end frontier.
        obj = json.loads(self.bundle.to_bytes())
        obj["end"] = frontier_for(snapshot(sequence=9)).to_bytes().hex()
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(reseal(obj), KEY, 100.0)

    def test_freshness_and_floor_apply_per_snapshot(self):
        future = seal_evidence_revocation_list_bundle(
            [snapshot(sequence=1, issued_at=200.0)], KEY, 200.0
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(future, KEY, 100.0)
        low = seal_evidence_revocation_list_bundle(
            [snapshot(sequence=1)], KEY, 100.0, min=0
        )
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(low, KEY, 100.0, min=2)
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(self.bundle, KEY, "100")
        with self.assertRaises(ValueError):
            audit_evidence_revocation_list_bundle(self.bundle, KEY, 100.0, min=1.5)


class AuditorAuditBundleTest(unittest.TestCase):
    def setUp(self):
        self.snaps = [snapshot(sequence=n) for n in range(1, 5)]

    def test_empty_ledger_accepts_empty_start_and_advances(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        self.assertIsNone(auditor.checkpoint)
        bundle = seal_evidence_revocation_list_bundle(
            self.snaps[:2], KEY, 100.0
        )
        self.assertIs(auditor.audit_bundle(bundle, 100.0), auditor)
        self.assertEqual(
            auditor.checkpoint,
            audit_evidence_revocation_list_bundle(bundle, KEY, 100.0),
        )
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_non_empty_start_must_match_checkpoint(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit_bundle(
            seal_evidence_revocation_list_bundle([self.snaps[0]], KEY, 100.0),
            100.0,
        )
        # An empty-start bundle no longer fits.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                seal_evidence_revocation_list_bundle(
                    [self.snaps[1], self.snaps[2]], KEY, 100.0
                ),
                100.0,
            )
        # The matching continuation commits.
        cont = seal_evidence_revocation_list_bundle(
            [self.snaps[1], self.snaps[2]],
            KEY,
            100.0,
            start=auditor.checkpoint,
        )
        auditor.audit_bundle(cont, 100.0)
        self.assertEqual(auditor.checkpoint.sequence, 3)

    def test_empty_ledger_rejects_non_empty_start(self):
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[1]], KEY, 100.0, start=frontier_for(self.snaps[0])
        )
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(KEY).audit_bundle(bundle, 100.0)

    def test_replay_of_committed_bundle_rejected_and_state_unchanged(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        bundle = seal_evidence_revocation_list_bundle(
            [self.snaps[0], self.snaps[1]], KEY, 100.0
        )
        auditor.audit_bundle(bundle, 100.0)
        checkpoint = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle, 100.0)
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_failure_leaves_checkpoint_untouched(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        good = seal_evidence_revocation_list_bundle([self.snaps[0]], KEY, 100.0)
        auditor.audit_bundle(good, 100.0)
        checkpoint = auditor.checkpoint
        # A bundle starting right but carrying a bad snapshot.
        obj = json.loads(
            seal_evidence_revocation_list_bundle(
                [self.snaps[1]], KEY, 100.0, start=checkpoint
            ).to_bytes()
        )
        obj["snapshots"][0] = self.snaps[0].to_bytes().hex()
        with self.assertRaises(ValueError):
            auditor.audit_bundle(reseal(obj), KEY, 100.0)
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_per_snapshot_and_bundle_share_lock_and_frontier(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.snaps[0], 100.0)
        cont = seal_evidence_revocation_list_bundle(
            [self.snaps[1], self.snaps[2]],
            KEY,
            100.0,
            start=auditor.checkpoint,
        )
        auditor.audit_bundle(cont, 100.0)
        # Identical-snapshot per-snapshot replay remains a no-op.
        self.assertIs(auditor.audit(self.snaps[2], 100.0), auditor)
        self.assertEqual(auditor.checkpoint.sequence, 3)
        last = seal_evidence_revocation_list_bundle(
            [self.snaps[3]], KEY, 100.0, start=auditor.checkpoint
        )
        auditor.audit_bundle(last.to_bytes(), 100.0)
        self.assertEqual(auditor.checkpoint.sequence, 4)

    def test_type_and_value_split(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        with self.assertRaises(TypeError):
            auditor.audit_bundle(object(), 100.0)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(b"nonsense", 100.0)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(
                seal_evidence_revocation_list_bundle(
                    [self.snaps[0]], KEY, 100.0
                ),
                "100",
            )

    def test_concurrent_bundles_linearize_in_lock_order(self):
        # Competing one-snapshot forks all start from the empty ledger:
        # exactly one can commit, after which the others' empty start no
        # longer matches the advanced checkpoint.
        forks = [
            seal_evidence_revocation_list_bundle([snap], KEY, 100.0)
            for snap in self.snaps
        ]
        auditor = EvidenceRevocationListAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(len(forks))

        def commit(bundle):
            barrier.wait()
            try:
                auditor.audit_bundle(bundle, 100.0)
                outcomes.append(True)
            except ValueError:
                outcomes.append(False)

        threads = [threading.Thread(target=commit, args=(b,)) for b in forks]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(outcomes), 1)
        winner = next(
            bundle
            for bundle in forks
            if bundle.end == auditor.checkpoint.to_bytes()
        )
        self.assertIsNotNone(winner)
        self.assertIn(auditor.checkpoint.sequence, range(1, 5))


class EvidenceRevocationListBundleExportsTest(unittest.TestCase):
    def test_bundle_api_is_exported(self):
        import nearproof

        for name in (
            "EvidenceRevocationListBundle",
            "seal_evidence_revocation_list_bundle",
            "audit_evidence_revocation_list_bundle",
        ):
            self.assertIn(name, nearproof.__all__)
            self.assertIs(
                getattr(nearproof, name),
                getattr(
                    __import__("nearproof"),
                    name,
                ),
            )
        self.assertTrue(
            hasattr(nearproof.EvidenceRevocationListAuditor, "audit_bundle")
        )


if __name__ == "__main__":
    unittest.main()
