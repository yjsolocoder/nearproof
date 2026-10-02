import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    ObservationRevocationList,
    ObservationRevocationListAuditor,
    ObservationRevocationListState,
    _OBSERVATION_REVOCATION_LIST_STATE_PREFIX,
    _encode_payload,
    _observation_revocation_list_state_mac,
    _observation_revocation_list_state_payload,
    make_observation_crl,
    revoke_observation,
)

ROOT = b"\x09" * 32
OTHER_ROOT = b"\x08" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C}


def revocation(ident, revoked_at=100.0, *, key=None):
    return revoke_observation(ident, revoked_at, key or KEYS[ident])


def crl(entries=("a",), sequence=7, issued_at=120.0, *, root=ROOT, revoked_at=100.0):
    return make_observation_crl(
        [revocation(ident, revoked_at) for ident in entries],
        sequence,
        issued_at,
        root,
    )


def state_mac(root, state):
    return _observation_revocation_list_state_mac(
        root, _observation_revocation_list_state_payload(state)
    )


def make_state(sequence, snapshot, *, root=ROOT, mac=None):
    if mac is None:
        placeholder = ObservationRevocationListState(
            1, sequence, hashlib.sha256(snapshot.to_bytes()).digest(), b"\x00" * 32
        )
        mac = state_mac(root, placeholder)
    return ObservationRevocationListState(
        1, sequence, hashlib.sha256(snapshot.to_bytes()).digest(), mac
    )


class ObservationRevocationListStateContractTest(unittest.TestCase):
    def setUp(self):
        self.crl = crl(sequence=7)

    def test_is_frozen_hashable_and_equal_by_fields(self):
        first = make_state(7, self.crl)
        second = ObservationRevocationListState(
            1, first.sequence, first.digest, first.mac
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.sequence, first.digest, first.mac),
            (1, 7, hashlib.sha256(self.crl.to_bytes()).digest(), first.mac),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 8
        # Frozen, hashable states work as dict keys and set members.
        self.assertEqual({first: 1}.get(second), 1)
        self.assertEqual(len({first, second}), 1)

    def test_positional_field_order(self):
        digest = b"\x01" * 32
        mac = b"\x02" * 32
        state = ObservationRevocationListState(1, 9, digest, mac)
        self.assertEqual(
            (state.version, state.sequence, state.digest, state.mac),
            (1, 9, digest, mac),
        )

    def test_version_shape_vs_value(self):
        digest = b"\x01" * 32
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(bad, 1, digest, b"\x00" * 32)
        for bad in ("1", 1.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListState(bad, 1, digest, b"\x00" * 32)

    def test_sequence_is_non_bool_u64(self):
        digest = b"\x01" * 32
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListState(1, bad, digest, b"\x00" * 32)
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(1, bad, digest, b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            ObservationRevocationListState(1, good, digest, b"\x00" * 32)

    def test_digest_and_mac_shape_vs_value(self):
        for bad in ("ab" * 32, None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListState(1, 1, bad, b"\x00" * 32)
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListState(1, 1, b"\x00" * 32, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(1, 1, bad, b"\x00" * 32)
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(1, 1, b"\x00" * 32, bad)


class ObservationRevocationListStateEncodingTest(unittest.TestCase):
    def test_to_bytes_shape(self):
        snapshot = crl(sequence=7, issued_at=120.0)
        state = make_state(7, snapshot)
        blob = state.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        self.assertEqual(
            blob,
            json.dumps(
                {
                    "version": 1,
                    "sequence": 7,
                    "digest": state.digest.hex(),
                    "mac": state.mac.hex(),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        self.assertEqual(
            list(json.loads(blob)), ["version", "sequence", "digest", "mac"]
        )

    def test_round_trip(self):
        for sequence in (0, 1, 2**64 - 1):
            snapshot = crl(sequence=sequence, issued_at=float(sequence) or 1.0)
            state = make_state(sequence, snapshot)
            self.assertEqual(
                ObservationRevocationListState.from_bytes(state.to_bytes()), state
            )

    def test_from_bytes_non_bytes_is_type_error(self):
        state = make_state(1, crl(sequence=1))
        for bad in (state.to_bytes().decode(), None, 42, [1],
                    bytearray(state.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListState.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(make_state(1, crl(sequence=1)).to_bytes())
        blobs = [
            json.dumps({"sequence": 1, "version": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"], "mac": good["mac"],
                        "extra": 1}, separators=(",", ":")).encode(),
            (
                b'{"version":1,"sequence":1,"digest":'
                + json.dumps(good["digest"]).encode()
                + b',"mac":'
                + json.dumps(good["mac"]).encode()
                + b',"version":1}'
            ),
            json.dumps({"version": 2, "sequence": 1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(make_state(1, crl(sequence=1)).to_bytes())
        blobs = [
            json.dumps({"version": 1, "sequence": True,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": -1,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 2**64,
                        "digest": good["digest"], "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": "zz", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"].upper(),
                        "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": "00", "mac": good["mac"]},
                       separators=(",", ":")).encode(),
            json.dumps({"version": 1, "sequence": 1,
                        "digest": good["digest"], "mac": "ab" * 31},
                       separators=(",", ":")).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = make_state(1, crl(sequence=1)).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json", b"", bytes([len(data)]) + data):
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        state = make_state(1, crl(sequence=1), mac=b"\x00" * 32)
        decoded = ObservationRevocationListState.from_bytes(state.to_bytes())
        self.assertEqual(decoded, state)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class ObservationRevocationListStateMacTest(unittest.TestCase):
    def test_digest_is_sha256_of_canonical_snapshot(self):
        snapshot = crl(sequence=3, issued_at=120.0)
        state = make_state(3, snapshot)
        self.assertEqual(
            state.digest, hashlib.sha256(snapshot.to_bytes()).digest()
        )
        # Two snapshots sharing a sequence differ in digest.
        other = crl(sequence=3, issued_at=9.0)
        self.assertNotEqual(
            hashlib.sha256(snapshot.to_bytes()).digest(),
            hashlib.sha256(other.to_bytes()).digest(),
        )

    def test_mac_formula_direct_concatenation(self):
        snapshot = crl(sequence=2, issued_at=120.0)
        state = make_state(2, snapshot)
        encoding = _encode_payload(
            _observation_revocation_list_state_payload(state)
        )
        self.assertEqual(
            state.mac,
            hmac.new(
                ROOT,
                _OBSERVATION_REVOCATION_LIST_STATE_PREFIX + encoding,
                hashlib.sha256,
            ).digest(),
        )
        self.assertEqual(_OBSERVATION_REVOCATION_LIST_STATE_PREFIX, b"NPORS1")
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            ROOT,
            _OBSERVATION_REVOCATION_LIST_STATE_PREFIX
            + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(state.mac, forged)
        self.assertNotEqual(
            state.mac,
            hmac.new(
                OTHER_ROOT,
                _OBSERVATION_REVOCATION_LIST_STATE_PREFIX + encoding,
                hashlib.sha256,
            ).digest(),
        )


class AuditorInitTest(unittest.TestCase):
    def setUp(self):
        self.crl = crl(sequence=1, issued_at=10.0, revoked_at=5.0)

    def test_root_contract(self):
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(b"")
        for bad in (bytearray(ROOT), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListAuditor(bad)

    def test_checkpoint_is_keyword_only(self):
        state = make_state(1, self.crl)
        with self.assertRaises(TypeError):
            ObservationRevocationListAuditor(ROOT, state)
        self.assertIsNone(ObservationRevocationListAuditor(ROOT).checkpoint)
        self.assertIsNone(
            ObservationRevocationListAuditor(ROOT, checkpoint=None).checkpoint
        )

    def test_checkpoint_wrong_kind_is_type_error(self):
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListAuditor(ROOT, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(ROOT, checkpoint=b"not json")

    def test_checkpoint_mac_verified(self):
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(
                ROOT, checkpoint=make_state(1, self.crl, mac=b"\x00" * 32)
            )
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(
                ROOT, checkpoint=make_state(1, self.crl, root=OTHER_ROOT)
            )
        state = make_state(1, self.crl)
        self.assertIs(
            ObservationRevocationListAuditor(
                ROOT, checkpoint=state
            ).checkpoint,
            state,
        )
        restored = ObservationRevocationListAuditor(
            ROOT, checkpoint=state.to_bytes()
        ).checkpoint
        self.assertEqual(restored, state)

    def test_checkpoint_property_is_read_only(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = make_state(1, self.crl)


class AuditorGatingTest(unittest.TestCase):
    def setUp(self):
        self.c1 = crl(("a",), sequence=1, issued_at=10.0, revoked_at=5.0)
        self.c2 = crl(
            ("a", "b"), sequence=2, issued_at=11.0, revoked_at=5.0
        )
        self.c3 = crl(
            ("a", "b", "c"), sequence=3, issued_at=12.0, revoked_at=5.0
        )
        # Same sequence as c1 but different content -> different digest.
        self.c1_other = crl(
            ("a",), sequence=1, issued_at=12.0, revoked_at=5.0
        )

    def test_first_audit_advances_from_empty(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        self.assertIs(auditor.audit(self.c1, KEYS, now=10.0), auditor)
        self.assertEqual(auditor.checkpoint, make_state(1, self.c1))
        auditor2 = ObservationRevocationListAuditor(ROOT)
        self.assertIs(
            auditor2.audit(self.c1.to_bytes(), KEYS, now=10.0), auditor2
        )
        self.assertEqual(auditor2.checkpoint, make_state(1, self.c1))

    def test_higher_sequence_advances(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=10.0)
        auditor.audit(self.c2, KEYS, now=11.0)
        self.assertEqual(auditor.checkpoint, make_state(2, self.c2))
        auditor.audit(self.c3, KEYS, now=12.0)
        self.assertEqual(auditor.checkpoint, make_state(3, self.c3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c2, KEYS, now=11.0)
        with self.assertRaises(ValueError):
            auditor.audit(self.c1, KEYS, now=11.0)
        self.assertEqual(auditor.checkpoint, make_state(2, self.c2))

    def test_same_sequence_same_digest_is_a_replay_returning_self(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=10.0)
        checkpoint = auditor.checkpoint
        for _ in range(3):
            self.assertIs(auditor.audit(self.c1, KEYS, now=10.0), auditor)
            self.assertIs(
                auditor.audit(self.c1.to_bytes(), KEYS, now=10.0), auditor
            )
        self.assertEqual(auditor.checkpoint, make_state(1, self.c1))
        # A replay does not mint a replacement checkpoint object.
        self.assertIs(auditor.checkpoint, checkpoint)

    def test_same_sequence_different_digest_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=12.0)
        self.assertNotEqual(
            hashlib.sha256(self.c1.to_bytes()).digest(),
            hashlib.sha256(self.c1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.c1_other, KEYS, now=12.0)
        self.assertEqual(auditor.checkpoint, make_state(1, self.c1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=10.0)
        # A snapshot signed under another root never reaches the gate.
        with self.assertRaises(ValueError):
            auditor.audit(
                crl(
                    ("a",),
                    sequence=3,
                    issued_at=12.0,
                    revoked_at=5.0,
                    root=OTHER_ROOT,
                ),
                KEYS,
                now=12.0,
            )
        # Tampered snapshot bytes.
        tampered = self.c2.to_bytes().replace(b'"sequence":2', b'"sequence":9')
        self.assertNotEqual(tampered, self.c2.to_bytes())
        with self.assertRaises(ValueError):
            auditor.audit(tampered, KEYS, now=11.0)
        # An inner entry MAC forged but with a valid outer list MAC.
        bogus = dataclasses.replace(
            revocation("a", revoked_at=0.0), mac=b"\x01" * 32
        )
        placeholder = ObservationRevocationList(
            1, 0, 0.0, (bogus,), b"\x00" * 32
        )
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": 0.0,
            "entries": [
                {
                    "version": 1,
                    "id": "a",
                    "revoked_at": 0.0,
                    "mac": "01" * 32,
                }
            ],
        }
        outer = hmac.new(
            ROOT,
            b"NPORL1" + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(placeholder, mac=outer)
        with self.assertRaises(ValueError):
            auditor.audit(forged, KEYS, now=10.0)
        # Unknown entry id.
        with self.assertRaises(ValueError):
            auditor.audit(
                crl(("a", "b"), sequence=3, issued_at=12.0, revoked_at=5.0),
                {"a": KEY_A},
                now=12.0,
            )
        # Malformed snapshot bytes.
        with self.assertRaises(ValueError):
            auditor.audit(b"not json", KEYS, now=10.0)
        # A foreign snapshot type is a snapshot violation.
        for bad in (None, 42, object(), []):
            with self.assertRaises(ValueError, msg=repr(type(bad))):
                auditor.audit(bad, KEYS, now=10.0)
        self.assertEqual(auditor.checkpoint, make_state(1, self.c1))

    def test_future_snapshot_and_min_floor_enforced_then_gated(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=10.0)
        with self.assertRaises(ValueError):
            auditor.audit(self.c2, KEYS, now=10.5)  # issued_at 11.0 > now
        # A higher sequence below the explicit floor is rejected.
        with self.assertRaises(ValueError):
            auditor.audit(self.c2, KEYS, now=11.0, min=5)
        # The floor equals the carried sequence at the boundary.
        auditor.audit(self.c2, KEYS, now=11.0, min=2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.c2))
        for bad_now in (float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                auditor.audit(self.c3, KEYS, now=bad_now)
        for bad_min in (True, False, 1.0, "0", None):
            with self.assertRaises(TypeError, msg=repr(bad_min)):
                auditor.audit(self.c3, KEYS, now=12.0, min=bad_min)
        with self.assertRaises(ValueError):
            auditor.audit(self.c3, KEYS, now=12.0, min=2**64)
        with self.assertRaises(ValueError):
            auditor.audit(self.c3, KEYS, now=12.0, min=-1)
        self.assertEqual(auditor.checkpoint, make_state(2, self.c2))

    def test_keyword_shape_errors_are_type_errors(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=10.0)
        for bad_now in ("11", None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad_now)):
                auditor.audit(self.c2, KEYS, now=bad_now)
        for bad_keys in (None, 42, [], {1: KEY_A}, {"a": "k"}):
            with self.assertRaises(TypeError, msg=repr(bad_keys)):
                auditor.audit(self.c2, bad_keys, now=11.0)
        # Empty id/key remain value violations.
        with self.assertRaises(ValueError):
            auditor.audit(self.c2, {"": KEY_A}, now=11.0)
        with self.assertRaises(ValueError):
            auditor.audit(self.c2, {"a": b""}, now=11.0)
        self.assertEqual(auditor.checkpoint, make_state(1, self.c1))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c2, KEYS, now=11.0)
        saved = auditor.checkpoint.to_bytes()
        restarted = ObservationRevocationListAuditor(ROOT, checkpoint=saved)
        # The old frontier still replays.
        self.assertIs(
            restarted.audit(self.c2, KEYS, now=11.0), restarted
        )
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.audit(self.c1, KEYS, now=11.0)
        # Progress past the restored frontier still advances.
        restarted.audit(self.c3.to_bytes(), KEYS, now=12.0)
        self.assertEqual(restarted.checkpoint, make_state(3, self.c3))

    def test_u64_boundary_sequence_advances_and_replays(self):
        top = crl(sequence=2**64 - 1, issued_at=100.0, revoked_at=5.0)
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(top, KEYS, now=100.0)
        self.assertEqual(auditor.checkpoint.sequence, 2**64 - 1)
        self.assertEqual(auditor.checkpoint, make_state(2**64 - 1, top))
        # The frontier itself still replays.
        auditor.audit(top.to_bytes(), KEYS, now=100.0)
        self.assertEqual(auditor.checkpoint.sequence, 2**64 - 1)


class AuditorConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.c1 = crl(("a",), sequence=1, issued_at=10.0, revoked_at=5.0)
        self.c2 = crl(
            ("a", "b"), sequence=2, issued_at=11.0, revoked_at=5.0
        )

    def test_concurrent_audits_never_roll_back(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        errors = []

        def worker(item):
            try:
                auditor.audit(item, KEYS, now=11.0)
            except ValueError:
                # Lower-sequence audits after c2 has advanced must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [self.c1, self.c1.to_bytes(), self.c2, self.c1,
                 self.c2.to_bytes(), self.c1] * 8
        threads = [
            threading.Thread(target=worker, args=(item,)) for item in items
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.c2))

    def test_advance_wins_against_rejected_rollback(self):
        start = threading.Barrier(2)
        stop = threading.Event()
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.c1, KEYS, now=10.0)
        outcomes = []

        def rollback():
            start.wait()
            while not stop.is_set():
                try:
                    auditor.audit(self.c1, KEYS, now=11.0)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            auditor.audit(self.c2, KEYS, now=11.0)
            outcomes.append("advanced")
            stop.set()

        threads = [threading.Thread(target=rollback),
                   threading.Thread(target=advance)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertEqual(auditor.checkpoint, make_state(2, self.c2))
        # Deterministically, on the now-advanced frontier the old snapshot
        # is a rejected rollback (the hammering loop above only proves the
        # concurrent case never corrupted the frontier).
        with self.assertRaises(ValueError):
            auditor.audit(self.c1, KEYS, now=11.0)


if __name__ == "__main__":
    unittest.main()
