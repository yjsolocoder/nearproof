import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
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
NOW = 130.0


def crl(entries=("a",), sequence=7, issued_at=120.0, *, root=ROOT,
        revoked_at=100.0):
    return make_observation_crl(
        [revoke_observation(ident, revoked_at, KEYS[ident])
         for ident in entries],
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
            1,
            sequence,
            hashlib.sha256(snapshot.to_bytes()).digest(),
            b"\x00" * 32,
        )
        mac = state_mac(root, placeholder)
    return ObservationRevocationListState(
        1,
        sequence,
        hashlib.sha256(snapshot.to_bytes()).digest(),
        mac,
    )


class ObservationRevocationListStateContractTest(unittest.TestCase):
    def setUp(self):
        self.snapshot = crl(("a", "b"))

    def test_is_frozen_hashable_and_equal_by_fields(self):
        first = make_state(7, self.snapshot)
        second = ObservationRevocationListState(
            1, first.sequence, first.digest, first.mac
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.sequence, first.digest, first.mac),
            (
                1,
                7,
                hashlib.sha256(self.snapshot.to_bytes()).digest(),
                first.mac,
            ),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 8

    def test_positional_field_order(self):
        digest = b"\x01" * 32
        mac = b"\x02" * 32
        state = ObservationRevocationListState(1, 9, digest, mac)
        self.assertEqual(
            (state.version, state.sequence, state.digest, state.mac),
            (1, 9, digest, mac),
        )

    def test_version_must_be_one(self):
        digest = b"\x01" * 32
        for bad in (0, 2, "1", 1.0, True, False, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(bad, 1, digest, b"\x00" * 32)

    def test_sequence_is_non_bool_u64(self):
        digest = b"\x01" * 32
        for bad in (True, False, 1.0, "1", None, -1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(1, bad, digest, b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            ObservationRevocationListState(1, good, digest, b"\x00" * 32)

    def test_digest_and_mac_must_be_exactly_32_bytes(self):
        for bad in (b"\x00" * 31, b"\x00" * 33, "", "ab" * 32, None, 7):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(1, 1, bad, b"\x00" * 32)
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState(1, 1, b"\x00" * 32, bad)


class ObservationRevocationListStateEncodingTest(unittest.TestCase):
    def setUp(self):
        self.snapshot = crl(("a", "b"))

    def test_to_bytes_shape(self):
        state = make_state(7, self.snapshot)
        blob = state.to_bytes()
        obj = json.loads(blob)
        self.assertEqual(list(obj), ["version", "sequence", "digest", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["sequence"], 7)
        self.assertEqual(obj["digest"], state.digest.hex())
        self.assertEqual(obj["mac"], state.mac.hex())
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

    def test_round_trip(self):
        for sequence in (0, 1, 2**64 - 1):
            state = make_state(sequence, crl(sequence=sequence))
            self.assertEqual(
                ObservationRevocationListState.from_bytes(state.to_bytes()),
                state,
            )

    def test_from_bytes_rejects_non_bytes(self):
        state = make_state(1, self.snapshot)
        for bad in (
            state.to_bytes().decode(),
            None,
            42,
            [1],
            bytearray(state.to_bytes()),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ObservationRevocationListState.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(make_state(1, self.snapshot).to_bytes())
        blobs = [
            json.dumps(
                {
                    "sequence": 1,
                    "version": 1,
                    "digest": good["digest"],
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": good["digest"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": good["digest"],
                    "mac": good["mac"],
                    "extra": 1,
                },
                separators=(",", ":"),
            ).encode(),
            # A genuinely duplicated key cannot be built via a Python dict
            # literal (it would collapse pre-serialization).
            (
                b'{"version":1,"sequence":1,"digest":'
                + json.dumps(good["digest"]).encode()
                + b',"mac":'
                + json.dumps(good["mac"]).encode()
                + b',"version":1}'
            ),
            json.dumps(
                {
                    "version": 2,
                    "sequence": 1,
                    "digest": good["digest"],
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(make_state(1, self.snapshot).to_bytes())
        blobs = [
            json.dumps(
                {
                    "version": 1,
                    "sequence": True,
                    "digest": good["digest"],
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": -1,
                    "digest": good["digest"],
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 2**64,
                    "digest": good["digest"],
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": "zz",
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": good["digest"].upper(),
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": "00",
                    "mac": good["mac"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": good["digest"],
                    "mac": "ab" * 31,
                },
                separators=(",", ":"),
            ).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = make_state(1, self.snapshot).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json", b""):
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        state = make_state(1, self.snapshot, mac=b"\x00" * 32)
        decoded = ObservationRevocationListState.from_bytes(state.to_bytes())
        self.assertEqual(decoded, state)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class ObservationRevocationListStateMacTest(unittest.TestCase):
    def test_digest_is_sha256_of_canonical_snapshot(self):
        snapshot = crl(("a", "c"), sequence=3, issued_at=4.5)
        state = make_state(3, snapshot)
        self.assertEqual(
            state.digest, hashlib.sha256(snapshot.to_bytes()).digest()
        )

    def test_mac_formula_direct_concatenation(self):
        snapshot = crl(sequence=2)
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
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            ROOT,
            _OBSERVATION_REVOCATION_LIST_STATE_PREFIX
            + str(len(encoding)).encode()
            + encoding,
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

    def test_state_mac_is_distinct_from_list_mac(self):
        # The NPORS1 prefix must not collide with the NPORL1 list MAC
        # even though both are HMACs under the same root.
        snapshot = crl(sequence=2)
        state = make_state(2, snapshot)
        self.assertNotEqual(state.mac, snapshot.mac)


class AuditorInitTest(unittest.TestCase):
    def setUp(self):
        self.snapshot = crl(("a",))

    def test_root_contract(self):
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(b"")
        for bad in (bytearray(ROOT), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                ObservationRevocationListAuditor(bad)

    def test_checkpoint_is_keyword_only(self):
        state = make_state(1, self.snapshot)
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
                ROOT,
                checkpoint=make_state(1, self.snapshot, mac=b"\x00" * 32),
            )
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(
                ROOT,
                checkpoint=make_state(1, self.snapshot, root=OTHER_ROOT),
            )
        state = make_state(1, self.snapshot)
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
            auditor.checkpoint = make_state(1, self.snapshot)


class AuditorGatingTest(unittest.TestCase):
    def setUp(self):
        self.s1 = crl(("a",), sequence=1)
        self.s2 = crl(("a", "b"), sequence=2)
        self.s3 = crl(("a", "b", "c"), sequence=3)
        # Same sequence as s1 but different content -> different digest.
        self.s1_other = crl((), sequence=1)

    def test_first_audit_advances_from_empty(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        self.assertIs(auditor.audit(self.s1, KEYS, now=NOW), auditor)
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))
        # Bytes input is accepted identically.
        auditor2 = ObservationRevocationListAuditor(ROOT)
        self.assertIs(
            auditor2.audit(self.s1.to_bytes(), KEYS, now=NOW), auditor2
        )
        self.assertEqual(auditor2.checkpoint, make_state(1, self.s1))

    def test_higher_sequence_advances(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        auditor.audit(self.s2, KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(2, self.s2))
        auditor.audit(self.s3, KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(3, self.s3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s2, KEYS, now=NOW)
        with self.assertRaises(ValueError):
            auditor.audit(self.s1, KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(2, self.s2))

    def test_same_sequence_same_digest_is_a_replay(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        for _ in range(3):
            self.assertIs(auditor.audit(self.s1, KEYS, now=NOW), auditor)
            self.assertIs(
                auditor.audit(self.s1.to_bytes(), KEYS, now=NOW), auditor
            )
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))

    def test_same_sequence_different_digest_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        self.assertNotEqual(
            hashlib.sha256(self.s1.to_bytes()).digest(),
            hashlib.sha256(self.s1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.s1_other, KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        # A list signed under another root never reaches the gate.
        with self.assertRaises(ValueError):
            auditor.audit(
                crl(("a",), sequence=3, root=OTHER_ROOT), KEYS, now=NOW
            )
        # Tampered list MAC.
        payload = json.loads(self.s2.to_bytes())
        payload["sequence"] = 9
        tampered = json.dumps(payload, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            auditor.audit(tampered, KEYS, now=NOW)
        # A forged per-entry MAC never reaches the gate.
        bogus_entry = revoke_observation("a", 100.0, b"\x01" * 32)
        forged = make_observation_crl([bogus_entry], 3, 120.0, ROOT)
        with self.assertRaises(ValueError):
            auditor.audit(forged, KEYS, now=NOW)
        # Unknown entry id.
        with self.assertRaises(ValueError):
            auditor.audit(self.s3, {"a": KEY_A, "b": KEY_B}, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))

    def test_snapshot_contract_errors_are_value_errors(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        for bad in (None, 42, object(), [], "crl", b"not json"):
            with self.assertRaises(ValueError, msg=repr(type(bad))):
                auditor.audit(bad, KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))

    def test_keys_shape_errors_are_type_errors(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        for bad in (["a"], {1: KEY_A}, {"a": "key"}, None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit(self.s2, bad, now=NOW)
        for bad in ({"": KEY_A}, {"a": b""}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(self.s2, bad, now=NOW)
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))

    def test_now_and_min_contract(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        # Shape errors on the keyword arguments are TypeErrors.
        for bad_now in (None, "130", True, False):
            with self.assertRaises(TypeError, msg=repr(bad_now)):
                auditor.audit(self.s3, KEYS, now=bad_now)
        for bad_min in (True, False, 1.5, "7", None):
            with self.assertRaises(TypeError, msg=repr(bad_min)):
                auditor.audit(self.s3, KEYS, now=NOW, min=bad_min)
        # Non-finite now and an out-of-range floor are value errors.
        for bad_now in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                auditor.audit(self.s3, KEYS, now=bad_now)
        for bad_min in (-1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                auditor.audit(self.s3, KEYS, now=NOW, min=bad_min)
        # now is required.
        with self.assertRaises(TypeError):
            auditor.audit(self.s3, KEYS)
        self.assertEqual(auditor.checkpoint, make_state(1, self.s1))

    def test_future_snapshot_and_min_floor_enforced_then_gated(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        # Future-dated list and future-dated entry never reach the gate.
        with self.assertRaises(ValueError):
            auditor.audit(
                crl(("a",), sequence=2, issued_at=200.0), KEYS, now=199.0
            )
        with self.assertRaises(ValueError):
            auditor.audit(
                crl(("a",), sequence=2, revoked_at=150.0), KEYS, now=149.0
            )
        # A higher sequence below the explicit floor is rejected.
        with self.assertRaises(ValueError):
            auditor.audit(self.s2, KEYS, now=NOW, min=5)
        # The floor equals the carried sequence at the boundary.
        auditor.audit(self.s2, KEYS, now=NOW, min=2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.s2))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s2, KEYS, now=NOW)
        saved = auditor.checkpoint.to_bytes()
        restarted = ObservationRevocationListAuditor(ROOT, checkpoint=saved)
        # The old frontier still replays.
        self.assertIs(
            restarted.audit(self.s2, KEYS, now=NOW), restarted
        )
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.audit(self.s1, KEYS, now=NOW)
        # Progress past the restored frontier still advances.
        restarted.audit(self.s3.to_bytes(), KEYS, now=NOW)
        self.assertEqual(restarted.checkpoint, make_state(3, self.s3))

    def test_restored_checkpoint_uses_canonical_bytes_form(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        blob = auditor.checkpoint.to_bytes()
        self.assertEqual(
            ObservationRevocationListAuditor(
                ROOT, checkpoint=blob
            ).checkpoint,
            auditor.checkpoint,
        )

    def test_u64_boundary_sequence_advances_and_replays(self):
        top = crl((), sequence=2**64 - 1)
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(top, KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint.sequence, 2**64 - 1)
        self.assertEqual(auditor.checkpoint, make_state(2**64 - 1, top))
        # The frontier itself still replays and cannot move past 2**64.
        auditor.audit(top.to_bytes(), KEYS, now=NOW)
        self.assertEqual(auditor.checkpoint.sequence, 2**64 - 1)
        # No valid snapshot can carry sequence 2**64: the record contract
        # rejects it before the auditor gate is ever reached.
        with self.assertRaises(ValueError):
            crl((), sequence=2**64)


class AuditorConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.s1 = crl(("a",), sequence=1)
        self.s2 = crl(("a", "b"), sequence=2)

    def test_concurrent_audits_never_roll_back(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        errors = []

        def worker(item):
            try:
                auditor.audit(item, KEYS, now=NOW)
            except ValueError:
                # Lower-sequence audits after s2 has advanced must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [
            self.s1, self.s1.to_bytes(), self.s2, self.s1,
            self.s2.to_bytes(), self.s1,
        ] * 8
        threads = [
            threading.Thread(target=worker, args=(item,)) for item in items
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.s2))

    def test_advance_wins_against_rejected_rollback(self):
        start = threading.Barrier(2)
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(self.s1, KEYS, now=NOW)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    auditor.audit(self.s1, KEYS, now=NOW)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            auditor.audit(self.s2, KEYS, now=NOW)
            outcomes.append("advanced")

        threads = [
            threading.Thread(target=rollback),
            threading.Thread(target=advance),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(auditor.checkpoint, make_state(2, self.s2))


if __name__ == "__main__":
    unittest.main()
