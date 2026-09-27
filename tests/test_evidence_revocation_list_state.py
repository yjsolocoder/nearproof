import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    EvidenceRevocationList,
    EvidenceRevocationListAuditor,
    EvidenceRevocationListState,
    Prover,
    Verifier,
    _EVIDENCE_REVOCATION_LIST_STATE_PREFIX,
    _encode_payload,
    _evidence_revocation_list_state_mac,
    _evidence_revocation_list_state_payload,
    make_evidence_revocation_list,
    revoke_evidence,
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


class EvidenceRevocationListStateContractTest(unittest.TestCase):
    def setUp(self):
        _v, _p, self.records = make_evidence_list(3)
        self.erl = snapshot([revoke_evidence(self.records[0], 0.0, KEY)])

    def test_is_frozen_and_equal_by_fields(self):
        first = make_state(1, self.erl)
        second = EvidenceRevocationListState(
            1, first.sequence, first.digest, first.mac
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(
            (first.version, first.sequence, first.digest, first.mac),
            (1, 1, hashlib.sha256(self.erl.to_bytes()).digest(), first.mac),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 2

    def test_positional_field_order(self):
        digest = b"\x01" * 32
        mac = b"\x02" * 32
        state = EvidenceRevocationListState(1, 9, digest, mac)
        self.assertEqual(
            (state.version, state.sequence, state.digest, state.mac),
            (1, 9, digest, mac),
        )

    def test_version_shape_vs_value(self):
        digest = b"\x01" * 32
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListState(bad, 1, digest, b"\x00" * 32)
        for bad in ("1", 1.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListState(bad, 1, digest, b"\x00" * 32)

    def test_sequence_is_non_bool_u64(self):
        digest = b"\x01" * 32
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListState(1, bad, digest, b"\x00" * 32)
        for bad in (-1, 2**64):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListState(1, bad, digest, b"\x00" * 32)
        for good in (0, 1, 2**64 - 1):
            EvidenceRevocationListState(1, good, digest, b"\x00" * 32)

    def test_digest_and_mac_shape_vs_value(self):
        for bad in ("ab" * 32, None, 7):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListState(1, 1, bad, b"\x00" * 32)
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListState(1, 1, b"\x00" * 32, bad)
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListState(1, 1, bad, b"\x00" * 32)
            with self.assertRaises(ValueError, msg=repr(bad)):
                EvidenceRevocationListState(1, 1, b"\x00" * 32, bad)


class EvidenceRevocationListStateEncodingTest(unittest.TestCase):
    def setUp(self):
        _v, _p, self.records = make_evidence_list(2)

    def test_to_bytes_shape(self):
        erl = snapshot([revoke_evidence(self.records[0], 4.0, KEY)], sequence=7)
        state = make_state(7, erl)
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
            erl = snapshot(sequence=sequence, issued_at=float(sequence))
            state = make_state(sequence, erl)
            self.assertEqual(
                EvidenceRevocationListState.from_bytes(state.to_bytes()), state
            )

    def test_from_bytes_non_bytes_is_type_error(self):
        state = make_state(1, snapshot(sequence=1))
        for bad in (state.to_bytes().decode(), None, 42, [1],
                    bytearray(state.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListState.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(make_state(1, snapshot(sequence=1)).to_bytes())
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
                EvidenceRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(make_state(1, snapshot(sequence=1)).to_bytes())
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
                EvidenceRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = make_state(1, snapshot(sequence=1)).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json", b"", bytes([len(data)]) + data):
            with self.assertRaises(ValueError, msg=blob):
                EvidenceRevocationListState.from_bytes(blob)

    def test_from_bytes_does_not_verify_mac(self):
        state = make_state(1, snapshot(sequence=1), mac=b"\x00" * 32)
        decoded = EvidenceRevocationListState.from_bytes(state.to_bytes())
        self.assertEqual(decoded, state)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class EvidenceRevocationListStateMacTest(unittest.TestCase):
    def setUp(self):
        _v, _p, self.records = make_evidence_list(3)

    def test_digest_is_sha256_of_canonical_snapshot(self):
        erl = snapshot(
            [revoke_evidence(self.records[0], 4.0, KEY)],
            sequence=3, issued_at=4.5,
        )
        state = make_state(3, erl)
        self.assertEqual(state.digest, hashlib.sha256(erl.to_bytes()).digest())
        # Two snapshots sharing a sequence differ in digest.
        other = snapshot(sequence=3, issued_at=9.0)
        self.assertNotEqual(
            hashlib.sha256(erl.to_bytes()).digest(),
            hashlib.sha256(other.to_bytes()).digest(),
        )

    def test_mac_formula_direct_concatenation(self):
        erl = snapshot(sequence=2, issued_at=5.0)
        state = make_state(2, erl)
        encoding = _encode_payload(_evidence_revocation_list_state_payload(state))
        self.assertEqual(
            state.mac,
            hmac.new(KEY, _EVIDENCE_REVOCATION_LIST_STATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        self.assertEqual(_EVIDENCE_REVOCATION_LIST_STATE_PREFIX, b"NPES1")
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_STATE_PREFIX
            + str(len(encoding)).encode() + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(state.mac, forged)
        self.assertNotEqual(
            state.mac,
            hmac.new(OTHER_KEY,
                     _EVIDENCE_REVOCATION_LIST_STATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )


class AuditorInitTest(unittest.TestCase):
    def setUp(self):
        _v, _p, self.records = make_evidence_list(2)
        self.erl = snapshot(sequence=1)

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(b"")
        for bad in (bytearray(KEY), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListAuditor(bad)

    def test_checkpoint_is_keyword_only(self):
        state = make_state(1, self.erl)
        with self.assertRaises(TypeError):
            EvidenceRevocationListAuditor(KEY, state)
        self.assertIsNone(EvidenceRevocationListAuditor(KEY).checkpoint)
        self.assertIsNone(
            EvidenceRevocationListAuditor(KEY, checkpoint=None).checkpoint
        )

    def test_checkpoint_wrong_kind_is_type_error(self):
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(KEY, checkpoint=b"not json")

    def test_checkpoint_mac_verified(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(
                KEY, checkpoint=make_state(1, self.erl, mac=b"\x00" * 32)
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(
                KEY, checkpoint=make_state(1, self.erl, key=OTHER_KEY)
            )
        state = make_state(1, self.erl)
        self.assertIs(
            EvidenceRevocationListAuditor(KEY, checkpoint=state).checkpoint,
            state,
        )
        restored = EvidenceRevocationListAuditor(
            KEY, checkpoint=state.to_bytes()
        ).checkpoint
        self.assertEqual(restored, state)

    def test_checkpoint_property_is_read_only(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = make_state(1, self.erl)


class AuditorGatingTest(unittest.TestCase):
    def setUp(self):
        _v, _p, self.records = make_evidence_list(3)
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(
            [revoke_evidence(self.records[0], 11.0, KEY)],
            sequence=2, issued_at=11.0,
        )
        self.e3 = snapshot(sequence=3, issued_at=12.0)
        # Same sequence as e1 but different content -> different digest.
        self.e1_other = snapshot(sequence=1, issued_at=12.0)

    def test_first_audit_advances_from_empty(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        self.assertIs(auditor.audit(self.e1, 10.0), auditor)
        self.assertEqual(auditor.checkpoint, make_state(1, self.e1))
        auditor2 = EvidenceRevocationListAuditor(KEY)
        self.assertIs(auditor2.audit(self.e1.to_bytes(), 10.0), auditor2)
        self.assertEqual(auditor2.checkpoint, make_state(1, self.e1))

    def test_higher_sequence_advances(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        auditor.audit(self.e2, 11.0)
        self.assertEqual(auditor.checkpoint, make_state(2, self.e2))
        auditor.audit(self.e3, 12.0)
        self.assertEqual(auditor.checkpoint, make_state(3, self.e3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e2, 11.0)
        with self.assertRaises(ValueError):
            auditor.audit(self.e1, 11.0)
        self.assertEqual(auditor.checkpoint, make_state(2, self.e2))

    def test_same_sequence_same_digest_is_a_replay(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        for _ in range(3):
            self.assertIs(auditor.audit(self.e1, 10.0), auditor)
            self.assertIs(auditor.audit(self.e1.to_bytes(), 10.0), auditor)
        self.assertEqual(auditor.checkpoint, make_state(1, self.e1))

    def test_same_sequence_different_digest_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 12.0)
        self.assertNotEqual(
            hashlib.sha256(self.e1.to_bytes()).digest(),
            hashlib.sha256(self.e1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.e1_other, 12.0)
        self.assertEqual(auditor.checkpoint, make_state(1, self.e1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        # A snapshot signed under another key never reaches the gate.
        with self.assertRaises(ValueError):
            auditor.audit(
                snapshot(sequence=3, issued_at=12.0, key=OTHER_KEY), 12.0
            )
        # Tampered snapshot bytes.
        tampered = self.e2.to_bytes().replace(b'"sequence":2', b'"sequence":9')
        self.assertNotEqual(tampered, self.e2.to_bytes())
        with self.assertRaises(ValueError):
            auditor.audit(tampered, 11.0)
        # An inner entry MAC forged but with a valid outer list MAC.
        bogus = dataclasses.replace(
            revoke_evidence(self.records[0], 0.0, KEY), mac=b"\x01" * 32
        )
        placeholder = EvidenceRevocationList(
            1, 0, 0.0, (bogus,), b"\x00" * 32
        )
        payload = {
            "version": 1,
            "sequence": 0,
            "issued_at": 0.0,
            "entries": [
                {
                    "version": 1,
                    "round_index": bogus.round_index,
                    "nonce": bogus.nonce.hex(),
                    "revoked_at": 0.0,
                    "mac": "01" * 32,
                }
            ],
        }
        outer = hmac.new(
            KEY, b"NPERL1" + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(placeholder, mac=outer)
        with self.assertRaises(ValueError):
            auditor.audit(forged, 10.0)
        # Malformed argument and bad parameter shapes.
        for bad in (b"not json",):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(bad, 10.0)
        for bad in (None, 42, object(), []):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                auditor.audit(bad, 10.0)
        self.assertEqual(auditor.checkpoint, make_state(1, self.e1))

    def test_future_snapshot_and_min_floor_enforced_then_gated(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        with self.assertRaises(ValueError):
            auditor.audit(self.e2, 10.5)  # issued_at 11.0 > now
        # A higher sequence below the explicit floor is rejected.
        with self.assertRaises(ValueError):
            auditor.audit(self.e2, 11.0, min=5)
        # The floor equals the carried sequence at the boundary.
        auditor.audit(self.e2, 11.0, min=2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.e2))
        for bad_now in ("11", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad_now)):
                auditor.audit(self.e3, bad_now)
        for bad_min in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad_min)):
                auditor.audit(self.e3, 12.0, min=bad_min)
        self.assertEqual(auditor.checkpoint, make_state(2, self.e2))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e2, 11.0)
        saved = auditor.checkpoint.to_bytes()
        restarted = EvidenceRevocationListAuditor(KEY, checkpoint=saved)
        # The old frontier still replays.
        self.assertIs(restarted.audit(self.e2, 11.0), restarted)
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.audit(self.e1, 11.0)
        # Progress past the restored frontier still advances.
        restarted.audit(self.e3.to_bytes(), 12.0)
        self.assertEqual(restarted.checkpoint, make_state(3, self.e3))

    def test_u64_boundary_sequence_advances_and_replays(self):
        top = snapshot(sequence=2**64 - 1, issued_at=100.0)
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(top, 100.0)
        self.assertEqual(auditor.checkpoint.sequence, 2**64 - 1)
        self.assertEqual(auditor.checkpoint, make_state(2**64 - 1, top))
        # The frontier itself still replays.
        auditor.audit(top.to_bytes(), 100.0)
        self.assertEqual(auditor.checkpoint.sequence, 2**64 - 1)


class AuditorConcurrencyTest(unittest.TestCase):
    def setUp(self):
        _v, _p, self.records = make_evidence_list(2)
        self.e1 = snapshot(sequence=1, issued_at=10.0)
        self.e2 = snapshot(sequence=2, issued_at=11.0)

    def test_concurrent_audits_never_roll_back(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        errors = []

        def worker(item):
            try:
                auditor.audit(item, 11.0)
            except ValueError:
                # Lower-sequence audits after e2 has advanced must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [self.e1, self.e1.to_bytes(), self.e2, self.e1,
                 self.e2.to_bytes(), self.e1] * 8
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint, make_state(2, self.e2))

    def test_advance_wins_against_rejected_rollback(self):
        start = threading.Barrier(2)
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.e1, 10.0)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    auditor.audit(self.e1, 11.0)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            auditor.audit(self.e2, 11.0)
            outcomes.append("advanced")

        threads = [threading.Thread(target=rollback),
                   threading.Thread(target=advance)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertIn("advanced", outcomes)
        self.assertTrue(outcomes.count("rejected") > 0)
        self.assertEqual(auditor.checkpoint, make_state(2, self.e2))


if __name__ == "__main__":
    unittest.main()
