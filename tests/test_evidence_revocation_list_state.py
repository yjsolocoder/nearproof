import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    BoundEvidenceRevocation,
    EvidenceRevocationList,
    EvidenceRevocationListAuditor,
    EvidenceRevocationListState,
    Prover,
    Verifier,
    _EVIDENCE_REVOCATION_LIST_STATE_PREFIX,
    _evidence_revocation_list_state_payload,
    _evidence_revocation_list_state_signature,
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


def revocation(record, revoked_at=0.0, key=KEY):
    return revoke_evidence(record, revoked_at, key)


def snapshot(entries=(), *, sequence=1, issued_at=100.0, key=KEY):
    return make_evidence_revocation_list(list(entries), sequence, issued_at, key)


def state_signature(key, state):
    return _evidence_revocation_list_state_signature(
        key, _evidence_revocation_list_state_payload(state)
    )


def make_state(sequence, digest, *, key=KEY, signature=None):
    if signature is None:
        placeholder = EvidenceRevocationListState(
            1, sequence, digest, b"\x00" * 32
        )
        signature = state_signature(key, placeholder)
    return EvidenceRevocationListState(1, sequence, digest, signature)


def state_of(erl, *, key=KEY, signature=None):
    digest = hashlib.sha256(erl.to_bytes()).digest()
    return make_state(erl.sequence, digest, key=key, signature=signature)


class EvidenceRevocationListStateContractTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)
        self.digest = hashlib.sha256(
            snapshot([revocation(self.records[0])]).to_bytes()
        ).digest()

    def make(self, **overrides):
        values = {
            "version": 1,
            "sequence": 7,
            "digest": self.digest,
            "signature": b"\x00" * 32,
        }
        values.update(overrides)
        return EvidenceRevocationListState(
            values["version"],
            values["sequence"],
            values["digest"],
            values["signature"],
        )

    def test_is_frozen_and_equal_by_fields(self):
        erl = snapshot([revocation(self.records[0])], sequence=3)
        first = state_of(erl)
        second = EvidenceRevocationListState(
            1, first.sequence, bytes(first.digest), bytes(first.signature)
        )
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.sequence = 4

    def test_positional_field_order(self):
        state = self.make(sequence=9, digest=b"\x01" * 32, signature=b"\x02" * 32)
        self.assertEqual(
            (state.version, state.sequence, state.digest, state.signature),
            (1, 9, b"\x01" * 32, b"\x02" * 32),
        )

    def test_version_shape_and_value(self):
        for bad in (0, 2, -1):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(version=bad)
        for bad in ("1", 1.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(version=bad)

    def test_sequence_shape_and_value(self):
        for good in (0, 1, 0xFFFFFFFFFFFFFFFF):
            self.assertEqual(self.make(sequence=good).sequence, good)
        for bad in ("1", 1.0, None, True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.make(sequence=bad)
        for bad in (-1, 0x10000000000000000):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.make(sequence=bad)

    def test_digest_and_signature_shape_and_value(self):
        for name in ("digest", "signature"):
            for bad in ("00" * 32, None, 7):
                with self.assertRaises(TypeError, msg=(name, repr(bad))):
                    self.make(**{name: bad})
            for bad in (b"", b"\x00" * 31, b"\x00" * 33):
                with self.assertRaises(ValueError, msg=(name, repr(bad))):
                    self.make(**{name: bad})


class EvidenceRevocationListStateEncodingTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def test_to_bytes_shape(self):
        erl = snapshot([revocation(self.records[0])], sequence=7)
        state = state_of(erl)
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
                    "signature": state.signature.hex(),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        self.assertEqual(
            list(json.loads(blob)), ["version", "sequence", "digest", "signature"]
        )

    def test_round_trip(self):
        for sequence in (0, 1, 2**64 - 1):
            state = state_of(snapshot(sequence=sequence))
            self.assertEqual(
                EvidenceRevocationListState.from_bytes(state.to_bytes()), state
            )

    def test_from_bytes_rejects_non_bytes(self):
        state = state_of(snapshot())
        for bad in (state.to_bytes().decode(), None, 42, [1], bytearray(state.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListState.from_bytes(bad)

    def test_from_bytes_rejects_key_violations(self):
        good = json.loads(state_of(snapshot()).to_bytes())
        blobs = [
            json.dumps(
                {
                    "sequence": good["sequence"],
                    "version": 1,
                    "digest": good["digest"],
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": good["sequence"],
                    "digest": good["digest"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": good["sequence"],
                    "digest": good["digest"],
                    "signature": good["signature"],
                    "extra": 1,
                },
                separators=(",", ":"),
            ).encode(),
            b'{"version":1,"sequence":1,"digest":'
            + json.dumps(good["digest"]).encode()
            + b',"signature":'
            + json.dumps(good["signature"]).encode()
            + b',"version":1}',
            json.dumps(
                {
                    "version": 2,
                    "sequence": good["sequence"],
                    "digest": good["digest"],
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                EvidenceRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_bad_values(self):
        good = json.loads(state_of(snapshot()).to_bytes())
        blobs = [
            json.dumps(
                {
                    "version": 1,
                    "sequence": True,
                    "digest": good["digest"],
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": -1,
                    "digest": good["digest"],
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 2**64,
                    "digest": good["digest"],
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": "zz",
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": good["digest"].upper(),
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": "00",
                    "signature": good["signature"],
                },
                separators=(",", ":"),
            ).encode(),
            json.dumps(
                {
                    "version": 1,
                    "sequence": 1,
                    "digest": good["digest"],
                    "signature": "ab" * 31,
                },
                separators=(",", ":"),
            ).encode(),
        ]
        for blob in blobs:
            with self.assertRaises(ValueError, msg=blob):
                EvidenceRevocationListState.from_bytes(blob)

    def test_from_bytes_rejects_non_canonical_encoding(self):
        data = state_of(snapshot()).to_bytes()
        for blob in (data + b" ", data.replace(b",", b", ", 1), b"{}", b"[]",
                     b"not json", b""):
            with self.assertRaises(ValueError, msg=blob):
                EvidenceRevocationListState.from_bytes(blob)

    def test_from_bytes_does_not_verify_signature(self):
        state = state_of(snapshot(), signature=b"\x00" * 32)
        decoded = EvidenceRevocationListState.from_bytes(state.to_bytes())
        self.assertEqual(decoded, state)
        self.assertEqual(decoded.signature, b"\x00" * 32)


class EvidenceRevocationListStateSignatureTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def test_digest_is_sha256_of_canonical_snapshot(self):
        erl = snapshot([revocation(self.records[0])], sequence=3, issued_at=4.5)
        state = state_of(erl)
        self.assertEqual(state.digest, hashlib.sha256(erl.to_bytes()).digest())

    def test_digest_distinguishes_same_sequence_snapshots(self):
        first = snapshot([], sequence=1, issued_at=1.0)
        second = snapshot([], sequence=1, issued_at=2.0)
        self.assertEqual(first.sequence, second.sequence)
        self.assertNotEqual(first.to_bytes(), second.to_bytes())
        self.assertNotEqual(
            hashlib.sha256(first.to_bytes()).digest(),
            hashlib.sha256(second.to_bytes()).digest(),
        )

    def test_signature_formula_direct_concatenation(self):
        erl = snapshot([revocation(self.records[0])], sequence=2)
        state = state_of(erl)
        encoding = json.dumps(
            _evidence_revocation_list_state_payload(state),
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            state.signature,
            hmac.new(KEY, _EVIDENCE_REVOCATION_LIST_STATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )
        self.assertEqual(_EVIDENCE_REVOCATION_LIST_STATE_PREFIX, b"NPES1")
        # No length prefix between the prefix and the encoding.
        forged = hmac.new(
            KEY,
            _EVIDENCE_REVOCATION_LIST_STATE_PREFIX
            + str(len(encoding)).encode()
            + encoding,
            hashlib.sha256,
        ).digest()
        self.assertNotEqual(state.signature, forged)
        self.assertNotEqual(
            state.signature,
            hmac.new(OTHER_KEY, _EVIDENCE_REVOCATION_LIST_STATE_PREFIX + encoding,
                     hashlib.sha256).digest(),
        )


class EvidenceRevocationListAuditorInitTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def test_key_contract(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(b"")
        for bad in (bytearray(KEY), "", None, 0, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListAuditor(bad)

    def test_checkpoint_is_keyword_only(self):
        state = state_of(snapshot())
        with self.assertRaises(TypeError):
            EvidenceRevocationListAuditor(KEY, state)
        self.assertIsNone(EvidenceRevocationListAuditor(KEY).checkpoint)
        self.assertIs(
            EvidenceRevocationListAuditor(KEY, checkpoint=None).checkpoint, None
        )

    def test_checkpoint_must_be_state_bytes_or_none(self):
        for bad in ("x", 1, [], {}, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                EvidenceRevocationListAuditor(KEY, checkpoint=bad)

    def test_checkpoint_malformed_bytes_rejected(self):
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(KEY, checkpoint=b"not json")

    def test_checkpoint_signature_verified(self):
        erl = snapshot()
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(
                KEY, checkpoint=state_of(erl, signature=b"\x00" * 32)
            )
        with self.assertRaises(ValueError):
            EvidenceRevocationListAuditor(
                KEY, checkpoint=state_of(erl, key=OTHER_KEY)
            )
        # Object and canonical bytes forms both accepted when the signature
        # is good.
        state = state_of(erl)
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
            auditor.checkpoint = state_of(snapshot())


class EvidenceRevocationListAuditorGatingTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)
        self.entry = revocation(self.records[0])
        self.s1 = snapshot([], sequence=1, issued_at=1.0)
        self.s2 = snapshot([self.entry], sequence=2, issued_at=5.0)
        self.s3 = snapshot([], sequence=3, issued_at=9.0)
        # Same sequence as s1 but different content -> different digest.
        self.s1_other = snapshot([self.entry], sequence=1, issued_at=9.0)

    def test_first_audit_advances_from_empty(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        self.assertIs(auditor.audit(self.s1, 10.0), auditor)
        self.assertEqual(auditor.checkpoint, state_of(self.s1))
        # Bytes input is accepted identically.
        auditor2 = EvidenceRevocationListAuditor(KEY)
        self.assertIs(auditor2.audit(self.s1.to_bytes(), 10.0), auditor2)
        self.assertEqual(auditor2.checkpoint, state_of(self.s1))

    def test_higher_sequence_advances(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 10.0)
        auditor.audit(self.s2, 10.0)
        self.assertEqual(auditor.checkpoint, state_of(self.s2))
        auditor.audit(self.s3, 10.0)
        self.assertEqual(auditor.checkpoint, state_of(self.s3))

    def test_lower_sequence_rejected_and_state_unchanged(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s2, 10.0)
        with self.assertRaises(ValueError):
            auditor.audit(self.s1, 10.0)
        self.assertEqual(auditor.checkpoint, state_of(self.s2))

    def test_same_sequence_same_digest_is_a_replay(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 10.0)
        for _ in range(3):
            self.assertIs(auditor.audit(self.s1, 10.0), auditor)
            self.assertIs(auditor.audit(self.s1.to_bytes(), 10.0), auditor)
        self.assertEqual(auditor.checkpoint, state_of(self.s1))

    def test_same_sequence_different_digest_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 10.0)
        self.assertNotEqual(
            hashlib.sha256(self.s1.to_bytes()).digest(),
            hashlib.sha256(self.s1_other.to_bytes()).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(self.s1_other, 10.0)
        self.assertEqual(auditor.checkpoint, state_of(self.s1))

    def test_min_floor_enforced_inside_lock(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s3, 10.0)
        # An above-frontier sequence below the caller floor is rejected.
        with self.assertRaises(ValueError):
            auditor.audit(
                snapshot([], sequence=4, issued_at=9.0), 10.0, min=5
            )
        # Equality on the floor is accepted.
        auditor.audit(
            snapshot([], sequence=4, issued_at=9.0), 10.0, min=4
        )
        self.assertEqual(auditor.checkpoint.sequence, 4)

    def test_future_snapshot_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(
                snapshot([], sequence=1, issued_at=10.0001), 10.0
            )
        self.assertIsNone(auditor.checkpoint)
        # issued_at == now is the boundary and succeeds.
        auditor.audit(snapshot([], sequence=1, issued_at=10.0), 10.0)
        self.assertIsNotNone(auditor.checkpoint)

    def test_bad_now_and_min(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        erl = self.s1
        for bad in ("10", None, True, float("inf"), float("nan")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(erl, bad)
        for bad in (True, False, 1.0, "0", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit(erl, 10.0, min=bad)
        self.assertIsNone(auditor.checkpoint)

    def test_bad_x_type_and_malformed_bytes(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        for bad in (None, 42, object(), [], self.entry):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                auditor.audit(bad, 10.0)
        with self.assertRaises(ValueError):
            auditor.audit(b"not json", 10.0)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(snapshot(key=OTHER_KEY), 10.0)
        self.assertIsNone(auditor.checkpoint)

    def test_inner_entry_mac_checked(self):
        bogus = BoundEvidenceRevocation(
            1, self.records[0].round_index, self.records[0].nonce, 0.0,
            b"\x01" * 32,
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
            KEY,
            b"NPERL1"
            + json.dumps(payload, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).digest()
        forged = dataclasses.replace(placeholder, mac=outer)
        auditor = EvidenceRevocationListAuditor(KEY)
        with self.assertRaisesRegex(ValueError, "bound evidence revocation mac"):
            auditor.audit(forged, 10.0)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_snapshot_bytes_rejected(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 10.0)
        blob = self.s2.to_bytes()
        tampered = blob.replace(b'"sequence":2', b'"sequence":9')
        self.assertNotEqual(tampered, blob)
        with self.assertRaises(ValueError):
            auditor.audit(tampered, 10.0)
        self.assertEqual(auditor.checkpoint, state_of(self.s1))

    def test_cryptographic_failure_leaves_state_unchanged(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s1, 10.0)
        # A snapshot signed under another key never reaches the gate.
        with self.assertRaises(ValueError):
            auditor.audit(
                snapshot([], sequence=3, key=OTHER_KEY), 10.0
            )
        # Tampered outer MAC.
        tampered = dataclasses.replace(
            self.s2, mac=bytes(b ^ 1 for b in self.s2.mac)
        )
        with self.assertRaises(ValueError):
            auditor.audit(tampered, 10.0)
        # Malformed argument.
        for bad in (None, 42, b"not json"):
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                auditor.audit(bad, 10.0)
        self.assertEqual(auditor.checkpoint, state_of(self.s1))

    def test_checkpoint_restarts_at_the_frontier(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s2, 10.0)
        saved = auditor.checkpoint.to_bytes()
        restarted = EvidenceRevocationListAuditor(KEY, checkpoint=saved)
        self.assertEqual(restarted.checkpoint, auditor.checkpoint)
        # The old frontier still replays.
        self.assertIs(restarted.audit(self.s2, 10.0), restarted)
        # Rollback is refused across the restart.
        with self.assertRaises(ValueError):
            restarted.audit(self.s1, 10.0)
        # A same-sequence/different-digest snapshot is refused too.
        with self.assertRaises(ValueError):
            restarted.audit(self.s1_other, 10.0)
        # Progress past the restored frontier still advances.
        restarted.audit(self.s3, 10.0)
        self.assertEqual(restarted.checkpoint, state_of(self.s3))

    def test_frontier_round_trip_is_byte_stable(self):
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(self.s2, 10.0)
        frontier = auditor.checkpoint
        blob = frontier.to_bytes()
        self.assertEqual(
            EvidenceRevocationListState.from_bytes(blob), frontier
        )
        self.assertEqual(
            EvidenceRevocationListAuditor(
                KEY, checkpoint=blob
            ).checkpoint,
            frontier,
        )


class EvidenceRevocationListAuditorConcurrencyTest(unittest.TestCase):
    def setUp(self):
        _verifier, _prover, self.records = make_evidence_list(3)

    def test_concurrent_audits_never_roll_back(self):
        s1 = snapshot([], sequence=1, issued_at=1.0)
        s2 = snapshot([], sequence=2, issued_at=5.0)
        auditor = EvidenceRevocationListAuditor(KEY)
        errors = []

        def worker(item):
            try:
                auditor.audit(item, 10.0)
            except ValueError:
                # Lower-sequence audits after s2 has advanced must reject.
                pass
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        items = [s1, s1.to_bytes(), s2, s1, s2.to_bytes(), s1] * 8
        threads = [threading.Thread(target=worker, args=(item,)) for item in items]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(auditor.checkpoint, state_of(s2))

    def test_advance_wins_against_rejected_rollback(self):
        s1 = snapshot([], sequence=1, issued_at=1.0)
        s2 = snapshot([], sequence=2, issued_at=5.0)
        start = threading.Barrier(2)
        auditor = EvidenceRevocationListAuditor(KEY)
        auditor.audit(s1, 10.0)
        outcomes = []

        def rollback():
            start.wait()
            for _ in range(1000):
                try:
                    auditor.audit(s1, 10.0)
                except ValueError:
                    outcomes.append("rejected")

        def advance():
            start.wait()
            auditor.audit(s2, 10.0)
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
        self.assertEqual(auditor.checkpoint, state_of(s2))


if __name__ == "__main__":
    unittest.main()
