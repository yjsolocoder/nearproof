"""Protocol-compatibility regression tests for the observation revocation
list auditor, its checkpoint export and the restore path.

Unlike the contract tests, every expectation here is a fixed byte literal
pinned in this file, and every signature is additionally recomputed from
the documented public wire format with nothing but the standard library
(``json``/``hmac``/``hashlib``) — no private helper of the library under
test is consulted, so a synchronised drift of the library's private
encoding or signing helpers cannot keep these tests green.

Fixed inputs: root key ``ROOT``, entry keys ``KEY_ALPHA``/``KEY_BETA``,
sequences 5 and 9, and the timestamps 42.5, 100.0, 200.5 and 300.25.
"""

import hashlib
import hmac
import json
import unittest

from nearproof import (
    ObservationRevocation,
    ObservationRevocationList,
    ObservationRevocationListAuditor,
    ObservationRevocationListState,
    audit_observation_crl,
    make_observation_crl,
    revoke_observation,
)

# Fixed key material and per-verifier key mapping.
ROOT = b"np-root-key-0123456789abcdef"
KEY_ALPHA = b"np-alpha-key-0123456789abcde"
KEY_BETA = b"np-beta-key-0123456789abcdef"
KEYS = {"alpha": KEY_ALPHA, "beta": KEY_BETA}

# --- Fixed sample bytes (pinned protocol vectors) -------------------------

ENTRY_ALPHA_BYTES = (
    b'{"version":1,"id":"alpha","revoked_at":100.0,'
    b'"mac":"7bbdc4ba604f1af29700611b5ba9477e45913a7f187f1854499951f57d4cdf25"}'
)
ENTRY_BETA_BYTES = (
    b'{"version":1,"id":"beta","revoked_at":200.5,'
    b'"mac":"e51bede7e5999d94db883980506dd034ffc731493c2c59d5f50114aa027f048e"}'
)
EMPTY_SEQ5_BYTES = (
    b'{"version":1,"sequence":5,"issued_at":42.5,"entries":[],'
    b'"mac":"f1bf21b8aa589deccd5c57011dad578a4f997db6b191082606f9c2e0ce4e6443"}'
)
TWO_SEQ9_BYTES = (
    b'{"version":1,"sequence":9,"issued_at":300.25,'
    b'"entries":['
    b'{"version":1,"id":"alpha","revoked_at":100.0,'
    b'"mac":"7bbdc4ba604f1af29700611b5ba9477e45913a7f187f1854499951f57d4cdf25"},'
    b'{"version":1,"id":"beta","revoked_at":200.5,'
    b'"mac":"e51bede7e5999d94db883980506dd034ffc731493c2c59d5f50114aa027f048e"}'
    b'],'
    b'"mac":"3fe17521d9d804681f39a4ddb2a800a788066a1f0d01955b2d5c731006ece267"}'
)
# Same sequence and issued_at as TWO_SEQ9_BYTES but different content, so a
# different snapshot digest: the same-sequence/different-digest rejection
# vector.
EMPTY_SEQ9_BYTES = (
    b'{"version":1,"sequence":9,"issued_at":300.25,"entries":[],'
    b'"mac":"33462a2f07dc8f4201583c01198cbf1f1257bc70ed60b24f0baf6778e3950ea6"}'
)
STATE_EMPTY_SEQ5_BYTES = (
    b'{"version":1,"sequence":5,'
    b'"digest":"915e6e52c684fbc1f5408391624684a9b41aa98b320112fffe4aaa2f126e7eaa",'
    b'"mac":"76f36a28817340b4f7de8a30d92a9c355ce4f22aaad02195dc602d39228c45b3"}'
)
STATE_TWO_SEQ9_BYTES = (
    b'{"version":1,"sequence":9,'
    b'"digest":"b328b8cd35ed4f455a9604297545724087d593c080738b9153afff637f56552e",'
    b'"mac":"2e4089f9b1b0a9295386a5025961c22f1ac2c92241941165fa44405b9a09c0a1"}'
)

# --- Independent recomputation from the documented public format ----------
#
# The canonical encoding is compact UTF-8 JSON (","/":" separators, keys in
# field order, hex fields lowercase); the list MAC is
# HMAC-SHA256(root, b"NPORL1" + encoding) and the checkpoint MAC is
# HMAC-SHA256(root, b"NPORS1" + encoding), each over every field except
# "mac" itself, prefix and encoding concatenated directly. The checkpoint
# digest is SHA256 over the canonical snapshot bytes.


def _canonical(payload):
    return json.dumps(payload, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def _entry_mac(key, ident, revoked_at):
    payload = {"version": 1, "id": ident, "revoked_at": revoked_at}
    return hmac.new(key, _canonical(payload), hashlib.sha256).digest()


def _entry_object(ident, revoked_at, mac):
    return {
        "version": 1,
        "id": ident,
        "revoked_at": revoked_at,
        "mac": mac.hex(),
    }


def _list_mac(root, sequence, issued_at, entries):
    payload = {
        "version": 1,
        "sequence": sequence,
        "issued_at": issued_at,
        "entries": [
            _entry_object(ident, revoked_at, mac)
            for ident, revoked_at, mac in entries
        ],
    }
    return hmac.new(root, b"NPORL1" + _canonical(payload), hashlib.sha256).digest()


def _state_mac(root, sequence, digest):
    payload = {"version": 1, "sequence": sequence, "digest": digest.hex()}
    return hmac.new(root, b"NPORS1" + _canonical(payload), hashlib.sha256).digest()


def _list_bytes(sequence, issued_at, entries):
    payload = {
        "version": 1,
        "sequence": sequence,
        "issued_at": issued_at,
        "entries": [
            _entry_object(ident, revoked_at, mac)
            for ident, revoked_at, mac in entries
        ],
    }
    payload["mac"] = _list_mac(ROOT, sequence, issued_at, entries).hex()
    return _canonical(payload)


class FixedVectorTest(unittest.TestCase):
    """The public signing entry points reproduce the pinned bytes exactly."""

    def test_empty_list_vector(self):
        crl = make_observation_crl([], 5, 42.5, ROOT)
        self.assertEqual(crl.to_bytes(), EMPTY_SEQ5_BYTES)
        self.assertEqual(
            (crl.version, crl.sequence, crl.issued_at, crl.entries),
            (1, 5, 42.5, ()),
        )

    def test_two_entry_list_vector(self):
        entry_alpha = revoke_observation("alpha", 100.0, KEY_ALPHA)
        entry_beta = revoke_observation("beta", 200.5, KEY_BETA)
        self.assertEqual(entry_alpha.to_bytes(), ENTRY_ALPHA_BYTES)
        self.assertEqual(entry_beta.to_bytes(), ENTRY_BETA_BYTES)
        # Input order must not influence the canonical encoding: the
        # entries are pinned sorted by id in the expected bytes.
        crl = make_observation_crl([entry_beta, entry_alpha], 9, 300.25, ROOT)
        self.assertEqual(crl.to_bytes(), TWO_SEQ9_BYTES)
        self.assertEqual(
            [entry.id for entry in crl.entries], ["alpha", "beta"]
        )

    def test_vectors_pass_public_parsers(self):
        for blob in (EMPTY_SEQ5_BYTES, TWO_SEQ9_BYTES, EMPTY_SEQ9_BYTES):
            crl = ObservationRevocationList.from_bytes(blob)
            self.assertEqual(crl.to_bytes(), blob)
        for blob in (ENTRY_ALPHA_BYTES, ENTRY_BETA_BYTES):
            entry = ObservationRevocation.from_bytes(blob)
            self.assertEqual(entry.to_bytes(), blob)
        for blob in (STATE_EMPTY_SEQ5_BYTES, STATE_TWO_SEQ9_BYTES):
            state = ObservationRevocationListState.from_bytes(blob)
            self.assertEqual(state.to_bytes(), blob)
        # The nested entries of the list vector are the entry vectors.
        crl = ObservationRevocationList.from_bytes(TWO_SEQ9_BYTES)
        self.assertEqual(crl.entries[0].to_bytes(), ENTRY_ALPHA_BYTES)
        self.assertEqual(crl.entries[1].to_bytes(), ENTRY_BETA_BYTES)


class IndependentProtocolCheckTest(unittest.TestCase):
    """Every signature and digest in the pinned vectors is recomputed from
    the documented public format with the standard library only."""

    def test_entry_signatures(self):
        alpha = ObservationRevocation.from_bytes(ENTRY_ALPHA_BYTES)
        beta = ObservationRevocation.from_bytes(ENTRY_BETA_BYTES)
        self.assertEqual(alpha.mac, _entry_mac(KEY_ALPHA, "alpha", 100.0))
        self.assertEqual(beta.mac, _entry_mac(KEY_BETA, "beta", 200.5))
        # The entries are not self-signed under the root or each other's key.
        self.assertNotEqual(alpha.mac, _entry_mac(KEY_BETA, "alpha", 100.0))
        self.assertNotEqual(alpha.mac, _entry_mac(ROOT, "alpha", 100.0))

    def test_list_signatures(self):
        entries = [
            ("alpha", 100.0, bytes.fromhex(json.loads(ENTRY_ALPHA_BYTES)["mac"])),
            ("beta", 200.5, bytes.fromhex(json.loads(ENTRY_BETA_BYTES)["mac"])),
        ]
        empty5 = ObservationRevocationList.from_bytes(EMPTY_SEQ5_BYTES)
        self.assertEqual(empty5.mac, _list_mac(ROOT, 5, 42.5, []))
        two9 = ObservationRevocationList.from_bytes(TWO_SEQ9_BYTES)
        self.assertEqual(two9.mac, _list_mac(ROOT, 9, 300.25, entries))
        empty9 = ObservationRevocationList.from_bytes(EMPTY_SEQ9_BYTES)
        self.assertEqual(empty9.mac, _list_mac(ROOT, 9, 300.25, []))
        # The independently rebuilt encodings equal the pinned bytes.
        self.assertEqual(_list_bytes(9, 300.25, entries), TWO_SEQ9_BYTES)
        self.assertEqual(_list_bytes(5, 42.5, []), EMPTY_SEQ5_BYTES)

    def test_snapshot_digests_and_checkpoint_signatures(self):
        for list_blob, state_blob in (
            (EMPTY_SEQ5_BYTES, STATE_EMPTY_SEQ5_BYTES),
            (TWO_SEQ9_BYTES, STATE_TWO_SEQ9_BYTES),
        ):
            state = ObservationRevocationListState.from_bytes(state_blob)
            self.assertEqual(state.version, 1)
            self.assertEqual(
                state.digest, hashlib.sha256(list_blob).digest()
            )
            self.assertEqual(
                state.mac,
                _state_mac(ROOT, state.sequence, state.digest),
            )
        # The two sequence-9 snapshots genuinely differ in digest.
        self.assertNotEqual(
            hashlib.sha256(TWO_SEQ9_BYTES).digest(),
            hashlib.sha256(EMPTY_SEQ9_BYTES).digest(),
        )

    def test_stateless_audit_accepts_the_vectors(self):
        self.assertIsNone(
            audit_observation_crl(EMPTY_SEQ5_BYTES, ROOT, KEYS, now=42.5)
        )
        self.assertIsNone(
            audit_observation_crl(TWO_SEQ9_BYTES, ROOT, KEYS, now=300.25)
        )
        self.assertIsNone(
            audit_observation_crl(
                ObservationRevocationList.from_bytes(TWO_SEQ9_BYTES),
                ROOT,
                KEYS,
                now=300.25,
            )
        )


class AuditorLifecycleTest(unittest.TestCase):
    """Checkpoint establishment, replay, advance and restore, observed only
    through the public ``checkpoint`` property and record attributes."""

    def test_first_audit_returns_self_and_establishes_checkpoint(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        self.assertIsNone(auditor.checkpoint)
        self.assertIs(
            auditor.audit(EMPTY_SEQ5_BYTES, KEYS, now=42.5), auditor
        )
        checkpoint = auditor.checkpoint
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint.to_bytes(), STATE_EMPTY_SEQ5_BYTES)
        self.assertEqual(
            (checkpoint.version, checkpoint.sequence),
            (1, 5),
        )
        self.assertEqual(
            checkpoint.digest, hashlib.sha256(EMPTY_SEQ5_BYTES).digest()
        )

    def test_replay_keeps_checkpoint_and_higher_sequence_advances(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(EMPTY_SEQ5_BYTES, KEYS, now=42.5)
        checkpoint = auditor.checkpoint
        # Same sequence, same digest: an accepted replay.
        for blob in (EMPTY_SEQ5_BYTES, EMPTY_SEQ5_BYTES):
            self.assertIs(auditor.audit(blob, KEYS, now=42.5), auditor)
            self.assertIs(auditor.checkpoint, checkpoint)
            self.assertEqual(
                auditor.checkpoint.to_bytes(), STATE_EMPTY_SEQ5_BYTES
            )
        # A higher sequence advances the frontier to the pinned state.
        self.assertIs(auditor.audit(TWO_SEQ9_BYTES, KEYS, now=300.25), auditor)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_TWO_SEQ9_BYTES)
        self.assertEqual(auditor.checkpoint.sequence, 9)

    def test_older_sequence_and_conflicting_snapshot_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(TWO_SEQ9_BYTES, KEYS, now=300.25)
        before = auditor.checkpoint.to_bytes()
        # Older sequence.
        with self.assertRaises(ValueError):
            auditor.audit(EMPTY_SEQ5_BYTES, KEYS, now=300.25)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        # Same sequence, different digest.
        with self.assertRaises(ValueError):
            auditor.audit(EMPTY_SEQ9_BYTES, KEYS, now=300.25)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        self.assertEqual(before, STATE_TWO_SEQ9_BYTES)

    def test_restore_from_checkpoint_object_continues_identically(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(EMPTY_SEQ5_BYTES, KEYS, now=42.5)
        exported = auditor.checkpoint
        restored = ObservationRevocationListAuditor(ROOT, checkpoint=exported)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_EMPTY_SEQ5_BYTES)
        # The restored auditor replays the frontier and advances exactly as
        # the uninterrupted one.
        self.assertIs(
            restored.audit(EMPTY_SEQ5_BYTES, KEYS, now=42.5), restored
        )
        restored.audit(TWO_SEQ9_BYTES, KEYS, now=300.25)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO_SEQ9_BYTES)
        with self.assertRaises(ValueError):
            restored.audit(EMPTY_SEQ5_BYTES, KEYS, now=300.25)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO_SEQ9_BYTES)

    def test_restore_from_checkpoint_bytes_continues_identically(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(TWO_SEQ9_BYTES, KEYS, now=300.25)
        saved = auditor.checkpoint.to_bytes()
        self.assertEqual(saved, STATE_TWO_SEQ9_BYTES)
        restored = ObservationRevocationListAuditor(ROOT, checkpoint=saved)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO_SEQ9_BYTES)
        # Replay of the identical snapshot is accepted; the conflicting
        # same-sequence snapshot and the older sequence are rejected.
        self.assertIs(restored.audit(TWO_SEQ9_BYTES, KEYS, now=300.25), restored)
        with self.assertRaises(ValueError):
            restored.audit(EMPTY_SEQ9_BYTES, KEYS, now=300.25)
        with self.assertRaises(ValueError):
            restored.audit(EMPTY_SEQ5_BYTES, KEYS, now=300.25)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO_SEQ9_BYTES)


class FormatVersusSignatureTest(unittest.TestCase):
    """Format validity and signature validity are distinguished: a
    well-formed but wrongly signed artefact parses yet fails the audit."""

    def test_tampered_checkpoint_mac_parses_but_fails_restore(self):
        good = json.loads(STATE_TWO_SEQ9_BYTES)
        forged_mac = "00" * 32
        self.assertNotEqual(good["mac"], forged_mac)
        tampered = _canonical({**good, "mac": forged_mac})
        self.assertEqual(len(tampered), len(STATE_TWO_SEQ9_BYTES))
        # The encoding is still canonical and contract-satisfying.
        parsed = ObservationRevocationListState.from_bytes(tampered)
        self.assertEqual(parsed.to_bytes(), tampered)
        self.assertEqual(parsed.sequence, 9)
        # Restoring an auditor from it fails the MAC check, from both the
        # bytes and the parsed object.
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(ROOT, checkpoint=tampered)
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(ROOT, checkpoint=parsed)

    def test_forged_entry_mac_under_valid_list_mac_rejected(self):
        # A well-formed list whose outer MAC is validly recomputed over an
        # inner entry whose own MAC was replaced: format and list signature
        # are fine, the entry signature is not.
        forged_entry = ObservationRevocation(
            version=1, id="alpha", revoked_at=100.0, mac=b"\x00" * 32
        )
        entries = [
            ("alpha", 100.0, b"\x00" * 32),
            ("beta", 200.5, bytes.fromhex(json.loads(ENTRY_BETA_BYTES)["mac"])),
        ]
        forged_blob = _list_bytes(9, 300.25, entries)
        # The forged bytes parse and carry a valid outer list MAC.
        forged = ObservationRevocationList.from_bytes(forged_blob)
        self.assertEqual(forged.mac, _list_mac(ROOT, 9, 300.25, entries))
        self.assertEqual(forged.entries[0], forged_entry)
        auditor = ObservationRevocationListAuditor(ROOT)
        with self.assertRaises(ValueError):
            auditor.audit(forged_blob, KEYS, now=300.25)
        # The rejection happened before any state was established.
        self.assertIsNone(auditor.checkpoint)
        # Same rejection on an auditor with an established frontier, which
        # must not advance either.
        auditor.audit(EMPTY_SEQ5_BYTES, KEYS, now=42.5)
        with self.assertRaises(ValueError):
            auditor.audit(forged, KEYS, now=300.25)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_EMPTY_SEQ5_BYTES)

    def test_accepted_snapshot_reaudited_with_wrong_keys_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(TWO_SEQ9_BYTES, KEYS, now=300.25)
        before = auditor.checkpoint.to_bytes()
        # The identical, already accepted snapshot is verified again: a
        # wrong entry key is not skipped on digest equality.
        with self.assertRaises(ValueError):
            auditor.audit(
                TWO_SEQ9_BYTES,
                {"alpha": KEY_BETA, "beta": KEY_ALPHA},
                now=300.25,
            )
        # A mapping missing one entry's key is rejected likewise.
        with self.assertRaises(ValueError):
            auditor.audit(TWO_SEQ9_BYTES, {"alpha": KEY_ALPHA}, now=300.25)
        with self.assertRaises(ValueError):
            auditor.audit(TWO_SEQ9_BYTES, {}, now=300.25)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        # The correct mapping still replays.
        self.assertIs(auditor.audit(TWO_SEQ9_BYTES, KEYS, now=300.25), auditor)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)


class CheckpointParsingTest(unittest.TestCase):
    def test_non_canonical_checkpoint_bytes_rejected(self):
        blobs = [
            STATE_TWO_SEQ9_BYTES + b" ",
            STATE_TWO_SEQ9_BYTES.replace(b",", b", ", 1),
            STATE_TWO_SEQ9_BYTES.replace(b":1,", b": 1,", 1),
            # Uppercase hex in the digest is not the canonical spelling.
            STATE_TWO_SEQ9_BYTES.replace(
                b"b328b8cd35ed4f455a9604297545724087d593c080738b9153afff637f56552e",
                b"B328B8CD35ED4F455A9604297545724087D593C080738B9153AFFF637F56552E",
            ),
            json.dumps(
                json.loads(STATE_TWO_SEQ9_BYTES), indent=2
            ).encode("utf-8"),
            b"{}",
            b"not json",
            b"",
        ]
        for blob in blobs:
            self.assertNotEqual(blob, STATE_TWO_SEQ9_BYTES)
            with self.assertRaises(ValueError, msg=blob[:40]):
                ObservationRevocationListState.from_bytes(blob)
            with self.assertRaises(ValueError, msg=blob[:40]):
                ObservationRevocationListAuditor(ROOT, checkpoint=blob)

    def test_non_bytes_checkpoint_input_is_type_error(self):
        for bad in (
            STATE_TWO_SEQ9_BYTES.decode("utf-8"),
            None,
            42,
            [1],
            bytearray(STATE_TWO_SEQ9_BYTES),
        ):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                ObservationRevocationListState.from_bytes(bad)
        # The auditor constructor likewise rejects foreign checkpoint types.
        for bad in (STATE_TWO_SEQ9_BYTES.decode("utf-8"), 42, [], {}):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                ObservationRevocationListAuditor(ROOT, checkpoint=bad)


if __name__ == "__main__":
    unittest.main()
