"""Protocol-compatibility regression tests for ObservationRevocationListAuditor.

Unlike the neighbouring checkpoint tests, every expectation here is a fixed
golden byte string embedded in this file, cross-checked against an
independent stdlib-only recomputation of the documented public wire format
(compact JSON, keys in field order, floats spelled as floats, lowercase hex
MACs; entry MAC = HMAC-SHA256(key, encoding without "mac"); list MAC =
HMAC-SHA256(root, b"NPORL1" + encoding without "mac"); snapshot digest =
SHA256(canonical list bytes); checkpoint MAC = HMAC-SHA256(root, b"NPORS1" +
encoding without "mac")). No private helper of the library under test is
imported, so a synchronised drift of the library's own encoder and signer
cannot keep these tests green.
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

# Fixed sample key material. The root signs lists and checkpoints; each
# verifier id has its own shared entry key.
ROOT = b"observation-crl-root-key/0001"
KEY_ALPHA = b"verifier-shared-key/alpha/01"
KEY_BETA = b"verifier-shared-key/beta/002"
KEY_WRONG = b"verifier-shared-key/wrong/00"

KEYS = {"alpha": KEY_ALPHA, "beta": KEY_BETA}

# --- Golden samples: fixed inputs, fixed expected bytes. ---
#
# Entries: revoke_observation(id, revoked_at, key).
ENTRY_ALPHA = (
    b'{"version":1,"id":"alpha","revoked_at":100.25,'
    b'"mac":"393d08244195aece1292359ee4e2d0c7c42e48ea3a3d86601f2109b2d81a9580"}'
)
ENTRY_BETA = (
    b'{"version":1,"id":"beta","revoked_at":99.5,'
    b'"mac":"b220cf128d51fab9bf65c1ede3e312c05ab34b787bef3c8a58aaa468fd30360e"}'
)
ENTRY_ALPHA_MAC = "393d08244195aece1292359ee4e2d0c7c42e48ea3a3d86601f2109b2d81a9580"
ENTRY_BETA_MAC = "b220cf128d51fab9bf65c1ede3e312c05ab34b787bef3c8a58aaa468fd30360e"

# Empty revocation list: sequence 3, issued_at 120.5, no entries.
LIST_EMPTY = (
    b'{"version":1,"sequence":3,"issued_at":120.5,"entries":[],'
    b'"mac":"bb10ac0ed8a0eb0cc1082ff91de5f37b78422f7f5876dcf509d74dc9187a71e8"}'
)
LIST_EMPTY_MAC = "bb10ac0ed8a0eb0cc1082ff91de5f37b78422f7f5876dcf509d74dc9187a71e8"
LIST_EMPTY_DIGEST = "e95fb004de947e2489b1b80e6f8c7ad0a374e65644b1828f8ec12b51ee0edd7e"

# Two-entry list signed by two different verifier keys: sequence 4,
# issued_at 130.0, entries alpha (revoked_at 100.25) and beta (99.5).
LIST_TWO = (
    b'{"version":1,"sequence":4,"issued_at":130.0,'
    b'"entries":['
    b'{"version":1,"id":"alpha","revoked_at":100.25,'
    b'"mac":"393d08244195aece1292359ee4e2d0c7c42e48ea3a3d86601f2109b2d81a9580"},'
    b'{"version":1,"id":"beta","revoked_at":99.5,'
    b'"mac":"b220cf128d51fab9bf65c1ede3e312c05ab34b787bef3c8a58aaa468fd30360e"}],'
    b'"mac":"3692815b29e5209b380ffbce31999c37d56d8c97172fa709693263b70e5771a7"}'
)
LIST_TWO_MAC = "3692815b29e5209b380ffbce31999c37d56d8c97172fa709693263b70e5771a7"
LIST_TWO_DIGEST = "c467c2b3aa20f3cc7cc65ab38294df79eb4c06b0a77e9a3ad1de07f5760be493"

# Checkpoints exported after auditing the two lists above.
STATE_EMPTY = (
    b'{"version":1,"sequence":3,'
    b'"digest":"e95fb004de947e2489b1b80e6f8c7ad0a374e65644b1828f8ec12b51ee0edd7e",'
    b'"mac":"56f588877f6773c6e1b331c8ef01329cbdd3ef8423129ceeedf22942ae732958"}'
)
STATE_EMPTY_MAC = "56f588877f6773c6e1b331c8ef01329cbdd3ef8423129ceeedf22942ae732958"
STATE_TWO = (
    b'{"version":1,"sequence":4,'
    b'"digest":"c467c2b3aa20f3cc7cc65ab38294df79eb4c06b0a77e9a3ad1de07f5760be493",'
    b'"mac":"87f1916762b57b2b093afe80c7418f7d5be8e39a0406487c7dabf11c394488cb"}'
)
STATE_TWO_MAC = "87f1916762b57b2b093afe80c7418f7d5be8e39a0406487c7dabf11c394488cb"


# --- Independent stdlib-only recomputation of the public wire format. ---

def _canon(payload):
    return json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _entry_mac(key, ident, revoked_at):
    return hmac.new(
        key,
        _canon({"version": 1, "id": ident, "revoked_at": revoked_at}),
        hashlib.sha256,
    ).digest()


def _list_payload(sequence, issued_at, entries):
    # entries: iterable of (id, revoked_at, mac hex) in canonical order.
    return {
        "version": 1,
        "sequence": sequence,
        "issued_at": issued_at,
        "entries": [
            {"version": 1, "id": ident, "revoked_at": revoked_at, "mac": mac}
            for ident, revoked_at, mac in entries
        ],
    }


def _list_mac(root, sequence, issued_at, entries):
    return hmac.new(
        root,
        b"NPORL1" + _canon(_list_payload(sequence, issued_at, entries)),
        hashlib.sha256,
    ).digest()


def _list_bytes(sequence, issued_at, entries, mac):
    payload = _list_payload(sequence, issued_at, entries)
    payload["mac"] = mac.hex()
    return _canon(payload)


def _state_mac(root, sequence, digest):
    return hmac.new(
        root,
        b"NPORS1"
        + _canon({"version": 1, "sequence": sequence, "digest": digest.hex()}),
        hashlib.sha256,
    ).digest()


def _state_bytes(sequence, digest, mac):
    return _canon(
        {
            "version": 1,
            "sequence": sequence,
            "digest": digest.hex(),
            "mac": mac.hex(),
        }
    )


TWO_ENTRIES = [
    ("alpha", 100.25, ENTRY_ALPHA_MAC),
    ("beta", 99.5, ENTRY_BETA_MAC),
]


class GoldenVectorTest(unittest.TestCase):
    """The fixed samples match an independent recomputation of the public
    format, and the public issuance entry points reproduce them byte for
    byte."""

    def test_entry_vectors(self):
        self.assertEqual(
            _entry_mac(KEY_ALPHA, "alpha", 100.25).hex(), ENTRY_ALPHA_MAC
        )
        self.assertEqual(_entry_mac(KEY_BETA, "beta", 99.5).hex(), ENTRY_BETA_MAC)
        self.assertEqual(
            revoke_observation("alpha", 100.25, KEY_ALPHA).to_bytes(), ENTRY_ALPHA
        )
        self.assertEqual(
            revoke_observation("beta", 99.5, KEY_BETA).to_bytes(), ENTRY_BETA
        )
        for blob in (ENTRY_ALPHA, ENTRY_BETA):
            self.assertEqual(ObservationRevocation.from_bytes(blob).to_bytes(), blob)

    def test_empty_list_vector(self):
        self.assertEqual(_list_mac(ROOT, 3, 120.5, []).hex(), LIST_EMPTY_MAC)
        self.assertEqual(
            _list_bytes(3, 120.5, [], bytes.fromhex(LIST_EMPTY_MAC)), LIST_EMPTY
        )
        self.assertEqual(
            hashlib.sha256(LIST_EMPTY).hexdigest(), LIST_EMPTY_DIGEST
        )
        self.assertEqual(
            make_observation_crl([], 3, 120.5, ROOT).to_bytes(), LIST_EMPTY
        )
        parsed = ObservationRevocationList.from_bytes(LIST_EMPTY)
        self.assertEqual(parsed.to_bytes(), LIST_EMPTY)
        self.assertEqual(parsed.entries, ())

    def test_two_entry_list_vector(self):
        self.assertEqual(
            _list_mac(ROOT, 4, 130.0, TWO_ENTRIES).hex(), LIST_TWO_MAC
        )
        self.assertEqual(
            _list_bytes(4, 130.0, TWO_ENTRIES, bytes.fromhex(LIST_TWO_MAC)),
            LIST_TWO,
        )
        self.assertEqual(hashlib.sha256(LIST_TWO).hexdigest(), LIST_TWO_DIGEST)
        # Input order does not influence the canonical encoding: the entries
        # are passed in reverse id order and still land sorted.
        entries = [
            revoke_observation("beta", 99.5, KEY_BETA),
            revoke_observation("alpha", 100.25, KEY_ALPHA),
        ]
        self.assertEqual(
            make_observation_crl(entries, 4, 130.0, ROOT).to_bytes(), LIST_TWO
        )
        parsed = ObservationRevocationList.from_bytes(LIST_TWO)
        self.assertEqual(parsed.to_bytes(), LIST_TWO)
        self.assertEqual([entry.id for entry in parsed.entries], ["alpha", "beta"])

    def test_state_vectors(self):
        for blob, sequence, digest_hex, mac_hex, state_blob in (
            (LIST_EMPTY, 3, LIST_EMPTY_DIGEST, STATE_EMPTY_MAC, STATE_EMPTY),
            (LIST_TWO, 4, LIST_TWO_DIGEST, STATE_TWO_MAC, STATE_TWO),
        ):
            digest = hashlib.sha256(blob).digest()
            self.assertEqual(digest.hex(), digest_hex)
            mac = _state_mac(ROOT, sequence, digest)
            self.assertEqual(mac.hex(), mac_hex)
            self.assertEqual(_state_bytes(sequence, digest, mac), state_blob)
            parsed = ObservationRevocationListState.from_bytes(state_blob)
            self.assertEqual(parsed.to_bytes(), state_blob)
            self.assertEqual(parsed.sequence, sequence)
            self.assertEqual(parsed.digest, digest)
            self.assertEqual(parsed.mac, mac)

    def test_golden_bytes_pass_the_stateless_public_audit(self):
        self.assertIsNone(
            audit_observation_crl(LIST_EMPTY, ROOT, {}, now=120.5)
        )
        self.assertIsNone(
            audit_observation_crl(LIST_TWO, ROOT, KEYS, now=130.0)
        )
        # The parsed objects audit identically to the canonical bytes.
        self.assertIsNone(
            audit_observation_crl(
                ObservationRevocationList.from_bytes(LIST_TWO),
                ROOT,
                KEYS,
                now=130.0,
            )
        )


class AuditorLifecycleTest(unittest.TestCase):
    """Gating and checkpoint progression against the fixed samples, observed
    only through the public checkpoint property."""

    def test_first_audit_returns_self_and_establishes_checkpoint(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        self.assertIsNone(auditor.checkpoint)
        self.assertIs(auditor.audit(LIST_TWO, KEYS, now=130.0), auditor)
        checkpoint = auditor.checkpoint
        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint.to_bytes(), STATE_TWO)
        self.assertEqual(checkpoint.sequence, 4)
        self.assertEqual(checkpoint.digest, hashlib.sha256(LIST_TWO).digest())
        self.assertEqual(checkpoint.mac.hex(), STATE_TWO_MAC)
        # The empty list audits just the same from the empty state.
        other = ObservationRevocationListAuditor(ROOT)
        self.assertIs(other.audit(LIST_EMPTY, {}, now=120.5), other)
        self.assertEqual(other.checkpoint.to_bytes(), STATE_EMPTY)

    def test_same_sequence_same_digest_replay_keeps_checkpoint(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        checkpoint = auditor.checkpoint
        for snapshot in (
            LIST_TWO,
            ObservationRevocationList.from_bytes(LIST_TWO),
        ):
            self.assertIs(auditor.audit(snapshot, KEYS, now=130.0), auditor)
            self.assertIs(auditor.checkpoint, checkpoint)
            self.assertEqual(auditor.checkpoint.to_bytes(), STATE_TWO)

    def test_higher_sequence_advances(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_EMPTY, {}, now=120.5)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_EMPTY)
        self.assertIs(auditor.audit(LIST_TWO, KEYS, now=130.0), auditor)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_TWO)

    def test_lower_sequence_rejected_and_checkpoint_bytes_unchanged(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        before = auditor.checkpoint.to_bytes()
        with self.assertRaises(ValueError):
            auditor.audit(LIST_EMPTY, {}, now=130.0)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_TWO)

    def test_same_sequence_different_digest_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        before = auditor.checkpoint.to_bytes()
        # Same sequence 4, different issued_at: a different snapshot digest.
        variant = make_observation_crl(
            [
                revoke_observation("alpha", 100.25, KEY_ALPHA),
                revoke_observation("beta", 99.5, KEY_BETA),
            ],
            4,
            131.0,
            ROOT,
        )
        self.assertNotEqual(variant.to_bytes(), LIST_TWO)
        self.assertNotEqual(
            hashlib.sha256(variant.to_bytes()).digest(),
            hashlib.sha256(LIST_TWO).digest(),
        )
        with self.assertRaises(ValueError):
            auditor.audit(variant, KEYS, now=131.0)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)


class AuditorRestoreTest(unittest.TestCase):
    """A checkpoint exported as an object or as bytes restores an auditor
    that keeps auditing to the same results."""

    def test_exported_checkpoint_matches_golden_bytes(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_EMPTY, {}, now=120.5)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_EMPTY)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_TWO)

    def test_restore_from_checkpoint_bytes(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        exported = auditor.checkpoint.to_bytes()
        self.assertEqual(exported, STATE_TWO)

        restored = ObservationRevocationListAuditor(ROOT, checkpoint=exported)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO)
        # The frontier snapshot still replays after the restart.
        self.assertIs(restored.audit(LIST_TWO, KEYS, now=130.0), restored)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO)
        # Rollback past the restored frontier is still refused.
        with self.assertRaises(ValueError):
            restored.audit(LIST_EMPTY, {}, now=130.0)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO)

    def test_restore_from_checkpoint_object(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        exported = auditor.checkpoint

        restored = ObservationRevocationListAuditor(ROOT, checkpoint=exported)
        self.assertEqual(restored.checkpoint, exported)
        self.assertIs(restored.audit(LIST_TWO, KEYS, now=130.0), restored)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO)
        with self.assertRaises(ValueError):
            restored.audit(LIST_EMPTY, {}, now=130.0)
        self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO)

    def test_restore_then_advance_matches_direct_run(self):
        direct = ObservationRevocationListAuditor(ROOT)
        direct.audit(LIST_EMPTY, {}, now=120.5)
        direct.audit(LIST_TWO, KEYS, now=130.0)

        partial = ObservationRevocationListAuditor(ROOT)
        partial.audit(LIST_EMPTY, {}, now=120.5)
        saved = partial.checkpoint.to_bytes()
        self.assertEqual(saved, STATE_EMPTY)

        for checkpoint in (saved, ObservationRevocationListState.from_bytes(saved)):
            restored = ObservationRevocationListAuditor(ROOT, checkpoint=checkpoint)
            self.assertIs(restored.audit(LIST_TWO, KEYS, now=130.0), restored)
            self.assertEqual(restored.checkpoint.to_bytes(), STATE_TWO)
            self.assertEqual(restored.checkpoint, direct.checkpoint)


class FormatVersusSignatureTest(unittest.TestCase):
    """Well-formed bytes and valid signatures are distinct properties."""

    def test_tampered_checkpoint_mac_parses_but_fails_restore(self):
        # An equal-length but wrong MAC keeps the encoding canonical.
        tampered = STATE_TWO.replace(STATE_TWO_MAC.encode(), b"00" * 32)
        self.assertNotEqual(tampered, STATE_TWO)
        parsed = ObservationRevocationListState.from_bytes(tampered)
        self.assertEqual(parsed.to_bytes(), tampered)
        self.assertEqual(parsed.mac, b"\x00" * 32)
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(ROOT, checkpoint=tampered)
        with self.assertRaises(ValueError):
            ObservationRevocationListAuditor(ROOT, checkpoint=parsed)

    def test_forged_entry_mac_with_valid_outer_mac_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_EMPTY, {}, now=120.5)
        before = auditor.checkpoint.to_bytes()
        # Corrupt one inner entry MAC but re-sign the outer list MAC with
        # the genuine root, so only the per-verifier layer can catch it.
        forged_entries = [
            ("alpha", 100.25, "00" * 32),
            ("beta", 99.5, ENTRY_BETA_MAC),
        ]
        outer = _list_mac(ROOT, 4, 130.0, forged_entries)
        forged = _list_bytes(4, 130.0, forged_entries, outer)
        # The forgery is well-formed: it parses and its outer MAC verifies.
        self.assertEqual(
            ObservationRevocationList.from_bytes(forged).to_bytes(), forged
        )
        self.assertEqual(
            _list_mac(ROOT, 4, 130.0, forged_entries).hex(), outer.hex()
        )
        with self.assertRaises(ValueError):
            auditor.audit(forged, KEYS, now=130.0)
        # The rejection must not have advanced the checkpoint.
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_EMPTY)

    def test_reaudit_of_accepted_snapshot_with_bad_keys_rejected(self):
        auditor = ObservationRevocationListAuditor(ROOT)
        auditor.audit(LIST_TWO, KEYS, now=130.0)
        before = auditor.checkpoint.to_bytes()
        # The identical snapshot is a digest replay at the gate, but the
        # per-entry verification runs first and must still fail.
        with self.assertRaises(ValueError):
            auditor.audit(
                LIST_TWO,
                {"alpha": KEY_WRONG, "beta": KEY_BETA},
                now=130.0,
            )
        with self.assertRaises(ValueError):
            auditor.audit(LIST_TWO, {"alpha": KEY_ALPHA}, now=130.0)
        with self.assertRaises(ValueError):
            auditor.audit(LIST_TWO, {}, now=130.0)
        self.assertEqual(auditor.checkpoint.to_bytes(), before)
        self.assertEqual(auditor.checkpoint.to_bytes(), STATE_TWO)

    def test_non_canonical_checkpoint_bytes_rejected_at_parse(self):
        upper = STATE_TWO.replace(
            LIST_TWO_DIGEST.encode(), LIST_TWO_DIGEST.upper().encode()
        )
        self.assertNotEqual(upper, STATE_TWO)
        for blob in (
            STATE_TWO + b" ",
            STATE_TWO.replace(b",", b", ", 1),
            STATE_TWO.replace(b'"sequence":4', b'"sequence":4.0'),
            upper,
            b"",
            b"not json",
        ):
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListState.from_bytes(blob)
            with self.assertRaises(ValueError, msg=blob):
                ObservationRevocationListAuditor(ROOT, checkpoint=blob)

    def test_non_bytes_checkpoint_input_is_type_error(self):
        for bad in (
            STATE_TWO.decode("utf-8"),
            bytearray(STATE_TWO),
            0,
            42,
            ["version"],
            object(),
        ):
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                ObservationRevocationListState.from_bytes(bad)
            with self.assertRaises(TypeError, msg=repr(type(bad))):
                ObservationRevocationListAuditor(ROOT, checkpoint=bad)
        # None is a valid auditor checkpoint (empty state) but never valid
        # state bytes.
        with self.assertRaises(TypeError):
            ObservationRevocationListState.from_bytes(None)


if __name__ == "__main__":
    unittest.main()
