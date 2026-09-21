import dataclasses
import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryEvidence,
    BitMapHistoryJournalAuditor,
    BitMapHistoryJournalBundle,
    BitMapHistoryJournalState,
    BitMapUpdate,
    _bit_map_history_evidence_mac,
    _bit_map_history_journal_bundle_mac,
    _bit_map_history_journal_mac,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    _encode_payload,
    audit_map_history_journal_bundle,
    seal_map_history,
    seal_map_history_journal_bundle,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2

SID_A = b"\x0a" * 32
SID_B = b"\x0b" * 32
HASH_1 = b"\x01" * 32
HASH_2 = b"\x02" * 32
HASH_3 = b"\x03" * 32
ZERO = b"\x00" * 32

U64_MAX = 0xFFFFFFFFFFFFFFFF


def map_for(entries, key=KEY):
    ordered = tuple(sorted(entries))
    return BitMap(1, ordered, _bit_map_mac(key, _bit_map_payload(ordered)))


def update_for(before, after, key=KEY):
    placeholder = BitMapUpdate(1, before, after, ZERO)
    mac = _bit_map_update_mac(key, _bit_map_update_payload(placeholder))
    return BitMapUpdate(1, before, after, mac)


MAP_1 = map_for(((SID_A, 1, HASH_1),))
MAP_2 = map_for(((SID_A, 1, HASH_1), (SID_B, 2, HASH_2)))
MAP_3 = map_for(((SID_A, 3, HASH_3), (SID_B, 2, HASH_2)))

UPDATE_1 = update_for(b"", MAP_1.to_bytes())
UPDATE_2 = update_for(MAP_1.to_bytes(), MAP_2.to_bytes())
UPDATE_3 = update_for(MAP_2.to_bytes(), MAP_3.to_bytes())

# "" -> MAP_2 and MAP_2 -> MAP_3.
EVIDENCE_1 = seal_map_history([UPDATE_1, UPDATE_2], KEY)
EVIDENCE_2 = seal_map_history([UPDATE_3], KEY, checkpoint=MAP_2)
# "" -> MAP_1, one segment competing with EVIDENCE_1 from the empty journal.
EVIDENCE_SOLO = seal_map_history([UPDATE_1], KEY)


def audited_state(*evidences, key=KEY):
    auditor = BitMapHistoryJournalAuditor(key)
    for evidence in evidences:
        auditor.audit(evidence)
    return auditor.state


STATE_1 = audited_state(EVIDENCE_1)
STATE_2 = audited_state(EVIDENCE_1, EVIDENCE_2)

# "" -> STATE_1, STATE_1 -> STATE_2 and "" -> STATE_2.
BUNDLE_1 = seal_map_history_journal_bundle([EVIDENCE_1], KEY)
BUNDLE_2 = seal_map_history_journal_bundle([EVIDENCE_2], KEY, state=STATE_1)
BUNDLE_FULL = seal_map_history_journal_bundle([EVIDENCE_1, EVIDENCE_2], KEY)
BUNDLE_SOLO = seal_map_history_journal_bundle([EVIDENCE_SOLO], KEY)


def bundle_for(start, evidences, end, key=KEY):
    """A bundle with the NPBJ3 mac recomputed over the first four fields."""
    placeholder = BitMapHistoryJournalBundle(1, start, evidences, end, ZERO)
    return dataclasses.replace(
        placeholder, mac=_bit_map_history_journal_bundle_mac(key, placeholder)
    )


class AuditBundleSuccessTest(unittest.TestCase):
    def test_commits_whole_bundle_from_empty(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_1), auditor)
        self.assertEqual(auditor.state, STATE_1)
        self.assertEqual(auditor.state.to_bytes(), BUNDLE_1.end)

    def test_commits_full_chain_in_one_step(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, STATE_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        self.assertIs(
            auditor.audit_bundle(BUNDLE_FULL.to_bytes()), auditor
        )
        self.assertEqual(auditor.state, STATE_2)

    def test_continues_from_non_empty_state(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, STATE_2)

    def test_restarted_auditor_continues_from_bundle_start(self):
        first = BitMapHistoryJournalAuditor(KEY)
        first.audit_bundle(BUNDLE_1)
        restored = BitMapHistoryJournalAuditor(
            KEY, state=first.state.to_bytes()
        )
        restored.audit_bundle(BUNDLE_2)
        self.assertEqual(restored.state, STATE_2)

    def test_mixes_with_single_segment_audit(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, STATE_2)
        auditor2 = BitMapHistoryJournalAuditor(KEY)
        auditor2.audit_bundle(BUNDLE_1)
        auditor2.audit(EVIDENCE_2)
        self.assertEqual(auditor2.state, STATE_2)

    def test_agrees_with_standalone_verifier(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(
            auditor.state,
            audit_map_history_journal_bundle(BUNDLE_FULL, KEY),
        )


class AuditBundleTypeContractTest(unittest.TestCase):
    def test_wrong_argument_type(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_empty_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(b"")
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(b"junk")
        self.assertIsNone(auditor.state)


class AuditBundleStartMatchTest(unittest.TestCase):
    def test_empty_auditor_requires_empty_start(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_non_empty_auditor_requires_current_state(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        # An empty-start bundle no longer chains onto the advanced state.
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, STATE_1)

    def test_same_bundle_replay_is_rejected(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, before)

    def test_fork_from_other_start_rejected(self):
        # Advance the journal through the single-entry branch, then present
        # a bundle starting from the two-entry state.
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_SOLO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state.checkpoint, MAP_1.to_bytes())
        self.assertEqual(auditor.state.sequence, 1)


class AuditBundleCryptoFailureTest(unittest.TestCase):
    def test_tampered_bundle_mac(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        tampered = dataclasses.replace(BUNDLE_1, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(tampered)
        self.assertIsNone(auditor.state)

    def test_wrong_key(self):
        foreign_map = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        foreign_update = update_for(
            b"", foreign_map.to_bytes(), key=OTHER_KEY
        )
        foreign_evidence = seal_map_history([foreign_update], OTHER_KEY)
        foreign_bundle = seal_map_history_journal_bundle(
            [foreign_evidence], OTHER_KEY
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(foreign_bundle)
        self.assertIsNone(auditor.state)

    def test_tampered_start_state_mac(self):
        tampered_start = dataclasses.replace(STATE_1, mac=ZERO).to_bytes()
        bundle = bundle_for(
            tampered_start, (EVIDENCE_2.to_bytes(),), STATE_2.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, STATE_1)

    def test_tampered_end_state_mac(self):
        tampered_end = dataclasses.replace(STATE_2, mac=ZERO).to_bytes()
        bundle = bundle_for(
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_2.to_bytes()),
            tampered_end,
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_foreign_checkpoint_key(self):
        # Bundle mac valid under KEY, end state NPBJ1 valid under KEY but
        # its embedded checkpoint NPBL1 is signed under another key.
        foreign_map = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        placeholder = BitMapHistoryJournalState(
            1, 1, foreign_map.to_bytes(), STATE_1.digest, ZERO
        )
        mixed = dataclasses.replace(
            placeholder, mac=_bit_map_history_journal_mac(KEY, placeholder)
        )
        bundle = bundle_for(
            b"", (EVIDENCE_1.to_bytes(),), mixed.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_end_mismatch(self):
        # Valid bundle mac and endpoint MACs, but the replayed chain lands
        # at STATE_1 while the bundle claims STATE_2.
        bundle = bundle_for(
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_2.to_bytes()),
            STATE_1.to_bytes(),
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_tampered_inner_evidence_mac(self):
        # A fresh bundle mac over an evidence whose NPBH1 mac is zero.
        tampered_evidence = BitMapHistoryEvidence(
            1, EVIDENCE_1.body, ZERO
        ).to_bytes()
        bundle = bundle_for(
            b"", (tampered_evidence,), STATE_1.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_broken_inner_update_chain(self):
        # NPBH1 intact over a body whose updates do not chain; reseal the
        # bundle around the bad evidence and a plausible end.
        body = _encode_payload(
            [
                "",
                [
                    UPDATE_1.to_bytes().hex(),
                    UPDATE_3.to_bytes().hex(),
                ],
                MAP_3.to_bytes().hex(),
            ]
        )
        broken_evidence = BitMapHistoryEvidence(
            1, body, _bit_map_history_evidence_mac(KEY, body)
        ).to_bytes()
        bundle = bundle_for(
            b"", (broken_evidence,), STATE_1.to_bytes()
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_gap_between_segments(self):
        # Two individually valid segments that do not join: EVIDENCE_2
        # needs MAP_2 but the first segment ends at MAP_2 here... instead
        # present EVIDENCE_2 twice from an empty-looking start.
        bundle = bundle_for(
            b"",
            (EVIDENCE_2.to_bytes(),),
            STATE_2.to_bytes(),
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_failure_after_first_segment_is_atomic(self):
        # The first segment commits on the tentative state, the second
        # does not chain: nothing may be visible afterwards.
        bundle = bundle_for(
            b"",
            (EVIDENCE_1.to_bytes(), EVIDENCE_1.to_bytes()),
            STATE_2.to_bytes(),
        )
        auditor = BitMapHistoryJournalAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertIsNone(auditor.state)

    def test_sequence_overflow(self):
        digest = HASH_2
        placeholder = BitMapHistoryJournalState(
            1, U64_MAX, MAP_2.to_bytes(), digest, ZERO
        )
        state = dataclasses.replace(
            placeholder, mac=_bit_map_history_journal_mac(KEY, placeholder)
        )
        bundle = bundle_for(
            state.to_bytes(),
            (EVIDENCE_2.to_bytes(),),
            STATE_2.to_bytes(),
        )
        auditor = BitMapHistoryJournalAuditor(KEY, state=state)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(bundle)
        self.assertEqual(auditor.state, state)


class AuditBundleConcurrencyTest(unittest.TestCase):
    def test_competing_bundles_linearize(self):
        auditor = BitMapHistoryJournalAuditor(KEY)
        results = []
        failures = []

        def run(bundle):
            try:
                results.append(auditor.audit_bundle(bundle))
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(BUNDLE_SOLO,)),
            threading.Thread(target=run, args=(BUNDLE_1,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.state.sequence, 1)
        self.assertIn(
            auditor.state.checkpoint,
            (MAP_1.to_bytes(), MAP_2.to_bytes()),
        )


if __name__ == "__main__":
    unittest.main()
