import threading
import unittest

from nearproof import (
    BitMap,
    BitMapHistoryEvidence,
    BitMapHistoryEvidenceAuditor,
    BitMapUpdate,
    _bit_map_mac,
    _bit_map_payload,
    _bit_map_update_mac,
    _bit_map_update_payload,
    seal_map_history,
)

KEY = b"shared-secret-key" * 2
OTHER_KEY = b"a-different-key!!" * 2

SID_A = b"\x0a" * 32
SID_B = b"\x0b" * 32
HASH_1 = b"\x01" * 32
HASH_2 = b"\x02" * 32
HASH_3 = b"\x03" * 32
ZERO = b"\x00" * 32


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


class ConstructorContractTest(unittest.TestCase):
    def test_key_must_be_bytes(self):
        for bad in ("secret", 7, None, bytearray(b"k")):
            with self.assertRaises(TypeError):
                BitMapHistoryEvidenceAuditor(bad)

    def test_key_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            BitMapHistoryEvidenceAuditor(b"")

    def test_checkpoint_kind(self):
        with self.assertRaises(TypeError):
            BitMapHistoryEvidenceAuditor(KEY, checkpoint="x")
        with self.assertRaises(TypeError):
            BitMapHistoryEvidenceAuditor(KEY, checkpoint=1)

    def test_checkpoint_must_be_canonical(self):
        with self.assertRaises(ValueError):
            BitMapHistoryEvidenceAuditor(KEY, checkpoint=b"\x00")

    def test_checkpoint_mac_must_match(self):
        foreign = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        with self.assertRaises(ValueError):
            BitMapHistoryEvidenceAuditor(KEY, checkpoint=foreign)

    def test_checkpoint_accepts_instance_and_bytes(self):
        self.assertEqual(
            BitMapHistoryEvidenceAuditor(KEY, checkpoint=MAP_3).checkpoint,
            MAP_3,
        )
        self.assertEqual(
            BitMapHistoryEvidenceAuditor(
                KEY, checkpoint=MAP_3.to_bytes()
            ).checkpoint,
            MAP_3,
        )

    def test_fresh_auditor_has_no_checkpoint(self):
        self.assertIsNone(BitMapHistoryEvidenceAuditor(KEY).checkpoint)


class AuditContractTest(unittest.TestCase):
    def test_empty_state_requires_empty_start(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(EVIDENCE_2)
        self.assertIsNone(auditor.checkpoint)

    def test_audit_accepts_instance_and_bytes(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        result = auditor.audit(EVIDENCE_1.to_bytes())
        self.assertIsInstance(result, BitMap)
        self.assertEqual(result, MAP_2)
        self.assertEqual(auditor.checkpoint, MAP_2)
        self.assertEqual(auditor.audit(EVIDENCE_2), MAP_3)
        self.assertEqual(auditor.checkpoint, MAP_3)

    def test_replay_is_rejected_and_state_kept(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        with self.assertRaises(ValueError):
            auditor.audit(EVIDENCE_1)
        self.assertEqual(auditor.checkpoint, MAP_2)

    def test_fork_from_same_start_is_rejected(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        fork = seal_map_history([UPDATE_1], KEY)
        with self.assertRaises(ValueError):
            auditor.audit(fork)
        self.assertEqual(auditor.checkpoint, MAP_2)

    def test_old_segment_rejected_after_restart(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        auditor.audit(EVIDENCE_1)
        auditor.audit(EVIDENCE_2)
        restored = BitMapHistoryEvidenceAuditor(
            KEY, checkpoint=auditor.checkpoint.to_bytes()
        )
        with self.assertRaises(ValueError):
            restored.audit(EVIDENCE_2)
        self.assertEqual(restored.checkpoint, MAP_3)

    def test_wrong_argument_type(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        for bad in (1, "x", None, [EVIDENCE_1]):
            with self.assertRaises(TypeError):
                auditor.audit(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(b"junk")
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_key_evidence(self):
        other_map = map_for(((SID_A, 1, HASH_1),), key=OTHER_KEY)
        other_update = update_for(b"", other_map.to_bytes(), key=OTHER_KEY)
        foreign = seal_map_history([other_update], OTHER_KEY)
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(foreign)
        self.assertIsNone(auditor.checkpoint)

    def test_tampered_mac(self):
        tampered = BitMapHistoryEvidence(1, EVIDENCE_1.body, ZERO)
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(tampered)
        self.assertIsNone(auditor.checkpoint)

    def test_broken_chain_inside_body(self):
        body = __import__("nearproof")._encode_payload(
            [
                "",
                [
                    UPDATE_1.to_bytes().hex(),
                    UPDATE_3.to_bytes().hex(),
                ],
                MAP_3.to_bytes().hex(),
            ]
        )
        from nearproof import _bit_map_history_evidence_mac

        broken = BitMapHistoryEvidence(
            1, body, _bit_map_history_evidence_mac(KEY, body)
        )
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit(broken)
        self.assertIsNone(auditor.checkpoint)

    def test_checkpoint_property_is_read_only(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        with self.assertRaises(AttributeError):
            auditor.checkpoint = MAP_1


class ConcurrencyTest(unittest.TestCase):
    def test_competing_segments_linearize(self):
        auditor = BitMapHistoryEvidenceAuditor(KEY)
        first = seal_map_history([UPDATE_1], KEY)  # "" -> MAP_1
        second = EVIDENCE_1  # "" -> MAP_2
        results = []
        failures = []

        def run(evidence):
            try:
                results.append(auditor.audit(evidence))
            except ValueError:
                failures.append(evidence)

        threads = [
            threading.Thread(target=run, args=(first,)),
            threading.Thread(target=run, args=(second,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(auditor.checkpoint, results[0])


if __name__ == "__main__":
    unittest.main()
