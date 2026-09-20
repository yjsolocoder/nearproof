import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    CertifiedConsensusEvidence,
    Consensus,
    RangeDecision,
    attest_observation_for_point,
    audit_cert_evidence,
    cert,
    locate_cert,
    locate_cert_evidence,
)

ROOT = b"\x09" * 32
KEY_A = b"\xaa" * 32
KEY_B = b"\xbb" * 32
KEY_C = b"\xcc" * 32
KEY_D = b"\xdd" * 32

KEYS = {"a": KEY_A, "b": KEY_B, "c": KEY_C, "d": KEY_D}
POSITIONS = {"a": (3.0, 0.0), "b": (0.0, 4.0), "c": (0.0, 0.0),
             "d": (50.0, 50.0)}

POINT = (0.0, 0.0)
CONTEXT = "room-7"


def decision(upper_bound=5.0, *, accepted=True, sample_count=1):
    return RangeDecision(
        sample_count=sample_count, upper_bound=upper_bound, accepted=accepted
    )


def trust(ident):
    px, py = POSITIONS[ident]
    return cert(ident, px, py, KEYS[ident], ROOT)


def record(ident, upper_bound=5.0, *, key=None, point=POINT, context=CONTEXT):
    x, y = POSITIONS[ident]
    return attest_observation_for_point(
        ident, x, y, decision(upper_bound), point, context, 0.0,
        key or KEYS[ident],
    )


def triangle_records(upper_bound=5.0):
    return [record("a", upper_bound), record("b", upper_bound),
            record("c", upper_bound)]


def triangle_trusts():
    return [trust("a"), trust("b"), trust("c")]


def evidence(records=None, trusts=None, point=POINT, context=CONTEXT):
    return locate_cert_evidence(
        triangle_records() if records is None else records,
        point, context,
        triangle_trusts() if trusts is None else trusts,
        ROOT,
    )


def outer(ev):
    return json.loads(ev.to_bytes())


def body_array(ev):
    return json.loads(bytes.fromhex(outer(ev)["body"]))


class CertifiedConsensusEvidenceContractTest(unittest.TestCase):
    def test_is_frozen_and_equal_by_fields(self):
        ev = evidence()
        same = CertifiedConsensusEvidence(1, ev.body, ev.mac)
        self.assertEqual(ev, same)
        self.assertEqual(hash(ev), hash(same))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ev.mac = b"\x00" * 32

    def test_positional_field_order(self):
        body = b"[]"
        ev = CertifiedConsensusEvidence(1, body, b"\x00" * 32)
        self.assertEqual((ev.version, ev.body, ev.mac),
                         (1, body, b"\x00" * 32))

    def test_version_must_be_one(self):
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence(bad, b"[]", b"\x00" * 32)

    def test_body_must_be_bytes(self):
        for bad in ("[]", bytearray(b"[]"), None, 42, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence(1, bad, b"\x00" * 32)

    def test_mac_must_be_exactly_32_bytes(self):
        for bad in (b"\x00" * 31, b"\x00" * 33, "ab" * 32, None, 32):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence(1, b"[]", bad)

    def test_to_bytes_rejects_a_body_that_is_not_the_contract_array(self):
        for bad in (b"", b"not json", b"{}", b"[]", b"[null,null,null,null]"):
            ev = CertifiedConsensusEvidence(1, bad, b"\x00" * 32)
            with self.assertRaises(ValueError, msg=repr(bad)):
                ev.to_bytes()


class LocateCertEvidenceTest(unittest.TestCase):
    def test_wraps_the_locate_cert_consensus(self):
        ev = evidence()
        point, context, records, trusts, consensus = body_array(ev)
        self.assertEqual(point, [0.0, 0.0])
        self.assertEqual(context, CONTEXT)
        self.assertEqual(len(records), 3)
        self.assertEqual(len(trusts), 3)
        self.assertEqual(
            [json.loads(bytes.fromhex(h))["id"] for h in records],
            ["a", "b", "c"],
        )
        self.assertEqual(
            [json.loads(bytes.fromhex(h))["id"] for h in trusts],
            ["a", "b", "c"],
        )
        self.assertEqual(consensus, [3, 3, [], True])
        self.assertEqual(
            audit_cert_evidence(ev, ROOT),
            locate_cert(triangle_records(), POINT, CONTEXT,
                        triangle_trusts(), ROOT),
        )

    def test_rejected_ids_are_carried_through(self):
        ev = evidence(triangle_records() + [record("d")],
                      triangle_trusts() + [trust("d")])
        self.assertEqual(body_array(ev)[4], [4, 3, ["d"], True])
        result = audit_cert_evidence(ev, ROOT)
        self.assertEqual(result, Consensus(4, 3, ("d",), True))

    def test_body_arrays_are_sorted_and_aligned_whatever_the_input_order(self):
        records = triangle_records()
        trusts = triangle_trusts()
        ev = locate_cert_evidence(
            [records[2].to_bytes(), records[0], records[1]],
            POINT, CONTEXT,
            [trusts[1], trusts[2].to_bytes(), trusts[0]],
            ROOT,
        )
        _, _, record_hex, trust_hex, _ = body_array(ev)
        record_ids = [json.loads(bytes.fromhex(h))["id"] for h in record_hex]
        trust_ids = [json.loads(bytes.fromhex(h))["id"] for h in trust_hex]
        self.assertEqual(record_ids, ["a", "b", "c"])
        self.assertEqual(trust_ids, record_ids)
        # The sorted evidence still audits and yields the same consensus.
        self.assertEqual(audit_cert_evidence(ev, ROOT),
                         locate_cert(records, POINT, CONTEXT, trusts, ROOT))

    def test_mac_formula(self):
        ev = evidence()
        body = bytes.fromhex(outer(ev)["body"])
        expected = hmac.new(ROOT, b"NPCCE1" + body,
                            hashlib.sha256).digest()
        self.assertEqual(ev.mac, expected)

    def test_empty_root_rejected(self):
        with self.assertRaises(ValueError):
            locate_cert_evidence(triangle_records(), POINT, CONTEXT,
                                 triangle_trusts(), b"")

    def test_non_bytes_root_rejected(self):
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                locate_cert_evidence(triangle_records(), POINT, CONTEXT,
                                     triangle_trusts(), bad)

    def test_query_and_participant_contracts_propagate(self):
        with self.assertRaises(ValueError):
            evidence(point=(1.0,))
        with self.assertRaises(ValueError):
            evidence(point=(True, 0.0))
        with self.assertRaises(ValueError):
            evidence(context="")
        with self.assertRaises(ValueError):
            evidence(records=triangle_records()[:2],
                     trusts=triangle_trusts()[:2])
        with self.assertRaises(ValueError):
            evidence(records=[42], trusts=triangle_trusts())
        with self.assertRaises(ValueError):
            evidence(trusts=[42])
        with self.assertRaises(ValueError):
            locate_cert_evidence(triangle_records(), POINT, CONTEXT,
                                 triangle_trusts()[:2], ROOT)

    def test_returns_consensus_even_when_quorum_is_not_met(self):
        # Upper bound 1.0 covers only the verifier at the origin.
        ev = evidence(records=triangle_records(upper_bound=1.0))
        self.assertEqual(body_array(ev)[4], [3, 1, ["a", "b"], False])
        result = audit_cert_evidence(ev, ROOT)
        self.assertEqual(result, Consensus(3, 1, ("a", "b"), False))


class CertifiedConsensusEvidenceEncodingTest(unittest.TestCase):
    def test_outer_layout_is_compact_json_in_field_order(self):
        ev = evidence()
        obj = outer(ev)
        self.assertEqual(list(obj), ["version", "body", "mac"])
        self.assertEqual(obj["version"], 1)
        self.assertIsInstance(obj["body"], str)
        self.assertIsInstance(obj["mac"], str)
        self.assertEqual(obj["mac"], ev.mac.hex())
        expected = json.dumps(
            {"version": 1, "body": ev.body.hex(), "mac": ev.mac.hex()},
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(ev.to_bytes(), expected)
        self.assertNotIn(b" ", ev.to_bytes())

    def test_body_is_compact_json(self):
        ev = evidence()
        body = bytes.fromhex(outer(ev)["body"])
        self.assertNotIn(b" ", body)
        self.assertEqual(
            body,
            json.dumps(json.loads(body), separators=(",", ":")).encode(),
        )

    def test_round_trip(self):
        ev = evidence()
        self.assertEqual(
            CertifiedConsensusEvidence.from_bytes(ev.to_bytes()), ev
        )
        ev2 = evidence(triangle_records() + [record("d")],
                       triangle_trusts() + [trust("d")])
        self.assertEqual(
            CertifiedConsensusEvidence.from_bytes(ev2.to_bytes()), ev2
        )

    def test_from_bytes_rejects_non_bytes(self):
        data = evidence().to_bytes()
        for bad in (data.decode("utf-8"), None, 42, [1], bytearray(data)):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence.from_bytes(bad)

    def test_from_bytes_rejects_outer_key_violations(self):
        data = evidence().to_bytes()
        obj = json.loads(data)
        variants = [
            {k: obj[k] for k in ("body", "mac")},                  # missing
            {**obj, "extra": 1},                                  # extra
            {"mac": obj["mac"], "body": obj["body"],
             "version": 1},                                       # reordered
        ]
        # A duplicated key cannot be expressed through a dict.
        for bad_json in [json.dumps(v, separators=(",", ":")).encode()
                         for v in variants]:
            with self.assertRaises(ValueError):
                CertifiedConsensusEvidence.from_bytes(bad_json)
        duplicated = data[:-1] + b',"version":1}'
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(duplicated)
        for bad in (b"{}", b"[]", b"null", b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_outer_encoding(self):
        data = evidence().to_bytes()
        for bad in (data + b" ", b" " + data,
                    json.dumps(json.loads(data), indent=1).encode()):
            with self.assertRaises(ValueError, msg=repr(bad[:10])):
                CertifiedConsensusEvidence.from_bytes(bad)

    def test_from_bytes_rejects_non_canonical_body_encoding(self):
        ev = evidence()
        obj = outer(ev)
        spaced = json.dumps(json.loads(bytes.fromhex(obj["body"])),
                            separators=(", ", ": ")).encode()
        obj["body"] = spaced.hex()
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_uppercase_hex(self):
        data = evidence().to_bytes()
        obj = json.loads(data)
        obj["mac"] = obj["mac"][:-2] + "AB"
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )
        # An uppercase hex digit inside the body string is rejected too.
        obj = json.loads(data)
        body_hex = obj["body"]
        index = next(i for i, ch in enumerate(body_hex) if ch.isalpha())
        obj["body"] = (body_hex[:index] + body_hex[index].upper()
                       + body_hex[index + 1:])
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_version_and_mac_length(self):
        ev = evidence()
        obj = outer(ev)
        obj["version"] = 2
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )
        obj = outer(ev)
        obj["mac"] = "00" * 31
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def _body_bytes(self, mutate):
        """Return outer encoding whose body array was mutated via mutate()."""
        ev = evidence()
        obj = outer(ev)
        arr = json.loads(bytes.fromhex(obj["body"]))
        mutate(arr)
        obj["body"] = json.dumps(arr, separators=(",", ":")).encode().hex()
        # Keep a syntactically valid 32-byte mac; MAC verification is not
        # part of from_bytes.
        return json.dumps(obj, separators=(",", ":")).encode()

    def test_from_bytes_rejects_bad_point(self):
        for bad in ([0.0], [0.0, 0.0, 0.0], [True, 0.0],
                    ["0.0", 0.0], [float("inf"), 0.0]):
            data = self._body_bytes(lambda arr: arr.__setitem__(0, bad))
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence.from_bytes(data)

    def test_from_bytes_rejects_bad_context(self):
        for bad in ("", 7, None):
            data = self._body_bytes(lambda arr: arr.__setitem__(1, bad))
            with self.assertRaises(ValueError, msg=repr(bad)):
                CertifiedConsensusEvidence.from_bytes(data)

    def test_from_bytes_rejects_bad_record_and_trust_arrays(self):
        data = self._body_bytes(lambda arr: arr.__setitem__(2, "ab"))
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(data)
        data = self._body_bytes(lambda arr: arr.__setitem__(3, ["zz"]))
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(data)
        # Swap two records so the id order is broken.
        def unsort(arr):
            arr[2][0], arr[2][1] = arr[2][1], arr[2][0]
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(self._body_bytes(unsort))
        # Trusts aligned to a different id order.
        def misalign(arr):
            arr[3][0], arr[3][1] = arr[3][1], arr[3][0]
        with self.assertRaises(ValueError):
            CertifiedConsensusEvidence.from_bytes(self._body_bytes(misalign))

    def test_from_bytes_rejects_bad_consensus(self):
        cases = [
            lambda a: a.__setitem__(4, [3, 3, [], 1]),          # accepted
            lambda a: a.__setitem__(4, [3, 3, [], None]),
            lambda a: a.__setitem__(4, [3, 3, ["b", "a"], False]),
            lambda a: a.__setitem__(4, [3, 3, ["a", "a"], False]),
            lambda a: a.__setitem__(4, [3, 3, ["z"], False]),
            lambda a: a.__setitem__(4, [3, 2, [], True]),       # support count
            lambda a: a.__setitem__(4, [2, 3, [], True]),       # total count
            lambda a: a.__setitem__(4, [3, 3, [], True][:3]),   # length
            lambda a: a.__setitem__(4, {}),
        ]
        for mutate in cases:
            with self.assertRaises(ValueError, msg=repr(mutate)):
                CertifiedConsensusEvidence.from_bytes(self._body_bytes(mutate))

    def test_from_bytes_does_not_verify_mac(self):
        ev = evidence()
        obj = outer(ev)
        obj["mac"] = "00" * 32
        forged = json.dumps(obj, separators=(",", ":")).encode()
        decoded = CertifiedConsensusEvidence.from_bytes(forged)
        self.assertEqual(decoded.mac, b"\x00" * 32)


class AuditCertEvidenceTest(unittest.TestCase):
    def test_accepts_object_and_bytes(self):
        ev = evidence()
        result = locate_cert(triangle_records(), POINT, CONTEXT,
                             triangle_trusts(), ROOT)
        self.assertEqual(audit_cert_evidence(ev, ROOT), result)
        self.assertEqual(audit_cert_evidence(ev.to_bytes(), ROOT), result)

    def test_wrong_root_rejected(self):
        with self.assertRaises(ValueError):
            audit_cert_evidence(evidence(), b"\x08" * 32)

    def test_empty_and_non_bytes_root_rejected(self):
        with self.assertRaises(ValueError):
            audit_cert_evidence(evidence(), b"")
        for bad in (bytearray(ROOT), "", None, 0):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_cert_evidence(evidence(), bad)

    def test_bad_evidence_type_rejected(self):
        for bad in (42, None, "ab", []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_cert_evidence(bad, ROOT)

    def test_bad_body_contract_rejected_even_for_an_object(self):
        ev = CertifiedConsensusEvidence(1, b"not json", b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_cert_evidence(ev, ROOT)

    def test_tampered_mac_rejected(self):
        ev = evidence()
        forged = CertifiedConsensusEvidence(1, ev.body, b"\x00" * 32)
        with self.assertRaises(ValueError):
            audit_cert_evidence(forged, ROOT)

    def test_tampered_body_rejected(self):
        ev = evidence()
        obj = json.loads(ev.to_bytes())
        body = bytes.fromhex(obj["body"])
        # Flip a body byte; the bytes stay 32-char-paired hex at the outer
        # layer but the inner contract must no longer parse.
        tampered = bytes([body[0] ^ 0x01]) + body[1:]
        obj["body"] = tampered.hex()
        data = json.dumps(obj, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            audit_cert_evidence(data, ROOT)

    def test_mac_valid_but_record_set_altered_is_caught_by_rerun(self):
        # Replace one certified record with an observation signed under a
        # different key, then sign the new body with the root: the MAC
        # verifies, but rerunning locate_cert rejects the record MAC.
        ev = evidence()
        arr = body_array(ev)
        forged_record = record("a", key=b"\x77" * 32)
        arr[2][0] = forged_record.to_bytes().hex()
        body = json.dumps(arr, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + body, hashlib.sha256).digest()
        signed = CertifiedConsensusEvidence(1, body, mac)
        with self.assertRaises(ValueError):
            audit_cert_evidence(signed, ROOT)

    def test_mac_valid_but_claimed_consensus_mismatch_is_rejected(self):
        ev = evidence()
        arr = body_array(ev)
        # Internally consistent ([total, support, rejected, accepted]) and
        # lexically sorted, but contradicted by the actual geometry.
        arr[4] = [3, 2, ["a"], False]
        body = json.dumps(arr, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + body, hashlib.sha256).digest()
        data = CertifiedConsensusEvidence(1, body, mac).to_bytes()
        with self.assertRaises(ValueError):
            audit_cert_evidence(data, ROOT)

    def test_mac_valid_but_point_binding_contradicted_is_rejected(self):
        ev = evidence()
        arr = body_array(ev)
        # Claim a different point in the body while the records stay bound
        # to the origin. The body contract itself rejects this (every
        # record must be bound to the body point).
        arr[0] = [1.0, 0.0]
        body = json.dumps(arr, separators=(",", ":")).encode()
        mac = hmac.new(ROOT, b"NPCCE1" + body, hashlib.sha256).digest()
        with self.assertRaises(ValueError):
            audit_cert_evidence(CertifiedConsensusEvidence(1, body, mac), ROOT)


if __name__ == "__main__":
    unittest.main()
