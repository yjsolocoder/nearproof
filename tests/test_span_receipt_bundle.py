import dataclasses
import hashlib
import hmac
import json
import unittest

from nearproof import (
    RangeAuditor,
    RangeFrontier,
    SpanReceiptBundle,
    _range_frontier_mac,
    _range_receipt_mac,
    _span_receipt_bundle_content_bytes,
    _span_receipt_bundle_signature,
    audit_span_receipt_bundle,
    seal_span_receipt_bundle,
)
from test_range_auditor_audit_batch import (
    CHAIN,
    CFRONTIER_1,
    CFRONTIER_2,
    KEY,
    OTHER_KEY,
    RDIGEST_1,
    RDIGEST_2,
    RECEIPT_R1,
    RECEIPT_RCP,
    RFRONTIER_1,
    RFRONTIER_2,
    U64_MAX,
    ZERO,
    range_frontier_for,
)

BUNDLE_1 = seal_span_receipt_bundle([RECEIPT_R1], KEY)
BUNDLE_2 = seal_span_receipt_bundle(
    [RECEIPT_RCP], KEY, start=RFRONTIER_1
)
BUNDLE_FULL = seal_span_receipt_bundle(
    [RECEIPT_R1, RECEIPT_RCP], KEY
)


def resign(bundle, key=KEY):
    return dataclasses.replace(
        bundle,
        signature=_span_receipt_bundle_signature(key, bundle),
    )


class SpanReceiptBundleFieldContractTest(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(BUNDLE_FULL.version, 1)
        self.assertEqual(BUNDLE_FULL.start, b"")
        self.assertEqual(
            BUNDLE_FULL.receipts,
            (RECEIPT_R1.to_bytes(), RECEIPT_RCP.to_bytes()),
        )
        self.assertEqual(BUNDLE_FULL.end, RFRONTIER_2.to_bytes())
        self.assertEqual(len(BUNDLE_FULL.signature), 32)
        self.assertEqual(BUNDLE_2.start, RFRONTIER_1.to_bytes())

    def test_positional_construction_and_equality(self):
        direct = SpanReceiptBundle(
            BUNDLE_FULL.version,
            BUNDLE_FULL.start,
            BUNDLE_FULL.receipts,
            BUNDLE_FULL.end,
            BUNDLE_FULL.signature,
        )
        self.assertEqual(direct, BUNDLE_FULL)
        self.assertEqual(hash(direct), hash(BUNDLE_FULL))
        self.assertNotEqual(BUNDLE_1, BUNDLE_2)

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            BUNDLE_1.version = 2  # type: ignore[misc]

    def test_version_contract(self):
        for bad in ("1", 1.0, True, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanReceiptBundle(
                    bad,
                    b"",
                    (RECEIPT_R1.to_bytes(),),
                    RFRONTIER_1.to_bytes(),
                    ZERO,
                )
        with self.assertRaises(ValueError):
            SpanReceiptBundle(
                2,
                b"",
                (RECEIPT_R1.to_bytes(),),
                RFRONTIER_1.to_bytes(),
                ZERO,
            )

    def test_start_contract(self):
        with self.assertRaises(TypeError):
            SpanReceiptBundle(
                1,
                42,
                (RECEIPT_R1.to_bytes(),),
                RFRONTIER_1.to_bytes(),
                ZERO,
            )
        with self.assertRaises(ValueError):
            SpanReceiptBundle(
                1,
                b"\x00",
                (RECEIPT_R1.to_bytes(),),
                RFRONTIER_1.to_bytes(),
                ZERO,
            )

    def test_receipts_contract(self):
        with self.assertRaises(TypeError):
            SpanReceiptBundle(
                1,
                b"",
                [RECEIPT_R1.to_bytes()],
                RFRONTIER_1.to_bytes(),
                ZERO,
            )
        with self.assertRaises(ValueError):
            SpanReceiptBundle(
                1, b"", (), RFRONTIER_1.to_bytes(), ZERO
            )
        with self.assertRaises(TypeError):
            SpanReceiptBundle(
                1, b"", ("ab",), RFRONTIER_1.to_bytes(), ZERO
            )
        with self.assertRaises(ValueError):
            SpanReceiptBundle(
                1, b"", (b"\x00\x01",), RFRONTIER_1.to_bytes(), ZERO
            )

    def test_end_contract(self):
        with self.assertRaises(TypeError):
            SpanReceiptBundle(
                1,
                b"",
                (RECEIPT_R1.to_bytes(),),
                42,
                ZERO,
            )
        with self.assertRaises(ValueError):
            SpanReceiptBundle(
                1,
                b"",
                (RECEIPT_R1.to_bytes(),),
                b"",
                ZERO,
            )

    def test_signature_contract(self):
        fields = (1, b"", (RECEIPT_R1.to_bytes(),), RFRONTIER_1.to_bytes())
        with self.assertRaises(TypeError):
            SpanReceiptBundle(*fields, "00" * 32)
        with self.assertRaises(ValueError):
            SpanReceiptBundle(*fields, b"\x00" * 31)


class SpanReceiptBundleEncodingTest(unittest.TestCase):
    def test_round_trip(self):
        for bundle in (BUNDLE_1, BUNDLE_2, BUNDLE_FULL):
            data = bundle.to_bytes()
            self.assertEqual(
                SpanReceiptBundle.from_bytes(data), bundle
            )
            self.assertEqual(
                SpanReceiptBundle.from_bytes(data).to_bytes(), data
            )

    def test_encoding_shape(self):
        outer = json.loads(BUNDLE_FULL.to_bytes())
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], "")
        self.assertEqual(
            outer[2],
            [
                RECEIPT_R1.to_bytes().hex(),
                RECEIPT_RCP.to_bytes().hex(),
            ],
        )
        self.assertEqual(outer[3], RFRONTIER_2.to_bytes().hex())
        self.assertEqual(outer[4], BUNDLE_FULL.signature.hex())
        self.assertEqual(
            json.loads(BUNDLE_2.to_bytes())[1],
            RFRONTIER_1.to_bytes().hex(),
        )

    def test_from_bytes_type_contract(self):
        with self.assertRaises(TypeError):
            SpanReceiptBundle.from_bytes("x")
        with self.assertRaises(TypeError):
            SpanReceiptBundle.from_bytes(None)

    def test_from_bytes_rejects_non_canonical(self):
        canonical = BUNDLE_FULL.to_bytes()
        # Whitespace around the first separator breaks byte-for-byte
        # re-encoding.
        with self.assertRaises(ValueError):
            SpanReceiptBundle.from_bytes(canonical.replace(b",", b", ", 1))
        parsed = json.loads(canonical)
        for index, value in (
            (0, 2),
            (2, []),
            (1, "AB"),
            (4, parsed[4].upper()),
        ):
            doc = json.loads(canonical)
            doc[index] = value
            with self.assertRaises(ValueError, msg=(index, value)):
                SpanReceiptBundle.from_bytes(
                    json.dumps(doc, separators=(",", ":")).encode()
                )
        for bad in (b"junk", b"[]"):
            with self.assertRaises(ValueError, msg=bad):
                SpanReceiptBundle.from_bytes(bad)

    def test_from_bytes_verifies_no_signature(self):
        # Parsing never verifies the NPBJ35 signature or any carried MAC.
        parsed = json.loads(BUNDLE_FULL.to_bytes())
        parsed[4] = "00" * 32
        record = SpanReceiptBundle.from_bytes(
            json.dumps(parsed, separators=(",", ":")).encode()
        )
        self.assertEqual(record.signature, ZERO)


class SpanReceiptBundleSignatureTest(unittest.TestCase):
    def test_signature_is_npbj35_hmac(self):
        expected = hmac.new(
            KEY,
            b"NPBJ35"
            + _span_receipt_bundle_content_bytes(BUNDLE_FULL),
            hashlib.sha256,
        ).digest()
        self.assertEqual(BUNDLE_FULL.signature, expected)

    def test_signature_covers_only_first_four_fields(self):
        tampered = dataclasses.replace(
            BUNDLE_FULL, signature=b"\x01" * 32
        )
        self.assertEqual(
            _span_receipt_bundle_signature(KEY, tampered),
            _span_receipt_bundle_signature(KEY, BUNDLE_FULL),
        )


class SealSpanReceiptBundleTest(unittest.TestCase):
    def test_seal_matches_manual_chain(self):
        self.assertEqual(BUNDLE_FULL.end, RFRONTIER_2.to_bytes())
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_FULL, KEY), RFRONTIER_2
        )

    def test_seal_from_checkpoint_object_and_bytes(self):
        via_object = seal_span_receipt_bundle(
            [RECEIPT_RCP], KEY, start=RFRONTIER_1
        )
        via_bytes = seal_span_receipt_bundle(
            [RECEIPT_RCP], KEY, start=RFRONTIER_1.to_bytes()
        )
        self.assertEqual(via_object, BUNDLE_2)
        self.assertEqual(via_bytes, BUNDLE_2)

    def test_seal_accepts_canonical_bytes_receipts(self):
        bundle = seal_span_receipt_bundle(
            [RECEIPT_R1.to_bytes(), RECEIPT_RCP.to_bytes()], KEY
        )
        self.assertEqual(bundle, BUNDLE_FULL)

    def test_seal_accepts_any_non_empty_iterable(self):
        self.assertEqual(
            seal_span_receipt_bundle(list((RECEIPT_R1,)), KEY),
            BUNDLE_1,
        )
        self.assertEqual(
            seal_span_receipt_bundle(
                (r for r in (RECEIPT_R1, RECEIPT_RCP)), KEY
            ),
            BUNDLE_FULL,
        )

    def test_seal_is_pure_computation(self):
        # Sealing touches no auditor state.
        auditor = RangeAuditor(KEY)
        seal_span_receipt_bundle([RECEIPT_R1], KEY)
        self.assertIsNone(auditor.state)

    def test_seal_type_contract(self):
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle(42, KEY)
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle(None, KEY)
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle([RECEIPT_R1], "k")
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle([RECEIPT_R1], None)
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle([42], KEY)
        with self.assertRaises(TypeError):
            seal_span_receipt_bundle([RECEIPT_R1], KEY, start=42)

    def test_seal_value_contract(self):
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([], KEY)
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([RECEIPT_R1], b"")
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([RECEIPT_R1], OTHER_KEY)
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle([RECEIPT_R1], KEY, start=b"junk")

    def test_broken_chain_rejected(self):
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_RCP, RECEIPT_R1], KEY
            )
        # The second receipt starts at RFRONTIER_1 but the chain began
        # with no receipt at all.
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_RCP], KEY
            )

    def test_overflow_rejected(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        with self.assertRaises(ValueError):
            seal_span_receipt_bundle(
                [RECEIPT_RCP], KEY, start=maxed
            )


class AuditSpanReceiptBundleTest(unittest.TestCase):
    def test_audit_returns_frontier(self):
        frontier = audit_span_receipt_bundle(BUNDLE_FULL, KEY)
        self.assertIsInstance(frontier, RangeFrontier)
        self.assertEqual(frontier, RFRONTIER_2)
        self.assertEqual(frontier.sequence, 2)
        self.assertEqual(frontier.end, CFRONTIER_2.to_bytes())
        self.assertEqual(frontier.digest, RDIGEST_2)
        self.assertEqual(
            frontier.mac, _range_frontier_mac(KEY, frontier)
        )

    def test_audit_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_FULL.to_bytes(), KEY),
            RFRONTIER_2,
        )

    def test_audit_single_receipt_bundle(self):
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_1, KEY), RFRONTIER_1
        )

    def test_audit_from_carried_checkpoint(self):
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_2, KEY), RFRONTIER_2
        )

    def test_audit_matches_stateful_auditor(self):
        via_bundle = audit_span_receipt_bundle(BUNDLE_FULL, KEY)
        via_auditor = RangeAuditor(KEY).audit_batch(CHAIN).state
        self.assertEqual(via_bundle, via_auditor)

    def test_audit_is_pure_check(self):
        self.assertEqual(
            audit_span_receipt_bundle(BUNDLE_FULL, KEY),
            audit_span_receipt_bundle(BUNDLE_FULL, KEY),
        )

    def test_audit_type_contract(self):
        with self.assertRaises(TypeError):
            audit_span_receipt_bundle(42, KEY)
        with self.assertRaises(TypeError):
            audit_span_receipt_bundle(None, KEY)
        with self.assertRaises(TypeError):
            audit_span_receipt_bundle(BUNDLE_FULL, "k")
        with self.assertRaises(TypeError):
            audit_span_receipt_bundle(BUNDLE_FULL, None)

    def test_audit_value_contract(self):
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(b"junk", KEY)
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(BUNDLE_FULL, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(BUNDLE_FULL, OTHER_KEY)

    def test_bundle_signature_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(
                dataclasses.replace(BUNDLE_FULL, signature=ZERO), KEY
            )

    def test_tampered_carried_receipt_rejected(self):
        # Re-sign over a tampered carried receipt: the NPBJ35 signature
        # can be made consistent, but the receipt's own NPBJ12 MAC cannot.
        tampered = dataclasses.replace(
            BUNDLE_FULL,
            receipts=(
                dataclasses.replace(RECEIPT_R1, mac=ZERO).to_bytes(),
                RECEIPT_RCP.to_bytes(),
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(resign(tampered), KEY)

    def test_tampered_start_frontier_rejected(self):
        # Flip the carried start frontier's range MAC: the five-layer
        # endpoint MAC check rejects it before replay.
        bad_start = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        tampered = dataclasses.replace(BUNDLE_2, start=bad_start.to_bytes())
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(resign(tampered), KEY)

    def test_tampered_end_frontier_rejected(self):
        bad_end = dataclasses.replace(RFRONTIER_2, mac=ZERO)
        tampered = dataclasses.replace(
            BUNDLE_FULL, end=bad_end.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(resign(tampered), KEY)

    def test_end_must_match_replayed_chain(self):
        tampered = dataclasses.replace(
            BUNDLE_FULL, end=RFRONTIER_1.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(resign(tampered), KEY)

    def test_start_mismatch_rejected(self):
        # BUNDLE_2's carried chain starts at RFRONTIER_1; claiming the
        # empty start cannot replay to its end.
        tampered = dataclasses.replace(BUNDLE_2, start=b"")
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(resign(tampered), KEY)

    def test_broken_link_inside_bundle_rejected(self):
        forged_receipt = dataclasses.replace(RECEIPT_RCP, start=b"")
        forged_receipt = dataclasses.replace(
            forged_receipt,
            mac=_range_receipt_mac(KEY, forged_receipt),
        )
        tampered = dataclasses.replace(
            BUNDLE_FULL,
            receipts=(
                RECEIPT_R1.to_bytes(),
                forged_receipt.to_bytes(),
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_receipt_bundle(resign(tampered), KEY)


if __name__ == "__main__":
    unittest.main()
