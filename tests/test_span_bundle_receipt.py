import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeAuditor,
    SpanBundleReceipt,
    SpanReceiptBundle,
    _span_bundle_receipt_content_bytes,
    _span_bundle_receipt_signature,
    audit_bundle_receipt,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    RANGE_1,
    RECEIPT_R1,
    RFRONTIER_1,
    RFRONTIER_2,
    ZERO,
)
from test_range_auditor_audit_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    resign,
)


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPBJ36 signature recomputed over
    the first four fields; ``start``/``end``/``digest`` default to the
    honest values."""
    placeholder = SpanBundleReceipt(
        1,
        bundle.start if start is None else start,
        hashlib.sha256(bundle.to_bytes()).digest()
        if digest is None
        else digest,
        bundle.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_signature(key, placeholder),
    )


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)
RECEIPT_FULL = receipt_for(BUNDLE_FULL)


class SpanBundleReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = SpanBundleReceipt(
            1,
            b"",
            RECEIPT_1.bundle_digest,
            RFRONTIER_1.to_bytes(),
            RECEIPT_1.signature,
        )
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(hash(receipt), hash(RECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, RFRONTIER_1.to_bytes())



    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_1.signature = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # Malformed bytes are value errors: the start is empty or a
        # canonical range frontier.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # b"" (no receipt yet) is a valid start.
        dataclasses.replace(RECEIPT_1, start=b"")

    def test_bundle_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty range frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, signature=bad)


class SpanBundleReceiptEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'"' + RECEIPT_1.bundle_digest.hex().encode() + b'",'
            b'"' + RFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + RECEIPT_1.signature.hex().encode() + b'"]'
        )
        self.assertEqual(RECEIPT_1.to_bytes(), expected)

    def test_round_trip(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_FULL):
            blob = receipt.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(SpanBundleReceipt.from_bytes(blob), receipt)
            self.assertEqual(
                SpanBundleReceipt.from_bytes(blob).to_bytes(), blob
            )

    def test_from_bytes_type_contract(self):
        blob = RECEIPT_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceipt.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            RECEIPT_1.bundle_digest.hex(),
            RFRONTIER_1.to_bytes().hex(),
            RECEIPT_1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 1),
            (2, 64),
            (3, 1),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                SpanBundleReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            SpanBundleReceipt.from_bytes(blob.replace(b",", b", "))
        upper = blob.replace(
            RECEIPT_1.signature.hex().encode(),
            RECEIPT_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            SpanBundleReceipt.from_bytes(upper)
        with self.assertRaises(ValueError):
            SpanBundleReceipt.from_bytes(blob.replace(b"[1,", b"[2,", 1))

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            RECEIPT_1.bundle_digest.hex(),
            RFRONTIER_1.to_bytes().hex(),
            RECEIPT_1.signature.hex(),
        ]
        for index, bad_value in (
            (1, "junk"),
            (2, "00"),
            (3, ""),
            (3, "junk"),
            (4, "00"),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(ValueError, msg=(index, bad_value)):
                SpanBundleReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        # Neither the receipt signature nor any nested frontier MAC is
        # checked at parse time.
        tampered = dataclasses.replace(RECEIPT_1, signature=ZERO)
        parsed = SpanBundleReceipt.from_bytes(tampered.to_bytes())
        self.assertEqual(parsed, tampered)

    def test_signature_scheme(self):
        expected_signature = hmac.new(
            KEY,
            b"NPBJ36" + _span_bundle_receipt_content_bytes(RECEIPT_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_1.signature, expected_signature)


class RangeAuditorCommitBundleTest(unittest.TestCase):
    def test_commit_returns_receipt(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_bundle(BUNDLE_1)
        self.assertIsInstance(receipt, SpanBundleReceipt)
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, RFRONTIER_1.to_bytes())
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_receipt_signature_verifies(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_bundle(BUNDLE_FULL)
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_signature(KEY, receipt),
        )
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_bundle(BUNDLE_1.to_bytes())
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_continues_from_non_empty_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.commit_bundle(BUNDLE_1)
        receipt = auditor.commit_bundle(BUNDLE_2)
        self.assertEqual(receipt, RECEIPT_2)
        self.assertEqual(receipt.start, RFRONTIER_1.to_bytes())
        self.assertEqual(receipt.end, RFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_matches_audit_bundle_state(self):
        via_commit = RangeAuditor(KEY)
        via_commit.commit_bundle(BUNDLE_FULL)
        via_audit = RangeAuditor(KEY)
        via_audit.audit_bundle(BUNDLE_FULL)
        self.assertEqual(via_commit.state, via_audit.state)

    def test_failure_changes_nothing_and_yields_no_receipt(self):
        auditor = RangeAuditor(KEY)
        auditor.commit_bundle(BUNDLE_1)
        before = auditor.state
        # A replayed bundle no longer chains onto the advanced frontier.
        with self.assertRaises(ValueError):
            auditor.commit_bundle(BUNDLE_1)
        # An old fork fails the same start linkage.
        with self.assertRaises(ValueError):
            auditor.commit_bundle(BUNDLE_FULL)
        # A tampered bundle signature is rejected too.
        tampered = dataclasses.replace(BUNDLE_2, signature=ZERO)
        with self.assertRaises(ValueError):
            auditor.commit_bundle(tampered)
        self.assertIs(auditor.state, before)

    def test_wrong_argument_type(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).commit_bundle(BUNDLE_FULL)

    def test_audit_bundle_interface_unchanged(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_1), auditor)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_receipt_verifies_against_bundle(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_bundle(BUNDLE_FULL)
        final = audit_bundle_receipt(receipt, BUNDLE_FULL, KEY)
        self.assertEqual(final, RFRONTIER_2)
        self.assertEqual(final, auditor.state)

    def test_competing_commits_linearize(self):
        auditor = RangeAuditor(KEY)
        receipts, failures = [], []

        def run(bundle):
            try:
                receipts.append(auditor.commit_bundle(bundle))
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(BUNDLE_1,)),
            threading.Thread(target=run, args=(BUNDLE_FULL,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        # The one committed bundle's receipt attests the committed chain.
        receipt = receipts[0]
        self.assertEqual(receipt.end, auditor.state.to_bytes())

    def test_commit_bundle_shares_lock_with_old_entry_points(self):
        auditor = RangeAuditor(KEY)
        receipts, failures = [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                receipts.append((token, action()))
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(lambda: auditor.commit_bundle(BUNDLE_FULL), "commit"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_bundle(BUNDLE_FULL), "bundle"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit(RECEIPT_R1, RANGE_1), "one"),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 2)
        token, result = receipts[0]
        if token == "commit":
            self.assertIsInstance(result, SpanBundleReceipt)
            self.assertEqual(result.end, auditor.state.to_bytes())
            self.assertEqual(auditor.state, RFRONTIER_2)
        elif token == "bundle":
            self.assertIs(result, auditor)
            self.assertEqual(auditor.state, RFRONTIER_2)
        else:
            self.assertEqual(auditor.state, RFRONTIER_1)


class AuditBundleReceiptTest(unittest.TestCase):
    def test_verifies_and_returns_end_frontier(self):
        self.assertEqual(
            audit_bundle_receipt(RECEIPT_1, BUNDLE_1, KEY), RFRONTIER_1
        )
        self.assertEqual(
            audit_bundle_receipt(RECEIPT_FULL, BUNDLE_FULL, KEY),
            RFRONTIER_2,
        )
        self.assertEqual(
            audit_bundle_receipt(RECEIPT_2, BUNDLE_2, KEY), RFRONTIER_2
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_bundle_receipt(
                RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), KEY
            ),
            RFRONTIER_1,
        )

    def test_touches_no_auditor_state(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        before = auditor.state
        final = audit_bundle_receipt(RECEIPT_2, BUNDLE_2, KEY)
        self.assertEqual(final, RFRONTIER_2)
        self.assertIs(auditor.state, before)

    def test_type_contract(self):
        for bad in (1, "x", None, [RECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_bundle_receipt(bad, BUNDLE_1, KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_bundle_receipt(RECEIPT_1, bad, KEY)
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_bundle_receipt(RECEIPT_1, BUNDLE_1, bad)

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_1, BUNDLE_1, b"")
        with self.assertRaises(ValueError):
            audit_bundle_receipt(b"junk", BUNDLE_1, KEY)
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            audit_bundle_receipt(
                blob.replace(b",", b", "), BUNDLE_1, KEY
            )

    def test_tampered_receipt_signature(self):
        tampered = dataclasses.replace(RECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(tampered, BUNDLE_1, KEY)

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_1, BUNDLE_1, OTHER_KEY)

    def test_bundle_digest_binds_one_bundle(self):
        # BUNDLE_1 and BUNDLE_FULL both start empty, and BUNDLE_FULL's
        # chain ends where BUNDLE_2's chain ends: an honest receipt for
        # one never attests another bundle over the same or overlapping
        # endpoints.
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_1, BUNDLE_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, BUNDLE_2, KEY)

    def test_tampered_bundle_digest_field(self):
        tampered = receipt_for(BUNDLE_1, digest=ZERO)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(tampered, BUNDLE_1, KEY)

    def test_endpoint_mismatch(self):
        # Receipt signature and bundle digest both verify, but the
        # receipt's endpoints do not match the bundle's.
        mismatched = receipt_for(
            BUNDLE_1,
            start=RFRONTIER_1.to_bytes(),
            end=RFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_bundle_receipt(mismatched, BUNDLE_1, KEY)

    def test_forged_end_rejected(self):
        # Receipt honestly attests a bundle whose replayed chain does not
        # reach its claimed end.
        placeholder = SpanReceiptBundle(
            1,
            BUNDLE_1.start,
            BUNDLE_1.receipts,
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        bad_bundle = resign(placeholder)
        receipt = receipt_for(bad_bundle)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(receipt, bad_bundle, KEY)


if __name__ == "__main__":
    unittest.main()
