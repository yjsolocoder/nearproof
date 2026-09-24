import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptAuditor,
    StreamCommitReceiptBundleReceipt,
    _stream_commit_receipt_bundle_mac,
    _stream_commit_receipt_bundle_receipt_content_bytes,
    _stream_commit_receipt_bundle_receipt_mac,
    audit_stream_commit_receipt_bundle_receipt,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    ZERO,
)
from test_stream_commit_receipt_bundle import (
    BUNDLE_1,
    BUNDLE_2,
    BUNDLE_FULL,
    BUNDLE_SOLO,
)
from test_stream_commit_receipt_frontier import (
    CFRONTIER_1,
    CFRONTIER_2,
    CFRONTIER_FULL,
)


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPBJ28 mac recomputed over the
    first four fields; ``start``/``end``/``digest`` default to the honest
    values."""
    placeholder = StreamCommitReceiptBundleReceipt(
        1,
        bundle.start if start is None else start,
        hashlib.sha256(bundle.to_bytes()).digest() if digest is None else digest,
        bundle.end if end is None else end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        mac=_stream_commit_receipt_bundle_receipt_mac(key, placeholder),
    )


RECEIPT_1 = receipt_for(BUNDLE_1)
RECEIPT_2 = receipt_for(BUNDLE_2)
RECEIPT_FULL = receipt_for(BUNDLE_FULL)
RECEIPT_SOLO = receipt_for(BUNDLE_SOLO)


class StreamCommitReceiptBundleReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = StreamCommitReceiptBundleReceipt(
            1,
            b"",
            RECEIPT_1.bundle_digest,
            CFRONTIER_1.to_bytes(),
            RECEIPT_1.mac,
        )
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(hash(receipt), hash(RECEIPT_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(receipt.end, CFRONTIER_1.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_1.mac = ZERO

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(RECEIPT_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # Malformed bytes are value errors: the start is empty or a
        # canonical commit frontier.
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, start=bad)
        # b"" (the empty ledger) is a valid start.
        dataclasses.replace(RECEIPT_1, start=b"")

    def test_bundle_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, bundle_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(CFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)
        # Empty and malformed bytes are value errors: the end is a
        # non-empty commit frontier.
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, end=bad)

    def test_mac_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, mac=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(RECEIPT_1, mac=bad)


class StreamCommitReceiptBundleReceiptEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"",'
            b'"' + RECEIPT_1.bundle_digest.hex().encode() + b'",'
            b'"' + CFRONTIER_1.to_bytes().hex().encode() + b'",'
            b'"' + RECEIPT_1.mac.hex().encode() + b'"]'
        )
        self.assertEqual(RECEIPT_1.to_bytes(), expected)

    def test_round_trip(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_FULL, RECEIPT_SOLO):
            blob = receipt.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptBundleReceipt.from_bytes(blob), receipt
            )
            self.assertEqual(
                StreamCommitReceiptBundleReceipt.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = RECEIPT_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptBundleReceipt.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptBundleReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            RECEIPT_1.bundle_digest.hex(),
            CFRONTIER_1.to_bytes().hex(),
            RECEIPT_1.mac.hex(),
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
                StreamCommitReceiptBundleReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceipt.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            RECEIPT_1.mac.hex().encode(),
            RECEIPT_1.mac.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceipt.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptBundleReceipt.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            RECEIPT_1.bundle_digest.hex(),
            CFRONTIER_1.to_bytes().hex(),
            RECEIPT_1.mac.hex(),
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
                StreamCommitReceiptBundleReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_mac(self):
        # Neither the receipt MAC nor any nested frontier MAC is checked
        # at parse time.
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        parsed = StreamCommitReceiptBundleReceipt.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)

    def test_mac_scheme(self):
        expected_mac = hmac.new(
            KEY,
            b"NPBJ28"
            + _stream_commit_receipt_bundle_receipt_content_bytes(RECEIPT_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_1.mac, expected_mac)


class StreamCommitReceiptAuditorAuditBundleReceiptTest(unittest.TestCase):
    def test_commit_returns_receipt(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1)
        self.assertIsInstance(receipt, StreamCommitReceiptBundleReceipt)
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_1.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, CFRONTIER_1.to_bytes())
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_receipt_mac_verifies(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        self.assertEqual(
            receipt.mac,
            _stream_commit_receipt_bundle_receipt_mac(KEY, receipt),
        )
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_1.to_bytes())
        self.assertEqual(receipt, RECEIPT_1)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_continues_from_non_empty_frontier(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        receipt = auditor.audit_bundle_receipt(BUNDLE_2)
        self.assertEqual(receipt, RECEIPT_2)
        self.assertEqual(receipt.start, CFRONTIER_1.to_bytes())
        self.assertEqual(receipt.end, CFRONTIER_2.to_bytes())
        self.assertEqual(auditor.state, CFRONTIER_2)

    def test_failure_changes_nothing_and_yields_no_receipt(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        auditor.audit_bundle_receipt(BUNDLE_1)
        before = auditor.state
        # A replayed bundle no longer chains onto the advanced frontier.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_1)
        # An old fork fails the same start linkage.
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(BUNDLE_FULL)
        # A tampered bundle mac is rejected too.
        tampered = dataclasses.replace(BUNDLE_2, mac=ZERO)
        with self.assertRaises(ValueError):
            auditor.audit_bundle_receipt(tampered)
        self.assertIs(auditor.state, before)

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_bytes_is_value_error(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle_receipt(bad)
        self.assertIsNone(auditor.state)

    def test_audit_bundle_interface_unchanged(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_1), auditor)
        self.assertEqual(auditor.state, CFRONTIER_1)

    def test_receipt_verifies_against_bundle(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        receipt = auditor.audit_bundle_receipt(BUNDLE_FULL)
        final = audit_stream_commit_receipt_bundle_receipt(
            receipt, BUNDLE_FULL, KEY
        )
        self.assertEqual(final, CFRONTIER_2)
        self.assertEqual(final, auditor.state)

    def test_competing_commits_linearize(self):
        auditor = StreamCommitReceiptAuditor(KEY)
        receipts, failures = [], []

        def run(bundle):
            try:
                receipts.append(auditor.audit_bundle_receipt(bundle))
            except ValueError:
                failures.append(bundle)

        threads = [
            threading.Thread(target=run, args=(BUNDLE_1,)),
            threading.Thread(target=run, args=(BUNDLE_SOLO,)),
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
        self.assertEqual(auditor.state.sequence, 1)


class AuditStreamCommitReceiptBundleReceiptTest(unittest.TestCase):
    def test_verifies_and_returns_end_frontier(self):
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_1, KEY
            ),
            CFRONTIER_1,
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_FULL, KEY
            ),
            CFRONTIER_2,
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_2, BUNDLE_2, KEY
            ),
            CFRONTIER_2,
        )
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_SOLO, BUNDLE_SOLO, KEY
            ),
            CFRONTIER_FULL,
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), KEY
            ),
            CFRONTIER_1,
        )

    def test_type_contract(self):
        for bad in (1, "x", None, [RECEIPT_1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle_receipt(
                    bad, BUNDLE_1, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle_receipt(
                    RECEIPT_1, bad, KEY
                )
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_bundle_receipt(
                    RECEIPT_1, BUNDLE_1, bad
                )

    def test_value_contract(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_1, b""
            )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                b"junk", BUNDLE_1, KEY
            )
        blob = RECEIPT_1.to_bytes()
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                blob.replace(b",", b", "), BUNDLE_1, KEY
            )

    def test_tampered_receipt_mac(self):
        tampered = dataclasses.replace(RECEIPT_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                tampered, BUNDLE_1, KEY
            )

    def test_wrong_key(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_1, OTHER_KEY
            )

    def test_bundle_digest_binds_one_bundle(self):
        # BUNDLE_1 and BUNDLE_SOLO both start empty and commit one
        # receipt, and BUNDLE_FULL shares the same end frontier as
        # BUNDLE_2's chain: an honest receipt for one never attests
        # another bundle over the same or overlapping endpoints.
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_1, BUNDLE_SOLO, KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                RECEIPT_FULL, BUNDLE_2, KEY
            )

    def test_tampered_bundle_digest_field(self):
        tampered = receipt_for(BUNDLE_1, digest=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                tampered, BUNDLE_1, KEY
            )

    def test_endpoint_mismatch(self):
        # Receipt mac and bundle digest both verify, but the receipt's
        # endpoints do not match the bundle's.
        mismatched = receipt_for(
            BUNDLE_1,
            start=CFRONTIER_1.to_bytes(),
            end=CFRONTIER_2.to_bytes(),
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                mismatched, BUNDLE_1, KEY
            )

    def test_invalid_bundle_still_rejected(self):
        # Receipt honestly attests a bundle whose replayed chain does not
        # reach its claimed end.
        from nearproof import StreamCommitReceiptBundle

        placeholder = StreamCommitReceiptBundle(
            1,
            BUNDLE_1.start,
            BUNDLE_1.receipts,
            CFRONTIER_2.to_bytes(),
            ZERO,
        )
        bad_bundle = dataclasses.replace(
            placeholder,
            mac=_stream_commit_receipt_bundle_mac(KEY, placeholder),
        )
        receipt = receipt_for(bad_bundle)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_bundle_receipt(
                receipt, bad_bundle, KEY
            )


if __name__ == "__main__":
    unittest.main()
