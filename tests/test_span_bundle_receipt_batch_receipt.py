import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    SpanBundleReceiptAuditor,
    SpanBundleReceiptBatchReceipt,
    SpanBundleReceiptFrontier,
    _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX,
    _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX,
    _span_bundle_receipt_batch_receipt_content_bytes,
    _span_bundle_receipt_batch_receipt_signature,
    _span_bundle_receipt_batch_signature,
    _span_bundle_receipt_frontier_signature,
    audit_span_bundle_receipt_batch_receipt,
)
from test_range_auditor_audit_batch import (
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RDIGEST_1,
    RFRONTIER_1,
    U64_MAX,
    ZERO,
    range_frontier_for,
)
from test_span_bundle_receipt import (
    BUNDLE_1,
    RECEIPT_1,
    RECEIPT_2,
)
from test_span_bundle_receipt_batch import (
    BATCH_1,
    BATCH_2,
    BATCH_FULL,
    batch_for,
    resign_receipt,
)
from test_span_bundle_receipt_frontier import (
    PFRONTIER_1,
    PFRONTIER_2,
)


def batch_receipt_for(batch, key=KEY):
    placeholder = SpanBundleReceiptBatchReceipt(
        1,
        batch.start,
        hashlib.sha256(batch.to_bytes()).digest(),
        batch.end,
        ZERO,
    )
    return dataclasses.replace(
        placeholder,
        signature=_span_bundle_receipt_batch_receipt_signature(
            key, placeholder
        ),
    )


RECEIPT_C1 = batch_receipt_for(BATCH_1)
RECEIPT_C2 = batch_receipt_for(BATCH_2)
RECEIPT_CFULL = batch_receipt_for(BATCH_FULL)


class SpanBundleReceiptBatchReceiptFieldTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [
                field.name
                for field in dataclasses.fields(
                    SpanBundleReceiptBatchReceipt
                )
            ],
            ["version", "start", "digest", "end", "signature"],
        )
        self.assertNotIn("key", RECEIPT_CFULL.__dict__)
        self.assertNotIn("mac", RECEIPT_CFULL.__dict__)

    def test_positional_construction_and_field_equality(self):
        receipt = SpanBundleReceiptBatchReceipt(
            1,
            BATCH_FULL.start,
            hashlib.sha256(BATCH_FULL.to_bytes()).digest(),
            BATCH_FULL.end,
            _span_bundle_receipt_batch_receipt_signature(
                KEY, RECEIPT_CFULL
            ),
        )
        self.assertEqual(receipt, RECEIPT_CFULL)
        self.assertEqual(
            dataclasses.astuple(receipt), dataclasses.astuple(RECEIPT_CFULL)
        )
        self.assertNotEqual(
            receipt,
            dataclasses.replace(receipt, signature=b"\x01" * 32),
        )
        self.assertEqual(hash(receipt), hash(RECEIPT_CFULL))

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_C1.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            RECEIPT_C1.signature = b""

    def test_version_contract(self):
        for bad in ("1", 1.0, True, None, b"1"):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    bad, b"", ZERO, PFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceipt(
                2, b"", ZERO, PFRONTIER_1.to_bytes(), ZERO
            )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceipt(
                0, b"", ZERO, PFRONTIER_1.to_bytes(), ZERO
            )

    def test_start_contract(self):
        for bad in (1, "ab", None, [b""]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, bad, ZERO, PFRONTIER_1.to_bytes(), ZERO
                )
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceipt(
                1, b"\xff", ZERO, PFRONTIER_1.to_bytes(), ZERO
            )
        # b"" (no receipt yet) is a valid start.
        SpanBundleReceiptBatchReceipt(
            1, b"", ZERO, PFRONTIER_1.to_bytes(), ZERO
        )

    def test_digest_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, b"", bad, PFRONTIER_1.to_bytes(), ZERO
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, b"", bad, PFRONTIER_1.to_bytes(), ZERO
                )

    def test_end_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, b"", ZERO, bad, ZERO
                )
        # The end is a canonical non-empty span bundle receipt
        # frontier: empty, junk and a range frontier encoding all fail.
        for bad in (b"", b"\xff", RFRONTIER_1.to_bytes()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, b"", ZERO, bad, ZERO
                )

    def test_signature_contract(self):
        for bad in (1, "ab", None, [ZERO]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, b"", ZERO, PFRONTIER_1.to_bytes(), bad
                )
        for bad in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt(
                    1, b"", ZERO, PFRONTIER_1.to_bytes(), bad
                )


class SpanBundleReceiptBatchReceiptEncodingTest(unittest.TestCase):
    def test_round_trip_byte_for_byte(self):
        for receipt in (RECEIPT_C1, RECEIPT_C2, RECEIPT_CFULL):
            data = receipt.to_bytes()
            self.assertIsInstance(data, bytes)
            parsed = SpanBundleReceiptBatchReceipt.from_bytes(data)
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), data)

    def test_encoding_shape(self):
        data = RECEIPT_C1.to_bytes()
        outer = json.loads(data)
        self.assertIsInstance(outer, list)
        self.assertEqual(len(outer), 5)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], RECEIPT_C1.start.hex())
        self.assertEqual(outer[2], RECEIPT_C1.digest.hex())
        self.assertEqual(outer[3], RECEIPT_C1.end.hex())
        self.assertEqual(outer[4], RECEIPT_C1.signature.hex())
        # Compact: no whitespace, lowercase hex, no length prefix.
        self.assertNotIn(b" ", data)
        self.assertNotIn(b"\n", data)
        self.assertEqual(
            data, data.decode("utf-8").lower().encode("utf-8")
        )
        # C is exactly the first four fields; the NPBJ39 prefix is
        # concatenated directly with no delimiter or length prefix.
        self.assertEqual(
            _span_bundle_receipt_batch_receipt_content_bytes(RECEIPT_C1),
            json.dumps(
                [outer[0], outer[1], outer[2], outer[3]],
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def test_uppercase_hex_rejected(self):
        data = RECEIPT_C1.to_bytes()
        outer = json.loads(data)
        outer[2] = outer[2].upper()
        with self.assertRaises(ValueError):
            SpanBundleReceiptBatchReceipt.from_bytes(
                json.dumps(outer, separators=(",", ":")).encode("utf-8")
            )

    def test_from_bytes_type_contract(self):
        for bad in ("x", 1, None, [RECEIPT_C1], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt.from_bytes(bad)

    def test_from_bytes_value_contract(self):
        for bad in (
            b"junk",
            b"[]",
            b"[1]",
            json.dumps(
                [
                    1,
                    "",
                    ZERO.hex(),
                    PFRONTIER_1.to_bytes().hex(),
                    ZERO.hex(),
                    0,
                ],
                separators=(",", ":"),
            ).encode("utf-8"),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            RECEIPT_C1.start.hex(),
            RECEIPT_C1.digest.hex(),
            RECEIPT_C1.end.hex(),
            RECEIPT_C1.signature.hex(),
        ]
        for index, bad_value in (
            (0, "1"),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError):
                SpanBundleReceiptBatchReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_non_canonical_spelling_rejected(self):
        data = RECEIPT_C1.to_bytes()
        for bad in (
            data + b" ",
            data.replace(b",", b", ", 1),
            b" " + data,
            json.dumps(json.loads(data), indent=1).encode("utf-8"),
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceiptBatchReceipt.from_bytes(bad)

    def test_from_bytes_does_not_verify_signature(self):
        # An all-zero signature parses: signatures are checked only by
        # audit_span_bundle_receipt_batch_receipt.
        forged = dataclasses.replace(RECEIPT_C1, signature=ZERO)
        decoded = SpanBundleReceiptBatchReceipt.from_bytes(forged.to_bytes())
        self.assertEqual(decoded, forged)


class SpanBundleReceiptBatchReceiptSignatureTest(unittest.TestCase):
    def test_signature_is_npbj39_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_RECEIPT_PREFIX
            + _span_bundle_receipt_batch_receipt_content_bytes(
                RECEIPT_CFULL
            ),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_CFULL.signature, expected)
        self.assertEqual(
            RECEIPT_CFULL.signature,
            _span_bundle_receipt_batch_receipt_signature(
                KEY, RECEIPT_CFULL
            ),
        )
        self.assertEqual(len(RECEIPT_CFULL.signature), 32)

    def test_new_domain_label_distinct_from_batch(self):
        # The batch's own NPBJ38 label and the frontier NPBJ37 label
        # produce different signatures over the same content.
        content = _span_bundle_receipt_batch_receipt_content_bytes(
            RECEIPT_CFULL
        )
        for label in (_SPAN_BUNDLE_RECEIPT_BATCH_PREFIX, b"NPBJ37"):
            wrong = hmac.new(
                KEY, label + content, hashlib.sha256
            ).digest()
            self.assertNotEqual(wrong, RECEIPT_CFULL.signature)


class CommitBatchTest(unittest.TestCase):
    def test_commit_returns_receipt_and_advances(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipt = auditor.commit_batch(BATCH_FULL)
        self.assertIsInstance(receipt, SpanBundleReceiptBatchReceipt)
        self.assertEqual(receipt, RECEIPT_CFULL)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.digest,
            hashlib.sha256(BATCH_FULL.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, PFRONTIER_2.to_bytes())
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_batch_receipt_signature(KEY, receipt),
        )

    def test_commit_accepts_canonical_bytes(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        receipt = auditor.commit_batch(BATCH_FULL.to_bytes())
        self.assertEqual(receipt, RECEIPT_CFULL)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_single_and_chained_commits(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        self.assertEqual(auditor.commit_batch(BATCH_1), RECEIPT_C1)
        self.assertEqual(auditor.checkpoint, PFRONTIER_1)
        self.assertEqual(auditor.commit_batch(BATCH_2), RECEIPT_C2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_commit_matches_audit_batch(self):
        via_commit = SpanBundleReceiptAuditor(KEY)
        via_commit.commit_batch(BATCH_1)
        via_commit.commit_batch(BATCH_2)
        via_batch = SpanBundleReceiptAuditor(KEY)
        via_batch.audit_batch(BATCH_1)
        via_batch.audit_batch(BATCH_2)
        self.assertEqual(via_commit.checkpoint, via_batch.checkpoint)

    def test_commit_type_contract(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [BATCH_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_bytes_is_value_error(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        for bad in (
            b"junk",
            b"[1,2,3]",
            b"",
            BATCH_FULL.to_bytes() + b" ",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_batch(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_failed_commit_changes_nothing_and_mints_nothing(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        # BATCH_FULL starts from the empty ledger: it cannot extend
        # PFRONTIER_1, so the commit fails and no receipt is minted.
        with self.assertRaises(ValueError):
            auditor.commit_batch(BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.commit_batch(BATCH_2), RECEIPT_C2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(OTHER_KEY).commit_batch(BATCH_FULL)

    def test_batch_signature_mismatch_rejected(self):
        forged = dataclasses.replace(BATCH_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            SpanBundleReceiptAuditor(KEY).commit_batch(forged)

    def test_endpoint_signature_mismatches_have_distinct_texts(self):
        # The batch record's own NPBJ38 failure and the endpoint
        # frontier signature failures report separate texts.
        auditor = SpanBundleReceiptAuditor(KEY)
        try:
            auditor.commit_batch(
                dataclasses.replace(BATCH_FULL, signature=ZERO)
            )
        except ValueError as error:
            self.assertIn("batch signature", str(error))
            self.assertNotIn("frontier signatures", str(error))
        bad_start_frontier = dataclasses.replace(
            PFRONTIER_1, signature=ZERO
        )
        bad = dataclasses.replace(
            BATCH_2, start=bad_start_frontier.to_bytes()
        )
        bad = dataclasses.replace(
            bad,
            signature=_span_bundle_receipt_batch_signature(KEY, bad),
        )
        try:
            auditor.commit_batch(bad)
        except ValueError as error:
            self.assertIn("start frontier signatures", str(error))
            self.assertNotIn("batch signature does", str(error))
        # Flip the end frontier's NPBJ37 signature to hit the distinct
        # end-failure text.
        bad_end_frontier = dataclasses.replace(
            PFRONTIER_1, signature=ZERO
        )
        bad_end = dataclasses.replace(
            BATCH_FULL, end=bad_end_frontier.to_bytes()
        )
        bad_end = dataclasses.replace(
            bad_end,
            signature=_span_bundle_receipt_batch_signature(KEY, bad_end),
        )
        try:
            auditor.commit_batch(bad_end)
        except ValueError as error:
            self.assertIn("end frontier signatures", str(error))

    def test_replay_rejected_without_state_change(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        first = auditor.commit_batch(BATCH_FULL)
        self.assertEqual(first, RECEIPT_CFULL)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_batch(BATCH_FULL)
        self.assertIs(auditor.checkpoint, before)

    def test_overflow_rejected_without_state_change(self):
        # A span-bundle-receipt frontier pinned at u64 max cannot accept
        # one more receipt through a commit.
        max_range = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        placeholder = SpanBundleReceiptFrontier(
            1, U64_MAX, max_range.to_bytes(), ZERO, ZERO
        )
        maxed = dataclasses.replace(
            placeholder,
            signature=_span_bundle_receipt_frontier_signature(
                KEY, placeholder
            ),
        )
        continuation = resign_receipt(
            dataclasses.replace(RECEIPT_1, start=maxed.end)
        )
        overflow = batch_for(
            maxed.to_bytes(),
            (continuation.to_bytes(),),
            maxed.to_bytes(),
        )
        auditor = SpanBundleReceiptAuditor(KEY, checkpoint=maxed)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_batch(overflow)
        self.assertIs(auditor.checkpoint, before)


class CommitBatchLinearizationTest(unittest.TestCase):
    def test_single_batch_and_commit_compete_on_one_lock(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        successes, failures = [], []
        barrier = threading.Barrier(3)

        def run(action, token):
            barrier.wait()
            try:
                action()
                successes.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.commit_batch(BATCH_FULL),
                    "full",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.commit_batch(BATCH_1), "one"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_1, BUNDLE_1),
                    "single",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 2)
        # The checkpoint never went backwards: a BATCH_2 continuation
        # links cleanly from whichever single step won.
        if successes[0] != "full":
            auditor.commit_batch(BATCH_2)
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)

    def test_two_competing_commits_one_wins_one_receipt(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                auditor.commit_batch(BATCH_FULL)
                outcomes.append("ok")
            except ValueError:
                outcomes.append("replay")

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ok", "replay"])
        self.assertEqual(auditor.checkpoint, PFRONTIER_2)


class AuditSpanBundleReceiptBatchReceiptTest(unittest.TestCase):
    def test_accepts_objects_and_canonical_bytes(self):
        final = audit_span_bundle_receipt_batch_receipt(
            RECEIPT_CFULL, BATCH_FULL, KEY
        )
        self.assertIsInstance(final, SpanBundleReceiptFrontier)
        self.assertEqual(final, PFRONTIER_2)
        again = audit_span_bundle_receipt_batch_receipt(
            RECEIPT_CFULL.to_bytes(), BATCH_FULL.to_bytes(), KEY
        )
        self.assertEqual(again, PFRONTIER_2)

    def test_single_and_chained_batches(self):
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_C1, BATCH_1, KEY
            ),
            PFRONTIER_1,
        )
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_C2, BATCH_2, KEY
            ),
            PFRONTIER_2,
        )

    def test_returns_end_frontier(self):
        final = audit_span_bundle_receipt_batch_receipt(
            RECEIPT_C2, BATCH_2, KEY
        )
        self.assertEqual(final.to_bytes(), BATCH_2.end)
        self.assertEqual(final, PFRONTIER_2)

    def test_receipt_round_trips_through_transport(self):
        # The observable contract: to_bytes/from_bytes is byte-for-byte
        # and the transported receipt still independently verifies.
        transported = SpanBundleReceiptBatchReceipt.from_bytes(
            RECEIPT_CFULL.to_bytes()
        )
        self.assertEqual(transported.to_bytes(), RECEIPT_CFULL.to_bytes())
        self.assertEqual(
            audit_span_bundle_receipt_batch_receipt(
                transported, BATCH_FULL, KEY
            ),
            PFRONTIER_2,
        )

    def test_type_contract(self):
        for bad_r in (
            1,
            "x",
            None,
            [RECEIPT_CFULL],
            object(),
            True,
        ):
            with self.assertRaises(TypeError, msg=repr(bad_r)):
                audit_span_bundle_receipt_batch_receipt(
                    bad_r, BATCH_FULL, KEY
                )
        for bad_b in (1, "x", None, [BATCH_FULL], object()):
            with self.assertRaises(TypeError, msg=repr(bad_b)):
                audit_span_bundle_receipt_batch_receipt(
                    RECEIPT_CFULL, bad_b, KEY
                )
        for bad_key in (1, "x", None, [KEY], object(), bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad_key)):
                audit_span_bundle_receipt_batch_receipt(
                    RECEIPT_CFULL, BATCH_FULL, bad_key
                )

    def test_empty_key_is_value_error(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_CFULL, BATCH_FULL, b""
            )

    def test_malformed_bytes_is_value_error(self):
        for bad in (b"junk", b"[1,2,3]", b""):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt(
                    bad, BATCH_FULL, KEY
                )
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_span_bundle_receipt_batch_receipt(
                    RECEIPT_CFULL, bad, KEY
                )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_CFULL, BATCH_FULL, OTHER_KEY
            )

    def test_tampered_signature_rejected(self):
        forged = dataclasses.replace(RECEIPT_CFULL, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                forged, BATCH_FULL, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                forged.to_bytes(), BATCH_FULL, KEY
            )

    def test_wrong_domain_label_rejected(self):
        wrong = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_BATCH_PREFIX
            + _span_bundle_receipt_batch_receipt_content_bytes(
                RECEIPT_CFULL
            ),
            hashlib.sha256,
        ).digest()
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                dataclasses.replace(RECEIPT_CFULL, signature=wrong),
                BATCH_FULL,
                KEY,
            )

    def test_tampered_digest_rejected(self):
        # A changed digest with a freshly recomputed NPBJ39 signature
        # still fails the constant-time digest comparison.
        forged = dataclasses.replace(RECEIPT_CFULL, digest=ZERO)
        signed = dataclasses.replace(
            forged,
            signature=_span_bundle_receipt_batch_receipt_signature(
                KEY, forged
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                signed, BATCH_FULL, KEY
            )

    def test_digest_binds_the_exact_batch_bytes(self):
        # Another batch record over the very same endpoints is not
        # acknowledged: its canonical bytes differ (here the carried
        # receipt body is tampered and the outer batch honestly
        # re-signed over the changed body), so SHA256(batch.to_bytes())
        # no longer equals the receipt digest, and it is rejected before
        # the batch replay.
        tampered_receipts = (
            dataclasses.replace(RECEIPT_1, signature=ZERO).to_bytes(),
            RECEIPT_2.to_bytes(),
        )
        same_endpoints = batch_for(
            BATCH_FULL.start,
            tampered_receipts,
            BATCH_FULL.end,
        )
        self.assertEqual(same_endpoints.start, RECEIPT_CFULL.start)
        self.assertEqual(same_endpoints.end, RECEIPT_CFULL.end)
        self.assertNotEqual(
            same_endpoints.to_bytes(), BATCH_FULL.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_CFULL, same_endpoints, KEY
            )

    def test_tampered_start_rejected(self):
        # A structurally valid span frontier different from the batch's
        # declared start; the receipt signature is honestly recomputed
        # so only the endpoint comparison can fail.
        forged = dataclasses.replace(
            RECEIPT_C2, start=PFRONTIER_2.to_bytes()
        )
        signed = dataclasses.replace(
            forged,
            signature=_span_bundle_receipt_batch_receipt_signature(
                KEY, forged
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                signed, BATCH_2, KEY
            )

    def test_tampered_end_rejected(self):
        forged = dataclasses.replace(
            RECEIPT_C1, end=PFRONTIER_2.to_bytes()
        )
        signed = dataclasses.replace(
            forged,
            signature=_span_bundle_receipt_batch_receipt_signature(
                KEY, forged
            ),
        )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                signed, BATCH_1, KEY
            )

    def test_receipt_of_other_batch_rejected(self):
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_C1, BATCH_2, KEY
            )
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_C2, BATCH_1, KEY
            )

    def test_batch_is_reverified(self):
        # The NPBJ38 batch signature is re-checked as part of the batch
        # audit.
        forged_batch = dataclasses.replace(BATCH_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                RECEIPT_CFULL, forged_batch, KEY
            )
        # A tampered carried receipt fails the whole-segment replay even
        # with a matching receipt over an honestly re-signed batch.
        tampered_receipts = (
            RECEIPT_1.to_bytes(),
            dataclasses.replace(RECEIPT_2, signature=ZERO).to_bytes(),
        )
        signed_batch = batch_for(
            b"", tampered_receipts, PFRONTIER_2.to_bytes()
        )
        signed_receipt = batch_receipt_for(signed_batch)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                signed_receipt, signed_batch, KEY
            )

    def test_forged_end_rejected(self):
        # An honestly NPBJ38-signed batch declaring an end the replay
        # cannot reach fails the whole-segment verification.
        forged = dataclasses.replace(BATCH_2, end=PFRONTIER_1.to_bytes())
        forged = dataclasses.replace(
            forged,
            signature=_span_bundle_receipt_batch_signature(KEY, forged),
        )
        receipt = batch_receipt_for(forged)
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                receipt, forged, KEY
            )

    def test_stateless_pure_check_touches_no_auditor(self):
        auditor = SpanBundleReceiptAuditor(KEY)
        audit_span_bundle_receipt_batch_receipt(
            RECEIPT_CFULL, BATCH_FULL, KEY
        )
        self.assertIsNone(auditor.checkpoint)
        auditor.audit_batch(BATCH_1)
        before = auditor.checkpoint
        # A standalone audit succeeds regardless of the live
        # auditor's state and changes none of it...
        audit_span_bundle_receipt_batch_receipt(
            RECEIPT_CFULL, BATCH_FULL, KEY
        )
        self.assertIs(auditor.checkpoint, before)
        # ...just as a failing one does.
        with self.assertRaises(ValueError):
            audit_span_bundle_receipt_batch_receipt(
                dataclasses.replace(RECEIPT_CFULL, signature=ZERO),
                BATCH_FULL,
                KEY,
            )
        self.assertIs(auditor.checkpoint, before)


if __name__ == "__main__":
    unittest.main()
