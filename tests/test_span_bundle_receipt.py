import dataclasses
import hashlib
import hmac
import json
import threading
import unittest

from nearproof import (
    RangeAuditor,
    RangeFrontier,
    SpanBundleReceipt,
    SpanReceiptBundle,
    _SPAN_BUNDLE_RECEIPT_PREFIX,
    _range_frontier_mac,
    _span_bundle_receipt_content_bytes,
    _span_bundle_receipt_signature,
    _span_receipt_bundle_signature,
    audit_bundle_receipt,
    seal_span_receipt_bundle,
)
from test_range_auditor_audit_batch import (
    CHAIN,
    CFRONTIER_1,
    KEY,
    OTHER_KEY,
    RANGE_1,
    RANGE_FROM_CP,
    RDIGEST_1,
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


def receipt_for(bundle, key=KEY, start=None, end=None, digest=None):
    """A receipt over ``bundle`` with the NPBJ36 signature recomputed over
    the first four fields; ``start``/``end``/``digest`` default to the
    honest values."""
    placeholder = SpanBundleReceipt(
        1,
        bundle.start if start is None else start,
        (
            hashlib.sha256(bundle.to_bytes()).digest()
            if digest is None
            else digest
        ),
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


def resign_bundle(bundle, key=KEY):
    return dataclasses.replace(
        bundle,
        signature=_span_receipt_bundle_signature(key, bundle),
    )


class SpanBundleReceiptFieldContractTest(unittest.TestCase):
    def test_field_order_and_no_key(self):
        self.assertEqual(
            [field.name for field in dataclasses.fields(SpanBundleReceipt)],
            ["version", "start", "bundle_digest", "end", "signature"],
        )
        self.assertNotIn("key", RECEIPT_FULL.__dict__)
        self.assertNotIn("mac", RECEIPT_FULL.__dict__)

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
    def test_compact_lowercase_hex_shape(self):
        raw = RECEIPT_FULL.to_bytes()
        outer = json.loads(raw)
        self.assertEqual(outer[0], 1)
        self.assertEqual(outer[1], BUNDLE_FULL.start.hex())
        self.assertEqual(
            outer[2],
            hashlib.sha256(BUNDLE_FULL.to_bytes()).hexdigest(),
        )
        self.assertEqual(outer[3], BUNDLE_FULL.end.hex())
        self.assertEqual(outer[4], RECEIPT_FULL.signature.hex())
        # Compact: no whitespace, no length prefix, lowercase hex only.
        self.assertNotIn(b" ", raw)
        self.assertEqual(raw, raw.decode("utf-8").lower().encode("utf-8"))

    def test_round_trip_byte_for_byte(self):
        for receipt in (RECEIPT_1, RECEIPT_2, RECEIPT_FULL):
            raw = receipt.to_bytes()
            parsed = SpanBundleReceipt.from_bytes(raw)
            self.assertEqual(parsed, receipt)
            self.assertEqual(parsed.to_bytes(), raw)

    def test_parse_does_not_verify_signature(self):
        # A structurally valid receipt with an all-zero signature parses;
        # the signature is checked only by audit_bundle_receipt.
        unsigned = dataclasses.replace(RECEIPT_1, signature=ZERO)
        parsed = SpanBundleReceipt.from_bytes(unsigned.to_bytes())
        self.assertEqual(parsed, unsigned)

    def test_non_canonical_spelling_rejected(self):
        raw = RECEIPT_1.to_bytes()
        variants = (
            b"",
            b"junk",
            b"[1,2,3]",
            raw + b" ",
            raw.replace(b",", b", ", 1),
            b" " + raw,
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                SpanBundleReceipt.from_bytes(bad)

    def test_wrong_json_shape_rejected(self):
        cases = (
            b"{}",
            b"[1,2,3,4]",
            b"[1,2,3,4,5,6]",
            b'["1","","' + ZERO.hex().encode() + b'","'
            + RFRONTIER_1.to_bytes().hex().encode()
            + b'","' + ZERO.hex().encode() + b'"]',
        )
        for bad in cases:
            with self.assertRaises((TypeError, ValueError), msg=repr(bad)):
                SpanBundleReceipt.from_bytes(bad)

    def test_from_bytes_wrong_kind_is_type_error(self):
        for bad in (1, "x", None, [RECEIPT_1.to_bytes()], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                SpanBundleReceipt.from_bytes(bad)

    def test_signature_is_npbj36_over_first_four_fields(self):
        expected = hmac.new(
            KEY,
            _SPAN_BUNDLE_RECEIPT_PREFIX
            + _span_bundle_receipt_content_bytes(RECEIPT_FULL),
            hashlib.sha256,
        ).digest()
        self.assertEqual(RECEIPT_FULL.signature, expected)
        self.assertEqual(len(RECEIPT_FULL.signature), 32)
        # The prefix and the compact encoding are concatenated directly,
        # with no delimiter or length prefix between them.
        joined = json.dumps(
            [
                RECEIPT_FULL.version,
                RECEIPT_FULL.start.hex(),
                RECEIPT_FULL.bundle_digest.hex(),
                RECEIPT_FULL.end.hex(),
            ],
            separators=(",", ":"),
            sort_keys=False,
        ).encode()
        self.assertEqual(
            hmac.new(
                KEY, _SPAN_BUNDLE_RECEIPT_PREFIX + joined, hashlib.sha256
            ).digest(),
            RECEIPT_FULL.signature,
        )


class CommitBundleSuccessTest(unittest.TestCase):
    def test_mints_receipt_and_advances(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_bundle(BUNDLE_FULL)
        self.assertIsInstance(receipt, SpanBundleReceipt)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.bundle_digest,
            hashlib.sha256(BUNDLE_FULL.to_bytes()).digest(),
        )
        self.assertEqual(receipt.end, BUNDLE_FULL.end)
        self.assertEqual(
            receipt.signature,
            _span_bundle_receipt_signature(KEY, receipt),
        )

    def test_does_not_return_auditor(self):
        auditor = RangeAuditor(KEY)
        self.assertNotIsInstance(auditor.commit_bundle(BUNDLE_1), RangeAuditor)

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        receipt = auditor.commit_bundle(BUNDLE_FULL.to_bytes())
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(receipt, RECEIPT_FULL)

    def test_chained_commits_and_restart(self):
        auditor = RangeAuditor(KEY)
        self.assertEqual(auditor.commit_bundle(BUNDLE_1), RECEIPT_1)
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertEqual(auditor.commit_bundle(BUNDLE_2), RECEIPT_2)
        self.assertEqual(auditor.state, RFRONTIER_2)
        restored = RangeAuditor(
            KEY, checkpoint=RFRONTIER_1.to_bytes()
        )
        self.assertEqual(restored.commit_bundle(BUNDLE_2), RECEIPT_2)
        self.assertEqual(restored.state, RFRONTIER_2)

    def test_matches_other_entry_points(self):
        via_commit = RangeAuditor(KEY)
        via_commit.commit_bundle(BUNDLE_1)
        via_commit.commit_bundle(BUNDLE_2)
        via_singles = RangeAuditor(KEY)
        via_singles.audit(RECEIPT_R1, RANGE_1)
        via_singles.audit(RECEIPT_RCP, RANGE_FROM_CP)
        via_audit = RangeAuditor(KEY)
        via_audit.audit_bundle(BUNDLE_FULL)
        self.assertEqual(via_commit.state, via_singles.state)
        self.assertEqual(via_commit.state, via_audit.state)


class CommitBundleFailureTest(unittest.TestCase):
    def test_replay_rejected_without_receipt_or_rollback(self):
        auditor = RangeAuditor(KEY)
        auditor.commit_bundle(BUNDLE_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.commit_bundle(BUNDLE_FULL.to_bytes())
        self.assertIs(auditor.state, before)

    def test_wrong_start_rejected(self):
        # BUNDLE_2 starts at RFRONTIER_1 and cannot commit into an empty
        # auditor; nothing is minted and the state stays empty.
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).commit_bundle(BUNDLE_FULL)

    def test_bad_signature_rejected(self):
        forged = dataclasses.replace(BUNDLE_FULL, signature=ZERO)
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_bundle(forged)
        self.assertIsNone(auditor.state)

    def test_old_fork_rejected(self):
        fork_frontier = range_frontier_for(
            1, CFRONTIER_1.to_bytes(), b"\x02" * 32
        )
        placeholder = SpanReceiptBundle(
            1,
            fork_frontier.to_bytes(),
            (RECEIPT_RCP.to_bytes(),),
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        fork = resign_bundle(placeholder)
        auditor = RangeAuditor(KEY)
        auditor.commit_bundle(BUNDLE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_bundle(fork)
        self.assertIs(auditor.state, before)

    def test_overflow_rejected_without_state_change(self):
        maxed = range_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        placeholder = SpanReceiptBundle(
            1,
            maxed.to_bytes(),
            (RECEIPT_RCP.to_bytes(),),
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        overflow = resign_bundle(placeholder)
        auditor = RangeAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.commit_bundle(overflow)
        self.assertIs(auditor.state, before)

    def test_failed_call_mints_nothing_and_keeps_auditor_usable(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_bundle(b"junk")
        with self.assertRaises(TypeError):
            auditor.commit_bundle(42)
        self.assertIsNone(auditor.state)
        receipt = auditor.commit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(
            audit_bundle_receipt(receipt, BUNDLE_FULL, KEY), RFRONTIER_2
        )

    def test_wrong_kind_is_type_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_bundle(bad)
        self.assertIsNone(auditor.state)


class CommitBundleLinearizationTest(unittest.TestCase):
    def test_all_entry_points_compete_on_one_lock(self):
        auditor = RangeAuditor(KEY)
        successes, failures, receipts = [], [], []
        barrier = threading.Barrier(4)

        def run(action, token):
            barrier.wait()
            try:
                result = action()
                successes.append(token)
                if isinstance(result, SpanBundleReceipt):
                    receipts.append(token)
            except ValueError:
                failures.append(token)

        threads = [
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.commit_bundle(BUNDLE_FULL),
                    "commit",
                ),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_bundle(BUNDLE_FULL), "audit"),
            ),
            threading.Thread(
                target=run,
                args=(lambda: auditor.audit_batch(CHAIN), "batch"),
            ),
            threading.Thread(
                target=run,
                args=(
                    lambda: auditor.audit(RECEIPT_R1, RANGE_1),
                    "one",
                ),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 3)
        winner = successes[0]
        # A receipt exists exactly when commit_bundle won.
        self.assertEqual(receipts, ["commit"] if winner == "commit" else [])
        if winner == "one":
            self.assertEqual(auditor.state, RFRONTIER_1)
        else:
            self.assertEqual(auditor.state, RFRONTIER_2)
        # The frontier never went backwards: whichever call won, a later
        # BUNDLE_2 still links cleanly from the winning end.
        if winner == "one":
            auditor.audit_bundle(BUNDLE_2)
            self.assertEqual(auditor.state, RFRONTIER_2)

    def test_two_competing_full_commits_one_wins(self):
        auditor = RangeAuditor(KEY)
        outcomes = []
        barrier = threading.Barrier(2)

        def run():
            barrier.wait()
            try:
                auditor.commit_bundle(BUNDLE_FULL)
                outcomes.append("ok")
            except ValueError:
                outcomes.append("replay")

        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ok", "replay"])
        self.assertEqual(auditor.state, RFRONTIER_2)


class AuditBundleReceiptSuccessTest(unittest.TestCase):
    def test_returns_final_frontier(self):
        final = audit_bundle_receipt(RECEIPT_FULL, BUNDLE_FULL, KEY)
        self.assertEqual(final, RFRONTIER_2)
        self.assertEqual(
            final.mac, _range_frontier_mac(KEY, final)
        )

    def test_accepts_objects_or_canonical_bytes(self):
        self.assertEqual(
            audit_bundle_receipt(
                RECEIPT_1.to_bytes(), BUNDLE_1.to_bytes(), KEY
            ),
            RFRONTIER_1,
        )
        self.assertEqual(
            audit_bundle_receipt(
                RECEIPT_2, BUNDLE_2.to_bytes(), KEY
            ),
            RFRONTIER_2,
        )
        self.assertEqual(
            audit_bundle_receipt(
                RECEIPT_2.to_bytes(), BUNDLE_2, KEY
            ),
            RFRONTIER_2,
        )

    def test_round_trip_then_verify(self):
        produced = RangeAuditor(KEY).commit_bundle(BUNDLE_FULL)
        transported = SpanBundleReceipt.from_bytes(produced.to_bytes())
        self.assertEqual(transported, produced)
        self.assertEqual(
            audit_bundle_receipt(transported, BUNDLE_FULL, KEY),
            RFRONTIER_2,
        )

    def test_stateless_and_touches_no_auditor(self):
        # Verification needs no RangeAuditor at all, and a third party can
        # verify a bundle against the same key regardless of any local
        # ledger state.
        advanced = RangeAuditor(KEY)
        advanced.commit_bundle(BUNDLE_FULL)
        # Re-verifying the first bundle still works from an "empty"
        # perspective — nothing consults or mutates ``advanced``.
        self.assertEqual(
            audit_bundle_receipt(RECEIPT_1, BUNDLE_1, KEY),
            RFRONTIER_1,
        )
        self.assertEqual(advanced.state, RFRONTIER_2)
        self.assertIsInstance(
            audit_bundle_receipt(RECEIPT_1, BUNDLE_1, KEY), RangeFrontier
        )


class AuditBundleReceiptDigestBindingTest(unittest.TestCase):
    def test_receipt_binds_exactly_one_bundle(self):
        # A structurally valid, properly NPBJ35-signed bundle carrying the
        # same start and end fields as BUNDLE_FULL but a different body is
        # not admitted by a receipt minted over BUNDLE_FULL.
        placeholder = SpanReceiptBundle(
            1,
            BUNDLE_FULL.start,
            (RECEIPT_R1.to_bytes(),),
            BUNDLE_FULL.end,
            ZERO,
        )
        other = resign_bundle(placeholder)
        self.assertEqual(other.start, BUNDLE_FULL.start)
        self.assertEqual(other.end, BUNDLE_FULL.end)
        self.assertNotEqual(other.to_bytes(), BUNDLE_FULL.to_bytes())
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, other, KEY)

    def test_receipt_over_one_bundle_rejected_for_another(self):
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_1, BUNDLE_2, KEY)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, BUNDLE_1, KEY)

    def test_digest_field_equals_sha256_of_bundle(self):
        self.assertEqual(
            RECEIPT_FULL.bundle_digest,
            hashlib.sha256(BUNDLE_FULL.to_bytes()).digest(),
        )
        bad = dataclasses.replace(
            RECEIPT_FULL, bundle_digest=b"\x09" * 32
        )
        bad = receipt_for(BUNDLE_FULL, digest=bad.bundle_digest)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(bad, BUNDLE_FULL, KEY)


class AuditBundleReceiptViolationTest(unittest.TestCase):
    def test_wrong_key_and_empty_key(self):
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, BUNDLE_FULL, OTHER_KEY)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, BUNDLE_FULL, b"")

    def test_wrong_key_type_is_type_error(self):
        for bad in ("k", 1, None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_bundle_receipt(RECEIPT_FULL, BUNDLE_FULL, bad)

    def test_wrong_argument_kinds_are_type_errors(self):
        for bad_receipt in (1, "x", None, [RECEIPT_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad_receipt)):
                audit_bundle_receipt(bad_receipt, BUNDLE_FULL, KEY)
        for bad_bundle in (1, "x", None, [BUNDLE_FULL], object(), True):
            with self.assertRaises(TypeError, msg=repr(bad_bundle)):
                audit_bundle_receipt(RECEIPT_FULL, bad_bundle, KEY)

    def test_non_canonical_bytes_are_value_errors(self):
        with self.assertRaises(ValueError):
            audit_bundle_receipt(
                RECEIPT_FULL.to_bytes() + b" ", BUNDLE_FULL, KEY
            )
        with self.assertRaises(ValueError):
            audit_bundle_receipt(
                RECEIPT_FULL, BUNDLE_FULL.to_bytes() + b"\n", KEY
            )
        with self.assertRaises(ValueError):
            audit_bundle_receipt(b"junk", BUNDLE_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, b"junk", KEY)

    def test_tampered_signature_rejected(self):
        bad = dataclasses.replace(RECEIPT_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(bad, BUNDLE_FULL, KEY)

    def test_tampered_bundle_body_rejected(self):
        raw = bytearray(BUNDLE_FULL.to_bytes())
        raw[-1] ^= 0x01
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, bytes(raw), KEY)

    def test_tampered_carried_receipt_rejected(self):
        # Re-sign a bundle whose carried receipt is forged: the receipt
        # over the original bundle is rejected on the digest mismatch,
        # and a receipt re-minted over the tampered bundle is rejected
        # once the carried chain fails full verification.
        placeholder = SpanReceiptBundle(
            1,
            b"",
            (
                dataclasses.replace(RECEIPT_R1, mac=ZERO).to_bytes(),
                RECEIPT_RCP.to_bytes(),
            ),
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        tampered = resign_bundle(placeholder)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(RECEIPT_FULL, tampered, KEY)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(receipt_for(tampered), tampered, KEY)

    def test_forged_endpoint_rejected(self):
        # A receipt signed over honest content but naming a different end
        # frontier does not match the bundle's end.
        forged_end = receipt_for(BUNDLE_FULL, end=BUNDLE_1.end)
        self.assertEqual(forged_end.end, BUNDLE_1.end)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(forged_end, BUNDLE_FULL, KEY)
        forged_start = receipt_for(BUNDLE_2, start=b"")
        with self.assertRaises(ValueError):
            audit_bundle_receipt(forged_start, BUNDLE_2, KEY)

    def test_signature_must_use_npbj36_domain(self):
        # A signature computed under a different domain label is just a
        # wrong signature.
        wrong_domain = hmac.new(
            KEY,
            b"NPBJ35" + _span_bundle_receipt_content_bytes(RECEIPT_FULL),
            hashlib.sha256,
        ).digest()
        bad = dataclasses.replace(RECEIPT_FULL, signature=wrong_domain)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(bad, BUNDLE_FULL, KEY)

    def test_unsigned_receipt_rejected(self):
        unsigned = dataclasses.replace(RECEIPT_1, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_bundle_receipt(unsigned, BUNDLE_1, KEY)


if __name__ == "__main__":
    unittest.main()
