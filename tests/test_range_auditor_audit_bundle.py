import dataclasses
import threading
import unittest

from nearproof import (
    RangeAuditor,
    SpanReceiptBundle,
    _range_frontier_mac,
    _range_receipt_mac,
    _span_receipt_bundle_signature,
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


def resign(bundle, key=KEY):
    return dataclasses.replace(
        bundle,
        signature=_span_receipt_bundle_signature(key, bundle),
    )


class AuditBundleSuccessTest(unittest.TestCase):
    def test_returns_self_and_advances_to_declared_end(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(auditor.audit_bundle(BUNDLE_FULL), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)
        self.assertEqual(auditor.state.sequence, 2)

    def test_accepts_canonical_bytes(self):
        auditor = RangeAuditor(KEY)
        self.assertIs(
            auditor.audit_bundle(BUNDLE_FULL.to_bytes()), auditor
        )
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_single_receipt_bundle(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_chained_bundles_start_at_current_state(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertIs(auditor.audit_bundle(BUNDLE_2), auditor)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_matches_audit_and_audit_batch(self):
        via_bundle = RangeAuditor(KEY)
        via_bundle.audit_bundle(BUNDLE_1)
        via_bundle.audit_bundle(BUNDLE_2)
        via_singles = RangeAuditor(KEY)
        via_singles.audit(RECEIPT_R1, RANGE_1)
        via_singles.audit(RECEIPT_RCP, RANGE_FROM_CP)
        via_batch = RangeAuditor(KEY)
        via_batch.audit_batch(CHAIN)
        self.assertEqual(via_bundle.state, via_singles.state)
        self.assertEqual(via_bundle.state, via_batch.state)

    def test_mixed_with_old_entry_points(self):
        auditor = RangeAuditor(KEY)
        auditor.audit(RECEIPT_R1, RANGE_1)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        auditor.audit(RECEIPT_RCP, RANGE_FROM_CP)
        self.assertEqual(auditor.state, RFRONTIER_2)
        auditor = RangeAuditor(KEY)
        auditor.audit_batch(((RECEIPT_R1, RANGE_1),))
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_restart_from_checkpoint_then_bundle(self):
        first = RangeAuditor(KEY)
        first.audit_bundle(BUNDLE_1)
        restored = RangeAuditor(
            KEY, checkpoint=first.state.to_bytes()
        )
        restored.audit_bundle(BUNDLE_2)
        self.assertEqual(restored.state, RFRONTIER_2)

    def test_success_advances_frontier_without_receipt(self):
        # The commit advances the read-only frontier and returns the
        # auditor itself — no whole-bundle commit receipt is minted.
        auditor = RangeAuditor(KEY)
        result = auditor.audit_bundle(BUNDLE_1)
        self.assertIs(result, auditor)
        self.assertEqual(auditor.state, RFRONTIER_1)
        self.assertEqual(
            auditor.state.mac, _range_frontier_mac(KEY, auditor.state)
        )


class AuditBundleStartTest(unittest.TestCase):
    def test_empty_auditor_rejects_non_empty_start(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)

    def test_non_empty_auditor_rejects_empty_start(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_same_bundle_replayed_rejected(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_FULL)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.state, before)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL.to_bytes())
        self.assertIs(auditor.state, before)

    def test_old_fork_rejected(self):
        # A structurally valid bundle starting at a different frontier
        # than the current one is an old fork.
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
        fork = resign(placeholder)
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(fork)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_broken_link_inside_bundle_rejected(self):
        # The second carried receipt is re-signed (its NPBJ12 MAC and
        # endpoints still valid) but starts at the empty string while the
        # first ends elsewhere: it verifies on its own merits yet breaks
        # the replayed chain.
        forged_receipt = dataclasses.replace(RECEIPT_RCP, start=b"")
        forged_receipt = dataclasses.replace(
            forged_receipt,
            mac=_range_receipt_mac(KEY, forged_receipt),
        )
        placeholder = SpanReceiptBundle(
            1,
            b"",
            (RECEIPT_R1.to_bytes(), forged_receipt.to_bytes()),
            RFRONTIER_2.to_bytes(),
            ZERO,
        )
        forged = resign(placeholder)
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(forged)
        self.assertIsNone(auditor.state)


class AuditBundleTypeContractTest(unittest.TestCase):
    def test_wrong_kind_is_type_error(self):
        auditor = RangeAuditor(KEY)
        for bad in (1, "x", None, [BUNDLE_FULL], object(), True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_malformed_or_non_canonical_bytes_is_value_error(self):
        auditor = RangeAuditor(KEY)
        variants = (
            b"junk",
            b"[1,2,3]",
            b"",
            BUNDLE_FULL.to_bytes() + b" ",
        )
        for bad in variants:
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.audit_bundle(bad)
        self.assertIsNone(auditor.state)

    def test_failed_call_leaves_auditor_usable(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(b"junk")
        with self.assertRaises(TypeError):
            auditor.audit_bundle(42)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)


class AuditBundleVerificationTest(unittest.TestCase):
    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            RangeAuditor(OTHER_KEY).audit_bundle(BUNDLE_FULL)

    def test_bundle_signature_mismatch_rejected(self):
        forged = dataclasses.replace(BUNDLE_FULL, signature=ZERO)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(forged)

    def test_tampered_start_frontier_rejected(self):
        bad_start = dataclasses.replace(RFRONTIER_1, mac=ZERO)
        placeholder = SpanReceiptBundle(
            1,
            bad_start.to_bytes(),
            (RECEIPT_RCP.to_bytes(),),
            BUNDLE_2.end,
            ZERO,
        )
        tampered = resign(placeholder)
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(tampered)
        self.assertEqual(auditor.state, RFRONTIER_1)

    def test_tampered_end_frontier_rejected(self):
        bad_end = dataclasses.replace(RFRONTIER_2, mac=ZERO)
        placeholder = SpanReceiptBundle(
            1,
            b"",
            BUNDLE_FULL.receipts,
            bad_end.to_bytes(),
            ZERO,
        )
        tampered = resign(placeholder)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(tampered)

    def test_tampered_carried_receipt_rejected(self):
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
        tampered = resign(placeholder)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(tampered)

    def test_end_must_match_replayed_chain(self):
        placeholder = SpanReceiptBundle(
            1,
            BUNDLE_FULL.start,
            BUNDLE_FULL.receipts,
            RFRONTIER_1.to_bytes(),
            ZERO,
        )
        tampered = resign(placeholder)
        with self.assertRaises(ValueError):
            RangeAuditor(KEY).audit_bundle(tampered)


class AuditBundleAtomicityTest(unittest.TestCase):
    def test_failure_changes_nothing_from_empty(self):
        auditor = RangeAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_2)
        self.assertIsNone(auditor.state)
        auditor.audit_bundle(BUNDLE_FULL)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_failure_keeps_prior_frontier(self):
        auditor = RangeAuditor(KEY)
        auditor.audit_bundle(BUNDLE_1)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(BUNDLE_FULL)
        self.assertIs(auditor.state, before)
        auditor.audit_bundle(BUNDLE_2)
        self.assertEqual(auditor.state, RFRONTIER_2)

    def test_sequence_overflow_rejected_without_state_change(self):
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
        overflow = resign(placeholder)
        auditor = RangeAuditor(KEY, checkpoint=maxed)
        before = auditor.state
        with self.assertRaises(ValueError):
            auditor.audit_bundle(overflow)
        self.assertIs(auditor.state, before)


class AuditBundleLinearizationTest(unittest.TestCase):
    def test_bundle_batch_and_single_competing_calls_linearize(self):
        auditor = RangeAuditor(KEY)
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
                    lambda: auditor.audit_bundle(BUNDLE_FULL),
                    "bundle",
                ),
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
        self.assertEqual(len(failures), 2)
        winner = successes[0]
        if winner == "one":
            self.assertEqual(auditor.state, RFRONTIER_1)
        else:
            self.assertEqual(auditor.state, RFRONTIER_2)


if __name__ == "__main__":
    unittest.main()
