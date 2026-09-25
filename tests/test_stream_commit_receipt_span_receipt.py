import dataclasses
import hashlib
import hmac
import inspect
import json
import threading
import unittest

from nearproof import (
    StreamCommitReceiptBundleReceiptAuditor,
    StreamCommitReceiptSpanReceipt,
    _stream_commit_receipt_span_receipt_content_bytes,
    _stream_commit_receipt_span_receipt_signature,
    audit_stream_commit_receipt_span_receipt,
)
from test_range_auditor_audit_batch import (
    KEY,
    OTHER_KEY,
    U64_MAX,
    ZERO,
)
from test_stream_commit_receipt_bundle_receipt import (
    BUNDLE_2,
    RECEIPT_1,
    RECEIPT_2,
)
from test_stream_commit_receipt_bundle_receipt_frontier import (
    RDIGEST_1,
    RFRONTIER_1,
    RFRONTIER_2,
    bundle_receipt_frontier_for,
)
from test_stream_commit_receipt_frontier import CFRONTIER_2
from test_stream_commit_receipt_span import (
    SPAN_1,
    SPAN_2,
    SPAN_FULL,
    SPAN_SOLO,
    seal_stream_commit_receipt_span,
    span_for,
)


def _commit(span, *prior, key=KEY):
    """Fresh auditor, audit the prior spans, then commit ``span``."""
    auditor = StreamCommitReceiptBundleReceiptAuditor(key)
    for booked in prior:
        auditor.audit_span(booked)
    return auditor.commit_span(span)


# The interval receipts an honest ledger mints: the genesis interval on
# an empty ledger, its continuation and the whole chain booked in one
# step.
SR_1 = _commit(SPAN_1)
SR_2 = _commit(SPAN_2, SPAN_1)
SR_FULL = _commit(SPAN_FULL)


def receipt_for(start, span_digest, end, key=KEY):
    """A span receipt with its NPBJ32 signature recomputed over the
    first four fields."""
    placeholder = StreamCommitReceiptSpanReceipt(
        1, start, span_digest, end, ZERO
    )
    return dataclasses.replace(
        placeholder,
        signature=_stream_commit_receipt_span_receipt_signature(
            key, placeholder
        ),
    )


class StreamCommitReceiptSpanReceiptFieldContractTest(unittest.TestCase):
    def test_constructs_positionally_and_compares_by_fields(self):
        receipt = StreamCommitReceiptSpanReceipt(
            1,
            b"",
            hashlib.sha256(SPAN_1.to_bytes()).digest(),
            RFRONTIER_1.to_bytes(),
            SR_1.signature,
        )
        self.assertEqual(receipt, SR_1)
        self.assertEqual(hash(receipt), hash(SR_1))
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.start, b"")
        self.assertEqual(
            receipt.span_digest, hashlib.sha256(SPAN_1.to_bytes()).digest()
        )
        self.assertEqual(receipt.end, RFRONTIER_1.to_bytes())

    def test_fields_of_chain_and_continuation(self):
        self.assertEqual(SR_FULL.start, b"")
        self.assertEqual(
            SR_FULL.span_digest,
            hashlib.sha256(SPAN_FULL.to_bytes()).digest(),
        )
        self.assertEqual(SR_FULL.end, RFRONTIER_2.to_bytes())
        self.assertEqual(SR_2.start, RFRONTIER_1.to_bytes())
        self.assertEqual(
            SR_2.span_digest,
            hashlib.sha256(SPAN_2.to_bytes()).digest(),
        )
        self.assertEqual(SR_2.end, RFRONTIER_2.to_bytes())

    def test_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            SR_1.signature = ZERO

    def test_no_alias_attributes(self):
        self.assertEqual(
            sorted(field.name for field in dataclasses.fields(SR_1)),
            ["end", "signature", "span_digest", "start", "version"],
        )

    def test_version_contract(self):
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SR_1, version=bad)
        with self.assertRaises(ValueError):
            dataclasses.replace(SR_1, version=2)

    def test_start_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SR_1, start=bad)
        for bad in (b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SR_1, start=bad)
        dataclasses.replace(SR_1, start=b"")
        dataclasses.replace(SR_1, start=RFRONTIER_1.to_bytes())

    def test_span_digest_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SR_1, span_digest=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SR_1, span_digest=bad)

    def test_end_contract(self):
        for bad in (1, "1", None, bytearray(RFRONTIER_1.to_bytes())):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SR_1, end=bad)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SR_1, end=bad)

    def test_signature_contract(self):
        for bad in (1, "1", None, bytearray(ZERO)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                dataclasses.replace(SR_1, signature=bad)
        for bad in (b"", ZERO + b"\x00", ZERO[:-1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                dataclasses.replace(SR_1, signature=bad)


class StreamCommitReceiptSpanReceiptEncodingTest(unittest.TestCase):
    def test_canonical_encoding_shape(self):
        expected = (
            b'[1,"","'
            + hashlib.sha256(SPAN_1.to_bytes()).hexdigest().encode()
            + b'","'
            + RFRONTIER_1.to_bytes().hex().encode()
            + b'","'
            + SR_1.signature.hex().encode()
            + b'"]'
        )
        self.assertEqual(SR_1.to_bytes(), expected)

    def test_round_trip(self):
        for receipt in (SR_1, SR_2, SR_FULL):
            blob = receipt.to_bytes()
            self.assertIsInstance(blob, bytes)
            self.assertEqual(
                StreamCommitReceiptSpanReceipt.from_bytes(blob), receipt
            )
            self.assertEqual(
                StreamCommitReceiptSpanReceipt.from_bytes(blob).to_bytes(),
                blob,
            )

    def test_from_bytes_type_contract(self):
        blob = SR_1.to_bytes()
        for bad in (1, "x", None, bytearray(blob)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                StreamCommitReceiptSpanReceipt.from_bytes(bad)

    def test_from_bytes_rejects_malformed(self):
        for bad in (
            b"",
            b"junk",
            b"{}",
            b"[1,2,3]",
            b"[1,2,3,4,5,6]",
        ):
            with self.assertRaises(ValueError, msg=repr(bad)):
                StreamCommitReceiptSpanReceipt.from_bytes(bad)

    def test_from_bytes_field_type_contract(self):
        good = [
            1,
            "",
            hashlib.sha256(SPAN_1.to_bytes()).hexdigest(),
            RFRONTIER_1.to_bytes().hex(),
            SR_1.signature.hex(),
        ]
        for index, bad_value in ((0, "1"), (2, 1)):
            broken = list(good)
            broken[index] = bad_value
            with self.assertRaises(TypeError, msg=(index, bad_value)):
                StreamCommitReceiptSpanReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_rejects_non_canonical_spelling(self):
        blob = SR_1.to_bytes()
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpanReceipt.from_bytes(
                blob.replace(b",", b", ")
            )
        upper = blob.replace(
            SR_1.signature.hex().encode(),
            SR_1.signature.hex().upper().encode(),
        )
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpanReceipt.from_bytes(upper)
        with self.assertRaises(ValueError):
            StreamCommitReceiptSpanReceipt.from_bytes(
                blob.replace(b"[1,", b"[2,", 1)
            )

    def test_from_bytes_rejects_bad_field_values(self):
        good = [
            1,
            "",
            hashlib.sha256(SPAN_1.to_bytes()).hexdigest(),
            RFRONTIER_1.to_bytes().hex(),
            SR_1.signature.hex(),
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
                StreamCommitReceiptSpanReceipt.from_bytes(
                    json.dumps(broken, separators=(",", ":")).encode()
                )

    def test_from_bytes_does_not_verify_signature(self):
        tampered = dataclasses.replace(SR_1, signature=ZERO)
        parsed = StreamCommitReceiptSpanReceipt.from_bytes(
            tampered.to_bytes()
        )
        self.assertEqual(parsed, tampered)


class StreamCommitReceiptSpanReceiptSignatureTest(unittest.TestCase):
    def test_signature_scheme(self):
        expected = hmac.new(
            KEY,
            b"NPBJ32"
            + _stream_commit_receipt_span_receipt_content_bytes(SR_1),
            hashlib.sha256,
        ).digest()
        self.assertEqual(SR_1.signature, expected)
        self.assertEqual(len(SR_1.signature), 32)

    def test_signature_covers_exactly_first_four_fields(self):
        # The covered content is independent of the signature, but moves
        # when any of the first four fields change.
        content = _stream_commit_receipt_span_receipt_content_bytes(SR_1)
        self.assertEqual(
            _stream_commit_receipt_span_receipt_content_bytes(
                dataclasses.replace(SR_1, signature=ZERO)
            ),
            content,
        )
        self.assertNotEqual(
            _stream_commit_receipt_span_receipt_content_bytes(
                dataclasses.replace(SR_1, span_digest=ZERO)
            ),
            content,
        )

    def test_span_digest_is_hash_of_canonical_span_bytes(self):
        for span, receipt in (
            (SPAN_1, SR_1),
            (SPAN_2, SR_2),
            (SPAN_FULL, SR_FULL),
        ):
            self.assertEqual(
                receipt.span_digest,
                hashlib.sha256(span.to_bytes()).digest(),
            )
            self.assertEqual(len(receipt.span_digest), 32)


class CommitSpanTest(unittest.TestCase):
    def test_commits_and_returns_receipt(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_1)
        self.assertIsInstance(receipt, StreamCommitReceiptSpanReceipt)
        self.assertEqual(receipt, SR_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_whole_chain_books_in_one_step(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_FULL)
        self.assertEqual(receipt, SR_FULL)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)
        self.assertEqual(auditor.checkpoint.sequence, 2)

    def test_continuation_after_first_interval(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        first = auditor.commit_span(SPAN_1)
        second = auditor.commit_span(SPAN_2)
        self.assertEqual(first, SR_1)
        self.assertEqual(second, SR_2)
        self.assertEqual(auditor.checkpoint, RFRONTIER_2)

    def test_accepts_canonical_bytes(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_1.to_bytes())
        self.assertEqual(receipt, SR_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_restart_from_checkpoint_continues(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        for checkpoint in (
            auditor.checkpoint,
            auditor.checkpoint.to_bytes(),
        ):
            restored = StreamCommitReceiptBundleReceiptAuditor(
                KEY, checkpoint=checkpoint
            )
            self.assertEqual(restored.commit_span(SPAN_2), SR_2)
            self.assertEqual(restored.checkpoint, RFRONTIER_2)

    def test_first_interval_must_start_empty(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_2)
        self.assertIsNone(auditor.checkpoint)

    def test_replayed_interval_rejected_and_mints_nothing(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        receipt = auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(receipt, SR_1)

    def test_old_fork_rejected_and_mints_nothing(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_FULL)
        before = auditor.checkpoint
        for span in (SPAN_1, SPAN_2, SPAN_SOLO):
            with self.assertRaises(ValueError):
                auditor.commit_span(span)
        self.assertIs(auditor.checkpoint, before)

    def test_same_sequence_fork_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_SOLO)
        self.assertIs(auditor.checkpoint, before)

    def test_tampered_span_rejected_leaves_state(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(dataclasses.replace(SPAN_2, mac=ZERO))
        self.assertIs(auditor.checkpoint, before)

    def test_wrong_key_rejected(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(OTHER_KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1)
        self.assertIsNone(auditor.checkpoint)

    def test_wrong_argument_type(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (1, "x", None, [SPAN_1], (SPAN_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                auditor.commit_span(bad)
        self.assertIsNone(auditor.checkpoint)

    def test_malformed_or_non_canonical_bytes_is_value_error(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                auditor.commit_span(bad)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1.to_bytes().replace(b",", b", "))
        self.assertIsNone(auditor.checkpoint)

    def test_failure_then_recovery(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_2)
        self.assertIsNone(auditor.checkpoint)
        self.assertEqual(auditor.commit_span(SPAN_1), SR_1)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)

    def test_shares_lock_with_single_and_span_audit(self):
        # An interval committed here lands exactly where the
        # one-at-a-time and span audits do, and all three continue one
        # another; replays are rejected either way.
        via_commit = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_commit.commit_span(SPAN_1)
        via_single = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_single.audit(SPAN_1.items[0][0], SPAN_1.items[0][1])
        self.assertEqual(via_commit.checkpoint, via_single.checkpoint)
        via_commit.audit(RECEIPT_2, BUNDLE_2)
        self.assertEqual(via_commit.checkpoint, RFRONTIER_2)
        with self.assertRaises(ValueError):
            via_commit.commit_span(SPAN_2)
        via_span = StreamCommitReceiptBundleReceiptAuditor(KEY)
        via_span.audit_span(SPAN_1)
        with self.assertRaises(ValueError):
            via_span.commit_span(SPAN_1)

    def test_sequence_overflow(self):
        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_2.to_bytes(), RDIGEST_1
        )
        auditor = StreamCommitReceiptBundleReceiptAuditor(
            KEY, checkpoint=maxed
        )
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(
                seal_stream_commit_receipt_span(
                    [(RECEIPT_2, BUNDLE_2)], KEY, start=maxed
                )
            )
        self.assertIs(auditor.checkpoint, before)

    def test_competing_commits_linearize(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        wins, losses = [], []

        def run(span, tag):
            try:
                wins.append((tag, auditor.commit_span(span)))
            except ValueError:
                losses.append(tag)

        threads = [
            threading.Thread(target=run, args=(SPAN_1, "a")),
            threading.Thread(target=run, args=(SPAN_SOLO, "b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(losses), 1)
        self.assertEqual(auditor.checkpoint.sequence, 1)
        # The one minted receipt verifies against exactly its span and
        # reaches the live checkpoint.
        tag, receipt = wins[0]
        winning_span = SPAN_1 if tag == "a" else SPAN_SOLO
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                receipt, winning_span, KEY
            ),
            auditor.checkpoint,
        )

    def test_commit_linearizes_against_span_audit(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        outcomes = []

        def run_commit():
            try:
                auditor.commit_span(SPAN_1)
                outcomes.append("commit")
            except ValueError:
                outcomes.append("commit-lost")

        def run_audit():
            try:
                auditor.audit_span(SPAN_SOLO)
                outcomes.append("audit")
            except ValueError:
                outcomes.append("audit-lost")

        threads = [
            threading.Thread(target=run_commit),
            threading.Thread(target=run_audit),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(sum(outcomes.count(tag) for tag in ("commit", "audit")), 1)
        self.assertEqual(
            sum(outcomes.count(tag) for tag in ("commit-lost", "audit-lost")),
            1,
        )
        self.assertEqual(auditor.checkpoint.sequence, 1)

    def test_accepted_interval_is_never_lost(self):
        auditor = StreamCommitReceiptBundleReceiptAuditor(KEY)
        auditor.commit_span(SPAN_1)
        before = auditor.checkpoint
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_SOLO)
        with self.assertRaises(ValueError):
            auditor.commit_span(SPAN_1)
        self.assertIs(auditor.checkpoint, before)
        self.assertEqual(auditor.checkpoint, RFRONTIER_1)


class AuditStreamCommitReceiptSpanReceiptTest(unittest.TestCase):
    def test_returns_end_frontier(self):
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(SR_1, SPAN_1, KEY),
            RFRONTIER_1,
        )
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(SR_2, SPAN_2, KEY),
            RFRONTIER_2,
        )
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(SR_FULL, SPAN_FULL, KEY),
            RFRONTIER_2,
        )

    def test_accepts_canonical_bytes(self):
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                SR_2.to_bytes(), SPAN_2.to_bytes(), KEY
            ),
            RFRONTIER_2,
        )

    def test_verifies_continuation_without_any_auditor(self):
        # A continuation interval cannot enter a fresh auditor, yet the
        # stateless entry verifies it on its own merits and touches no
        # auditor state while doing so.
        fresh = StreamCommitReceiptBundleReceiptAuditor(KEY)
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(SR_2, SPAN_2, KEY),
            RFRONTIER_2,
        )
        self.assertIsNone(fresh.checkpoint)
        with self.assertRaises(ValueError):
            fresh.audit_span(SPAN_2)

    def test_repeated_submission_verifies_twice(self):
        # The pure entry keeps no state; a duplicate ledger commit is
        # commit_span's job to reject.
        for _ in range(2):
            self.assertEqual(
                audit_stream_commit_receipt_span_receipt(SR_1, SPAN_1, KEY),
                RFRONTIER_1,
            )

    def test_wrong_receipt_type(self):
        for bad in (1, "x", None, [SR_1], (SR_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span_receipt(bad, SPAN_1, KEY)

    def test_wrong_span_type(self):
        for bad in (1, "x", None, [SPAN_1], (SPAN_1,), object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span_receipt(SR_1, bad, KEY)

    def test_malformed_or_non_canonical_bytes_is_value_error(self):
        for bad in (b"", b"junk", b"[1,2,3]"):
            with self.assertRaises(ValueError, msg=("receipt", repr(bad))):
                audit_stream_commit_receipt_span_receipt(bad, SPAN_1, KEY)
            with self.assertRaises(ValueError, msg=("span", repr(bad))):
                audit_stream_commit_receipt_span_receipt(SR_1, bad, KEY)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SR_1.to_bytes().replace(b",", b", "), SPAN_1, KEY
            )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                SR_1, SPAN_1.to_bytes().replace(b",", b", "), KEY
            )

    def test_key_contract(self):
        for bad in (1, "x", None, bytearray(KEY)):
            with self.assertRaises(TypeError, msg=repr(bad)):
                audit_stream_commit_receipt_span_receipt(SR_1, SPAN_1, bad)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(SR_1, SPAN_1, b"")

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(SR_1, SPAN_1, OTHER_KEY)

    def test_forged_signature_rejected(self):
        tampered = dataclasses.replace(SR_1, signature=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(tampered, SPAN_1, KEY)

    def test_span_digest_binds_exactly_one_interval(self):
        # The genesis receipt does not attest the whole-chain packing nor
        # vice versa, and not the competing solo fork either, even though
        # the intervals share an end or a start.
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(SR_1, SPAN_FULL, KEY)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(SR_FULL, SPAN_1, KEY)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(SR_1, SPAN_SOLO, KEY)
        # A valid signature over a swapped digest is still a mismatch.
        swapped = receipt_for(
            SR_1.start,
            hashlib.sha256(SPAN_SOLO.to_bytes()).digest(),
            SR_1.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(swapped, SPAN_1, KEY)

    def test_start_mismatch_rejected(self):
        # Properly signed receipt claiming a non-empty start for the
        # genesis span.
        forged = receipt_for(
            RFRONTIER_1.to_bytes(), SR_1.span_digest, SR_1.end
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(forged, SPAN_1, KEY)

    def test_end_mismatch_rejected(self):
        # Properly signed receipt whose end is a valid frontier the span
        # does not reach.
        forged = receipt_for(
            SR_1.start, SR_1.span_digest, RFRONTIER_2.to_bytes()
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(forged, SPAN_1, KEY)

    def test_tampered_span_bytes_rejected_by_digest(self):
        # The receipt honestly signs SPAN_1's digest and endpoints, but
        # the presented span bytes were altered: the digest no longer
        # matches.
        tampered_span = dataclasses.replace(SPAN_1, mac=ZERO)
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(SR_1, tampered_span, KEY)

    def test_carried_chain_tampering_rejected_by_replay(self):
        # A receipt honestly signed over a tampered span's digest and
        # endpoints (so every outer comparison passes) must still fail
        # when the span chain is replayed: the carried receipt's NPBJ28
        # MAC is wrong.
        broken_receipt = dataclasses.replace(RECEIPT_1, mac=ZERO)
        broken_span = span_for(
            SPAN_1.start,
            ((broken_receipt.to_bytes(), SPAN_1.items[0][1]),),
            SPAN_1.end,
        )
        forged = receipt_for(
            b"",
            hashlib.sha256(broken_span.to_bytes()).digest(),
            broken_span.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                forged, broken_span, KEY
            )

    def test_swapped_bundle_rejected_by_replay(self):
        # Honest outer receipt over a span carrying receipt 1 with the
        # wrong bundle; the inner bundle audit fails during replay.
        broken_span = span_for(
            SPAN_1.start,
            ((RECEIPT_1.to_bytes(), SPAN_SOLO.items[0][1]),),
            SPAN_1.end,
        )
        forged = receipt_for(
            b"",
            hashlib.sha256(broken_span.to_bytes()).digest(),
            broken_span.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                forged, broken_span, KEY
            )

    def test_sequence_overflow_rejected(self):
        # A syntactically valid, properly NPBJ31-MAC'd span whose start
        # frontier already sits at the u64 sequence maximum: the outer
        # receipt comparisons all pass, but the interval replay must
        # raise on the u64 overflow, so no such receipt can be confirmed.
        from test_stream_commit_receipt_frontier import CFRONTIER_1

        maxed = bundle_receipt_frontier_for(
            U64_MAX, CFRONTIER_1.to_bytes(), RDIGEST_1
        )
        overflowed = span_for(
            maxed.to_bytes(),
            ((RECEIPT_2.to_bytes(), BUNDLE_2.to_bytes()),),
            maxed.to_bytes(),
        )
        receipt = receipt_for(
            maxed.to_bytes(),
            hashlib.sha256(overflowed.to_bytes()).digest(),
            overflowed.end,
        )
        with self.assertRaises(ValueError):
            audit_stream_commit_receipt_span_receipt(
                receipt, overflowed, KEY
            )


class StreamCommitReceiptSpanReceiptParameterNamingTest(unittest.TestCase):
    def test_stateless_audit_params_named_receipt_span_key(self):
        signature = inspect.signature(
            audit_stream_commit_receipt_span_receipt
        )
        self.assertEqual(
            list(signature.parameters), ["receipt", "span", "key"]
        )

    def test_commit_span_param_named_x(self):
        signature = inspect.signature(
            StreamCommitReceiptBundleReceiptAuditor.commit_span
        )
        self.assertEqual(list(signature.parameters), ["self", "x"])

    def test_entry_verifies_with_keyword_arguments(self):
        self.assertEqual(
            audit_stream_commit_receipt_span_receipt(
                receipt=SR_1, span=SPAN_1, key=KEY
            ),
            RFRONTIER_1,
        )


if __name__ == "__main__":
    unittest.main()
