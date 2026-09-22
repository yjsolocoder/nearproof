"""nearproof - verifiable distance measurement and location proofs.

Public API: AttestedObservation / BitEvidence / BitFrontier / BitGate /
BitGuard / BitMap / BitMapHistoryAuditor / BitMapHistoryEvidence /
BitMapHistoryEvidenceAuditor / BitMapHistoryJournalAuditor /
BitMapHistoryJournalBundle / BitMapHistoryJournalReceipt /
BitMapHistoryJournalReceiptAuditor / BitMapHistoryJournalReceiptFrontier /
BitMapHistoryJournalState / BitMapUpdate /
BitRound /
BitSession /
BitState / BoundAttestedObservation / BoundEvidence /
BoundEvidenceRevocation / CertifiedConsensusEvidence / Challenge /
ChallengeStateError / CommitRange / CommitRangeAuditor / Consensus / ContextRevocation / CrlProof / CrlProofAuditor / CrlState /
Evidence /
JournalBatchReceipt / JournalBatchReceiptAuditor /
JournalBatchReceiptFrontier /
Measurement / Observation / ObservationRevocation / Prover / RangeDecision
/ RangeReceipt / SPEED_OF_LIGHT_MPS / TrustRevocation / TrustRevocationList / Verifier /
VerifierTrust / assess / attest_observation /
attest_observation_for_point / audit / audit_b / audit_bound /
audit_bound_policy /
audit_cert_evidence / audit_crl / audit_map_history /
audit_map_history_evidence / audit_map_history_journal_bundle /
audit_map_history_journal_receipt /
audit_map_update /
audit_proof / audit_range / audit_receipt / cert / locate /
locate_attested / locate_bound_attested / locate_cert /
locate_cert_evidence / make_crl / prove_crl / revoke_bound /
revoke_context / revoke_observation / revoke_trust / seal_map_history /
seal_map_history_journal_bundle / seal_range.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from statistics import median
from typing import Callable, Optional

__all__ = [
    "AttestedObservation",
    "BitEvidence",
    "BitFrontier",
    "BitGate",
    "BitGuard",
    "BitMap",
    "BitMapHistoryAuditor",
    "BitMapHistoryEvidence",
    "BitMapHistoryEvidenceAuditor",
    "BitMapHistoryJournalAuditor",
    "BitMapHistoryJournalBundle",
    "BitMapHistoryJournalReceipt",
    "BitMapHistoryJournalReceiptAuditor",
    "BitMapHistoryJournalReceiptBatch",
    "BitMapHistoryJournalReceiptFrontier",
    "BitMapHistoryJournalState",
    "BitMapUpdate",
    "BitRound",
    "BitSession",
    "BitState",
    "BoundAttestedObservation",
    "BoundEvidence",
    "BoundEvidenceRevocation",
    "CertifiedConsensusEvidence",
    "Challenge",
    "ChallengeStateError",
    "CommitRange",
    "CommitRangeAuditor",
    "Consensus",
    "ContextRevocation",
    "CrlProof",
    "CrlProofAuditor",
    "CrlState",
    "Evidence",
    "JournalBatchReceipt",
    "JournalBatchReceiptAuditor",
    "JournalBatchReceiptFrontier",
    "Measurement",
    "Observation",
    "ObservationRevocation",
    "Prover",
    "RangeDecision",
    "RangeReceipt",
    "SPEED_OF_LIGHT_MPS",
    "TrustRevocation",
    "TrustRevocationList",
    "Verifier",
    "VerifierTrust",
    "assess",
    "attest_observation",
    "attest_observation_for_point",
    "audit",
    "audit_b",
    "audit_bound",
    "audit_bound_policy",
    "audit_cert_evidence",
    "audit_commit",
    "audit_crl",
    "audit_map_history",
    "audit_map_history_evidence",
    "audit_map_history_journal_bundle",
    "audit_map_history_journal_receipt",
    "audit_map_history_journal_receipt_batch",
    "audit_map_update",
    "audit_proof",
    "audit_range",
    "audit_receipt",
    "cert",
    "locate",
    "locate_attested",
    "locate_bound_attested",
    "locate_cert",
    "locate_cert_evidence",
    "make_crl",
    "prove_crl",
    "revoke_bound",
    "revoke_context",
    "revoke_observation",
    "revoke_trust",
    "seal_map_history",
    "seal_map_history_journal_bundle",
    "seal_map_history_journal_receipt_batch",
    "seal_range",
]

SPEED_OF_LIGHT_MPS = 299_792_458.0
NONCE_BYTES = 16
# Context, opening and their bound digest are all fixed at 32 bytes.
CONTEXT_BYTES = 32
OPENING_BYTES = 32
DIGEST_BYTES = 32
# Domain separation prefixes for the commitment hash and the bound response.
_DIGEST_PREFIX = b"NPC1"
_RESPONSE_PREFIX = b"NPR1"
# Domain separation prefix for the bound-evidence MAC.
_BOUND_EVIDENCE_PREFIX = b"NPBE1"
# Domain separation prefix for the bound-evidence revocation MAC.
_BOUND_REVOCATION_PREFIX = b"NPBR1"
# Domain separation prefix for the context revocation MAC.
_CONTEXT_REVOCATION_PREFIX = b"NPCR1"
# Domain separation prefix for the verifier-trust MAC.
_TRUST_PREFIX = b"NPVT1"
# Domain separation prefix for the verifier-trust revocation MAC.
_TRUST_REVOCATION_PREFIX = b"NPVR1"
# Domain separation prefix for the trust-revocation-list MAC.
_TRUST_REVOCATION_LIST_PREFIX = b"NPVRL1"
# Domain separation prefix for the certified-consensus-evidence MAC.
_CERT_EVIDENCE_PREFIX = b"NPCCE1"
# Domain separation prefix for the CRL-snapshot proof MAC.
_CRL_PROOF_PREFIX = b"NPCCE2"
# Domain separation prefix for the rollback-protection CRL-state MAC.
_CRL_STATE_PREFIX = b"NPCK1"
# Domain separation prefixes for the bit-challenge protocol: the transcript
# digest, the per-bit response and the bit-evidence MAC respectively.
_BIT_TRANSCRIPT_PREFIX = b"NPFC1"
_BIT_RESPONSE_PREFIX = b"NPFR1"
_BIT_EVIDENCE_PREFIX = b"NPFB1"
# Domain separation prefix for the resumable bit-session checkpoint MAC.
_BIT_STATE_PREFIX = b"NPBS1"
# Domain separation prefix for the rollback-protection bit-session frontier MAC.
_BIT_FRONTIER_PREFIX = b"NPBF1"
# Domain separation prefix for the partitioned rollback-protection table MAC.
_BIT_MAP_PREFIX = b"NPBL1"
# Domain separation prefix for the table-transition proof MAC.
_BIT_MAP_UPDATE_PREFIX = b"NPBU1"
# Domain separation prefix for the table-history evidence MAC.
_BIT_MAP_HISTORY_PREFIX = b"NPBH1"
# Domain separation prefixes for the history-evidence journal: the state MAC
# and the digest-chain step respectively.
_BIT_MAP_HISTORY_JOURNAL_MAC_PREFIX = b"NPBJ1"
_BIT_MAP_HISTORY_JOURNAL_DIGEST_PREFIX = b"NPBJ2"
# Domain separation prefix for the history-evidence journal bundle MAC.
_BIT_MAP_HISTORY_JOURNAL_BUNDLE_PREFIX = b"NPBJ3"
# Domain separation prefix for the history-evidence journal receipt MAC.
_BIT_MAP_HISTORY_JOURNAL_RECEIPT_PREFIX = b"NPBJ4"
# Domain separation prefixes for the journal-receipt frontier: the frontier
# MAC and the digest-chain step respectively.
_BIT_MAP_HISTORY_JOURNAL_FRONTIER_MAC_PREFIX = b"NPBJ5"
_BIT_MAP_HISTORY_JOURNAL_FRONTIER_DIGEST_PREFIX = b"NPBJ6"
# Domain separation prefix for the journal-receipt batch MAC.
_BIT_MAP_HISTORY_JOURNAL_RECEIPT_BATCH_PREFIX = b"NPBJ7"
# Domain separation prefix for the batch-commit receipt MAC.
_BIT_MAP_HISTORY_JOURNAL_BATCH_RECEIPT_PREFIX = b"NPBJ8"
# Domain separation prefixes for the batch-commit frontier: the commit
# frontier MAC and the commit digest-chain step respectively.
_BIT_MAP_HISTORY_JOURNAL_BATCH_RECEIPT_FRONTIER_MAC_PREFIX = b"NPBJ9"
_BIT_MAP_HISTORY_JOURNAL_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX = b"NPBJ10"
# Domain separation prefix for the transferable commit-range proof MAC.
_COMMIT_RANGE_PREFIX = b"NPBJ11"
# Domain separation prefix for the commit range receipt MAC.
_RANGE_RECEIPT_MAC_PREFIX = b"NPBJ12"
# A bit transcript (t) is 16 random bytes; per-bit responses are 32 bytes.
BIT_T_BYTES = 16
BIT_R_BYTES = 32

_PENDING = "pending"
_CONSUMED = "consumed"
_REVOKED = "revoked"
_EXPIRED = "expired"


@dataclass(frozen=True)
class Challenge:
    """One challenge issued by a verifier."""

    round_index: int
    nonce: bytes


class ChallengeStateError(ValueError):
    """A challenge is unknown to this verifier, consumed, revoked, or expired.

    Subclasses :class:`ValueError` so callers catching the legacy validation
    errors keep working.
    """


@dataclass(frozen=True)
class Measurement:
    """The outcome of one challenge/response round."""

    round_index: int
    nonce: bytes
    response: bytes
    elapsed_seconds: float
    distance_meters: float


@dataclass(frozen=True)
class RangeDecision:
    """The result of :func:`assess` over a batch of rounds.

    ``sample_count`` counts every input sample (including outliers),
    ``upper_bound`` is the largest distance among the inliers, and
    ``accepted`` says whether that bound is at most the configured limit.
    """

    sample_count: int
    upper_bound: float
    accepted: bool


@dataclass(frozen=True)
class Observation:
    """One verifier's contribution to a 2D location consensus.

    ``id`` is the verifier's unique non-empty identifier, ``(x, y)`` its
    finite non-bool coordinates, and ``decision`` the :class:`RangeDecision`
    bounding the prover's distance from it. Only the decision's
    ``upper_bound`` (a finite non-negative number) participates in the
    consensus; its ``accepted`` flag never does.
    """

    id: str
    x: float
    y: float
    decision: "RangeDecision"


@dataclass(frozen=True)
class Consensus:
    """The outcome of :func:`locate` over a set of :class:`Observation`.

    ``total`` counts every observation, ``support`` those whose disk covers
    the queried point, ``rejected`` is the lexicographically sorted tuple of
    the non-supporting verifier ids, and ``accepted`` says whether the
    support reaches the requested quorum.
    """

    total: int
    support: int
    rejected: tuple[str, ...]
    accepted: bool


_EVIDENCE_FIELDS = (
    "version",
    "round_index",
    "nonce",
    "response",
    "start",
    "end",
    "speed",
    "elapsed",
    "distance",
    "result",
    "mac",
)


class _OrderedObject(json.JSONDecoder):
    """JSON decoder that rejects duplicate and out-of-field-order object keys.

    A plain ``json.loads`` silently keeps the last value of a duplicated key
    and only preserves the order of first appearance, so enforce both the
    exact key set and its order during parsing.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys != list(_EVIDENCE_FIELDS):
            raise ValueError("evidence JSON keys must be exactly the fields in field order")
        return dict(pairs)


def _evidence_payload(evidence: "Evidence") -> dict:
    """The JSON-ready evidence fields except ``mac``, in field order."""
    return {
        "version": evidence.version,
        "round_index": evidence.round_index,
        "nonce": evidence.nonce.hex(),
        "response": evidence.response.hex(),
        "start": evidence.start,
        "end": evidence.end,
        "speed": evidence.speed,
        "elapsed": evidence.elapsed,
        "distance": evidence.distance,
        "result": evidence.result,
    }


def _encode_payload(payload: dict) -> bytes:
    """The canonical evidence encoding: compact UTF-8 JSON, no NaN/Infinity."""
    return json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _evidence_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over the canonical encoding of the fields without ``mac``."""
    return hmac.new(key, _encode_payload(payload), hashlib.sha256).digest()


def _parse_int_field(value: object, name: str) -> int:
    # bool is an int subclass but is not a number for the evidence contract.
    if type(value) is not int:
        raise ValueError(f"evidence {name} must be an integer")
    return value


def _parse_float_field(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"evidence {name} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"evidence {name} must be a finite number")
    return number


def _parse_hex_field(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"evidence {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"evidence {name} must be a lowercase hex string") from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(f"evidence {name} must be a lowercase hex string")
    return raw


@dataclass(frozen=True)
class Evidence:
    """A tamper-evident record of one accepted verification round.

    Produced by :meth:`Verifier.verify_evidence`. ``version`` is always ``1``
    and ``result`` always ``"accepted"``; no key material is stored. ``mac``
    is HMAC-SHA256 over the canonical encoding of every field except ``mac``
    itself, so a holder of the shared key can re-check the record later with
    :func:`audit` without access to the verifier.
    """

    version: int
    round_index: int
    nonce: bytes
    response: bytes
    start: float
    end: float
    speed: float
    elapsed: float
    distance: float
    result: str
    mac: bytes

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, byte fields as
        lowercase hex, no whitespace, no NaN/Infinity."""
        payload = _evidence_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Evidence":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the evidence fields appearing once
        each in field order, ``version == 1``, ``result == "accepted"``,
        non-bool integers, finite non-bool numbers, lowercase hex strings for
        the byte fields, and a MAC that decodes to exactly 32 bytes. The MAC
        is not verified here — use :func:`audit` with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("evidence data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedObject)
        except ValueError as error:
            raise ValueError(f"evidence is not valid JSON: {error}") from error
        if not isinstance(obj, dict):
            raise ValueError(
                "evidence must be a JSON object with exactly the evidence fields"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("evidence version must be 1")
        result = obj["result"]
        if result != "accepted":
            raise ValueError('evidence result must be "accepted"')
        mac = _parse_hex_field(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError("evidence mac must decode to exactly 32 bytes")
        return cls(
            version=version,
            round_index=_parse_int_field(obj["round_index"], "round_index"),
            nonce=_parse_hex_field(obj["nonce"], "nonce"),
            response=_parse_hex_field(obj["response"], "response"),
            start=_parse_float_field(obj["start"], "start"),
            end=_parse_float_field(obj["end"], "end"),
            speed=_parse_float_field(obj["speed"], "speed"),
            elapsed=_parse_float_field(obj["elapsed"], "elapsed"),
            distance=_parse_float_field(obj["distance"], "distance"),
            result=result,
            mac=mac,
        )


def _require_finite(*values: float) -> None:
    if not all(math.isfinite(value) for value in values):
        raise ValueError("evidence values must be finite numbers")


def _validate_evidence(evidence: Evidence) -> None:
    """Enforce the field contract on an in-memory :class:`Evidence`."""
    if type(evidence.version) is not int or evidence.version != 1:
        raise ValueError("evidence version must be 1")
    if type(evidence.round_index) is not int:
        raise ValueError("evidence round_index must be an integer")
    for name in ("nonce", "response", "mac"):
        if not isinstance(getattr(evidence, name), bytes):
            raise ValueError(f"evidence {name} must be bytes")
    for name in ("start", "end", "speed", "elapsed", "distance"):
        value = getattr(evidence, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"evidence {name} must be a finite number")
        if not math.isfinite(value):
            raise ValueError(f"evidence {name} must be a finite number")
    if evidence.result != "accepted":
        raise ValueError('evidence result must be "accepted"')


_BOUND_EVIDENCE_FIELDS = (
    "version",
    "evidence",
    "context",
    "digest",
    "opening",
    "mac",
)

_BOUND_REVOCATION_FIELDS = (
    "version",
    "round_index",
    "nonce",
    "revoked_at",
    "mac",
)

_CONTEXT_REVOCATION_FIELDS = (
    "version",
    "context",
    "revoked_at",
    "mac",
)


class _OrderedBoundEvidenceObject(json.JSONDecoder):
    """JSON decoder that rejects duplicate and out-of-field-order object keys.

    The outer bound-evidence object, the nested evidence object, the
    bound-evidence-revocation object and the context-revocation object must
    each contain exactly their own fields, once each, in field order; the
    field sets are distinguishable by their key lists, so a single hook can
    check all of them.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys in (
            list(_BOUND_EVIDENCE_FIELDS),
            list(_EVIDENCE_FIELDS),
            list(_BOUND_REVOCATION_FIELDS),
            list(_CONTEXT_REVOCATION_FIELDS),
        ):
            return dict(pairs)
        raise ValueError(
            "JSON keys must be exactly the record fields in field order"
        )


def _bound_evidence_payload(record: "BoundEvidence") -> dict:
    """The JSON-ready bound-evidence fields except ``mac``, in field order.

    The nested evidence keeps its own canonical field order and carries its
    own ``mac`` as lowercase hex, exactly as :meth:`Evidence.to_bytes`
    encodes it.
    """
    evidence = _evidence_payload(record.evidence)
    evidence["mac"] = record.evidence.mac.hex()
    return {
        "version": record.version,
        "evidence": evidence,
        "context": record.context.hex(),
        "digest": record.digest.hex(),
        "opening": record.opening.hex(),
    }


def _bound_evidence_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPBE1"`` plus the canonical encoding without ``mac``."""
    return hmac.new(
        key, _BOUND_EVIDENCE_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


@dataclass(frozen=True)
class BoundEvidence:
    """A tamper-evident record of one accepted context-bound round.

    Produced by :meth:`Verifier.verify_bound`. ``version`` is always ``1``;
    ``evidence`` the :class:`Evidence` of the round; ``context``, ``digest``
    and ``opening`` the 32-byte commitment values of the bound challenge,
    with ``digest == SHA256(b"NPC1" + context + opening)``; ``mac`` exactly
    32 bytes — HMAC-SHA256 over ``b"NPBE1"`` plus the canonical encoding of
    every field except ``mac`` itself, so a holder of the shared key can
    re-check the record later with :func:`audit_bound`. Any contract
    violation raises :class:`ValueError` at construction time. No key
    material is stored.
    """

    version: int
    evidence: Evidence
    context: bytes
    digest: bytes
    opening: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("bound evidence version must be 1")
        if not isinstance(self.evidence, Evidence):
            raise ValueError("bound evidence evidence must be an Evidence")
        _validate_evidence(self.evidence)
        for name in ("context", "digest", "opening", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"bound evidence {name} must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``evidence`` as
        a nested object with its own keys in field order, byte fields as
        lowercase hex, no whitespace, no NaN/Infinity."""
        payload = _bound_evidence_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BoundEvidence":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the bound-evidence fields appearing
        once each in field order (missing, extra, duplicated or out-of-order
        keys are rejected, likewise inside the nested evidence object, which
        must satisfy the full :meth:`Evidence.from_bytes` contract),
        ``version == 1``, and the four byte fields as lowercase hex strings
        decoding to exactly 32 bytes each. After parsing and field validation
        the record is re-encoded with :meth:`to_bytes` and the result must
        equal the input byte for byte, so formatted JSON, whitespace and any
        non-canonical number or string spelling are rejected as well. Neither
        MAC is verified here — use :func:`audit_bound` with the shared key
        for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("bound evidence data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedBoundEvidenceObject)
        except ValueError as error:
            raise ValueError(
                f"bound evidence is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(_BOUND_EVIDENCE_FIELDS):
            raise ValueError(
                "bound evidence must be a JSON object with exactly the"
                " bound evidence fields"
            )
        raw_evidence = obj["evidence"]
        if not isinstance(raw_evidence, dict) or list(raw_evidence) != list(
            _EVIDENCE_FIELDS
        ):
            raise ValueError(
                "bound evidence evidence must be a JSON object with exactly"
                " the evidence fields"
            )
        # The nested object is already known to carry exactly the evidence
        # keys in field order, so its canonical re-encoding can go straight
        # through the Evidence contract (version, result, field types and
        # the 32-byte inner mac included).
        evidence = Evidence.from_bytes(_encode_payload(raw_evidence))
        version = _parse_int_field(obj["version"], "version")
        fields: dict[str, bytes] = {}
        for name in ("context", "digest", "opening", "mac"):
            fields[name] = _parse_hex_field(obj[name], name)
        record = cls(
            version=version,
            evidence=evidence,
            context=fields["context"],
            digest=fields["digest"],
            opening=fields["opening"],
            mac=fields["mac"],
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as AttestedObservation.from_bytes:
            # no whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("bound evidence encoding is not canonical")
        return record


def _bound_revocation_payload(revocation: "BoundEvidenceRevocation") -> dict:
    """The JSON-ready bound-evidence revocation fields except ``mac``."""
    return {
        "version": revocation.version,
        "round_index": revocation.round_index,
        "nonce": revocation.nonce.hex(),
        "revoked_at": revocation.revoked_at,
    }


def _bound_revocation_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPBR1"`` plus the canonical encoding without ``mac``."""
    return hmac.new(
        key, _BOUND_REVOCATION_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


@dataclass(frozen=True)
class BoundEvidenceRevocation:
    """A MAC'd, timestamped revocation of one context-bound evidence round.

    ``version`` is always ``1``; ``round_index`` a non-bool unsigned 64-bit
    integer and ``nonce`` exactly 16 bytes, together identifying one
    :class:`BoundEvidence` round via its nested evidence's
    ``(round_index, nonce)``; ``revoked_at`` a finite non-bool non-negative
    number; ``mac`` exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBR1" + encoding)`` over the canonical encoding of
    every field except ``mac`` itself. Any contract violation raises
    :class:`ValueError` at construction time. No key material is stored.
    """

    version: int
    round_index: int
    nonce: bytes
    revoked_at: float
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("bound evidence revocation version must be 1")
        if isinstance(self.round_index, bool) or type(self.round_index) is not int:
            raise ValueError("bound evidence revocation round_index must be an integer")
        if not 0 <= self.round_index <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bound evidence revocation round_index must fit in an unsigned"
                " 64-bit integer"
            )
        if not isinstance(self.nonce, bytes) or len(self.nonce) != NONCE_BYTES:
            raise ValueError(
                f"bound evidence revocation nonce must be exactly {NONCE_BYTES}"
                " bytes"
            )
        value = self.revoked_at
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                "bound evidence revocation revoked_at must be a finite"
                " non-negative number"
            )
        if not math.isfinite(value) or value < 0:
            raise ValueError(
                "bound evidence revocation revoked_at must be a finite"
                " non-negative number"
            )
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError("bound evidence revocation mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``nonce`` and
        ``mac`` as lowercase hex, no whitespace, no NaN/Infinity."""
        payload = _bound_revocation_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BoundEvidenceRevocation":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the revocation fields appearing
        once each in field order (missing, extra, duplicated or out-of-order
        keys are rejected), ``version == 1``, a non-bool u64 ``round_index``,
        ``nonce`` a lowercase hex string decoding to exactly 16 bytes, a
        finite non-bool non-negative ``revoked_at`` and ``mac`` a lowercase
        hex string decoding to exactly 32 bytes. ``revoked_at`` keeps its
        parsed type: a JSON integer stays an ``int`` and a JSON float stays
        a ``float``, so both the integer and the floating-point spelling
        round-trip. After parsing and field validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the input
        byte for byte, so formatted JSON, whitespace and any non-canonical
        number or string spelling are rejected as well. The MAC is not
        verified here — use :func:`audit_bound_policy` with the shared key
        for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("bound evidence revocation data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedBoundEvidenceObject)
        except ValueError as error:
            raise ValueError(
                f"bound evidence revocation is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(_BOUND_REVOCATION_FIELDS):
            raise ValueError(
                "bound evidence revocation must be a JSON object with exactly"
                " the bound evidence revocation fields"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("bound evidence revocation version must be 1")
        round_index = _parse_int_field(obj["round_index"], "round_index")
        if not 0 <= round_index <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bound evidence revocation round_index must fit in an unsigned"
                " 64-bit integer"
            )
        nonce = _parse_hex_field(obj["nonce"], "nonce")
        if len(nonce) != NONCE_BYTES:
            raise ValueError(
                f"bound evidence revocation nonce must decode to exactly"
                f" {NONCE_BYTES} bytes"
            )
        revoked_at = obj["revoked_at"]
        # Keep the parsed type: an integer revoked_at re-encodes as the same
        # integer, a float as the same float — coercing either way would
        # break the canonical re-encoding comparison below.
        if isinstance(revoked_at, bool) or not isinstance(revoked_at, (int, float)):
            raise ValueError(
                "bound evidence revocation revoked_at must be a finite"
                " non-negative number"
            )
        if not math.isfinite(revoked_at) or revoked_at < 0:
            raise ValueError(
                "bound evidence revocation revoked_at must be a finite"
                " non-negative number"
            )
        mac = _parse_hex_field(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError("bound evidence revocation mac must decode to 32 bytes")
        record = cls(
            version=version,
            round_index=round_index,
            nonce=nonce,
            revoked_at=revoked_at,
            mac=mac,
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("bound evidence revocation encoding is not canonical")
        return record


def revoke_bound(
    bound: "BoundEvidence | bytes",
    revoked_at: object,
    key: object,
) -> BoundEvidenceRevocation:
    """Sign a revocation of one context-bound evidence round.

    Returns a :class:`BoundEvidenceRevocation` whose ``round_index`` and
    ``nonce`` identify the nested evidence of ``bound`` (which may be a
    :class:`BoundEvidence` or its canonical :meth:`BoundEvidence.to_bytes`
    encoding). ``key`` must be non-empty and ``revoked_at`` a finite non-bool
    non-negative number (``version`` is set to ``1``); any violation raises
    :class:`ValueError`. The record is pure data: signing reads and mutates
    no verifier state.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    if isinstance(bound, bytes):
        bound = BoundEvidence.from_bytes(bound)
    elif not isinstance(bound, BoundEvidence):
        raise ValueError("bound evidence must be a BoundEvidence instance or bytes")
    record = BoundEvidenceRevocation(
        version=1,
        round_index=bound.evidence.round_index,
        nonce=bound.evidence.nonce,
        revoked_at=revoked_at,  # type: ignore[arg-type]
        mac=b"\x00" * 32,
    )
    return replace(
        record, mac=_bound_revocation_mac(key, _bound_revocation_payload(record))
    )


def _context_revocation_payload(revocation: "ContextRevocation") -> dict:
    """The JSON-ready context revocation fields except ``mac``."""
    return {
        "version": revocation.version,
        "context": revocation.context.hex(),
        "revoked_at": revocation.revoked_at,
    }


def _context_revocation_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPCR1"`` plus the canonical encoding without ``mac``."""
    return hmac.new(
        key, _CONTEXT_REVOCATION_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _parse_context_revocation_hex(value: object, name: str) -> bytes:
    # Same lowercase-hex rule as the other records, but a non-string value
    # is a shape error (TypeError), not a value error.
    if not isinstance(value, str):
        raise TypeError(
            f"context revocation {name} must be a lowercase hex string"
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"context revocation {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(f"context revocation {name} must be a lowercase hex string")
    return raw


@dataclass(frozen=True)
class ContextRevocation:
    """A MAC'd, timestamped revocation of every bound evidence for one context.

    ``version`` is always ``1``; ``context`` exactly 32 bytes, identifying
    every :class:`BoundEvidence` carrying that context; ``revoked_at`` a
    finite non-bool non-negative number, stored as ``float``; ``mac``
    exactly 32 bytes — ``HMAC-SHA256(key, b"NPCR1" + encoding)`` over the
    canonical encoding of every field except ``mac`` itself. A field of the
    wrong type raises :class:`TypeError` at construction time; a value
    contract violation raises :class:`ValueError`. No key material is
    stored.
    """

    version: int
    context: bytes
    revoked_at: float
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("context revocation version must be an integer")
        if self.version != 1:
            raise ValueError("context revocation version must be 1")
        if not isinstance(self.context, bytes):
            raise TypeError("context revocation context must be bytes")
        if len(self.context) != CONTEXT_BYTES:
            raise ValueError(
                f"context revocation context must be exactly {CONTEXT_BYTES}"
                " bytes"
            )
        value = self.revoked_at
        if not isinstance(value, (int, float)):
            raise TypeError("context revocation revoked_at must be a number")
        if isinstance(value, bool) or not math.isfinite(value) or value < 0:
            raise ValueError(
                "context revocation revoked_at must be a finite non-negative"
                " number"
            )
        # The canonical encoding always spells revoked_at as a float.
        object.__setattr__(self, "revoked_at", float(value))
        if not isinstance(self.mac, bytes):
            raise TypeError("context revocation mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError("context revocation mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``context``
        and ``mac`` as lowercase hex, no whitespace, no length prefix, no
        NaN/Infinity."""
        payload = _context_revocation_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ContextRevocation":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the contract: exactly the revocation
        fields appearing once each in field order (missing, extra,
        duplicated or out-of-order keys are rejected), ``version == 1``,
        ``context`` a lowercase hex string decoding to exactly 32 bytes, a
        finite non-bool non-negative ``revoked_at`` (stored as ``float``,
        so only the floating-point spelling round-trips) and ``mac`` a
        lowercase hex string decoding to exactly 32 bytes. After parsing
        and field validation the record is re-encoded with :meth:`to_bytes`
        and the result must equal the input byte for byte, so formatted
        JSON, whitespace and any non-canonical number or string spelling
        are rejected as well. The MAC is not verified here — use
        :func:`audit_bound_policy` with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("context revocation data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedBoundEvidenceObject)
        except ValueError as error:
            raise ValueError(
                f"context revocation is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(_CONTEXT_REVOCATION_FIELDS):
            raise ValueError(
                "context revocation must be a JSON object with exactly the"
                " context revocation fields"
            )
        record = cls(
            version=obj["version"],
            context=_parse_context_revocation_hex(obj["context"], "context"),
            revoked_at=obj["revoked_at"],
            mac=_parse_context_revocation_hex(obj["mac"], "mac"),
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("context revocation encoding is not canonical")
        return record


def revoke_context(
    context: object,
    revoked_at: object,
    key: object,
) -> ContextRevocation:
    """Sign a revocation of every bound evidence carrying ``context``.

    Returns a :class:`ContextRevocation` with ``version`` set to ``1``.
    ``key`` must be non-empty and ``context``/``revoked_at`` must satisfy
    the :class:`ContextRevocation` field contract; a value violation raises
    :class:`ValueError` and a type (shape) violation raises
    :class:`TypeError`. The record is pure data: signing reads and mutates
    no verifier state.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    record = ContextRevocation(
        version=1,
        context=context,  # type: ignore[arg-type]
        revoked_at=revoked_at,  # type: ignore[arg-type]
        mac=b"\x00" * 32,
    )
    return replace(
        record, mac=_context_revocation_mac(key, _context_revocation_payload(record))
    )


def _decode_revocation_entry(
    data: bytes,
) -> "BoundEvidenceRevocation | ContextRevocation":
    """Parse a canonical revocation encoding into its record type.

    The two revocation records have disjoint key sets, so the JSON keys of
    the encoding decide which contract applies; the chosen
    :meth:`from_bytes` then performs the full validation.
    """
    try:
        obj = json.loads(data)
    except ValueError:
        obj = None
    if isinstance(obj, dict) and list(obj) == list(_CONTEXT_REVOCATION_FIELDS):
        return ContextRevocation.from_bytes(data)
    return BoundEvidenceRevocation.from_bytes(data)


def keyed_response(key: bytes, nonce: bytes) -> bytes:
    """The response a holder of ``key`` must produce for ``nonce``."""
    return hmac.new(key, nonce, hashlib.sha256).digest()


def context_digest(context: bytes, opening: bytes) -> bytes:
    """The commitment ``SHA256(b"NPC1" + context + opening)``.

    ``context`` and ``opening`` are concatenated with no separator or length
    prefix; both are fixed-width 32-byte values so the concatenation is
    unambiguous.
    """
    return hashlib.sha256(_DIGEST_PREFIX + context + opening).digest()


def bound_response(
    key: bytes, digest: bytes, round_index: int, nonce: bytes
) -> bytes:
    """The bound response for one context-attested round.

    ``HMAC-SHA256(key, b"NPR1" + digest + u64be(round_index) + nonce)`` with
    ``round_index`` encoded as a fixed 8-byte unsigned big-endian integer.
    """
    message = (
        _RESPONSE_PREFIX
        + digest
        + int(round_index).to_bytes(8, byteorder="big", signed=False)
        + nonce
    )
    return hmac.new(key, message, hashlib.sha256).digest()


def bit_transcript_digest(context: bytes, opening: bytes) -> bytes:
    """The bit-round transcript digest ``D = SHA256(b"NPFC1" + C + O)``.

    ``C``/``O`` are fixed-width 32-byte values, concatenated directly after
    the domain prefix with no separator or length prefix.
    """
    return hashlib.sha256(_BIT_TRANSCRIPT_PREFIX + context + opening).digest()


def bit_response(
    key: bytes, t: bytes, digest: bytes, index: int, bit: int
) -> bytes:
    """The response for one bit challenge.

    ``r = HMAC-SHA256(key, b"NPFR1" + t + u32be(i) + bytes([b]) + d)`` with
    ``i`` encoded as a fixed 4-byte unsigned big-endian integer, ``b`` a
    single zero/one byte and ``d`` the 32-byte transcript digest ``D``.
    """
    message = (
        _BIT_RESPONSE_PREFIX
        + t
        + int(index).to_bytes(4, byteorder="big", signed=False)
        + bytes([bit])
        + digest
    )
    return hmac.new(key, message, hashlib.sha256).digest()


@dataclass(frozen=True)
class BitRound:
    """One bit challenge issued by :meth:`BitSession.next`.

    ``version`` is always ``1``; ``t`` the 16-byte transcript of the issuing
    session; ``index`` the non-bool unsigned 32-bit round index and ``bit``
    the non-bool challenge bit (exactly ``0`` or ``1``). Instances are
    constructed positionally in field order and compare by field values, so
    a submitted round can be checked against the pending one with ``==``. A
    field of the wrong type raises :class:`TypeError` at construction time;
    a value contract violation raises :class:`ValueError`.
    """

    version: int
    t: bytes
    index: int
    bit: int

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("bit round version must be an integer")
        if self.version != 1:
            raise ValueError("bit round version must be 1")
        if not isinstance(self.t, bytes):
            raise TypeError("bit round t must be bytes")
        if len(self.t) != BIT_T_BYTES:
            raise ValueError(f"bit round t must be exactly {BIT_T_BYTES} bytes")
        if type(self.index) is not int:
            # ``type`` excludes bools; the index is a non-bool u32.
            raise TypeError("bit round index must be an integer")
        if not 0 <= self.index <= 0xFFFFFFFF:
            raise ValueError(
                "bit round index must fit in an unsigned 32-bit integer"
            )
        if type(self.bit) is not int:
            raise TypeError("bit round bit must be an integer")
        if self.bit not in (0, 1):
            raise ValueError("bit round bit must be exactly 0 or 1")


def _validate_bit_session_args(
    context: object, opening: object, rounds: object, timeout: object
) -> tuple[int, float]:
    """The shared ``bits``/:meth:`Verifier.start_bits` argument contract.

    Returns ``(rounds, float(timeout))``; every violation raises
    :class:`ValueError`.
    """
    if not isinstance(context, bytes) or len(context) != CONTEXT_BYTES:
        raise ValueError(f"context must be exactly {CONTEXT_BYTES} bytes")
    if not isinstance(opening, bytes) or len(opening) != OPENING_BYTES:
        raise ValueError(f"opening must be exactly {OPENING_BYTES} bytes")
    if isinstance(rounds, bool) or type(rounds) is not int:
        raise ValueError("rounds must be a non-bool integer")
    # The range is closed at 2**32; round indices still fit a u32
    # because they run 0 .. rounds-1.
    if not 1 <= rounds <= 2**32:
        raise ValueError("rounds must be in the range 1 .. 2**32")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be a finite positive number")
    limit_time = float(timeout)
    if not math.isfinite(limit_time) or limit_time <= 0:
        raise ValueError("timeout must be a finite positive number")
    return rounds, limit_time


class Prover:
    """Answers challenges with a keyed response."""

    def __init__(self, shared_key: bytes) -> None:
        if not shared_key:
            raise ValueError("shared_key must not be empty")
        self._key = bytes(shared_key)

    def respond(self, challenge: Challenge) -> bytes:
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        return keyed_response(self._key, challenge.nonce)

    def reveal(
        self, challenge: Challenge, context: bytes, opening: bytes
    ) -> bytes:
        """Answer a context-bound challenge by revealing the opening.

        Returns the response a holder of the shared key must produce for a
        challenge bound to ``digest = SHA256(b"NPC1" + context + opening)``:
        ``HMAC-SHA256(key, b"NPR1" + digest + u64be(round_index) + nonce)``.
        ``context`` and ``opening`` must each be exactly 32 bytes; the
        challenge's ``round_index`` must be a non-bool unsigned 64-bit integer
        and its ``nonce`` exactly 16 bytes.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        if not isinstance(context, bytes):
            raise TypeError("context must be bytes")
        if not isinstance(opening, bytes):
            raise TypeError("opening must be bytes")
        if len(context) != CONTEXT_BYTES:
            raise ValueError(f"context must be exactly {CONTEXT_BYTES} bytes")
        if len(opening) != OPENING_BYTES:
            raise ValueError(f"opening must be exactly {OPENING_BYTES} bytes")
        round_index = challenge.round_index
        if isinstance(round_index, bool) or type(round_index) is not int:
            raise ValueError("round_index must be a non-bool integer")
        if not 0 <= round_index <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("round_index must fit in an unsigned 64-bit integer")
        if not isinstance(challenge.nonce, bytes):
            raise TypeError("nonce must be bytes")
        if len(challenge.nonce) != NONCE_BYTES:
            raise ValueError(f"nonce must be exactly {NONCE_BYTES} bytes")
        digest = context_digest(context, opening)
        return bound_response(self._key, digest, round_index, challenge.nonce)

    def bit(self, t: bytes, d: bytes, i: int, b: int) -> bytes:
        """Answer one bit challenge as used by :meth:`Verifier.bits`.

        Returns ``r = HMAC-SHA256(key, b"NPFR1" + t + u32be(i) +
        bytes([b]) + d)``: ``t`` must be exactly 16 bytes, ``d`` exactly 32
        bytes, ``i`` a non-bool unsigned 32-bit integer and ``b`` exactly
        ``0`` or ``1`` (a bool is not accepted for either integer). Any
        contract violation raises :class:`ValueError`.
        """
        if not isinstance(t, bytes) or len(t) != BIT_T_BYTES:
            raise ValueError(f"t must be exactly {BIT_T_BYTES} bytes")
        if not isinstance(d, bytes) or len(d) != DIGEST_BYTES:
            raise ValueError(f"d must be exactly {DIGEST_BYTES} bytes")
        if isinstance(i, bool) or type(i) is not int:
            raise ValueError("i must be a non-bool integer")
        if not 0 <= i <= 0xFFFFFFFF:
            raise ValueError("i must fit in an unsigned 32-bit integer")
        if type(b) is not int or b not in (0, 1):
            # ``type`` excludes bools and floats (1.0 == 1 would otherwise
            # satisfy the membership test); only the exact ints 0 and 1.
            raise ValueError("b must be exactly 0 or 1")
        return bit_response(self._key, t, d, i, b)


class Verifier:
    """Measures the round trip of a single challenge/response exchange.

    With ``replay_protection=True`` the verifier tracks the challenges it
    issues and ``verify`` only accepts the exact pending challenge object the
    same instance issued. Challenges are consumed atomically on success and
    may be revoked explicitly with :meth:`revoke`.

    With ``challenge_ttl_seconds`` set (which requires replay protection) each
    challenge is stamped with the verifier's clock at issue time and expires
    at issue time plus the TTL. Expiry is a terminal state: an expired
    challenge can no longer be verified or revoked.
    """

    def __init__(
        self,
        shared_key: bytes,
        *,
        speed_mps: float = SPEED_OF_LIGHT_MPS,
        clock: Callable[[], float] = time.perf_counter,
        replay_protection: bool = False,
        challenge_ttl_seconds: Optional[float] = None,
    ) -> None:
        if not shared_key:
            raise ValueError("shared_key must not be empty")
        if speed_mps <= 0:
            raise ValueError("speed_mps must be positive")
        if challenge_ttl_seconds is not None:
            if isinstance(challenge_ttl_seconds, bool) or not isinstance(
                challenge_ttl_seconds, (int, float)
            ):
                raise ValueError("challenge_ttl_seconds must be a finite positive number")
            ttl = float(challenge_ttl_seconds)
            if not math.isfinite(ttl) or ttl <= 0:
                raise ValueError("challenge_ttl_seconds must be a finite positive number")
            if not replay_protection:
                raise ValueError(
                    "challenge_ttl_seconds requires replay_protection=True"
                )
        self._key = bytes(shared_key)
        self._speed = float(speed_mps)
        self._clock = clock
        self._round = 0
        self._replay_protection = bool(replay_protection)
        self._challenge_ttl: Optional[float] = (
            float(challenge_ttl_seconds) if challenge_ttl_seconds is not None else None
        )
        self._lock = threading.Lock()
        # id(issued challenge) -> [challenge, state, deadline]. Holding the
        # challenge object in the value keeps its id alive (no reuse) and makes
        # the registry bind to the issuing instance and the exact object, not to
        # a collidable round_index. The deadline is ``None`` when no TTL is
        # configured.
        self._challenges: dict[int, list] = {}

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    @property
    def round_count(self) -> int:
        return self._round

    def new_challenge(
        self, *, context: Optional[bytes] = None, digest: Optional[bytes] = None
    ) -> Challenge:
        """Issue a challenge.

        With both ``context`` and ``digest`` left as ``None`` this is the
        original behaviour. A context-bound challenge is requested by passing
        the two together (passing only one raises :class:`ValueError`): each
        must be exactly 32 bytes and bound issuance requires
        ``replay_protection=True`` so the binding is registered with the
        challenge. The issued challenge object is unchanged; the verifier
        remembers the ``(context, digest)`` pair and :meth:`verify` only
        accepts a matching opening for it.
        """
        bound_context, bound_digest = self._check_binding_args(context, digest)
        if bound_context is not None and not self._replay_protection:
            raise ValueError(
                "context-bound challenges require replay_protection=True"
            )
        challenge = Challenge(round_index=self._round + 1, nonce=os.urandom(NONCE_BYTES))
        if self._replay_protection:
            with self._lock:
                self._round += 1
                deadline = None
                if self._challenge_ttl is not None:
                    deadline = self._clock() + self._challenge_ttl
                # Entries always carry the bound context/digest in slots 3/4;
                # both are None for an unbound challenge.
                self._challenges[id(challenge)] = [
                    challenge, _PENDING, deadline, bound_context, bound_digest
                ]
        else:
            self._round += 1
        return challenge

    @staticmethod
    def _check_binding_args(
        context: Optional[bytes], digest: Optional[bytes]
    ) -> tuple[Optional[bytes], Optional[bytes]]:
        """Validate the ``new_challenge`` context/digest keyword pair."""
        if context is None and digest is None:
            return None, None
        if context is None or digest is None:
            raise ValueError("context and digest must be provided together")
        if not isinstance(context, bytes):
            raise TypeError("context must be bytes")
        if not isinstance(digest, bytes):
            raise TypeError("digest must be bytes")
        if len(context) != CONTEXT_BYTES:
            raise ValueError(f"context must be exactly {CONTEXT_BYTES} bytes")
        if len(digest) != DIGEST_BYTES:
            raise ValueError(f"digest must be exactly {DIGEST_BYTES} bytes")
        return context, digest

    def _entry_for(self, challenge: Challenge) -> list | None:
        """Return the registry entry for the exact issued challenge object."""
        entry = self._challenges.get(id(challenge))
        if entry is not None and entry[0] is challenge:
            return entry
        return None

    def revoke(self, challenge: Challenge) -> None:
        """Revoke a pending challenge so it can never be verified.

        Only a challenge issued by this verifier that is still pending and not
        expired can be revoked. Unknown, already consumed, already revoked, or
        expired challenges raise :class:`ChallengeStateError`.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        with self._lock:
            entry = self._entry_for(challenge)
            if entry is None:
                if not self._replay_protection:
                    raise ChallengeStateError(
                        "challenge is not registered because replay protection is disabled"
                    )
                raise ChallengeStateError("challenge was not issued by this verifier")
            state = entry[1]
            if state == _CONSUMED:
                raise ChallengeStateError("challenge has already been verified")
            if state == _REVOKED:
                raise ChallengeStateError("challenge has already been revoked")
            if state == _EXPIRED:
                raise ChallengeStateError("challenge has expired")
            if entry[2] is not None and self._clock() >= entry[2]:
                # Expiry is terminal: record it once so a later clock reading
                # (even a clock rolled backwards) can never revive the
                # challenge.
                entry[1] = _EXPIRED
                raise ChallengeStateError("challenge has expired")
            entry[1] = _REVOKED
            return

    def verify(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        *,
        opening: Optional[bytes] = None,
    ) -> Measurement:
        """Validate the response and turn the elapsed round trip into a distance.

        When replay protection is enabled, ``challenge`` must be the exact
        pending object returned by :meth:`new_challenge` on this instance.
        Failed validation (bad response, negative elapsed time, wrong argument
        types) leaves the challenge pending so the caller can retry; only a
        successful return consumes it, and concurrent attempts can succeed at
        most once.

        When a TTL is configured the clock is read exactly once per call: an
        expired challenge (current time at or past its deadline) raises
        :class:`ChallengeStateError` and can never be verified, even if the
        rest of the response is valid.

        With ``opening=None`` the response is the original keyed response over
        the nonce. Passing ``opening`` selects the context-bound protocol: it
        must be exactly 32 bytes and the challenge must be the exact object
        issued bound to ``(context, digest)`` by :meth:`new_challenge`, with
        ``SHA256(b"NPC1" + context + opening) == digest``; the response must
        then be ``HMAC-SHA256(key, b"NPR1" + digest + u64be(round_index) +
        nonce)`` (as produced by :meth:`Prover.reveal`). A wrong-length opening
        or a digest/opening mismatch raises :class:`ValueError` and leaves the
        challenge pending.
        """
        measurement, _end, _start = self._verify_round(
            challenge, response, started_at, require_finite=False, opening=opening
        )
        return measurement

    def verify_evidence(
        self, challenge: Challenge, response: bytes, started_at: float
    ) -> Evidence:
        """Like :meth:`verify`, but return a MAC'd :class:`Evidence` record.

        Takes the same arguments and applies the same state, TTL and
        validation order; the challenge is consumed atomically on success
        exactly as in :meth:`verify`. In the record, ``start`` is
        ``float(started_at)`` and ``end`` is the single clock reading of the
        call.

        Unlike :meth:`verify`, any non-finite number that would be recorded
        (``started_at``, the clock reading, or the derived elapsed time,
        speed or distance) raises :class:`ValueError` and leaves the
        challenge pending.
        """
        measurement, end, start = self._verify_round(
            challenge, response, started_at, require_finite=True
        )
        payload = {
            "version": 1,
            "round_index": measurement.round_index,
            "nonce": measurement.nonce.hex(),
            "response": measurement.response.hex(),
            "start": start,
            "end": end,
            "speed": self._speed,
            "elapsed": measurement.elapsed_seconds,
            "distance": measurement.distance_meters,
            "result": "accepted",
        }
        return Evidence(
            version=1,
            round_index=measurement.round_index,
            nonce=measurement.nonce,
            response=measurement.response,
            start=start,
            end=end,
            speed=self._speed,
            elapsed=measurement.elapsed_seconds,
            distance=measurement.distance_meters,
            result="accepted",
            mac=_evidence_mac(self._key, payload),
        )

    def verify_bound(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        *,
        opening: bytes,
    ) -> "BoundEvidence":
        """Like :meth:`verify_evidence`, but for a context-bound challenge and
        returning a :class:`BoundEvidence` record.

        Only a challenge issued bound to ``(context, digest)`` by
        :meth:`new_challenge` can be verified this way; an unbound challenge
        (or a verifier without replay protection, where no binding can be
        registered) raises :class:`ValueError`. ``opening`` is keyword-only
        and required: a non-bytes opening (``None`` included) raises
        :class:`TypeError`, a wrong length or a commitment mismatch raises
        :class:`ValueError`. State, TTL and atomic-consumption semantics are
        exactly those of :meth:`verify_evidence`, including the validation
        order — state and expiry first, then ranging, then binding and
        response — so an unknown, consumed, revoked or expired challenge
        raises :class:`ChallengeStateError` even when the opening is
        malformed, and any failure leaves the challenge pending. Any
        non-finite recorded number raises :class:`ValueError` without
        consuming the challenge.

        The returned record embeds the round's :class:`Evidence` (MAC'd with
        the shared key exactly as :meth:`verify_evidence` produces), the
        registered ``context``/``digest`` pair and the revealed ``opening``,
        and is itself MAC'd: ``mac = HMAC-SHA256(key, b"NPBE1" + encoding)``
        over the canonical encoding of every field except ``mac`` itself.
        """
        measurement, end, start = self._verify_round(
            challenge, response, started_at, require_finite=True,
            opening=opening, opening_required=True,
        )
        entry = self._entry_for(challenge)
        # A successful bound round implies replay protection is on and the
        # challenge was issued bound, so the registry entry and its binding
        # are still there after the atomic consumption.
        bound_context, bound_digest = entry[3], entry[4]
        payload = {
            "version": 1,
            "round_index": measurement.round_index,
            "nonce": measurement.nonce.hex(),
            "response": measurement.response.hex(),
            "start": start,
            "end": end,
            "speed": self._speed,
            "elapsed": measurement.elapsed_seconds,
            "distance": measurement.distance_meters,
            "result": "accepted",
        }
        evidence = Evidence(
            version=1,
            round_index=measurement.round_index,
            nonce=measurement.nonce,
            response=measurement.response,
            start=start,
            end=end,
            speed=self._speed,
            elapsed=measurement.elapsed_seconds,
            distance=measurement.distance_meters,
            result="accepted",
            mac=_evidence_mac(self._key, payload),
        )
        record = BoundEvidence(
            version=1,
            evidence=evidence,
            context=bound_context,
            digest=bound_digest,
            opening=opening,
            mac=b"\x00" * 32,
        )
        return replace(
            record, mac=_bound_evidence_mac(self._key, _bound_evidence_payload(record))
        )

    def _verify_round(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        *,
        require_finite: bool,
        opening: Optional[bytes] = None,
        opening_required: bool = False,
    ) -> tuple[Measurement, float, float]:
        """Shared core of :meth:`verify` and :meth:`verify_evidence`.

        Returns ``(measurement, end, start)`` where ``end`` is the single
        clock reading of the call and ``start`` is ``float(started_at)``.
        With ``require_finite`` every recorded number is checked for
        finiteness before anything is consumed. ``opening`` selects the
        context-bound response protocol (``None`` is the legacy protocol).
        With ``opening_required`` (used by :meth:`verify_bound`, which only
        runs the context-bound protocol) a ``None`` opening is a shape error
        raising :class:`TypeError` — but only after the challenge state and
        TTL checks, so a malformed opening never masks them.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        if not self._replay_protection:
            if opening_required and opening is None:
                # Without a registry there are no state or TTL checks, so the
                # shape error surfaces immediately.
                raise TypeError("opening must be bytes")
            return self._verify_legacy(
                challenge, response, started_at, require_finite, opening
            )

        with self._lock:
            entry = self._entry_for(challenge)
            if entry is None:
                raise ChallengeStateError("challenge was not issued by this verifier")
            state = entry[1]
            if state == _CONSUMED:
                raise ChallengeStateError("challenge has already been verified")
            if state == _REVOKED:
                raise ChallengeStateError("challenge has been revoked")
            if state == _EXPIRED:
                raise ChallengeStateError("challenge has expired")

            # State, expiry and consumption are all decided under the same
            # lock, with the clock read at most once, so a challenge can
            # succeed at most once before its deadline and never at/after it.
            now = self._clock()
            if entry[2] is not None and now >= entry[2]:
                # Terminal: pin the state so nothing can revive the challenge.
                entry[1] = _EXPIRED
                raise ChallengeStateError("challenge has expired")

            # All validations run while holding the lock so a failure leaves
            # the challenge pending and the pending -> consumed transition is
            # atomic across concurrent calls.
            start = float(started_at)
            elapsed = now - start
            distance = elapsed * self._speed / 2.0
            if require_finite:
                _require_finite(start, now, elapsed, self._speed, distance)
            if elapsed < 0:
                raise ValueError("elapsed time must not be negative")
            # Opening/binding validation is part of response validation, so
            # it runs after state, expiry and ranging checks and leaves the
            # challenge pending on failure.
            if opening_required and opening is None:
                # verify_bound only runs the context-bound protocol; None is
                # a shape error there, raised only here so state, expiry and
                # ranging failures take precedence over it.
                raise TypeError("opening must be bytes")
            expected = self._expected_response(
                challenge, entry[3], entry[4], opening
            )
            response_bytes = bytes(response)
            if not hmac.compare_digest(expected, response_bytes):
                raise ValueError("response does not match the challenge")
            entry[1] = _CONSUMED

        measurement = Measurement(
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=response_bytes,
            elapsed_seconds=elapsed,
            distance_meters=distance,
        )
        return measurement, now, start

    def _expected_response(
        self,
        challenge: Challenge,
        bound_context: Optional[bytes],
        bound_digest: Optional[bytes],
        opening: Optional[bytes],
    ) -> bytes:
        """The response bytes expected for a round under the selected protocol.

        ``bound_context``/``bound_digest`` are the binding registered with the
        challenge (both ``None`` when it is unbound or, in legacy mode, when no
        registry exists). ``opening=None`` selects the nonce-only response; an
        opening that is not 32-byte ``bytes`` raises :class:`TypeError` for the
        shape error and :class:`ValueError` for every other mismatch.
        """
        if opening is None:
            if bound_context is None:
                return keyed_response(self._key, challenge.nonce)
            # The challenge was issued bound to a context, so it can only be
            # answered by revealing the matching opening; the legacy nonce
            # response (and the absence of an opening) never satisfies it.
            raise ValueError(
                "challenge was issued with a context binding; an opening is"
                " required"
            )
        if not isinstance(opening, bytes):
            raise TypeError("opening must be bytes")
        if len(opening) != OPENING_BYTES:
            raise ValueError(f"opening must be exactly {OPENING_BYTES} bytes")
        if bound_context is None:
            raise ValueError(
                "challenge was not issued with a context binding"
            )
        if not hmac.compare_digest(
            context_digest(bound_context, opening), bound_digest
        ):
            raise ValueError("opening does not match the challenge context binding")
        return bound_response(
            self._key, bound_digest, challenge.round_index, challenge.nonce
        )

    def _verify_legacy(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        require_finite: bool = False,
        opening: Optional[bytes] = None,
    ) -> tuple[Measurement, float, float]:
        """Original single-round behaviour, unchanged when protection is off."""
        end = self._clock()
        start = float(started_at)
        elapsed = end - start
        distance = elapsed * self._speed / 2.0
        if require_finite:
            _require_finite(start, end, elapsed, self._speed, distance)
        if elapsed < 0:
            raise ValueError("elapsed time must not be negative")
        # Without a registry no binding can exist, so reveal-style verification
        # can never match here; opening=None keeps the original behaviour.
        expected = self._expected_response(challenge, None, None, opening)
        response_bytes = bytes(response)
        if not hmac.compare_digest(expected, response_bytes):
            raise ValueError("response does not match the challenge")
        # The signal travels to the prover and back, so halve the round trip.
        measurement = Measurement(
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=response_bytes,
            elapsed_seconds=elapsed,
            distance_meters=distance,
        )
        return measurement, end, start

    def measure(self, prover: Prover) -> Measurement:
        """Run one complete round against ``prover``."""
        challenge = self.new_challenge()
        started_at = self._clock()
        response = prover.respond(challenge)
        return self.verify(challenge, response, started_at)

    def bits(
        self,
        prover: object,
        context: object,
        opening: object,
        *,
        rounds: object = 32,
        timeout: object = 0.001,
    ) -> bytes:
        """Run a bit-challenge session and return MAC'd :class:`BitEvidence`.

        For each of ``rounds`` rounds the verifier draws a random challenge
        bit, reads the clock (``s``), calls ``prover.bit(t, D, i, b)`` and
        reads the clock again (``e``), then verifies the returned ``r`` in
        constant time against
        ``HMAC-SHA256(key, b"NPFR1" + t + u32be(i) + bytes([b]) + D)`` with
        ``i`` equal to the round index. ``t`` is a fresh random 16-byte
        transcript and ``D = SHA256(b"NPFC1" + context + opening)``;
        ``context`` and ``opening`` must each be exactly 32 bytes.

        Every round must satisfy ``0 <= e - s <= float(timeout)``; the
        session's distance bound is ``L = max(e - s) * V / 2`` for the
        verifier's propagation speed ``V``. The returned bytes are the
        canonical :meth:`BitEvidence.to_bytes` encoding of
        ``[1, t, C, D, O, Q, V, T, L, M]`` with
        ``M = HMAC-SHA256(key, b"NPFB1" + E)`` over the same array without
        ``M``.

        ``rounds`` must be a non-bool integer in ``1 .. 2**32`` and
        ``timeout`` a finite positive non-bool number. Every contract
        violation — including a prover ``bit`` that is not callable or
        returns anything other than the correct 32 bytes — raises
        :class:`ValueError`.
        """
        rounds, limit_time = _validate_bit_session_args(
            context, opening, rounds, timeout
        )
        if not math.isfinite(self._speed):
            raise ValueError("speed_mps must be finite to record bit evidence")
        answer = getattr(prover, "bit", None)
        if not callable(answer):
            raise ValueError("prover must provide a callable bit(t, d, i, b)")

        transcript = os.urandom(BIT_T_BYTES)
        digest = bit_transcript_digest(context, opening)
        queries: list[tuple[int, bytes, float, float]] = []
        durations: list[float] = []
        for index in range(rounds):
            bit_value = os.urandom(1)[0] & 1
            start = self._clock()
            try:
                response = answer(transcript, digest, index, bit_value)
            except TypeError as error:
                # The prover interface is bit(t, d, i, b); a callable that
                # cannot be invoked with those four arguments violates the
                # entry contract like any other malformed prover.
                raise ValueError("prover bit must be callable as bit(t, d, i, b)") from error
            end = self._clock()
            for label, reading in (("s", start), ("e", end)):
                if isinstance(reading, bool) or not isinstance(
                    reading, (int, float)
                ):
                    raise ValueError("clock readings must be finite numbers")
            if not isinstance(response, bytes) or len(response) != BIT_R_BYTES:
                raise ValueError("prover bit response must be exactly 32 bytes")
            expected = bit_response(
                self._key, transcript, digest, index, bit_value
            )
            if not hmac.compare_digest(expected, response):
                raise ValueError("prover bit response does not match the challenge")
            start_f = float(start)
            end_f = float(end)
            if not math.isfinite(start_f) or not math.isfinite(end_f):
                raise ValueError("clock readings must be finite numbers")
            duration = end_f - start_f
            if not 0.0 <= duration <= limit_time:
                raise ValueError("bit round trip must satisfy 0 <= e - s <= timeout")
            queries.append((bit_value, response, start_f, end_f))
            durations.append(duration)
        bound = max(durations) * self._speed / 2.0
        if not math.isfinite(bound) or bound < 0:
            raise ValueError("computed distance bound must be finite and non-negative")

        record = BitEvidence(
            version=1,
            t=transcript,
            context=context,
            digest=digest,
            opening=opening,
            queries=tuple(queries),
            speed=self._speed,
            timeout=limit_time,
            limit=bound,
            mac=b"\x00" * 32,
        )
        return replace(
            record, mac=_bit_evidence_mac(self._key, _bit_evidence_payload(record))
        ).to_bytes()

    def start_bits(
        self,
        context: object,
        opening: object,
        *,
        rounds: object = 32,
        timeout: object = 0.001,
    ) -> "BitSession":
        """Start a step-driven bit-challenge session and return it.

        Same argument contract as :meth:`bits`: ``context`` and ``opening``
        must each be exactly 32 bytes, ``rounds`` a non-bool integer in
        ``1 .. 2**32`` and ``timeout`` a finite positive non-bool number;
        every violation raises :class:`ValueError`. The returned
        :class:`BitSession` draws a fresh random 16-byte transcript ``t``
        and is then driven round by round from the outside: each
        :meth:`BitSession.next` issues one :class:`BitRound`, each
        :meth:`BitSession.submit` checks the response transported back, and
        :meth:`BitSession.finish` produces the same canonical
        :class:`BitEvidence` bytes :meth:`bits` returns.
        """
        rounds, limit_time = _validate_bit_session_args(
            context, opening, rounds, timeout
        )
        if not math.isfinite(self._speed):
            raise ValueError("speed_mps must be finite to record bit evidence")
        return BitSession(
            self._key,
            self._clock,
            self._speed,
            context,
            opening,
            rounds,
            limit_time,
        )

    def resume_bits(
        self, x: object, *, floor: object = None
    ) -> "BitSession":
        """Resume a step-driven bit session from a :class:`BitState`.

        ``x`` must be a :class:`BitState` or its canonical
        :meth:`BitState.to_bytes` encoding — any other type raises
        :class:`TypeError`, as does a ``floor`` that is neither ``None`` nor
        one of those. After the checkpoint MAC
        ``HMAC-SHA256(key, b"NPBS1" + E)`` is verified in constant time, the
        carried session is recovered from scratch and every value is
        recomputed: ``D = SHA256(b"NPFC1" + C + O)``, every recorded
        response against
        ``HMAC-SHA256(key, b"NPFR1" + t + u32be(i) + bytes([b]) + D)`` at
        its query index, and the closed interval ``0 <= e - s <= T``; a
        carried pending round ``P`` must describe exactly the next index
        (``len(Q)``). Every mismatch raises :class:`ValueError`.

        ``floor`` is the caller's previously accepted checkpoint, if any:
        a lower ``seq`` is rejected as a rollback; an equal ``seq`` is
        accepted solely as a replay of the identical body (compared as
        ``SHA256(body)``); a higher ``seq`` must carry the same first seven
        body fields (``t, C, D, O, R, T, V``), its ``Q`` must extend the
        floor's ``Q`` item for item as a prefix, and when the floor carried
        a pending round ``P`` the very next ``Q`` item must continue it with
        the same challenge bit and start reading ``(b, s)``. The restored
        :class:`BitSession` is active, uses this verifier's clock and the
        checkpoint's own ``V``/``T``, and can be driven with
        :meth:`BitSession.next`/:meth:`submit`/:meth:`finish` exactly like a
        fresh session.
        """
        def coerced(value: object, name: str) -> "BitState":
            if isinstance(value, BitState):
                return value
            if isinstance(value, bytes):
                try:
                    return BitState.from_bytes(value)
                except TypeError as error:
                    # The argument had the right kind; a field-shape failure
                    # surfacing while parsing its byte content is a value
                    # error, exactly as in audit_proof.
                    raise ValueError(
                        f"{name} does not satisfy the bit state field"
                        " contract"
                    ) from error
            raise TypeError(
                f"{name} must be a BitState instance or its canonical bytes"
            )

        state = coerced(x, "x")
        floor_state = None if floor is None else coerced(floor, "floor")
        recovered = self._recover_bit_state(state)
        if floor_state is not None:
            floor_recovered = self._recover_bit_state(floor_state)
            self._gate_bit_state_floor(state, recovered, floor_state, floor_recovered)
        (
            transcript,
            context,
            digest,
            opening,
            rounds,
            timeout,
            speed,
            queries,
            previous,
        ) = recovered
        return BitSession._restore(
            self._key,
            self._clock,
            speed,
            context,
            opening,
            rounds,
            timeout,
            transcript,
            digest,
            queries,
            previous,
        )

    def _recover_bit_state(
        self, state: "BitState"
    ) -> "tuple[bytes, bytes, bytes, bytes, int, float, float, tuple, Optional[tuple]]":
        """Verify one checkpoint's MAC and recompute every carried value."""
        if not hmac.compare_digest(
            _bit_state_mac(self._key, state.seq, state.body), state.mac
        ):
            raise ValueError("bit state mac does not match the key")
        (
            transcript,
            context,
            digest,
            opening,
            rounds,
            timeout,
            speed,
            queries,
            previous,
        ) = _parse_bit_state_body(state.body)
        if not hmac.compare_digest(
            bit_transcript_digest(context, opening), digest
        ):
            raise ValueError(
                "bit state digest does not match context and opening"
            )
        for index, (bit_value, response, start, end) in enumerate(queries):
            if not hmac.compare_digest(
                bit_response(
                    self._key, transcript, digest, index, bit_value
                ),
                response,
            ):
                raise ValueError(
                    "bit state response does not match the challenge"
                )
            if not 0.0 <= end - start <= timeout:
                raise ValueError(
                    "bit state round trip must satisfy 0 <= e - s <= timeout"
                )
        return (
            transcript,
            context,
            digest,
            opening,
            rounds,
            timeout,
            speed,
            queries,
            previous,
        )

    @staticmethod
    def _gate_bit_state_floor(
        state: "BitState",
        recovered: tuple,
        floor_state: "BitState",
        floor_recovered: tuple,
    ) -> None:
        """Enforce monotone, prefix-extending progress over a floor state."""
        if state.seq < floor_state.seq:
            raise ValueError(
                "bit state seq is below the floor checkpoint"
            )
        if state.seq == floor_state.seq:
            if not hmac.compare_digest(
                hashlib.sha256(state.body).digest(),
                hashlib.sha256(floor_state.body).digest(),
            ):
                raise ValueError(
                    "bit state carries a different body at the floor seq"
                )
            return
        # Higher seq: the fixed session parameters must be identical...
        (
            t,
            context,
            digest,
            opening,
            rounds,
            timeout,
            speed,
            queries,
            _previous,
        ) = recovered
        (
            floor_t,
            floor_context,
            floor_digest,
            floor_opening,
            floor_rounds,
            floor_timeout,
            floor_speed,
            floor_queries,
            floor_previous,
        ) = floor_recovered
        if (
            t,
            context,
            digest,
            opening,
            rounds,
            timeout,
            speed,
        ) != (
            floor_t,
            floor_context,
            floor_digest,
            floor_opening,
            floor_rounds,
            floor_timeout,
            floor_speed,
        ):
            raise ValueError(
                "bit state session parameters must extend the floor"
                " checkpoint"
            )
        prefix = floor_state.seq
        if queries[:prefix] != floor_queries:
            raise ValueError(
                "bit state Q must extend the floor Q as a prefix"
            )
        if floor_previous is not None:
            # The floor's outstanding round has since been completed: the
            # first new Q item must answer that same (b, s) challenge.
            if prefix >= len(queries):
                raise ValueError(
                    "bit state must complete the floor checkpoint's pending"
                    " round"
                )
            _pending_index, pending_bit, pending_start = floor_previous
            next_bit, _next_response, next_start, _next_end = queries[prefix]
            if (next_bit, next_start) != (pending_bit, pending_start):
                raise ValueError(
                    "bit state next Q item must continue the floor pending"
                    " round's b and s"
                )


class BitSession:
    """One step-driven bit-challenge session created by :meth:`Verifier.start_bits`.

    The session draws its random 16-byte transcript ``t`` at creation and
    fixes ``D = SHA256(b"NPFC1" + context + opening)``. At most one round is
    pending at any time: :meth:`next` draws a random challenge bit and reads
    the clock once (``s``); :meth:`submit` reads the clock once (``e``),
    verifies the response in constant time against
    ``HMAC-SHA256(key, b"NPFR1" + t + u32be(i) + bytes([b]) + D)`` and
    requires ``0 <= e - s <= timeout``. Successful rounds enter ``Q`` in
    order; once every round has succeeded, :meth:`finish` returns the
    canonical :meth:`BitEvidence.to_bytes` encoding (exactly as
    :meth:`Verifier.bits` produces). :meth:`revoke` abandons the session.

    ``t``, ``index`` and ``bit`` bind a :class:`BitRound` to its session and
    position: a round from another session, an out-of-order or duplicate
    round, and any call after the session has terminated (finished or
    revoked) raise :class:`ValueError`. State advances atomically under a
    lock, so concurrent submissions succeed at most once; a failed
    submission does not advance the session and may be retried while the
    round is still within its timeout. A shape violation (an argument of
    the wrong type) raises :class:`TypeError`; every other contract
    violation raises :class:`ValueError`.
    """

    _ACTIVE = "active"
    _FINISHED = "finished"
    _REVOKED = "revoked"

    def __init__(
        self,
        key: bytes,
        clock: Callable[[], float],
        speed: float,
        context: bytes,
        opening: bytes,
        rounds: int,
        timeout: float,
    ) -> None:
        self._key = key
        self._clock = clock
        self._speed = speed
        self._context = context
        self._opening = opening
        self._rounds = rounds
        self._timeout = timeout
        self._t = os.urandom(BIT_T_BYTES)
        self._digest = bit_transcript_digest(context, opening)
        self._queries: list[tuple[int, bytes, float, float]] = []
        self._durations: list[float] = []
        # The pending (round, s) pair, or None when no round is outstanding.
        self._pending: Optional[tuple[BitRound, float]] = None
        self._state = self._ACTIVE
        self._lock = threading.Lock()

    @classmethod
    def _restore(
        cls,
        key: bytes,
        clock: Callable[[], float],
        speed: float,
        context: bytes,
        opening: bytes,
        rounds: int,
        timeout: float,
        transcript: bytes,
        digest: bytes,
        queries: "tuple[tuple[int, bytes, float, float], ...]",
        previous: "Optional[tuple[int, int, float]]",
    ) -> "BitSession":
        """Rebuild an active session from a recovered :class:`BitState`.

        All fields arrive already parsed and cryptographically recovered by
        :meth:`Verifier.resume_bits`; the constructor bypasses the random
        transcript draw and recomputes nothing beyond the per-query
        durations. A carried ``previous`` pending round becomes the
        outstanding :class:`BitRound`, equal by field to the one originally
        issued.
        """
        session = cls.__new__(cls)
        session._key = key
        session._clock = clock
        session._speed = speed
        session._context = context
        session._opening = opening
        session._rounds = rounds
        session._timeout = timeout
        session._t = transcript
        session._digest = digest
        session._queries = list(queries)
        session._durations = [end - start for _b, _r, start, end in queries]
        if previous is None:
            session._pending = None
        else:
            pending_index, pending_bit, pending_start = previous
            session._pending = (
                BitRound(
                    version=1,
                    t=transcript,
                    index=pending_index,
                    bit=pending_bit,
                ),
                pending_start,
            )
        session._state = cls._ACTIVE
        session._lock = threading.Lock()
        return session

    @property
    def t(self) -> bytes:
        """The session's random 16-byte transcript."""
        return self._t

    def _require_active(self) -> None:
        if self._state == self._FINISHED:
            raise ValueError("bit session has already been finished")
        if self._state == self._REVOKED:
            raise ValueError("bit session has been revoked")

    @staticmethod
    def _read_clock(reading: object) -> float:
        if isinstance(reading, bool) or not isinstance(reading, (int, float)):
            raise ValueError("clock readings must be finite numbers")
        value = float(reading)
        if not math.isfinite(value):
            raise ValueError("clock readings must be finite numbers")
        return value

    def next(self) -> BitRound:
        """Issue the next bit challenge of the session.

        Draws a random challenge bit, reads the clock once (``s``) and
        returns the :class:`BitRound` binding ``t``, the round index and the
        bit. Only one round may be pending: calling :meth:`next` again
        before :meth:`submit` consumes the pending round raises
        :class:`ValueError`, as does calling it once every round has been
        issued or after the session has terminated.
        """
        with self._lock:
            self._require_active()
            if self._pending is not None:
                raise ValueError("a bit round is already pending")
            index = len(self._queries)
            if index >= self._rounds:
                raise ValueError("all bit rounds have already been issued")
            bit_value = os.urandom(1)[0] & 1
            start = self._read_clock(self._clock())
            bit_round = BitRound(version=1, t=self._t, index=index, bit=bit_value)
            self._pending = (bit_round, start)
            return bit_round

    def submit(self, round: object, response: object) -> None:
        """Check the response to the pending round and advance the session.

        ``round`` must be the exact :class:`BitRound` (by field equality)
        most recently issued by :meth:`next` on this session and
        ``response`` the 32 bytes the prover returned for it. The clock is
        read once (``e``); the response is compared in constant time against
        ``HMAC-SHA256(key, b"NPFR1" + t + u32be(i) + bytes([b]) + D)`` and
        the round trip must satisfy ``0 <= e - s <= timeout``. On success
        the round is recorded in ``Q`` and the session advances; on any
        failure the pending round is kept so the caller can retry while it
        is still within its timeout. A ``round`` that is not a
        :class:`BitRound` or a non-bytes ``response`` raises
        :class:`TypeError`; every other violation — a round from another
        session, an out-of-order or duplicate round, a call with no round
        pending or after termination, a malformed or mismatching response
        and an out-of-bounds round trip — raises :class:`ValueError`.
        """
        if not isinstance(round, BitRound):
            raise TypeError("round must be a BitRound")
        if not isinstance(response, bytes):
            raise TypeError("response must be bytes")
        with self._lock:
            self._require_active()
            pending = self._pending
            if pending is None:
                raise ValueError("no bit round is pending")
            expected_round, start = pending
            if round != expected_round:
                raise ValueError("round does not match the pending bit round")
            end = self._read_clock(self._clock())
            if len(response) != BIT_R_BYTES:
                raise ValueError("bit response must be exactly 32 bytes")
            expected = bit_response(
                self._key, self._t, self._digest, expected_round.index,
                expected_round.bit,
            )
            if not hmac.compare_digest(expected, response):
                raise ValueError("bit response does not match the challenge")
            duration = end - start
            if not 0.0 <= duration <= self._timeout:
                raise ValueError(
                    "bit round trip must satisfy 0 <= e - s <= timeout"
                )
            # The pending -> recorded transition is atomic under the lock,
            # so concurrent submissions can succeed at most once.
            self._queries.append((expected_round.bit, response, start, end))
            self._durations.append(duration)
            self._pending = None

    def finish(self) -> bytes:
        """Close the session and return the MAC'd :class:`BitEvidence` bytes.

        Only a session whose every round has succeeded (none pending, none
        missing) can be finished; anything else raises :class:`ValueError`.
        The distance bound is ``L = max(e - s) * V / 2`` and the returned
        bytes are the canonical :meth:`BitEvidence.to_bytes` encoding of
        ``[1, t, C, D, O, Q, V, T, L, M]`` with
        ``M = HMAC-SHA256(key, b"NPFB1" + E)`` over the same array without
        ``M`` — exactly the record :meth:`Verifier.bits` returns. Finishing
        is terminal: every later call on the session raises
        :class:`ValueError`.
        """
        with self._lock:
            self._require_active()
            if self._pending is not None:
                raise ValueError("a bit round is still pending")
            if len(self._queries) != self._rounds:
                raise ValueError("not all bit rounds have succeeded")
            bound = max(self._durations) * self._speed / 2.0
            if not math.isfinite(bound) or bound < 0:
                raise ValueError(
                    "computed distance bound must be finite and non-negative"
                )
            record = BitEvidence(
                version=1,
                t=self._t,
                context=self._context,
                digest=self._digest,
                opening=self._opening,
                queries=tuple(self._queries),
                speed=self._speed,
                timeout=self._timeout,
                limit=bound,
                mac=b"\x00" * 32,
            )
            blob = replace(
                record,
                mac=_bit_evidence_mac(self._key, _bit_evidence_payload(record)),
            ).to_bytes()
            self._state = self._FINISHED
            return blob

    def checkpoint(self) -> bytes:
        """Serialize the active session as a MAC'd :class:`BitState`.

        Produces the canonical :meth:`BitState.to_bytes` encoding of a
        checkpoint carrying every completed query in ``Q`` (``seq`` is their
        count) and, while a round is outstanding, ``P = [seq, b, s]`` for
        that pending round; ``P`` is ``null`` when no round is pending. The
        checkpoint MAC is
        ``HMAC-SHA256(key, b"NPBS1" + E)`` over the outer array without its
        MAC. The session is left untouched and stays active, so it can keep
        making progress and be checkpointed again; the bytes are passed to
        :meth:`Verifier.resume_bits` to continue on another verifier using
        the same key. Only an active session can be checkpointed — calling
        this on a finished or revoked session raises :class:`ValueError`.
        """
        with self._lock:
            self._require_active()
            previous: "Optional[tuple[int, int, float]]" = None
            if self._pending is not None:
                pending_round, pending_start = self._pending
                # A pending round is always the next index, i.e. one per
                # completed query.
                previous = (
                    pending_round.index,
                    pending_round.bit,
                    pending_start,
                )
            queries = tuple(self._queries)
            body = _bit_state_body_bytes(
                self._t,
                self._context,
                self._digest,
                self._opening,
                self._rounds,
                self._timeout,
                self._speed,
                queries,
                previous,
            )
            seq = len(self._queries)
            return BitState(
                version=1,
                seq=seq,
                body=body,
                mac=_bit_state_mac(self._key, seq, body),
            ).to_bytes()

    def revoke(self) -> None:
        """Abandon the session so no further round can be issued or accepted.

        Only an active session can be revoked; revoking a finished or
        already revoked session raises :class:`ValueError`. Revocation is
        terminal: every later call on the session raises :class:`ValueError`.
        """
        with self._lock:
            self._require_active()
            self._state = self._REVOKED


def _bit_evidence_payload(record: "BitEvidence") -> list:
    """The JSON-ready bit-evidence array ``E``: ``A`` without its MAC ``M``.

    Each query is encoded as ``[b, r, s, e]`` with ``r`` a lowercase hex
    string and the clock readings JSON numbers.
    """
    return [
        record.version,
        record.t.hex(),
        record.context.hex(),
        record.digest.hex(),
        record.opening.hex(),
        [[b, r.hex(), s, e] for b, r, s, e in record.queries],
        record.speed,
        record.timeout,
        record.limit,
    ]


def _bit_evidence_mac(key: bytes, payload: list) -> bytes:
    """``HMAC-SHA256(key, b"NPFB1" + E)`` over the canonical array ``E``."""
    return hmac.new(
        key, _BIT_EVIDENCE_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


@dataclass(frozen=True)
class BitEvidence:
    """A tamper-evident record of one accepted :meth:`Verifier.bits` session.

    The canonical encoding is a compact UTF-8 JSON array in field order::

        [1, t, C, D, O, Q, V, T, L, M]

    ``version`` is always ``1``; ``t`` is 16 bytes; ``context`` (``C``),
    ``opening`` (``O``), ``digest`` (``D``) and ``mac`` (``M``) are each
    exactly 32 bytes with
    ``D = SHA256(b"NPFC1" + C + O)``; ``Q`` is a tuple of
    ``(b, r, s, e)`` query records (challenge bit, 32-byte response and the
    two clock readings) whose round index is their tuple position;
    ``V``/``T``/``L`` are finite non-bool floats (the speed, the timeout and
    ``L = max(e - s) * V / 2``, always non-negative). ``M`` is
    ``HMAC-SHA256(key, b"NPFB1" + E)`` over the same array without ``M``.
    Any contract violation raises :class:`ValueError` at construction time.
    No key material is stored.
    """

    version: int
    t: bytes
    context: bytes
    digest: bytes
    opening: bytes
    queries: tuple
    speed: float
    timeout: float
    limit: float
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("bit evidence version must be 1")
        if not isinstance(self.t, bytes) or len(self.t) != BIT_T_BYTES:
            raise ValueError(f"bit evidence t must be exactly {BIT_T_BYTES} bytes")
        for name in ("context", "opening", "digest", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"bit evidence {name} must be exactly 32 bytes")
        if not isinstance(self.queries, tuple) or not self.queries:
            raise ValueError("bit evidence queries must be a non-empty tuple")
        for position, query in enumerate(self.queries):
            if not isinstance(query, tuple) or len(query) != 4:
                raise ValueError(
                    "bit evidence each query must be a (b, r, s, e) tuple"
                )
            bit_value, response, start, end = query
            if type(bit_value) is not int or bit_value not in (0, 1):
                raise ValueError("bit evidence challenge bits must be 0 or 1")
            if not isinstance(response, bytes) or len(response) != BIT_R_BYTES:
                raise ValueError("bit evidence response must be exactly 32 bytes")
            for label, reading in (("s", start), ("e", end)):
                if isinstance(reading, bool) or not isinstance(
                    reading, (int, float)
                ) or not math.isfinite(reading):
                    raise ValueError(
                        f"bit evidence clock reading {label} must be a finite"
                        " non-bool number"
                    )
        for name in ("speed", "timeout", "limit"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"bit evidence {name} must be a finite number")
            if not math.isfinite(value):
                raise ValueError(f"bit evidence {name} must be a finite number")
        if self.timeout <= 0:
            raise ValueError("bit evidence timeout must be positive")
        if self.limit < 0:
            raise ValueError("bit evidence limit must be non-negative")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the array
        ``[1, t, C, D, O, Q, V, T, L, M]``, byte fields as lowercase hex,
        no whitespace, no NaN/Infinity."""
        payload = _bit_evidence_payload(self)
        payload.append(self.mac.hex())
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitEvidence":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: an array of exactly ten elements in field
        order, ``version == 1``, lowercase hex for the byte fields (``t``
        decoding to 16 bytes, the other four to 32 each), a non-empty array
        of ``[b, r, s, e]`` queries with ``b`` in ``{0, 1}``, ``r`` a
        32-byte lowercase hex string and ``s``/``e`` finite non-bool
        numbers, and finite non-bool numbers for ``V``/``T``/``L`` with a
        positive ``T`` and non-negative ``L``. After parsing and validation
        the record is re-encoded and the result must equal the input byte
        for byte. The MAC is not verified here — use :func:`audit_b` with
        the shared key for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("bit evidence data must be bytes")
        try:
            decoded = json.loads(data)
        except ValueError as error:
            raise ValueError(f"bit evidence is not valid JSON: {error}") from error
        record = _parse_bit_evidence(decoded)
        if record.to_bytes() != data:
            raise ValueError("bit evidence encoding is not canonical")
        return record


def _parse_bit_evidence_hex(value: object, name: str, length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"bit evidence {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"bit evidence {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value or len(raw) != length:
        raise ValueError(
            f"bit evidence {name} must be a lowercase hex string of exactly"
            f" {length} bytes"
        )
    return raw


def _parse_bit_evidence_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"bit evidence {name} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"bit evidence {name} must be a finite number")
    return number


def _parse_bit_evidence(decoded: object) -> "BitEvidence":
    if not isinstance(decoded, list) or len(decoded) != 10:
        raise ValueError(
            "bit evidence must be a JSON array of exactly version, t, C, D,"
            " O, Q, V, T, L and M"
        )
    (
        raw_version,
        raw_t,
        raw_context,
        raw_digest,
        raw_opening,
        raw_queries,
        raw_speed,
        raw_timeout,
        raw_limit,
        raw_mac,
    ) = decoded
    version = _parse_int_field(raw_version, "version")
    if version != 1:
        raise ValueError("bit evidence version must be 1")
    t = _parse_bit_evidence_hex(raw_t, "t", BIT_T_BYTES)
    context = _parse_bit_evidence_hex(raw_context, "C", CONTEXT_BYTES)
    digest = _parse_bit_evidence_hex(raw_digest, "D", DIGEST_BYTES)
    opening = _parse_bit_evidence_hex(raw_opening, "O", OPENING_BYTES)
    mac = _parse_bit_evidence_hex(raw_mac, "M", 32)
    if not isinstance(raw_queries, list) or not raw_queries:
        raise ValueError("bit evidence Q must be a non-empty array")
    queries: list[tuple[int, bytes, float, float]] = []
    for raw_query in raw_queries:
        if not isinstance(raw_query, list) or len(raw_query) != 4:
            raise ValueError(
                "bit evidence each query must be an array of exactly b, r, s"
                " and e"
            )
        raw_bit, raw_response, raw_start, raw_end = raw_query
        # JSON booleans must be distinguished from the integer challenge bit
        # 0/1; true/false are shape violations here.
        if isinstance(raw_bit, bool) or type(raw_bit) is not int:
            raise ValueError("bit evidence b must be 0 or 1")
        if raw_bit not in (0, 1):
            raise ValueError("bit evidence b must be 0 or 1")
        response = _parse_bit_evidence_hex(raw_response, "r", BIT_R_BYTES)
        start = _parse_bit_evidence_number(raw_start, "s")
        end = _parse_bit_evidence_number(raw_end, "e")
        queries.append((raw_bit, response, start, end))
    speed = _parse_bit_evidence_number(raw_speed, "V")
    timeout = _parse_bit_evidence_number(raw_timeout, "T")
    limit = _parse_bit_evidence_number(raw_limit, "L")
    return BitEvidence(
        version=version,
        t=t,
        context=context,
        digest=digest,
        opening=opening,
        queries=tuple(queries),
        speed=speed,
        timeout=timeout,
        limit=limit,
        mac=mac,
    )


def audit_b(x: object, k: object) -> float:
    """Re-verify a :class:`BitEvidence` byte record against the shared key.

    ``x`` is the canonical :meth:`BitEvidence.to_bytes` encoding and ``k``
    the shared key; both must be non-empty ``bytes`` and nothing else — a
    :class:`BitEvidence` instance, ``bytearray``, ``str`` or empty value
    all raise :class:`ValueError`, as does every other contract violation.
    Every cryptographic and ranging check is recomputed from scratch and
    compared in constant time:

    - the MAC: ``M == HMAC-SHA256(k, b"NPFB1" + E)``;
    - the transcript digest: ``D == SHA256(b"NPFC1" + C + O)``;
    - each response, at its tuple index ``i``:
      ``r == HMAC-SHA256(k, b"NPFR1" + t + u32be(i) + bytes([b]) + D)``;
    - each round trip ``R = e - s`` must satisfy ``0 <= R <= T``;
    - the bound: ``L == max(R) * V / 2``.

    On success the recomputed bound ``L`` is returned. Auditing is a pure
    check: it touches no verifier state.
    """
    if not isinstance(x, bytes) or not x:
        raise ValueError("x must be non-empty bytes")
    if not isinstance(k, bytes) or not k:
        raise ValueError("k must be non-empty bytes")
    record = BitEvidence.from_bytes(x)

    if not hmac.compare_digest(
        _bit_evidence_mac(k, _bit_evidence_payload(record)), record.mac
    ):
        raise ValueError("bit evidence mac does not match")
    if not hmac.compare_digest(
        bit_transcript_digest(record.context, record.opening), record.digest
    ):
        raise ValueError("bit evidence digest does not match context and opening")
    durations = []
    for index, (bit_value, response, start, end) in enumerate(record.queries):
        if not hmac.compare_digest(
            bit_response(k, record.t, record.digest, index, bit_value), response
        ):
            raise ValueError("bit evidence response does not match the challenge")
        duration = end - start
        if not 0.0 <= duration <= record.timeout:
            raise ValueError(
                "bit evidence round trip must satisfy 0 <= e - s <= timeout"
            )
        durations.append(duration)
    bound = max(durations) * record.speed / 2.0
    if bound != record.limit:
        raise ValueError("bit evidence limit does not match the round trips and speed")
    return bound


_BIT_STATE_BODY_FIELDS = 9


def _bit_state_mac(key: bytes, seq: int, body: bytes) -> bytes:
    """``HMAC-SHA256(key, b"NPBS1" + E)`` over the outer array without ``mac``.

    ``E`` is the canonical compact-JSON encoding of ``[version, seq, body]``
    with ``body`` a lowercase hex string, exactly the first three elements of
    the outer document; the prefix and ``E`` are concatenated directly with
    no separator or length prefix.
    """
    return hmac.new(
        key,
        _BIT_STATE_PREFIX + _encode_payload([1, seq, body.hex()]),
        hashlib.sha256,
    ).digest()


def _bit_state_body_bytes(
    t: bytes,
    context: bytes,
    digest: bytes,
    opening: bytes,
    rounds: int,
    timeout: float,
    speed: float,
    queries: "tuple[tuple[int, bytes, float, float], ...]",
    previous: "Optional[tuple[int, int, float]]",
) -> bytes:
    """Encode the inner ``[t, C, D, O, R, T, V, Q, P]`` body array."""
    return _encode_payload(
        [
            t.hex(),
            context.hex(),
            digest.hex(),
            opening.hex(),
            rounds,
            timeout,
            speed,
            [[b, r.hex(), s, e] for b, r, s, e in queries],
            None if previous is None else [previous[0], previous[1], previous[2]],
        ]
    )


def _parse_bit_state_hex(value: object, name: str, length: int) -> bytes:
    """Lowercase round-tripping hex; a non-string value is a shape error.

    Mirrors the other split TypeError/ValueError records: the wrong value
    type raises :class:`TypeError`, an invalid or wrong-length hex string
    raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise TypeError(f"bit state {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"bit state {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value or len(raw) != length:
        raise ValueError(
            f"bit state {name} must be a lowercase hex string of exactly"
            f" {length} bytes"
        )
    return raw


def _parse_bit_state_body(
    body: bytes,
) -> "tuple[bytes, bytes, bytes, bytes, int, float, float, tuple, Optional[tuple]]":
    """Parse and validate a checkpoint body, returning its typed fields.

    The body must be the canonical compact-JSON array
    ``[t, C, D, O, R, T, V, Q, P]``: ``t`` 16 bytes, ``C``/``D``/``O``
    32 bytes each as lowercase hex; ``R`` a non-bool integer in
    ``1 .. 2**32``; ``T``/``V`` finite positive non-bool numbers; ``Q`` an
    array of ``[b, r, s, e]`` query items with ``seq = len(Q) <= R``; ``P``
    either null or ``[seq, b, s]`` whose ``seq`` is a non-bool integer below
    ``R``. A field of the wrong type raises :class:`TypeError`; every other
    violation (including a non-canonical spelling) raises
    :class:`ValueError`.
    """
    try:
        decoded = json.loads(body)
    except ValueError as error:
        raise ValueError("bit state body must be compact JSON") from error
    if not isinstance(decoded, list) or len(decoded) != _BIT_STATE_BODY_FIELDS:
        raise ValueError(
            "bit state body must be an array of exactly t, C, D, O, R, T, V,"
            " Q and P"
        )
    (
        raw_t,
        raw_context,
        raw_digest,
        raw_opening,
        raw_rounds,
        raw_timeout,
        raw_speed,
        raw_queries,
        raw_previous,
    ) = decoded
    t = _parse_bit_state_hex(raw_t, "t", BIT_T_BYTES)
    context = _parse_bit_state_hex(raw_context, "C", CONTEXT_BYTES)
    digest = _parse_bit_state_hex(raw_digest, "D", DIGEST_BYTES)
    opening = _parse_bit_state_hex(raw_opening, "O", OPENING_BYTES)
    if type(raw_rounds) is not int:
        # ``type`` excludes bools; R is a non-bool integer.
        raise TypeError("bit state R must be a non-bool integer")
    if not 1 <= raw_rounds <= 2**32:
        raise ValueError("bit state R must be in the range 1 .. 2**32")
    for raw_value, label in ((raw_timeout, "T"), (raw_speed, "V")):
        if not isinstance(raw_value, (int, float)):
            raise TypeError(f"bit state {label} must be a finite number")
        if isinstance(raw_value, bool) or not math.isfinite(raw_value):
            raise ValueError(f"bit state {label} must be a finite number")
    timeout = float(raw_timeout)
    speed = float(raw_speed)
    if timeout <= 0:
        raise ValueError("bit state T must be positive")
    if speed <= 0:
        raise ValueError("bit state V must be positive")
    if not isinstance(raw_queries, list):
        raise TypeError("bit state Q must be an array")
    queries: list[tuple[int, bytes, float, float]] = []
    for raw_query in raw_queries:
        if not isinstance(raw_query, list):
            raise TypeError(
                "bit state each Q item must be an array of exactly b, r, s"
                " and e"
            )
        if len(raw_query) != 4:
            raise ValueError(
                "bit state each Q item must be an array of exactly b, r, s"
                " and e"
            )
        raw_bit, raw_response, raw_start, raw_end = raw_query
        if type(raw_bit) is not int:
            # ``type`` excludes bools; the challenge bit is the exact int 0/1.
            raise TypeError("bit state b must be 0 or 1")
        if raw_bit not in (0, 1):
            raise ValueError("bit state b must be 0 or 1")
        response = _parse_bit_state_hex(raw_response, "r", BIT_R_BYTES)
        for raw_reading, label in (
            (raw_start, "s"),
            (raw_end, "e"),
        ):
            if not isinstance(raw_reading, (int, float)):
                raise TypeError(
                    f"bit state clock reading {label} must be a finite number"
                )
            if isinstance(raw_reading, bool) or not math.isfinite(raw_reading):
                raise ValueError(
                    f"bit state clock reading {label} must be a finite"
                    " non-bool number"
                )
        queries.append((raw_bit, response, float(raw_start), float(raw_end)))
    seq = len(queries)
    if seq > raw_rounds:
        raise ValueError("bit state seq must satisfy 0 <= seq <= R")
    previous: "Optional[tuple[int, int, float]]" = None
    if raw_previous is not None:
        if not isinstance(raw_previous, list):
            raise TypeError(
                "bit state P must be null or an array of exactly seq, b and s"
            )
        if len(raw_previous) != 3:
            raise ValueError(
                "bit state P must be null or an array of exactly seq, b and s"
            )
        raw_pseq, raw_pbit, raw_pstart = raw_previous
        if type(raw_pseq) is not int:
            raise TypeError("bit state P seq must be a non-bool integer")
        if not 0 <= raw_pseq < raw_rounds:
            raise ValueError("bit state P seq must satisfy 0 <= seq < R")
        # Rounds complete in index order with no gaps, so the outstanding
        # round is always the one right after the last recorded query.
        if raw_pseq != seq:
            raise ValueError(
                "bit state P seq must be the next query index (len(Q))"
            )
        if type(raw_pbit) is not int:
            raise TypeError("bit state P b must be 0 or 1")
        if raw_pbit not in (0, 1):
            raise ValueError("bit state P b must be 0 or 1")
        if not isinstance(raw_pstart, (int, float)):
            raise TypeError("bit state P s must be a finite number")
        if isinstance(raw_pstart, bool) or not math.isfinite(raw_pstart):
            raise ValueError("bit state P s must be a finite number")
        previous = (raw_pseq, raw_pbit, float(raw_pstart))
    # Canonical spelling is built from the typed values (numbers as
    # floats), so an integer s/e/T/V literal re-spells as a float and is
    # rejected along with whitespace, pretty-printing and framing.
    canonical = [
        t.hex(),
        context.hex(),
        digest.hex(),
        opening.hex(),
        raw_rounds,
        timeout,
        speed,
        [[b, r.hex(), start, end] for b, r, start, end in queries],
        (
            None
            if previous is None
            else [previous[0], previous[1], previous[2]]
        ),
    ]
    if _encode_payload(canonical) != body:
        raise ValueError("bit state body encoding is not canonical")
    return (
        t,
        context,
        digest,
        opening,
        raw_rounds,
        timeout,
        speed,
        tuple(queries),
        previous,
    )


@dataclass(frozen=True)
class BitState:
    """A MAC'd checkpoint of a step-driven bit session for later resumption.

    ``version`` is always ``1``; ``seq`` a non-bool unsigned 64-bit integer
    equal to the number of completed queries carried in the body; ``body``
    the canonical compact UTF-8 JSON array
    ``[t, C, D, O, R, T, V, Q, P]``; ``mac`` exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBS1" + E)`` where ``E`` is the outer field-order
    array without its ``mac``, ``[1, seq, body_hex]``, encoded the same
    compact way, the two segments concatenated directly with no separator
    or length prefix.

    Inside the body: ``t``/``C``/``D``/``O`` follow the existing bit
    protocol (a 16-byte transcript and three 32-byte values with
    ``D = SHA256(b"NPFC1" + C + O)``); ``R`` is a non-bool integer in
    ``1 .. 2**32`` (the total round count); ``T``/``V`` finite positive
    non-bool numbers (the timeout and propagation speed); ``Q`` the
    completed query items ``[b, r, s, e]`` with the same field contract as
    in :class:`BitEvidence` and ``seq = len(Q) <= R``; ``P`` is either
    ``null`` or ``[seq, b, s]`` describing the round still pending when the
    checkpoint was taken, whose ``seq`` must be below ``R``. Instances are
    frozen, constructed positionally in field order and compare equal by
    their fields. A field of the wrong type raises :class:`TypeError`;
    every other contract violation raises :class:`ValueError`. No key
    material is stored.
    """

    version: int
    seq: int
    body: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("bit state version must be an integer")
        if self.version != 1:
            raise ValueError("bit state version must be 1")
        if isinstance(self.seq, bool) or type(self.seq) is not int:
            raise TypeError("bit state seq must be a non-bool integer")
        if not 0 <= self.seq <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit state seq must fit in an unsigned 64-bit integer"
            )
        if not isinstance(self.body, bytes):
            raise TypeError("bit state body must be bytes")
        if not isinstance(self.mac, bytes):
            raise TypeError("bit state mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError("bit state mac must be exactly 32 bytes")
        parsed = _parse_bit_state_body(self.body)
        if len(parsed[7]) != self.seq:
            raise ValueError("bit state seq must equal the number of body Q items")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, seq, body, mac]`` with ``body`` and ``mac`` lowercase hex.

        The opaque ``body`` must itself be canonical compact JSON: decoding
        it and re-encoding with the canonical encoder must reproduce the
        stored bytes exactly. A body that is not JSON, violates the body
        field contract or whose canonical re-encoding differs (whitespace,
        pretty-printing, framing or a non-canonical spelling) raises
        :class:`ValueError`, while a body field of the wrong type raises
        :class:`TypeError`; the instance is frozen, so the stored bytes are
        never replaced by the re-encoding.
        """
        # __post_init__ already enforced the body contract, but re-check its
        # canonical spelling here like the other opaque-body records: the
        # body is decoded and re-encoded and must match byte for byte.
        _parse_bit_state_body(self.body)
        return _encode_payload(
            [1, self.seq, self.body.hex(), self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitState":
        """Decode :meth:`to_bytes` output, enforcing the full field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and for
        fields of the wrong type (including a wrong-typed field inside the
        body); raises :class:`ValueError` for anything that does not satisfy
        the value contract: an outer array of exactly four elements in field
        order, ``version == 1``, a non-bool u64 ``seq``, a lowercase hex
        ``body`` decoding to the canonical ``[t, C, D, O, R, T, V, Q, P]``
        array (``seq`` must equal the number of ``Q`` items), and a 32-byte
        lowercase hex ``mac``. Both the inner body and the outer document
        must be canonical compact JSON, so re-encoding the parsed record
        must equal the input byte for byte; formatted JSON, whitespace and
        non-canonical number spellings are rejected. The MAC is not
        verified here — use :meth:`Verifier.resume_bits` with the shared key
        for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("bit state data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(f"bit state is not valid JSON: {error}") from error
        if not isinstance(outer, list) or len(outer) != 4:
            raise ValueError(
                "bit state must be a JSON array of exactly version, seq, body"
                " and mac"
            )
        raw_version, raw_seq, raw_body, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError("bit state version must be an integer")
        if raw_version != 1:
            raise ValueError("bit state version must be 1")
        if type(raw_seq) is not int:
            raise TypeError("bit state seq must be a non-bool integer")
        if not 0 <= raw_seq <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit state seq must fit in an unsigned 64-bit integer"
            )
        if not isinstance(raw_body, str):
            raise TypeError("bit state body must be a lowercase hex string")
        try:
            body = bytes.fromhex(raw_body)
        except ValueError as error:
            raise ValueError(
                "bit state body must be a lowercase hex string"
            ) from error
        if body.hex() != raw_body:
            raise ValueError("bit state body must be a lowercase hex string")
        if not isinstance(raw_mac, str):
            raise TypeError("bit state mac must be a lowercase hex string")
        try:
            mac = bytes.fromhex(raw_mac)
        except ValueError as error:
            raise ValueError(
                "bit state mac must be a lowercase hex string"
            ) from error
        if mac.hex() != raw_mac or len(mac) != 32:
            raise ValueError(
                "bit state mac must be a lowercase hex string of exactly 32"
                " bytes"
            )
        # The constructor enforces the inner body contract too; a field of
        # the wrong type inside it stays a TypeError, every other failure is
        # a ValueError.
        record = cls(version=1, seq=raw_seq, body=body, mac=mac)
        if record.to_bytes() != data:
            raise ValueError("bit state encoding is not canonical")
        return record


_BIT_FRONTIER_FIELDS = ("version", "seq", "digest", "mac")


def _bit_frontier_payload(frontier: "BitFrontier") -> dict:
    """The JSON-ready frontier fields except ``mac``, in field order."""
    return {
        "version": frontier.version,
        "seq": frontier.seq,
        "digest": frontier.digest.hex(),
    }


def _bit_frontier_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPBF1"`` plus the canonical encoding without mac.

    The prefix and the encoding are concatenated directly with no separator
    or length prefix.
    """
    return hmac.new(
        key, _BIT_FRONTIER_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _parse_bit_frontier_hex(value: object, name: str) -> bytes:
    """Lowercase round-tripping hex for the frontier byte fields.

    Mirrors the split TypeError/ValueError records: the wrong value type
    raises :class:`TypeError`, an invalid or wrong-length hex string raises
    :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise TypeError(f"bit frontier {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"bit frontier {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        raise ValueError(f"bit frontier {name} must be a lowercase hex string")
    return raw


class _OrderedBitFrontierObject(json.JSONDecoder):
    """JSON decoder rejecting duplicate/out-of-order BitFrontier object keys."""

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys == list(_BIT_FRONTIER_FIELDS):
            return dict(pairs)
        raise ValueError(
            "bit frontier JSON keys must be exactly version, seq, digest and"
            " mac in field order"
        )


@dataclass(frozen=True)
class BitFrontier:
    """A key-MAC'd, rollback-resistant checkpoint of the bit-session frontier.

    ``version`` is always ``1``; ``seq`` a non-bool unsigned 64-bit integer
    (the accepted :class:`BitState` sequence); ``digest`` exactly 32 bytes —
    ``SHA256(x.body)`` over the carried checkpoint body; ``mac`` exactly
    32 bytes —
    ``HMAC-SHA256(key, b"NPBF1" + encoding)`` over the canonical compact
    encoding of every field except ``mac`` itself, the prefix and the
    encoding concatenated directly with no separator or length prefix.
    Instances are frozen, constructed positionally in field order and
    compare equal by their fields. A field of the wrong type raises
    :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    seq: int
    digest: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("bit frontier version must be an integer")
        if self.version != 1:
            raise ValueError("bit frontier version must be 1")
        if isinstance(self.seq, bool) or type(self.seq) is not int:
            raise TypeError("bit frontier seq must be a non-bool integer")
        if not 0 <= self.seq <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit frontier seq must fit in an unsigned 64-bit integer"
            )
        for name in ("digest", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(f"bit frontier {name} must be bytes")
            if len(value) != 32:
                raise ValueError(f"bit frontier {name} must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order
        ``version, seq, digest, mac``, ``digest`` and ``mac`` as lowercase
        hex, no whitespace, no length prefix."""
        payload = _bit_frontier_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitFrontier":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and for
        fields of the wrong type; raises :class:`ValueError` for anything
        that does not satisfy the value contract: an object with exactly
        the keys ``version, seq, digest, mac`` once each in that order
        (missing, extra, duplicated or out-of-order keys are rejected),
        ``version == 1``, a non-bool u64 ``seq``, and ``digest``/``mac``
        lowercase hex strings decoding to exactly 32 bytes each. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. The MAC is not verified here — pass the encoding to
        :class:`BitGuard` (or recompute :func:`_bit_frontier_mac` with the
        shared key) for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("bit frontier data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedBitFrontierObject)
        except ValueError as error:
            raise ValueError(f"bit frontier is not valid JSON: {error}") from error
        if not isinstance(obj, dict) or list(obj) != list(_BIT_FRONTIER_FIELDS):
            raise ValueError(
                "bit frontier must be a JSON object with exactly the version,"
                " seq, digest and mac fields in field order"
            )
        if type(obj["version"]) is not int:
            raise TypeError("bit frontier version must be an integer")
        version = obj["version"]
        if version != 1:
            raise ValueError("bit frontier version must be 1")
        if type(obj["seq"]) is not int:
            raise TypeError("bit frontier seq must be a non-bool integer")
        seq = obj["seq"]
        if not 0 <= seq <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit frontier seq must fit in an unsigned 64-bit integer"
            )
        digest = _parse_bit_frontier_hex(obj["digest"], "digest")
        if len(digest) != 32:
            raise ValueError(
                "bit frontier digest must decode to exactly 32 bytes"
            )
        mac = _parse_bit_frontier_hex(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError("bit frontier mac must decode to exactly 32 bytes")
        record = cls(version=version, seq=seq, digest=digest, mac=mac)
        if record.to_bytes() != data:
            raise ValueError("bit frontier encoding is not canonical")
        return record


class BitGuard:
    """Stateful bit-session resumption gate that refuses sequence rollback.

    ``verifier`` is the :class:`Verifier` holding the shared key (and clock
    and speed) every resumed session is restored with. ``checkpoint`` is
    keyword-only: ``None`` (the default) starts from the empty frontier;
    otherwise it must be a :class:`BitFrontier` or its canonical
    :meth:`BitFrontier.to_bytes` encoding, and its MAC is recomputed with
    the verifier's shared key and compared in constant time (a wrong-typed
    argument raises :class:`TypeError`; a malformed encoding or MAC
    mismatch raises :class:`ValueError`). Across a restart the caller must
    pass the value previously exported at :attr:`checkpoint`; nothing is
    persisted by the guard itself.

    Each :meth:`resume` accepts a :class:`BitState` or its canonical
    :meth:`BitState.to_bytes` bytes, exactly like
    :meth:`Verifier.resume_bits`, which runs first: the checkpoint MAC is
    verified and the carried session recovered and recomputed from
    scratch. Only after that succeeds is the carried ``seq`` and
    ``SHA256(body)`` compared against the frontier under a lock: a lower
    ``seq`` is rejected, an equal ``seq`` is accepted solely as a replay of
    the identical body, and a higher ``seq`` advances the frontier, which
    is MAC'd as ``HMAC-SHA256(key, b"NPBF1" + encoding)``. The verify,
    gate and update are atomic: a rejected state never changes the
    frontier and concurrent resumes can never move it backwards. A
    wrong-typed argument raises :class:`TypeError`; every other failure —
    a malformed encoding, a bad MAC, a failed recovery or a rejected
    rollback — raises :class:`ValueError` and leaves the frontier
    untouched.
    """

    def __init__(self, verifier: object, *, checkpoint: object = None) -> None:
        if not isinstance(verifier, Verifier):
            raise TypeError("verifier must be a Verifier instance")
        self._verifier = verifier
        self._key = verifier._key
        self._lock = threading.Lock()
        self._frontier: "Optional[BitFrontier]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, BitFrontier):
            frontier = checkpoint
        elif isinstance(checkpoint, bytes):
            frontier = BitFrontier.from_bytes(checkpoint)
        else:
            raise TypeError(
                "checkpoint must be a BitFrontier instance, its canonical"
                " bytes, or None"
            )
        if not hmac.compare_digest(
            _bit_frontier_mac(self._key, _bit_frontier_payload(frontier)),
            frontier.mac,
        ):
            raise ValueError("checkpoint mac does not match the verifier key")
        self._frontier = frontier

    @property
    def checkpoint(self) -> "Optional[BitFrontier]":
        """The current frontier :class:`BitFrontier`, or ``None`` before the
        first successfully resumed state. The returned object is frozen and
        the property read-only; persist its :meth:`BitFrontier.to_bytes`
        output and pass it back to a new guard to survive a restart."""
        return self._frontier

    def resume(self, x: object) -> "BitSession":
        """Verify and resume ``x``, enforcing monotone checkpoint progress.

        ``x`` must be a :class:`BitState` or its canonical
        :meth:`BitState.to_bytes` encoding — any other type raises
        :class:`TypeError`. Recovery runs exactly as
        :meth:`Verifier.resume_bits` (the ``NPBS1`` MAC is verified in
        constant time and every carried value is recomputed from scratch),
        then the seq/digest gate and the frontier update are serialized
        under the guard lock: lower ``seq`` rejected, equal ``seq``
        accepted only with the identical ``SHA256(body)`` as a replay that
        leaves the frontier untouched, higher ``seq`` advancing it to a
        fresh ``NPBF1``-MAC'd :class:`BitFrontier`. Every failure raises
        :class:`ValueError` and changes no state. On success the restored
        active :class:`BitSession` is returned.
        """
        state = self._coerce_state(x)
        # The cryptographic recovery is a pure check, but it runs inside the
        # same lock as the gate and the update so that verification, gating
        # and the frontier advance are one atomic step: no concurrent resume
        # can observe or interleave a half-checked frontier.
        with self._lock:
            session = self._verifier.resume_bits(state)
            current = self._frontier
            digest = hashlib.sha256(state.body).digest()
            if current is not None:
                if state.seq < current.seq:
                    raise ValueError(
                        "bit state seq is below the guarded frontier"
                    )
                if state.seq == current.seq:
                    if not hmac.compare_digest(digest, current.digest):
                        raise ValueError(
                            "bit state carries a different body at the"
                            " frontier seq"
                        )
                    # Identical body: an accepted replay, nothing to advance.
                    return session
            candidate = BitFrontier(
                version=1,
                seq=state.seq,
                digest=digest,
                mac=b"\x00" * 32,
            )
            self._frontier = replace(
                candidate,
                mac=_bit_frontier_mac(
                    self._key, _bit_frontier_payload(candidate)
                ),
            )
            return session

    @staticmethod
    def _coerce_state(x: object) -> "BitState":
        if isinstance(x, BitState):
            return x
        if isinstance(x, bytes):
            try:
                return BitState.from_bytes(x)
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error,
                # exactly as in Verifier.resume_bits.
                raise ValueError(
                    "x does not satisfy the bit state field contract"
                ) from error
        raise TypeError(
            "x must be a BitState instance or its canonical bytes"
        )


def _bit_map_payload(entries: "tuple[tuple[bytes, int, bytes], ...]") -> list:
    """The JSON-ready ``[1, E]`` array without ``mac``, in field order."""
    return [1, [[sid.hex(), seq, digest.hex()] for sid, seq, digest in entries]]


def _bit_map_mac(key: bytes, payload: list) -> bytes:
    """HMAC-SHA256 over ``b"NPBL1"`` plus the canonical ``[1, E]`` encoding.

    The prefix and the encoding are concatenated directly with no separator
    or length prefix.
    """
    return hmac.new(
        key, _BIT_MAP_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _bit_map_update_payload(update: "BitMapUpdate") -> list:
    """The JSON-ready ``[1, B, A]`` array without ``mac``, in field order."""
    return [1, update.before.hex(), update.after.hex()]


def _bit_map_update_mac(key: bytes, payload: list) -> bytes:
    """HMAC-SHA256 over ``b"NPBU1"`` plus the canonical ``[1, B, A]`` encoding.

    The prefix and the encoding are concatenated directly with no separator
    or length prefix.
    """
    return hmac.new(
        key, _BIT_MAP_UPDATE_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _parse_bit_map_hex(value: object, name: str) -> bytes:
    """Lowercase round-tripping hex for the table byte fields.

    Mirrors the other split TypeError/ValueError records: the wrong value
    type raises :class:`TypeError`, an invalid or non-lowercase hex string
    raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise TypeError(f"bit map {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"bit map {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        raise ValueError(f"bit map {name} must be a lowercase hex string")
    return raw


def _bit_state_sid(state: "BitState") -> bytes:
    """The partition key of a checkpoint: ``SHA256(S)`` where ``S`` is the
    canonical compact-JSON encoding of the body's first seven items
    ``[t, C, D, O, R, T, V]`` — everything identifying the session itself,
    with no per-round progress."""
    (
        transcript,
        context,
        digest,
        opening,
        rounds,
        timeout,
        speed,
        _queries,
        _previous,
    ) = _parse_bit_state_body(state.body)
    return hashlib.sha256(
        _encode_payload(
            [
                transcript.hex(),
                context.hex(),
                digest.hex(),
                opening.hex(),
                rounds,
                timeout,
                speed,
            ]
        )
    ).digest()


@dataclass(frozen=True)
class BitMap:
    """A key-MAC'd, rollback-resistant table of per-session bit frontiers.

    ``version`` is always ``1``; ``entries`` a tuple of
    ``(sid, seq, hash)`` tuples ordered by strictly ascending ``sid``
    (unique by construction), one per resumed session partition: ``sid``
    exactly 32 bytes — ``SHA256(S)`` where ``S`` is the canonical
    compact-JSON encoding of the checkpoint body's first seven items
    ``[t, C, D, O, R, T, V]``; ``seq`` a non-bool unsigned 64-bit integer
    (the accepted :class:`BitState` sequence, equal to its number of ``Q``
    items); ``hash`` exactly 32 bytes — ``SHA256(body)`` over the carried
    checkpoint body. ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBL1" + C)`` where ``C`` is the canonical compact
    encoding of ``[1, E]`` (the version and the entries without ``mac``),
    the prefix and ``C`` concatenated directly with no separator or length
    prefix. Instances are frozen, constructed positionally in field order
    and compare equal by their fields. A field of the wrong type raises
    :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    entries: tuple
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("bit map version must be an integer")
        if self.version != 1:
            raise ValueError("bit map version must be 1")
        if not isinstance(self.entries, tuple):
            raise TypeError("bit map entries must be a tuple")
        previous_sid: "Optional[bytes]" = None
        for entry in self.entries:
            if not isinstance(entry, tuple):
                raise TypeError(
                    "bit map each entry must be a (sid, seq, hash) tuple"
                )
            if len(entry) != 3:
                raise ValueError(
                    "bit map each entry must be a (sid, seq, hash) tuple"
                )
            sid, seq, digest = entry
            for name, value in (("sid", sid), ("hash", digest)):
                if not isinstance(value, bytes):
                    raise TypeError(f"bit map entry {name} must be bytes")
                if len(value) != 32:
                    raise ValueError(
                        f"bit map entry {name} must be exactly 32 bytes"
                    )
            if isinstance(seq, bool) or type(seq) is not int:
                raise TypeError(
                    "bit map entry seq must be a non-bool integer"
                )
            if not 0 <= seq <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(
                    "bit map entry seq must fit in an unsigned 64-bit integer"
                )
            if previous_sid is not None and sid <= previous_sid:
                raise ValueError(
                    "bit map entries must be unique and ordered by"
                    " ascending sid"
                )
            previous_sid = sid
        if not isinstance(self.mac, bytes):
            raise TypeError("bit map mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError("bit map mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the array ``[1, E, M]`` where
        ``E`` items are ``[sid, seq, hash]`` and ``sid``/``hash``/``M`` are
        lowercase hex, no whitespace, no length prefix."""
        return _encode_payload(
            _bit_map_payload(self.entries) + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMap":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, entries, mac]``, ``version == 1``, each entry
        an array of exactly ``[sid, seq, hash]`` with ``sid``/``hash``
        lowercase hex decoding to exactly 32 bytes each and ``seq`` a
        non-bool u64, entries unique and ordered by ascending ``sid``, and
        ``mac`` a lowercase hex string decoding to exactly 32 bytes. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. The MAC is not verified here — pass the encoding to
        :class:`BitGate` (or recompute :func:`_bit_map_mac` with the shared
        key) for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("bit map data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(f"bit map is not valid JSON: {error}") from error
        if not isinstance(outer, list) or len(outer) != 3:
            raise ValueError(
                "bit map must be a JSON array of exactly version, entries"
                " and mac"
            )
        raw_version, raw_entries, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError("bit map version must be an integer")
        if raw_version != 1:
            raise ValueError("bit map version must be 1")
        if not isinstance(raw_entries, list):
            raise TypeError("bit map entries must be an array")
        entries: "list[tuple[bytes, int, bytes]]" = []
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, list):
                raise TypeError(
                    "bit map each entry must be an array of exactly sid,"
                    " seq and hash"
                )
            if len(raw_entry) != 3:
                raise ValueError(
                    "bit map each entry must be an array of exactly sid,"
                    " seq and hash"
                )
            raw_sid, raw_seq, raw_hash = raw_entry
            sid = _parse_bit_map_hex(raw_sid, "sid")
            if len(sid) != 32:
                raise ValueError(
                    "bit map sid must decode to exactly 32 bytes"
                )
            digest = _parse_bit_map_hex(raw_hash, "hash")
            if len(digest) != 32:
                raise ValueError(
                    "bit map hash must decode to exactly 32 bytes"
                )
            if type(raw_seq) is not int:
                raise TypeError("bit map entry seq must be a non-bool integer")
            if not 0 <= raw_seq <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(
                    "bit map entry seq must fit in an unsigned 64-bit integer"
                )
            entries.append((sid, raw_seq, digest))
        mac = _parse_bit_map_hex(raw_mac, "mac")
        if len(mac) != 32:
            raise ValueError("bit map mac must decode to exactly 32 bytes")
        record = cls(version=1, entries=tuple(entries), mac=mac)
        if record.to_bytes() != data:
            raise ValueError("bit map encoding is not canonical")
        return record


def _require_bit_map_encoding(value: bytes, name: str, allow_empty: bool) -> None:
    """Enforce the canonical-:class:`BitMap`-bytes contract of a proof field.

    ``value`` is already known to be ``bytes``; when ``allow_empty`` holds,
    ``b""`` (no table existed yet) is also accepted. Every violation raises
    :class:`ValueError`, including the field-shape :class:`TypeError` a
    malformed inner document would otherwise surface.
    """
    if allow_empty and value == b"":
        return
    try:
        BitMap.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"bit map update {name} must be the canonical BitMap encoding"
        ) from error


@dataclass(frozen=True)
class BitMapUpdate:
    """A key-MAC'd attestation of one atomic :class:`BitMap` transition.

    ``version`` is always ``1``. ``before`` is ``b""`` — no table existed
    yet — or the canonical :meth:`BitMap.to_bytes` encoding of the table
    before the transition; ``after`` is the canonical
    :meth:`BitMap.to_bytes` encoding of the table after it. ``mac`` is
    exactly 32 bytes — ``HMAC-SHA256(key, b"NPBU1" + C)`` where ``C`` is
    the canonical compact encoding of ``[1, B, A]`` (the version and the
    lowercase hex of both table encodings, without ``mac``), the prefix
    and ``C`` concatenated directly with no separator or length prefix.
    Instances are frozen, constructed positionally in field order and
    compare equal by their fields. A field of the wrong type raises
    :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    before: bytes
    after: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("bit map update version must be an integer")
        if self.version != 1:
            raise ValueError("bit map update version must be 1")
        if not isinstance(self.before, bytes):
            raise TypeError("bit map update before must be bytes")
        _require_bit_map_encoding(self.before, "before", allow_empty=True)
        if not isinstance(self.after, bytes):
            raise TypeError("bit map update after must be bytes")
        _require_bit_map_encoding(self.after, "after", allow_empty=False)
        if not isinstance(self.mac, bytes):
            raise TypeError("bit map update mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError("bit map update mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the array ``[1, B, A, M]`` where
        ``B``/``A``/``M`` are the lowercase hex of the ``before``/``after``
        table encodings and the MAC, no whitespace, no length prefix."""
        return _encode_payload(
            _bit_map_update_payload(self) + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMapUpdate":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, before, after, mac]``, ``version == 1``,
        ``before`` a lowercase hex string decoding to ``b""`` or the
        canonical :class:`BitMap` encoding, ``after`` a lowercase hex
        string decoding to the canonical :class:`BitMap` encoding, and
        ``mac`` a lowercase hex string decoding to exactly 32 bytes. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for
        byte, so formatted JSON, whitespace and any non-canonical spelling
        are rejected too. The MAC is not verified here — pass the record
        to :func:`audit_map_update` with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("bit map update data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"bit map update is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 4:
            raise ValueError(
                "bit map update must be a JSON array of exactly version,"
                " before, after and mac"
            )
        raw_version, raw_before, raw_after, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError("bit map update version must be an integer")
        if raw_version != 1:
            raise ValueError("bit map update version must be 1")
        before = _parse_bit_map_hex(raw_before, "before")
        after = _parse_bit_map_hex(raw_after, "after")
        mac = _parse_bit_map_hex(raw_mac, "mac")
        record = cls(version=1, before=before, after=after, mac=mac)
        if record.to_bytes() != data:
            raise ValueError("bit map update encoding is not canonical")
        return record


class BitGate:
    """Stateful bit-session resumption gate partitioning the anti-rollback
    frontier by session.

    Unlike :class:`BitGuard`, which tracks a single frontier, the gate
    keeps one ``(sid, seq, hash)`` frontier per session partition, so
    independent sessions interleaved on the same verifier each advance
    their own monotone sequence. ``verifier`` is the :class:`Verifier`
    holding the shared key (and clock and speed) every resumed session is
    restored with. ``checkpoint`` is keyword-only: ``None`` (the default)
    starts from the empty table; otherwise it must be a :class:`BitMap` or
    its canonical :meth:`BitMap.to_bytes` encoding, and its MAC is
    recomputed with the verifier's shared key and compared in constant
    time (a wrong-typed argument raises :class:`TypeError`; a malformed
    encoding or MAC mismatch raises :class:`ValueError`). Across a restart
    the caller must pass the value previously exported at
    :attr:`checkpoint`; nothing is persisted by the gate itself.

    Each :meth:`resume` accepts a :class:`BitState` or its canonical
    :meth:`BitState.to_bytes` bytes, exactly like
    :meth:`Verifier.resume_bits`, which runs first: the checkpoint MAC is
    verified and the carried session recovered and recomputed from
    scratch. Only after that succeeds is the session's ``sid`` derived and
    its ``seq``/``SHA256(body)`` compared against that partition's entry
    under a lock: a lower ``seq`` is rejected, an equal ``seq`` is accepted
    solely as a replay of the identical body, and a higher ``seq`` advances
    the entry; a first-seen ``sid`` starts a new partition. The verify,
    gate and update are atomic: a rejected state never changes the table
    and concurrent resumes can never move an entry backwards or lose an
    update. A wrong-typed argument raises :class:`TypeError`; every other
    failure — a malformed encoding, a bad MAC, a failed recovery or a
    rejected rollback — raises :class:`ValueError` and leaves the table
    untouched.
    """

    def __init__(self, verifier: object, *, checkpoint: object = None) -> None:
        if not isinstance(verifier, Verifier):
            raise TypeError("verifier must be a Verifier instance")
        self._verifier = verifier
        self._key = verifier._key
        self._lock = threading.Lock()
        self._table: "Optional[BitMap]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, BitMap):
            table = checkpoint
        elif isinstance(checkpoint, bytes):
            table = BitMap.from_bytes(checkpoint)
        else:
            raise TypeError(
                "checkpoint must be a BitMap instance, its canonical"
                " bytes, or None"
            )
        if not hmac.compare_digest(
            _bit_map_mac(self._key, _bit_map_payload(table.entries)),
            table.mac,
        ):
            raise ValueError("checkpoint mac does not match the verifier key")
        self._table = table

    @property
    def checkpoint(self) -> "Optional[BitMap]":
        """The current frontier :class:`BitMap`, or ``None`` before the
        first successfully resumed state. The returned object is frozen and
        the property read-only; persist its :meth:`BitMap.to_bytes` output
        and pass it back to a new gate to survive a restart."""
        return self._table

    def resume(self, x: object) -> "BitSession":
        """Verify and resume ``x``, enforcing monotone per-session progress.

        ``x`` must be a :class:`BitState` or its canonical
        :meth:`BitState.to_bytes` encoding — any other type raises
        :class:`TypeError`. Recovery runs exactly as
        :meth:`Verifier.resume_bits` (the ``NPBS1`` MAC is verified in
        constant time and every carried value is recomputed from scratch),
        then the session's ``sid`` is derived and the seq/hash gate and the
        table update are serialized under the gate lock: lower ``seq``
        rejected, equal ``seq`` accepted only with the identical
        ``SHA256(body)`` as a replay that leaves the table untouched,
        higher ``seq`` advancing the partition's entry, and a first-seen
        ``sid`` inserting a new entry — the updated table is MAC'd as
        ``HMAC-SHA256(key, b"NPBL1" + C)``. Every failure raises
        :class:`ValueError` and changes no state. On success the restored
        active :class:`BitSession` is returned.
        """
        return self.resume_tx(x)[0]

    def resume_tx(self, x: object) -> "tuple[BitSession, BitMapUpdate]":
        """Verify and resume ``x`` like :meth:`resume`, also issuing a proof.

        The recovery, the seq/hash gate and the table update run exactly as
        :meth:`resume`, atomically under the gate lock; on success a
        :class:`BitMapUpdate` attesting the transition is returned together
        with the restored active :class:`BitSession`. The proof carries the
        canonical encoding of the table before the transition (``b""``
        when no table existed yet) and after it, MAC'd as
        ``HMAC-SHA256(key, b"NPBU1" + C)``; an accepted replay leaves the
        table untouched and attests the identical before/after encoding.
        Every failure raises the same exception :meth:`resume` would raise
        and changes no state — no proof is issued for a rejected state.
        """
        state = BitGuard._coerce_state(x)
        # The cryptographic recovery is a pure check, but it runs inside
        # the same lock as the gate and the update so that verification,
        # gating and the table advance are one atomic step: no concurrent
        # resume can observe or interleave a half-checked table.
        with self._lock:
            session = self._verifier.resume_bits(state)
            sid = _bit_state_sid(state)
            digest = hashlib.sha256(state.body).digest()
            current = self._table
            before = b"" if current is None else current.to_bytes()
            entries = () if current is None else current.entries
            index = 0
            while index < len(entries) and entries[index][0] < sid:
                index += 1
            if index < len(entries) and entries[index][0] == sid:
                _entry_sid, entry_seq, entry_hash = entries[index]
                if state.seq < entry_seq:
                    raise ValueError(
                        "bit state seq is below the guarded frontier for"
                        " its session"
                    )
                if state.seq == entry_seq:
                    if not hmac.compare_digest(digest, entry_hash):
                        raise ValueError(
                            "bit state carries a different body at the"
                            " frontier seq"
                        )
                    # Identical body: an accepted replay, nothing to advance.
                    return session, self._issue_update(before, before)
                entries = entries[:index] + entries[index + 1 :]
            updated = (
                entries[:index] + ((sid, state.seq, digest),)
                + entries[index:]
            )
            candidate = BitMap(version=1, entries=updated, mac=b"\x00" * 32)
            self._table = replace(
                candidate,
                mac=_bit_map_mac(
                    self._key, _bit_map_payload(candidate.entries)
                ),
            )
            return session, self._issue_update(before, self._table.to_bytes())

    def _issue_update(self, before: bytes, after: bytes) -> "BitMapUpdate":
        """MAC the ``before``/``after`` transition with the gate key."""
        candidate = BitMapUpdate(
            version=1, before=before, after=after, mac=b"\x00" * 32
        )
        return replace(
            candidate,
            mac=_bit_map_update_mac(
                self._key, _bit_map_update_payload(candidate)
            ),
        )


def _coerce_bit_map_update(x: object, name: str) -> "BitMapUpdate":
    """Coerce a :class:`BitMapUpdate` or its canonical bytes, splitting the
    TypeError/ValueError contract exactly as the public auditors do: the
    wrong kind of argument raises :class:`TypeError`, a field-shape failure
    surfacing while parsing byte content of the right kind is a value
    error."""
    if isinstance(x, BitMapUpdate):
        return x
    if isinstance(x, bytes):
        try:
            return BitMapUpdate.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the bit map update field contract"
            ) from error
    raise TypeError(
        f"{name} must be a BitMapUpdate instance or its canonical bytes"
    )


def audit_map_update(x: object, key: object) -> None:
    """Re-verify a :class:`BitMapUpdate` transition proof against ``key``.

    ``x`` must be a :class:`BitMapUpdate` or its canonical
    :meth:`BitMapUpdate.to_bytes` encoding and ``key`` the non-empty shared
    key — a wrong-typed argument raises :class:`TypeError`, every other
    contract violation raises :class:`ValueError`. The proof's own MAC is
    recomputed as ``HMAC-SHA256(key, b"NPBU1" + C)`` and compared in
    constant time, and the ``NPBL1`` MAC of every table the proof carries
    is verified against ``key`` the same way. The transition itself must
    then be one of exactly three shapes, with every other entry of the
    table unchanged: the table is identical before and after (an accepted
    replay), exactly one entry is added, or exactly one entry keeps its
    ``sid`` while its ``seq`` strictly increases and its ``hash`` changes.
    When ``before`` is ``b""`` — no table existed yet — the transition
    creates the very first partition, so the ``after`` table must hold
    exactly one entry; an empty or multi-entry initial table is rejected.
    Auditing is a pure check: it touches no gate state and returns
    ``None``.
    """
    update = _coerce_bit_map_update(x, "x")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    if not hmac.compare_digest(
        _bit_map_update_mac(key, _bit_map_update_payload(update)), update.mac
    ):
        raise ValueError("bit map update mac does not match")
    before_entries: "tuple[tuple[bytes, int, bytes], ...]" = ()
    if update.before:
        before_table = BitMap.from_bytes(update.before)
        if not hmac.compare_digest(
            _bit_map_mac(key, _bit_map_payload(before_table.entries)),
            before_table.mac,
        ):
            raise ValueError("bit map update before table mac does not match")
        before_entries = before_table.entries
    after_table = BitMap.from_bytes(update.after)
    if not hmac.compare_digest(
        _bit_map_mac(key, _bit_map_payload(after_table.entries)),
        after_table.mac,
    ):
        raise ValueError("bit map update after table mac does not match")
    after_entries = after_table.entries
    if not update.before and len(after_entries) != 1:
        # No table existed before: the transition creates the very first
        # partition, so the after table must hold exactly one entry — an
        # empty or multi-entry initial table is not a valid start.
        raise ValueError(
            "bit map update with no before table must create exactly one"
            " entry"
        )
    if after_entries == before_entries:
        # The identical table: an accepted replay attested as a no-op.
        return None
    if len(after_entries) == len(before_entries) + 1:
        # Exactly one added entry; every other entry unchanged.
        for index in range(len(after_entries)):
            if (
                after_entries[:index] + after_entries[index + 1 :]
                == before_entries
            ):
                return None
        raise ValueError(
            "bit map update adds an entry but changes other entries"
        )
    if len(after_entries) == len(before_entries):
        # Exactly one entry advancing: same sid, higher seq, changed hash.
        changed = [
            index
            for index in range(len(after_entries))
            if after_entries[index] != before_entries[index]
        ]
        if len(changed) == 1:
            index = changed[0]
            before_sid, before_seq, before_hash = before_entries[index]
            after_sid, after_seq, after_hash = after_entries[index]
            if (
                after_sid == before_sid
                and after_seq > before_seq
                and after_hash != before_hash
            ):
                return None
        raise ValueError(
            "bit map update must advance exactly one entry to a higher seq"
            " with a changed hash"
        )
    raise ValueError(
        "bit map update must keep the table, add exactly one entry or"
        " advance exactly one entry"
    )


def audit_map_history(
    updates: object, key: object, *, checkpoint: object = None
) -> "BitMap":
    """Re-verify a contiguous chain of :class:`BitMapUpdate` proofs.

    ``updates`` must be a non-empty iterable whose items are each a
    :class:`BitMapUpdate` or its canonical :meth:`BitMapUpdate.to_bytes`
    encoding, and ``key`` the non-empty shared ``bytes`` key.
    ``checkpoint`` is keyword-only: ``None`` (the default) starts the chain
    from no table at all, otherwise it must be a :class:`BitMap` or its
    canonical :meth:`BitMap.to_bytes` encoding. A non-iterable ``updates``,
    a non-``bytes`` ``key``, a wrong-typed item or a wrong-kind
    ``checkpoint`` raises :class:`TypeError`; an empty sequence, an empty
    key, a malformed or non-canonical encoding, a MAC mismatch or any
    failed per-update audit raises :class:`ValueError`.

    When a checkpoint is given, its ``NPBL1`` MAC is recomputed with
    ``key`` and compared in constant time and its canonical
    :meth:`BitMap.to_bytes` encoding is the starting point of the chain;
    with ``checkpoint=None`` the starting point is ``b""`` and the first
    update must attest the creation of the first partition. Every update
    is audited with :func:`audit_map_update` and must chain byte for byte:
    the first ``before`` must equal the starting point and every later
    ``before`` must equal the previous ``after``, so a gap or a reordered
    proof is rejected. Auditing is a pure check: it touches no gate state
    and returns no partial result — on success the frozen :class:`BitMap`
    of the final ``after`` is returned.
    """
    try:
        items = list(updates)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(
            "updates must be an iterable of BitMapUpdate instances or"
            " their canonical bytes"
        ) from None
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if isinstance(checkpoint, BitMap):
        start_table = checkpoint
    elif isinstance(checkpoint, bytes):
        try:
            start_table = BitMap.from_bytes(checkpoint)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                "checkpoint does not satisfy the bit map field contract"
            ) from error
    elif checkpoint is not None:
        raise TypeError(
            "checkpoint must be a BitMap instance, its canonical bytes,"
            " or None"
        )
    else:
        start_table = None
    if not key:
        raise ValueError("key must be non-empty")
    if not items:
        raise ValueError("updates must be a non-empty sequence")
    if start_table is None:
        current = b""
    else:
        if not hmac.compare_digest(
            _bit_map_mac(key, _bit_map_payload(start_table.entries)),
            start_table.mac,
        ):
            raise ValueError("checkpoint mac does not match the key")
        current = start_table.to_bytes()
    for item in items:
        update = _coerce_bit_map_update(item, "updates items")
        audit_map_update(update, key)
        if update.before != current:
            raise ValueError(
                "bit map history is not contiguous: each update before"
                " must equal the previous after"
            )
        current = update.after
    return BitMap.from_bytes(current)


class BitMapHistoryAuditor:
    """Stateful batch auditor for :class:`BitMapUpdate` proof chains.

    ``key`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    shared key the tables and transition proofs are MAC'd with.
    ``checkpoint`` is keyword-only: ``None`` (the default) starts from no
    table at all; otherwise it must be a :class:`BitMap` or its canonical
    :meth:`BitMap.to_bytes` encoding (any other type raises
    :class:`TypeError`), parsed under the full :class:`BitMap` contract and
    its ``NPBL1`` MAC recomputed with ``key`` and compared in constant time
    — a malformed encoding or MAC mismatch raises :class:`ValueError`.
    Across a restart the caller must pass the value previously exported at
    :attr:`checkpoint`; nothing is persisted by the auditor itself.

    Each :meth:`audit` re-runs :func:`audit_map_history` over the batch
    under the auditor lock, starting from the current checkpoint: the first
    update's ``before`` must equal the current starting point byte for byte
    and every later ``before`` the previous ``after``. Only when the whole
    batch verifies is the checkpoint replaced with the final ``after``
    table, so any parse, MAC, transition or chain failure leaves the
    checkpoint untouched and no partial result is returned. Concurrent
    audits linearize in lock-acquisition order: of competing batches
    chaining from the same starting point only the one that still chains
    onto the latest ``after`` can succeed, and a committed batch is never
    lost.
    """

    def __init__(self, key: object, *, checkpoint: object = None) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must be non-empty")
        self._key = key
        self._lock = threading.Lock()
        self._table: "Optional[BitMap]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, BitMap):
            table = checkpoint
        elif isinstance(checkpoint, bytes):
            try:
                table = BitMap.from_bytes(checkpoint)
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error.
                raise ValueError(
                    "checkpoint does not satisfy the bit map field contract"
                ) from error
        else:
            raise TypeError(
                "checkpoint must be a BitMap instance, its canonical bytes,"
                " or None"
            )
        if not hmac.compare_digest(
            _bit_map_mac(self._key, _bit_map_payload(table.entries)),
            table.mac,
        ):
            raise ValueError("checkpoint mac does not match the key")
        self._table = table

    @property
    def checkpoint(self) -> "Optional[BitMap]":
        """The current frontier :class:`BitMap`, or ``None`` before the
        first successfully audited batch. The returned object is frozen and
        the property read-only; persist its :meth:`BitMap.to_bytes` output
        and pass it back to a new auditor to survive a restart."""
        return self._table

    def audit(self, updates: object) -> "BitMap":
        """Audit one batch of :class:`BitMapUpdate` proofs and advance.

        ``updates`` must be a non-empty iterable whose items are each a
        :class:`BitMapUpdate` or its canonical
        :meth:`BitMapUpdate.to_bytes` encoding — a non-iterable argument or
        a wrong-typed item raises :class:`TypeError`; an empty batch and
        every parse, MAC, transition or chain failure raises
        :class:`ValueError`. The whole batch is verified with
        :func:`audit_map_history` against the current checkpoint under the
        auditor lock, so the check and the checkpoint advance are one
        atomic step: a failed batch changes nothing and returns no partial
        result, and concurrent batches are serialized in lock-acquisition
        order. On success the checkpoint is replaced and the frozen
        :class:`BitMap` of the final ``after`` is returned.
        """
        with self._lock:
            result = audit_map_history(
                updates, self._key, checkpoint=self._table
            )
            self._table = result
            return result


def _parse_bit_map_history_hex(value: object, name: str) -> bytes:
    """Lowercase round-tripping hex inside a history body.

    The body is opaque byte content, so — exactly like
    :func:`_require_bit_map_encoding` — every violation surfaces as
    :class:`ValueError`, including the field-shape :class:`TypeError` a
    wrong-typed item would otherwise raise.
    """
    try:
        return _parse_bit_map_hex(value, name)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"bit map history body {name} must be a lowercase hex string"
        ) from error


def _require_bit_map_history_encoding(
    value: bytes, name: str, allow_empty: bool
) -> None:
    """Enforce the canonical-:class:`BitMap`-bytes contract of a body item.

    ``value`` is already known to be ``bytes``; when ``allow_empty`` holds,
    ``b""`` (no table existed yet) is also accepted. Every violation raises
    :class:`ValueError`.
    """
    if allow_empty and value == b"":
        return
    try:
        BitMap.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"bit map history body {name} must be the canonical BitMap"
            " encoding"
        ) from error


def _require_bit_map_history_body(body: bytes) -> None:
    """Enforce the canonical-body contract of a :class:`BitMapHistoryEvidence`.

    ``body`` is already known to be ``bytes`` and must be the canonical
    compact UTF-8 JSON encoding of ``[start, updates, end]``: ``start`` the
    empty string (no table existed yet) or the lowercase hex of the
    canonical starting :class:`BitMap` encoding, ``updates`` a non-empty
    array of lowercase hex strings each decoding to the canonical
    :class:`BitMapUpdate` encoding, and ``end`` the lowercase hex of the
    canonical final :class:`BitMap` encoding. Every violation raises
    :class:`ValueError`, including the field-shape :class:`TypeError` a
    malformed inner document would otherwise surface. The chain itself —
    contiguity, per-update validity and that ``end`` is the final ``after``
    — is not checked here; :func:`audit_map_history_evidence` recomputes it.
    """
    try:
        outer = json.loads(body)
    except ValueError as error:
        raise ValueError(
            f"bit map history body is not valid JSON: {error}"
        ) from error
    if not isinstance(outer, list) or len(outer) != 3:
        raise ValueError(
            "bit map history body must be an array of exactly start,"
            " updates and end"
        )
    raw_start, raw_updates, raw_end = outer
    start = _parse_bit_map_history_hex(raw_start, "start")
    _require_bit_map_history_encoding(start, "start", allow_empty=True)
    if not isinstance(raw_updates, list):
        raise ValueError("bit map history body updates must be an array")
    if not raw_updates:
        raise ValueError("bit map history body updates must be non-empty")
    for raw_update in raw_updates:
        encoding = _parse_bit_map_history_hex(raw_update, "update")
        try:
            BitMapUpdate.from_bytes(encoding)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "bit map history body update must be the canonical"
                " BitMapUpdate encoding"
            ) from error
    end = _parse_bit_map_history_hex(raw_end, "end")
    _require_bit_map_history_encoding(end, "end", allow_empty=False)
    if _encode_payload(outer) != body:
        raise ValueError("bit map history body encoding is not canonical")


def _bit_map_history_body_parts(
    body: bytes,
) -> "tuple[bytes, list[bytes], bytes]":
    """Split an already-validated history body into start, updates and end."""
    raw_start, raw_updates, raw_end = json.loads(body)
    return (
        bytes.fromhex(raw_start),
        [bytes.fromhex(raw_update) for raw_update in raw_updates],
        bytes.fromhex(raw_end),
    )


def _bit_map_history_evidence_mac(key: bytes, body: bytes) -> bytes:
    """HMAC-SHA256 over ``b"NPBH1"`` plus the body, concatenated directly
    with no separator or length prefix."""
    return hmac.new(
        key, _BIT_MAP_HISTORY_PREFIX + body, hashlib.sha256
    ).digest()


@dataclass(frozen=True)
class BitMapHistoryEvidence:
    """A key-MAC'd attestation of one contiguous :class:`BitMapUpdate` chain.

    ``version`` is always ``1``. ``body`` is the canonical compact UTF-8
    JSON encoding of ``[start, updates, end]``: ``start`` the empty string
    — no table existed yet — or the lowercase hex of the canonical
    :class:`BitMap` encoding the chain starts from, ``updates`` a non-empty
    array of lowercase hex strings each decoding to the canonical
    :class:`BitMapUpdate` encoding, and ``end`` the lowercase hex of the
    canonical :class:`BitMap` encoding of the final table. ``mac`` is
    exactly 32 bytes — ``HMAC-SHA256(key, b"NPBH1" + body)``, the prefix
    and the body concatenated directly with no separator or length prefix.
    Instances are frozen, constructed positionally in field order and
    compare equal by their fields. A field of the wrong type raises
    :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    body: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("bit map history evidence version must be an integer")
        if self.version != 1:
            raise ValueError("bit map history evidence version must be 1")
        if not isinstance(self.body, bytes):
            raise TypeError("bit map history evidence body must be bytes")
        _require_bit_map_history_body(self.body)
        if not isinstance(self.mac, bytes):
            raise TypeError("bit map history evidence mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError(
                "bit map history evidence mac must be exactly 32 bytes"
            )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the array ``[1, B, M]`` where
        ``B``/``M`` are the lowercase hex of the body and the MAC, no
        whitespace, no length prefix."""
        return _encode_payload([1, self.body.hex(), self.mac.hex()])

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMapHistoryEvidence":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, body, mac]``, ``version == 1``, ``body`` a
        lowercase hex string decoding to the canonical history body and
        ``mac`` a lowercase hex string decoding to exactly 32 bytes. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for
        byte, so formatted JSON, whitespace and any non-canonical spelling
        are rejected too. The MAC is not verified here — pass the record
        to :func:`audit_map_history_evidence` with the shared key for
        that.
        """
        if not isinstance(data, bytes):
            raise TypeError("bit map history evidence data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"bit map history evidence is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 3:
            raise ValueError(
                "bit map history evidence must be a JSON array of exactly"
                " version, body and mac"
            )
        raw_version, raw_body, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError("bit map history evidence version must be an integer")
        if raw_version != 1:
            raise ValueError("bit map history evidence version must be 1")
        body = _parse_bit_map_hex(raw_body, "history body")
        mac = _parse_bit_map_hex(raw_mac, "history mac")
        if len(mac) != 32:
            raise ValueError(
                "bit map history evidence mac must decode to exactly 32 bytes"
            )
        record = cls(version=1, body=body, mac=mac)
        if record.to_bytes() != data:
            raise ValueError("bit map history evidence encoding is not canonical")
        return record


def _coerce_bit_map_history_evidence(
    x: object, name: str
) -> "BitMapHistoryEvidence":
    """Coerce a :class:`BitMapHistoryEvidence` or its canonical bytes,
    splitting the TypeError/ValueError contract exactly as the public
    auditors do: the wrong kind of argument raises :class:`TypeError`, a
    field-shape failure surfacing while parsing byte content of the right
    kind is a value error."""
    if isinstance(x, BitMapHistoryEvidence):
        return x
    if isinstance(x, bytes):
        try:
            return BitMapHistoryEvidence.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the bit map history evidence"
                " field contract"
            ) from error
    raise TypeError(
        f"{name} must be a BitMapHistoryEvidence instance or its canonical"
        " bytes"
    )


def seal_map_history(
    updates: object, key: object, *, checkpoint: object = None
) -> "BitMapHistoryEvidence":
    """Audit a contiguous :class:`BitMapUpdate` chain and seal it as evidence.

    ``updates``, ``key`` and the keyword-only ``checkpoint`` are validated
    exactly as :func:`audit_map_history` validates them — a non-iterable
    ``updates``, a non-``bytes`` ``key``, a wrong-typed item or a
    wrong-kind ``checkpoint`` raises :class:`TypeError`; an empty sequence,
    an empty key, a malformed or non-canonical encoding, a MAC mismatch, a
    failed per-update audit or a broken chain raises :class:`ValueError`.
    The whole chain is verified with :func:`audit_map_history` first and
    only on success is the evidence produced: the body carries the
    starting point (``""`` when ``checkpoint`` is ``None``, else the hex
    of its canonical :class:`BitMap` encoding), the canonical encoding of
    every update in order and the canonical encoding of the final table,
    MAC'd as ``HMAC-SHA256(key, b"NPBH1" + body)``. Sealing touches no
    gate or auditor state.
    """
    try:
        items = list(updates)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(
            "updates must be an iterable of BitMapUpdate instances or"
            " their canonical bytes"
        ) from None
    final = audit_map_history(items, key, checkpoint=checkpoint)
    coerced = [_coerce_bit_map_update(item, "updates items") for item in items]
    if checkpoint is None:
        start = b""
    elif isinstance(checkpoint, BitMap):
        start = checkpoint.to_bytes()
    else:
        # Canonical BitMap bytes, already validated by audit_map_history.
        start = checkpoint  # type: ignore[assignment]
    body = _encode_payload(
        [
            start.hex(),
            [update.to_bytes().hex() for update in coerced],
            final.to_bytes().hex(),
        ]
    )
    return BitMapHistoryEvidence(
        version=1,
        body=body,
        mac=_bit_map_history_evidence_mac(key, body),
    )


def audit_map_history_evidence(x: object, key: object) -> "BitMap":
    """Re-verify a :class:`BitMapHistoryEvidence` against ``key``.

    ``x`` must be a :class:`BitMapHistoryEvidence` or its canonical
    :meth:`BitMapHistoryEvidence.to_bytes` encoding and ``key`` the
    non-empty shared ``bytes`` key — a wrong-typed argument raises
    :class:`TypeError`, every other contract violation raises
    :class:`ValueError`. The evidence MAC is recomputed as
    ``HMAC-SHA256(key, b"NPBH1" + body)`` and compared in constant time,
    then the carried chain is re-audited from scratch with
    :func:`audit_map_history` — starting from no table when the body's
    ``start`` is empty and from the carried starting table otherwise —
    and the recomputed final table must equal the body's ``end`` byte for
    byte. Auditing is a pure check: it touches no gate or auditor state
    and returns no partial result — on success the frozen :class:`BitMap`
    of the final ``after`` is returned.
    """
    evidence = _coerce_bit_map_history_evidence(x, "x")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    if not hmac.compare_digest(
        _bit_map_history_evidence_mac(key, evidence.body), evidence.mac
    ):
        raise ValueError("bit map history evidence mac does not match")
    start, update_encodings, end = _bit_map_history_body_parts(evidence.body)
    updates = [
        BitMapUpdate.from_bytes(encoding) for encoding in update_encodings
    ]
    final = audit_map_history(
        updates, key, checkpoint=None if not start else start
    )
    if final.to_bytes() != end:
        raise ValueError(
            "bit map history evidence end does not match the audited chain"
        )
    return final


class BitMapHistoryEvidenceAuditor:
    """Stateful auditor chaining attested :class:`BitMapHistoryEvidence`
    segments into one monotone, restartable audit stream.

    ``key`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    shared key the tables, transition proofs and history evidence are
    MAC'd with. ``checkpoint`` is keyword-only: ``None`` (the default)
    starts from no table at all; otherwise it must be a :class:`BitMap` or
    its canonical :meth:`BitMap.to_bytes` encoding (any other type raises
    :class:`TypeError`), parsed under the full :class:`BitMap` contract and
    its ``NPBL1`` MAC recomputed with ``key`` and compared in constant time
    — a malformed encoding or MAC mismatch raises :class:`ValueError`.
    Across a restart the caller must pass the value previously exported at
    :attr:`checkpoint`; nothing is persisted by the auditor itself.

    Each :meth:`audit` re-verifies one :class:`BitMapHistoryEvidence` with
    :func:`audit_map_history_evidence` under the auditor lock — the
    evidence MAC, every carried update and the final table are all
    recomputed — and then demands the chain segment starts exactly where
    the auditor currently stands: with no checkpoint the body's ``start``
    must be the empty string, and with a checkpoint the ``start`` encoding
    must equal the checkpoint's canonical :meth:`BitMap.to_bytes` output
    byte for byte. Only when both checks pass is the checkpoint replaced
    with the body's ``end`` table, so a replayed already-advanced segment,
    a fork from an earlier starting point, a broken chain, a wrong key, a
    tampered or non-canonical encoding and a mismatched start all raise
    :class:`ValueError` and leave the checkpoint untouched. Concurrent
    audits linearize in lock-acquisition order: of competing segments
    chaining from the same starting point only the first to commit
    succeeds, and a committed segment is never lost.
    """

    def __init__(self, key: object, *, checkpoint: object = None) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must be non-empty")
        self._key = key
        self._lock = threading.Lock()
        self._table: "Optional[BitMap]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, BitMap):
            table = checkpoint
        elif isinstance(checkpoint, bytes):
            try:
                table = BitMap.from_bytes(checkpoint)
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error.
                raise ValueError(
                    "checkpoint does not satisfy the bit map field contract"
                ) from error
        else:
            raise TypeError(
                "checkpoint must be a BitMap instance, its canonical bytes,"
                " or None"
            )
        if not hmac.compare_digest(
            _bit_map_mac(self._key, _bit_map_payload(table.entries)),
            table.mac,
        ):
            raise ValueError("checkpoint mac does not match the key")
        self._table = table

    @property
    def checkpoint(self) -> "Optional[BitMap]":
        """The current frontier :class:`BitMap`, or ``None`` before the
        first successfully audited segment. The returned object is frozen
        and the property read-only; persist its :meth:`BitMap.to_bytes`
        output and pass it back to a new auditor to survive a restart."""
        return self._table

    def audit(self, x: object) -> "BitMap":
        """Audit one :class:`BitMapHistoryEvidence` segment and advance.

        ``x`` must be a :class:`BitMapHistoryEvidence` or its canonical
        :meth:`BitMapHistoryEvidence.to_bytes` encoding — any other type
        raises :class:`TypeError`; a malformed or non-canonical encoding,
        a MAC mismatch, a failed carried update, an ``end`` that does not
        match the audited chain, or a ``start`` that does not equal the
        current checkpoint (the empty string when no segment has committed
        yet) raises :class:`ValueError`. The evidence is re-verified with
        :func:`audit_map_history_evidence` and the start matched against
        the checkpoint under the auditor lock, so verification and the
        checkpoint advance are one atomic step: a failed segment changes
        nothing and returns no partial result, and concurrent segments are
        serialized in lock-acquisition order. On success the checkpoint is
        replaced with the segment's ``end`` table and that frozen
        :class:`BitMap` is returned.
        """
        with self._lock:
            evidence = _coerce_bit_map_history_evidence(x, "x")
            final = audit_map_history_evidence(evidence, self._key)
            start, _, _ = _bit_map_history_body_parts(evidence.body)
            current = b"" if self._table is None else self._table.to_bytes()
            if start != current:
                raise ValueError(
                    "bit map history evidence start does not match the"
                    " current checkpoint"
                )
            self._table = final
            return final


def _bit_map_history_journal_u64be(sequence: int) -> bytes:
    """The fixed 8-byte big-endian encoding of a non-bool u64 sequence."""
    return sequence.to_bytes(8, byteorder="big", signed=False)


def _bit_map_history_journal_content(state: "BitMapHistoryJournalState") -> list:
    """The JSON-ready first four state fields (everything but ``mac``)."""
    return [
        state.version,
        state.sequence,
        state.checkpoint.hex(),
        state.digest.hex(),
    ]


def _bit_map_history_journal_content_bytes(
    state: "BitMapHistoryJournalState",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four state fields."""
    return _encode_payload(_bit_map_history_journal_content(state))


def _bit_map_history_journal_mac(
    key: bytes, state: "BitMapHistoryJournalState"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ1" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_MAC_PREFIX
        + _bit_map_history_journal_content_bytes(state),
        hashlib.sha256,
    ).digest()


def _bit_map_history_journal_next_digest(
    previous: bytes, sequence: int, evidence: bytes
) -> bytes:
    """One digest-chain step: ``SHA256(b"NPBJ2" + d + u64be(n) + E)``.

    The prefix, the previous 32-byte digest, the fixed 8-byte big-endian
    sequence and the canonical evidence bytes are concatenated directly with
    no separator or length prefix."""
    return hashlib.sha256(
        _BIT_MAP_HISTORY_JOURNAL_DIGEST_PREFIX
        + previous
        + _bit_map_history_journal_u64be(sequence)
        + evidence
    ).digest()


def _require_bit_map_history_journal_checkpoint(value: bytes) -> None:
    """Enforce that a state ``checkpoint`` is the canonical non-empty
    :class:`BitMap` encoding. ``value`` is already known to be ``bytes``;
    :meth:`BitMap.from_bytes` enforces the full contract including its
    canonical re-encoding check, and every violation — including the
    field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        BitMap.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "bit map history journal state checkpoint must be the canonical"
            " BitMap encoding"
        ) from error


@dataclass(frozen=True)
class BitMapHistoryJournalState:
    """A key-MAC'd, digest-chained checkpoint of the audited history stream.

    ``version`` is always ``1``; ``sequence`` a non-bool unsigned 64-bit
    integer (the number of audited :class:`BitMapHistoryEvidence` segments);
    ``checkpoint`` the canonical non-empty :meth:`BitMap.to_bytes` encoding
    of the table the audited chain currently ends at; ``digest`` exactly 32
    bytes — the head of a hash chain with ``d0`` fixed at 32 zero bytes and
    each accepted segment extending it as
    ``d' = SHA256(b"NPBJ2" + d + u64be(n) + E)`` where ``n`` is the new
    sequence, ``u64be(n)`` its fixed 8-byte big-endian encoding and ``E``
    the canonical :meth:`BitMapHistoryEvidence.to_bytes` bytes, every part
    concatenated directly with no separator or length prefix; ``mac``
    exactly 32 bytes — ``HMAC-SHA256(key, b"NPBJ1" + C)`` where ``C`` is the
    canonical compact encoding of the first four fields (the version,
    sequence, lowercase-hex checkpoint and lowercase-hex digest, without
    ``mac``), the prefix and ``C`` concatenated directly with no separator
    or length prefix. Instances are frozen, constructed positionally in
    field order and compare equal by their fields. A field of the wrong
    type raises :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    sequence: int
    checkpoint: bytes
    digest: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "bit map history journal state version must be an integer"
            )
        if self.version != 1:
            raise ValueError("bit map history journal state version must be 1")
        if isinstance(self.sequence, bool) or type(self.sequence) is not int:
            raise TypeError(
                "bit map history journal state sequence must be a non-bool"
                " integer"
            )
        if not 0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit map history journal state sequence must fit in an"
                " unsigned 64-bit integer"
            )
        if not isinstance(self.checkpoint, bytes):
            raise TypeError(
                "bit map history journal state checkpoint must be bytes"
            )
        _require_bit_map_history_journal_checkpoint(self.checkpoint)
        for name in ("digest", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(
                    f"bit map history journal state {name} must be bytes"
                )
            if len(value) != 32:
                raise ValueError(
                    f"bit map history journal state {name} must be exactly 32"
                    " bytes"
                )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, sequence, checkpoint, digest, mac]`` where ``checkpoint``,
        ``digest`` and ``mac`` are lowercase hex, no whitespace, no length
        prefix."""
        return _encode_payload(
            _bit_map_history_journal_content(self) + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMapHistoryJournalState":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and for
        fields of the wrong type; raises :class:`ValueError` for anything
        that does not satisfy the value contract: an array of exactly
        ``[version, sequence, checkpoint, digest, mac]`` in that order,
        ``version == 1``, ``sequence`` a non-bool u64, ``checkpoint`` a
        lowercase hex string decoding to the canonical non-empty
        :class:`BitMap` encoding, and ``digest``/``mac`` lowercase hex
        strings decoding to exactly 32 bytes each. After parsing and field
        validation the record is re-encoded with :meth:`to_bytes` and the
        result must equal the input byte for byte, so formatted JSON,
        whitespace and any non-canonical spelling are rejected too. Neither
        the :class:`BitMap` checkpoint MAC, the digest chain nor the state
        MAC is verified here — pass the encoding to
        :class:`BitMapHistoryJournalAuditor` for that.
        """
        if not isinstance(data, bytes):
            raise TypeError(
                "bit map history journal state data must be bytes"
            )
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"bit map history journal state is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "bit map history journal state must be a JSON array of"
                " exactly version, sequence, checkpoint, digest and mac"
            )
        raw_version, raw_sequence, raw_checkpoint, raw_digest, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "bit map history journal state version must be an integer"
            )
        if raw_version != 1:
            raise ValueError("bit map history journal state version must be 1")
        if type(raw_sequence) is not int:
            raise TypeError(
                "bit map history journal state sequence must be a non-bool"
                " integer"
            )
        if not 0 <= raw_sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit map history journal state sequence must fit in an"
                " unsigned 64-bit integer"
            )
        checkpoint = _parse_bit_map_hex(raw_checkpoint, "journal checkpoint")
        _require_bit_map_history_journal_checkpoint(checkpoint)
        digest = _parse_bit_map_hex(raw_digest, "journal digest")
        if len(digest) != 32:
            raise ValueError(
                "bit map history journal state digest must decode to exactly"
                " 32 bytes"
            )
        mac = _parse_bit_map_hex(raw_mac, "journal mac")
        if len(mac) != 32:
            raise ValueError(
                "bit map history journal state mac must decode to exactly 32"
                " bytes"
            )
        record = cls(
            version=1,
            sequence=raw_sequence,
            checkpoint=checkpoint,
            digest=digest,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "bit map history journal state encoding is not canonical"
            )
        return record


class BitMapHistoryJournalAuditor:
    """Stateful auditor chaining attested :class:`BitMapHistoryEvidence`
    segments into one monotone, restartable, sequence-numbered journal.

    ``key`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    shared key the tables, transition proofs, history evidence and journal
    states are MAC'd with. ``state`` is keyword-only: ``None`` (the default)
    starts from sequence zero and no table at all, with the digest chain
    rooted at ``d0`` (32 zero bytes); otherwise it must be a
    :class:`BitMapHistoryJournalState` or its canonical
    :meth:`BitMapHistoryJournalState.to_bytes` encoding (any other type
    raises :class:`TypeError`). A supplied state is checked at two MAC
    layers, both compared in constant time: its checkpoint is parsed under
    the full :class:`BitMap` contract and its ``NPBL1`` MAC recomputed with
    ``key``, and the state's own ``NPBJ1`` MAC is recomputed over the
    canonical encoding of its first four fields — a malformed encoding or
    either MAC mismatch raises :class:`ValueError`. Across a restart the
    caller must pass the value previously exported at :attr:`state`;
    nothing is persisted by the auditor itself.

    Each :meth:`audit` accepts one :class:`BitMapHistoryEvidence` (or its
    canonical bytes) and, under the auditor lock, re-verifies it exactly
    like :func:`audit_map_history_evidence` — the ``NPBH1`` evidence MAC,
    every carried ``NPBU1``/``NPBL1`` MAC and the whole chain are
    recomputed — and then demands the segment starts exactly where the
    journal currently stands: with no state the body's ``start`` must be
    the empty string, and otherwise it must equal the state checkpoint's
    canonical :meth:`BitMap.to_bytes` bytes. Only then does the journal
    advance: ``n`` is the old sequence plus one, the new checkpoint is the
    segment's ``end`` table, the new digest is
    ``SHA256(b"NPBJ2" + d + u64be(n) + E)`` over the previous digest, the
    fixed 8-byte big-endian ``n`` and the canonical evidence bytes, and the
    new state is MAC'd as ``HMAC-SHA256(key, b"NPBJ1" + C)``. Verification
    and the state advance are one atomic step: a failed segment raises
    :class:`ValueError` and leaves the state untouched, and concurrent
    audits linearize in lock-acquisition order so a committed segment is
    never lost.

    :meth:`audit_bundle` accepts one whole
    :class:`BitMapHistoryJournalBundle` (or its canonical bytes) and commits
    its entire evidence chain as a single atomic step under the same lock,
    replaying onto a tentative state and replacing :attr:`state` only once
    every segment has verified and the replayed final state equals the
    bundle's ``end`` byte for byte.
    """

    def __init__(self, key: object, *, state: object = None) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must be non-empty")
        self._key = key
        self._lock = threading.Lock()
        self._state: "Optional[BitMapHistoryJournalState]" = None
        if state is None:
            return
        if isinstance(state, BitMapHistoryJournalState):
            journal = state
        elif isinstance(state, bytes):
            try:
                journal = BitMapHistoryJournalState.from_bytes(state)
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error.
                raise ValueError(
                    "state does not satisfy the bit map history journal state"
                    " field contract"
                ) from error
        else:
            raise TypeError(
                "state must be a BitMapHistoryJournalState instance, its"
                " canonical bytes, or None"
            )
        # Two MAC layers, both always recomputed and each compared in
        # constant time before either result is consulted.
        table = BitMap.from_bytes(journal.checkpoint)
        checkpoint_mac_ok = hmac.compare_digest(
            _bit_map_mac(self._key, _bit_map_payload(table.entries)),
            table.mac,
        )
        state_mac_ok = hmac.compare_digest(
            _bit_map_history_journal_mac(self._key, journal), journal.mac
        )
        if not checkpoint_mac_ok or not state_mac_ok:
            raise ValueError("journal state mac does not match the key")
        self._state = journal

    @property
    def state(self) -> "Optional[BitMapHistoryJournalState]":
        """The current journal :class:`BitMapHistoryJournalState`, or
        ``None`` before the first successfully audited segment. The
        returned object is frozen and the property read-only; persist its
        :meth:`BitMapHistoryJournalState.to_bytes` output and pass it back
        to a new auditor to survive a restart."""
        return self._state

    def audit(self, x: object) -> "BitMapHistoryJournalAuditor":
        """Audit one :class:`BitMapHistoryEvidence` segment and advance.

        ``x`` must be a :class:`BitMapHistoryEvidence` or its canonical
        :meth:`BitMapHistoryEvidence.to_bytes` encoding — any other type
        raises :class:`TypeError`; a malformed or non-canonical encoding,
        a MAC mismatch, a failed carried update, an ``end`` that does not
        match the audited chain, a sequence that would overflow u64, or a
        ``start`` that does not equal the current checkpoint (the empty
        string when no segment has committed yet) raises
        :class:`ValueError`. The evidence is re-verified and the start
        matched against the checkpoint under the auditor lock, and the
        sequence, digest-chain head, checkpoint table and state MAC are all
        advanced in the same atomic step, so a failed segment changes
        nothing and concurrent segments are serialized in lock-acquisition
        order. Returns the auditor itself.
        """
        with self._lock:
            evidence = _coerce_bit_map_history_evidence(x, "x")
            final = audit_map_history_evidence(evidence, self._key)
            start, _, _ = _bit_map_history_body_parts(evidence.body)
            current = (
                b"" if self._state is None else self._state.checkpoint
            )
            if start != current:
                raise ValueError(
                    "bit map history evidence start does not match the"
                    " journal checkpoint"
                )
            previous_sequence = 0 if self._state is None else self._state.sequence
            if previous_sequence >= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(
                    "bit map history journal sequence would overflow the"
                    " unsigned 64-bit range"
                )
            sequence = previous_sequence + 1
            previous_digest = (
                b"\x00" * 32 if self._state is None else self._state.digest
            )
            digest = _bit_map_history_journal_next_digest(
                previous_digest, sequence, evidence.to_bytes()
            )
            candidate = BitMapHistoryJournalState(
                version=1,
                sequence=sequence,
                checkpoint=final.to_bytes(),
                digest=digest,
                mac=b"\x00" * 32,
            )
            self._state = replace(
                candidate,
                mac=_bit_map_history_journal_mac(self._key, candidate),
            )
            return self

    def audit_bundle(self, x: object) -> "BitMapHistoryJournalAuditor":
        """Atomically audit one whole :class:`BitMapHistoryJournalBundle`
        and advance the journal to its ``end`` state.

        ``x`` must be a :class:`BitMapHistoryJournalBundle` or its canonical
        :meth:`BitMapHistoryJournalBundle.to_bytes` encoding — any other
        type raises :class:`TypeError`; every other contract violation
        raises :class:`ValueError`. Everything runs under the auditor lock
        as one atomic step, in this order:

        1. the bundle is parsed per its canonical contract and its
           ``NPBJ3`` MAC recomputed as
           ``HMAC-SHA256(key, b"NPBJ3" + C)`` and compared in constant
           time;
        2. the non-empty ``start`` state and the ``end`` state each have
           both MAC layers recomputed — the embedded checkpoint table's
           ``NPBL1`` MAC and the state's own ``NPBJ1`` MAC — each compared
           in constant time, and no replay begins until both layers of
           both endpoints pass;
        3. the bundle ``start`` must equal the current journal state byte
           for byte: an empty auditor accepts only ``start == b""`` and a
           non-empty auditor demands ``start == state.to_bytes()``;
        4. the carried segments are replayed in order onto a tentative
           journal state only — each segment's ``NPBH1`` evidence MAC and
           every inner ``NPBU1``/``NPBL1`` MAC are re-verified exactly as
           in :meth:`audit`, its body ``start`` must continue byte for
           byte from the tentative checkpoint, the u64 sequence must not
           overflow and the digest advances as
           ``SHA256(b"NPBJ2" + d + u64be(n) + E)``;
        5. only when every segment verifies and the tentative final state's
           canonical bytes equal the bundle ``end`` byte for byte is the
           read-only :attr:`state` replaced with the tentative state.

        Any failure raises :class:`ValueError` and leaves the journal
        state untouched; re-submitting an already committed bundle is
        rejected because its ``start`` no longer matches the advanced
        state, and concurrent :meth:`audit`/:meth:`audit_bundle` calls
        linearize in lock-acquisition order so a committed chain is never
        lost or partially applied. Returns the auditor itself.
        """
        with self._lock:
            self._audit_bundle_locked(x)
            return self

    def _audit_bundle_locked(
        self, x: object
    ) -> "BitMapHistoryJournalBundle":
        """The lock-held body of :meth:`audit_bundle`: verify and commit
        one whole bundle, returning the coerced bundle. The caller must
        hold the auditor lock; every failure raises before any state
        change."""
        bundle = _coerce_bit_map_history_journal_bundle(x, "x")
        if not hmac.compare_digest(
            _bit_map_history_journal_bundle_mac(self._key, bundle),
            bundle.mac,
        ):
            raise ValueError(
                "bit map history journal bundle mac does not match"
            )
        start_state: "Optional[BitMapHistoryJournalState]" = None
        if bundle.start:
            start_state = BitMapHistoryJournalState.from_bytes(
                bundle.start
            )
            _verify_bit_map_history_journal_state_macs(
                self._key, start_state, "start"
            )
        end_state = BitMapHistoryJournalState.from_bytes(bundle.end)
        _verify_bit_map_history_journal_state_macs(
            self._key, end_state, "end"
        )
        current = (
            b"" if self._state is None else self._state.to_bytes()
        )
        if bundle.start != current:
            raise ValueError(
                "bit map history journal bundle start does not match"
                " the journal state"
            )
        candidate = _replay_bit_map_history_journal_bundle(
            self._key, start_state, bundle.evidences
        )
        if candidate.to_bytes() != bundle.end:
            raise ValueError(
                "bit map history journal bundle end does not match the"
                " replayed chain"
            )
        self._state = candidate
        return bundle

    def audit_bundle_receipt(
        self, x: object
    ) -> "BitMapHistoryJournalReceipt":
        """Atomically commit one whole :class:`BitMapHistoryJournalBundle`
        exactly like :meth:`audit_bundle` and return a
        :class:`BitMapHistoryJournalReceipt` attesting the commit.

        ``x`` follows the same contract as :meth:`audit_bundle` — a
        :class:`BitMapHistoryJournalBundle` or its canonical bytes; any
        other type raises :class:`TypeError`, every other contract
        violation raises :class:`ValueError`. Verification and the state
        advance run under the same auditor lock as
        :meth:`audit`/:meth:`audit_bundle`, so concurrent calls linearize
        in lock-acquisition order; the receipt is produced only after the
        commit succeeds, and any failure leaves the journal state
        untouched and produces no receipt. The returned receipt carries
        the bundle's ``start`` and ``end``, the digest
        ``SHA256(bundle.to_bytes())`` and the MAC
        ``HMAC-SHA256(key, b"NPBJ4" + C)`` over the canonical encoding of
        the first four fields. The legacy :meth:`audit_bundle` interface
        is unchanged.
        """
        with self._lock:
            bundle = self._audit_bundle_locked(x)
            receipt = BitMapHistoryJournalReceipt(
                version=1,
                start=bundle.start,
                bundle_digest=hashlib.sha256(bundle.to_bytes()).digest(),
                end=bundle.end,
                mac=b"\x00" * 32,
            )
            return replace(
                receipt,
                mac=_bit_map_history_journal_receipt_mac(
                    self._key, receipt
                ),
            )


def _require_bit_map_history_journal_state_encoding(
    value: bytes, name: str, allow_empty: bool
) -> None:
    """Enforce the canonical-:class:`BitMapHistoryJournalState`-bytes
    contract of a bundle endpoint.

    ``value`` is already known to be ``bytes``; when ``allow_empty`` holds,
    ``b""`` (the chain starts from the empty journal) is also accepted.
    :meth:`BitMapHistoryJournalState.from_bytes` enforces the full contract
    including its canonical re-encoding check, and every violation —
    including the field-shape :class:`TypeError` a malformed inner document
    would otherwise surface — raises :class:`ValueError`."""
    if allow_empty and value == b"":
        return
    try:
        BitMapHistoryJournalState.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"bit map history journal bundle {name} must be the canonical"
            " BitMapHistoryJournalState encoding"
        ) from error


def _require_bit_map_history_journal_bundle_evidence(value: bytes) -> None:
    """Enforce the canonical-:class:`BitMapHistoryEvidence`-bytes contract
    of a bundle ``evidences`` item.

    ``value`` is already known to be ``bytes``; every violation — including
    the field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        BitMapHistoryEvidence.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "bit map history journal bundle evidences items must be the"
            " canonical BitMapHistoryEvidence encoding"
        ) from error


def _bit_map_history_journal_bundle_content(
    bundle: "BitMapHistoryJournalBundle",
) -> list:
    """The JSON-ready first four bundle fields (everything but ``mac``)."""
    return [
        bundle.version,
        bundle.start.hex(),
        [evidence.hex() for evidence in bundle.evidences],
        bundle.end.hex(),
    ]


def _bit_map_history_journal_bundle_content_bytes(
    bundle: "BitMapHistoryJournalBundle",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four bundle fields."""
    return _encode_payload(_bit_map_history_journal_bundle_content(bundle))


def _bit_map_history_journal_bundle_mac(
    key: bytes, bundle: "BitMapHistoryJournalBundle"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ3" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_BUNDLE_PREFIX
        + _bit_map_history_journal_bundle_content_bytes(bundle),
        hashlib.sha256,
    ).digest()


@dataclass(frozen=True)
class BitMapHistoryJournalBundle:
    """A key-MAC'd attestation sealing one contiguous
    :class:`BitMapHistoryEvidence` chain against the journal.

    ``version`` is always ``1``. ``start`` is the canonical
    :meth:`BitMapHistoryJournalState.to_bytes` encoding of the journal state
    the chain starts from, or ``b""`` when the chain starts from the empty
    journal (sequence zero, no table, the digest chain rooted at ``d0``).
    ``evidences`` is a non-empty ordered tuple of canonical
    :meth:`BitMapHistoryEvidence.to_bytes` bytes — the segments to replay in
    order. ``end`` is the canonical non-empty
    :meth:`BitMapHistoryJournalState.to_bytes` encoding of the journal state
    the chain ends at. ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBJ3" + C)`` where ``C`` is the canonical compact
    encoding of the first four fields (the version, the lowercase-hex start,
    the array of lowercase-hex evidence encodings and the lowercase-hex end,
    without ``mac``), the prefix and ``C`` concatenated directly with no
    separator or length prefix. Instances are frozen, constructed
    positionally in field order and compare equal by their fields. A field
    of the wrong type raises :class:`TypeError`; every other contract
    violation raises :class:`ValueError`. No key material is stored.
    """

    version: int
    start: bytes
    evidences: tuple
    end: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "bit map history journal bundle version must be an integer"
            )
        if self.version != 1:
            raise ValueError(
                "bit map history journal bundle version must be 1"
            )
        if not isinstance(self.start, bytes):
            raise TypeError(
                "bit map history journal bundle start must be bytes"
            )
        _require_bit_map_history_journal_state_encoding(
            self.start, "start", allow_empty=True
        )
        if not isinstance(self.evidences, tuple):
            raise TypeError(
                "bit map history journal bundle evidences must be a tuple"
            )
        if not self.evidences:
            raise ValueError(
                "bit map history journal bundle evidences must be non-empty"
            )
        for evidence in self.evidences:
            if not isinstance(evidence, bytes):
                raise TypeError(
                    "bit map history journal bundle evidences items must be"
                    " bytes"
                )
            _require_bit_map_history_journal_bundle_evidence(evidence)
        if not isinstance(self.end, bytes):
            raise TypeError("bit map history journal bundle end must be bytes")
        _require_bit_map_history_journal_state_encoding(
            self.end, "end", allow_empty=False
        )
        if not isinstance(self.mac, bytes):
            raise TypeError("bit map history journal bundle mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError(
                "bit map history journal bundle mac must be exactly 32 bytes"
            )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, start, evidences, end, mac]`` where ``start``, ``end`` and
        ``mac`` are lowercase hex and ``evidences`` is the array of the
        lowercase-hex canonical evidence encodings, no whitespace, no length
        prefix."""
        return _encode_payload(
            _bit_map_history_journal_bundle_content(self) + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMapHistoryJournalBundle":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and for
        fields of the wrong type; raises :class:`ValueError` for anything
        that does not satisfy the value contract: an array of exactly
        ``[version, start, evidences, end, mac]`` in that order,
        ``version == 1``, ``start`` a lowercase hex string that is empty or
        decodes to the canonical :class:`BitMapHistoryJournalState` encoding,
        ``evidences`` a non-empty array of lowercase hex strings each
        decoding to the canonical :class:`BitMapHistoryEvidence` encoding,
        ``end`` a lowercase hex string decoding to the canonical
        :class:`BitMapHistoryJournalState` encoding and ``mac`` a lowercase
        hex string decoding to exactly 32 bytes. After parsing and field
        validation the record is re-encoded with :meth:`to_bytes` and the
        result must equal the input byte for byte, so formatted JSON,
        whitespace and any non-canonical spelling are rejected too. No MAC
        is verified here — neither the bundle MAC nor the endpoint state
        MACs; pass the record to :func:`audit_map_history_journal_bundle`
        with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("bit map history journal bundle data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"bit map history journal bundle is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "bit map history journal bundle must be a JSON array of"
                " exactly version, start, evidences, end and mac"
            )
        raw_version, raw_start, raw_evidences, raw_end, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "bit map history journal bundle version must be an integer"
            )
        if raw_version != 1:
            raise ValueError(
                "bit map history journal bundle version must be 1"
            )
        start = _parse_bit_map_hex(raw_start, "journal bundle start")
        _require_bit_map_history_journal_state_encoding(
            start, "start", allow_empty=True
        )
        if not isinstance(raw_evidences, list):
            raise TypeError(
                "bit map history journal bundle evidences must be an array"
            )
        if not raw_evidences:
            raise ValueError(
                "bit map history journal bundle evidences must be non-empty"
            )
        evidences = tuple(
            _parse_bit_map_hex(raw_evidence, "journal bundle evidence")
            for raw_evidence in raw_evidences
        )
        for evidence in evidences:
            _require_bit_map_history_journal_bundle_evidence(evidence)
        end = _parse_bit_map_hex(raw_end, "journal bundle end")
        _require_bit_map_history_journal_state_encoding(
            end, "end", allow_empty=False
        )
        mac = _parse_bit_map_hex(raw_mac, "journal bundle mac")
        if len(mac) != 32:
            raise ValueError(
                "bit map history journal bundle mac must decode to exactly 32"
                " bytes"
            )
        record = cls(
            version=1,
            start=start,
            evidences=evidences,
            end=end,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "bit map history journal bundle encoding is not canonical"
            )
        return record


def _coerce_bit_map_history_journal_bundle(
    x: object, name: str
) -> "BitMapHistoryJournalBundle":
    """Coerce a :class:`BitMapHistoryJournalBundle` or its canonical bytes,
    splitting the TypeError/ValueError contract exactly as the public
    auditors do: the wrong kind of argument raises :class:`TypeError`, a
    field-shape failure surfacing while parsing byte content of the right
    kind is a value error."""
    if isinstance(x, BitMapHistoryJournalBundle):
        return x
    if isinstance(x, bytes):
        try:
            return BitMapHistoryJournalBundle.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the bit map history journal bundle"
                " field contract"
            ) from error
    raise TypeError(
        f"{name} must be a BitMapHistoryJournalBundle instance or its"
        " canonical bytes"
    )


def _verify_bit_map_history_journal_state_macs(
    key: bytes, journal: "BitMapHistoryJournalState", name: str
) -> None:
    """Recompute both MAC layers of a parsed journal state — the checkpoint
    table's ``NPBL1`` MAC and the state's own ``NPBJ1`` MAC. Both layers are
    always recomputed and each compared in constant time before either
    result is consulted."""
    table = BitMap.from_bytes(journal.checkpoint)
    checkpoint_mac_ok = hmac.compare_digest(
        _bit_map_mac(key, _bit_map_payload(table.entries)),
        table.mac,
    )
    state_mac_ok = hmac.compare_digest(
        _bit_map_history_journal_mac(key, journal), journal.mac
    )
    if not checkpoint_mac_ok or not state_mac_ok:
        raise ValueError(
            f"bit map history journal bundle {name} mac does not match the"
            " key"
        )


def _replay_bit_map_history_journal_bundle(
    key: bytes,
    journal: "Optional[BitMapHistoryJournalState]",
    evidence_encodings: "tuple[bytes, ...]",
) -> "BitMapHistoryJournalState":
    """Replay a bundle's evidence chain onto a tentative journal state.

    ``journal`` is the parsed and MAC-verified starting state or ``None``
    for the empty journal (sequence zero, no table, digest rooted at
    ``d0``). Each carried encoding is re-parsed and audited exactly as
    :meth:`BitMapHistoryJournalAuditor.audit` audits it — the ``NPBH1``
    evidence MAC and every inner ``NPBU1``/``NPBL1`` MAC are recomputed —
    and the body ``start`` must continue byte for byte from the tentative
    checkpoint before the u64 sequence, digest-chain head, checkpoint
    table and state MAC advance. The replay touches no shared state: the
    caller adopts the returned tentative state only after its own endpoint
    comparison, and every failure raises :class:`ValueError`.
    """
    for encoding in evidence_encodings:
        evidence = BitMapHistoryEvidence.from_bytes(encoding)
        final = audit_map_history_evidence(evidence, key)
        start, _, _ = _bit_map_history_body_parts(evidence.body)
        current = b"" if journal is None else journal.checkpoint
        if start != current:
            raise ValueError(
                "bit map history evidence start does not match the"
                " journal checkpoint"
            )
        previous_sequence = 0 if journal is None else journal.sequence
        if previous_sequence >= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit map history journal sequence would overflow the"
                " unsigned 64-bit range"
            )
        sequence = previous_sequence + 1
        previous_digest = (
            b"\x00" * 32 if journal is None else journal.digest
        )
        digest = _bit_map_history_journal_next_digest(
            previous_digest, sequence, evidence.to_bytes()
        )
        candidate = BitMapHistoryJournalState(
            version=1,
            sequence=sequence,
            checkpoint=final.to_bytes(),
            digest=digest,
            mac=b"\x00" * 32,
        )
        journal = replace(
            candidate,
            mac=_bit_map_history_journal_mac(key, candidate),
        )
    # The bundle contract guarantees a non-empty chain, so the result is
    # always a concrete state.
    return journal  # type: ignore[return-value]


def seal_map_history_journal_bundle(
    evidences: object, key: object, *, state: object = None
) -> "BitMapHistoryJournalBundle":
    """Audit a contiguous :class:`BitMapHistoryEvidence` chain against the
    journal and seal it as a bundle.

    ``evidences`` must be a non-empty iterable whose items are each a
    :class:`BitMapHistoryEvidence` or its canonical
    :meth:`BitMapHistoryEvidence.to_bytes` encoding, and ``key`` the
    non-empty shared ``bytes`` key. ``state`` is keyword-only: ``None``
    (the default) starts the chain from the empty journal — sequence zero,
    no table, the digest chain rooted at ``d0`` — otherwise it must be a
    :class:`BitMapHistoryJournalState` or its canonical
    :meth:`BitMapHistoryJournalState.to_bytes` encoding. A non-iterable
    ``evidences``, a non-``bytes`` ``key``, a wrong-typed item or a
    wrong-kind ``state`` raises :class:`TypeError`; an empty sequence, an
    empty key, a malformed or non-canonical encoding, a MAC mismatch, a
    failed segment audit, a sequence overflow or a broken chain raises
    :class:`ValueError`. The whole chain is verified first — exactly as
    :class:`BitMapHistoryJournalAuditor` audits it, starting from the
    supplied state — and only on success is the bundle produced: ``start``
    carries the starting point (``b""`` when ``state`` is ``None``, else
    the state's canonical encoding), ``evidences`` the canonical encoding
    of every segment in order and ``end`` the canonical encoding of the
    final journal state, MAC'd as ``HMAC-SHA256(key, b"NPBJ3" + C)``.
    Sealing touches no auditor state.
    """
    try:
        items = list(evidences)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(
            "evidences must be an iterable of BitMapHistoryEvidence instances"
            " or their canonical bytes"
        ) from None
    auditor = BitMapHistoryJournalAuditor(key, state=state)
    coerced = [
        _coerce_bit_map_history_evidence(item, "evidences items")
        for item in items
    ]
    if not coerced:
        raise ValueError("evidences must be a non-empty sequence")
    for evidence in coerced:
        auditor.audit(evidence)
    if state is None:
        start = b""
    elif isinstance(state, BitMapHistoryJournalState):
        start = state.to_bytes()
    else:
        # Canonical BitMapHistoryJournalState bytes, already validated by the
        # auditor constructor.
        start = state  # type: ignore[assignment]
    final = auditor.state
    bundle = BitMapHistoryJournalBundle(
        version=1,
        start=start,
        evidences=tuple(evidence.to_bytes() for evidence in coerced),
        end=final.to_bytes(),  # type: ignore[union-attr]
        mac=b"\x00" * 32,
    )
    return replace(
        bundle, mac=_bit_map_history_journal_bundle_mac(key, bundle)
    )


def audit_map_history_journal_bundle(
    x: object, key: object
) -> "BitMapHistoryJournalState":
    """Re-verify a :class:`BitMapHistoryJournalBundle` against ``key``.

    ``x`` must be a :class:`BitMapHistoryJournalBundle` or its canonical
    :meth:`BitMapHistoryJournalBundle.to_bytes` encoding and ``key`` the
    non-empty shared ``bytes`` key — a wrong-typed argument raises
    :class:`TypeError`, every other contract violation raises
    :class:`ValueError`. The bundle MAC is recomputed as
    ``HMAC-SHA256(key, b"NPBJ3" + C)`` and compared in constant time; then
    both endpoint states are checked at two MAC layers each — the
    checkpoint table's ``NPBL1`` MAC and the state's own ``NPBJ1`` MAC,
    both always recomputed and each compared in constant time — and finally
    the carried segments are replayed one by one exactly as
    :class:`BitMapHistoryJournalAuditor` audits them, starting from the
    empty journal when ``start`` is empty and from the carried starting
    state otherwise; the replayed final state must equal the bundle's
    ``end`` byte for byte. Auditing is a pure check: it touches no auditor
    state and returns no partial result — on success the frozen
    :class:`BitMapHistoryJournalState` the chain ends at is returned.
    """
    bundle = _coerce_bit_map_history_journal_bundle(x, "x")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    if not hmac.compare_digest(
        _bit_map_history_journal_bundle_mac(key, bundle), bundle.mac
    ):
        raise ValueError("bit map history journal bundle mac does not match")
    if bundle.start:
        _verify_bit_map_history_journal_state_macs(
            key, BitMapHistoryJournalState.from_bytes(bundle.start), "start"
        )
    _verify_bit_map_history_journal_state_macs(
        key, BitMapHistoryJournalState.from_bytes(bundle.end), "end"
    )
    auditor = BitMapHistoryJournalAuditor(
        key, state=bundle.start if bundle.start else None
    )
    for evidence in bundle.evidences:
        auditor.audit(evidence)
    final = auditor.state
    if final is None or final.to_bytes() != bundle.end:
        raise ValueError(
            "bit map history journal bundle end does not match the replayed"
            " chain"
        )
    return final


def _bit_map_history_journal_receipt_content(
    receipt: "BitMapHistoryJournalReceipt",
) -> list:
    """The JSON-ready first four receipt fields (everything but ``mac``)."""
    return [
        receipt.version,
        receipt.start.hex(),
        receipt.bundle_digest.hex(),
        receipt.end.hex(),
    ]


def _bit_map_history_journal_receipt_content_bytes(
    receipt: "BitMapHistoryJournalReceipt",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four receipt fields."""
    return _encode_payload(_bit_map_history_journal_receipt_content(receipt))


def _bit_map_history_journal_receipt_mac(
    key: bytes, receipt: "BitMapHistoryJournalReceipt"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ4" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_RECEIPT_PREFIX
        + _bit_map_history_journal_receipt_content_bytes(receipt),
        hashlib.sha256,
    ).digest()


@dataclass(frozen=True)
class BitMapHistoryJournalReceipt:
    """A key-MAC'd receipt attesting one committed
    :class:`BitMapHistoryJournalBundle`.

    ``version`` is always ``1``. ``start`` is the canonical
    :meth:`BitMapHistoryJournalState.to_bytes` encoding of the journal
    state the committed chain started from, or ``b""`` when it started
    from the empty journal. ``bundle_digest`` is exactly 32 bytes —
    ``SHA256(bundle.to_bytes())`` over the canonical encoding of the
    committed bundle. ``end`` is the canonical non-empty
    :meth:`BitMapHistoryJournalState.to_bytes` encoding of the journal
    state the chain ended at. ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBJ4" + C)`` where ``C`` is the canonical
    compact encoding of the first four fields (the version, the
    lowercase-hex start, the lowercase-hex bundle digest and the
    lowercase-hex end, without ``mac``), the prefix and ``C`` concatenated
    directly with no separator or length prefix. Instances are frozen,
    constructed positionally in field order and compare equal by their
    fields. A field of the wrong type raises :class:`TypeError`; every
    other contract violation raises :class:`ValueError`. No key material
    is stored.
    """

    version: int
    start: bytes
    bundle_digest: bytes
    end: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "bit map history journal receipt version must be an integer"
            )
        if self.version != 1:
            raise ValueError(
                "bit map history journal receipt version must be 1"
            )
        if not isinstance(self.start, bytes):
            raise TypeError(
                "bit map history journal receipt start must be bytes"
            )
        _require_bit_map_history_journal_state_encoding(
            self.start, "start", allow_empty=True
        )
        if not isinstance(self.bundle_digest, bytes):
            raise TypeError(
                "bit map history journal receipt bundle_digest must be bytes"
            )
        if len(self.bundle_digest) != 32:
            raise ValueError(
                "bit map history journal receipt bundle_digest must be"
                " exactly 32 bytes"
            )
        if not isinstance(self.end, bytes):
            raise TypeError(
                "bit map history journal receipt end must be bytes"
            )
        _require_bit_map_history_journal_state_encoding(
            self.end, "end", allow_empty=False
        )
        if not isinstance(self.mac, bytes):
            raise TypeError(
                "bit map history journal receipt mac must be bytes"
            )
        if len(self.mac) != 32:
            raise ValueError(
                "bit map history journal receipt mac must be exactly 32"
                " bytes"
            )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, start, bundle_digest, end, mac]`` where ``start``,
        ``bundle_digest``, ``end`` and ``mac`` are lowercase hex, no
        whitespace, no length prefix."""
        return _encode_payload(
            _bit_map_history_journal_receipt_content(self) + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMapHistoryJournalReceipt":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, start, bundle_digest, end, mac]`` in that
        order, ``version == 1``, ``start`` a lowercase hex string that is
        empty or decodes to the canonical
        :class:`BitMapHistoryJournalState` encoding, ``bundle_digest`` a
        lowercase hex string decoding to exactly 32 bytes, ``end`` a
        lowercase hex string decoding to the canonical
        :class:`BitMapHistoryJournalState` encoding and ``mac`` a
        lowercase hex string decoding to exactly 32 bytes. After parsing
        and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for
        byte, so formatted JSON, whitespace and any non-canonical
        spelling are rejected too. No MAC is verified here — pass the
        record to :func:`audit_map_history_journal_receipt` with the
        shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError(
                "bit map history journal receipt data must be bytes"
            )
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"bit map history journal receipt is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "bit map history journal receipt must be a JSON array of"
                " exactly version, start, bundle_digest, end and mac"
            )
        raw_version, raw_start, raw_digest, raw_end, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "bit map history journal receipt version must be an integer"
            )
        if raw_version != 1:
            raise ValueError(
                "bit map history journal receipt version must be 1"
            )
        start = _parse_bit_map_hex(raw_start, "journal receipt start")
        _require_bit_map_history_journal_state_encoding(
            start, "start", allow_empty=True
        )
        bundle_digest = _parse_bit_map_hex(
            raw_digest, "journal receipt bundle_digest"
        )
        if len(bundle_digest) != 32:
            raise ValueError(
                "bit map history journal receipt bundle_digest must decode"
                " to exactly 32 bytes"
            )
        end = _parse_bit_map_hex(raw_end, "journal receipt end")
        _require_bit_map_history_journal_state_encoding(
            end, "end", allow_empty=False
        )
        mac = _parse_bit_map_hex(raw_mac, "journal receipt mac")
        if len(mac) != 32:
            raise ValueError(
                "bit map history journal receipt mac must decode to exactly"
                " 32 bytes"
            )
        record = cls(
            version=1,
            start=start,
            bundle_digest=bundle_digest,
            end=end,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "bit map history journal receipt encoding is not canonical"
            )
        return record


def _coerce_bit_map_history_journal_receipt(
    x: object, name: str
) -> "BitMapHistoryJournalReceipt":
    """Coerce a :class:`BitMapHistoryJournalReceipt` or its canonical
    bytes, splitting the TypeError/ValueError contract exactly as the
    public auditors do: the wrong kind of argument raises
    :class:`TypeError`, a field-shape failure surfacing while parsing
    byte content of the right kind is a value error."""
    if isinstance(x, BitMapHistoryJournalReceipt):
        return x
    if isinstance(x, bytes):
        try:
            return BitMapHistoryJournalReceipt.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the bit map history journal"
                " receipt field contract"
            ) from error
    raise TypeError(
        f"{name} must be a BitMapHistoryJournalReceipt instance or its"
        " canonical bytes"
    )


def audit_map_history_journal_receipt(
    receipt: object, bundle: object, key: object
) -> "BitMapHistoryJournalState":
    """Re-verify a :class:`BitMapHistoryJournalReceipt` against the
    ``bundle`` it attests and the shared ``key``.

    ``receipt`` must be a :class:`BitMapHistoryJournalReceipt` or its
    canonical :meth:`BitMapHistoryJournalReceipt.to_bytes` encoding,
    ``bundle`` a :class:`BitMapHistoryJournalBundle` or its canonical
    :meth:`BitMapHistoryJournalBundle.to_bytes` encoding and ``key`` the
    non-empty shared ``bytes`` key — a wrong-typed argument raises
    :class:`TypeError`, every other contract violation raises
    :class:`ValueError`. The receipt MAC is recomputed as
    ``HMAC-SHA256(key, b"NPBJ4" + C)`` and the bundle digest recomputed
    as ``SHA256(bundle.to_bytes())``; both are always recomputed and each
    compared in constant time before either result is consulted. The
    receipt's ``start`` and ``end`` must then equal the bundle's
    ``start`` and ``end`` byte for byte, and finally the bundle itself is
    verified exactly as :func:`audit_map_history_journal_bundle` verifies
    it. Auditing is a pure check: it touches no auditor state and returns
    no partial result — on success the frozen
    :class:`BitMapHistoryJournalState` the chain ends at is returned.
    """
    receipt = _coerce_bit_map_history_journal_receipt(receipt, "receipt")
    bundle = _coerce_bit_map_history_journal_bundle(bundle, "bundle")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    # The receipt MAC and the bundle digest are both always recomputed
    # and each compared in constant time before either result is
    # consulted.
    mac_ok = hmac.compare_digest(
        _bit_map_history_journal_receipt_mac(key, receipt), receipt.mac
    )
    digest_ok = hmac.compare_digest(
        hashlib.sha256(bundle.to_bytes()).digest(), receipt.bundle_digest
    )
    if not mac_ok or not digest_ok:
        raise ValueError(
            "bit map history journal receipt mac or bundle digest does not"
            " match"
        )
    if receipt.start != bundle.start or receipt.end != bundle.end:
        raise ValueError(
            "bit map history journal receipt endpoints do not match the"
            " bundle"
        )
    return audit_map_history_journal_bundle(bundle, key)


def _bit_map_history_journal_receipt_frontier_content(
    frontier: "BitMapHistoryJournalReceiptFrontier",
) -> list:
    """The JSON-ready first four frontier fields (everything but ``mac``)."""
    return [
        frontier.version,
        frontier.sequence,
        frontier.end.hex(),
        frontier.digest.hex(),
    ]


def _bit_map_history_journal_receipt_frontier_content_bytes(
    frontier: "BitMapHistoryJournalReceiptFrontier",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four frontier
    fields."""
    return _encode_payload(
        _bit_map_history_journal_receipt_frontier_content(frontier)
    )


def _bit_map_history_journal_receipt_frontier_mac(
    key: bytes, frontier: "BitMapHistoryJournalReceiptFrontier"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ5" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_FRONTIER_MAC_PREFIX
        + _bit_map_history_journal_receipt_frontier_content_bytes(frontier),
        hashlib.sha256,
    ).digest()


def _bit_map_history_journal_receipt_frontier_next_digest(
    previous: bytes, sequence: int, receipt: bytes
) -> bytes:
    """One digest-chain step: ``SHA256(b"NPBJ6" + d + u64be(n) + R)``.

    The prefix, the previous 32-byte digest, the fixed 8-byte big-endian
    sequence and the canonical receipt bytes are concatenated directly with
    no separator or length prefix."""
    return hashlib.sha256(
        _BIT_MAP_HISTORY_JOURNAL_FRONTIER_DIGEST_PREFIX
        + previous
        + _bit_map_history_journal_u64be(sequence)
        + receipt
    ).digest()


def _require_bit_map_history_journal_receipt_frontier_end(
    value: bytes,
) -> None:
    """Enforce that a frontier ``end`` is the canonical non-empty
    :class:`BitMapHistoryJournalState` encoding. ``value`` is already known
    to be ``bytes``; :meth:`BitMapHistoryJournalState.from_bytes` enforces
    the full contract including its canonical re-encoding check, and every
    violation — including the field-shape :class:`TypeError` a malformed
    inner document would otherwise surface — raises :class:`ValueError`."""
    try:
        BitMapHistoryJournalState.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "bit map history journal receipt frontier end must be the"
            " canonical BitMapHistoryJournalState encoding"
        ) from error


@dataclass(frozen=True)
class BitMapHistoryJournalReceiptFrontier:
    """A key-MAC'd, digest-chained frontier over the audited receipt stream.

    ``version`` is always ``1``; ``sequence`` a non-bool unsigned 64-bit
    integer (the number of audited :class:`BitMapHistoryJournalReceipt`
    commits); ``end`` the canonical non-empty
    :meth:`BitMapHistoryJournalState.to_bytes` encoding of the journal
    state the audited receipt chain currently ends at; ``digest`` exactly
    32 bytes — the head of a hash chain with ``d0`` fixed at 32 zero bytes
    and each accepted receipt extending it as
    ``d' = SHA256(b"NPBJ6" + d + u64be(n) + R)`` where ``n`` is the new
    sequence, ``u64be(n)`` its fixed 8-byte big-endian encoding and ``R``
    the canonical :meth:`BitMapHistoryJournalReceipt.to_bytes` bytes,
    every part concatenated directly with no separator or length prefix;
    ``mac`` exactly 32 bytes — ``HMAC-SHA256(key, b"NPBJ5" + C)`` where
    ``C`` is the canonical compact encoding of the first four fields (the
    version, sequence, lowercase-hex end and lowercase-hex digest, without
    ``mac``), the prefix and ``C`` concatenated directly with no separator
    or length prefix. Instances are frozen, constructed positionally in
    field order and compare equal by their fields. A field of the wrong
    type raises :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    sequence: int
    end: bytes
    digest: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "bit map history journal receipt frontier version must be an"
                " integer"
            )
        if self.version != 1:
            raise ValueError(
                "bit map history journal receipt frontier version must be 1"
            )
        if isinstance(self.sequence, bool) or type(self.sequence) is not int:
            raise TypeError(
                "bit map history journal receipt frontier sequence must be a"
                " non-bool integer"
            )
        if not 0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit map history journal receipt frontier sequence must fit"
                " in an unsigned 64-bit integer"
            )
        if not isinstance(self.end, bytes):
            raise TypeError(
                "bit map history journal receipt frontier end must be bytes"
            )
        _require_bit_map_history_journal_receipt_frontier_end(self.end)
        for name in ("digest", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(
                    f"bit map history journal receipt frontier {name} must be"
                    " bytes"
                )
            if len(value) != 32:
                raise ValueError(
                    f"bit map history journal receipt frontier {name} must be"
                    " exactly 32 bytes"
                )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, sequence, end, digest, mac]`` where ``end``, ``digest`` and
        ``mac`` are lowercase hex, no whitespace, no length prefix."""
        return _encode_payload(
            _bit_map_history_journal_receipt_frontier_content(self)
            + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(
        cls, data: bytes
    ) -> "BitMapHistoryJournalReceiptFrontier":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, sequence, end, digest, mac]`` in that order,
        ``version == 1``, ``sequence`` a non-bool u64, ``end`` a lowercase
        hex string decoding to the canonical non-empty
        :class:`BitMapHistoryJournalState` encoding, and ``digest``/``mac``
        lowercase hex strings decoding to exactly 32 bytes each. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. No MAC is verified here — neither the frontier MAC
        nor the MACs of the ``end`` state; pass the record to
        :class:`BitMapHistoryJournalReceiptAuditor` for that.
        """
        if not isinstance(data, bytes):
            raise TypeError(
                "bit map history journal receipt frontier data must be bytes"
            )
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                "bit map history journal receipt frontier is not valid JSON:"
                f" {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "bit map history journal receipt frontier must be a JSON"
                " array of exactly version, sequence, end, digest and mac"
            )
        raw_version, raw_sequence, raw_end, raw_digest, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "bit map history journal receipt frontier version must be an"
                " integer"
            )
        if raw_version != 1:
            raise ValueError(
                "bit map history journal receipt frontier version must be 1"
            )
        if type(raw_sequence) is not int:
            raise TypeError(
                "bit map history journal receipt frontier sequence must be a"
                " non-bool integer"
            )
        if not 0 <= raw_sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "bit map history journal receipt frontier sequence must fit"
                " in an unsigned 64-bit integer"
            )
        end = _parse_bit_map_hex(raw_end, "journal receipt frontier end")
        _require_bit_map_history_journal_receipt_frontier_end(end)
        digest = _parse_bit_map_hex(
            raw_digest, "journal receipt frontier digest"
        )
        if len(digest) != 32:
            raise ValueError(
                "bit map history journal receipt frontier digest must decode"
                " to exactly 32 bytes"
            )
        mac = _parse_bit_map_hex(raw_mac, "journal receipt frontier mac")
        if len(mac) != 32:
            raise ValueError(
                "bit map history journal receipt frontier mac must decode to"
                " exactly 32 bytes"
            )
        record = cls(
            version=1,
            sequence=raw_sequence,
            end=end,
            digest=digest,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "bit map history journal receipt frontier encoding is not"
                " canonical"
            )
        return record


class BitMapHistoryJournalReceiptAuditor:
    """Stateful auditor chaining committed
    :class:`BitMapHistoryJournalReceipt` receipts into one monotone,
    restartable, sequence-numbered frontier.

    ``key`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    shared key the tables, journal states, bundles and receipts are MAC'd
    with. ``checkpoint`` is keyword-only: ``None`` (the default) starts
    from sequence zero and no receipt at all, with the digest chain rooted
    at ``d0`` (32 zero bytes); otherwise it must be a
    :class:`BitMapHistoryJournalReceiptFrontier` or its canonical
    :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` encoding (any
    other type raises :class:`TypeError`). A supplied frontier is checked
    at three MAC layers, all always recomputed and each compared in
    constant time before any result is consulted: the frontier's own
    ``NPBJ5`` MAC over the canonical encoding of its first four fields,
    and the two layers of its ``end`` state — the embedded checkpoint
    table's ``NPBL1`` MAC and the state's own ``NPBJ1`` MAC. A malformed
    encoding or any MAC mismatch raises :class:`ValueError`. Across a
    restart the caller must pass the value previously exported at
    :attr:`checkpoint`; nothing is persisted by the auditor itself.

    Each :meth:`audit` accepts one :class:`BitMapHistoryJournalReceipt`
    and the :class:`BitMapHistoryJournalBundle` it attests (either as
    objects or as their canonical bytes) and, under the auditor lock,
    re-verifies the pair exactly like
    :func:`audit_map_history_journal_receipt` — the ``NPBJ4`` receipt MAC,
    the bundle digest, the endpoint equality and the whole bundle
    verification — and then demands the receipt starts exactly where the
    frontier currently stands: with no frontier the receipt's ``start``
    must be the empty string, and otherwise it must equal the frontier
    ``end`` byte for byte. Only then does the frontier advance: ``n`` is
    the old sequence plus one, the new ``end`` is the receipt's ``end``,
    the new digest is ``SHA256(b"NPBJ6" + d + u64be(n) + R)`` over the
    previous digest, the fixed 8-byte big-endian ``n`` and the canonical
    receipt bytes, and the new frontier is MAC'd as
    ``HMAC-SHA256(key, b"NPBJ5" + C)``. Verification and the frontier
    advance are one atomic step: a failed audit raises :class:`ValueError`
    and leaves the frontier untouched, and concurrent audits linearize in
    lock-acquisition order so a committed receipt is never lost.

    :meth:`audit_batch` accepts one
    :class:`BitMapHistoryJournalReceiptBatch` (or its canonical
    :meth:`BitMapHistoryJournalReceiptBatch.to_bytes` encoding) sealing a
    whole contiguous receipt chain and commits it as a single transaction
    under the same lock: the batch ``NPBJ7`` MAC and every MAC layer of
    both non-empty endpoint frontiers are re-verified in constant time
    before any item is replayed, the batch ``start`` must equal the current
    :attr:`checkpoint` byte for byte (``b""`` only when no receipt has
    committed yet), the carried receipt/bundle pairs are replayed in order
    on a temporary frontier, and only when every pair audits and the
    temporary frontier's canonical bytes equal the batch ``end`` byte for
    byte is the checkpoint replaced — a failed batch raises
    :class:`ValueError` and changes nothing, and the same batch replayed is
    rejected on its mismatching ``start``. :meth:`audit` and
    :meth:`audit_batch` share the auditor lock, so single receipts and
    batches linearize together.

    :meth:`commit` verifies and advances exactly like :meth:`audit_batch`
    under the same shared lock, but instead of returning the auditor it
    mints and returns a :class:`JournalBatchReceipt` over the committed
    batch — its ``start``, ``SHA256(batch.to_bytes())`` digest and ``end``
    frontier MAC'd as ``HMAC-SHA256(key, b"NPBJ8" + C)``; a failed commit
    mints nothing and advances nothing.
    """

    def __init__(self, key: object, *, checkpoint: object = None) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must be non-empty")
        self._key = key
        self._lock = threading.Lock()
        self._frontier: "Optional[BitMapHistoryJournalReceiptFrontier]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, BitMapHistoryJournalReceiptFrontier):
            frontier = checkpoint
        elif isinstance(checkpoint, bytes):
            try:
                frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(
                    checkpoint
                )
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error.
                raise ValueError(
                    "checkpoint does not satisfy the bit map history journal"
                    " receipt frontier field contract"
                ) from error
        else:
            raise TypeError(
                "checkpoint must be a BitMapHistoryJournalReceiptFrontier"
                " instance, its canonical bytes, or None"
            )
        # Three MAC layers, all always recomputed and each compared in
        # constant time before any result is consulted: the frontier's own
        # NPBJ5 MAC and the two layers of its end state.
        end_state = BitMapHistoryJournalState.from_bytes(frontier.end)
        table = BitMap.from_bytes(end_state.checkpoint)
        checkpoint_mac_ok = hmac.compare_digest(
            _bit_map_mac(self._key, _bit_map_payload(table.entries)),
            table.mac,
        )
        state_mac_ok = hmac.compare_digest(
            _bit_map_history_journal_mac(self._key, end_state), end_state.mac
        )
        frontier_mac_ok = hmac.compare_digest(
            _bit_map_history_journal_receipt_frontier_mac(
                self._key, frontier
            ),
            frontier.mac,
        )
        if not checkpoint_mac_ok or not state_mac_ok or not frontier_mac_ok:
            raise ValueError(
                "receipt frontier mac does not match the key"
            )
        self._frontier = frontier

    @property
    def checkpoint(
        self,
    ) -> "Optional[BitMapHistoryJournalReceiptFrontier]":
        """The current :class:`BitMapHistoryJournalReceiptFrontier`, or
        ``None`` before the first successfully audited receipt. The
        returned object is frozen and the property read-only; persist its
        :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` output and
        pass it back to a new auditor to survive a restart."""
        return self._frontier

    def audit(
        self, receipt: object, bundle: object
    ) -> "BitMapHistoryJournalReceiptAuditor":
        """Audit one committed receipt against its bundle and advance.

        ``receipt`` must be a :class:`BitMapHistoryJournalReceipt` or its
        canonical :meth:`BitMapHistoryJournalReceipt.to_bytes` encoding
        and ``bundle`` the :class:`BitMapHistoryJournalBundle` it attests
        or its canonical :meth:`BitMapHistoryJournalBundle.to_bytes`
        encoding — any other type raises :class:`TypeError`; a malformed
        or non-canonical encoding, a MAC or digest mismatch, endpoints
        that do not match the bundle, a bundle that fails verification, a
        sequence that would overflow u64, or a receipt ``start`` that does
        not equal the current frontier ``end`` (the empty string when no
        receipt has committed yet) raises :class:`ValueError`. The pair is
        re-verified exactly as :func:`audit_map_history_journal_receipt`
        verifies it and the start matched against the frontier under the
        auditor lock, and the sequence, digest-chain head, end state and
        frontier MAC are all advanced in the same atomic step, so a failed
        audit changes nothing and concurrent audits are serialized in
        lock-acquisition order. Returns the auditor itself.
        """
        with self._lock:
            receipt = _coerce_bit_map_history_journal_receipt(
                receipt, "receipt"
            )
            bundle = _coerce_bit_map_history_journal_bundle(bundle, "bundle")
            audit_map_history_journal_receipt(receipt, bundle, self._key)
            current = (
                b"" if self._frontier is None else self._frontier.end
            )
            if receipt.start != current:
                raise ValueError(
                    "bit map history journal receipt start does not match"
                    " the frontier end"
                )
            previous_sequence = (
                0 if self._frontier is None else self._frontier.sequence
            )
            if previous_sequence >= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(
                    "bit map history journal receipt frontier sequence would"
                    " overflow the unsigned 64-bit range"
                )
            sequence = previous_sequence + 1
            previous_digest = (
                b"\x00" * 32
                if self._frontier is None
                else self._frontier.digest
            )
            digest = _bit_map_history_journal_receipt_frontier_next_digest(
                previous_digest, sequence, receipt.to_bytes()
            )
            candidate = BitMapHistoryJournalReceiptFrontier(
                version=1,
                sequence=sequence,
                end=receipt.end,
                digest=digest,
                mac=b"\x00" * 32,
            )
            self._frontier = replace(
                candidate,
                mac=_bit_map_history_journal_receipt_frontier_mac(
                    self._key, candidate
                ),
            )
            return self

    def audit_batch(self, x: object) -> "BitMapHistoryJournalReceiptAuditor":
        """Audit one committed :class:`BitMapHistoryJournalReceiptBatch`
        and commit the whole chain as a single transaction.

        ``x`` must be a :class:`BitMapHistoryJournalReceiptBatch` or its
        canonical :meth:`BitMapHistoryJournalReceiptBatch.to_bytes`
        encoding — any other type raises :class:`TypeError`; a malformed or
        non-canonical encoding, a batch MAC mismatch, an endpoint frontier
        or state/table MAC mismatch, a ``start`` that does not equal the
        current :attr:`checkpoint` byte for byte (``b""`` only before the
        first committed receipt), a carried receipt or bundle that fails its
        audit, a sequence that would overflow u64, or a replayed final
        frontier that does not equal the batch ``end`` raises
        :class:`ValueError`. Under the auditor lock the batch ``NPBJ7`` MAC
        is recomputed and compared in constant time first; then every
        non-empty endpoint frontier is checked at three MAC layers — the
        frontier's own ``NPBJ5`` MAC and the two layers of its ``end``
        state, the embedded checkpoint table's ``NPBL1`` MAC and the
        state's own ``NPBJ1`` MAC, all always recomputed and each compared
        in constant time — and only once all of that passes are the carried
        receipt/bundle pairs replayed in order on a temporary frontier,
        each exactly as :meth:`audit` audits it, with the digest chain
        extending as ``SHA256(b"NPBJ6" + d + u64be(n) + R)``. The live
        checkpoint is replaced once, and only when every pair audits and
        the temporary frontier's canonical bytes equal the batch ``end``
        byte for byte; a failed batch changes no state, so the same batch
        replayed is afterwards rejected on its mismatching ``start``.
        :meth:`audit` and :meth:`audit_batch` share the auditor lock and
        linearize together in lock-acquisition order. Returns the auditor
        itself.
        """
        with self._lock:
            batch = _coerce_bit_map_history_journal_receipt_batch(x, "x")
            self._frontier = self._replay_receipt_batch_locked(batch)
            return self

    def _replay_receipt_batch_locked(
        self, batch: "BitMapHistoryJournalReceiptBatch"
    ) -> "BitMapHistoryJournalReceiptFrontier":
        """Verify one batch against the current frontier and return the
        resulting frontier without mutating any auditor state.

        The caller must hold :attr:`_lock`. The batch ``NPBJ7`` MAC is
        recomputed and compared in constant time first; then every
        non-empty endpoint frontier is checked at three MAC layers — the
        frontier's own ``NPBJ5`` MAC and the two layers of its ``end``
        state, the embedded checkpoint table's ``NPBL1`` MAC and the
        state's own ``NPBJ1`` MAC, all always recomputed and each compared
        in constant time — the batch ``start`` must equal the current
        :attr:`checkpoint` byte for byte (``b""`` only when no receipt has
        committed yet), and the carried receipt/bundle pairs are replayed
        in order on a temporary frontier whose canonical final bytes must
        equal the batch ``end`` byte for byte. Any failure raises
        :class:`ValueError` before a result is returned; the temporary
        frontier is discarded either way, so the caller's checkpoint is
        untouched until it adopts the returned frontier itself.
        """
        # The batch NPBJ7 MAC is always recomputed and compared in
        # constant time before anything else is consulted.
        if not hmac.compare_digest(
            _bit_map_history_journal_receipt_batch_mac(
                self._key, batch
            ),
            batch.mac,
        ):
            raise ValueError(
                "bit map history journal receipt batch mac does not"
                " match"
            )
        # Every non-empty endpoint is checked at three MAC layers — the
        # frontier's own NPBJ5 MAC, the end state's NPBJ1 MAC and the
        # embedded table's NPBL1 MAC — before any item is replayed.
        if batch.start:
            _verify_bit_map_history_journal_receipt_frontier_macs(
                self._key,
                BitMapHistoryJournalReceiptFrontier.from_bytes(
                    batch.start
                ),
                "start",
            )
        _verify_bit_map_history_journal_receipt_frontier_macs(
            self._key,
            BitMapHistoryJournalReceiptFrontier.from_bytes(batch.end),
            "end",
        )
        current = (
            b""
            if self._frontier is None
            else self._frontier.to_bytes()
        )
        if batch.start != current:
            raise ValueError(
                "bit map history journal receipt batch start does not"
                " match the frontier"
            )
        # Replay the whole chain on a temporary frontier; the live
        # checkpoint is read but never mutated until the caller adopts the
        # returned frontier.
        candidate = BitMapHistoryJournalReceiptAuditor(
            self._key,
            checkpoint=batch.start if batch.start else None,
        )
        for receipt, bundle in batch.items:
            candidate.audit(receipt, bundle)
        final = candidate.checkpoint
        if final is None or final.to_bytes() != batch.end:
            raise ValueError(
                "bit map history journal receipt batch end does not"
                " match the replayed chain"
            )
        return final

    def commit(self, x: object) -> "JournalBatchReceipt":
        """Audit one committed :class:`BitMapHistoryJournalReceiptBatch`
        exactly like :meth:`audit_batch`, advance the frontier, and return a
        :class:`JournalBatchReceipt` attesting the committed batch.

        ``x`` must be a :class:`BitMapHistoryJournalReceiptBatch` or its
        canonical :meth:`BitMapHistoryJournalReceiptBatch.to_bytes`
        encoding — any other type raises :class:`TypeError`; every other
        contract violation (a malformed or non-canonical encoding, a batch
        MAC mismatch, an endpoint frontier or state/table MAC mismatch, a
        ``start`` that does not equal the current :attr:`checkpoint` byte
        for byte, a carried receipt or bundle that fails its audit, or a
        replayed final frontier that does not equal the batch ``end``)
        raises :class:`ValueError`. The verification is exactly
        :meth:`audit_batch`'s and runs under the same lock shared with
        :meth:`audit`; the checkpoint advances to the batch ``end`` once,
        and only when the whole batch verifies, and the returned receipt is
        then minted over it — ``start`` the batch ``start`` (``b""`` before
        the first committed receipt), ``batch_digest``
        ``SHA256(batch.to_bytes())``, ``end`` the batch ``end`` and ``mac``
        ``HMAC-SHA256(key, b"NPBJ8" + C)`` over the canonical compact
        encoding of those four fields. A failure raises before anything is
        minted and leaves the frontier exactly where it stood. Returns the
        frozen :class:`JournalBatchReceipt`; the auditor itself is not
        returned.
        """
        with self._lock:
            batch = _coerce_bit_map_history_journal_receipt_batch(x, "x")
            # Adopt the replayed frontier only once the whole batch has
            # verified; a failure inside raises before this assignment and
            # leaves the checkpoint exactly where it stood.
            final = self._replay_receipt_batch_locked(batch)
            self._frontier = final
            placeholder = JournalBatchReceipt(
                version=1,
                start=batch.start,
                batch_digest=hashlib.sha256(batch.to_bytes()).digest(),
                end=batch.end,
                mac=b"\x00" * 32,
            )
            return replace(
                placeholder,
                mac=_bit_map_history_journal_batch_receipt_mac(
                    self._key, placeholder
                ),
            )


def _require_bit_map_history_journal_receipt_frontier_encoding(
    value: bytes, name: str, allow_empty: bool
) -> None:
    """Enforce the canonical-:class:`BitMapHistoryJournalReceiptFrontier`-bytes
    contract of a batch endpoint.

    ``value`` is already known to be ``bytes``; when ``allow_empty`` holds,
    ``b""`` (the chain starts with no receipt at all) is also accepted.
    :meth:`BitMapHistoryJournalReceiptFrontier.from_bytes` enforces the full
    contract including its canonical re-encoding check, and every violation —
    including the field-shape :class:`TypeError` a malformed inner document
    would otherwise surface — raises :class:`ValueError`."""
    if allow_empty and value == b"":
        return
    try:
        BitMapHistoryJournalReceiptFrontier.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"bit map history journal receipt batch {name} must be the"
            " canonical BitMapHistoryJournalReceiptFrontier encoding"
        ) from error


def _require_bit_map_history_journal_receipt_batch_receipt(
    value: bytes,
) -> None:
    """Enforce the canonical-:class:`BitMapHistoryJournalReceipt`-bytes
    contract of a batch ``items`` receipt.

    ``value`` is already known to be ``bytes``; every violation — including
    the field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        BitMapHistoryJournalReceipt.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "bit map history journal receipt batch items receipts must be"
            " the canonical BitMapHistoryJournalReceipt encoding"
        ) from error


def _require_bit_map_history_journal_receipt_batch_bundle(
    value: bytes,
) -> None:
    """Enforce the canonical-:class:`BitMapHistoryJournalBundle`-bytes
    contract of a batch ``items`` bundle.

    ``value`` is already known to be ``bytes``; every violation — including
    the field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        BitMapHistoryJournalBundle.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "bit map history journal receipt batch items bundles must be"
            " the canonical BitMapHistoryJournalBundle encoding"
        ) from error


def _bit_map_history_journal_receipt_batch_content(
    batch: "BitMapHistoryJournalReceiptBatch",
) -> list:
    """The JSON-ready first four batch fields (everything but ``mac``)."""
    return [
        batch.version,
        batch.start.hex(),
        [
            [receipt.hex(), bundle.hex()]
            for receipt, bundle in batch.items
        ],
        batch.end.hex(),
    ]


def _bit_map_history_journal_receipt_batch_content_bytes(
    batch: "BitMapHistoryJournalReceiptBatch",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four batch fields."""
    return _encode_payload(
        _bit_map_history_journal_receipt_batch_content(batch)
    )


def _bit_map_history_journal_receipt_batch_mac(
    key: bytes, batch: "BitMapHistoryJournalReceiptBatch"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ7" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_RECEIPT_BATCH_PREFIX
        + _bit_map_history_journal_receipt_batch_content_bytes(batch),
        hashlib.sha256,
    ).digest()


@dataclass(frozen=True)
class BitMapHistoryJournalReceiptBatch:
    """A key-MAC'd batch sealing one contiguous committed
    :class:`BitMapHistoryJournalReceipt` chain against the receipt frontier.

    ``version`` is always ``1``. ``start`` is the canonical
    :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` encoding of the
    receipt frontier the chain starts from, or ``b""`` when the chain starts
    with no receipt at all (sequence zero, the digest chain rooted at
    ``d0``). ``items`` is a non-empty ordered tuple of
    ``(receipt, bundle)`` pairs — the canonical
    :meth:`BitMapHistoryJournalReceipt.to_bytes` bytes of each committed
    receipt together with the canonical
    :meth:`BitMapHistoryJournalBundle.to_bytes` bytes of the bundle it
    attests, to replay in order. ``end`` is the canonical non-empty
    :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` encoding of the
    receipt frontier the chain ends at. ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBJ7" + C)`` where ``C`` is the canonical compact
    encoding of the first four fields (the version, the lowercase-hex start,
    the array of lowercase-hex receipt/bundle pairs and the lowercase-hex
    end, without ``mac``), the prefix and ``C`` concatenated directly with
    no separator or length prefix. Instances are frozen, constructed
    positionally in field order and compare equal by their fields. A field
    of the wrong type raises :class:`TypeError`; every other contract
    violation raises :class:`ValueError`. No key material is stored.
    """

    version: int
    start: bytes
    items: tuple
    end: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "bit map history journal receipt batch version must be an"
                " integer"
            )
        if self.version != 1:
            raise ValueError(
                "bit map history journal receipt batch version must be 1"
            )
        if not isinstance(self.start, bytes):
            raise TypeError(
                "bit map history journal receipt batch start must be bytes"
            )
        _require_bit_map_history_journal_receipt_frontier_encoding(
            self.start, "start", allow_empty=True
        )
        if not isinstance(self.items, tuple):
            raise TypeError(
                "bit map history journal receipt batch items must be a tuple"
            )
        if not self.items:
            raise ValueError(
                "bit map history journal receipt batch items must be"
                " non-empty"
            )
        for item in self.items:
            if not isinstance(item, tuple):
                raise TypeError(
                    "bit map history journal receipt batch items items must"
                    " be tuples"
                )
            if len(item) != 2:
                raise ValueError(
                    "bit map history journal receipt batch items items must"
                    " be (receipt, bundle) pairs"
                )
            receipt, bundle = item
            if not isinstance(receipt, bytes):
                raise TypeError(
                    "bit map history journal receipt batch items receipts"
                    " must be bytes"
                )
            _require_bit_map_history_journal_receipt_batch_receipt(receipt)
            if not isinstance(bundle, bytes):
                raise TypeError(
                    "bit map history journal receipt batch items bundles"
                    " must be bytes"
                )
            _require_bit_map_history_journal_receipt_batch_bundle(bundle)
        if not isinstance(self.end, bytes):
            raise TypeError(
                "bit map history journal receipt batch end must be bytes"
            )
        _require_bit_map_history_journal_receipt_frontier_encoding(
            self.end, "end", allow_empty=False
        )
        if not isinstance(self.mac, bytes):
            raise TypeError(
                "bit map history journal receipt batch mac must be bytes"
            )
        if len(self.mac) != 32:
            raise ValueError(
                "bit map history journal receipt batch mac must be exactly"
                " 32 bytes"
            )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, start, items, end, mac]`` where ``start``, ``end`` and ``mac``
        are lowercase hex and ``items`` is the array of the lowercase-hex
        ``[receipt, bundle]`` canonical encoding pairs, no whitespace, no
        length prefix."""
        return _encode_payload(
            _bit_map_history_journal_receipt_batch_content(self)
            + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "BitMapHistoryJournalReceiptBatch":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, start, items, end, mac]`` in that order,
        ``version == 1``, ``start`` a lowercase hex string that is empty or
        decodes to the canonical
        :class:`BitMapHistoryJournalReceiptFrontier` encoding, ``items`` a
        non-empty array of ``[receipt, bundle]`` pairs of lowercase hex
        strings decoding to the canonical
        :class:`BitMapHistoryJournalReceipt` and
        :class:`BitMapHistoryJournalBundle` encodings, ``end`` a lowercase
        hex string decoding to the canonical
        :class:`BitMapHistoryJournalReceiptFrontier` encoding and ``mac`` a
        lowercase hex string decoding to exactly 32 bytes. After parsing
        and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. No MAC is verified here — neither the batch MAC nor
        any MAC of the carried receipts, bundles, frontiers or states; pass
        the record to :func:`audit_map_history_journal_receipt_batch` with
        the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError(
                "bit map history journal receipt batch data must be bytes"
            )
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                "bit map history journal receipt batch is not valid JSON:"
                f" {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "bit map history journal receipt batch must be a JSON array"
                " of exactly version, start, items, end and mac"
            )
        raw_version, raw_start, raw_items, raw_end, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "bit map history journal receipt batch version must be an"
                " integer"
            )
        if raw_version != 1:
            raise ValueError(
                "bit map history journal receipt batch version must be 1"
            )
        start = _parse_bit_map_hex(raw_start, "journal receipt batch start")
        _require_bit_map_history_journal_receipt_frontier_encoding(
            start, "start", allow_empty=True
        )
        if not isinstance(raw_items, list):
            raise TypeError(
                "bit map history journal receipt batch items must be an"
                " array"
            )
        if not raw_items:
            raise ValueError(
                "bit map history journal receipt batch items must be"
                " non-empty"
            )
        items = []
        for raw_item in raw_items:
            if not isinstance(raw_item, list):
                raise TypeError(
                    "bit map history journal receipt batch items items must"
                    " be arrays"
                )
            if len(raw_item) != 2:
                raise ValueError(
                    "bit map history journal receipt batch items items must"
                    " be [receipt, bundle] pairs"
                )
            raw_receipt, raw_bundle = raw_item
            receipt = _parse_bit_map_hex(
                raw_receipt, "journal receipt batch items receipts"
            )
            _require_bit_map_history_journal_receipt_batch_receipt(receipt)
            bundle = _parse_bit_map_hex(
                raw_bundle, "journal receipt batch items bundles"
            )
            _require_bit_map_history_journal_receipt_batch_bundle(bundle)
            items.append((receipt, bundle))
        end = _parse_bit_map_hex(raw_end, "journal receipt batch end")
        _require_bit_map_history_journal_receipt_frontier_encoding(
            end, "end", allow_empty=False
        )
        mac = _parse_bit_map_hex(raw_mac, "journal receipt batch mac")
        if len(mac) != 32:
            raise ValueError(
                "bit map history journal receipt batch mac must decode to"
                " exactly 32 bytes"
            )
        record = cls(
            version=1,
            start=start,
            items=tuple(items),
            end=end,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "bit map history journal receipt batch encoding is not"
                " canonical"
            )
        return record


def _coerce_bit_map_history_journal_receipt_batch(
    x: object, name: str
) -> "BitMapHistoryJournalReceiptBatch":
    """Coerce a :class:`BitMapHistoryJournalReceiptBatch` or its canonical
    bytes, splitting the TypeError/ValueError contract exactly as the public
    auditors do: the wrong kind of argument raises :class:`TypeError`, a
    field-shape failure surfacing while parsing byte content of the right
    kind is a value error."""
    if isinstance(x, BitMapHistoryJournalReceiptBatch):
        return x
    if isinstance(x, bytes):
        try:
            return BitMapHistoryJournalReceiptBatch.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the bit map history journal"
                " receipt batch field contract"
            ) from error
    raise TypeError(
        f"{name} must be a BitMapHistoryJournalReceiptBatch instance or its"
        " canonical bytes"
    )


def _verify_bit_map_history_journal_receipt_frontier_macs(
    key: bytes, frontier: "BitMapHistoryJournalReceiptFrontier", name: str
) -> None:
    """Recompute all three MAC layers of a parsed receipt frontier — the
    frontier's own ``NPBJ5`` MAC and the two layers of its ``end`` state,
    the embedded checkpoint table's ``NPBL1`` MAC and the state's own
    ``NPBJ1`` MAC. All layers are always recomputed and each compared in
    constant time before any result is consulted."""
    end_state = BitMapHistoryJournalState.from_bytes(frontier.end)
    table = BitMap.from_bytes(end_state.checkpoint)
    checkpoint_mac_ok = hmac.compare_digest(
        _bit_map_mac(key, _bit_map_payload(table.entries)),
        table.mac,
    )
    state_mac_ok = hmac.compare_digest(
        _bit_map_history_journal_mac(key, end_state), end_state.mac
    )
    frontier_mac_ok = hmac.compare_digest(
        _bit_map_history_journal_receipt_frontier_mac(key, frontier),
        frontier.mac,
    )
    if not checkpoint_mac_ok or not state_mac_ok or not frontier_mac_ok:
        raise ValueError(
            f"bit map history journal receipt batch {name} mac does not"
            " match the key"
        )


def seal_map_history_journal_receipt_batch(
    items: object, key: object, *, checkpoint: object = None
) -> "BitMapHistoryJournalReceiptBatch":
    """Audit a contiguous committed :class:`BitMapHistoryJournalReceipt`
    chain against the receipt frontier and seal it as a batch.

    ``items`` must be a non-empty iterable of ``(receipt, bundle)`` pairs
    whose receipt is each a :class:`BitMapHistoryJournalReceipt` or its
    canonical :meth:`BitMapHistoryJournalReceipt.to_bytes` encoding and
    whose bundle the attested :class:`BitMapHistoryJournalBundle` or its
    canonical :meth:`BitMapHistoryJournalBundle.to_bytes` encoding, and
    ``key`` the non-empty shared ``bytes`` key. ``checkpoint`` is
    keyword-only: ``None`` (the default) starts the chain with no receipt
    at all — sequence zero, the digest chain rooted at ``d0`` — otherwise
    it must be a :class:`BitMapHistoryJournalReceiptFrontier` or its
    canonical :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes`
    encoding. A non-iterable ``items``, a non-``bytes`` ``key``, a
    wrong-typed pair member or a wrong-kind ``checkpoint`` raises
    :class:`TypeError`; an empty sequence, an empty key, a malformed or
    non-canonical encoding, a MAC mismatch, a failed receipt audit, a
    sequence overflow or a broken chain raises :class:`ValueError`. The
    whole chain is verified first — exactly as
    :class:`BitMapHistoryJournalReceiptAuditor` audits it, starting from
    the supplied checkpoint — and only on success is the batch produced:
    ``start`` carries the starting point (``b""`` when ``checkpoint`` is
    ``None``, else the frontier's canonical encoding), ``items`` the
    canonical encoding pair of every receipt and its bundle in order and
    ``end`` the canonical encoding of the final receipt frontier, MAC'd as
    ``HMAC-SHA256(key, b"NPBJ7" + C)``. Sealing touches no auditor state.
    """
    try:
        pairs = list(items)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(
            "items must be an iterable of (receipt, bundle) pairs"
        ) from None
    auditor = BitMapHistoryJournalReceiptAuditor(key, checkpoint=checkpoint)
    coerced = []
    for pair in pairs:
        try:
            raw_receipt, raw_bundle = pair
        except TypeError:
            raise TypeError(
                "items items must be (receipt, bundle) pairs"
            ) from None
        except ValueError:
            raise ValueError(
                "items items must be (receipt, bundle) pairs"
            ) from None
        coerced.append(
            (
                _coerce_bit_map_history_journal_receipt(
                    raw_receipt, "items receipts"
                ),
                _coerce_bit_map_history_journal_bundle(
                    raw_bundle, "items bundles"
                ),
            )
        )
    if not coerced:
        raise ValueError("items must be a non-empty sequence")
    for receipt, bundle in coerced:
        auditor.audit(receipt, bundle)
    if checkpoint is None:
        start = b""
    elif isinstance(checkpoint, BitMapHistoryJournalReceiptFrontier):
        start = checkpoint.to_bytes()
    else:
        # Canonical BitMapHistoryJournalReceiptFrontier bytes, already
        # validated by the auditor constructor.
        start = checkpoint  # type: ignore[assignment]
    final = auditor.checkpoint
    batch = BitMapHistoryJournalReceiptBatch(
        version=1,
        start=start,
        items=tuple(
            (receipt.to_bytes(), bundle.to_bytes())
            for receipt, bundle in coerced
        ),
        end=final.to_bytes(),  # type: ignore[union-attr]
        mac=b"\x00" * 32,
    )
    return replace(
        batch, mac=_bit_map_history_journal_receipt_batch_mac(key, batch)
    )


def audit_map_history_journal_receipt_batch(
    x: object, key: object
) -> "BitMapHistoryJournalReceiptFrontier":
    """Re-verify a :class:`BitMapHistoryJournalReceiptBatch` against ``key``.

    ``x`` must be a :class:`BitMapHistoryJournalReceiptBatch` or its
    canonical :meth:`BitMapHistoryJournalReceiptBatch.to_bytes` encoding
    and ``key`` the non-empty shared ``bytes`` key — a wrong-typed argument
    raises :class:`TypeError`, every other contract violation raises
    :class:`ValueError`. The batch MAC is recomputed as
    ``HMAC-SHA256(key, b"NPBJ7" + C)`` and compared in constant time; then
    each endpoint frontier is checked at three MAC layers — the frontier's
    own ``NPBJ5`` MAC and the two layers of its ``end`` state, the embedded
    checkpoint table's ``NPBL1`` MAC and the state's own ``NPBJ1`` MAC, all
    always recomputed and each compared in constant time — and finally the
    carried receipt/bundle pairs are replayed one by one exactly as
    :class:`BitMapHistoryJournalReceiptAuditor` audits them, starting with
    no receipt at all when ``start`` is empty and from the carried starting
    frontier otherwise; the replayed final frontier must equal the batch's
    ``end`` byte for byte. Auditing is a pure check: it touches no auditor
    state and returns no partial result — on success the frozen
    :class:`BitMapHistoryJournalReceiptFrontier` the chain ends at is
    returned.
    """
    batch = _coerce_bit_map_history_journal_receipt_batch(x, "x")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    if not hmac.compare_digest(
        _bit_map_history_journal_receipt_batch_mac(key, batch), batch.mac
    ):
        raise ValueError(
            "bit map history journal receipt batch mac does not match"
        )
    if batch.start:
        _verify_bit_map_history_journal_receipt_frontier_macs(
            key,
            BitMapHistoryJournalReceiptFrontier.from_bytes(batch.start),
            "start",
        )
    _verify_bit_map_history_journal_receipt_frontier_macs(
        key,
        BitMapHistoryJournalReceiptFrontier.from_bytes(batch.end),
        "end",
    )
    auditor = BitMapHistoryJournalReceiptAuditor(
        key, checkpoint=batch.start if batch.start else None
    )
    for receipt, bundle in batch.items:
        auditor.audit(receipt, bundle)
    final = auditor.checkpoint
    if final is None or final.to_bytes() != batch.end:
        raise ValueError(
            "bit map history journal receipt batch end does not match the"
            " replayed chain"
        )
    return final


def _bit_map_history_journal_batch_receipt_content(
    receipt: "JournalBatchReceipt",
) -> list:
    """The JSON-ready first four batch-commit receipt fields (everything
    but ``mac``)."""
    return [
        receipt.version,
        receipt.start.hex(),
        receipt.batch_digest.hex(),
        receipt.end.hex(),
    ]


def _bit_map_history_journal_batch_receipt_content_bytes(
    receipt: "JournalBatchReceipt",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four batch-commit
    receipt fields."""
    return _encode_payload(
        _bit_map_history_journal_batch_receipt_content(receipt)
    )


def _bit_map_history_journal_batch_receipt_mac(
    key: bytes, receipt: "JournalBatchReceipt"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ8" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_BATCH_RECEIPT_PREFIX
        + _bit_map_history_journal_batch_receipt_content_bytes(receipt),
        hashlib.sha256,
    ).digest()


@dataclass(frozen=True)
class JournalBatchReceipt:
    """A key-MAC'd receipt attesting one committed
    :class:`BitMapHistoryJournalReceiptBatch`.

    ``version`` is always ``1``. ``start`` is the canonical
    :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` encoding of the
    receipt frontier the committed batch started from, or ``b""`` when it
    started with no receipt at all. ``batch_digest`` is exactly 32 bytes —
    ``SHA256(batch.to_bytes())`` over the canonical encoding of the
    committed :class:`BitMapHistoryJournalReceiptBatch`. ``end`` is the
    canonical non-empty
    :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` encoding of the
    receipt frontier the batch ended at. ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(key, b"NPBJ8" + C)`` where ``C`` is the canonical compact
    encoding of the first four fields (the version, the lowercase-hex
    start, the lowercase-hex batch digest and the lowercase-hex end,
    without ``mac``), the prefix and ``C`` concatenated directly with no
    separator or length prefix. Instances are frozen, constructed
    positionally in field order and compare equal by their fields. A field
    of the wrong type raises :class:`TypeError`; every other contract
    violation raises :class:`ValueError`. No key material is stored.
    """

    version: int
    start: bytes
    batch_digest: bytes
    end: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "journal batch receipt version must be an integer"
            )
        if self.version != 1:
            raise ValueError("journal batch receipt version must be 1")
        if not isinstance(self.start, bytes):
            raise TypeError("journal batch receipt start must be bytes")
        _require_bit_map_history_journal_receipt_frontier_encoding(
            self.start, "start", allow_empty=True
        )
        if not isinstance(self.batch_digest, bytes):
            raise TypeError(
                "journal batch receipt batch_digest must be bytes"
            )
        if len(self.batch_digest) != 32:
            raise ValueError(
                "journal batch receipt batch_digest must be exactly 32"
                " bytes"
            )
        if not isinstance(self.end, bytes):
            raise TypeError("journal batch receipt end must be bytes")
        _require_bit_map_history_journal_receipt_frontier_encoding(
            self.end, "end", allow_empty=False
        )
        if not isinstance(self.mac, bytes):
            raise TypeError("journal batch receipt mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError(
                "journal batch receipt mac must be exactly 32 bytes"
            )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, start, batch_digest, end, mac]`` where ``start``,
        ``batch_digest``, ``end`` and ``mac`` are lowercase hex, no
        whitespace, no length prefix."""
        return _encode_payload(
            _bit_map_history_journal_batch_receipt_content(self)
            + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "JournalBatchReceipt":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, start, batch_digest, end, mac]`` in that order,
        ``version == 1``, ``start`` a lowercase hex string that is empty or
        decodes to the canonical
        :class:`BitMapHistoryJournalReceiptFrontier` encoding,
        ``batch_digest`` a lowercase hex string decoding to exactly 32
        bytes, ``end`` a lowercase hex string decoding to the canonical
        non-empty :class:`BitMapHistoryJournalReceiptFrontier` encoding and
        ``mac`` a lowercase hex string decoding to exactly 32 bytes. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. No MAC is verified here — pass the record to
        :func:`audit_commit` with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("journal batch receipt data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"journal batch receipt is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "journal batch receipt must be a JSON array of exactly"
                " version, start, batch_digest, end and mac"
            )
        raw_version, raw_start, raw_digest, raw_end, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "journal batch receipt version must be an integer"
            )
        if raw_version != 1:
            raise ValueError("journal batch receipt version must be 1")
        start = _parse_bit_map_hex(raw_start, "batch receipt start")
        _require_bit_map_history_journal_receipt_frontier_encoding(
            start, "start", allow_empty=True
        )
        batch_digest = _parse_bit_map_hex(
            raw_digest, "batch receipt batch_digest"
        )
        if len(batch_digest) != 32:
            raise ValueError(
                "journal batch receipt batch_digest must decode to exactly"
                " 32 bytes"
            )
        end = _parse_bit_map_hex(raw_end, "batch receipt end")
        _require_bit_map_history_journal_receipt_frontier_encoding(
            end, "end", allow_empty=False
        )
        mac = _parse_bit_map_hex(raw_mac, "batch receipt mac")
        if len(mac) != 32:
            raise ValueError(
                "journal batch receipt mac must decode to exactly 32 bytes"
            )
        record = cls(
            version=1,
            start=start,
            batch_digest=batch_digest,
            end=end,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "journal batch receipt encoding is not canonical"
            )
        return record


def _coerce_bit_map_history_journal_batch_receipt(
    x: object, name: str
) -> "JournalBatchReceipt":
    """Coerce a :class:`JournalBatchReceipt` or its canonical bytes,
    splitting the TypeError/ValueError contract exactly as the public
    auditors do: the wrong kind of argument raises :class:`TypeError`, a
    field-shape failure surfacing while parsing byte content of the right
    kind is a value error."""
    if isinstance(x, JournalBatchReceipt):
        return x
    if isinstance(x, bytes):
        try:
            return JournalBatchReceipt.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the journal batch receipt field"
                " contract"
            ) from error
    raise TypeError(
        f"{name} must be a JournalBatchReceipt instance or its canonical"
        " bytes"
    )


def audit_commit(r: object, b: object, key: object) -> "BitMapHistoryJournalReceiptFrontier":
    """Re-verify a :class:`JournalBatchReceipt` against the
    :class:`BitMapHistoryJournalReceiptBatch` it attests and the shared
    ``key``.

    ``r`` must be a :class:`JournalBatchReceipt` or its canonical
    :meth:`JournalBatchReceipt.to_bytes` encoding, ``b`` a
    :class:`BitMapHistoryJournalReceiptBatch` or its canonical
    :meth:`BitMapHistoryJournalReceiptBatch.to_bytes` encoding and ``key``
    the non-empty shared ``bytes`` key — a wrong-typed argument raises
    :class:`TypeError`, every other contract violation raises
    :class:`ValueError`. The receipt MAC is recomputed as
    ``HMAC-SHA256(key, b"NPBJ8" + C)`` and the batch digest recomputed as
    ``SHA256(batch.to_bytes())``; both are always recomputed and each
    compared in constant time before either result is consulted. The
    receipt's ``start`` and ``end`` must then equal the batch's ``start``
    and ``end`` byte for byte, and finally the batch itself is verified
    exactly as :func:`audit_map_history_journal_receipt_batch` verifies it
    — the batch ``NPBJ7`` MAC, every MAC layer of both endpoint
    frontiers, and the carried receipt/bundle chain replayed from the
    batch ``start`` to its ``end``. Auditing is a pure check: it touches no
    auditor state and returns no partial result — on success the frozen
    :class:`BitMapHistoryJournalReceiptFrontier` at the batch ``end`` is
    returned.
    """
    receipt = _coerce_bit_map_history_journal_batch_receipt(r, "r")
    batch = _coerce_bit_map_history_journal_receipt_batch(b, "b")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    # The receipt MAC, the batch digest and the two endpoints are all
    # always recomputed/compared in constant time before any result is
    # consulted.
    mac_ok = hmac.compare_digest(
        _bit_map_history_journal_batch_receipt_mac(key, receipt), receipt.mac
    )
    digest_ok = hmac.compare_digest(
        hashlib.sha256(batch.to_bytes()).digest(), receipt.batch_digest
    )
    start_ok = hmac.compare_digest(receipt.start, batch.start)
    end_ok = hmac.compare_digest(receipt.end, batch.end)
    if not mac_ok or not digest_ok or not start_ok or not end_ok:
        raise ValueError(
            "journal batch receipt mac, batch digest or endpoints do not"
            " match"
        )
    # Verifying the batch re-verifies its NPBJ7 MAC, every MAC layer of
    # both endpoint frontiers and the whole carried receipt/bundle chain,
    # returning the frozen frontier at the batch end (it itself raises
    # ValueError if the replayed frontier does not equal that end).
    return audit_map_history_journal_receipt_batch(batch, key)


def _bit_map_history_journal_batch_receipt_frontier_content(
    frontier: "JournalBatchReceiptFrontier",
) -> list:
    """The JSON-ready first four commit-frontier fields (everything but
    ``mac``)."""
    return [
        frontier.version,
        frontier.sequence,
        frontier.end.hex(),
        frontier.digest.hex(),
    ]


def _bit_map_history_journal_batch_receipt_frontier_content_bytes(
    frontier: "JournalBatchReceiptFrontier",
) -> bytes:
    """The canonical compact encoding ``C`` of the first four commit-frontier
    fields."""
    return _encode_payload(
        _bit_map_history_journal_batch_receipt_frontier_content(frontier)
    )


def _bit_map_history_journal_batch_receipt_frontier_mac(
    key: bytes, frontier: "JournalBatchReceiptFrontier"
) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ9" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _BIT_MAP_HISTORY_JOURNAL_BATCH_RECEIPT_FRONTIER_MAC_PREFIX
        + _bit_map_history_journal_batch_receipt_frontier_content_bytes(
            frontier
        ),
        hashlib.sha256,
    ).digest()


def _bit_map_history_journal_batch_receipt_frontier_next_digest(
    previous: bytes, sequence: int, receipt: bytes
) -> bytes:
    """One commit digest-chain step:
    ``SHA256(b"NPBJ10" + d + u64be(n) + R)``.

    The prefix, the previous 32-byte digest, the fixed 8-byte big-endian
    sequence and the canonical receipt bytes are concatenated directly with
    no separator or length prefix."""
    return hashlib.sha256(
        _BIT_MAP_HISTORY_JOURNAL_BATCH_RECEIPT_FRONTIER_DIGEST_PREFIX
        + previous
        + _bit_map_history_journal_u64be(sequence)
        + receipt
    ).digest()


def _require_journal_batch_receipt_frontier_end(value: bytes) -> None:
    """Enforce that a commit frontier ``end`` is the canonical non-empty
    :class:`BitMapHistoryJournalReceiptFrontier` encoding. ``value`` is
    already known to be ``bytes``;
    :meth:`BitMapHistoryJournalReceiptFrontier.from_bytes` enforces the full
    contract including its canonical re-encoding check, and every violation —
    including the field-shape :class:`TypeError` a malformed inner document
    would otherwise surface — raises :class:`ValueError`."""
    try:
        BitMapHistoryJournalReceiptFrontier.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "journal batch receipt frontier end must be the canonical"
            " BitMapHistoryJournalReceiptFrontier encoding"
        ) from error


@dataclass(frozen=True)
class JournalBatchReceiptFrontier:
    """A key-MAC'd, digest-chained frontier over the audited
    :class:`JournalBatchReceipt` commit stream.

    ``version`` is always ``1``; ``sequence`` a non-bool unsigned 64-bit
    integer (the number of audited :class:`JournalBatchReceipt` commits);
    ``end`` the canonical non-empty
    :meth:`BitMapHistoryJournalReceiptFrontier.to_bytes` encoding of the
    receipt frontier the audited commit chain currently ends at; ``digest``
    exactly 32 bytes — the head of a hash chain with ``d0`` fixed at 32 zero
    bytes and each accepted commit receipt extending it as
    ``d' = SHA256(b"NPBJ10" + d + u64be(n) + R)`` where ``n`` is the new
    sequence, ``u64be(n)`` its fixed 8-byte big-endian encoding and ``R``
    the canonical :meth:`JournalBatchReceipt.to_bytes` bytes, every part
    concatenated directly with no separator or length prefix; ``mac``
    exactly 32 bytes — ``HMAC-SHA256(key, b"NPBJ9" + C)`` where ``C`` is the
    canonical compact encoding of the first four fields (the version,
    sequence, lowercase-hex end and lowercase-hex digest, without ``mac``),
    the prefix and ``C`` concatenated directly with no separator or length
    prefix. Instances are frozen, constructed positionally in field order
    and compare equal by their fields. A field of the wrong type raises
    :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    sequence: int
    end: bytes
    digest: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError(
                "journal batch receipt frontier version must be an integer"
            )
        if self.version != 1:
            raise ValueError(
                "journal batch receipt frontier version must be 1"
            )
        if isinstance(self.sequence, bool) or type(self.sequence) is not int:
            raise TypeError(
                "journal batch receipt frontier sequence must be a non-bool"
                " integer"
            )
        if not 0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "journal batch receipt frontier sequence must fit in an"
                " unsigned 64-bit integer"
            )
        if not isinstance(self.end, bytes):
            raise TypeError(
                "journal batch receipt frontier end must be bytes"
            )
        _require_journal_batch_receipt_frontier_end(self.end)
        for name in ("digest", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(
                    f"journal batch receipt frontier {name} must be bytes"
                )
            if len(value) != 32:
                raise ValueError(
                    f"journal batch receipt frontier {name} must be exactly"
                    " 32 bytes"
                )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, sequence, end, digest, mac]`` where ``end``, ``digest`` and
        ``mac`` are lowercase hex, no whitespace, no length prefix."""
        return _encode_payload(
            _bit_map_history_journal_batch_receipt_frontier_content(self)
            + [self.mac.hex()]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "JournalBatchReceiptFrontier":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, sequence, end, digest, mac]`` in that order,
        ``version == 1``, ``sequence`` a non-bool u64, ``end`` a lowercase
        hex string decoding to the canonical non-empty
        :class:`BitMapHistoryJournalReceiptFrontier` encoding, and
        ``digest``/``mac`` lowercase hex strings decoding to exactly 32
        bytes each. After parsing and field validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the
        input byte for byte, so formatted JSON, whitespace and any
        non-canonical spelling are rejected too. No MAC is verified here —
        neither the commit frontier MAC nor the MACs of the ``end``
        receipt frontier; pass the record to
        :class:`JournalBatchReceiptAuditor` for that.
        """
        if not isinstance(data, bytes):
            raise TypeError(
                "journal batch receipt frontier data must be bytes"
            )
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                "journal batch receipt frontier is not valid JSON:"
                f" {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "journal batch receipt frontier must be a JSON array of"
                " exactly version, sequence, end, digest and mac"
            )
        raw_version, raw_sequence, raw_end, raw_digest, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError(
                "journal batch receipt frontier version must be an integer"
            )
        if raw_version != 1:
            raise ValueError(
                "journal batch receipt frontier version must be 1"
            )
        if type(raw_sequence) is not int:
            raise TypeError(
                "journal batch receipt frontier sequence must be a non-bool"
                " integer"
            )
        if not 0 <= raw_sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "journal batch receipt frontier sequence must fit in an"
                " unsigned 64-bit integer"
            )
        end = _parse_bit_map_hex(raw_end, "batch receipt frontier end")
        _require_journal_batch_receipt_frontier_end(end)
        digest = _parse_bit_map_hex(
            raw_digest, "batch receipt frontier digest"
        )
        if len(digest) != 32:
            raise ValueError(
                "journal batch receipt frontier digest must decode to"
                " exactly 32 bytes"
            )
        mac = _parse_bit_map_hex(raw_mac, "batch receipt frontier mac")
        if len(mac) != 32:
            raise ValueError(
                "journal batch receipt frontier mac must decode to exactly"
                " 32 bytes"
            )
        record = cls(
            version=1,
            sequence=raw_sequence,
            end=end,
            digest=digest,
            mac=mac,
        )
        if record.to_bytes() != data:
            raise ValueError(
                "journal batch receipt frontier encoding is not canonical"
            )
        return record


def _verify_journal_batch_receipt_frontier_macs(
    key: bytes, frontier: "JournalBatchReceiptFrontier"
) -> None:
    """Recompute all four MAC layers of a parsed commit frontier — the
    commit frontier's own ``NPBJ9`` MAC and the three layers of its ``end``
    receipt frontier: that frontier's own ``NPBJ5`` MAC, its ``end``
    state's ``NPBJ1`` MAC and the state's embedded checkpoint table's
    ``NPBL1`` MAC. All layers are always recomputed and each compared in
    constant time before any result is consulted."""
    end_frontier = BitMapHistoryJournalReceiptFrontier.from_bytes(frontier.end)
    end_state = BitMapHistoryJournalState.from_bytes(end_frontier.end)
    table = BitMap.from_bytes(end_state.checkpoint)
    checkpoint_mac_ok = hmac.compare_digest(
        _bit_map_mac(key, _bit_map_payload(table.entries)),
        table.mac,
    )
    state_mac_ok = hmac.compare_digest(
        _bit_map_history_journal_mac(key, end_state), end_state.mac
    )
    end_frontier_mac_ok = hmac.compare_digest(
        _bit_map_history_journal_receipt_frontier_mac(key, end_frontier),
        end_frontier.mac,
    )
    frontier_mac_ok = hmac.compare_digest(
        _bit_map_history_journal_batch_receipt_frontier_mac(key, frontier),
        frontier.mac,
    )
    if (
        not checkpoint_mac_ok
        or not state_mac_ok
        or not end_frontier_mac_ok
        or not frontier_mac_ok
    ):
        raise ValueError(
            "journal batch receipt frontier mac does not match the key"
        )


class JournalBatchReceiptAuditor:
    """Stateful auditor chaining committed :class:`JournalBatchReceipt`
    commit receipts into one monotone, restartable, sequence-numbered
    :class:`JournalBatchReceiptFrontier`.

    ``key`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    shared key the batches, receipts and receipt frontiers are MAC'd with.
    ``checkpoint`` is keyword-only: ``None`` (the default) starts from
    sequence zero with no commit at all and the digest chain rooted at
    ``d0`` (32 zero bytes); otherwise it must be a
    :class:`JournalBatchReceiptFrontier` or its canonical
    :meth:`JournalBatchReceiptFrontier.to_bytes` encoding (any other type
    raises :class:`TypeError`). A supplied frontier is checked at four MAC
    layers, all always recomputed and each compared in constant time before
    any result is consulted: the commit frontier's own ``NPBJ9`` MAC over
    the canonical encoding of its first four fields, and the three layers
    of its ``end`` receipt frontier — the embedded checkpoint table's
    ``NPBL1`` MAC, the journal state's own ``NPBJ1`` MAC and the receipt
    frontier's own ``NPBJ5`` MAC. A malformed encoding or any MAC mismatch
    raises :class:`ValueError`. Across a restart the caller must pass the
    value previously exported at :attr:`state`; nothing is persisted by the
    auditor itself.

    Each :meth:`audit` accepts one :class:`JournalBatchReceipt` and the
    :class:`BitMapHistoryJournalReceiptBatch` it attests (either as objects
    or as their canonical bytes) and, under the auditor lock, re-verifies
    the pair exactly like :func:`audit_commit` — the ``NPBJ8`` receipt MAC,
    the batch digest, the endpoint equality and the whole batch
    verification — and then demands the receipt starts exactly where the
    commit frontier currently stands: with no frontier the receipt's
    ``start`` must be the empty string, and otherwise it must equal the
    frontier ``end`` byte for byte. Only then does the frontier advance:
    ``n`` is the old sequence plus one, the new ``end`` is the receipt's
    ``end``, the new digest is
    ``SHA256(b"NPBJ10" + d + u64be(n) + R)`` over the previous digest, the
    fixed 8-byte big-endian ``n`` and the canonical receipt bytes, and the
    new commit frontier is MAC'd as
    ``HMAC-SHA256(key, b"NPBJ9" + C)``. Verification and the frontier
    advance are one atomic step: a failed audit raises :class:`ValueError`
    (and a wrong-typed argument :class:`TypeError`) and leaves the frontier
    untouched, and concurrent audits linearize in lock-acquisition order so
    a committed receipt is never lost.
    """

    def __init__(self, key: object, *, checkpoint: object = None) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must be non-empty")
        self._key = key
        self._lock = threading.Lock()
        self._frontier: "Optional[JournalBatchReceiptFrontier]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, JournalBatchReceiptFrontier):
            frontier = checkpoint
        elif isinstance(checkpoint, bytes):
            try:
                frontier = JournalBatchReceiptFrontier.from_bytes(checkpoint)
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error.
                raise ValueError(
                    "checkpoint does not satisfy the journal batch receipt"
                    " frontier field contract"
                ) from error
        else:
            raise TypeError(
                "checkpoint must be a JournalBatchReceiptFrontier instance,"
                " its canonical bytes, or None"
            )
        _verify_journal_batch_receipt_frontier_macs(self._key, frontier)
        self._frontier = frontier

    @property
    def state(self) -> "Optional[JournalBatchReceiptFrontier]":
        """The current :class:`JournalBatchReceiptFrontier`, or ``None``
        before the first successfully audited commit. The returned object
        is frozen and the property read-only; persist its
        :meth:`JournalBatchReceiptFrontier.to_bytes` output and pass it back
        to a new auditor to survive a restart."""
        return self._frontier

    def audit(
        self, receipt: object, batch: object
    ) -> "JournalBatchReceiptAuditor":
        """Audit one committed :class:`JournalBatchReceipt` against its
        :class:`BitMapHistoryJournalReceiptBatch` and advance.

        ``receipt`` must be a :class:`JournalBatchReceipt` or its canonical
        :meth:`JournalBatchReceipt.to_bytes` encoding and ``batch`` the
        :class:`BitMapHistoryJournalReceiptBatch` it attests or its canonical
        :meth:`BitMapHistoryJournalReceiptBatch.to_bytes` encoding — any
        other type raises :class:`TypeError`; a malformed or non-canonical
        encoding, a MAC or digest mismatch, endpoints that do not match the
        batch, a batch that fails verification, a sequence that would
        overflow u64, or a receipt ``start`` that does not equal the current
        frontier ``end`` (the empty string when no commit has happened yet)
        raises :class:`ValueError`. The pair is re-verified exactly as
        :func:`audit_commit` verifies it and the start matched against the
        frontier under the auditor lock, and the sequence, digest-chain
        head, end frontier and commit frontier MAC are all advanced in the
        same atomic step, so a failed audit changes nothing and concurrent
        audits are serialized in lock-acquisition order. Returns the
        auditor itself.
        """
        with self._lock:
            receipt = _coerce_bit_map_history_journal_batch_receipt(
                receipt, "receipt"
            )
            batch = _coerce_bit_map_history_journal_receipt_batch(
                batch, "batch"
            )
            # audit_commit is a pure check: the NPBJ8 receipt MAC, the batch
            # digest, the endpoints and the whole carried batch chain,
            # returning the frozen receipt frontier at the batch end.
            audit_commit(receipt, batch, self._key)
            current = b"" if self._frontier is None else self._frontier.end
            if receipt.start != current:
                raise ValueError(
                    "journal batch receipt start does not match the frontier"
                    " end"
                )
            previous_sequence = (
                0 if self._frontier is None else self._frontier.sequence
            )
            if previous_sequence >= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(
                    "journal batch receipt frontier sequence would overflow"
                    " the unsigned 64-bit range"
                )
            sequence = previous_sequence + 1
            previous_digest = (
                b"\x00" * 32
                if self._frontier is None
                else self._frontier.digest
            )
            digest = (
                _bit_map_history_journal_batch_receipt_frontier_next_digest(
                    previous_digest, sequence, receipt.to_bytes()
                )
            )
            candidate = JournalBatchReceiptFrontier(
                version=1,
                sequence=sequence,
                end=receipt.end,
                digest=digest,
                mac=b"\x00" * 32,
            )
            self._frontier = replace(
                candidate,
                mac=_bit_map_history_journal_batch_receipt_frontier_mac(
                    self._key, candidate
                ),
            )
            return self


def _commit_range_body_content(
    start: bytes, items: "tuple[tuple[bytes, bytes], ...]", end: bytes
) -> list:
    """The JSON-ready commit-range body ``[S, I, E]``: the lowercase-hex
    starting commit frontier (or the empty string), the non-empty array of
    lowercase-hex ``[receipt, batch]`` canonical encoding pairs and the
    lowercase-hex final commit frontier."""
    return [
        start.hex(),
        [[receipt.hex(), batch.hex()] for receipt, batch in items],
        end.hex(),
    ]


def _commit_range_body_bytes(
    start: bytes, items: "tuple[tuple[bytes, bytes], ...]", end: bytes
) -> bytes:
    """The canonical compact encoding ``body`` of the commit-range body."""
    return _encode_payload(_commit_range_body_content(start, items, end))


def _commit_range_mac(key: bytes, body: bytes) -> bytes:
    """``HMAC-SHA256(key, b"NPBJ11" + body)``. The prefix and ``body`` are
    concatenated directly with no separator or length prefix."""
    return hmac.new(
        key, _COMMIT_RANGE_PREFIX + body, hashlib.sha256
    ).digest()


def _require_commit_range_frontier(
    value: bytes, name: str, allow_empty: bool
) -> None:
    """Enforce the canonical-:class:`JournalBatchReceiptFrontier`-bytes
    contract of a commit-range endpoint.

    ``value`` is already known to be ``bytes``; when ``allow_empty`` holds,
    ``b""`` (the range starts with no commit at all) is also accepted.
    :meth:`JournalBatchReceiptFrontier.from_bytes` enforces the full contract
    including its canonical re-encoding check, and every violation —
    including the field-shape :class:`TypeError` a malformed inner document
    would otherwise surface — raises :class:`ValueError`."""
    if allow_empty and value == b"":
        return
    try:
        JournalBatchReceiptFrontier.from_bytes(value)
    except (TypeError, ValueError) as error:
        suffix = " or empty" if allow_empty else ""
        raise ValueError(
            f"commit range {name} must be the canonical"
            f" JournalBatchReceiptFrontier encoding{suffix}"
        ) from error


def _require_commit_range_receipt(value: bytes) -> None:
    """Enforce the canonical-:class:`JournalBatchReceipt`-bytes contract of
    a commit-range item receipt.

    ``value`` is already known to be ``bytes``; every violation — including
    the field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        JournalBatchReceipt.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "commit range items receipts must be the canonical"
            " JournalBatchReceipt encoding"
        ) from error


def _require_commit_range_batch(value: bytes) -> None:
    """Enforce the canonical-:class:`BitMapHistoryJournalReceiptBatch`-bytes
    contract of a commit-range item batch.

    ``value`` is already known to be ``bytes``; every violation — including
    the field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        BitMapHistoryJournalReceiptBatch.from_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "commit range items batches must be the canonical"
            " BitMapHistoryJournalReceiptBatch encoding"
        ) from error


def _parse_commit_range_body(
    body: bytes,
) -> "tuple[bytes, tuple[tuple[bytes, bytes], ...], bytes]":
    """Parse and fully validate a canonical commit-range ``body``.

    The body must be the compact UTF-8 JSON array ``[S, I, E]`` in that
    order: ``S`` a lowercase hex string that is empty or decodes to the
    canonical non-empty :class:`JournalBatchReceiptFrontier` encoding;
    ``I`` a non-empty array of ``[R, B]`` pairs, each a lowercase hex
    string decoding to the canonical :class:`JournalBatchReceipt` encoding
    followed by one decoding to the canonical
    :class:`BitMapHistoryJournalReceiptBatch` encoding; and ``E`` a
    non-empty lowercase hex string decoding to the canonical non-empty
    :class:`JournalBatchReceiptFrontier` encoding. After parsing, the body
    is re-encoded and the result must equal the input byte for byte, so
    formatted JSON, whitespace and any non-canonical spelling are rejected.
    Returns the decoded ``(start, items, end)`` with ``items`` a tuple of
    canonical ``(receipt, batch)`` byte pairs."""
    try:
        document = json.loads(body)
    except ValueError as error:
        raise ValueError(f"commit range body is not valid JSON: {error}") from error
    if not isinstance(document, list) or len(document) != 3:
        raise ValueError(
            "commit range body must be a JSON array of exactly start, items"
            " and end"
        )
    raw_start, raw_items, raw_end = document
    start = _parse_bit_map_hex(raw_start, "commit range start")
    _require_commit_range_frontier(start, "start", allow_empty=True)
    if not isinstance(raw_items, list):
        raise TypeError("commit range items must be an array")
    if not raw_items:
        raise ValueError("commit range items must be non-empty")
    items: "list[tuple[bytes, bytes]]" = []
    for raw_item in raw_items:
        if not isinstance(raw_item, list):
            raise TypeError("commit range items entries must be arrays")
        if len(raw_item) != 2:
            raise ValueError(
                "commit range items entries must be [receipt, batch] pairs"
            )
        raw_receipt, raw_batch = raw_item
        receipt = _parse_bit_map_hex(raw_receipt, "commit range receipt")
        _require_commit_range_receipt(receipt)
        batch = _parse_bit_map_hex(raw_batch, "commit range batch")
        _require_commit_range_batch(batch)
        items.append((receipt, batch))
    end = _parse_bit_map_hex(raw_end, "commit range end")
    _require_commit_range_frontier(end, "end", allow_empty=False)
    parsed_start = start
    parsed_items = tuple(items)
    parsed_end = end
    if (
        _commit_range_body_bytes(parsed_start, parsed_items, parsed_end)
        != body
    ):
        raise ValueError("commit range body encoding is not canonical")
    return parsed_start, parsed_items, parsed_end


def _require_commit_range_body(body: bytes) -> None:
    """Enforce the full canonical commit-range body contract. ``body`` is
    already known to be ``bytes``; every violation — including the
    field-shape :class:`TypeError` a malformed inner document would
    otherwise surface — raises :class:`ValueError`."""
    try:
        _parse_commit_range_body(body)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "commit range body must be the canonical [start, items, end]"
            " encoding"
        ) from error


@dataclass(frozen=True)
class CommitRange:
    """A transferable, independently re-checkable proof over a contiguous
    range of committed :class:`JournalBatchReceipt` commits and the commit
    frontier they end at.

    ``version`` is always ``1``. ``body`` is the canonical compact UTF-8
    JSON array ``[S, I, E]``: ``S`` the lowercase hex of the
    :class:`JournalBatchReceiptFrontier` checkpoint the range starts from,
    or the empty string when it starts from nothing (sequence zero, the
    commit digest chain rooted at ``d0``); ``I`` a non-empty array of
    ``[R, B]`` pairs replayed in order, ``R`` the lowercase hex of the
    canonical :meth:`JournalBatchReceipt.to_bytes` encoding of each
    committed receipt and ``B`` the lowercase hex of the canonical
    :meth:`BitMapHistoryJournalReceiptBatch.to_bytes` encoding of the batch
    it attests; and ``E`` the lowercase hex of the canonical non-empty
    :class:`JournalBatchReceiptFrontier` encoding the range ends at.
    ``mac`` is exactly 32 bytes — ``HMAC-SHA256(key, b"NPBJ11" + body)``,
    the prefix and ``body`` concatenated directly with no separator or
    length prefix. Instances are frozen, constructed positionally in field
    order and compare equal by their fields. A field of the wrong type
    raises :class:`TypeError`; every other contract violation raises
    :class:`ValueError`. No key material is stored.
    """

    version: int
    body: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("commit range version must be an integer")
        if self.version != 1:
            raise ValueError("commit range version must be 1")
        if not isinstance(self.body, bytes):
            raise TypeError("commit range body must be bytes")
        _require_commit_range_body(self.body)
        if not isinstance(self.mac, bytes):
            raise TypeError("commit range mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError("commit range mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, body, mac]`` where ``body`` and ``mac`` are lowercase hex, no
        whitespace, no length prefix."""
        return _encode_payload([self.version, self.body.hex(), self.mac.hex()])

    @classmethod
    def from_bytes(cls, data: bytes) -> "CommitRange":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, body, mac]`` in that order, ``version == 1``,
        ``body`` a lowercase hex string decoding to the canonical
        ``[S, I, E]`` body (an empty-or-frontier start, a non-empty array
        of canonical receipt/batch pairs and a non-empty frontier end), and
        ``mac`` a lowercase hex string decoding to exactly 32 bytes. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. The MAC is not verified here — neither the range MAC
        nor any MAC of the carried commits or checkpoints; pass the record
        to :func:`audit_range` with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("commit range data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"commit range is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 3:
            raise ValueError(
                "commit range must be a JSON array of exactly version,"
                " body and mac"
            )
        raw_version, raw_body, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError("commit range version must be an integer")
        if raw_version != 1:
            raise ValueError("commit range version must be 1")
        body = _parse_bit_map_hex(raw_body, "commit range body")
        _parse_commit_range_body(body)
        mac = _parse_bit_map_hex(raw_mac, "commit range mac")
        if len(mac) != 32:
            raise ValueError(
                "commit range mac must decode to exactly 32 bytes"
            )
        record = cls(version=1, body=body, mac=mac)
        if record.to_bytes() != data:
            raise ValueError("commit range encoding is not canonical")
        return record


def _coerce_commit_range(x: object, name: str) -> "CommitRange":
    """Coerce a :class:`CommitRange` or its canonical bytes, splitting the
    TypeError/ValueError contract exactly as the public auditors do: the
    wrong kind of argument raises :class:`TypeError`, a field-shape failure
    surfacing while parsing byte content of the right kind is a value
    error."""
    if isinstance(x, CommitRange):
        return x
    if isinstance(x, bytes):
        try:
            return CommitRange.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the commit range field contract"
            ) from error
    raise TypeError(
        f"{name} must be a CommitRange instance or its canonical bytes"
    )


def seal_range(
    items: object, key: object, *, checkpoint: object = None
) -> "CommitRange":
    """Audit a contiguous committed :class:`JournalBatchReceipt` range and
    seal it as a transferable :class:`CommitRange`.

    ``items`` must be a non-empty iterable of ``(receipt, batch)`` pairs
    whose receipt is each a :class:`JournalBatchReceipt` or its canonical
    :meth:`JournalBatchReceipt.to_bytes` encoding and whose batch the
    attested :class:`BitMapHistoryJournalReceiptBatch` or its canonical
    :meth:`BitMapHistoryJournalReceiptBatch.to_bytes` encoding, and ``key``
    the non-empty shared ``bytes`` key. ``checkpoint`` is keyword-only:
    ``None`` (the default) starts the range from sequence zero with the
    commit digest chain rooted at ``d0`` (the first receipt must then start
    empty); otherwise it must be a :class:`JournalBatchReceiptFrontier` or
    its canonical :meth:`JournalBatchReceiptFrontier.to_bytes` encoding. A
    non-iterable ``items``, a non-``bytes`` ``key``, a wrong-typed pair
    member or a wrong-kind ``checkpoint`` raises :class:`TypeError`; an
    empty sequence, an empty key, a malformed or non-canonical encoding, a
    checkpoint MAC mismatch, a failed commit audit, a sequence overflow or
    a receipt that does not continue exactly where the frontier stands
    raises :class:`ValueError`. The whole range is replayed first, exactly
    as :class:`JournalBatchReceiptAuditor` audits it starting from the
    supplied checkpoint — each pair re-verified like :func:`audit_commit`
    and the frontier advanced per ``NPBJ10`` — and only on success is the
    range produced: its body carries the starting point (the empty string
    when ``checkpoint`` is ``None``, else the checkpoint's canonical
    encoding), every canonical receipt/batch pair in order and the final
    frontier's canonical encoding, MAC'd as
    ``HMAC-SHA256(key, b"NPBJ11" + body)``. Sealing touches no auditor
    state.
    """
    try:
        pairs = list(items)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError(
            "items must be an iterable of (receipt, batch) pairs"
        ) from None
    auditor = JournalBatchReceiptAuditor(key, checkpoint=checkpoint)
    coerced: "list[tuple[JournalBatchReceipt, BitMapHistoryJournalReceiptBatch]]" = []
    for pair in pairs:
        try:
            raw_receipt, raw_batch = pair
        except TypeError:
            raise TypeError(
                "items entries must be (receipt, batch) pairs"
            ) from None
        except ValueError:
            raise ValueError(
                "items entries must be (receipt, batch) pairs"
            ) from None
        coerced.append(
            (
                _coerce_bit_map_history_journal_batch_receipt(
                    raw_receipt, "items receipts"
                ),
                _coerce_bit_map_history_journal_receipt_batch(
                    raw_batch, "items batches"
                ),
            )
        )
    if not coerced:
        raise ValueError("items must be a non-empty sequence")
    for receipt, batch in coerced:
        auditor.audit(receipt, batch)
    if checkpoint is None:
        start = b""
    elif isinstance(checkpoint, JournalBatchReceiptFrontier):
        start = checkpoint.to_bytes()
    else:
        # Canonical JournalBatchReceiptFrontier bytes, already validated by
        # the auditor constructor.
        start = checkpoint  # type: ignore[assignment]
    final = auditor.state
    body = _commit_range_body_bytes(
        start,
        tuple(
            (receipt.to_bytes(), batch.to_bytes())
            for receipt, batch in coerced
        ),
        final.to_bytes(),  # type: ignore[union-attr]
    )
    return CommitRange(
        version=1, body=body, mac=_commit_range_mac(key, body)
    )


def audit_range(
    x: object, key: object
) -> "JournalBatchReceiptFrontier":
    """Re-verify a :class:`CommitRange` against ``key``, from nothing or
    from its carried checkpoint.

    ``x`` must be a :class:`CommitRange` or its canonical
    :meth:`CommitRange.to_bytes` encoding and ``key`` the non-empty shared
    ``bytes`` key — a wrong-typed argument raises :class:`TypeError`, every
    other contract violation raises :class:`ValueError`. The range MAC is
    recomputed as ``HMAC-SHA256(key, b"NPBJ11" + body)`` and compared in
    constant time; then every carried ``[R, B]`` pair is replayed in order
    exactly as :class:`JournalBatchReceiptAuditor` audits it — each pair
    re-verified like :func:`audit_commit` and the frontier advanced per
    ``NPBJ10`` — starting from no commit at all when the body's ``S`` is
    empty and from that checkpoint frontier otherwise (its four MAC layers
    recomputed on load). The receipts must be contiguous — each one's start
    must equal the frontier end currently in force — and the replayed final
    frontier must equal the body's ``E`` byte for byte. Auditing is a pure
    check: it touches no auditor state and returns no partial result — on
    success the frozen :class:`JournalBatchReceiptFrontier` at ``E`` is
    returned, letting a third party independently establish both the
    continuous commit stream and its final frontier from an empty start or
    from a trusted checkpoint.
    """
    record = _coerce_commit_range(x, "x")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    if not hmac.compare_digest(
        _commit_range_mac(key, record.body), record.mac
    ):
        raise ValueError("commit range mac does not match the key")
    start, items, end = _parse_commit_range_body(record.body)
    checkpoint = (
        JournalBatchReceiptFrontier.from_bytes(start) if start else None
    )
    auditor = JournalBatchReceiptAuditor(key, checkpoint=checkpoint)
    for receipt, batch in items:
        auditor.audit(receipt, batch)
    final = auditor.state
    if final is None or final.to_bytes() != end:
        raise ValueError(
            "commit range end does not match the replayed chain"
        )
    return final


def _range_receipt_content(receipt: "RangeReceipt") -> list:
    """The JSON-ready first four range-receipt fields (everything but
    ``mac``)."""
    return [
        receipt.version,
        receipt.start.hex(),
        receipt.digest.hex(),
        receipt.end.hex(),
    ]


def _range_receipt_content_bytes(receipt: "RangeReceipt") -> bytes:
    """The canonical compact encoding ``C`` of the first four range-receipt
    fields."""
    return _encode_payload(_range_receipt_content(receipt))


def _range_receipt_mac(key: bytes, receipt: "RangeReceipt") -> bytes:
    """``HMAC-SHA256(key, b"NPBJ12" + C)`` where ``C`` is the canonical
    encoding of the first four fields. The prefix and ``C`` are concatenated
    directly with no separator or length prefix."""
    return hmac.new(
        key,
        _RANGE_RECEIPT_MAC_PREFIX + _range_receipt_content_bytes(receipt),
        hashlib.sha256,
    ).digest()


def _require_range_receipt_frontier(
    value: bytes, name: str, allow_empty: bool
) -> None:
    """Enforce the canonical-:class:`JournalBatchReceiptFrontier`-bytes
    contract of a range-receipt endpoint.

    ``value`` is already known to be ``bytes``; when ``allow_empty`` holds,
    ``b""`` (the range starts with no commit at all) is also accepted.
    :meth:`JournalBatchReceiptFrontier.from_bytes` enforces the full contract
    including its canonical re-encoding check, and every violation —
    including the field-shape :class:`TypeError` a malformed inner document
    would otherwise surface — raises :class:`ValueError`."""
    if allow_empty and value == b"":
        return
    try:
        JournalBatchReceiptFrontier.from_bytes(value)
    except (TypeError, ValueError) as error:
        suffix = " or empty" if allow_empty else ""
        raise ValueError(
            f"range receipt {name} must be the canonical"
            f" JournalBatchReceiptFrontier encoding{suffix}"
        ) from error


@dataclass(frozen=True)
class RangeReceipt:
    """A key-MAC'd commit receipt attesting one audited :class:`CommitRange`
    and the commit frontier it ends at.

    ``version`` is always ``1``. ``start`` is the canonical
    :meth:`JournalBatchReceiptFrontier.to_bytes` encoding of the commit
    frontier the range started from, or the empty byte string when it
    started from nothing (sequence zero, the commit digest chain rooted at
    ``d0``); ``end`` is the canonical non-empty
    :class:`JournalBatchReceiptFrontier` encoding the range ends at.
    ``digest`` is exactly 32 bytes — ``SHA256(x.to_bytes())`` over the
    canonical :meth:`CommitRange.to_bytes` encoding of the audited range.
    ``mac`` is exactly 32 bytes — ``HMAC-SHA256(key, b"NPBJ12" + C)`` where
    ``C`` is the canonical compact encoding of the first four fields (the
    version, lowercase-hex start, lowercase-hex digest and lowercase-hex
    end, without ``mac``), the prefix and ``C`` concatenated directly with
    no separator or length prefix. Instances are frozen, constructed
    positionally in field order and compare equal by their fields. A field
    of the wrong type raises :class:`TypeError`; every other contract
    violation raises :class:`ValueError`. No key material is stored.
    """

    version: int
    start: bytes
    digest: bytes
    end: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("range receipt version must be an integer")
        if self.version != 1:
            raise ValueError("range receipt version must be 1")
        if not isinstance(self.start, bytes):
            raise TypeError("range receipt start must be bytes")
        _require_range_receipt_frontier(self.start, "start", allow_empty=True)
        if not isinstance(self.digest, bytes):
            raise TypeError("range receipt digest must be bytes")
        if len(self.digest) != 32:
            raise ValueError("range receipt digest must be exactly 32 bytes")
        if not isinstance(self.end, bytes):
            raise TypeError("range receipt end must be bytes")
        _require_range_receipt_frontier(self.end, "end", allow_empty=False)
        if not isinstance(self.mac, bytes):
            raise TypeError("range receipt mac must be bytes")
        if len(self.mac) != 32:
            raise ValueError("range receipt mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the field-order array
        ``[1, start, digest, end, mac]`` where ``start``, ``digest``,
        ``end`` and ``mac`` are lowercase hex, no whitespace, no length
        prefix."""
        return _encode_payload(_range_receipt_content(self) + [self.mac.hex()])

    @classmethod
    def from_bytes(cls, data: bytes) -> "RangeReceipt":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and
        for fields of the wrong type; raises :class:`ValueError` for
        anything that does not satisfy the value contract: an array of
        exactly ``[version, start, digest, end, mac]`` in that order,
        ``version == 1``, ``start`` a lowercase hex string that is empty or
        decodes to the canonical non-empty
        :class:`JournalBatchReceiptFrontier` encoding, ``end`` a non-empty
        lowercase hex string decoding to the canonical non-empty
        :class:`JournalBatchReceiptFrontier` encoding, and ``digest``/``mac``
        lowercase hex strings decoding to exactly 32 bytes each. After
        parsing and field validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace and any non-canonical spelling are
        rejected too. No MAC is verified here — neither the receipt MAC nor
        the MACs of the carried checkpoints; pass the record to
        :func:`audit_receipt` with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("range receipt data must be bytes")
        try:
            outer = json.loads(data)
        except ValueError as error:
            raise ValueError(
                f"range receipt is not valid JSON: {error}"
            ) from error
        if not isinstance(outer, list) or len(outer) != 5:
            raise ValueError(
                "range receipt must be a JSON array of exactly version,"
                " start, digest, end and mac"
            )
        raw_version, raw_start, raw_digest, raw_end, raw_mac = outer
        if type(raw_version) is not int:
            raise TypeError("range receipt version must be an integer")
        if raw_version != 1:
            raise ValueError("range receipt version must be 1")
        start = _parse_bit_map_hex(raw_start, "range receipt start")
        _require_range_receipt_frontier(start, "start", allow_empty=True)
        digest = _parse_bit_map_hex(raw_digest, "range receipt digest")
        if len(digest) != 32:
            raise ValueError(
                "range receipt digest must decode to exactly 32 bytes"
            )
        end = _parse_bit_map_hex(raw_end, "range receipt end")
        _require_range_receipt_frontier(end, "end", allow_empty=False)
        mac = _parse_bit_map_hex(raw_mac, "range receipt mac")
        if len(mac) != 32:
            raise ValueError(
                "range receipt mac must decode to exactly 32 bytes"
            )
        record = cls(version=1, start=start, digest=digest, end=end, mac=mac)
        if record.to_bytes() != data:
            raise ValueError("range receipt encoding is not canonical")
        return record


def _coerce_range_receipt(x: object, name: str) -> "RangeReceipt":
    """Coerce a :class:`RangeReceipt` or its canonical bytes, splitting the
    TypeError/ValueError contract exactly as the public auditors do: the
    wrong kind of argument raises :class:`TypeError`, a field-shape failure
    surfacing while parsing byte content of the right kind is a value
    error."""
    if isinstance(x, RangeReceipt):
        return x
    if isinstance(x, bytes):
        try:
            return RangeReceipt.from_bytes(x)
        except TypeError as error:
            # The argument had the right kind; a field-shape failure
            # surfacing while parsing its byte content is a value error.
            raise ValueError(
                f"{name} does not satisfy the range receipt field contract"
            ) from error
    raise TypeError(
        f"{name} must be a RangeReceipt instance or its canonical bytes"
    )


class CommitRangeAuditor:
    """Stateful auditor chaining verified :class:`CommitRange` proofs into
    one monotone, restartable :class:`JournalBatchReceiptFrontier`
    checkpoint.

    ``key`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    shared key the ranges, commits and commit frontiers are MAC'd with.
    ``checkpoint`` is keyword-only: ``None`` (the default) starts from
    sequence zero with no commit at all and the commit digest chain rooted
    at ``d0`` (32 zero bytes); otherwise it must be a
    :class:`JournalBatchReceiptFrontier` or its canonical
    :meth:`JournalBatchReceiptFrontier.to_bytes` encoding (any other type
    raises :class:`TypeError`). A supplied frontier is checked at four MAC
    layers, all always recomputed and each compared in constant time before
    any result is consulted: the commit frontier's own ``NPBJ9`` MAC over
    the canonical encoding of its first four fields, and the three layers
    of its ``end`` receipt frontier — the embedded checkpoint table's
    ``NPBL1`` MAC, the journal state's own ``NPBJ1`` MAC and the receipt
    frontier's own ``NPBJ5`` MAC. A malformed encoding or any MAC mismatch
    raises :class:`ValueError`. Across a restart the caller must pass the
    value previously exported at :attr:`checkpoint`; nothing is persisted
    by the auditor itself.

    Each :meth:`audit` accepts one :class:`CommitRange` (or its canonical
    bytes) and, under the auditor lock, re-verifies it exactly like
    :func:`audit_range` — the ``NPBJ11`` range MAC, every carried
    ``[R, B]`` pair replayed per ``NPBJ10`` and the replayed final frontier
    matched against the body's ``E`` — and then demands the range
    continues exactly where the auditor stands: with no checkpoint the
    body's ``S`` must be the empty string, and otherwise it must equal the
    current checkpoint's canonical
    :meth:`JournalBatchReceiptFrontier.to_bytes` encoding byte for byte.
    Only when the whole range passes and ``E``'s sequence is strictly
    higher than the current sequence is the frontier atomically replaced
    by the frontier at ``E``; an old range, a replay to the same end, a
    same-sequence different-digest fork, a range that does not start at
    the current checkpoint, an end that does not match the replayed chain
    and a sequence that would overflow u64 are all rejected. Verification
    and the frontier replacement are one atomic step: a failed audit
    raises :class:`ValueError` (and a wrong-typed argument
    :class:`TypeError`), leaves the checkpoint untouched and returns no
    partial result, and concurrent audits linearize in lock-acquisition
    order.

    :meth:`commit` performs the same locked audit and atomic advance and,
    only once the checkpoint replacement has succeeded, seals the committed
    range as a :class:`RangeReceipt` — carrying the range's start (the
    empty byte string when the range started from nothing), the
    ``SHA256`` of the range's canonical
    :meth:`CommitRange.to_bytes` encoding, the canonical encoding of the
    new checkpoint frontier and the ``NPBJ12`` receipt MAC — so the
    commitment can be re-checked later with :func:`audit_receipt`. A failed
    commit changes nothing and produces no receipt.
    """

    def __init__(self, key: object, *, checkpoint: object = None) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must be non-empty")
        self._key = key
        self._lock = threading.Lock()
        self._frontier: "Optional[JournalBatchReceiptFrontier]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, JournalBatchReceiptFrontier):
            frontier = checkpoint
        elif isinstance(checkpoint, bytes):
            try:
                frontier = JournalBatchReceiptFrontier.from_bytes(checkpoint)
            except TypeError as error:
                # The argument had the right kind; a field-shape failure
                # surfacing while parsing its byte content is a value error.
                raise ValueError(
                    "checkpoint does not satisfy the journal batch receipt"
                    " frontier field contract"
                ) from error
        else:
            raise TypeError(
                "checkpoint must be a JournalBatchReceiptFrontier instance,"
                " its canonical bytes, or None"
            )
        _verify_journal_batch_receipt_frontier_macs(self._key, frontier)
        self._frontier = frontier

    @property
    def checkpoint(self) -> "Optional[JournalBatchReceiptFrontier]":
        """The current :class:`JournalBatchReceiptFrontier` checkpoint, or
        ``None`` before the first successfully audited range. The returned
        object is frozen and the property read-only; persist its
        :meth:`JournalBatchReceiptFrontier.to_bytes` output and pass it
        back to a new auditor to survive a restart."""
        return self._frontier

    def _advance_locked(self, record: "CommitRange") -> "tuple[bytes, JournalBatchReceiptFrontier]":
        """Re-verify ``record`` and atomically replace the checkpoint.

        Must be called with the auditor lock held. Returns the range's
        start bytes (the empty byte string when it started from nothing)
        and the new checkpoint frontier at the range's end. On any failure
        the checkpoint is left untouched."""
        # audit_range is a pure check: the NPBJ11 range MAC, every
        # carried commit pair replayed per NPBJ10 from the body's S,
        # and the replayed final frontier matched against E.
        final = audit_range(record, self._key)
        start, _, _ = _parse_commit_range_body(record.body)
        current = (
            b"" if self._frontier is None else self._frontier.to_bytes()
        )
        if start != current:
            raise ValueError(
                "commit range start does not match the checkpoint"
            )
        current_sequence = (
            0 if self._frontier is None else self._frontier.sequence
        )
        if current_sequence >= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "commit range auditor sequence would overflow the"
                " unsigned 64-bit range"
            )
        if final.sequence <= current_sequence:
            raise ValueError(
                "commit range end sequence does not strictly advance"
                " the checkpoint"
            )
        self._frontier = final
        return start, final

    def audit(self, x: object) -> "CommitRangeAuditor":
        """Audit one :class:`CommitRange` and advance the checkpoint.

        ``x`` must be a :class:`CommitRange` or its canonical
        :meth:`CommitRange.to_bytes` encoding — any other type raises
        :class:`TypeError`; a malformed or non-canonical encoding, a range
        MAC, commit MAC or digest mismatch, a broken commit chain, a
        replayed final frontier that does not equal the body's ``E``, a
        body ``S`` that does not equal the current checkpoint (the empty
        string when no range has been audited yet), an ``E`` sequence that
        does not strictly advance the current sequence, or a sequence that
        would overflow u64 raises :class:`ValueError`. The range is
        re-verified exactly as :func:`audit_range` verifies it and the
        start and sequence gates checked under the auditor lock, and the
        checkpoint is replaced by the frontier at ``E`` in the same atomic
        step, so a failed audit changes nothing and concurrent audits are
        serialized in lock-acquisition order. Returns the auditor itself.
        """
        with self._lock:
            record = _coerce_commit_range(x, "x")
            self._advance_locked(record)
            return self

    def commit(self, x: object) -> "RangeReceipt":
        """Audit one :class:`CommitRange`, advance the checkpoint and seal
        the commitment as a :class:`RangeReceipt`.

        ``x`` must be a :class:`CommitRange` or its canonical
        :meth:`CommitRange.to_bytes` encoding — any other type raises
        :class:`TypeError`; every contract violation :meth:`audit` rejects
        raises :class:`ValueError` here too. The whole range is audited
        under the auditor lock exactly as :meth:`audit` audits it and the
        checkpoint atomically advanced in the same step; only once the
        checkpoint replacement has succeeded is the receipt produced: its
        ``start`` is the range's start (the empty byte string when the
        range started from nothing), its ``digest`` the ``SHA256`` of the
        range's canonical :meth:`CommitRange.to_bytes` encoding, its
        ``end`` the canonical encoding of the new checkpoint frontier and
        its ``mac`` the ``NPBJ12`` receipt MAC
        ``HMAC-SHA256(key, b"NPBJ12" + C)``. A failed commit changes
        nothing and produces no receipt, and concurrent commits and audits
        linearize in lock-acquisition order. The returned receipt is
        frozen and stores no key material; pass it with the range and the
        shared key to :func:`audit_receipt` to re-verify the commitment.
        """
        with self._lock:
            record = _coerce_commit_range(x, "x")
            start, final = self._advance_locked(record)
            receipt = RangeReceipt(
                version=1,
                start=start,
                digest=hashlib.sha256(record.to_bytes()).digest(),
                end=final.to_bytes(),
                mac=b"\x00" * 32,
            )
            return replace(
                receipt,
                mac=_range_receipt_mac(self._key, receipt),
            )


def audit_receipt(
    r: object, x: object, key: object
) -> "JournalBatchReceiptFrontier":
    """Re-verify a :class:`RangeReceipt` against its :class:`CommitRange`
    and the shared ``key``.

    ``r`` must be a :class:`RangeReceipt` or its canonical
    :meth:`RangeReceipt.to_bytes` encoding, ``x`` the :class:`CommitRange`
    it attests or its canonical :meth:`CommitRange.to_bytes` encoding and
    ``key`` the non-empty shared ``bytes`` key — a wrong-typed argument
    raises :class:`TypeError`, every other contract violation raises
    :class:`ValueError`. The receipt MAC is recomputed as
    ``HMAC-SHA256(key, b"NPBJ12" + C)`` over the canonical encoding of the
    receipt's first four fields, the range digest recomputed as
    ``SHA256(x.to_bytes())`` and the receipt's ``start``/``end`` matched
    against the range body's ``S``/``E`` — all four always recomputed and
    each compared in constant time before any result is consulted. The
    range itself is then re-verified exactly as :func:`audit_range`
    verifies it — the ``NPBJ11`` range MAC, every carried ``[R, B]`` pair
    replayed per ``NPBJ10`` and the replayed final frontier matched
    against the body's ``E``. Auditing is a pure check: it touches no
    auditor state and returns no partial result — on success the frozen
    :class:`JournalBatchReceiptFrontier` at the range's end is returned.
    """
    receipt = _coerce_range_receipt(r, "r")
    record = _coerce_commit_range(x, "x")
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if not key:
        raise ValueError("key must be non-empty")
    start, _, end = _parse_commit_range_body(record.body)
    # The receipt MAC, the range digest and the two endpoints are all
    # always recomputed/compared in constant time before any result is
    # consulted.
    mac_ok = hmac.compare_digest(
        _range_receipt_mac(key, receipt), receipt.mac
    )
    digest_ok = hmac.compare_digest(
        hashlib.sha256(record.to_bytes()).digest(), receipt.digest
    )
    start_ok = hmac.compare_digest(receipt.start, start)
    end_ok = hmac.compare_digest(receipt.end, end)
    if not mac_ok or not digest_ok or not start_ok or not end_ok:
        raise ValueError(
            "range receipt mac, range digest or endpoints do not match"
        )
    # Verifying the range re-verifies its NPBJ11 MAC, every MAC layer of
    # both endpoint frontiers and the whole carried commit chain,
    # returning the frozen frontier at the range end (it itself raises
    # ValueError if the replayed frontier does not equal that end).
    return audit_range(record, key)


def audit(evidence: Evidence | bytes, key: bytes) -> Measurement:
    """Re-verify an :class:`Evidence` record against the shared ``key``.

    Accepts the record itself or its ``to_bytes()`` encoding and rejects an
    empty ``key``. The MAC and the response HMAC are recomputed with ``key``
    and compared in constant time, and the elapsed time and halved distance
    are recomputed from ``start``/``end``/``speed``; any mismatch raises
    :class:`ValueError`. On success the audited values are returned as a
    :class:`Measurement`.

    Auditing is a pure check: it touches no verifier state and is no
    substitute for replay protection or challenge TTLs at verification time.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    if isinstance(evidence, bytes):
        evidence = Evidence.from_bytes(evidence)
    elif not isinstance(evidence, Evidence):
        raise ValueError("evidence must be an Evidence instance or bytes")
    _validate_evidence(evidence)
    if not hmac.compare_digest(_evidence_mac(key, _evidence_payload(evidence)), evidence.mac):
        raise ValueError("evidence mac does not match")
    if not hmac.compare_digest(keyed_response(key, evidence.nonce), evidence.response):
        raise ValueError("evidence response does not match the key and nonce")
    elapsed = evidence.end - evidence.start
    if elapsed != evidence.elapsed:
        raise ValueError("evidence elapsed does not match start and end")
    distance = elapsed * evidence.speed / 2.0
    if distance != evidence.distance:
        raise ValueError("evidence distance does not match elapsed and speed")
    return Measurement(
        round_index=evidence.round_index,
        nonce=evidence.nonce,
        response=evidence.response,
        elapsed_seconds=evidence.elapsed,
        distance_meters=evidence.distance,
    )


def audit_bound(bound: "BoundEvidence | bytes", key: bytes) -> Measurement:
    """Re-verify a :class:`BoundEvidence` record against the shared ``key``.

    Accepts the record itself or its ``to_bytes()`` encoding and rejects an
    empty ``key``. Four independent checks run, each compared in constant
    time and each raising :class:`ValueError` on mismatch:

    - the outer MAC: ``HMAC-SHA256(key, b"NPBE1" + encoding)`` over the
      canonical encoding of every field except ``mac`` itself;
    - the inner evidence MAC, exactly as :func:`audit` recomputes it;
    - the commitment: ``SHA256(b"NPC1" + context + opening)`` must equal the
      recorded ``digest``;
    - the bound response: ``HMAC-SHA256(key, b"NPR1" + digest +
      u64be(round_index) + nonce)`` must equal the recorded response.

    The elapsed time and halved distance are then recomputed from the nested
    evidence's ``start``/``end``/``speed`` as in :func:`audit`. On success
    the audited values are returned as a :class:`Measurement`.

    Auditing is a pure check: it touches no verifier state and is no
    substitute for replay protection or challenge TTLs at verification time.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    if isinstance(bound, bytes):
        bound = BoundEvidence.from_bytes(bound)
    elif not isinstance(bound, BoundEvidence):
        raise ValueError("bound evidence must be a BoundEvidence instance or bytes")
    evidence = bound.evidence
    if not hmac.compare_digest(
        _bound_evidence_mac(key, _bound_evidence_payload(bound)), bound.mac
    ):
        raise ValueError("bound evidence mac does not match")
    if not hmac.compare_digest(
        _evidence_mac(key, _evidence_payload(evidence)), evidence.mac
    ):
        raise ValueError("bound evidence evidence mac does not match")
    if not hmac.compare_digest(
        context_digest(bound.context, bound.opening), bound.digest
    ):
        raise ValueError("bound evidence digest does not match context and opening")
    if not hmac.compare_digest(
        bound_response(key, bound.digest, evidence.round_index, evidence.nonce),
        evidence.response,
    ):
        raise ValueError("bound evidence response does not match the key and binding")
    elapsed = evidence.end - evidence.start
    if elapsed != evidence.elapsed:
        raise ValueError("bound evidence elapsed does not match start and end")
    distance = elapsed * evidence.speed / 2.0
    if distance != evidence.distance:
        raise ValueError("bound evidence distance does not match elapsed and speed")
    return Measurement(
        round_index=evidence.round_index,
        nonce=evidence.nonce,
        response=evidence.response,
        elapsed_seconds=evidence.elapsed,
        distance_meters=evidence.distance,
    )


def audit_bound_policy(
    bound: "BoundEvidence | bytes",
    key: bytes,
    *,
    now: object = None,
    max_age: object = None,
    revocations: object = None,
) -> Measurement:
    """Re-verify a :class:`BoundEvidence` and enforce an optional freshness policy.

    ``bound`` may be the record itself or its canonical
    :meth:`BoundEvidence.to_bytes` encoding. The cryptographic,
    canonical-encoding and ranging checks are exactly those of
    :func:`audit_bound`, which runs first; every check it performs (and every
    :class:`ValueError` it raises) applies unchanged.

    With ``max_age=None`` (the default) no freshness check is performed.
    Otherwise ``max_age`` must be a non-bool finite non-negative number and
    ``now`` is required — a non-bool finite number; omitting it or violating
    either contract raises :class:`ValueError`. The audited ``bound.evidence.end``
    is taken as the issuance completion time and must satisfy the closed
    interval ``0 <= now - end <= max_age``: future-dated or over-age evidence
    raises :class:`ValueError`, and equality at either boundary is valid.

    With ``revocations=None`` (the default) no revocation check is performed
    and the behaviour is exactly as before. Otherwise ``revocations`` must be
    an iterable of :class:`BoundEvidenceRevocation` and/or
    :class:`ContextRevocation` instances and/or their canonical
    :meth:`to_bytes` encodings (mixing is allowed); an item that is none of
    those, or bytes that do not parse, raises :class:`ValueError`. Every
    revocation's MAC is recomputed with the same ``key`` the evidence is
    audited under and compared in constant time, so a wrong key or any
    tampering raises :class:`ValueError`. Two bound-evidence revocations
    carrying the same ``(round_index, nonce)`` pair, or two context
    revocations carrying the same ``context``, are likewise rejected, so at
    most one revocation of each kind can match this bound. When revocations
    are given ``now`` is required exactly as under ``max_age`` (a finite
    non-bool number): a revocation with ``revoked_at > now`` raises
    :class:`ValueError`. A bound-evidence revocation matches when its
    ``round_index`` and ``nonce`` identify this bound's evidence; a context
    revocation matches when its ``context`` equals this bound's context. A
    matching revocation with ``revoked_at >= bound.evidence.end`` (i.e.
    ``end <= revoked_at``) raises :class:`ValueError`; a non-matching
    revocation is ignored beyond the MAC and timestamp checks, and evidence
    whose ``end`` is strictly after the matching revocation survives and
    then follows the usual freshness check.

    Like :func:`audit_bound` this is a pure check: it touches no verifier
    state and no challenge lifecycle.
    """
    measurement = audit_bound(bound, key)
    if max_age is None and revocations is None:
        # No policy at all: `now` is ignored entirely and no clock read.
        return measurement
    check_age = max_age is not None
    age_limit = 0.0
    if check_age:
        if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
            raise ValueError("max_age must be a finite non-negative number")
        age_limit = float(max_age)
        if not math.isfinite(age_limit) or age_limit < 0:
            raise ValueError("max_age must be a finite non-negative number")
    if now is None:
        raise ValueError("now is required when max_age or revocations are set")
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise ValueError("now must be a finite number")
    current = float(now)
    if not math.isfinite(current):
        raise ValueError("now must be a finite number")
    record = (
        BoundEvidence.from_bytes(bound) if isinstance(bound, bytes) else bound
    )
    if revocations is not None:
        try:
            raw_revocations = list(revocations)  # type: ignore[arg-type]
        except TypeError as error:
            raise ValueError(
                "revocations must be an iterable of BoundEvidenceRevocation"
                " or ContextRevocation instances or bytes"
            ) from error
        target = (record.evidence.round_index, record.evidence.nonce)
        seen: set[tuple] = set()
        for entry in raw_revocations:
            if isinstance(entry, bytes):
                entry = _decode_revocation_entry(entry)
            if isinstance(entry, BoundEvidenceRevocation):
                identity = ("round", entry.round_index, entry.nonce)
                expected = _bound_revocation_mac(
                    bytes(key), _bound_revocation_payload(entry)
                )
                matches = (entry.round_index, entry.nonce) == target
                duplicate = (
                    "revocations contain a duplicate (round_index, nonce) pair"
                )
                kind = "bound evidence revocation"
            elif isinstance(entry, ContextRevocation):
                identity = ("context", entry.context)
                expected = _context_revocation_mac(
                    bytes(key), _context_revocation_payload(entry)
                )
                matches = entry.context == record.context
                duplicate = "revocations contain a duplicate context"
                kind = "context revocation"
            else:
                raise ValueError(
                    "revocations must contain only BoundEvidenceRevocation"
                    " or ContextRevocation instances or bytes"
                )
            if identity in seen:
                raise ValueError(duplicate)
            seen.add(identity)
            if not hmac.compare_digest(expected, entry.mac):
                raise ValueError(f"{kind} mac does not match")
            revoked_at = float(entry.revoked_at)
            if revoked_at > current:
                raise ValueError(f"{kind} is dated in the future")
            # Uniqueness above guarantees at most one matching entry.
            if matches and record.evidence.end <= revoked_at:
                raise ValueError(
                    "bound evidence was not completed after its revocation"
                )
    if check_age:
        age = current - record.evidence.end
        if not 0.0 <= age <= age_limit:
            raise ValueError("bound evidence is outside the allowed age")
    return measurement


def _check_assess_params(limit: object, min_samples: object) -> tuple[float, int]:
    """Validate ``limit`` and ``min_samples`` for :func:`assess`."""
    if isinstance(limit, bool) or not isinstance(limit, (int, float)):
        raise ValueError("limit must be a finite non-negative number")
    bound = float(limit)
    if not math.isfinite(bound) or bound < 0:
        raise ValueError("limit must be a finite non-negative number")
    if isinstance(min_samples, bool) or type(min_samples) is not int or min_samples < 1:
        raise ValueError("min_samples must be a positive integer")
    return bound, min_samples


def assess(
    samples: object,
    limit: object,
    *,
    key: object = None,
    min_samples: object = 5,
) -> "RangeDecision":
    """Decide whether a batch of rounds puts the prover within ``limit``.

    ``samples`` must be either all :class:`Measurement` instances, or all
    :class:`Evidence` instances / their :meth:`Evidence.to_bytes` encodings;
    mixing the two families (or any other type) raises :class:`ValueError`.
    For evidence samples a non-empty ``key`` is required and every item is
    verified with :func:`audit` before anything else, exactly as a standalone
    audit would.

    Duplicate ``(round_index, nonce)`` pairs and negative or non-finite
    elapsed times/distances raise :class:`ValueError`, as do fewer than
    ``min_samples`` samples in total or fewer than ``min_samples`` inliers.
    ``limit`` must be a non-bool, finite, non-negative number and
    ``min_samples`` a non-bool positive integer.

    The inliers are defined robustly: with distance median ``m`` and median
    absolute deviation ``MAD``, a sample is an inlier when ``MAD > 0`` and
    its distance lies in the closed interval ``[m - 3*MAD, m + 3*MAD]``; if
    ``MAD == 0`` only samples whose distance equals ``m`` are inliers. The
    decision's ``upper_bound`` is the largest inlier distance and
    ``accepted`` is ``True`` exactly when it is at most ``limit``;
    ``sample_count`` counts every input sample, outliers included.

    The result does not depend on input order and no verifier state is read
    or mutated.
    """
    bound, minimum = _check_assess_params(limit, min_samples)

    try:
        raw_samples = list(samples)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "samples must be an iterable of Measurement or Evidence/bytes"
        ) from error

    def sample_kind(sample: object) -> str:
        if isinstance(sample, Measurement):
            return "measurement"
        if isinstance(sample, (Evidence, bytes)):
            return "evidence"
        return "invalid"

    kinds = {sample_kind(sample) for sample in raw_samples}
    if "invalid" in kinds or (
        "measurement" in kinds and "evidence" in kinds
    ):
        raise ValueError(
            "samples must be all Measurement or all Evidence/bytes, not mixed"
        )

    if "evidence" in kinds:
        # audit() accepts Evidence and bytes alike, rejects an empty key and
        # verifies each record under the same semantics as a standalone call.
        measurements = [audit(sample, key) for sample in raw_samples]
    else:
        measurements = list(raw_samples)  # type: ignore[arg-type]

    if len(measurements) < minimum:
        raise ValueError(f"need at least {minimum} samples, got {len(measurements)}")

    seen: set[tuple[int, bytes]] = set()
    distances: list[float] = []
    for measurement in measurements:
        if type(measurement.round_index) is not int or not isinstance(
            measurement.nonce, bytes
        ):
            raise ValueError("sample round_index must be an int and nonce bytes")
        pair = (measurement.round_index, measurement.nonce)
        if pair in seen:
            raise ValueError("samples contain a duplicate (round_index, nonce) pair")
        seen.add(pair)
        for name, value in (
            ("elapsed_seconds", measurement.elapsed_seconds),
            ("distance_meters", measurement.distance_meters),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"sample {name} must be a finite non-negative number")
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise ValueError(f"sample {name} must be a finite non-negative number")
        distances.append(float(measurement.distance_meters))

    center = median(distances)
    mad = median(abs(distance - center) for distance in distances)
    if mad > 0:
        low, high = center - 3.0 * mad, center + 3.0 * mad
        inliers = [
            distance for distance in distances if low <= distance <= high
        ]
    else:
        inliers = [distance for distance in distances if distance == center]

    if len(inliers) < minimum:
        raise ValueError(
            f"need at least {minimum} inliers, got {len(inliers)}"
        )

    upper_bound = max(inliers)
    return RangeDecision(
        sample_count=len(measurements),
        upper_bound=upper_bound,
        accepted=upper_bound <= bound,
    )


def _finite_non_bool(value: object) -> float:
    """Return ``float(value)`` for a non-bool finite number, else raise."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("value must be a finite non-bool number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("value must be a finite non-bool number")
    return number


def locate(
    observations: object,
    point: object,
    *,
    quorum: object = 3,
    tolerance: object = 0.0,
) -> "Consensus":
    """Run a 2D multi-verifier consensus over ``observations`` at ``point``.

    Each :class:`Observation` contributes a closed disk centered at
    ``(x, y)`` with radius ``decision.upper_bound + tolerance``; an
    observation supports the point when
    ``math.hypot(point[0] - x, point[1] - y) <= upper_bound + tolerance``
    (the boundary counts as support). The decision's ``accepted`` flag is
    deliberately ignored — only its bound participates.

    ``observations`` must be an iterable of at least three observations with
    unique non-empty string ids, finite non-bool ``x``/``y`` coordinates and
    a :class:`RangeDecision` whose ``upper_bound`` is finite and
    non-negative. ``point`` must be a tuple of exactly two finite non-bool
    numbers. ``quorum`` must be a non-bool positive integer not exceeding the
    observation count and ``tolerance`` a finite non-bool non-negative
    number; every contract violation raises :class:`ValueError`.

    Contradictory disks (a point some verifiers cover and others do not) are
    reported through the result's ``rejected`` ids, never as an exception.
    ``rejected`` is sorted lexicographically, so the result is independent
    of input order; ``accepted`` is ``True`` exactly when ``support``
    reaches ``quorum``.
    """
    if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)):
        raise ValueError("tolerance must be a finite non-negative number")
    slack = float(tolerance)
    if not math.isfinite(slack) or slack < 0:
        raise ValueError("tolerance must be a finite non-negative number")

    if isinstance(quorum, bool) or type(quorum) is not int or quorum < 1:
        raise ValueError("quorum must be a positive integer")

    if not isinstance(point, tuple) or len(point) != 2:
        raise ValueError("point must be a tuple of exactly two finite numbers")
    px = _finite_non_bool(point[0])
    py = _finite_non_bool(point[1])

    try:
        raw_observations = list(observations)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError("observations must be an iterable of Observation") from error

    if len(raw_observations) < 3:
        raise ValueError(
            f"need at least 3 observations, got {len(raw_observations)}"
        )
    if quorum > len(raw_observations):
        raise ValueError("quorum must not exceed the number of observations")

    rejected: list[str] = []
    seen_ids: set[str] = set()
    for observation in raw_observations:
        if not isinstance(observation, Observation):
            raise ValueError("observations must contain only Observation instances")
        ident = observation.id
        if not isinstance(ident, str) or not ident:
            raise ValueError("observation id must be a non-empty string")
        if ident in seen_ids:
            raise ValueError(f"duplicate observation id: {ident!r}")
        seen_ids.add(ident)
        ox = _finite_non_bool(observation.x)
        oy = _finite_non_bool(observation.y)
        decision = observation.decision
        if not isinstance(decision, RangeDecision):
            raise ValueError("observation decision must be a RangeDecision")
        bound = _finite_non_bool(decision.upper_bound)
        if bound < 0:
            raise ValueError("decision upper_bound must be non-negative")
        if math.hypot(px - ox, py - oy) > bound + slack:
            rejected.append(ident)

    rejected.sort()
    support = len(raw_observations) - len(rejected)
    return Consensus(
        total=len(raw_observations),
        support=support,
        rejected=tuple(rejected),
        accepted=support >= quorum,
    )


_ATTESTED_FIELDS = (
    "version",
    "id",
    "x",
    "y",
    "decision",
    "issued_at",
    "mac",
)

_BOUND_ATTESTED_FIELDS = (
    "version",
    "id",
    "x",
    "y",
    "decision",
    "point",
    "context",
    "issued_at",
    "mac",
)

_DECISION_FIELDS = ("sample_count", "upper_bound", "accepted")

_REVOCATION_FIELDS = ("version", "id", "revoked_at", "mac")

_TRUST_FIELDS = ("version", "id", "x", "y", "key", "mac")

_TRUST_REVOCATION_FIELDS = ("version", "id", "target", "mac")

_TRUST_REVOCATION_LIST_FIELDS = (
    "version",
    "sequence",
    "issued_at",
    "entries",
    "mac",
)


class _OrderedAttestedObject(json.JSONDecoder):
    """JSON decoder that rejects duplicate and out-of-field-order object keys.

    The outer attested-observation object, the bound attested-observation
    object, the nested decision object, the observation-revocation object,
    the verifier-trust object, the trust-revocation object and the outer
    trust-revocation-list object must each contain exactly their own fields,
    once each, in field order (the nested entries of a revocation list carry
    the trust-revocation key set); the field sets are distinguishable by
    their key lists, so a single hook can check all of them.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys in (
            list(_ATTESTED_FIELDS),
            list(_BOUND_ATTESTED_FIELDS),
            list(_DECISION_FIELDS),
            list(_REVOCATION_FIELDS),
            list(_TRUST_FIELDS),
            list(_TRUST_REVOCATION_FIELDS),
            list(_TRUST_REVOCATION_LIST_FIELDS),
        ):
            return dict(pairs)
        raise ValueError(
            "JSON keys must be exactly the record fields in field order"
        )


def _attested_payload(observation: "AttestedObservation") -> dict:
    """The JSON-ready attested-observation fields except ``mac``, in field order."""
    decision = observation.decision
    return {
        "version": observation.version,
        "id": observation.id,
        "x": observation.x,
        "y": observation.y,
        "decision": {
            "sample_count": decision.sample_count,
            "upper_bound": decision.upper_bound,
            "accepted": decision.accepted,
        },
        "issued_at": observation.issued_at,
    }


def _attested_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over the canonical encoding of the fields without ``mac``."""
    return hmac.new(key, _encode_payload(payload), hashlib.sha256).digest()


@dataclass(frozen=True)
class AttestedObservation:
    """A MAC'd, timestamped :class:`Observation`-style record.

    ``version`` is always ``1``; ``id`` a non-empty string; ``x``, ``y`` and
    ``issued_at`` finite non-bool non-negative numbers; ``decision`` a
    :class:`RangeDecision` with a positive-int ``sample_count``, a finite
    non-negative ``upper_bound`` and a bool ``accepted``; ``mac`` exactly 32
    bytes — HMAC-SHA256 over the canonical encoding of every field except
    ``mac`` itself. Any contract violation raises :class:`ValueError` at
    construction time. No key material is stored.
    """

    version: int
    id: str
    x: float
    y: float
    decision: "RangeDecision"
    issued_at: float
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("attested observation version must be 1")
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("attested observation id must be a non-empty string")
        for name in ("x", "y", "issued_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"attested observation {name} must be a finite non-negative number"
                )
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"attested observation {name} must be a finite non-negative number"
                )
        decision = self.decision
        if not isinstance(decision, RangeDecision):
            raise ValueError("attested observation decision must be a RangeDecision")
        if type(decision.sample_count) is not int or decision.sample_count < 1:
            raise ValueError("decision sample_count must be a positive integer")
        bound = decision.upper_bound
        if (
            isinstance(bound, bool)
            or not isinstance(bound, (int, float))
            or not math.isfinite(bound)
            or bound < 0
        ):
            raise ValueError("decision upper_bound must be a finite non-negative number")
        if type(decision.accepted) is not bool:
            raise ValueError("decision accepted must be a bool")
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError("attested observation mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``decision`` as a
        nested object with its keys in field order, ``mac`` as lowercase hex,
        no whitespace, no NaN/Infinity."""
        payload = _attested_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "AttestedObservation":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the attested-observation fields
        appearing once each in field order (missing, extra, duplicated or
        out-of-order keys are rejected, likewise inside the nested decision
        object), ``version == 1``, and the same per-field rules as the
        constructor, with ``mac`` a lowercase hex string decoding to exactly
        32 bytes. After parsing and field validation the record is re-encoded
        with :meth:`to_bytes` and the result must equal the input byte for
        byte, so formatted JSON, whitespace between fields or around the
        document, and any non-canonical number or string spelling are
        rejected as well. The MAC is not verified here — use
        :func:`locate_attested` with the shared keys for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("attested observation data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedAttestedObject)
        except ValueError as error:
            raise ValueError(f"attested observation is not valid JSON: {error}") from error
        if not isinstance(obj, dict) or list(obj) != list(_ATTESTED_FIELDS):
            raise ValueError(
                "attested observation must be a JSON object with exactly the"
                " attested observation fields"
            )
        decision = obj["decision"]
        if not isinstance(decision, dict) or list(decision) != list(_DECISION_FIELDS):
            raise ValueError(
                "attested observation decision must be a JSON object with exactly"
                " the decision fields"
            )
        raw_mac = obj["mac"]
        if not isinstance(raw_mac, str):
            raise ValueError("attested observation mac must be a lowercase hex string")
        try:
            mac = bytes.fromhex(raw_mac)
        except ValueError as error:
            raise ValueError(
                "attested observation mac must be a lowercase hex string"
            ) from error
        if mac.hex() != raw_mac:
            # Rejects uppercase digits, separators and odd-length input that
            # bytes.fromhex would otherwise tolerate.
            raise ValueError("attested observation mac must be a lowercase hex string")
        record = cls(
            version=obj["version"],
            id=obj["id"],
            x=obj["x"],
            y=obj["y"],
            decision=RangeDecision(
                sample_count=decision["sample_count"],
                upper_bound=decision["upper_bound"],
                accepted=decision["accepted"],
            ),
            issued_at=obj["issued_at"],
            mac=mac,
        )
        if record.to_bytes() != data:
            # The fields parsed and validated, but the bytes are not the
            # canonical encoding: whitespace anywhere, pretty-printing, or
            # non-canonical number/string spellings (e.g. "3" for 3.0 or
            # escape sequences the encoder would not emit).
            raise ValueError("attested observation encoding is not canonical")
        return record


def _bound_attested_payload(observation: "BoundAttestedObservation") -> dict:
    """The JSON-ready bound attested-observation fields except ``mac``."""
    decision = observation.decision
    point = observation.point
    return {
        "version": observation.version,
        "id": observation.id,
        "x": observation.x,
        "y": observation.y,
        "decision": {
            "sample_count": decision.sample_count,
            "upper_bound": decision.upper_bound,
            "accepted": decision.accepted,
        },
        # A bare JSON array, unlike the tuple-encoded query point: no type
        # label and no length prefix (the array length is fixed at two).
        "point": [point[0], point[1]],
        "context": observation.context,
        "issued_at": observation.issued_at,
    }


def _bound_attested_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over the canonical encoding of the fields without ``mac``."""
    return hmac.new(key, _encode_payload(payload), hashlib.sha256).digest()


@dataclass(frozen=True)
class BoundAttestedObservation:
    """A MAC'd, timestamped observation bound to one point and use context.

    Like :class:`AttestedObservation`, but the signature additionally covers
    ``point`` — a tuple of exactly two finite non-bool numbers — and
    ``context``, a non-empty string naming the use the observation is bound
    to. ``version`` is always ``1``; ``id`` a non-empty string; ``x``, ``y``
    and ``issued_at`` finite non-bool non-negative numbers; ``decision`` a
    :class:`RangeDecision` with a positive-int ``sample_count``, a finite
    non-negative ``upper_bound`` and a bool ``accepted``; ``mac`` exactly 32
    bytes — HMAC-SHA256 over the canonical encoding of every field except
    ``mac`` itself. Any contract violation raises :class:`ValueError` at
    construction time. No key material is stored.
    """

    version: int
    id: str
    x: float
    y: float
    decision: "RangeDecision"
    point: tuple[float, float]
    context: str
    issued_at: float
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("bound attested observation version must be 1")
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("bound attested observation id must be a non-empty string")
        for name in ("x", "y", "issued_at"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"bound attested observation {name} must be a finite"
                    " non-negative number"
                )
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"bound attested observation {name} must be a finite"
                    " non-negative number"
                )
        decision = self.decision
        if not isinstance(decision, RangeDecision):
            raise ValueError(
                "bound attested observation decision must be a RangeDecision"
            )
        if type(decision.sample_count) is not int or decision.sample_count < 1:
            raise ValueError("decision sample_count must be a positive integer")
        bound = decision.upper_bound
        if (
            isinstance(bound, bool)
            or not isinstance(bound, (int, float))
            or not math.isfinite(bound)
            or bound < 0
        ):
            raise ValueError("decision upper_bound must be a finite non-negative number")
        if type(decision.accepted) is not bool:
            raise ValueError("decision accepted must be a bool")
        point = self.point
        if not isinstance(point, tuple) or len(point) != 2:
            raise ValueError(
                "bound attested observation point must be a tuple of exactly"
                " two finite numbers"
            )
        for coordinate in point:
            _finite_non_bool(coordinate)
        if not isinstance(self.context, str) or not self.context:
            raise ValueError(
                "bound attested observation context must be a non-empty string"
            )
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError("bound attested observation mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``decision`` as a
        nested object with its keys in field order, ``point`` as a bare
        two-element JSON array, ``mac`` as lowercase hex, no whitespace, no
        NaN/Infinity."""
        payload = _bound_attested_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BoundAttestedObservation":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the bound attested-observation
        fields appearing once each in field order (missing, extra, duplicated
        or out-of-order keys are rejected, likewise inside the nested
        decision object), ``point`` a JSON array of exactly two finite
        non-bool numbers, ``context`` a non-empty string, ``version == 1``,
        and the same per-field rules as the constructor, with ``mac`` a
        lowercase hex string decoding to exactly 32 bytes. After parsing and
        field validation the record is re-encoded with :meth:`to_bytes` and
        the result must equal the input byte for byte, so formatted JSON,
        whitespace, non-canonical spellings, or any length prefix/framing
        around the single JSON document are rejected as well. The MAC is not
        verified here — use :func:`locate_bound_attested` with the shared
        keys for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("bound attested observation data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedAttestedObject)
        except ValueError as error:
            raise ValueError(
                f"bound attested observation is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(_BOUND_ATTESTED_FIELDS):
            raise ValueError(
                "bound attested observation must be a JSON object with exactly"
                " the bound attested observation fields"
            )
        decision = obj["decision"]
        if not isinstance(decision, dict) or list(decision) != list(_DECISION_FIELDS):
            raise ValueError(
                "bound attested observation decision must be a JSON object"
                " with exactly the decision fields"
            )
        raw_point = obj["point"]
        if (
            not isinstance(raw_point, list)
            or len(raw_point) != 2
            or any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(value) for value in raw_point)
        ):
            raise ValueError(
                "bound attested observation point must be an array of exactly"
                " two finite numbers"
            )
        raw_context = obj["context"]
        if not isinstance(raw_context, str) or not raw_context:
            raise ValueError(
                "bound attested observation context must be a non-empty string"
            )
        raw_mac = obj["mac"]
        if not isinstance(raw_mac, str):
            raise ValueError(
                "bound attested observation mac must be a lowercase hex string"
            )
        try:
            mac = bytes.fromhex(raw_mac)
        except ValueError as error:
            raise ValueError(
                "bound attested observation mac must be a lowercase hex string"
            ) from error
        if mac.hex() != raw_mac:
            # Rejects uppercase digits, separators and odd-length input that
            # bytes.fromhex would otherwise tolerate.
            raise ValueError(
                "bound attested observation mac must be a lowercase hex string"
            )
        record = cls(
            version=obj["version"],
            id=obj["id"],
            x=obj["x"],
            y=obj["y"],
            decision=RangeDecision(
                sample_count=decision["sample_count"],
                upper_bound=decision["upper_bound"],
                accepted=decision["accepted"],
            ),
            point=(raw_point[0], raw_point[1]),
            context=raw_context,
            issued_at=obj["issued_at"],
            mac=mac,
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as AttestedObservation.from_bytes:
            # no whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError(
                "bound attested observation encoding is not canonical"
            )
        return record


def _revocation_payload(revocation: "ObservationRevocation") -> dict:
    """The JSON-ready revocation fields except ``mac``, in field order."""
    return {
        "version": revocation.version,
        "id": revocation.id,
        "revoked_at": revocation.revoked_at,
    }


def _revocation_mac(key: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over the canonical encoding of the fields without ``mac``."""
    return hmac.new(key, _encode_payload(payload), hashlib.sha256).digest()


@dataclass(frozen=True)
class ObservationRevocation:
    """A MAC'd, timestamped revocation of one verifier's observations.

    ``version`` is always ``1``; ``id`` a non-empty string identifying the
    verifier whose earlier observations are revoked; ``revoked_at`` a finite
    non-bool non-negative number; ``mac`` exactly 32 bytes — HMAC-SHA256 over
    the canonical encoding of every field except ``mac`` itself (the payload
    is the object without ``mac``). Any contract violation raises
    :class:`ValueError` at construction time. No key material is stored.
    """

    version: int
    id: str
    revoked_at: float
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("observation revocation version must be 1")
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("observation revocation id must be a non-empty string")
        value = self.revoked_at
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                "observation revocation revoked_at must be a finite non-negative number"
            )
        if not math.isfinite(value) or value < 0:
            raise ValueError(
                "observation revocation revoked_at must be a finite non-negative number"
            )
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError("observation revocation mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``mac`` as
        lowercase hex, no whitespace, no NaN/Infinity."""
        payload = _revocation_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ObservationRevocation":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the revocation fields appearing
        once each in field order (missing, extra, duplicated or out-of-order
        keys are rejected), ``version == 1``, and the same per-field rules as
        the constructor, with ``mac`` a lowercase hex string decoding to
        exactly 32 bytes. After parsing and field validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the input
        byte for byte, so formatted JSON, whitespace and any non-canonical
        number or string spelling are rejected as well. The MAC is not
        verified here — use :func:`locate_attested` with the shared keys for
        that.
        """
        if not isinstance(data, bytes):
            raise ValueError("observation revocation data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedAttestedObject)
        except ValueError as error:
            raise ValueError(
                f"observation revocation is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(_REVOCATION_FIELDS):
            raise ValueError(
                "observation revocation must be a JSON object with exactly the"
                " observation revocation fields"
            )
        raw_mac = obj["mac"]
        if not isinstance(raw_mac, str):
            raise ValueError("observation revocation mac must be a lowercase hex string")
        try:
            mac = bytes.fromhex(raw_mac)
        except ValueError as error:
            raise ValueError(
                "observation revocation mac must be a lowercase hex string"
            ) from error
        if mac.hex() != raw_mac:
            # Rejects uppercase digits, separators and odd-length input that
            # bytes.fromhex would otherwise tolerate.
            raise ValueError("observation revocation mac must be a lowercase hex string")
        record = cls(
            version=obj["version"],
            id=obj["id"],
            revoked_at=obj["revoked_at"],
            mac=mac,
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as AttestedObservation.from_bytes.
            raise ValueError("observation revocation encoding is not canonical")
        return record


def revoke_observation(
    id: object,
    revoked_at: object,
    key: object,
) -> ObservationRevocation:
    """Sign a revocation of one verifier's earlier observations.

    ``key`` must be non-empty; ``id`` and ``revoked_at`` must satisfy the
    :class:`ObservationRevocation` field contract (``version`` is set to
    ``1``), and any violation raises :class:`ValueError`. The record is pure
    data: signing reads and mutates no verifier state.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    record = ObservationRevocation(
        version=1,
        id=id,  # type: ignore[arg-type]
        revoked_at=revoked_at,  # type: ignore[arg-type]
        mac=b"\x00" * 32,
    )
    return replace(record, mac=_revocation_mac(key, _revocation_payload(record)))


def attest_observation(
    id: object,
    x: object,
    y: object,
    decision: object,
    issued_at: object,
    key: object,
) -> AttestedObservation:
    """Sign one verifier's observation, returning an :class:`AttestedObservation`.

    ``key`` must be non-empty; every other argument must satisfy the
    :class:`AttestedObservation` field contract (``version`` is set to ``1``),
    and any violation raises :class:`ValueError`. The record is pure data:
    signing reads and mutates no verifier state.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    record = AttestedObservation(
        version=1,
        id=id,  # type: ignore[arg-type]
        x=x,  # type: ignore[arg-type]
        y=y,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        issued_at=issued_at,  # type: ignore[arg-type]
        mac=b"\x00" * 32,
    )
    return replace(record, mac=_attested_mac(key, _attested_payload(record)))


def attest_observation_for_point(
    id: object,
    x: object,
    y: object,
    decision: object,
    point: object,
    context: object,
    issued_at: object,
    key: object,
) -> BoundAttestedObservation:
    """Sign one verifier's observation bound to ``point`` and ``context``.

    Returns a :class:`BoundAttestedObservation`. ``key`` must be non-empty;
    every other argument must satisfy the
    :class:`BoundAttestedObservation` field contract (``version`` is set to
    ``1``), and any violation raises :class:`ValueError`. The record is pure
    data: signing reads and mutates no verifier state.
    """
    if not key:
        raise ValueError("key must not be empty")
    key = bytes(key)
    record = BoundAttestedObservation(
        version=1,
        id=id,  # type: ignore[arg-type]
        x=x,  # type: ignore[arg-type]
        y=y,  # type: ignore[arg-type]
        decision=decision,  # type: ignore[arg-type]
        point=point,  # type: ignore[arg-type]
        context=context,  # type: ignore[arg-type]
        issued_at=issued_at,  # type: ignore[arg-type]
        mac=b"\x00" * 32,
    )
    return replace(
        record, mac=_bound_attested_mac(key, _bound_attested_payload(record))
    )


def locate_attested(
    observations: object,
    point: object,
    keys: object,
    *,
    quorum: object = 3,
    tolerance: object = 0.0,
    now: object = None,
    max_age: object = None,
    revocations: object = None,
) -> "Consensus":
    """Like :func:`locate`, but over MAC'd :class:`AttestedObservation` records.

    ``observations`` is an iterable of :class:`AttestedObservation` instances
    and/or their :meth:`AttestedObservation.to_bytes` encodings (mixing is
    allowed). ``keys`` must be a non-empty mapping of observation id to the
    non-empty shared key bytes of that verifier. Every record's MAC is
    recomputed with ``keys[id]`` and compared in constant time; an id missing
    from ``keys``, a duplicated id, a wrong key, or any tampering raises
    :class:`ValueError`.

    With ``max_age=None`` (the default) no freshness check is performed.
    Otherwise ``max_age`` must be a finite non-bool non-negative number and
    every record must satisfy ``0 <= now - issued_at <= max_age``, where
    ``now`` defaults to ``time.time()`` and, when given, must be a finite
    non-bool number; stale or future-dated records raise :class:`ValueError`.

    With ``revocations=None`` (the default) no revocation check is performed
    and the behaviour is exactly as before. Otherwise ``revocations`` must be
    an iterable of :class:`ObservationRevocation` instances and/or their
    canonical :meth:`ObservationRevocation.to_bytes` encodings (mixing is
    allowed). Each revocation's MAC is recomputed with ``keys[id]`` and
    compared in constant time; an id missing from ``keys``, a duplicated
    revocation id, a wrong key, any tampering, or any item that is neither a
    revocation nor its canonical bytes raises :class:`ValueError`. When
    revocations are given, ``now`` is required exactly as under ``max_age``
    (a finite non-bool number, defaulting to a single ``time.time()``
    reading) and a revocation with ``revoked_at > now`` raises
    :class:`ValueError`. An observation whose ``issued_at`` is at or before
    the ``revoked_at`` of a revocation with the same id raises
    :class:`ValueError`; observations issued strictly after the revocation
    are kept and follow the usual freshness and geometry rules.

    Verified records are then fed to :func:`locate` under its exact rules
    (``quorum`` and ``tolerance`` included) and its :class:`Consensus` is
    returned. The function is pure: it reads no verifier state and, aside
    from the default ``now`` clock reading, has no side effects.
    """
    if not isinstance(keys, Mapping) or not keys:
        raise ValueError("keys must be a non-empty mapping of observation id to key")
    key_map: dict[str, bytes] = {}
    for ident, key in keys.items():
        if not isinstance(ident, str) or not ident:
            raise ValueError("keys must map non-empty string ids to non-empty keys")
        if not isinstance(key, (bytes, bytearray)) or not key:
            raise ValueError("keys must map non-empty string ids to non-empty keys")
        key_map[ident] = bytes(key)

    check_age = max_age is not None
    age_limit = 0.0
    if check_age:
        if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
            raise ValueError("max_age must be a finite non-negative number")
        age_limit = float(max_age)
        if not math.isfinite(age_limit) or age_limit < 0:
            raise ValueError("max_age must be a finite non-negative number")
    current = 0.0
    if check_age or revocations is not None:
        # The clock is read at most once per call, and only when a freshness
        # or revocation check actually needs the current time.
        if now is None:
            current = time.time()
        elif isinstance(now, bool) or not isinstance(now, (int, float)):
            raise ValueError("now must be a finite number")
        else:
            current = float(now)
            if not math.isfinite(current):
                raise ValueError("now must be a finite number")

    revoked_at_by_id: dict[str, float] = {}
    if revocations is not None:
        try:
            raw_revocations = list(revocations)  # type: ignore[arg-type]
        except TypeError as error:
            raise ValueError(
                "revocations must be an iterable of ObservationRevocation or bytes"
            ) from error
        for entry in raw_revocations:
            if isinstance(entry, bytes):
                entry = ObservationRevocation.from_bytes(entry)
            if not isinstance(entry, ObservationRevocation):
                raise ValueError(
                    "revocations must contain only ObservationRevocation"
                    " instances or bytes"
                )
            ident = entry.id
            if ident in revoked_at_by_id:
                raise ValueError(f"duplicate revocation id: {ident!r}")
            key = key_map.get(ident)
            if key is None:
                raise ValueError(f"unknown revocation id: {ident!r}")
            if not hmac.compare_digest(
                _revocation_mac(key, _revocation_payload(entry)), entry.mac
            ):
                raise ValueError(
                    f"observation revocation mac does not match: {ident!r}"
                )
            revoked_at = float(entry.revoked_at)
            if revoked_at > current:
                raise ValueError(
                    f"observation revocation is dated in the future: {ident!r}"
                )
            revoked_at_by_id[ident] = revoked_at

    try:
        raw_observations = list(observations)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "observations must be an iterable of AttestedObservation or bytes"
        ) from error

    verified: list[Observation] = []
    seen_ids: set[str] = set()
    for item in raw_observations:
        if isinstance(item, bytes):
            item = AttestedObservation.from_bytes(item)
        if not isinstance(item, AttestedObservation):
            raise ValueError(
                "observations must contain only AttestedObservation instances or bytes"
            )
        ident = item.id
        if ident in seen_ids:
            raise ValueError(f"duplicate observation id: {ident!r}")
        seen_ids.add(ident)
        key = key_map.get(ident)
        if key is None:
            raise ValueError(f"unknown observation id: {ident!r}")
        if not hmac.compare_digest(
            _attested_mac(key, _attested_payload(item)), item.mac
        ):
            raise ValueError(f"attested observation mac does not match: {ident!r}")
        revoked_at = revoked_at_by_id.get(ident)
        if revoked_at is not None and float(item.issued_at) <= revoked_at:
            raise ValueError(
                f"attested observation not issued after its revocation: {ident!r}"
            )
        if check_age:
            age = current - float(item.issued_at)
            if not 0.0 <= age <= age_limit:
                raise ValueError(
                    f"attested observation outside the allowed age: {ident!r}"
                )
        verified.append(
            Observation(id=ident, x=item.x, y=item.y, decision=item.decision)
        )

    return locate(verified, point, quorum=quorum, tolerance=tolerance)


def locate_bound_attested(
    observations: object,
    point: object,
    context: object,
    keys: object,
    *,
    quorum: object = 3,
    tolerance: object = 0.0,
    now: object = None,
    max_age: object = None,
    revocations: object = None,
) -> "Consensus":
    """Like :func:`locate_attested`, but over point-bound
    :class:`BoundAttestedObservation` records.

    ``observations`` is an iterable of :class:`BoundAttestedObservation`
    instances and/or their :meth:`BoundAttestedObservation.to_bytes`
    encodings (mixing is allowed). ``keys``, ``now``, ``max_age`` and
    ``revocations`` follow the exact same rules as in
    :func:`locate_attested`: each record's MAC is recomputed with
    ``keys[id]`` and compared in constant time, and freshness/revocation
    checks are identical.

    In addition, after its MAC verifies, every record must be bound to the
    query: its ``point`` must equal ``point`` coordinate by coordinate and
    its ``context`` must equal ``context`` exactly. A record bound to a
    different point or context raises :class:`ValueError`, so a signature
    cannot be replayed into another location or use. ``point`` must be a
    tuple of exactly two finite non-bool numbers and ``context`` a non-empty
    string, as in :func:`locate`.

    Verified, matching records are then fed to :func:`locate` under its exact
    rules (``quorum`` and ``tolerance`` included) and its :class:`Consensus`
    is returned; failing to reach ``quorum`` is reported through the result,
    never as an exception. Contract violations raise :class:`ValueError`;
    calling-shape errors (missing or unexpected arguments, keyword-only
    options passed positionally) raise :class:`TypeError` as usual.
    """
    if not isinstance(keys, Mapping) or not keys:
        raise ValueError("keys must be a non-empty mapping of observation id to key")
    key_map: dict[str, bytes] = {}
    for ident, key in keys.items():
        if not isinstance(ident, str) or not ident:
            raise ValueError("keys must map non-empty string ids to non-empty keys")
        if not isinstance(key, (bytes, bytearray)) or not key:
            raise ValueError("keys must map non-empty string ids to non-empty keys")
        key_map[ident] = bytes(key)

    check_age = max_age is not None
    age_limit = 0.0
    if check_age:
        if isinstance(max_age, bool) or not isinstance(max_age, (int, float)):
            raise ValueError("max_age must be a finite non-negative number")
        age_limit = float(max_age)
        if not math.isfinite(age_limit) or age_limit < 0:
            raise ValueError("max_age must be a finite non-negative number")
    current = 0.0
    if check_age or revocations is not None:
        # The clock is read at most once per call, and only when a freshness
        # or revocation check actually needs the current time.
        if now is None:
            current = time.time()
        elif isinstance(now, bool) or not isinstance(now, (int, float)):
            raise ValueError("now must be a finite number")
        else:
            current = float(now)
            if not math.isfinite(current):
                raise ValueError("now must be a finite number")

    # The query binding is needed while examining every record, so enforce
    # the point/context contract up front under the same rules as locate().
    if not isinstance(point, tuple) or len(point) != 2:
        raise ValueError("point must be a tuple of exactly two finite numbers")
    px = _finite_non_bool(point[0])
    py = _finite_non_bool(point[1])
    if not isinstance(context, str) or not context:
        raise ValueError("context must be a non-empty string")

    revoked_at_by_id: dict[str, float] = {}
    if revocations is not None:
        try:
            raw_revocations = list(revocations)  # type: ignore[arg-type]
        except TypeError as error:
            raise ValueError(
                "revocations must be an iterable of ObservationRevocation or bytes"
            ) from error
        for entry in raw_revocations:
            if isinstance(entry, bytes):
                entry = ObservationRevocation.from_bytes(entry)
            if not isinstance(entry, ObservationRevocation):
                raise ValueError(
                    "revocations must contain only ObservationRevocation"
                    " instances or bytes"
                )
            ident = entry.id
            if ident in revoked_at_by_id:
                raise ValueError(f"duplicate revocation id: {ident!r}")
            key = key_map.get(ident)
            if key is None:
                raise ValueError(f"unknown revocation id: {ident!r}")
            if not hmac.compare_digest(
                _revocation_mac(key, _revocation_payload(entry)), entry.mac
            ):
                raise ValueError(
                    f"observation revocation mac does not match: {ident!r}"
                )
            revoked_at = float(entry.revoked_at)
            if revoked_at > current:
                raise ValueError(
                    f"observation revocation is dated in the future: {ident!r}"
                )
            revoked_at_by_id[ident] = revoked_at

    try:
        raw_observations = list(observations)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "observations must be an iterable of BoundAttestedObservation or bytes"
        ) from error

    verified: list[Observation] = []
    seen_ids: set[str] = set()
    for item in raw_observations:
        if isinstance(item, bytes):
            item = BoundAttestedObservation.from_bytes(item)
        if not isinstance(item, BoundAttestedObservation):
            raise ValueError(
                "observations must contain only BoundAttestedObservation"
                " instances or bytes"
            )
        ident = item.id
        if ident in seen_ids:
            raise ValueError(f"duplicate observation id: {ident!r}")
        seen_ids.add(ident)
        key = key_map.get(ident)
        if key is None:
            raise ValueError(f"unknown observation id: {ident!r}")
        if not hmac.compare_digest(
            _bound_attested_mac(key, _bound_attested_payload(item)), item.mac
        ):
            raise ValueError(
                f"bound attested observation mac does not match: {ident!r}"
            )
        # Only after the MAC verifies do the point/context bindings count:
        # the signed record must match the query coordinate by coordinate and
        # carry exactly the queried use context, or it is a contract breach.
        if item.point[0] != px or item.point[1] != py or item.context != context:
            raise ValueError(
                "bound attested observation is not bound to the queried"
                f" point and context: {ident!r}"
            )
        revoked_at = revoked_at_by_id.get(ident)
        if revoked_at is not None and float(item.issued_at) <= revoked_at:
            raise ValueError(
                f"attested observation not issued after its revocation: {ident!r}"
            )
        if check_age:
            age = current - float(item.issued_at)
            if not 0.0 <= age <= age_limit:
                raise ValueError(
                    f"attested observation outside the allowed age: {ident!r}"
                )
        verified.append(
            Observation(id=ident, x=item.x, y=item.y, decision=item.decision)
        )

    return locate(verified, point, quorum=quorum, tolerance=tolerance)


def _trust_payload(trust: "VerifierTrust") -> dict:
    """The JSON-ready verifier-trust fields except ``mac``, in field order."""
    return {
        "version": trust.version,
        "id": trust.id,
        "x": trust.x,
        "y": trust.y,
        "key": trust.key.hex(),
    }


def _trust_mac(root: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPVT1"`` plus the canonical encoding without ``mac``.

    The prefix and the encoding are concatenated directly, with no separator
    or length prefix.
    """
    return hmac.new(
        root, _TRUST_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _require_root(root: object) -> bytes:
    """Validate a root MAC key: non-empty ``bytes``, never coerced.

    A non-bytes value (``bytearray``, ``str``, ``None`` included) is a shape
    error raising :class:`TypeError`; an empty ``bytes`` value raises
    :class:`ValueError`.
    """
    if not isinstance(root, bytes):
        raise TypeError("root must be bytes")
    if not root:
        raise ValueError("root must not be empty")
    return root


@dataclass(frozen=True)
class VerifierTrust:
    """A root-MAC'd trust record binding one verifier id to its position and key.

    ``version`` is always ``1``; ``id`` a non-empty string; ``x`` and ``y``
    finite non-bool non-negative numbers; ``key`` the verifier's shared key,
    exactly 32 bytes; ``mac`` exactly 32 bytes —
    ``HMAC-SHA256(root, b"NPVT1" + encoding)`` over the canonical encoding of
    every field except ``mac`` itself, the prefix and the encoding
    concatenated directly with no length prefix. Any contract violation
    raises :class:`ValueError` at construction time. Instances are frozen,
    constructed positionally in field order and compare equal by their
    fields. No root material is stored.
    """

    version: int
    id: str
    x: float
    y: float
    key: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("verifier trust version must be 1")
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("verifier trust id must be a non-empty string")
        for name in ("x", "y"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"verifier trust {name} must be a finite non-negative number"
                )
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"verifier trust {name} must be a finite non-negative number"
                )
        for name in ("key", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"verifier trust {name} must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``key`` and
        ``mac`` as lowercase hex, no whitespace, no NaN/Infinity."""
        payload = _trust_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "VerifierTrust":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: exactly the verifier-trust fields appearing
        once each in field order (missing, extra, duplicated or out-of-order
        keys are rejected), ``version == 1``, and the same per-field rules as
        the constructor, with ``key`` and ``mac`` lowercase hex strings
        decoding to exactly 32 bytes each. After parsing and field validation
        the record is re-encoded with :meth:`to_bytes` and the result must
        equal the input byte for byte, so formatted JSON, whitespace and any
        non-canonical number or string spelling are rejected as well. The MAC
        is not verified here — use :func:`locate_cert` with the root key for
        that.
        """
        if not isinstance(data, bytes):
            raise ValueError("verifier trust data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedAttestedObject)
        except ValueError as error:
            raise ValueError(f"verifier trust is not valid JSON: {error}") from error
        if not isinstance(obj, dict) or list(obj) != list(_TRUST_FIELDS):
            raise ValueError(
                "verifier trust must be a JSON object with exactly the"
                " verifier trust fields"
            )
        record = cls(
            version=obj["version"],
            id=obj["id"],
            x=obj["x"],
            y=obj["y"],
            key=_parse_hex_field(obj["key"], "key"),
            mac=_parse_hex_field(obj["mac"], "mac"),
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("verifier trust encoding is not canonical")
        return record


def cert(
    id: object,
    x: object,
    y: object,
    key: object,
    root: object,
) -> VerifierTrust:
    """Sign a verifier-trust record under the root key, returning a
    :class:`VerifierTrust`.

    ``root`` must be non-empty ``bytes`` (a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`); every other
    argument must satisfy the :class:`VerifierTrust` field contract
    (``version`` is set to ``1``), and any violation raises
    :class:`ValueError`. The MAC is
    ``HMAC-SHA256(root, b"NPVT1" + encoding)`` over the canonical encoding of
    every field except ``mac`` itself, the two segments concatenated directly
    with no length prefix. The record is pure data: signing reads and mutates
    no verifier state.
    """
    root = _require_root(root)
    record = VerifierTrust(
        version=1,
        id=id,  # type: ignore[arg-type]
        x=x,  # type: ignore[arg-type]
        y=y,  # type: ignore[arg-type]
        key=key,  # type: ignore[arg-type]
        mac=b"\x00" * 32,
    )
    return replace(record, mac=_trust_mac(root, _trust_payload(record)))


def locate_cert(
    records: object,
    point: object,
    context: object,
    trusts: object,
    root: object,
    *,
    revocations: object = None,
    now: object = None,
    min: object = 0,
) -> "Consensus":
    """Like :func:`locate_bound_attested`, but keyed by root-certified
    :class:`VerifierTrust` records instead of a caller-supplied key mapping.

    ``records`` is an iterable of :class:`BoundAttestedObservation` instances
    and/or their :meth:`BoundAttestedObservation.to_bytes` encodings (mixing
    is allowed). ``trusts`` is an iterable of :class:`VerifierTrust`
    instances and/or their :meth:`VerifierTrust.to_bytes` encodings (mixing
    is allowed), at most one per id; ``root`` must be non-empty ``bytes`` (a
    non-bytes value raises :class:`TypeError`, an empty value
    :class:`ValueError`). Every trust's MAC is recomputed with ``root`` and
    compared in constant time; a duplicated trust id, a wrong root, or any
    tampering raises :class:`ValueError`. Each record id must then have
    exactly one trust: the record's MAC is recomputed with that trust's
    ``key`` and compared in constant time, and the trust's ``id``/``x``/``y``
    must equal the record's — a missing trust, a MAC mismatch, or an
    ``x``/``y`` disagreement raises :class:`ValueError`.

    With ``revocations=None`` (the default, also for an empty iterable) no
    revocation check is performed and the behaviour is exactly as before.
    Otherwise ``revocations`` is either a per-call iterable (the legacy
    form) or a signed snapshot :class:`TrustRevocationList` (object or its
    canonical :meth:`TrustRevocationList.to_bytes` bytes).

    The legacy iterable must contain :class:`TrustRevocation` instances
    and/or their canonical :meth:`TrustRevocation.to_bytes` encodings
    (mixing is allowed); an item that is neither, or bytes that do not
    parse, raises :class:`ValueError`. Every revocation's root MAC is
    recomputed with the same ``root`` and compared in constant time, so a
    wrong root or any tampering raises :class:`ValueError`. Two revocations
    carrying the same ``(id, target)`` pair are rejected as duplicates. A
    revocation hits a trust when its ``id`` equals the trust's id and its
    ``target`` equals the trust's ``mac``; a hit permanently revokes that
    certificate, so any observation whose id uses that trust raises
    :class:`ValueError` (a revocation can never revoke a certificate it was
    not issued against, because the target binds the exact certificate
    MAC). A revocation whose ``(id, target)`` pair does not hit one of the
    certificates the records actually use — an unknown id, a different
    certificate with the same id, or a certificate present in ``trusts``
    but unused by the records — is likewise rejected with
    :class:`ValueError`.

    A snapshot is a global list, so unlike the legacy iterable it may carry
    entries for certificates unrelated to this call: only its hits apply.
    It is authenticated wholesale with :func:`audit_crl` under ``root`` and
    ``now`` (required for a snapshot; omitting it raises
    :class:`ValueError`) and ``min`` (a non-bool integer, default ``0``):
    the list MAC and every entry MAC must verify, ``issued_at`` must not be
    in the future relative to ``now`` and ``sequence`` must be at least
    ``min``. A hit revokes the matching certificate exactly as under the
    legacy form. ``now`` and ``min`` are ignored for the legacy iterable
    form, whose semantics are unchanged.

    The remaining rules are exactly those of :func:`locate_bound_attested`
    with ``quorum`` fixed at ``3`` and ``tolerance`` fixed at ``0.0``:
    ``point`` must be a tuple of exactly two finite non-bool numbers,
    ``context`` a non-empty string, every record must be bound to the queried
    point and context, and the verified records are fed to :func:`locate`,
    whose :class:`Consensus` is returned. Contract violations raise
    :class:`ValueError`; the function is pure and reads no verifier state.
    """
    root = _require_root(root)

    # The query binding is needed while examining every record, so enforce
    # the point/context contract up front under the same rules as locate().
    if not isinstance(point, tuple) or len(point) != 2:
        raise ValueError("point must be a tuple of exactly two finite numbers")
    px = _finite_non_bool(point[0])
    py = _finite_non_bool(point[1])
    if not isinstance(context, str) or not context:
        raise ValueError("context must be a non-empty string")

    try:
        raw_trusts = list(trusts)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "trusts must be an iterable of VerifierTrust or bytes"
        ) from error
    trust_map: dict[str, VerifierTrust] = {}
    for entry in raw_trusts:
        if isinstance(entry, bytes):
            entry = VerifierTrust.from_bytes(entry)
        if not isinstance(entry, VerifierTrust):
            raise ValueError(
                "trusts must contain only VerifierTrust instances or bytes"
            )
        ident = entry.id
        if ident in trust_map:
            raise ValueError(f"duplicate trust id: {ident!r}")
        if not hmac.compare_digest(
            _trust_mac(root, _trust_payload(entry)), entry.mac
        ):
            raise ValueError(f"verifier trust mac does not match: {ident!r}")
        trust_map[ident] = entry

    # A revocation is permanent and targets the exact MAC of one
    # certificate, so every entry is fully validated (shape, uniqueness and
    # root MAC, all in constant time) before the records are verified; a
    # pair that does not hit a certificate the records actually use is
    # itself a contract breach.
    try:
        raw_records = list(records)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "records must be an iterable of BoundAttestedObservation or bytes"
        ) from error

    parsed_records: list[BoundAttestedObservation] = []
    used_ids: set[str] = set()
    for item in raw_records:
        if isinstance(item, bytes):
            item = BoundAttestedObservation.from_bytes(item)
        if not isinstance(item, BoundAttestedObservation):
            raise ValueError(
                "records must contain only BoundAttestedObservation"
                " instances or bytes"
            )
        parsed_records.append(item)
        used_ids.add(item.id)

    used_pairs = {
        (ident, trust_map[ident].mac)
        for ident in used_ids
        if ident in trust_map
    }
    revoked_pairs: set[tuple[str, bytes]] = set()
    if revocations is not None:
        if isinstance(revocations, (TrustRevocationList, bytes)):
            # Signed global snapshot: authenticated as a whole (both MAC
            # layers, issued_at and sequence) under root/now/min; `now` is
            # mandatory here and audit_crl raises if it is missing. A
            # snapshot is global, so only its hits apply — entries naming
            # other certificates are not a contract breach.
            audit_crl(revocations, root, now, min=min)
            snapshot = (
                TrustRevocationList.from_bytes(revocations)
                if isinstance(revocations, bytes)
                else revocations
            )
            revoked_pairs = {
                (entry.id, entry.target) for entry in snapshot.entries
            }
        else:
            try:
                raw_revocations = list(revocations)  # type: ignore[arg-type]
            except TypeError as error:
                raise ValueError(
                    "revocations must be an iterable of TrustRevocation or bytes,"
                    " or a TrustRevocationList snapshot"
                ) from error
            for entry in raw_revocations:
                if isinstance(entry, bytes):
                    entry = TrustRevocation.from_bytes(entry)
                if not isinstance(entry, TrustRevocation):
                    raise ValueError(
                        "revocations must contain only TrustRevocation instances"
                        " or bytes, or be a TrustRevocationList snapshot"
                    )
                pair = (entry.id, entry.target)
                if pair in revoked_pairs:
                    raise ValueError(
                        "revocations contain a duplicate (id, target) pair:"
                        f" {entry.id!r}"
                    )
                revoked_pairs.add(pair)
                if not hmac.compare_digest(
                    _trust_revocation_mac(
                        root, _trust_revocation_payload(entry)
                    ),
                    entry.mac,
                ):
                    raise ValueError(
                        f"trust revocation mac does not match: {entry.id!r}"
                    )
            for pair in revoked_pairs:
                # Only after every entry's root MAC has checked out do the
                # target bindings count: a validly signed revocation must hit
                # exactly a certificate used by one of the records — an
                # unrecognized id/target (an unused or unknown certificate
                # included) is rejected rather than silently ignored.
                if pair not in used_pairs:
                    raise ValueError(
                        "trust revocation does not match a certificate used by"
                        f" the records: {pair[0]!r}"
                    )

    verified: list[Observation] = []
    seen_ids: set[str] = set()
    for item in parsed_records:
        ident = item.id
        if ident in seen_ids:
            raise ValueError(f"duplicate observation id: {ident!r}")
        seen_ids.add(ident)
        trust = trust_map.get(ident)
        if trust is None:
            raise ValueError(f"missing verifier trust for id: {ident!r}")
        if (ident, trust.mac) in revoked_pairs:
            # Permanent revocation: a certificate whose root MAC is the
            # target of a valid revocation can never support a record.
            raise ValueError(f"verifier trust has been revoked: {ident!r}")
        if not hmac.compare_digest(
            _bound_attested_mac(trust.key, _bound_attested_payload(item)), item.mac
        ):
            raise ValueError(
                f"bound attested observation mac does not match: {ident!r}"
            )
        # Only after both MACs verify do the trust bindings count: the
        # certified id/x/y must equal the record's, or it is a contract
        # breach.
        if trust.x != item.x or trust.y != item.y:
            raise ValueError(
                f"verifier trust does not match the observation: {ident!r}"
            )
        # The signed record must match the query coordinate by coordinate
        # and carry exactly the queried use context, as in
        # locate_bound_attested.
        if item.point[0] != px or item.point[1] != py or item.context != context:
            raise ValueError(
                "bound attested observation is not bound to the queried"
                f" point and context: {ident!r}"
            )
        verified.append(
            Observation(id=ident, x=item.x, y=item.y, decision=item.decision)
        )

    return locate(verified, point, quorum=3, tolerance=0.0)


_CERT_EVIDENCE_FIELDS = ("version", "body", "mac")
_CERT_EVIDENCE_BODY_FIELDS = (
    "point",
    "context",
    "records",
    "trusts",
    "consensus",
)
_CONSENSUS_FIELDS = ("total", "support", "rejected", "accepted")


def _cert_evidence_mac(root: bytes, body: bytes) -> bytes:
    """HMAC-SHA256 over ``b"NPCCE1"`` plus the body bytes, directly concatenated.

    The body bytes are exactly the compact UTF-8 JSON array that sits in the
    ``body`` field of the outer document; the prefix carries no separator or
    length prefix.
    """
    return hmac.new(
        root, _CERT_EVIDENCE_PREFIX + body, hashlib.sha256
    ).digest()


def _require_body(value: object) -> bytes:
    """Validate the ``body`` field: ``bytes`` only, never coerced."""
    if not isinstance(value, bytes):
        raise ValueError("certified consensus evidence body must be bytes")
    return value


def _require_evidence_mac(value: object) -> bytes:
    """Validate the ``mac`` field: ``bytes`` of exactly 32 bytes."""
    if not isinstance(value, bytes):
        raise ValueError("certified consensus evidence mac must be bytes")
    if len(value) != 32:
        raise ValueError(
            "certified consensus evidence mac must be exactly 32 bytes"
        )
    return value


@dataclass(frozen=True)
class CertifiedConsensusEvidence:
    """A root-MAC'd snapshot of one :func:`locate_cert` run and its inputs.

    ``version`` is always ``1``; ``body`` is ``bytes`` holding the compact
    UTF-8 JSON array ``[point, context, records, trusts, consensus]``;
    ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(root, b"NPCCE1" + body)``, the prefix and the body
    concatenated directly with no separator or length prefix. ``body`` and
    ``mac`` that are not ``bytes`` (or a ``mac`` of the wrong length) raise
    :class:`ValueError` at construction time. Instances are frozen,
    constructed positionally in field order and compare equal by their
    fields. No root material is stored.

    Inside the body: ``point`` is a bare two-element JSON array of finite
    non-bool numbers; ``context`` a non-empty string; ``records`` and
    ``trusts`` are arrays of canonical lowercase hex strings, one per
    participating :class:`BoundAttestedObservation` and
    :class:`VerifierTrust`, corresponding uniquely by id (the records are
    sorted by id, and each trust is placed at the index of the record with
    the same id); ``consensus`` is an array in :class:`Consensus` field
    order ``[total, support, rejected, accepted]`` with ``rejected`` a
    lexicographically sorted array of ids. The body bytes themselves are
    opaque to the constructor — :func:`locate_cert_evidence` produces
    conforming ones and :meth:`from_bytes` enforces the whole contract.
    """

    version: int
    body: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("certified consensus evidence version must be 1")
        _require_body(self.body)
        _require_evidence_mac(self.mac)

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: outer keys ``version, body, mac`` in
        that order, ``body`` and ``mac`` as lowercase hex, no whitespace.

        The opaque ``body`` must itself be canonical compact JSON: decoding
        it and re-encoding with the canonical encoder must reproduce the
        stored bytes exactly. A body that is not JSON or whose canonical
        re-encoding differs (whitespace, pretty-printing, framing or a
        non-canonical spelling) raises :class:`ValueError`; the instance is
        frozen, so the stored bytes are never replaced by the re-encoding.
        """
        try:
            decoded_body = json.loads(self.body)
        except ValueError as error:
            raise ValueError(
                "certified consensus evidence body must be compact JSON"
            ) from error
        try:
            canonical_body = _encode_payload(decoded_body)
        except ValueError as error:
            raise ValueError(
                "certified consensus evidence body encoding is not canonical"
            ) from error
        if canonical_body != self.body:
            raise ValueError(
                "certified consensus evidence body encoding is not canonical"
            )
        return _encode_payload(
            {
                "version": self.version,
                "body": self.body.hex(),
                "mac": self.mac.hex(),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "CertifiedConsensusEvidence":
        """Decode :meth:`to_bytes` output, enforcing the full field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: an outer object with exactly the keys
        ``version, body, mac`` once each in that order, ``version == 1``,
        ``body`` and ``mac`` lowercase hex strings (``mac`` decoding to
        exactly 32 bytes), a body decoding to exactly the array
        ``[point, context, records, trusts, consensus]`` with ``point`` a
        two-element finite-non-bool-number array, ``context`` a non-empty
        string, ``records``/``trusts`` arrays of canonical lowercase hex
        strings equal in length and unique one-to-one by the ids parsed out
        of those encodings (records id-sorted, each trust aligned with the
        record of the same id), and a ``consensus`` array in
        ``[total, support, rejected, accepted]`` order with non-bool
        integers, a lexicographically sorted array of non-empty unique id
        strings for ``rejected``, and a bool ``accepted``. The body itself
        must be canonical compact JSON, so its own re-encoding must match
        byte for byte. After parsing and validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the
        input byte for byte, so formatted JSON, whitespace and any
        non-canonical spelling are rejected as well. Neither the outer MAC
        nor anything in the body is verified here — use
        :func:`audit_cert_evidence` with the root key for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("certified consensus evidence data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedCertEvidenceObject)
        except ValueError as error:
            raise ValueError(
                f"certified consensus evidence is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(_CERT_EVIDENCE_FIELDS):
            raise ValueError(
                "certified consensus evidence must be a JSON object with exactly"
                " the version, body and mac fields in field order"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("certified consensus evidence version must be 1")
        body = _parse_cert_evidence_hex(obj["body"], "body")
        mac = _parse_cert_evidence_hex(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError(
                "certified consensus evidence mac must decode to exactly 32"
                " bytes"
            )
        _parse_cert_evidence_body(body)
        record = cls(version=version, body=body, mac=mac)
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError(
                "certified consensus evidence encoding is not canonical"
            )
        return record


def _parse_cert_evidence_hex(value: object, name: str) -> bytes:
    # Same lowercase, round-tripping hex rule as the other records, but both
    # shape and value failures are ValueErrors for this record.
    if not isinstance(value, str):
        raise ValueError(
            f"certified consensus evidence {name} must be a lowercase hex"
            " string"
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"certified consensus evidence {name} must be a lowercase hex"
            " string"
        ) from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(
            f"certified consensus evidence {name} must be a lowercase hex"
            " string"
        )
    return raw


class _OrderedCertEvidenceObject(json.JSONDecoder):
    """JSON decoder rejecting duplicate/out-of-order keys at both layers.

    The outer object must carry exactly ``version, body, mac``; the body
    array carries objects only indirectly (the hex strings inside it decode
    to records/trusts whose own key order their ``from_bytes`` checks), so
    the only object key set to enforce at this layer is the outer one.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys == list(_CERT_EVIDENCE_FIELDS):
            return dict(pairs)
        raise ValueError(
            "certified consensus evidence JSON keys must be exactly version,"
            " body and mac in field order"
        )


def _parse_cert_evidence_body(body: bytes) -> list:
    """Parse and validate the body array, returning the decoded list.

    The body is the inner compact-JSON layer: it must itself be the
    canonical encoding of the decoded structure (a re-encoding must match
    byte for byte), and every embedded record/trust hex string must decode
    through that record's own byte contract.
    """
    try:
        decoded = json.loads(body)
    except ValueError as error:
        raise ValueError(
            "certified consensus evidence body must be compact JSON"
        ) from error
    if not isinstance(decoded, list) or len(decoded) != len(
        _CERT_EVIDENCE_BODY_FIELDS
    ):
        raise ValueError(
            "certified consensus evidence body must be an array of exactly"
            " point, context, records, trusts and consensus"
        )
    raw_point, raw_context, raw_records, raw_trusts, raw_consensus = decoded
    if (
        not isinstance(raw_point, list)
        or len(raw_point) != 2
        or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in raw_point
        )
    ):
        raise ValueError(
            "certified consensus evidence point must be an array of exactly"
            " two finite non-bool numbers"
        )
    if not isinstance(raw_context, str) or not raw_context:
        raise ValueError(
            "certified consensus evidence context must be a non-empty string"
        )
    record_blobs = _require_cert_evidence_hex_array(raw_records, "records")
    trust_blobs = _require_cert_evidence_hex_array(raw_trusts, "trusts")
    parsed_records = _parse_evidence_hex_items(
        record_blobs, BoundAttestedObservation, "records"
    )
    parsed_trusts = _parse_evidence_hex_items(
        trust_blobs, VerifierTrust, "trusts"
    )
    record_ids = [item.id for item in parsed_records]
    trust_ids = [item.id for item in parsed_trusts]
    if len(set(record_ids)) != len(record_ids):
        raise ValueError(
            "certified consensus evidence records must have unique ids"
        )
    if len(set(trust_ids)) != len(trust_ids):
        raise ValueError(
            "certified consensus evidence trusts must have unique ids"
        )
    if sorted(record_ids) != record_ids:
        # The canonical producer orders the records by id and aligns the
        # trusts at the same index order.
        raise ValueError(
            "certified consensus evidence records must be sorted by id"
        )
    if trust_ids != record_ids:
        # The two arrays correspond one-to-one by id at every index: an
        # unknown, missing or reordered trust is a contract breach rather
        # than a silent ignore.
        raise ValueError(
            "certified consensus evidence records and trusts must correspond"
            " one-to-one by id in the same order"
        )
    _parse_cert_evidence_consensus(raw_consensus)
    if _encode_payload(decoded) != body:
        # The inner layer is canonical compact JSON too: no whitespace,
        # pretty-printing, framing or non-canonical number/string spellings.
        raise ValueError(
            "certified consensus evidence body encoding is not canonical"
        )
    return decoded


def _require_cert_evidence_hex_array(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(
            f"certified consensus evidence {name} must be an array of"
            " lowercase hex strings"
        )
    return [_parse_cert_evidence_hex(entry, name) for entry in value]


def _parse_evidence_hex_items(raw_items: list, kind: type, name: str) -> list:
    """Decode each hex body item through the record's own byte contract."""
    parsed = []
    for raw in raw_items:
        try:
            parsed.append(kind.from_bytes(raw))
        except ValueError as error:
            raise ValueError(
                f"certified consensus evidence {name} must contain only"
                f" canonical {kind.__name__} encodings"
            ) from error
    return parsed


def _parse_cert_evidence_consensus(value: object) -> None:
    if not isinstance(value, list) or len(value) != len(_CONSENSUS_FIELDS):
        raise ValueError(
            "certified consensus evidence consensus must be an array of"
            " exactly total, support, rejected and accepted"
        )
    raw_total, raw_support, raw_rejected, raw_accepted = value
    for field_name, number in (("total", raw_total), ("support", raw_support)):
        if type(number) is not int:
            raise ValueError(
                f"certified consensus evidence consensus {field_name} must be"
                " a non-bool integer"
            )
    if not isinstance(raw_rejected, list) or any(
        not isinstance(ident, str) or not ident for ident in raw_rejected
    ):
        raise ValueError(
            "certified consensus evidence consensus rejected must be an array"
            " of non-empty strings"
        )
    if list(raw_rejected) != sorted(raw_rejected):
        raise ValueError(
            "certified consensus evidence consensus rejected must be sorted"
            " lexicographically"
        )
    if len(set(raw_rejected)) != len(raw_rejected):
        raise ValueError(
            "certified consensus evidence consensus rejected must contain no"
            " duplicates"
        )
    if type(raw_accepted) is not bool:
        raise ValueError(
            "certified consensus evidence consensus accepted must be a bool"
        )


def _build_cert_evidence_body(
    point: tuple[float, float],
    context: str,
    records: "list[BoundAttestedObservation]",
    trusts: "dict[str, VerifierTrust]",
    consensus: "Consensus",
) -> bytes:
    """Assemble the canonical body bytes for one locate_cert run.

    Records are sorted by id and the trusts are placed in the same id order,
    so the two arrays correspond one-to-one at each index; both are encoded
    through their own canonical byte encodings and carried as lowercase hex
    strings.
    """
    ordered_records = sorted(records, key=lambda item: item.id)
    body = [
        [point[0], point[1]],
        context,
        [item.to_bytes().hex() for item in ordered_records],
        [trusts[item.id].to_bytes().hex() for item in ordered_records],
        [
            consensus.total,
            consensus.support,
            list(consensus.rejected),
            consensus.accepted,
        ],
    ]
    return _encode_payload(body)


def locate_cert_evidence(
    records: object,
    point: object,
    context: object,
    trusts: object,
    root: object,
) -> CertifiedConsensusEvidence:
    """Run :func:`locate_cert` and package its result with its inputs.

    The arguments are exactly those of :func:`locate_cert` without the
    revocation options (a revocable run cannot be frozen into a long-lived
    evidence snapshot); every :func:`locate_cert` contract rule applies
    unchanged and every violation raises :class:`ValueError` (or
    :class:`TypeError` for a non-bytes root). On success the verified
    :class:`Consensus` is returned wrapped in a
    :class:`CertifiedConsensusEvidence` whose body carries the queried
    point and context, the participating records and trusts (records sorted
    by id, trusts aligned one-to-one by id, both as canonical lowercase hex
    strings), and the consensus as a ``[total, support, rejected,
    accepted]`` array with ``rejected`` lexicographically sorted; the MAC
    is ``HMAC-SHA256(root, b"NPCCE1" + body)``. The function is pure.
    """
    root = _require_root(root)

    # Materialise the iterables under the same mixing rules as locate_cert
    # before running it, so a one-shot iterable can be re-used to build the
    # body and so the body carries exactly the participating records.
    try:
        raw_records = list(records)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "records must be an iterable of BoundAttestedObservation or bytes"
        ) from error
    parsed_records: list[BoundAttestedObservation] = []
    for item in raw_records:
        if isinstance(item, bytes):
            item = BoundAttestedObservation.from_bytes(item)
        if not isinstance(item, BoundAttestedObservation):
            raise ValueError(
                "records must contain only BoundAttestedObservation"
                " instances or bytes"
            )
        parsed_records.append(item)

    try:
        raw_trusts = list(trusts)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "trusts must be an iterable of VerifierTrust or bytes"
        ) from error
    parsed_trusts: list[VerifierTrust] = []
    for entry in raw_trusts:
        if isinstance(entry, bytes):
            entry = VerifierTrust.from_bytes(entry)
        if not isinstance(entry, VerifierTrust):
            raise ValueError(
                "trusts must contain only VerifierTrust instances or bytes"
            )
        parsed_trusts.append(entry)

    consensus = locate_cert(parsed_records, point, context, parsed_trusts, root)

    trust_map = {entry.id: entry for entry in parsed_trusts}
    body = _build_cert_evidence_body(
        point,  # type: ignore[arg-type]
        context,  # type: ignore[arg-type]
        parsed_records,
        trust_map,
        consensus,
    )
    return CertifiedConsensusEvidence(
        version=1,
        body=body,
        mac=_cert_evidence_mac(root, body),
    )


def audit_cert_evidence(
    x: "CertifiedConsensusEvidence | bytes",
    root: object,
) -> "Consensus":
    """Authenticate a :class:`CertifiedConsensusEvidence` and rerun its proof.

    Accepts the evidence itself or its canonical
    :meth:`CertifiedConsensusEvidence.to_bytes` encoding; anything else, or
    any encoding that does not satisfy the record contract, raises
    :class:`ValueError`. ``root`` must be non-empty ``bytes`` (a non-bytes
    value raises :class:`TypeError`, an empty value :class:`ValueError`).
    The outer MAC is recomputed as
    ``HMAC-SHA256(root, b"NPCCE1" + body)`` and compared in constant time;
    a mismatch raises :class:`ValueError`. The body is then parsed and
    :func:`locate_cert` is rerun over exactly the records, trusts, point
    and context it carries (every record and trust MAC rechecked under the
    certificates and root); the recomputed :class:`Consensus` must equal
    the one carried in the body field by field — including the
    lexicographically sorted ``rejected`` tuple — or :class:`ValueError` is
    raised. On success the rerun :class:`Consensus` is returned.
    """
    root = _require_root(root)
    if isinstance(x, bytes):
        evidence = CertifiedConsensusEvidence.from_bytes(x)
    elif isinstance(x, CertifiedConsensusEvidence):
        evidence = x
    else:
        raise ValueError(
            "certified consensus evidence must be a"
            " CertifiedConsensusEvidence instance or bytes"
        )
    if not hmac.compare_digest(
        _cert_evidence_mac(root, evidence.body), evidence.mac
    ):
        raise ValueError("certified consensus evidence mac does not match")
    parsed = _parse_cert_evidence_body(evidence.body)
    raw_point, raw_context, raw_records, raw_trusts, raw_consensus = parsed
    record_blobs = [
        _parse_cert_evidence_hex(entry, "records") for entry in raw_records
    ]
    trust_blobs = [
        _parse_cert_evidence_hex(entry, "trusts") for entry in raw_trusts
    ]
    point = (raw_point[0], raw_point[1])
    consensus = locate_cert(
        record_blobs, point, raw_context, trust_blobs, root
    )
    carried = Consensus(
        total=raw_consensus[0],
        support=raw_consensus[1],
        rejected=tuple(raw_consensus[2]),
        accepted=raw_consensus[3],
    )
    if carried != consensus:
        raise ValueError(
            "certified consensus evidence consensus does not match the"
            " recomputed result"
        )
    return consensus


def _trust_revocation_payload(revocation: "TrustRevocation") -> dict:
    """The JSON-ready trust-revocation fields except ``mac``, in field order."""
    return {
        "version": revocation.version,
        "id": revocation.id,
        "target": revocation.target.hex(),
    }


def _trust_revocation_mac(root: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPVR1"`` plus the canonical encoding without ``mac``.

    The prefix and the encoding are concatenated directly, with no separator
    or length prefix.
    """
    return hmac.new(
        root, _TRUST_REVOCATION_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _parse_trust_revocation_hex(value: object, name: str) -> bytes:
    # Same lowercase-hex rule as the other records, but a non-string value is
    # a shape error (TypeError), not a value error.
    if not isinstance(value, str):
        raise TypeError(
            f"trust revocation {name} must be a lowercase hex string"
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"trust revocation {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(f"trust revocation {name} must be a lowercase hex string")
    return raw


@dataclass(frozen=True)
class TrustRevocation:
    """A root-MAC'd permanent revocation of one verifier-trust certificate.

    ``version`` is always ``1``; ``id`` a non-empty string equal to the
    revoked :class:`VerifierTrust` record's id; ``target`` exactly 32 bytes
    and equal to that certificate's ``mac`` (the value the root signed), so
    the revocation can only ever revoke that one certificate; ``mac``
    exactly 32 bytes — ``HMAC-SHA256(root, b"NPVR1" + encoding)`` over the
    canonical encoding of every field except ``mac`` itself, the prefix and
    the encoding concatenated directly with no length prefix. A field of the
    wrong type raises :class:`TypeError` at construction time; a value
    contract violation raises :class:`ValueError`. Instances are frozen,
    constructed positionally in field order and compare equal by their
    fields. No root material is stored.
    """

    version: int
    id: str
    target: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int:
            raise TypeError("trust revocation version must be an integer")
        if self.version != 1:
            raise ValueError("trust revocation version must be 1")
        if not isinstance(self.id, str):
            raise TypeError("trust revocation id must be a string")
        if not self.id:
            raise ValueError("trust revocation id must be a non-empty string")
        for name in ("target", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes):
                raise TypeError(f"trust revocation {name} must be bytes")
            if len(value) != 32:
                raise ValueError(
                    f"trust revocation {name} must be exactly 32 bytes"
                )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``target`` and
        ``mac`` as lowercase hex, no whitespace, no length prefix, no
        NaN/Infinity."""
        payload = _trust_revocation_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrustRevocation":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes`` and for
        fields of the wrong type; raises :class:`ValueError` for anything
        that does not satisfy the contract: exactly the revocation fields
        appearing once each in field order (missing, extra, duplicated or
        out-of-order keys are rejected), ``version == 1``, a non-empty
        string ``id``, and ``target``/``mac`` lowercase hex strings decoding
        to exactly 32 bytes each. After parsing and field validation the
        record is re-encoded with :meth:`to_bytes` and the result must equal
        the input byte for byte, so formatted JSON, whitespace and any
        non-canonical spelling are rejected as well. The MAC is not verified
        here — use :func:`locate_cert` with the root key (or
        :func:`revoke_trust` to issue one) for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("trust revocation data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedAttestedObject)
        except ValueError as error:
            raise ValueError(
                f"trust revocation is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(
            _TRUST_REVOCATION_FIELDS
        ):
            raise ValueError(
                "trust revocation must be a JSON object with exactly the"
                " trust revocation fields"
            )
        record = cls(
            version=obj["version"],
            id=obj["id"],
            target=_parse_trust_revocation_hex(obj["target"], "target"),
            mac=_parse_trust_revocation_hex(obj["mac"], "mac"),
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("trust revocation encoding is not canonical")
        return record


def revoke_trust(trust: object, root: object) -> TrustRevocation:
    """Permanently revoke one :class:`VerifierTrust` certificate.

    ``trust`` must be a :class:`VerifierTrust` instance (bytes are not
    accepted here, unlike the audit-style entry points) — any other type
    raises :class:`TypeError`. ``root`` must be non-empty ``bytes`` (a
    non-bytes value raises :class:`TypeError`, an empty value
    :class:`ValueError`). The returned :class:`TrustRevocation` has
    ``version`` set to ``1``, ``id`` copied from the trust, and
    ``target == trust.mac``; its MAC is
    ``HMAC-SHA256(root, b"NPVR1" + encoding)`` over the canonical encoding
    of every field except ``mac`` itself, the two segments concatenated
    directly with no length prefix. Signing is pure data: it reads and
    mutates no verifier state.
    """
    if not isinstance(trust, VerifierTrust):
        raise TypeError("trust must be a VerifierTrust")
    root = _require_root(root)
    record = TrustRevocation(
        version=1,
        id=trust.id,
        target=trust.mac,
        mac=b"\x00" * 32,
    )
    return replace(
        record,
        mac=_trust_revocation_mac(root, _trust_revocation_payload(record)),
    )


def _trust_revocation_list_payload(
    crl: "TrustRevocationList",
) -> dict:
    """The JSON-ready revocation-list fields except ``mac``, in field order.

    ``entries`` is encoded as a JSON array of objects, each carrying exactly
    the :class:`TrustRevocation` key set in its own field order.
    """
    return {
        "version": crl.version,
        "sequence": crl.sequence,
        "issued_at": crl.issued_at,
        "entries": [
            {**_trust_revocation_payload(entry), "mac": entry.mac.hex()}
            for entry in crl.entries
        ],
    }


def _trust_revocation_list_mac(root: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPVRL1"`` plus the canonical encoding without ``mac``.

    The prefix and the encoding are concatenated directly, with no separator
    or length prefix.
    """
    return hmac.new(
        root,
        _TRUST_REVOCATION_LIST_PREFIX + _encode_payload(payload),
        hashlib.sha256,
    ).digest()


@dataclass(frozen=True)
class TrustRevocationList:
    """A root-MAC'd snapshot list of :class:`TrustRevocation` entries.

    ``version`` is always ``1``; ``sequence`` a non-bool unsigned 64-bit
    integer; ``issued_at`` a finite non-bool non-negative number, stored as
    ``float``; ``entries`` a tuple of :class:`TrustRevocation` instances,
    sorted ascending by ``(id, target)`` with no duplicate pair; ``mac``
    exactly 32 bytes —
    ``HMAC-SHA256(root, b"NPVRL1" + encoding)`` over the canonical encoding
    of every field except ``mac`` itself (entries as an object array), the
    prefix and the encoding concatenated directly with no length prefix. Any
    contract violation raises :class:`ValueError` at construction time.
    Instances are frozen, constructed positionally in field order and
    compare equal by their fields. No root material is stored.
    """

    version: int
    sequence: int
    issued_at: float
    entries: "tuple[TrustRevocation, ...]"
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("trust revocation list version must be 1")
        if isinstance(self.sequence, bool) or type(self.sequence) is not int:
            raise ValueError("trust revocation list sequence must be an integer")
        if not 0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "trust revocation list sequence must fit in an unsigned"
                " 64-bit integer"
            )
        value = self.issued_at
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                "trust revocation list issued_at must be a finite non-negative"
                " number"
            )
        if not math.isfinite(value) or value < 0:
            raise ValueError(
                "trust revocation list issued_at must be a finite non-negative"
                " number"
            )
        # The canonical encoding always spells issued_at as a float.
        object.__setattr__(self, "issued_at", float(value))
        if not isinstance(self.entries, tuple):
            raise ValueError(
                "trust revocation list entries must be a tuple of"
                " TrustRevocation"
            )
        previous = None
        for entry in self.entries:
            if not isinstance(entry, TrustRevocation):
                raise ValueError(
                    "trust revocation list entries must contain only"
                    " TrustRevocation instances"
                )
            pair = (entry.id, entry.target)
            if previous is not None and pair <= previous:
                raise ValueError(
                    "trust revocation list entries must be sorted by"
                    " (id, target) with no duplicates"
                )
            previous = pair
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError("trust revocation list mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``entries`` as
        an array of objects with the trust-revocation keys in field order,
        ``issued_at`` as a float, ``mac`` as lowercase hex, no whitespace, no
        length prefix, no NaN/Infinity."""
        payload = _trust_revocation_list_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "TrustRevocationList":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Raises :class:`TypeError` for anything that is not ``bytes``; raises
        :class:`ValueError` for anything that does not satisfy the contract:
        exactly the list fields appearing once each in field order (missing,
        extra, duplicated or out-of-order keys are rejected, likewise inside
        every nested entry object), ``version == 1``, a non-bool u64
        ``sequence``, a finite non-bool non-negative ``issued_at`` stored as
        ``float``, an ``entries`` array of objects satisfying the
        :class:`TrustRevocation` contract, sorted by ``(id, target)`` with no
        duplicate pair, and ``mac`` a lowercase hex string decoding to
        exactly 32 bytes. After parsing and field validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the input
        byte for byte, so formatted JSON, whitespace and any non-canonical
        number or string spelling are rejected as well. Neither the list MAC
        nor any entry MAC is verified here — use :func:`audit_crl` with the
        root key for that.
        """
        if not isinstance(data, bytes):
            raise TypeError("trust revocation list data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedAttestedObject)
        except ValueError as error:
            raise ValueError(
                f"trust revocation list is not valid JSON: {error}"
            ) from error
        if not isinstance(obj, dict) or list(obj) != list(
            _TRUST_REVOCATION_LIST_FIELDS
        ):
            raise ValueError(
                "trust revocation list must be a JSON object with exactly the"
                " trust revocation list fields"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("trust revocation list version must be 1")
        sequence = _parse_int_field(obj["sequence"], "sequence")
        if not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "trust revocation list sequence must fit in an unsigned"
                " 64-bit integer"
            )
        issued_at = obj["issued_at"]
        if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)):
            raise ValueError(
                "trust revocation list issued_at must be a finite non-negative"
                " number"
            )
        if not math.isfinite(issued_at) or issued_at < 0:
            raise ValueError(
                "trust revocation list issued_at must be a finite non-negative"
                " number"
            )
        raw_entries = obj["entries"]
        if not isinstance(raw_entries, list):
            raise ValueError(
                "trust revocation list entries must be an array of objects"
            )
        entries: list[TrustRevocation] = []
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict) or list(raw_entry) != list(
                _TRUST_REVOCATION_FIELDS
            ):
                raise ValueError(
                    "trust revocation list entries must be JSON objects with"
                    " exactly the trust revocation fields"
                )
            try:
                entry = TrustRevocation(
                    version=raw_entry["version"],
                    id=raw_entry["id"],
                    target=_parse_trust_revocation_hex(
                        raw_entry["target"], "target"
                    ),
                    mac=_parse_trust_revocation_hex(raw_entry["mac"], "mac"),
                )
            except TypeError as error:
                # A nested entry of the right key set but the wrong field
                # shape makes the whole list encoding non-canonical; the
                # only TypeError this method raises is for non-bytes data.
                raise ValueError(
                    "trust revocation list entry does not satisfy the"
                    " trust revocation contract"
                ) from error
            entries.append(entry)
        mac = _parse_hex_field(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError(
                "trust revocation list mac must decode to exactly 32 bytes"
            )
        record = cls(
            version=version,
            sequence=sequence,
            issued_at=issued_at,
            entries=tuple(entries),
            mac=mac,
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings (including an integer issued_at, which
            # the float spelling would not reproduce).
            raise ValueError("trust revocation list encoding is not canonical")
        return record


def make_crl(
    items: object,
    seq: object,
    time: object,
    root: object,
) -> TrustRevocationList:
    """Sign a snapshot list of trust revocations under the root key.

    ``items`` is an iterable of :class:`TrustRevocation` instances (bytes
    encodings are not accepted here); it may be empty. The entries are
    copied into a tuple sorted ascending by ``(id, target)``, and a
    duplicate pair raises :class:`ValueError`. ``seq`` must be a non-bool
    unsigned 64-bit integer and ``time`` a finite non-bool non-negative
    number (stored as ``float``). ``root`` must be non-empty ``bytes`` — a
    non-bytes value raises :class:`TypeError`, an empty value
    :class:`ValueError` — and is the same root the entry certificates and
    their single revocations were signed with; the entries' own MACs are
    carried through unchanged. The returned :class:`TrustRevocationList`
    has ``version`` set to ``1`` and
    ``mac = HMAC-SHA256(root, b"NPVRL1" + encoding)`` over the canonical
    encoding of every field except ``mac`` itself, the prefix and the
    encoding concatenated directly with no length prefix. Signing is pure
    data: it reads and mutates no verifier state.
    """
    root = _require_root(root)
    try:
        raw_items = list(items)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "items must be an iterable of TrustRevocation"
        ) from error
    entries: list[TrustRevocation] = []
    for entry in raw_items:
        if not isinstance(entry, TrustRevocation):
            raise ValueError(
                "items must contain only TrustRevocation instances"
            )
        entries.append(entry)
    entries.sort(key=lambda entry: (entry.id, entry.target))
    record = TrustRevocationList(
        version=1,
        sequence=seq,  # type: ignore[arg-type]
        issued_at=time,  # type: ignore[arg-type]
        entries=tuple(entries),
        mac=b"\x00" * 32,
    )
    return replace(
        record,
        mac=_trust_revocation_list_mac(root, _trust_revocation_list_payload(record)),
    )


def audit_crl(
    x: "TrustRevocationList | bytes",
    root: object,
    now: object,
    min: object = 0,
) -> None:
    """Authenticate a :class:`TrustRevocationList` snapshot and check freshness.

    Accepts the list itself or its canonical
    :meth:`TrustRevocationList.to_bytes` encoding; anything else raises
    :class:`ValueError`. ``root`` must be non-empty ``bytes`` (a non-bytes
    value raises :class:`TypeError`, an empty value :class:`ValueError`);
    ``now`` must be a finite non-bool number and ``min`` a non-bool
    integer. Two MAC layers are recomputed with ``root`` and each compared
    in constant time: the list MAC is
    ``HMAC-SHA256(root, b"NPVRL1" + encoding)`` over the canonical encoding
    of every field except the list ``mac``, and every entry's root MAC is
    ``HMAC-SHA256(root, b"NPVR1" + encoding)`` exactly as
    :func:`locate_cert` verifies it; a mismatch on either layer raises
    :class:`ValueError`. The snapshot must also be current:
    ``issued_at > now`` (a future-dated list) or ``sequence < min``
    raises :class:`ValueError`. The check is pure: it returns ``None`` on
    success and touches no state.
    """
    root = _require_root(root)
    if isinstance(x, bytes):
        crl = TrustRevocationList.from_bytes(x)
    elif isinstance(x, TrustRevocationList):
        crl = x
    else:
        raise ValueError(
            "crl must be a TrustRevocationList instance or bytes"
        )
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise ValueError("now must be a finite number")
    current = float(now)
    if not math.isfinite(current):
        raise ValueError("now must be a finite number")
    if isinstance(min, bool) or type(min) is not int:
        raise ValueError("min must be an integer")
    if not hmac.compare_digest(
        _trust_revocation_list_mac(root, _trust_revocation_list_payload(crl)),
        crl.mac,
    ):
        raise ValueError("trust revocation list mac does not match")
    for entry in crl.entries:
        if not hmac.compare_digest(
            _trust_revocation_mac(root, _trust_revocation_payload(entry)),
            entry.mac,
        ):
            raise ValueError(
                f"trust revocation mac does not match: {entry.id!r}"
            )
    if crl.issued_at > current:
        raise ValueError("trust revocation list is dated in the future")
    if crl.sequence < min:
        raise ValueError("trust revocation list sequence is below the minimum")


_CRL_PROOF_FIELDS = ("version", "body", "mac")
_CRL_PROOF_BODY_FIELDS = (
    "point",
    "context",
    "records",
    "trusts",
    "crl",
    "now",
    "min",
    "consensus",
)


def _crl_proof_mac(root: bytes, body: bytes) -> bytes:
    """HMAC-SHA256 over ``b"NPCCE2"`` plus the body bytes, directly concatenated.

    The body bytes are exactly the compact UTF-8 JSON array that sits in the
    ``body`` field of the outer document; the prefix carries no separator or
    length prefix.
    """
    return hmac.new(root, _CRL_PROOF_PREFIX + body, hashlib.sha256).digest()


@dataclass(frozen=True)
class CrlProof:
    """A root-MAC'd snapshot of one :func:`locate_cert` run against a CRL.

    ``version`` is always ``1``; ``body`` is ``bytes`` holding the compact
    UTF-8 JSON array
    ``[point, context, records, trusts, crl, now, min, consensus]``;
    ``mac`` is exactly 32 bytes —
    ``HMAC-SHA256(root, b"NPCCE2" + body)``, the prefix and the body
    concatenated directly with no separator or length prefix. ``body`` and
    ``mac`` that are not ``bytes`` (or a ``mac`` of the wrong length) raise
    :class:`ValueError` at construction time. Instances are frozen,
    constructed positionally in field order and compare equal by their
    fields. No root material is stored.

    Inside the body: ``point`` is a bare two-element JSON array of finite
    non-bool numbers; ``context`` a non-empty string; ``records`` and
    ``trusts`` are arrays of canonical lowercase hex strings, one per
    participating :class:`BoundAttestedObservation` and
    :class:`VerifierTrust` (records sorted by id, each trust aligned with
    the record of the same id); ``crl`` the canonical
    :meth:`TrustRevocationList.to_bytes` encoding as a lowercase hex
    string; ``now`` a finite non-bool number; ``min`` a non-bool integer;
    ``consensus`` an array in :class:`Consensus` field order
    ``[total, support, rejected, accepted]`` with ``rejected`` a
    lexicographically sorted array of ids. The body bytes themselves are
    opaque to the constructor — :func:`prove_crl` produces conforming ones
    and :meth:`from_bytes` enforces the whole contract.
    """

    version: int
    body: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("crl proof version must be 1")
        if not isinstance(self.body, bytes):
            raise ValueError("crl proof body must be bytes")
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError("crl proof mac must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: outer keys ``version, body, mac`` in
        that order, ``body`` and ``mac`` as lowercase hex, no whitespace.

        The opaque ``body`` must itself be canonical compact JSON: decoding
        it and re-encoding with the canonical encoder must reproduce the
        stored bytes exactly. A body that is not JSON or whose canonical
        re-encoding differs raises :class:`ValueError`; the instance is
        frozen, so the stored bytes are never replaced by the re-encoding.
        """
        try:
            decoded_body = json.loads(self.body)
        except ValueError as error:
            raise ValueError("crl proof body must be compact JSON") from error
        try:
            canonical_body = _encode_payload(decoded_body)
        except ValueError as error:
            raise ValueError("crl proof body encoding is not canonical") from error
        if canonical_body != self.body:
            raise ValueError("crl proof body encoding is not canonical")
        return _encode_payload(
            {
                "version": self.version,
                "body": self.body.hex(),
                "mac": self.mac.hex(),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "CrlProof":
        """Decode :meth:`to_bytes` output, enforcing the full field contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: an outer object with exactly the keys
        ``version, body, mac`` once each in that order, ``version == 1``,
        ``body`` and ``mac`` lowercase hex strings (``mac`` decoding to
        exactly 32 bytes), a body decoding to exactly the array
        ``[point, context, records, trusts, crl, now, min, consensus]``
        with ``point`` a two-element finite-non-bool-number array,
        ``context`` a non-empty string, ``records``/``trusts`` arrays of
        canonical lowercase hex strings equal in length and unique
        one-to-one by the ids parsed out of those encodings (records
        id-sorted, each trust aligned with the record of the same id),
        ``crl`` a lowercase hex string decoding to a canonical
        :class:`TrustRevocationList` encoding, ``now`` a finite non-bool
        number, ``min`` a non-bool integer, and a ``consensus`` array in
        ``[total, support, rejected, accepted]`` order with non-bool
        integers, a lexicographically sorted array of non-empty unique id
        strings for ``rejected``, and a bool ``accepted``. The body itself
        must be canonical compact JSON, so its own re-encoding must match
        byte for byte. After parsing and validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the
        input byte for byte. Neither the outer MAC nor anything in the
        body is verified here — use :func:`audit_proof` with the root key
        for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("crl proof data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedCrlProofObject)
        except ValueError as error:
            raise ValueError(f"crl proof is not valid JSON: {error}") from error
        if not isinstance(obj, dict) or list(obj) != list(_CRL_PROOF_FIELDS):
            raise ValueError(
                "crl proof must be a JSON object with exactly the version,"
                " body and mac fields in field order"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("crl proof version must be 1")
        body = _parse_crl_proof_hex(obj["body"], "body")
        mac = _parse_crl_proof_hex(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError("crl proof mac must decode to exactly 32 bytes")
        _parse_crl_proof_body(body)
        record = cls(version=version, body=body, mac=mac)
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("crl proof encoding is not canonical")
        return record


def _parse_crl_proof_hex(value: object, name: str) -> bytes:
    # Same lowercase, round-tripping hex rule as the other records; both
    # shape and value failures are ValueErrors for this record.
    if not isinstance(value, str):
        raise ValueError(f"crl proof {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"crl proof {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(f"crl proof {name} must be a lowercase hex string")
    return raw


class _OrderedCrlProofObject(json.JSONDecoder):
    """JSON decoder rejecting duplicate/out-of-order keys at the outer layer.

    The outer object must carry exactly ``version, body, mac``; the body
    array carries objects only indirectly (the hex strings inside it decode
    to records/trusts/a CRL whose own key order their ``from_bytes``
    checks), so the only object key set to enforce at this layer is the
    outer one.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys == list(_CRL_PROOF_FIELDS):
            return dict(pairs)
        raise ValueError(
            "crl proof JSON keys must be exactly version, body and mac in"
            " field order"
        )


def _require_crl_proof_hex_array(value: object, name: str) -> list:
    if not isinstance(value, list):
        raise ValueError(
            f"crl proof {name} must be an array of lowercase hex strings"
        )
    return [_parse_crl_proof_hex(entry, name) for entry in value]


def _parse_crl_proof_hex_item(raw: bytes, kind: type, name: str) -> object:
    """Decode one hex body item through the record's own byte contract."""
    try:
        return kind.from_bytes(raw)
    except ValueError as error:
        raise ValueError(
            f"crl proof {name} must contain only canonical"
            f" {kind.__name__} encodings"
        ) from error


def _parse_crl_proof_consensus(value: object) -> None:
    if not isinstance(value, list) or len(value) != len(_CONSENSUS_FIELDS):
        raise ValueError(
            "crl proof consensus must be an array of exactly total, support,"
            " rejected and accepted"
        )
    raw_total, raw_support, raw_rejected, raw_accepted = value
    for field_name, number in (("total", raw_total), ("support", raw_support)):
        if type(number) is not int:
            raise ValueError(
                f"crl proof consensus {field_name} must be a non-bool integer"
            )
    if not isinstance(raw_rejected, list) or any(
        not isinstance(ident, str) or not ident for ident in raw_rejected
    ):
        raise ValueError(
            "crl proof consensus rejected must be an array of non-empty strings"
        )
    if list(raw_rejected) != sorted(raw_rejected):
        raise ValueError(
            "crl proof consensus rejected must be sorted lexicographically"
        )
    if len(set(raw_rejected)) != len(raw_rejected):
        raise ValueError(
            "crl proof consensus rejected must contain no duplicates"
        )
    if type(raw_accepted) is not bool:
        raise ValueError("crl proof consensus accepted must be a bool")


def _parse_crl_proof_body(body: bytes) -> list:
    """Parse and validate the body array, returning the decoded list.

    The body is the inner compact-JSON layer: it must itself be the
    canonical encoding of the decoded structure (a re-encoding must match
    byte for byte), and every embedded record/trust/CRL hex string must
    decode through that record's own byte contract.
    """
    try:
        decoded = json.loads(body)
    except ValueError as error:
        raise ValueError("crl proof body must be compact JSON") from error
    if not isinstance(decoded, list) or len(decoded) != len(_CRL_PROOF_BODY_FIELDS):
        raise ValueError(
            "crl proof body must be an array of exactly point, context,"
            " records, trusts, crl, now, min and consensus"
        )
    (
        raw_point,
        raw_context,
        raw_records,
        raw_trusts,
        raw_crl,
        raw_now,
        raw_min,
        raw_consensus,
    ) = decoded
    if (
        not isinstance(raw_point, list)
        or len(raw_point) != 2
        or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in raw_point
        )
    ):
        raise ValueError(
            "crl proof point must be an array of exactly two finite non-bool"
            " numbers"
        )
    if not isinstance(raw_context, str) or not raw_context:
        raise ValueError("crl proof context must be a non-empty string")
    record_blobs = _require_crl_proof_hex_array(raw_records, "records")
    trust_blobs = _require_crl_proof_hex_array(raw_trusts, "trusts")
    parsed_records = [
        _parse_crl_proof_hex_item(raw, BoundAttestedObservation, "records")
        for raw in record_blobs
    ]
    parsed_trusts = [
        _parse_crl_proof_hex_item(raw, VerifierTrust, "trusts")
        for raw in trust_blobs
    ]
    record_ids = [item.id for item in parsed_records]
    trust_ids = [item.id for item in parsed_trusts]
    if len(set(record_ids)) != len(record_ids):
        raise ValueError("crl proof records must have unique ids")
    if len(set(trust_ids)) != len(trust_ids):
        raise ValueError("crl proof trusts must have unique ids")
    if sorted(record_ids) != record_ids:
        # The canonical producer orders the records by id and aligns the
        # trusts at the same index order.
        raise ValueError("crl proof records must be sorted by id")
    if trust_ids != record_ids:
        # The two arrays correspond one-to-one by id at every index.
        raise ValueError(
            "crl proof records and trusts must correspond one-to-one by id"
            " in the same order"
        )
    crl_blob = _parse_crl_proof_hex(raw_crl, "crl")
    try:
        TrustRevocationList.from_bytes(crl_blob)
    except ValueError as error:
        raise ValueError(
            "crl proof crl must be a canonical TrustRevocationList encoding"
        ) from error
    if isinstance(raw_now, bool) or not isinstance(raw_now, (int, float)):
        raise ValueError("crl proof now must be a finite non-bool number")
    if not math.isfinite(raw_now):
        raise ValueError("crl proof now must be a finite non-bool number")
    if type(raw_min) is not int:
        raise ValueError("crl proof min must be a non-bool integer")
    _parse_crl_proof_consensus(raw_consensus)
    if _encode_payload(decoded) != body:
        # The inner layer is canonical compact JSON too: no whitespace,
        # pretty-printing, framing or non-canonical number/string spellings.
        raise ValueError("crl proof body encoding is not canonical")
    return decoded


def _build_crl_proof_body(
    point: tuple[float, float],
    context: str,
    records: "list[BoundAttestedObservation]",
    trusts: "dict[str, VerifierTrust]",
    crl: "TrustRevocationList",
    now: float,
    minimum: int,
    consensus: "Consensus",
) -> bytes:
    """Assemble the canonical body bytes for one snapshot locate_cert run.

    Records are sorted by id and the trusts are placed in the same id order,
    so the two arrays correspond one-to-one at each index; both, and the
    CRL snapshot, are encoded through their own canonical byte encodings
    and carried as lowercase hex strings.
    """
    ordered_records = sorted(records, key=lambda item: item.id)
    body = [
        [point[0], point[1]],
        context,
        [item.to_bytes().hex() for item in ordered_records],
        [trusts[item.id].to_bytes().hex() for item in ordered_records],
        crl.to_bytes().hex(),
        now,
        minimum,
        [
            consensus.total,
            consensus.support,
            list(consensus.rejected),
            consensus.accepted,
        ],
    ]
    return _encode_payload(body)


def prove_crl(
    records: object,
    point: object,
    context: object,
    trusts: object,
    root: object,
    crl: object,
    *,
    now: object,
    min: object = 0,
) -> CrlProof:
    """Run the snapshot path of :func:`locate_cert` and package its result.

    The positional arguments are those of :func:`locate_cert` plus ``crl``,
    a :class:`TrustRevocationList` or its canonical
    :meth:`TrustRevocationList.to_bytes` encoding; ``now`` is keyword-only
    and required and ``min`` (a non-bool integer, default ``0``)
    keyword-only, exactly as on the snapshot path of :func:`locate_cert`.
    The snapshot is audited with :func:`audit_crl` and its hits applied as
    part of the run, so a wrong root, a future-dated list, a sequence below
    ``min`` or a revoked participating certificate raises
    :class:`ValueError`; a non-bytes ``root`` raises :class:`TypeError`,
    following the same root contract as :func:`locate_cert`.

    On success the verified :class:`Consensus` is returned wrapped in a
    :class:`CrlProof` whose body is the compact JSON array
    ``[point, context, records, trusts, crl, now, min, consensus]`` with the
    participating records sorted by id, the trusts aligned one-to-one by
    id, records, trusts and CRL carried as canonical lowercase hex strings,
    and the consensus as a ``[total, support, rejected, accepted]`` array
    with ``rejected`` lexicographically sorted; the MAC is
    ``HMAC-SHA256(root, b"NPCCE2" + body)``. The function is pure.
    """
    root = _require_root(root)

    # Materialise the iterables under the same mixing rules as locate_cert
    # before running it, so a one-shot iterable can be re-used to build the
    # body and so the body carries exactly the participating records.
    try:
        raw_records = list(records)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "records must be an iterable of BoundAttestedObservation or bytes"
        ) from error
    parsed_records: list[BoundAttestedObservation] = []
    for item in raw_records:
        if isinstance(item, bytes):
            item = BoundAttestedObservation.from_bytes(item)
        if not isinstance(item, BoundAttestedObservation):
            raise ValueError(
                "records must contain only BoundAttestedObservation"
                " instances or bytes"
            )
        parsed_records.append(item)

    try:
        raw_trusts = list(trusts)  # type: ignore[arg-type]
    except TypeError as error:
        raise ValueError(
            "trusts must be an iterable of VerifierTrust or bytes"
        ) from error
    parsed_trusts: list[VerifierTrust] = []
    for entry in raw_trusts:
        if isinstance(entry, bytes):
            entry = VerifierTrust.from_bytes(entry)
        if not isinstance(entry, VerifierTrust):
            raise ValueError(
                "trusts must contain only VerifierTrust instances or bytes"
            )
        parsed_trusts.append(entry)

    if isinstance(crl, bytes):
        snapshot = TrustRevocationList.from_bytes(crl)
    elif isinstance(crl, TrustRevocationList):
        snapshot = crl
    else:
        raise ValueError(
            "crl must be a TrustRevocationList instance or bytes"
        )

    # audit_crl owns the now/min contract during the run below, but the body
    # must carry canonical values too, so enforce the same rules up front.
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise ValueError("now must be a finite number")
    current = float(now)
    if not math.isfinite(current):
        raise ValueError("now must be a finite number")
    if isinstance(min, bool) or type(min) is not int:
        raise ValueError("min must be an integer")

    consensus = locate_cert(
        parsed_records,
        point,
        context,
        parsed_trusts,
        root,
        revocations=snapshot,
        now=current,
        min=min,
    )

    trust_map = {entry.id: entry for entry in parsed_trusts}
    body = _build_crl_proof_body(
        point,  # type: ignore[arg-type]
        context,  # type: ignore[arg-type]
        parsed_records,
        trust_map,
        snapshot,
        current,
        min,
        consensus,
    )
    return CrlProof(
        version=1,
        body=body,
        mac=_crl_proof_mac(root, body),
    )


def audit_proof(x: "CrlProof | bytes", root: object) -> "Consensus":
    """Authenticate a :class:`CrlProof` and rerun its snapshot proof.

    Accepts the proof itself or its canonical :meth:`CrlProof.to_bytes`
    encoding; anything else, or any encoding that does not satisfy the
    record contract, raises :class:`ValueError`. ``root`` must be non-empty
    ``bytes`` — a non-bytes value raises :class:`TypeError`, an empty value
    :class:`ValueError`; every other failure (including any
    :class:`TypeError` raised while replaying the body) is reported as
    :class:`ValueError`.

    The outer MAC is recomputed as
    ``HMAC-SHA256(root, b"NPCCE2" + body)`` and compared in constant time;
    a mismatch raises :class:`ValueError`. The body is then parsed and the
    snapshot is replayed exactly as :func:`prove_crl` produced it:
    :func:`audit_crl` reruns over the carried CRL under the carried
    ``now``/``min`` and ``root`` (both MAC layers, freshness and sequence
    floor included), and :func:`locate_cert` is rerun over exactly the
    records, trusts, point, context and CRL snapshot the body carries
    (every record and trust MAC rechecked and the snapshot hits applied);
    the recomputed :class:`Consensus` must equal the one carried in the
    body field by field — including the lexicographically sorted
    ``rejected`` tuple — or :class:`ValueError` is raised. On success the
    rerun :class:`Consensus` is returned.
    """
    root = _require_root(root)
    try:
        return _audit_proof(x, root)
    except TypeError as error:
        # The only shape error reported as TypeError is the root type, which
        # was checked above; every replay failure is a ValueError.
        raise ValueError(f"crl proof is invalid: {error}") from error


def _audit_proof(x: object, root: bytes) -> "Consensus":
    """Inner replay for :func:`audit_proof`; root is already validated."""
    if isinstance(x, bytes):
        proof = CrlProof.from_bytes(x)
    elif isinstance(x, CrlProof):
        proof = x
    else:
        raise ValueError("crl proof must be a CrlProof instance or bytes")
    if not hmac.compare_digest(_crl_proof_mac(root, proof.body), proof.mac):
        raise ValueError("crl proof mac does not match")
    parsed = _parse_crl_proof_body(proof.body)
    (
        raw_point,
        raw_context,
        raw_records,
        raw_trusts,
        raw_crl,
        raw_now,
        raw_min,
        raw_consensus,
    ) = parsed
    record_blobs = [
        _parse_crl_proof_hex(entry, "records") for entry in raw_records
    ]
    trust_blobs = [_parse_crl_proof_hex(entry, "trusts") for entry in raw_trusts]
    crl_blob = _parse_crl_proof_hex(raw_crl, "crl")
    point = (raw_point[0], raw_point[1])
    # Replay the snapshot exactly as prove_crl ran it: audit_crl first
    # (it also runs inside locate_cert's snapshot path), then the locate.
    audit_crl(crl_blob, root, raw_now, min=raw_min)
    consensus = locate_cert(
        record_blobs,
        point,
        raw_context,
        trust_blobs,
        root,
        revocations=crl_blob,
        now=raw_now,
        min=raw_min,
    )
    carried = Consensus(
        total=raw_consensus[0],
        support=raw_consensus[1],
        rejected=tuple(raw_consensus[2]),
        accepted=raw_consensus[3],
    )
    if carried != consensus:
        raise ValueError(
            "crl proof consensus does not match the recomputed result"
        )
    return consensus


_CRL_STATE_FIELDS = ("version", "sequence", "digest", "mac")


def _crl_state_payload(state: "CrlState") -> dict:
    """The JSON-ready CRL-state fields except ``mac``, in field order."""
    return {
        "version": state.version,
        "sequence": state.sequence,
        "digest": state.digest.hex(),
    }


def _crl_state_mac(root: bytes, payload: dict) -> bytes:
    """HMAC-SHA256 over ``b"NPCK1"`` plus the canonical encoding without ``mac``.

    The prefix and the encoding are concatenated directly with no separator
    or length prefix.
    """
    return hmac.new(
        root, _CRL_STATE_PREFIX + _encode_payload(payload), hashlib.sha256
    ).digest()


def _parse_crl_state_hex(value: object, name: str) -> bytes:
    # Same lowercase, round-tripping hex rule as the other records.
    if not isinstance(value, str):
        raise ValueError(f"crl state {name} must be a lowercase hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"crl state {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(f"crl state {name} must be a lowercase hex string")
    return raw


class _OrderedCrlStateObject(json.JSONDecoder):
    """JSON decoder rejecting duplicate/out-of-order CrlState object keys."""

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys == list(_CRL_STATE_FIELDS):
            return dict(pairs)
        raise ValueError(
            "crl state JSON keys must be exactly version, sequence, digest"
            " and mac in field order"
        )


@dataclass(frozen=True)
class CrlState:
    """A root-MAC'd, rollback-resistant checkpoint of the audited CRL frontier.

    ``version`` is always ``1``; ``sequence`` a non-bool unsigned 64-bit
    integer (the audited :class:`TrustRevocationList` sequence); ``digest``
    exactly 32 bytes — ``SHA256(crl)`` over the canonical
    :meth:`TrustRevocationList.to_bytes` bytes carried inside the audited
    :class:`CrlProof`; ``mac`` exactly 32 bytes —
    ``HMAC-SHA256(root, b"NPCK1" + encoding)`` over the canonical encoding
    of every field except ``mac`` itself, the prefix and the encoding
    concatenated directly with no separator or length prefix. Any contract
    violation raises :class:`ValueError` at construction time. Instances are
    frozen, constructed positionally in field order and compare equal by
    their fields. No root material is stored.
    """

    version: int
    sequence: int
    digest: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("crl state version must be 1")
        if isinstance(self.sequence, bool) or type(self.sequence) is not int:
            raise ValueError("crl state sequence must be a non-bool integer")
        if not 0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "crl state sequence must fit in an unsigned 64-bit integer"
            )
        for name in ("digest", "mac"):
            value = getattr(self, name)
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError(f"crl state {name} must be exactly 32 bytes")

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: keys in field order, ``digest`` and
        ``mac`` as lowercase hex, no whitespace, no length prefix."""
        payload = _crl_state_payload(self)
        payload["mac"] = self.mac.hex()
        return _encode_payload(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> "CrlState":
        """Decode :meth:`to_bytes` output, enforcing the field contract.

        Only ``bytes`` input is accepted; raises :class:`ValueError` for
        anything that is not ``bytes`` or does not satisfy the contract: an
        object with exactly the keys ``version, sequence, digest, mac`` once
        each in that order (missing, extra, duplicated or out-of-order keys
        are rejected), ``version == 1``, a non-bool u64 ``sequence``, and
        ``digest``/``mac`` lowercase hex strings decoding to exactly 32
        bytes each. After parsing and field validation the record is
        re-encoded with :meth:`to_bytes` and the result must equal the input
        byte for byte, so formatted JSON, whitespace and any non-canonical
        number or string spelling are rejected as well. The MAC is not
        verified here — pass the encoding to :class:`CrlProofAuditor` (or
        recompute :func:`_crl_state_mac` with the root) for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("crl state data must be bytes")
        try:
            obj = json.loads(data, cls=_OrderedCrlStateObject)
        except ValueError as error:
            raise ValueError(f"crl state is not valid JSON: {error}") from error
        if not isinstance(obj, dict) or list(obj) != list(_CRL_STATE_FIELDS):
            raise ValueError(
                "crl state must be a JSON object with exactly the version,"
                " sequence, digest and mac fields in field order"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("crl state version must be 1")
        sequence = _parse_int_field(obj["sequence"], "sequence")
        if not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(
                "crl state sequence must fit in an unsigned 64-bit integer"
            )
        digest = _parse_crl_state_hex(obj["digest"], "digest")
        if len(digest) != 32:
            raise ValueError("crl state digest must decode to exactly 32 bytes")
        mac = _parse_crl_state_hex(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError("crl state mac must decode to exactly 32 bytes")
        record = cls(
            version=version, sequence=sequence, digest=digest, mac=mac
        )
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings.
            raise ValueError("crl state encoding is not canonical")
        return record


def _crl_proof_snapshot(proof: CrlProof) -> "tuple[int, bytes]":
    """Return ``(sequence, crl_bytes)`` from an already audited CRL proof.

    The ``crl`` body element is the canonical
    :meth:`TrustRevocationList.to_bytes` encoding as lowercase hex. Callers
    must only reach this after :func:`audit_proof` succeeded, which has
    already enforced the body and CRL contracts.
    """
    parsed = json.loads(proof.body)
    crl_blob = _parse_crl_proof_hex(parsed[4], "crl")
    snapshot = TrustRevocationList.from_bytes(crl_blob)
    return snapshot.sequence, crl_blob


class CrlProofAuditor:
    """Stateful :class:`CrlProof` auditor that refuses CRL sequence rollback.

    ``root`` must be non-empty ``bytes`` — a non-bytes value raises
    :class:`TypeError`, an empty value :class:`ValueError`; it is the same
    root the CRL snapshots, proofs and checkpoints are MAC'd with.
    ``checkpoint`` is keyword-only: ``None`` (the default) starts from the
    empty state; otherwise it must be a :class:`CrlState` or its canonical
    :meth:`CrlState.to_bytes` encoding, and its MAC is recomputed with
    ``root`` and compared in constant time (a malformed encoding or MAC
    mismatch raises :class:`ValueError`). Across a restart the caller must
    pass the value previously exported at :attr:`checkpoint`; nothing is
    persisted by the auditor itself.

    Each :meth:`audit` first runs the stateless :func:`audit_proof`; only
    after it succeeds is the carried CRL snapshot examined. Its sequence
    and ``SHA256`` over its canonical CRL bytes are compared against the
    checkpoint under a lock: a lower sequence is rejected, an equal
    sequence is accepted solely as a replay of the identical CRL digest
    (a different digest at the same sequence is rejected), and a higher
    sequence advances the checkpoint. The compare-and-update is atomic: a
    rejected proof never changes the checkpoint and concurrent audits can
    never move it backwards. Every failure other than a non-bytes ``root``
    raises :class:`ValueError`.
    """

    def __init__(self, root: object, *, checkpoint: object = None) -> None:
        self._root = _require_root(root)
        self._lock = threading.Lock()
        self._state: "Optional[CrlState]" = None
        if checkpoint is None:
            return
        if isinstance(checkpoint, CrlState):
            state = checkpoint
        elif isinstance(checkpoint, bytes):
            state = CrlState.from_bytes(checkpoint)
        else:
            raise ValueError(
                "checkpoint must be a CrlState instance, its canonical bytes,"
                " or None"
            )
        if not hmac.compare_digest(
            _crl_state_mac(self._root, _crl_state_payload(state)), state.mac
        ):
            raise ValueError("checkpoint mac does not match the root")
        self._state = state

    @property
    def checkpoint(self) -> "Optional[CrlState]":
        """The current frontier :class:`CrlState`, or ``None`` before the
        first successfully audited proof. The returned object is frozen and
        the property read-only; persist its :meth:`CrlState.to_bytes` output
        and pass it back to a new auditor to survive a restart."""
        return self._state

    def audit(self, proof: "CrlProof | bytes") -> "Consensus":
        """Audit ``proof`` and enforce monotone CRL progress.

        Accepts a :class:`CrlProof` or its canonical
        :meth:`CrlProof.to_bytes` encoding, exactly like :func:`audit_proof`,
        which runs first and whose result is returned on success: every
        cryptographic, canonicity and replay failure it raises is a
        :class:`ValueError` and leaves the checkpoint untouched. After that
        succeeds, the carried CRL is gated against the checkpoint under the
        lock — lower sequence rejected, equal sequence accepted only with
        the identical CRL digest, higher sequence advancing it — and the new
        checkpoint is MAC'd as ``HMAC-SHA256(root, b"NPCK1" + encoding)``.
        """
        # Parse before locking: a malformed argument is rejected without
        # touching the checkpoint or serializing against another audit.
        if isinstance(proof, bytes):
            record = CrlProof.from_bytes(proof)
        elif isinstance(proof, CrlProof):
            record = proof
        else:
            raise ValueError("crl proof must be a CrlProof instance or bytes")
        # audit_proof is pure and owns the cryptographic/value contract, so
        # run it outside the lock; only the compare-and-update is serialized.
        consensus = audit_proof(record, self._root)
        sequence, crl_blob = _crl_proof_snapshot(record)
        digest = hashlib.sha256(crl_blob).digest()
        with self._lock:
            current = self._state
            if current is not None:
                if sequence < current.sequence:
                    raise ValueError(
                        "crl proof sequence is below the audited checkpoint"
                    )
                if sequence == current.sequence and not hmac.compare_digest(
                    digest, current.digest
                ):
                    raise ValueError(
                        "crl proof carries a different crl at the checkpoint"
                        " sequence"
                    )
                if sequence == current.sequence:
                    # Identical snapshot: an accepted replay, nothing to
                    # advance.
                    return consensus
            candidate = CrlState(
                version=1,
                sequence=sequence,
                digest=digest,
                mac=b"\x00" * 32,
            )
            self._state = replace(
                candidate,
                mac=_crl_state_mac(
                    self._root, _crl_state_payload(candidate)
                ),
            )
        return consensus
