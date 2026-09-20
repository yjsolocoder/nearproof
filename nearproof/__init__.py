"""nearproof - verifiable distance measurement and location proofs.

Public API: AttestedObservation / BoundAttestedObservation / BoundEvidence /
BoundEvidenceRevocation / CertifiedConsensusEvidence / Challenge /
ChallengeStateError / Consensus / ContextRevocation / Evidence /
Measurement / Observation / ObservationRevocation / Prover /
RangeDecision / SPEED_OF_LIGHT_MPS / TrustRevocation /
TrustRevocationList / Verifier / VerifierTrust / assess /
attest_observation / attest_observation_for_point / audit / audit_bound /
audit_bound_policy / audit_cert_evidence / audit_crl / cert / locate /
locate_attested / locate_bound_attested / locate_cert /
locate_cert_evidence / make_crl / revoke_bound / revoke_context /
revoke_observation / revoke_trust.
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
    "BoundAttestedObservation",
    "BoundEvidence",
    "BoundEvidenceRevocation",
    "CertifiedConsensusEvidence",
    "Challenge",
    "ChallengeStateError",
    "Consensus",
    "ContextRevocation",
    "Evidence",
    "Measurement",
    "Observation",
    "ObservationRevocation",
    "Prover",
    "RangeDecision",
    "SPEED_OF_LIGHT_MPS",
    "TrustRevocation",
    "TrustRevocationList",
    "Verifier",
    "VerifierTrust",
    "assess",
    "attest_observation",
    "attest_observation_for_point",
    "audit",
    "audit_bound",
    "audit_bound_policy",
    "audit_crl",
    "cert",
    "locate",
    "locate_attested",
    "locate_bound_attested",
    "locate_cert",
    "make_crl",
    "revoke_bound",
    "revoke_context",
    "revoke_observation",
    "revoke_trust",
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


_CERT_EVIDENCE_FIELDS = ("version", "body", "mac")


class _OrderedCertEvidenceObject(json.JSONDecoder):
    """JSON decoder that rejects duplicate and out-of-field-order keys.

    The outer certified-consensus-evidence object is the only JSON object in
    the encoding (``body`` is a hex string and its decoded payload is a JSON
    array), so its keys must be exactly ``version``/``body``/``mac`` in field
    order.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys != list(_CERT_EVIDENCE_FIELDS):
            raise ValueError(
                "certified consensus evidence JSON keys must be exactly"
                " version, body, mac in field order"
            )
        return dict(pairs)


def _cert_evidence_hex(value: object, name: str) -> bytes:
    """Decode a canonical lowercase hex string inside a cert evidence body."""
    if not isinstance(value, str):
        raise ValueError(
            f"certified consensus evidence {name} must be a lowercase hex string"
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            f"certified consensus evidence {name} must be a lowercase hex string"
        ) from error
    if raw.hex() != value:
        # Rejects uppercase digits, separators and odd-length input that
        # bytes.fromhex would otherwise tolerate.
        raise ValueError(
            f"certified consensus evidence {name} must be a lowercase hex string"
        )
    return raw


def _decode_cert_body(body: bytes) -> list:
    """Validate a cert-evidence body and return its canonical JSON value.

    The body decodes to the five-element array
    ``[point, context, records, trusts, consensus]``. ``records``/``trusts``
    are arrays of canonical lowercase-hex encodings (of
    :class:`BoundAttestedObservation` and :class:`VerifierTrust`), sorted by
    unique id and aligned one-to-one in that id order; every record must be
    bound to the body point/context and its trust's coordinates must match.
    ``consensus`` is the four-element array
    ``[total, support, rejected, accepted]`` in :class:`Consensus` field
    order, with ``rejected`` strictly lexicographically sorted and confined
    to the record ids. Every contract violation raises :class:`ValueError`.
    No MAC is checked here.
    """
    if not isinstance(body, bytes):
        raise ValueError("certified consensus evidence body must be bytes")
    try:
        value = json.loads(body)
    except ValueError as error:
        raise ValueError(
            f"certified consensus evidence body is not valid JSON: {error}"
        ) from error
    if not isinstance(value, list) or len(value) != 5:
        raise ValueError(
            "certified consensus evidence body must be an array of exactly"
            " five elements"
        )
    point, context, raw_records, raw_trusts, raw_consensus = value

    if (
        not isinstance(point, list)
        or len(point) != 2
        or any(
            isinstance(coordinate, bool)
            or not isinstance(coordinate, (int, float))
            or not math.isfinite(coordinate)
            for coordinate in point
        )
    ):
        raise ValueError(
            "certified consensus evidence point must be an array of exactly"
            " two finite numbers"
        )
    if not isinstance(context, str) or not context:
        raise ValueError(
            "certified consensus evidence context must be a non-empty string"
        )

    if not isinstance(raw_records, list):
        raise ValueError(
            "certified consensus evidence records must be an array"
        )
    records: list[BoundAttestedObservation] = []
    for item in raw_records:
        raw = _cert_evidence_hex(item, "records")
        try:
            records.append(BoundAttestedObservation.from_bytes(raw))
        except ValueError as error:
            raise ValueError(
                "certified consensus evidence records must be canonical"
                " BoundAttestedObservation encodings"
            ) from error

    if not isinstance(raw_trusts, list):
        raise ValueError(
            "certified consensus evidence trusts must be an array"
        )
    trusts: list[VerifierTrust] = []
    for item in raw_trusts:
        raw = _cert_evidence_hex(item, "trusts")
        try:
            trusts.append(VerifierTrust.from_bytes(raw))
        except ValueError as error:
            raise ValueError(
                "certified consensus evidence trusts must be canonical"
                " VerifierTrust encodings"
            ) from error

    if len(records) < 3:
        raise ValueError(
            f"certified consensus evidence needs at least 3 records, got"
            f" {len(records)}"
        )
    if len(records) != len(trusts):
        raise ValueError(
            "certified consensus evidence records and trusts must correspond"
            " one-to-one in id order"
        )
    record_ids = [record.id for record in records]
    trust_ids = [trust.id for trust in trusts]
    if len(set(record_ids)) != len(record_ids) or record_ids != sorted(record_ids):
        raise ValueError(
            "certified consensus evidence records must be sorted by unique id"
        )
    if trust_ids != record_ids:
        raise ValueError(
            "certified consensus evidence trusts must align with the records"
            " one-to-one in id order"
        )
    for record, trust in zip(records, trusts):
        if record.point[0] != point[0] or record.point[1] != point[1]:
            raise ValueError(
                "certified consensus evidence record is not bound to the body"
                f" point: {record.id!r}"
            )
        if record.context != context:
            raise ValueError(
                "certified consensus evidence record is not bound to the body"
                f" context: {record.id!r}"
            )
        if trust.x != record.x or trust.y != record.y:
            raise ValueError(
                "certified consensus evidence trust does not match the"
                f" record: {record.id!r}"
            )

    if not isinstance(raw_consensus, list) or len(raw_consensus) != 4:
        raise ValueError(
            "certified consensus evidence consensus must be an array of"
            " exactly four elements"
        )
    total, support, rejected, accepted = raw_consensus
    if type(total) is not int or total < 0:
        raise ValueError(
            "certified consensus evidence consensus total must be a"
            " non-negative integer"
        )
    if type(support) is not int or support < 0 or support > total:
        raise ValueError(
            "certified consensus evidence consensus support must be a"
            " non-negative integer not exceeding total"
        )
    if type(accepted) is not bool:
        raise ValueError(
            "certified consensus evidence consensus accepted must be a bool"
        )
    if not isinstance(rejected, list) or not all(
        isinstance(ident, str) for ident in rejected
    ):
        raise ValueError(
            "certified consensus evidence consensus rejected must be an array"
            " of strings"
        )
    if len(set(rejected)) != len(rejected) or rejected != sorted(rejected):
        raise ValueError(
            "certified consensus evidence consensus rejected must be sorted"
            " lexicographically with no duplicates"
        )
    if total != len(records):
        raise ValueError(
            "certified consensus evidence consensus total must equal the"
            " number of records"
        )
    if support != total - len(rejected):
        raise ValueError(
            "certified consensus evidence consensus support must equal total"
            " minus the number of rejected ids"
        )
    if set(rejected) - set(record_ids):
        raise ValueError(
            "certified consensus evidence consensus rejected ids must be"
            " record ids"
        )

    return [
        [point[0], point[1]],
        context,
        [record.to_bytes().hex() for record in records],
        [trust.to_bytes().hex() for trust in trusts],
        [total, support, list(rejected), accepted],
    ]


def _cert_evidence_mac(root: bytes, body: bytes) -> bytes:
    """HMAC-SHA256 over ``b"NPCCE1"`` plus the body bytes, directly joined."""
    return hmac.new(
        root, _CERT_EVIDENCE_PREFIX + body, hashlib.sha256
    ).digest()


@dataclass(frozen=True)
class CertifiedConsensusEvidence:
    """A root-MAC'd, frozen evidence of one :func:`locate_cert` consensus.

    Constructed positionally in field order; instances are frozen and equal
    by their fields. ``version`` is always ``1``; ``body`` and ``mac`` are
    ``bytes`` and ``mac`` is exactly 32 bytes. Any contract violation raises
    :class:`ValueError` at construction time.

    ``body`` is compact UTF-8 JSON — the array
    ``[point, context, records, trusts, consensus]`` — where ``point`` is a
    two-element array of finite non-bool numbers, ``context`` a non-empty
    string, ``records``/``trusts`` arrays of canonical lowercase-hex
    :class:`BoundAttestedObservation`/:class:`VerifierTrust` encodings sorted
    by unique id and aligned one-to-one in that order, and ``consensus`` the
    array ``[total, support, rejected, accepted]`` in :class:`Consensus`
    field order with ``rejected`` lexicographically sorted. ``mac`` is
    ``HMAC-SHA256(root, b"NPCCE1" + body)``, the prefix and body joined
    directly with no separator or length prefix. No root material is stored.
    """

    version: int
    body: bytes
    mac: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("certified consensus evidence version must be 1")
        if not isinstance(self.body, bytes):
            raise ValueError("certified consensus evidence body must be bytes")
        if not isinstance(self.mac, bytes) or len(self.mac) != 32:
            raise ValueError(
                "certified consensus evidence mac must be exactly 32 bytes"
            )

    def to_bytes(self) -> bytes:
        """Encode as compact UTF-8 JSON: the outer keys in field order
        ``version, body, mac``, both ``body`` and ``mac`` as lowercase hex,
        no whitespace, no length prefix, no NaN/Infinity. The body is
        revalidated and re-encoded canonically."""
        body = _encode_payload(_decode_cert_body(self.body))
        return _encode_payload(
            {"version": self.version, "body": body.hex(), "mac": self.mac.hex()}
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "CertifiedConsensusEvidence":
        """Decode :meth:`to_bytes` output, enforcing the full body contract.

        Raises :class:`ValueError` for anything that is not ``bytes`` or does
        not satisfy the contract: the outer object must carry exactly
        ``version``/``body``/``mac`` once each in field order; ``version``
        must be ``1``; ``body`` must decode (as lowercase hex) to the
        five-element canonical body array described on this class, with its
        point, context, record/trust hex arrays and consensus array all
        valid; ``mac`` must be lowercase hex decoding to exactly 32 bytes.
        After parsing and validation the record is re-encoded with
        :meth:`to_bytes` and the result must equal the input byte for byte,
        so formatted JSON, whitespace, framing, non-canonical spellings and
        records/trusts not sorted by id are rejected as well. The MAC is not
        verified here — use :func:`audit_cert_evidence` with the root key for
        that.
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
                "certified consensus evidence must be a JSON object with"
                " exactly version, body and mac in field order"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("certified consensus evidence version must be 1")
        raw_body = _cert_evidence_hex(obj["body"], "body")
        body = _encode_payload(_decode_cert_body(raw_body))
        mac = _cert_evidence_hex(obj["mac"], "mac")
        if len(mac) != 32:
            raise ValueError(
                "certified consensus evidence mac must decode to exactly"
                " 32 bytes"
            )
        record = cls(version=version, body=body, mac=mac)
        if record.to_bytes() != data:
            # Same canonical-encoding rule as the other records: no
            # whitespace, pretty-printing, framing or non-canonical
            # number/string spellings at either JSON layer.
            raise ValueError(
                "certified consensus evidence encoding is not canonical"
            )
        return record


def locate_cert_evidence(
    records: object,
    point: object,
    context: object,
    trusts: object,
    root: object,
) -> CertifiedConsensusEvidence:
    """Run :func:`locate_cert` and wrap its result with the participating items.

    The arguments are exactly those of :func:`locate_cert` without its
    revocation/now/min options: ``records`` an iterable of
    :class:`BoundAttestedObservation` instances and/or their canonical
    encodings, ``trusts`` an iterable of :class:`VerifierTrust` instances
    and/or their canonical encodings, ``point`` a tuple of exactly two
    finite non-bool numbers, ``context`` a non-empty string, and ``root``
    non-empty ``bytes`` (a non-bytes root raises :class:`TypeError`, an empty
    one :class:`ValueError`). Every validation :func:`locate_cert` performs
    runs unchanged and raises :class:`ValueError` on any breach.

    On success the returned :class:`CertifiedConsensusEvidence` carries the
    body array ``[point, context, records, trusts, consensus]``: the
    participating records and trusts are their canonical encodings as
    lowercase hex, sorted by unique id and aligned one-to-one in that order,
    and ``consensus`` is the :func:`locate_cert` result in
    :class:`Consensus` field order with ``rejected`` lexicographically
    sorted. Its MAC is
    ``HMAC-SHA256(root, b"NPCCE1" + body)``, prefix and body joined directly
    with no separator or length prefix. The function is pure and reads no
    verifier state.
    """
    root = _require_root(root)
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
    for item in raw_trusts:
        if isinstance(item, bytes):
            item = VerifierTrust.from_bytes(item)
        if not isinstance(item, VerifierTrust):
            raise ValueError(
                "trusts must contain only VerifierTrust instances or bytes"
            )
        parsed_trusts.append(item)

    consensus = locate_cert(parsed_records, point, context, parsed_trusts, root)

    trust_by_id = {trust.id: trust for trust in parsed_trusts}
    ordered_records = sorted(parsed_records, key=lambda record: record.id)
    body = _encode_payload(
        [
            [point[0], point[1]],
            context,
            [record.to_bytes().hex() for record in ordered_records],
            [trust_by_id[record.id].to_bytes().hex() for record in ordered_records],
            [
                consensus.total,
                consensus.support,
                list(consensus.rejected),
                consensus.accepted,
            ],
        ]
    )
    record = CertifiedConsensusEvidence(
        version=1, body=body, mac=b"\x00" * 32
    )
    return replace(record, mac=_cert_evidence_mac(root, body))


def audit_cert_evidence(
    x: "CertifiedConsensusEvidence | bytes", root: object
) -> Consensus:
    """Authenticate a :class:`CertifiedConsensusEvidence` and rerun its consensus.

    Accepts the evidence itself or its canonical
    :meth:`CertifiedConsensusEvidence.to_bytes` encoding; anything else
    raises :class:`ValueError`. ``root`` must be non-empty ``bytes`` (a
    non-bytes value raises :class:`TypeError`, an empty value
    :class:`ValueError`). The full body contract is enforced through
    :meth:`CertifiedConsensusEvidence.from_bytes`, then the MAC is
    recomputed as ``HMAC-SHA256(root, b"NPCCE1" + body)`` and compared in
    constant time; a mismatch raises :class:`ValueError`. Finally
    :func:`locate_cert` is rerun from the body's point/context/records/
    trusts under ``root`` (re-verifying every trust MAC, record MAC and
    binding, and recomputing the geometry), and its :class:`Consensus` must
    equal the one carried in the body field by field — otherwise
    :class:`ValueError`. On success the rerun :class:`Consensus` is returned.
    The check is pure and touches no state.
    """
    root = _require_root(root)
    if isinstance(x, bytes):
        evidence = CertifiedConsensusEvidence.from_bytes(x)
    elif isinstance(x, CertifiedConsensusEvidence):
        evidence = x
        # An object built by hand still has to satisfy the body contract.
        _decode_cert_body(evidence.body)
    else:
        raise ValueError(
            "certified consensus evidence must be a"
            " CertifiedConsensusEvidence instance or bytes"
        )
    if not hmac.compare_digest(
        _cert_evidence_mac(root, evidence.body), evidence.mac
    ):
        raise ValueError("certified consensus evidence mac does not match")
    point_v, context, record_hex, trust_hex, consensus_v = _decode_cert_body(
        evidence.body
    )
    rerun = locate_cert(
        [bytes.fromhex(item) for item in record_hex],
        (point_v[0], point_v[1]),
        context,
        [bytes.fromhex(item) for item in trust_hex],
        root,
    )
    claimed = Consensus(
        total=consensus_v[0],
        support=consensus_v[1],
        rejected=tuple(consensus_v[2]),
        accepted=consensus_v[3],
    )
    if rerun != claimed:
        raise ValueError(
            "certified consensus evidence consensus does not match a rerun of"
            " locate_cert"
        )
    return rerun
