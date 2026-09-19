"""nearproof - verifiable distance measurement and location proofs.

Public API: AttestedObservation / Challenge / ChallengeStateError / Consensus /
Evidence / Measurement / Observation / ObservationRevocation / Prover /
RangeDecision / Verifier / assess / attest_observation / audit / locate /
locate_attested / revoke_observation.
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
    "Challenge",
    "ChallengeStateError",
    "Consensus",
    "Evidence",
    "Measurement",
    "Observation",
    "ObservationRevocation",
    "Prover",
    "RangeDecision",
    "SPEED_OF_LIGHT_MPS",
    "Verifier",
    "assess",
    "attest_observation",
    "audit",
    "locate",
    "locate_attested",
    "revoke_observation",
]

SPEED_OF_LIGHT_MPS = 299_792_458.0
NONCE_BYTES = 16

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


def keyed_response(key: bytes, nonce: bytes) -> bytes:
    """The response a holder of ``key`` must produce for ``nonce``."""
    return hmac.new(key, nonce, hashlib.sha256).digest()


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

    def new_challenge(self) -> Challenge:
        challenge = Challenge(round_index=self._round + 1, nonce=os.urandom(NONCE_BYTES))
        if self._replay_protection:
            with self._lock:
                self._round += 1
                deadline = None
                if self._challenge_ttl is not None:
                    deadline = self._clock() + self._challenge_ttl
                self._challenges[id(challenge)] = [challenge, _PENDING, deadline]
        else:
            self._round += 1
        return challenge

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

    def verify(self, challenge: Challenge, response: bytes, started_at: float) -> Measurement:
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
        """
        measurement, _end, _start = self._verify_round(
            challenge, response, started_at, require_finite=False
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

    def _verify_round(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        *,
        require_finite: bool,
    ) -> tuple[Measurement, float, float]:
        """Shared core of :meth:`verify` and :meth:`verify_evidence`.

        Returns ``(measurement, end, start)`` where ``end`` is the single
        clock reading of the call and ``start`` is ``float(started_at)``.
        With ``require_finite`` every recorded number is checked for
        finiteness before anything is consumed.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        if not self._replay_protection:
            return self._verify_legacy(challenge, response, started_at, require_finite)

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
            response_bytes = bytes(response)
            if not hmac.compare_digest(keyed_response(self._key, challenge.nonce), response_bytes):
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

    def _verify_legacy(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        require_finite: bool = False,
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
        response_bytes = bytes(response)
        if not hmac.compare_digest(keyed_response(self._key, challenge.nonce), response_bytes):
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

_DECISION_FIELDS = ("sample_count", "upper_bound", "accepted")

_REVOCATION_FIELDS = ("version", "id", "revoked_at", "mac")


class _OrderedAttestedObject(json.JSONDecoder):
    """JSON decoder that rejects duplicate and out-of-field-order object keys.

    The outer attested-observation object, the nested decision object and the
    observation-revocation object must each contain exactly their own fields,
    once each, in field order; the three field sets are distinguishable by
    their key lists, so a single hook can check all of them.
    """

    def __init__(self) -> None:
        super().__init__(object_pairs_hook=self._check_pairs)

    @staticmethod
    def _check_pairs(pairs: list) -> dict:
        keys = [key for key, _value in pairs]
        if keys in (
            list(_ATTESTED_FIELDS),
            list(_DECISION_FIELDS),
            list(_REVOCATION_FIELDS),
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
