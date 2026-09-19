"""nearproof - verifiable distance measurement and location proofs.

Public API: Challenge / ChallengeStateError / Evidence / Measurement /
Prover / RangeDecision / Verifier / assess / audit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import statistics
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

__all__ = [
    "Challenge",
    "ChallengeStateError",
    "Evidence",
    "Measurement",
    "Prover",
    "RangeDecision",
    "SPEED_OF_LIGHT_MPS",
    "Verifier",
    "assess",
    "audit",
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
        not satisfy the contract: exactly the evidence fields in field order,
        ``version == 1``, ``result == "accepted"``, non-bool integers, finite
        non-bool numbers, lowercase hex strings for the byte fields, and a
        32-byte ``mac``. The MAC is not verified here — use :func:`audit`
        with the shared key for that.
        """
        if not isinstance(data, bytes):
            raise ValueError("evidence data must be bytes")
        try:
            obj = json.loads(data)
        except ValueError as error:
            raise ValueError(f"evidence is not valid JSON: {error}") from error
        if not isinstance(obj, dict) or tuple(obj) != _EVIDENCE_FIELDS:
            raise ValueError(
                "evidence must be a JSON object with exactly the evidence "
                "fields in field order"
            )
        version = _parse_int_field(obj["version"], "version")
        if version != 1:
            raise ValueError("evidence version must be 1")
        result = obj["result"]
        if result != "accepted":
            raise ValueError('evidence result must be "accepted"')
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
            mac=_parse_mac_field(obj["mac"]),
        )


def _parse_mac_field(value: object) -> bytes:
    mac = _parse_hex_field(value, "mac")
    if len(mac) != 32:
        raise ValueError("evidence mac must decode to 32 bytes")
    return mac


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


@dataclass(frozen=True)
class RangeDecision:
    """The outcome of :func:`assess` over a batch of samples.

    ``sample_count`` counts every input sample (including outliers),
    ``upper_bound`` is the largest distance among the inlier samples, and
    ``accepted`` is true exactly when ``upper_bound`` does not exceed the
    assessed limit.
    """

    sample_count: int
    upper_bound: float
    accepted: bool


def _require_sample_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"sample {name} must be a finite non-negative number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"sample {name} must be a finite non-negative number")
    return number


def assess(
    samples,
    limit,
    *,
    key: Optional[bytes] = None,
    min_samples: int = 5,
) -> RangeDecision:
    """Decide an upper distance bound from a batch of measurement samples.

    ``samples`` must be all :class:`Measurement` instances, or all
    :class:`Evidence` records / their ``to_bytes()`` encodings (the two may
    be mixed with each other). Evidence samples are verified item by item
    with the audit semantics of :func:`audit`, which requires a non-empty
    ``key``. Mixing measurements with evidence, repeating a
    ``(round_index, nonce)`` pair, a negative or non-finite elapsed time or
    distance, or fewer than ``min_samples`` samples all raise
    :class:`ValueError`. ``limit`` must be a non-bool finite non-negative
    number and ``min_samples`` a non-bool positive integer.

    Let ``m`` be the median distance (for an even count, the mean of the two
    middle values) and MAD the median absolute deviation from ``m``. With
    ``MAD > 0`` the inliers are the samples in the closed interval
    ``[m - 3*MAD, m + 3*MAD]``; with ``MAD == 0`` only samples equal to ``m``
    are inliers. Fewer than ``min_samples`` inliers raises
    :class:`ValueError`. The decision's ``upper_bound`` is the largest
    inlier distance and ``accepted`` holds exactly when it does not exceed
    ``limit``; ``sample_count`` records every input sample.

    The result does not depend on the input order, and assessing is a pure
    function: it touches no verifier state.
    """
    if isinstance(limit, bool) or not isinstance(limit, (int, float)):
        raise ValueError("limit must be a finite non-negative number")
    limit = float(limit)
    if not math.isfinite(limit) or limit < 0:
        raise ValueError("limit must be a finite non-negative number")
    if isinstance(min_samples, bool) or not isinstance(min_samples, int):
        raise ValueError("min_samples must be a positive integer")
    if min_samples < 1:
        raise ValueError("min_samples must be a positive integer")

    items = list(samples)
    if len(items) < min_samples:
        raise ValueError("not enough samples")

    first = items[0]
    if isinstance(first, Measurement):
        measurements = []
        for item in items:
            if not isinstance(item, Measurement):
                raise ValueError(
                    "samples must be all Measurement or all Evidence/bytes"
                )
            measurements.append(item)
    elif isinstance(first, (Evidence, bytes)):
        if not key:
            raise ValueError("key must not be empty when assessing evidence")
        measurements = []
        for item in items:
            if not isinstance(item, (Evidence, bytes)):
                raise ValueError(
                    "samples must be all Measurement or all Evidence/bytes"
                )
            measurements.append(audit(item, key))
    else:
        raise ValueError("samples must be all Measurement or all Evidence/bytes")

    seen: set = set()
    distances = []
    for measurement in measurements:
        pair = (measurement.round_index, measurement.nonce)
        if pair in seen:
            raise ValueError("duplicate (round_index, nonce) sample")
        seen.add(pair)
        _require_sample_number(measurement.elapsed_seconds, "elapsed_seconds")
        distance = _require_sample_number(
            measurement.distance_meters, "distance_meters"
        )
        distances.append(distance)

    median = float(statistics.median(distances))
    mad = float(statistics.median([abs(d - median) for d in distances]))
    if mad > 0:
        low, high = median - 3.0 * mad, median + 3.0 * mad
        inliers = [d for d in distances if low <= d <= high]
    else:
        inliers = [d for d in distances if d == median]
    if len(inliers) < min_samples:
        raise ValueError("not enough inlier samples")

    upper_bound = max(inliers)
    return RangeDecision(
        sample_count=len(items),
        upper_bound=upper_bound,
        accepted=upper_bound <= limit,
    )
