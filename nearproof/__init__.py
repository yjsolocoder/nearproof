"""nearproof - verifiable distance measurement and location proofs.

Public API: Challenge / ChallengeStateError / Evidence / Measurement /
Prover / Verifier / audit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Union

__all__ = [
    "Challenge",
    "ChallengeStateError",
    "Evidence",
    "Measurement",
    "Prover",
    "SPEED_OF_LIGHT_MPS",
    "Verifier",
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


def keyed_response(key: bytes, nonce: bytes) -> bytes:
    """The response a holder of ``key`` must produce for ``nonce``."""
    return hmac.new(key, nonce, hashlib.sha256).digest()


_EVIDENCE_VERSION = 1
_EVIDENCE_RESULT = "accepted"
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
_EVIDENCE_NUMBER_FIELDS = ("start", "end", "speed", "elapsed", "distance")
_HEX_DIGITS = frozenset("0123456789abcdef")


def _encode_evidence(
    version: int,
    round_index: int,
    nonce: bytes,
    response: bytes,
    start: float,
    end: float,
    speed: float,
    elapsed: float,
    distance: float,
    result: str,
    mac: Optional[bytes] = None,
) -> bytes:
    """Canonical compact JSON encoding; bytes fields as lowercase hex."""
    obj = {
        "version": version,
        "round_index": round_index,
        "nonce": nonce.hex(),
        "response": response.hex(),
        "start": start,
        "end": end,
        "speed": speed,
        "elapsed": elapsed,
        "distance": distance,
        "result": result,
    }
    if mac is not None:
        obj["mac"] = mac.hex()
    return json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()


def _parse_hex_field(value: object, name: str) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) % 2
        or any(char not in _HEX_DIGITS for char in value)
    ):
        raise ValueError(f"{name} must be lowercase hexadecimal")
    return bytes.fromhex(value)


def _require_finite(*values: float) -> None:
    if not all(math.isfinite(value) for value in values):
        raise ValueError("evidence values must be finite numbers")


@dataclass(frozen=True)
class Evidence:
    """A tamper-evident record of one accepted challenge/response round.

    Produced by :meth:`Verifier.verify_evidence`. ``version`` is always 1 and
    ``result`` always ``"accepted"``. ``mac`` is HMAC-SHA256, keyed with the
    shared key, over the canonical encoding of every field except ``mac``
    itself; the key is never stored in the record.
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

    def _signed_bytes(self) -> bytes:
        """The canonical encoding of every field except ``mac``."""
        return _encode_evidence(
            self.version,
            self.round_index,
            self.nonce,
            self.response,
            self.start,
            self.end,
            self.speed,
            self.elapsed,
            self.distance,
            self.result,
        )

    def to_bytes(self) -> bytes:
        """Canonical compact UTF-8 JSON encoding of the whole record."""
        return _encode_evidence(
            self.version,
            self.round_index,
            self.nonce,
            self.response,
            self.start,
            self.end,
            self.speed,
            self.elapsed,
            self.distance,
            self.result,
            self.mac,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Evidence":
        """Parse the canonical encoding, enforcing the field contract.

        Anything that is not ``bytes`` holding a compact JSON object with
        exactly the evidence fields in field order — version 1, result
        ``"accepted"``, lowercase-hex byte fields, a 32-byte ``mac``, and
        finite non-boolean numbers — raises :class:`ValueError`.
        """
        if not isinstance(data, bytes):
            raise ValueError("evidence must be bytes")
        try:
            obj = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("evidence is not valid JSON") from exc
        if not isinstance(obj, dict) or list(obj) != list(_EVIDENCE_FIELDS):
            raise ValueError("evidence must be an object with the evidence fields")
        version = obj["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != 1:
            raise ValueError("unsupported evidence version")
        round_index = obj["round_index"]
        if isinstance(round_index, bool) or not isinstance(round_index, int):
            raise ValueError("round_index must be an integer")
        nonce = _parse_hex_field(obj["nonce"], "nonce")
        response = _parse_hex_field(obj["response"], "response")
        mac = _parse_hex_field(obj["mac"], "mac")
        if len(mac) != hashlib.sha256().digest_size:
            raise ValueError("mac must be 32 bytes")
        numbers = {}
        for name in _EVIDENCE_NUMBER_FIELDS:
            value = obj[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a finite number")
            value = float(value)
            if not math.isfinite(value):
                raise ValueError(f"{name} must be a finite number")
            numbers[name] = value
        if obj["result"] != _EVIDENCE_RESULT:
            raise ValueError('result must be "accepted"')
        return cls(
            version=_EVIDENCE_VERSION,
            round_index=round_index,
            nonce=nonce,
            response=response,
            start=numbers["start"],
            end=numbers["end"],
            speed=numbers["speed"],
            elapsed=numbers["elapsed"],
            distance=numbers["distance"],
            result=_EVIDENCE_RESULT,
            mac=mac,
        )


def audit(evidence: Union[Evidence, bytes], key: bytes) -> Measurement:
    """Re-validate an evidence record and return the measurement it attests to.

    ``evidence`` may be an :class:`Evidence` or its ``to_bytes()`` encoding.
    The MAC and the keyed response are recomputed with ``key`` and compared in
    constant time, and the elapsed time and halved distance are recomputed
    from ``start``/``end``/``speed``; any mismatch, or an empty ``key``,
    raises :class:`ValueError`.

    Auditing is pure re-validation of the record: it consumes no verifier
    state and is no substitute for the replay and TTL checks that
    :meth:`Verifier.verify_evidence` performs when the evidence is created.
    """
    if isinstance(evidence, bytes):
        evidence = Evidence.from_bytes(evidence)
    elif not isinstance(evidence, Evidence):
        raise TypeError("evidence must be an Evidence or bytes")
    if not key:
        raise ValueError("key must not be empty")
    key_bytes = bytes(key)
    expected_mac = hmac.new(key_bytes, evidence._signed_bytes(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, evidence.mac):
        raise ValueError("evidence mac does not match the key")
    if not hmac.compare_digest(keyed_response(key_bytes, evidence.nonce), evidence.response):
        raise ValueError("response does not match the challenge")
    elapsed = evidence.end - evidence.start
    if elapsed != evidence.elapsed:
        raise ValueError("elapsed time does not match start/end")
    distance = elapsed * evidence.speed / 2.0
    if distance != evidence.distance:
        raise ValueError("distance does not match elapsed/speed")
    return Measurement(
        round_index=evidence.round_index,
        nonce=evidence.nonce,
        response=evidence.response,
        elapsed_seconds=evidence.elapsed,
        distance_meters=evidence.distance,
    )


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
        _, _, response_bytes, elapsed, distance = self._verify_core(
            challenge, response, started_at, require_finite=False
        )
        return Measurement(
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=response_bytes,
            elapsed_seconds=elapsed,
            distance_meters=distance,
        )

    def verify_evidence(
        self, challenge: Challenge, response: bytes, started_at: float
    ) -> Evidence:
        """Like :meth:`verify`, but returns a keyed :class:`Evidence` record.

        Takes the same arguments and applies the same state, TTL and
        validation order with the same atomic consumption: a failed call
        leaves the challenge pending, only a successful return consumes it.
        ``start`` is ``float(started_at)`` and ``end`` is the single clock
        reading of the call. Unlike :meth:`verify`, non-finite numbers
        (``nan``/``inf`` start, clock reading, elapsed time or distance)
        raise :class:`ValueError` without consuming the challenge.
        """
        start, end, response_bytes, elapsed, distance = self._verify_core(
            challenge, response, started_at, require_finite=True
        )
        signed = _encode_evidence(
            _EVIDENCE_VERSION,
            challenge.round_index,
            challenge.nonce,
            response_bytes,
            start,
            end,
            self._speed,
            elapsed,
            distance,
            _EVIDENCE_RESULT,
        )
        return Evidence(
            version=_EVIDENCE_VERSION,
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=response_bytes,
            start=start,
            end=end,
            speed=self._speed,
            elapsed=elapsed,
            distance=distance,
            result=_EVIDENCE_RESULT,
            mac=hmac.new(self._key, signed, hashlib.sha256).digest(),
        )

    def _verify_core(
        self,
        challenge: Challenge,
        response: bytes,
        started_at: float,
        *,
        require_finite: bool,
    ) -> tuple[float, float, bytes, float, float]:
        """Shared timing/validation core for :meth:`verify` and
        :meth:`verify_evidence`.

        Returns ``(start, end, response_bytes, elapsed, distance)``. The clock
        is read at most once per call; with replay protection the state
        checks, expiry decision and the pending -> consumed transition all
        happen under the lock, so a challenge is consumed at most once and a
        failed call leaves it pending. With ``require_finite`` (evidence only)
        non-finite start/end/elapsed/distance raise :class:`ValueError` before
        anything is consumed.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        if not self._replay_protection:
            end = self._clock()
            start = float(started_at)
            elapsed = end - start
            if elapsed < 0:
                raise ValueError("elapsed time must not be negative")
            # The signal travels to the prover and back, so halve the round trip.
            distance = elapsed * self._speed / 2.0
            if require_finite:
                _require_finite(start, end, elapsed, distance)
            response_bytes = bytes(response)
            if not hmac.compare_digest(
                keyed_response(self._key, challenge.nonce), response_bytes
            ):
                raise ValueError("response does not match the challenge")
            return start, end, response_bytes, elapsed, distance

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
            if elapsed < 0:
                raise ValueError("elapsed time must not be negative")
            distance = elapsed * self._speed / 2.0
            if require_finite:
                _require_finite(start, now, elapsed, distance)
            response_bytes = bytes(response)
            if not hmac.compare_digest(
                keyed_response(self._key, challenge.nonce), response_bytes
            ):
                raise ValueError("response does not match the challenge")
            entry[1] = _CONSUMED
            return start, now, response_bytes, elapsed, distance

    def measure(self, prover: Prover) -> Measurement:
        """Run one complete round against ``prover``."""
        challenge = self.new_challenge()
        started_at = self._clock()
        response = prover.respond(challenge)
        return self.verify(challenge, response, started_at)
