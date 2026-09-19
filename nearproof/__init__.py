"""nearproof - verifiable distance measurement and location proofs.

Public API: Challenge / ChallengeStateError / Measurement / Prover / Verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "Challenge",
    "ChallengeStateError",
    "Measurement",
    "Prover",
    "SPEED_OF_LIGHT_MPS",
    "Verifier",
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
    """A challenge is unknown to this verifier, already consumed, revoked,
    or expired.

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

    With ``challenge_ttl_seconds`` set (requires ``replay_protection=True``)
    each issued challenge also carries a deadline: the ``clock()`` value at
    issuance plus the TTL. A challenge is only verifiable while the clock
    reads strictly before that deadline; at or past it the challenge is
    expired, a terminal state where both ``verify`` and ``revoke`` raise
    :class:`ChallengeStateError`.
    """

    def __init__(
        self,
        shared_key: bytes,
        *,
        speed_mps: float = SPEED_OF_LIGHT_MPS,
        clock: Callable[[], float] = time.perf_counter,
        replay_protection: bool = False,
        challenge_ttl_seconds: float | None = None,
    ) -> None:
        if not shared_key:
            raise ValueError("shared_key must not be empty")
        if speed_mps <= 0:
            raise ValueError("speed_mps must be positive")
        if challenge_ttl_seconds is None:
            self._challenge_ttl = None
        else:
            if isinstance(challenge_ttl_seconds, bool) or not isinstance(
                challenge_ttl_seconds, (int, float)
            ):
                raise ValueError(
                    "challenge_ttl_seconds must be None or a finite positive number"
                )
            ttl = float(challenge_ttl_seconds)
            if not math.isfinite(ttl) or ttl <= 0:
                raise ValueError(
                    "challenge_ttl_seconds must be None or a finite positive number"
                )
            if not replay_protection:
                raise ValueError("challenge_ttl_seconds requires replay_protection=True")
            self._challenge_ttl = ttl
        self._key = bytes(shared_key)
        self._speed = float(speed_mps)
        self._clock = clock
        self._round = 0
        self._replay_protection = bool(replay_protection)
        self._lock = threading.Lock()
        # id(issued challenge) -> [challenge, state, deadline]. Holding the
        # challenge object in the value keeps its id alive (no reuse) and
        # makes the registry bind to the issuing instance and the exact
        # object, not to a collidable round_index. ``deadline`` is the
        # clock() value at issuance plus the TTL, or None when no TTL is
        # configured (challenge never expires).
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
                    # Stamp the issuance time once; the deadline never moves
                    # afterwards, whatever happens to the challenge later.
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

        Only a challenge issued by this verifier that is still pending can be
        revoked. Unknown, already consumed, already revoked, or expired
        challenges raise :class:`ChallengeStateError`.
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
            if state == _PENDING:
                deadline = entry[2]
                if deadline is not None and self._clock() >= deadline:
                    entry[1] = _EXPIRED
                    raise ChallengeStateError("challenge has expired")
                entry[1] = _REVOKED
                return
            if state == _CONSUMED:
                raise ChallengeStateError("challenge has already been verified")
            if state == _EXPIRED:
                raise ChallengeStateError("challenge has expired")
            raise ChallengeStateError("challenge has already been revoked")

    def verify(self, challenge: Challenge, response: bytes, started_at: float) -> Measurement:
        """Validate the response and turn the elapsed round trip into a distance.

        When replay protection is enabled, ``challenge`` must be the exact
        pending object returned by :meth:`new_challenge` on this instance.
        Failed validation (bad response, negative elapsed time, wrong argument
        types) leaves the challenge pending so the caller can retry; only a
        successful return consumes it, and concurrent attempts can succeed at
        most once. If a TTL is configured, the challenge must also be checked
        before its deadline: at or past the deadline it expires terminally
        and every further ``verify`` raises :class:`ChallengeStateError`.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
        if not self._replay_protection:
            return self._verify_legacy(challenge, response, started_at)

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

            # All validations run while holding the lock so a failure leaves
            # the challenge pending and the pending -> consumed transition is
            # atomic across concurrent calls. The clock is read exactly once
            # so the expiry check and the elapsed time share a single "now".
            now = self._clock()
            deadline = entry[2]
            if deadline is not None and now >= deadline:
                entry[1] = _EXPIRED
                raise ChallengeStateError("challenge has expired")
            elapsed = now - float(started_at)
            if elapsed < 0:
                raise ValueError("elapsed time must not be negative")
            response_bytes = bytes(response)
            if not hmac.compare_digest(keyed_response(self._key, challenge.nonce), response_bytes):
                raise ValueError("response does not match the challenge")
            entry[1] = _CONSUMED

        return Measurement(
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=response_bytes,
            elapsed_seconds=elapsed,
            distance_meters=elapsed * self._speed / 2.0,
        )

    def _verify_legacy(
        self, challenge: Challenge, response: bytes, started_at: float
    ) -> Measurement:
        """Original single-round behaviour, unchanged when protection is off."""
        elapsed = self._clock() - float(started_at)
        if elapsed < 0:
            raise ValueError("elapsed time must not be negative")
        if not hmac.compare_digest(keyed_response(self._key, challenge.nonce), bytes(response)):
            raise ValueError("response does not match the challenge")
        # The signal travels to the prover and back, so halve the round trip.
        return Measurement(
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=bytes(response),
            elapsed_seconds=elapsed,
            distance_meters=elapsed * self._speed / 2.0,
        )

    def measure(self, prover: Prover) -> Measurement:
        """Run one complete round against ``prover``.

        With a TTL configured this fails with :class:`ChallengeStateError`
        if the response arrives at or after the challenge's deadline.
        """
        challenge = self.new_challenge()
        started_at = self._clock()
        response = prover.respond(challenge)
        return self.verify(challenge, response, started_at)
