"""nearproof - verifiable distance measurement and location proofs.

Public API: Challenge / Measurement / Prover / Verifier / ChallengeStateError.
"""

from __future__ import annotations

import hashlib
import hmac
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

# Lifecycle states of a challenge tracked by a replay-protected verifier.
_STATE_PENDING = "pending"
_STATE_CONSUMED = "consumed"
_STATE_REVOKED = "revoked"


class ChallengeStateError(ValueError):
    """Raised when a challenge is not a live, pending challenge of this verifier.

    This covers challenges that were never registered, were issued by another
    verifier instance, have already been successfully verified, or have been
    explicitly revoked.  It subclasses :class:`ValueError` so callers that only
    catch the broader failure type keep working.
    """


@dataclass(frozen=True)
class Challenge:
    """One challenge issued by a verifier."""

    round_index: int
    nonce: bytes


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
    """Measures the round trip of a single challenge/response exchange."""

    def __init__(
        self,
        shared_key: bytes,
        *,
        speed_mps: float = SPEED_OF_LIGHT_MPS,
        clock: Callable[[], float] = time.perf_counter,
        replay_protection: bool = False,
    ) -> None:
        if not shared_key:
            raise ValueError("shared_key must not be empty")
        if speed_mps <= 0:
            raise ValueError("speed_mps must be positive")
        self._key = bytes(shared_key)
        self._speed = float(speed_mps)
        self._clock = clock
        self._replay_protection = bool(replay_protection)
        self._round = 0
        # Maps the full challenge content (round_index + nonce) to its
        # lifecycle state.  The dict is per instance, so membership both binds
        # the challenge to the issuing verifier and pins its complete content;
        # a colliding round_index alone can never match.
        self._challenges: dict[Challenge, str] = {}
        self._lock = threading.Lock()

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    @property
    def round_count(self) -> int:
        return self._round

    @property
    def replay_protection(self) -> bool:
        return self._replay_protection

    def new_challenge(self) -> Challenge:
        self._round += 1
        challenge = Challenge(round_index=self._round, nonce=os.urandom(NONCE_BYTES))
        if self._replay_protection:
            with self._lock:
                self._challenges[challenge] = _STATE_PENDING
        return challenge

    def revoke(self, challenge: Challenge) -> None:
        """Revoke a challenge that is still pending on this verifier.

        A revoked challenge can never be verified afterwards.  Revoking an
        unknown, externally built, already-consumed or already-revoked
        challenge raises :class:`ChallengeStateError`.
        """
        if not self._replay_protection:
            raise ChallengeStateError(
                "replay protection is disabled; revoke is not available"
            )
        if not isinstance(challenge, Challenge):
            raise ChallengeStateError("challenge must be a Challenge")
        with self._lock:
            state = self._challenges.get(challenge)
            if state != _STATE_PENDING:
                raise ChallengeStateError(
                    "challenge is not pending on this verifier"
                )
            self._challenges[challenge] = _STATE_REVOKED

    def verify(self, challenge: Challenge, response: bytes, started_at: float) -> Measurement:
        """Validate the response and turn the elapsed round trip into a distance.

        With replay protection enabled the challenge must be a pending
        challenge issued by this verifier.  Only a successful return consumes
        it; any failure (bad response, negative elapsed time, bad argument
        types) leaves it pending and retryable.
        """
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")

        if self._replay_protection:
            # State gate (read-only at this point): only a live pending
            # challenge of this verifier may proceed.  It is checked before
            # response validation so replays of dead challenges always surface
            # as ChallengeStateError regardless of their payload.
            with self._lock:
                if self._challenges.get(challenge) != _STATE_PENDING:
                    raise ChallengeStateError(
                        "challenge is not a pending challenge of this verifier"
                    )

        # All failure-producing validation happens before the challenge is
        # claimed, so a failed call never burns the challenge and the caller
        # can retry after fixing the inputs.
        elapsed = self._clock() - float(started_at)
        if elapsed < 0:
            raise ValueError("elapsed time must not be negative")
        response = bytes(response)
        if not hmac.compare_digest(keyed_response(self._key, challenge.nonce), response):
            raise ValueError("response does not match the challenge")

        if self._replay_protection:
            # Atomically claim the pending challenge.  Concurrent calls that
            # passed the read-only gate race here; at most one observes the
            # pending state and returns successfully.
            with self._lock:
                if self._challenges.get(challenge) != _STATE_PENDING:
                    raise ChallengeStateError(
                        "challenge is not a pending challenge of this verifier"
                    )
                self._challenges[challenge] = _STATE_CONSUMED

        # The signal travels to the prover and back, so halve the round trip.
        return Measurement(
            round_index=challenge.round_index,
            nonce=challenge.nonce,
            response=response,
            elapsed_seconds=elapsed,
            distance_meters=elapsed * self._speed / 2.0,
        )

    def measure(self, prover: Prover) -> Measurement:
        """Run one complete round against ``prover``."""
        challenge = self.new_challenge()
        started_at = self._clock()
        response = prover.respond(challenge)
        return self.verify(challenge, response, started_at)
