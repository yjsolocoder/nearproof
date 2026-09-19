"""nearproof - verifiable distance measurement and location proofs.

Public API: Challenge / Measurement / Prover / Verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Callable

__all__ = [
    "Challenge",
    "Measurement",
    "Prover",
    "SPEED_OF_LIGHT_MPS",
    "Verifier",
]

SPEED_OF_LIGHT_MPS = 299_792_458.0
NONCE_BYTES = 16


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
    ) -> None:
        if not shared_key:
            raise ValueError("shared_key must not be empty")
        if speed_mps <= 0:
            raise ValueError("speed_mps must be positive")
        self._key = bytes(shared_key)
        self._speed = float(speed_mps)
        self._clock = clock
        self._round = 0

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    @property
    def round_count(self) -> int:
        return self._round

    def new_challenge(self) -> Challenge:
        self._round += 1
        return Challenge(round_index=self._round, nonce=os.urandom(NONCE_BYTES))

    def verify(self, challenge: Challenge, response: bytes, started_at: float) -> Measurement:
        """Validate the response and turn the elapsed round trip into a distance."""
        if not isinstance(challenge, Challenge):
            raise TypeError("challenge must be a Challenge")
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
        """Run one complete round against ``prover``."""
        challenge = self.new_challenge()
        started_at = self._clock()
        response = prover.respond(challenge)
        return self.verify(challenge, response, started_at)
