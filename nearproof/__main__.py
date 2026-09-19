"""Self-contained demo: python3 -m nearproof"""

from __future__ import annotations

from . import Prover, Verifier

SHARED_KEY = bytes(range(32))


class SteppedClock:
    """Deterministic clock used to show a reproducible distance."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def main() -> int:
    clock = SteppedClock()
    prover = Prover(SHARED_KEY)
    verifier = Verifier(SHARED_KEY, clock=clock)

    print("simulated round trips:")
    for trip_ns in (100.0, 1_000.0, 10_000.0):
        clock.now = 0.0
        challenge = verifier.new_challenge()
        started = clock.now
        response = prover.respond(challenge)
        clock.advance(trip_ns / 1e9)
        measurement = verifier.verify(challenge, response, started)
        print(f"  rtt={trip_ns:>8.0f} ns -> distance={measurement.distance_meters:>10.3f} m")

    print()
    print(f"rounds issued: {verifier.round_count}")
    challenge = verifier.new_challenge()
    try:
        verifier.verify(challenge, b"\x00" * 32, clock.now)
    except ValueError as error:
        print(f"forged response rejected: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
