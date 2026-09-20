import hashlib
import hmac
import unittest

from nearproof import (
    Challenge,
    ChallengeStateError,
    Measurement,
    Prover,
    Verifier,
)

KEY = b"shared-secret-key"
CONTEXT = b"\x02" * 32
OPENING = b"\x03" * 32
OTHER_OPENING = b"\x04" * 32


def bound_digest(context, opening):
    return hashlib.sha256(b"NPC1" + context + opening).digest()


def bound_response(key, digest, round_index, nonce):
    message = b"NPR1" + digest + round_index.to_bytes(8, "big") + nonce
    return hmac.new(key, message, hashlib.sha256).digest()


DIGEST = bound_digest(CONTEXT, OPENING)


class SteppedClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def fixture(ttl=None, **kwargs):
    clock = kwargs.pop("clock", None) or SteppedClock()
    prover = Prover(kwargs.pop("prover_key", KEY))
    kwargs.setdefault("replay_protection", True)
    kwargs.setdefault("challenge_ttl_seconds", ttl)
    verifier = Verifier(kwargs.pop("verifier_key", KEY), clock=clock, **kwargs)
    return clock, prover, verifier


class RevealTest(unittest.TestCase):
    def test_reveal_matches_spec_formula(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        self.assertEqual(
            response,
            bound_response(KEY, DIGEST, challenge.round_index, challenge.nonce),
        )

    def test_reveal_binds_round_index_and_nonce(self):
        prover = Prover(KEY)
        first = prover.reveal(Challenge(1, b"0" * 16), CONTEXT, OPENING)
        second = prover.reveal(Challenge(2, b"0" * 16), CONTEXT, OPENING)
        third = prover.reveal(Challenge(1, b"1" * 16), CONTEXT, OPENING)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)

    def test_reveal_requires_challenge(self):
        prover = Prover(KEY)
        with self.assertRaises(TypeError):
            prover.reveal("not a challenge", CONTEXT, OPENING)

    def test_reveal_round_index_must_be_u64(self):
        prover = Prover(KEY)
        for bad in (True, False, -1, 1 << 64, 1.5, "1"):
            with self.assertRaises(ValueError):
                prover.reveal(Challenge(bad, b"0" * 16), CONTEXT, OPENING)
        for good in (0, 1, (1 << 64) - 1):
            response = prover.reveal(Challenge(good, b"0" * 16), CONTEXT, OPENING)
            self.assertEqual(len(response), 32)

    def test_reveal_nonce_must_be_16_bytes(self):
        prover = Prover(KEY)
        for bad in (b"0" * 15, b"0" * 17, "0" * 16):
            with self.assertRaises(ValueError):
                prover.reveal(Challenge(1, bad), CONTEXT, OPENING)

    def test_reveal_context_and_opening_must_be_32_bytes(self):
        prover = Prover(KEY)
        challenge = Challenge(1, b"0" * 16)
        for bad in (b"\x00" * 31, b"\x00" * 33, "x" * 32, None):
            with self.assertRaises(ValueError):
                prover.reveal(challenge, bad, OPENING)
            with self.assertRaises(ValueError):
                prover.reveal(challenge, CONTEXT, bad)


class NewChallengeBindingTest(unittest.TestCase):
    def test_context_and_digest_must_be_paired(self):
        _, _, verifier = fixture()
        with self.assertRaises(ValueError):
            verifier.new_challenge(context=CONTEXT)
        with self.assertRaises(ValueError):
            verifier.new_challenge(digest=DIGEST)

    def test_context_and_digest_must_be_32_bytes(self):
        _, _, verifier = fixture()
        for bad in (b"\x00" * 31, b"\x00" * 33, "x" * 32):
            with self.assertRaises(ValueError):
                verifier.new_challenge(context=bad, digest=DIGEST)
            with self.assertRaises(ValueError):
                verifier.new_challenge(context=CONTEXT, digest=bad)

    def test_binding_requires_replay_protection(self):
        verifier = Verifier(KEY)
        with self.assertRaises(ValueError):
            verifier.new_challenge(context=CONTEXT, digest=DIGEST)

    def test_all_none_keeps_old_behavior(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        measurement = verifier.verify(challenge, prover.respond(challenge), 0.0)
        self.assertIsInstance(measurement, Measurement)

    def test_new_challenge_positional_shape_rejected(self):
        _, _, verifier = fixture()
        with self.assertRaises(TypeError):
            verifier.new_challenge(CONTEXT, DIGEST)


class BoundVerifyTest(unittest.TestCase):
    def test_round_trip(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        measurement = verifier.verify(challenge, response, 0.0, opening=OPENING)
        self.assertIsInstance(measurement, Measurement)
        self.assertEqual(measurement.response, response)

    def test_success_consumes_challenge(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        verifier.verify(challenge, response, 0.0, opening=OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, 0.0, opening=OPENING)

    def test_wrong_opening_rejected_and_challenge_stays_pending(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OTHER_OPENING)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, 0.0, opening=OTHER_OPENING)
        good = prover.reveal(challenge, CONTEXT, OPENING)
        verifier.verify(challenge, good, 0.0, opening=OPENING)

    def test_opening_must_be_32_bytes(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        for bad in (b"\x03" * 31, b"\x03" * 33, "x" * 32):
            with self.assertRaises(ValueError):
                verifier.verify(challenge, response, 0.0, opening=bad)

    def test_bound_challenge_requires_opening(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, response, 0.0)

    def test_unbound_challenge_rejects_opening(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify(
                challenge, prover.respond(challenge), 0.0, opening=OPENING
            )

    def test_legacy_mode_rejects_opening(self):
        prover = Prover(KEY)
        verifier = Verifier(KEY)
        challenge = Challenge(1, b"0" * 16)
        with self.assertRaises(ValueError):
            verifier.verify(
                challenge, prover.respond(challenge), 0.0, opening=OPENING
            )

    def test_wrong_response_rejected(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        legacy_response = prover.respond(challenge)
        with self.assertRaises(ValueError):
            verifier.verify(challenge, legacy_response, 0.0, opening=OPENING)

    def test_state_checks_precede_binding_checks(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        verifier.revoke(challenge)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, 0.0, opening=OPENING)

    def test_expired_bound_challenge_rejected(self):
        clock, prover, verifier = fixture(ttl=1.0)
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        clock.now = 2.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, 0.0, opening=OPENING)

    def test_verify_evidence_keeps_old_interface(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge()
        evidence = verifier.verify_evidence(challenge, prover.respond(challenge), 0.0)
        self.assertEqual(evidence.result, "accepted")

    def test_verify_evidence_rejects_bound_challenge(self):
        _, prover, verifier = fixture()
        challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
        response = prover.reveal(challenge, CONTEXT, OPENING)
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, 0.0)


if __name__ == "__main__":
    unittest.main()
