import dataclasses
import hashlib
import hmac
import json
import math
import unittest

from nearproof import (
    BoundEvidence,
    Challenge,
    ChallengeStateError,
    Evidence,
    Measurement,
    Prover,
    Verifier,
    _bound_evidence_mac,
    _bound_evidence_payload,
    _evidence_mac,
    _evidence_payload,
    audit,
    audit_bound,
    context_digest,
    keyed_response,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"

CONTEXT = b"\x11" * 32
OPENING = b"\x22" * 32
DIGEST = hashlib.sha256(b"NPC1" + CONTEXT + OPENING).digest()


class SteppedClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def issue(clock=None, **verifier_kwargs):
    clock = clock or SteppedClock()
    verifier_kwargs.setdefault("replay_protection", True)
    verifier_kwargs.setdefault("clock", clock)
    verifier = Verifier(KEY, **verifier_kwargs)
    prover = Prover(KEY)
    challenge = verifier.new_challenge(context=CONTEXT, digest=DIGEST)
    started = clock.now
    response = prover.reveal(challenge, CONTEXT, OPENING)
    return verifier, prover, challenge, response, started, clock


def make_bound(clock=None, **verifier_kwargs):
    verifier, prover, challenge, response, started, clock = issue(
        clock, **verifier_kwargs
    )
    clock.now += 1e-6
    bound = verifier.verify_bound(
        challenge, response, started, opening=OPENING
    )
    return bound


def make_bound_pair(clock=None, **verifier_kwargs):
    verifier, prover, challenge, response, started, clock = issue(
        clock, **verifier_kwargs
    )
    clock.now += 1e-6
    bound = verifier.verify_bound(
        challenge, response, started, opening=OPENING
    )
    return verifier, prover, bound


def bound_payload(bound):
    return _bound_evidence_payload(bound)


def bound_mac(bound, key):
    return _bound_evidence_mac(key, bound_payload(bound))


class BoundEvidenceRecordTest(unittest.TestCase):
    def test_fields_of_accepted_bound_round(self):
        bound = make_bound()
        self.assertEqual(bound.version, 1)
        self.assertIsInstance(bound.evidence, Evidence)
        evidence = bound.evidence
        self.assertEqual(evidence.version, 1)
        self.assertEqual(evidence.result, "accepted")
        self.assertEqual(bound.context, CONTEXT)
        self.assertEqual(bound.opening, OPENING)
        self.assertEqual(bound.digest, DIGEST)
        self.assertEqual(
            bound.digest, context_digest(bound.context, bound.opening)
        )
        self.assertEqual(len(bound.mac), 32)
        for name in ("context", "digest", "opening", "mac"):
            self.assertIsInstance(getattr(bound, name), bytes)
            self.assertEqual(len(getattr(bound, name)), 32)

    def test_is_frozen(self):
        bound = make_bound()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            bound.digest = b"\x00" * 32
        with self.assertRaises(dataclasses.FrozenInstanceError):
            bound.evidence = bound.evidence

    def test_nested_evidence_is_the_bound_round(self):
        bound = make_bound()
        evidence = bound.evidence
        self.assertEqual(
            evidence.response,
            hmac.new(
                KEY,
                b"NPR1"
                + DIGEST
                + evidence.round_index.to_bytes(8, "big")
                + evidence.nonce,
                hashlib.sha256,
            ).digest(),
        )
        self.assertEqual(evidence.elapsed, evidence.end - evidence.start)
        self.assertEqual(
            evidence.distance, evidence.elapsed * evidence.speed / 2.0
        )

    def test_outer_mac_definition(self):
        bound = make_bound()
        self.assertEqual(bound.mac, bound_mac(bound, KEY))
        self.assertNotEqual(bound.mac, bound_mac(bound, OTHER_KEY))
        # The NPBE1 domain prefix participates in the MAC.
        payload = json.dumps(
            bound_payload(bound), separators=(",", ":"), allow_nan=False
        ).encode()
        self.assertEqual(
            bound.mac,
            hmac.new(KEY, b"NPBE1" + payload, hashlib.sha256).digest(),
        )
        self.assertNotEqual(
            bound.mac,
            hmac.new(KEY, payload, hashlib.sha256).digest(),
        )


class BoundEvidenceConstructionTest(unittest.TestCase):
    def _evidence(self):
        bound = make_bound()
        return bound.evidence

    def test_valid_construction(self):
        bound = BoundEvidence(
            1, self._evidence(), CONTEXT, DIGEST, OPENING, b"\x00" * 32
        )
        self.assertEqual(bound.version, 1)

    def test_version_must_be_one(self):
        evidence = self._evidence()
        for bad in (0, 2, "1", 1.0, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidence(
                    bad, evidence, CONTEXT, DIGEST, OPENING, b"\x00" * 32
                )

    def test_evidence_must_be_evidence(self):
        for bad in (None, "evidence", b"x", object()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidence(
                    1, bad, CONTEXT, DIGEST, OPENING, b"\x00" * 32
                )

    def test_nested_evidence_contract_is_checked(self):
        evidence = self._evidence()
        for bad in (
            dataclasses.replace(evidence, version=2),
            dataclasses.replace(evidence, result="rejected"),
            dataclasses.replace(evidence, elapsed=math.inf),
        ):
            with self.assertRaises(ValueError):
                BoundEvidence(
                    1, bad, CONTEXT, DIGEST, OPENING, b"\x00" * 32
                )

    def test_byte_fields_must_be_exactly_32_bytes(self):
        evidence = self._evidence()
        for name, value in (
            ("context", CONTEXT),
            ("digest", DIGEST),
            ("opening", OPENING),
            ("mac", b"\x00" * 32),
        ):
            for bad in (b"", value[:-1], value + b"\x00", value.hex(), None):
                fields = {
                    "version": 1,
                    "evidence": evidence,
                    "context": CONTEXT,
                    "digest": DIGEST,
                    "opening": OPENING,
                    "mac": b"\x00" * 32,
                }
                fields[name] = bad
                with self.assertRaises(ValueError, msg=f"{name}={bad!r}"):
                    BoundEvidence(**fields)

    def test_digest_must_commit_to_context_and_opening(self):
        evidence = self._evidence()
        other_opening = b"\x33" * 32
        other_digest = context_digest(CONTEXT, other_opening)
        with self.assertRaises(ValueError):
            BoundEvidence(
                1, evidence, CONTEXT, DIGEST, other_opening, b"\x00" * 32
            )
        with self.assertRaises(ValueError):
            BoundEvidence(
                1, evidence, CONTEXT, other_digest, OPENING, b"\x00" * 32
            )


class BoundEvidenceSerializationTest(unittest.TestCase):
    def test_round_trip(self):
        bound = make_bound()
        clone = BoundEvidence.from_bytes(bound.to_bytes())
        self.assertEqual(clone, bound)
        self.assertIsInstance(clone.evidence, Evidence)

    def test_canonical_encoding(self):
        bound = make_bound()
        blob = bound.to_bytes()
        self.assertIsInstance(blob, bytes)
        self.assertNotIn(b" ", blob)
        obj = json.loads(blob)
        self.assertEqual(
            list(obj),
            ["version", "evidence", "context", "digest", "opening", "mac"],
        )
        self.assertEqual(
            list(obj["evidence"]),
            [
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
            ],
        )
        self.assertEqual(obj["version"], 1)
        self.assertEqual(obj["context"], CONTEXT.hex())
        self.assertEqual(obj["digest"], DIGEST.hex())
        self.assertEqual(obj["opening"], OPENING.hex())
        self.assertEqual(obj["mac"], bound.mac.hex())

    def test_encoding_is_a_single_unframed_json_document(self):
        blob = make_bound().to_bytes()
        obj, end = json.JSONDecoder().raw_decode(blob.decode())
        self.assertEqual(end, len(blob))
        self.assertIsInstance(obj, dict)

    def test_from_bytes_rejects_non_bytes(self):
        for bad in ("{}", b"{}".decode(), None, 42, bytearray(b"{}")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidence.from_bytes(bad)

    def test_from_bytes_rejects_non_object(self):
        for bad in (b"[]", b"[1,2,3]", b'"s"', b"1", b"not json", b"", b"{}"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BoundEvidence.from_bytes(bad)

    def _blob(self, bound=None, **overrides):
        bound = bound or make_bound()
        obj = json.loads(bound.to_bytes())
        obj.update(overrides)
        return json.dumps(obj, separators=(",", ":")).encode()

    def test_from_bytes_rejects_missing_key(self):
        obj = json.loads(self._blob())
        del obj["opening"]
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_extra_key(self):
        obj = json.loads(self._blob())
        obj["extra"] = 1
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_duplicate_key(self):
        blob = self._blob()
        duplicated = blob.replace(
            b'"version":1,', b'"version":1,"version":1,', 1
        )
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(duplicated)

    def test_from_bytes_rejects_out_of_order_keys(self):
        obj = json.loads(self._blob())
        reordered = {key: obj[key] for key in reversed(list(obj))}
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(reordered, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_nested_evidence_disorder(self):
        obj = json.loads(self._blob())
        nested = obj["evidence"]
        obj["evidence"] = {key: nested[key] for key in reversed(list(nested))}
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_nested_evidence_violations(self):
        # version of the nested evidence
        obj = json.loads(self._blob())
        obj["evidence"]["version"] = 2
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )
        # result of the nested evidence
        obj = json.loads(self._blob())
        obj["evidence"]["result"] = "rejected"
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )
        # non-finite nested number
        obj = json.loads(self._blob())
        obj["evidence"]["elapsed"] = float("nan")
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_rejects_bad_byte_field_encoding(self):
        for field in ("context", "digest", "opening", "mac"):
            for bad in ("00" * 31, "00" * 33, "GG" * 32, "AB" * 32, 123, None):
                with self.assertRaises(ValueError, msg=f"{field}={bad!r}"):
                    BoundEvidence.from_bytes(self._blob(**{field: bad}))

    def test_from_bytes_rejects_commitment_mismatch(self):
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(self._blob(opening="33" * 32))
        obj = json.loads(self._blob())
        obj["digest"] = "33" * 32
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(
                json.dumps(obj, separators=(",", ":")).encode()
            )

    def test_from_bytes_does_not_verify_macs(self):
        # A structurally valid record with dummy MACs parses; audit_bound is
        # what rejects it.
        obj = json.loads(self._blob())
        obj["mac"] = "00" * 32
        obj["evidence"]["mac"] = "00" * 32
        record = BoundEvidence.from_bytes(
            json.dumps(obj, separators=(",", ":")).encode()
        )
        self.assertEqual(record.mac, b"\x00" * 32)
        self.assertEqual(record.evidence.mac, b"\x00" * 32)

    def test_from_bytes_rejects_whitespace_and_pretty_print(self):
        blob = self._blob()
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(blob.replace(b",", b", ", 1))
        for padded in (b" " + blob, blob + b"\n", b"\t" + blob + b" "):
            with self.assertRaises(ValueError, msg=repr(padded[:8])):
                BoundEvidence.from_bytes(padded)
        obj = json.loads(blob)
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(json.dumps(obj, indent=2).encode())

    def test_plain_evidence_blob_does_not_decode_as_bound(self):
        bound = make_bound()
        with self.assertRaises(ValueError):
            BoundEvidence.from_bytes(bound.evidence.to_bytes())


class VerifyBoundTest(unittest.TestCase):
    def test_success_returns_bound_evidence(self):
        verifier, prover, challenge, response, started, clock = issue()
        clock.now += 1e-6
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        self.assertIsInstance(bound, BoundEvidence)
        self.assertEqual(bound.context, CONTEXT)
        self.assertEqual(bound.digest, DIGEST)
        self.assertEqual(bound.opening, OPENING)
        audit_bound(bound, KEY)

    def test_success_consumes_challenge(self):
        verifier, prover, challenge, response, started, _clock = issue()
        verifier.verify_bound(challenge, response, started, opening=OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, started, opening=OPENING
            )
        with self.assertRaises(ChallengeStateError):
            verifier.verify(challenge, response, started, opening=OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_evidence(challenge, response, started)

    def test_verify_then_verify_bound_is_rejected(self):
        verifier, prover, challenge, response, started, _clock = issue()
        verifier.verify(challenge, response, started, opening=OPENING)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, started, opening=OPENING
            )

    def test_verify_evidence_cannot_answer_bound_challenge(self):
        verifier, _prover, challenge, response, started, _clock = issue()
        # verify_evidence speaks the legacy protocol and cannot satisfy a bound
        # challenge, so the challenge stays pending and verify_bound works.
        with self.assertRaises(ValueError):
            verifier.verify_evidence(challenge, response, started)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_bad_response_does_not_consume(self):
        verifier, _prover, challenge, _response, started, _clock = issue()
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, started, opening=OPENING
            )
        response = Prover(KEY).reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        self.assertIsInstance(bound, BoundEvidence)

    def test_unknown_challenge_rejected(self):
        verifier, _prover, _challenge, _response, started, _clock = issue()
        foreign = Challenge(9, b"x" * 16)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                foreign, b"\x00" * 32, started, opening=OPENING
            )

    def test_revoked_challenge_rejected(self):
        verifier, _prover, challenge, response, started, _clock = issue()
        verifier.revoke(challenge)
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, started, opening=OPENING
            )

    def test_expired_challenge_rejected(self):
        clock = SteppedClock()
        verifier, _prover, challenge, response, started, _ = issue(
            clock, challenge_ttl_seconds=1.0
        )
        clock.now = 2.0
        with self.assertRaises(ChallengeStateError):
            verifier.verify_bound(
                challenge, response, started, opening=OPENING
            )

    def test_non_challenge_rejected(self):
        verifier, _prover, _challenge, _response, started, _clock = issue()
        with self.assertRaises(TypeError):
            verifier.verify_bound(
                object(), b"\x00" * 32, started, opening=OPENING
            )

    def test_opening_is_keyword_only(self):
        verifier, _prover, challenge, response, started, _clock = issue()
        with self.assertRaises(TypeError):
            verifier.verify_bound(challenge, response, started, OPENING)

    def test_missing_opening_raises_type_error(self):
        verifier, _prover, challenge, response, started, _clock = issue()
        with self.assertRaises(TypeError):
            verifier.verify_bound(challenge, response, started)

    def test_opening_wrong_type_raises_type_error_without_consuming(self):
        verifier, prover, challenge, _response, started, _clock = issue()
        for bad in ("x" * 32, bytearray(32), 32, ["x"] * 32):
            with self.assertRaises(TypeError, msg=repr(bad)):
                verifier.verify_bound(
                    challenge, b"\x00" * 32, started, opening=bad
                )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_opening_none_rejected_on_bound_challenge_without_consuming(self):
        # keyword-only opening=None must not silently take the legacy path.
        verifier, prover, challenge, _response, started, _clock = issue()
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, started, opening=None
            )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_opening_none_rejected_on_unbound_challenge(self):
        verifier = Verifier(KEY, replay_protection=True)
        prover = Prover(KEY)
        challenge = verifier.new_challenge()
        response = prover.respond(challenge)
        with self.assertRaises(ValueError):
            verifier.verify_bound(challenge, response, 0.0, opening=None)
        # Still pending: the legacy verify succeeds afterwards.
        measurement = verifier.verify(challenge, response, 0.0)
        self.assertIsInstance(measurement, Measurement)

    def test_unbound_challenge_rejects_an_opening(self):
        verifier = Verifier(KEY, replay_protection=True)
        prover = Prover(KEY)
        challenge = verifier.new_challenge()
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, 0.0, opening=OPENING
            )

    def test_opening_wrong_length_raises_value_error_without_consuming(self):
        verifier, prover, challenge, _response, started, _clock = issue()
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, started, opening=OPENING[:-1]
            )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_opening_commitment_mismatch_without_consuming(self):
        verifier, prover, challenge, _response, started, _clock = issue()
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, started, opening=b"\x33" * 32
            )
        response = prover.reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_legacy_mode_cannot_produce_bound_evidence(self):
        verifier = Verifier(KEY, replay_protection=False)
        challenge = Challenge(1, b"n" * 16)
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, 0.0, opening=OPENING
            )

    def test_non_finite_started_at_rejected_without_consuming(self):
        clock = SteppedClock()
        verifier, prover, challenge, response, _started, _ = issue(clock)
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, response, math.nan, opening=OPENING
            )
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, response, math.inf, opening=OPENING
            )
        clock.now = 1.0
        bound = verifier.verify_bound(
            challenge, response, 0.0, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_non_finite_clock_reading_rejected_without_consuming(self):
        clock = SteppedClock()
        verifier, prover, challenge, response, started, _ = issue(clock)
        clock.now = math.nan
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, response, started, opening=OPENING
            )
        clock.now = 1.0
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)

    def test_ttl_retry_must_stay_before_deadline(self):
        clock = SteppedClock()
        verifier, _prover, challenge, _response, started, _ = issue(
            clock, challenge_ttl_seconds=1.0
        )
        clock.now = 0.5
        with self.assertRaises(ValueError):
            verifier.verify_bound(
                challenge, b"\x00" * 32, started, opening=OPENING
            )
        response = Prover(KEY).reveal(challenge, CONTEXT, OPENING)
        bound = verifier.verify_bound(
            challenge, response, started, opening=OPENING
        )
        audit_bound(bound, KEY)


class AuditBoundTest(unittest.TestCase):
    def test_audit_returns_measurement(self):
        bound = make_bound()
        measurement = audit_bound(bound, KEY)
        self.assertIsInstance(measurement, Measurement)
        evidence = bound.evidence
        self.assertEqual(measurement.round_index, evidence.round_index)
        self.assertEqual(measurement.nonce, evidence.nonce)
        self.assertEqual(measurement.response, evidence.response)
        self.assertEqual(measurement.elapsed_seconds, evidence.elapsed)
        self.assertEqual(measurement.distance_meters, evidence.distance)

    def test_audit_accepts_bytes(self):
        bound = make_bound()
        self.assertEqual(
            audit_bound(bound.to_bytes(), KEY), audit_bound(bound, KEY)
        )

    def test_nested_evidence_is_not_a_legacy_evidence(self):
        # The nested record carries the NPR1 bound response, so a plain audit
        # (which expects the legacy nonce-only response HMAC) rejects it even
        # though the nested MAC and ranging are valid. audit_bound is the
        # checker that speaks the bound protocol.
        bound = make_bound()
        with self.assertRaises(ValueError):
            audit(bound.evidence, KEY)
        with self.assertRaises(ValueError):
            audit(bound.evidence.to_bytes(), KEY)

    def test_audit_rejects_empty_key(self):
        bound = make_bound()
        for bad in (b"", "", bytearray()):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_bound(bound, bad)

    def test_audit_rejects_bad_type(self):
        for bad in ("x", 123, None, {"version": 1}, b"not json"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                audit_bound(bad, KEY)

    def test_audit_rejects_wrong_key(self):
        bound = make_bound()
        with self.assertRaises(ValueError):
            audit_bound(bound, OTHER_KEY)

    def _reencode(self, bound, mutate):
        obj = json.loads(bound.to_bytes())
        mutate(obj)
        return json.dumps(obj, separators=(",", ":")).encode()

    def test_audit_rejects_tampered_context(self):
        bound = make_bound()
        blob = self._reencode(bound, lambda o: o.__setitem__("context", "99" * 32))
        with self.assertRaises(ValueError):
            audit_bound(blob, KEY)

    def test_audit_rejects_tampered_opening(self):
        bound = make_bound()
        blob = self._reencode(bound, lambda o: o.__setitem__("opening", "99" * 32))
        with self.assertRaises(ValueError):
            audit_bound(blob, KEY)

    def test_audit_rejects_tampered_digest(self):
        bound = make_bound()
        blob = self._reencode(bound, lambda o: o.__setitem__("digest", "99" * 32))
        with self.assertRaises(ValueError):
            audit_bound(blob, KEY)

    def test_audit_rejects_tampered_outer_mac(self):
        bound = make_bound()
        blob = self._reencode(bound, lambda o: o.__setitem__("mac", "00" * 32))
        with self.assertRaises(ValueError):
            audit_bound(blob, KEY)

    def test_audit_rejects_tampered_nested_mac(self):
        bound = make_bound()

        def mutate(obj):
            obj["evidence"]["mac"] = "00" * 32

        with self.assertRaises(ValueError):
            audit_bound(self._reencode(bound, mutate), KEY)

    def test_audit_rejects_tampered_nested_field(self):
        bound = make_bound()

        def mutate(obj):
            obj["evidence"]["round_index"] += 1

        with self.assertRaises(ValueError):
            audit_bound(self._reencode(bound, mutate), KEY)

    def _re_mac(self, bound, evidence):
        """Build a bound record with valid nested+outer MACs for ``evidence``."""
        evidence = dataclasses.replace(
            evidence, mac=_evidence_mac(KEY, _evidence_payload(evidence))
        )
        rebound = dataclasses.replace(bound, evidence=evidence, mac=b"\x00" * 32)
        return dataclasses.replace(
            rebound, mac=bound_mac(rebound, KEY)
        )

    def test_audit_recomputes_ranging(self):
        bound = make_bound()
        evidence = bound.evidence
        for field in ("elapsed", "distance"):
            forged = dataclasses.replace(
                evidence, **{field: getattr(evidence, field) + 1.0}
            )
            with self.assertRaises(ValueError, msg=field):
                audit_bound(self._re_mac(bound, forged), KEY)

    def test_audit_rejects_legacy_response_even_with_valid_macs(self):
        # With both MACs fixed up, NPC1 intact and ranging consistent, a
        # nonce-only legacy response must still fail the NPR1 check.
        bound = make_bound()
        evidence = dataclasses.replace(
            bound.evidence,
            response=keyed_response(KEY, bound.evidence.nonce),
        )
        forged = self._re_mac(bound, evidence)
        self.assertEqual(
            hmac.compare_digest(forged.mac, bound_mac(forged, KEY)), True
        )
        with self.assertRaises(ValueError):
            audit_bound(forged, KEY)

    def test_audit_rejects_response_for_other_digest(self):
        bound_a = make_bound()
        verifier, prover, bound_b = make_bound_pair()
        # Swap in another bound round's response: NPR1 over bound_a's digest
        # won't match even though both records are individually authentic.
        evidence = dataclasses.replace(
            bound_a.evidence, response=bound_b.evidence.response
        )
        with self.assertRaises(ValueError):
            audit_bound(self._re_mac(bound_a, evidence), KEY)


if __name__ == "__main__":
    unittest.main()
