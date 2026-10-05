import dataclasses
import math
import unittest

from nearproof import (
    Measurement,
    NoiseDecision,
    Prover,
    RangeDecision,
    ReliabilityDecision,
    Verifier,
    assess_reliability,
)

KEY = b"shared-secret-key"
OTHER_KEY = b"a-different-key!!"


def make_measurement(round_index, distance, *, elapsed=None, nonce=None):
    if nonce is None:
        nonce = bytes([round_index & 0xFF]) * 16
    if elapsed is None:
        elapsed = distance / 100.0
    return Measurement(
        round_index=round_index,
        nonce=nonce,
        response=b"r" * 32,
        elapsed_seconds=elapsed,
        distance_meters=float(distance),
    )


def make_samples(n, k, *, limit_distance=50.0, within_distance=5.0):
    """``n`` samples, the first ``k`` above a 10.0 limit, the rest below."""
    return [
        make_measurement(i + 1, limit_distance if i < k else within_distance)
        for i in range(n)
    ]


class AutoClock:
    """Two readings per round, ``step`` apart, giving deterministic RTTs."""

    def __init__(self, step=1e-7):
        self.readings = 0
        self.step = step

    def __call__(self):
        value = self.readings * self.step
        self.readings += 1
        return value


def make_evidence_list(count, key=KEY):
    prover = Prover(key)
    verifier = Verifier(key, clock=AutoClock(), replay_protection=True)
    records = []
    for _i in range(count):
        challenge = verifier.new_challenge()
        started = verifier.clock()
        records.append(
            verifier.verify_evidence(challenge, prover.respond(challenge), started)
        )
    return verifier, records


class ReliabilityDecisionContractTest(unittest.TestCase):
    def test_is_frozen(self):
        decision = assess_reliability(
            make_samples(5, 0), 10.0, max_exceedance=0.5
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            decision.accepted = False

    def test_fields_in_order(self):
        decision = assess_reliability(
            make_samples(5, 0), 10.0, max_exceedance=0.5
        )
        self.assertIsInstance(decision, ReliabilityDecision)
        self.assertEqual(
            decision,
            ReliabilityDecision(5, 0, 0.4507197283469411, 0.95, True),
        )
        self.assertEqual(decision.sample_count, 5)
        self.assertEqual(decision.exceedance_count, 0)
        self.assertEqual(decision.upper_probability, 0.4507197283469411)
        self.assertEqual(decision.confidence, 0.95)
        self.assertIs(decision.accepted, True)

    def test_equality_covers_every_field(self):
        base = ReliabilityDecision(8, 2, 0.5, 0.95, True)
        variants = (
            ("sample_count", 9),
            ("exceedance_count", 3),
            ("upper_probability", 0.6),
            ("confidence", 0.9),
            ("accepted", False),
        )
        for name, value in variants:
            changed = dataclasses.replace(base, **{name: value})
            self.assertNotEqual(base, changed, name)
        self.assertEqual(base, ReliabilityDecision(8, 2, 0.5, 0.95, True))

    def test_is_distinct_from_other_decisions(self):
        decision = ReliabilityDecision(5, 0, 0.5, 0.95, True)
        self.assertNotEqual(decision, RangeDecision(5, 10.0, True))
        self.assertNotEqual(
            decision, NoiseDecision(5, 5, 10.0, 0.0, 0.95, 10.0, 10.0, True)
        )


class ExceedanceCountTest(unittest.TestCase):
    def test_counts_every_valid_sample_without_outlier_removal(self):
        # A tight cluster plus one far outlier: assess would drop the
        # outlier, assess_reliability must count it.
        samples = [make_measurement(i, 10.0) for i in range(1, 6)]
        samples.append(make_measurement(6, 1000.0))
        decision = assess_reliability(samples, 10.0, max_exceedance=0.9)
        self.assertEqual(decision.sample_count, 6)
        self.assertEqual(decision.exceedance_count, 1)

    def test_strictly_greater_than_limit_counts(self):
        # distance == limit is NOT an exceedance.
        samples = [make_measurement(i, 10.0) for i in range(1, 6)]
        decision = assess_reliability(samples, 10.0, max_exceedance=0.9)
        self.assertEqual(decision.exceedance_count, 0)
        samples[0] = dataclasses.replace(
            samples[0], distance_meters=math.nextafter(10.0, math.inf)
        )
        decision = assess_reliability(samples, 10.0, max_exceedance=0.9)
        self.assertEqual(decision.exceedance_count, 1)

    def test_zero_exceedances_still_has_nonzero_upper(self):
        decision = assess_reliability(
            make_samples(5, 0), 10.0, max_exceedance=0.9
        )
        self.assertEqual(decision.exceedance_count, 0)
        self.assertGreater(decision.upper_probability, 0.0)
        self.assertLess(decision.upper_probability, 1.0)

    def test_all_exceeding_gives_one_and_rejects(self):
        decision = assess_reliability(
            make_samples(5, 5), 10.0, max_exceedance=0.999
        )
        self.assertEqual(decision.sample_count, 5)
        self.assertEqual(decision.exceedance_count, 5)
        self.assertEqual(decision.upper_probability, 1.0)
        self.assertFalse(decision.accepted)

    def test_upper_probability_always_in_unit_interval(self):
        for n, k in ((5, 0), (5, 2), (5, 5), (50, 1), (50, 49), (200, 100)):
            decision = assess_reliability(
                make_samples(n, k), 10.0, max_exceedance=0.5
            )
            self.assertTrue(math.isfinite(decision.upper_probability))
            self.assertGreaterEqual(decision.upper_probability, 0.0)
            self.assertLessEqual(decision.upper_probability, 1.0)

    def test_confidence_echoed_unrounded(self):
        decision = assess_reliability(
            make_samples(5, 0), 10.0, max_exceedance=0.9, confidence=0.123
        )
        self.assertEqual(decision.confidence, 0.123)


class AcceptedRuleTest(unittest.TestCase):
    def test_accepted_only_when_upper_at_most_max_exceedance(self):
        decision = assess_reliability(
            make_samples(5, 0), 10.0, max_exceedance=0.5
        )
        self.assertTrue(decision.accepted)
        below = assess_reliability(
            make_samples(5, 0),
            10.0,
            max_exceedance=math.nextafter(
                decision.upper_probability, 0.0
            ),
        )
        self.assertEqual(below.upper_probability, decision.upper_probability)
        self.assertFalse(below.accepted)

    def test_equality_accepts(self):
        decision = assess_reliability(
            make_samples(5, 0), 10.0, max_exceedance=0.5
        )
        equal = assess_reliability(
            make_samples(5, 0),
            10.0,
            max_exceedance=decision.upper_probability,
        )
        self.assertEqual(equal.upper_probability, decision.upper_probability)
        self.assertTrue(equal.accepted)


class ClopperPearsonReferenceTest(unittest.TestCase):
    """Reference values computed at 80-digit precision from the defining
    equation sum(comb(n,j)*p**j*(1-p)**(n-j), j=0..k) == 1 - confidence."""

    REFERENCES = (
        (0.9, 5, 0, 0.36904265551980675),
        (0.9, 5, 2, 0.7533635467115334),
        (0.9, 5, 4, 0.9791483623609768),
        (0.9, 10, 1, 0.33684772330672474),
        (0.9, 10, 5, 0.7326819013134481),
        (0.9, 20, 3, 0.3041868114074787),
        (0.9, 100, 3, 0.06558575150289181),
        (0.9, 100, 50, 0.5685831744062192),
        (0.9, 1000, 10, 0.015364975604890661),
        (0.9, 10000, 0, 0.00023023200184341366),
        (0.9, 10000, 100, 0.011399410549108473),
        (0.9, 10000, 5000, 0.5064573273912202),
        (0.95, 5, 0, 0.45071972834694113),
        (0.95, 5, 2, 0.8107446225622292),
        (0.95, 5, 4, 0.9897937816869885),
        (0.95, 10, 1, 0.39416330243650477),
        (0.95, 10, 5, 0.7775588989918709),
        (0.95, 20, 3, 0.34366380431428184),
        (0.95, 100, 3, 0.07571079374983006),
        (0.95, 100, 50, 0.5863782853690882),
        (0.95, 1000, 10, 0.016903175120562504),
        (0.95, 10000, 0, 0.000299528359776612),
        (0.95, 10000, 100, 0.011797233971347623),
        (0.95, 10000, 5000, 0.5082734955962606),
        (0.999, 5, 0, 0.748811356849042),
        (0.999, 5, 2, 0.9524481018245423),
        (0.999, 5, 4, 0.9997999199519664),
        (0.999, 10, 1, 0.6237230890888255),
        (0.999, 10, 5, 0.9101868101881457),
        (0.999, 20, 3, 0.5087293739733165),
        (0.999, 100, 3, 0.12422182878533783),
        (0.999, 100, 50, 0.6552019935746822),
        (0.999, 1000, 10, 0.023963812844688626),
        (0.999, 10000, 0, 0.0006905369974100783),
        (0.999, 10000, 100, 0.013468840676193816),
        (0.999, 10000, 5000, 0.515497053886422),
    )

    def test_reference_values_within_1e_minus_10(self):
        for confidence, n, k, expected in self.REFERENCES:
            decision = assess_reliability(
                make_samples(n, k),
                10.0,
                max_exceedance=0.999,
                confidence=confidence,
            )
            self.assertEqual(decision.sample_count, n)
            self.assertEqual(decision.exceedance_count, k)
            self.assertAlmostEqual(
                decision.upper_probability,
                expected,
                delta=1e-10,
                msg=(confidence, n, k),
            )

    def test_defining_equation_holds(self):
        # The returned p must satisfy the Clopper-Pearson equation
        # sum(comb(n,j)*p**j*(1-p)**(n-j), j=0..k) == 1 - confidence.
        for confidence, n, k in (
            (0.95, 5, 0),
            (0.95, 10, 3),
            (0.9, 50, 7),
            (0.999, 200, 40),
        ):
            decision = assess_reliability(
                make_samples(n, k),
                10.0,
                max_exceedance=0.999,
                confidence=confidence,
            )
            p = decision.upper_probability
            total = math.fsum(
                math.comb(n, j) * p**j * (1 - p) ** (n - j)
                for j in range(k + 1)
            )
            self.assertAlmostEqual(
                total, 1.0 - confidence, delta=1e-9, msg=(confidence, n, k)
            )


class OrderAndIterableTest(unittest.TestCase):
    def test_order_independence(self):
        samples = [
            make_measurement(i, d)
            for i, d in enumerate(
                [9.8, 50.0, 10.1, 5.0, 1000.0, 9.9, 10.0], start=1
            )
        ]
        first = assess_reliability(samples, 10.0, max_exceedance=0.9)
        second = assess_reliability(
            list(reversed(samples)), 10.0, max_exceedance=0.9
        )
        self.assertEqual(first, second)
        third = assess_reliability(
            [samples[3], samples[0], samples[6], samples[2],
             samples[5], samples[1], samples[4]],
            10.0,
            max_exceedance=0.9,
        )
        self.assertEqual(first, third)

    def test_one_shot_iterables(self):
        samples = make_samples(6, 1)
        expected = assess_reliability(samples, 10.0, max_exceedance=0.9)
        self.assertEqual(
            assess_reliability(iter(samples), 10.0, max_exceedance=0.9),
            expected,
        )
        self.assertEqual(
            assess_reliability(
                (sample for sample in samples), 10.0, max_exceedance=0.9
            ),
            expected,
        )

    def test_inputs_untouched(self):
        samples = make_samples(6, 1)
        snapshot = list(samples)
        assess_reliability(samples, 10.0, max_exceedance=0.9)
        self.assertEqual(samples, snapshot)


class AssessReliabilityValidationTest(unittest.TestCase):
    def setUp(self):
        self.five = make_samples(5, 0)

    def test_too_few_samples(self):
        with self.assertRaises(ValueError):
            assess_reliability(self.five[:3], 10.0, max_exceedance=0.5)
        with self.assertRaises(ValueError):
            assess_reliability([], 10.0, max_exceedance=0.5, min_samples=1)

    def test_min_samples_boundary(self):
        decision = assess_reliability(
            self.five[:3], 10.0, max_exceedance=0.9, min_samples=3
        )
        self.assertEqual(decision.sample_count, 3)

    def test_non_iterable_samples(self):
        for bad in (123, None, 5.0, object()):
            with self.assertRaises(ValueError, msg=bad):
                assess_reliability(bad, 10.0, max_exceedance=0.5)

    def test_invalid_element_type(self):
        for bad in ("x", 123, None, object(), b"raw-bytes"):
            samples = [bad] + self.five[1:]
            with self.assertRaises(ValueError, msg=bad):
                assess_reliability(samples, 10.0, max_exceedance=0.5)

    def test_mixed_measurement_and_evidence(self):
        _verifier, records = make_evidence_list(5)
        with self.assertRaises(ValueError):
            assess_reliability(
                records[:3] + self.five[:2],
                10.0,
                max_exceedance=0.5,
                key=KEY,
            )

    def test_duplicate_round_and_nonce(self):
        samples = [make_measurement(1, 5.0) for _ in range(5)]
        with self.assertRaises(ValueError):
            assess_reliability(samples, 10.0, max_exceedance=0.5)

    def test_negative_or_non_finite_or_bool_values(self):
        for field, value in (
            ("distance_meters", -0.1),
            ("distance_meters", math.nan),
            ("distance_meters", math.inf),
            ("distance_meters", True),
            ("distance_meters", "5"),
            ("elapsed_seconds", -1.0),
            ("elapsed_seconds", math.inf),
            ("elapsed_seconds", False),
        ):
            samples = make_samples(5, 0)
            samples[0] = dataclasses.replace(samples[0], **{field: value})
            with self.assertRaises(ValueError, msg=(field, value)):
                assess_reliability(samples, 10.0, max_exceedance=0.5)

    def test_limit_validation_matches_assess(self):
        for bad in (True, False, -0.1, math.nan, math.inf, "10", None):
            with self.assertRaises(ValueError, msg=bad):
                assess_reliability(self.five, bad, max_exceedance=0.5)

    def test_max_exceedance_validation(self):
        for bad in (
            0,
            1,
            -0.1,
            1.1,
            True,
            False,
            math.nan,
            math.inf,
            -math.inf,
            0.0,
            1.0,
            "0.1",
            None,
        ):
            with self.assertRaises(ValueError, msg=bad):
                assess_reliability(self.five, 10.0, max_exceedance=bad)

    def test_confidence_validation(self):
        for bad in (
            0,
            1,
            -0.1,
            1.1,
            True,
            False,
            math.nan,
            math.inf,
            -math.inf,
            0.0,
            1.0,
            "0.95",
            None,
        ):
            with self.assertRaises(ValueError, msg=bad):
                assess_reliability(
                    self.five, 10.0, max_exceedance=0.5, confidence=bad
                )

    def test_min_samples_validation_matches_assess(self):
        for bad in (0, -1, True, False, 1.0, "5", None):
            with self.assertRaises(ValueError, msg=bad):
                assess_reliability(
                    self.five, 10.0, max_exceedance=0.5, min_samples=bad
                )


class AssessReliabilityEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.verifier, self.records = make_evidence_list(6)
        self.blobs = [record.to_bytes() for record in self.records]

    def test_evidence_instances_bytes_and_mixed_agree(self):
        # The deterministic clock prints distances of ~15 m, so a 100 m
        # limit sees zero exceedances.
        objects = assess_reliability(
            self.records, 100.0, max_exceedance=0.5, key=KEY
        )
        as_bytes = assess_reliability(
            self.blobs, 100.0, max_exceedance=0.5, key=KEY
        )
        mixed = [
            self.records[0],
            self.blobs[1],
            self.records[2],
            self.blobs[3],
            self.records[4],
            self.blobs[5],
        ]
        mixed_decision = assess_reliability(
            mixed, 100.0, max_exceedance=0.5, key=KEY
        )
        self.assertIsInstance(objects, ReliabilityDecision)
        self.assertEqual(objects, as_bytes)
        self.assertEqual(objects, mixed_decision)
        self.assertEqual(objects.sample_count, 6)
        self.assertEqual(objects.exceedance_count, 0)

    def test_missing_key_rejected(self):
        with self.assertRaises(ValueError):
            assess_reliability(self.records, 10.0, max_exceedance=0.5)
        with self.assertRaises(ValueError):
            assess_reliability(
                self.blobs, 10.0, max_exceedance=0.5, key=None
            )

    def test_empty_key_rejected(self):
        for bad in (b"", "", bytearray()):
            with self.assertRaises(ValueError):
                assess_reliability(
                    self.records, 10.0, max_exceedance=0.5, key=bad
                )

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            assess_reliability(
                self.records, 10.0, max_exceedance=0.5, key=OTHER_KEY
            )

    def test_tampered_or_malformed_bytes_rejected(self):
        tampered = bytearray(self.blobs[0])
        tampered[20] ^= 0xFF
        with self.assertRaises(ValueError):
            assess_reliability(
                self.blobs[:5] + [bytes(tampered)],
                10.0,
                max_exceedance=0.5,
                key=KEY,
            )
        with self.assertRaises(ValueError):
            assess_reliability(
                self.blobs[:5] + [b"not json"],
                10.0,
                max_exceedance=0.5,
                key=KEY,
            )

    def test_duplicate_evidence_pair_rejected(self):
        with self.assertRaises(ValueError):
            assess_reliability(
                [self.records[0]] * 5, 10.0, max_exceedance=0.5, key=KEY
            )

    def test_measurement_input_ignores_key(self):
        samples = make_samples(5, 0)
        expected = assess_reliability(samples, 10.0, max_exceedance=0.5)
        for key in (None, KEY, OTHER_KEY, b""):
            self.assertEqual(
                assess_reliability(
                    samples, 10.0, max_exceedance=0.5, key=key
                ),
                expected,
            )

    def test_order_independence_with_evidence(self):
        first = assess_reliability(
            self.records, 10.0, max_exceedance=0.5, key=KEY
        )
        second = assess_reliability(
            list(reversed(self.records)), 10.0, max_exceedance=0.5, key=KEY
        )
        self.assertEqual(first, second)

    def test_verifier_state_untouched(self):
        before = self.verifier.round_count
        assess_reliability(self.records, 10.0, max_exceedance=0.5, key=KEY)
        assess_reliability(self.blobs, 10.0, max_exceedance=0.5, key=KEY)
        self.assertEqual(self.verifier.round_count, before)
        self.assertEqual(len(self.verifier._challenges), before)


if __name__ == "__main__":
    unittest.main()
