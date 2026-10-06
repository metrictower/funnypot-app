<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * The production assigner (FP-0311 §3.3). Weighted mapping with NO modulo bias:
 *
 *   digest_0 = HMAC-SHA256(experiment_key, "engagement-cohort/v1\0" . id . "\0" . revision . "\0" . subject_key)
 *
 * Each consecutive 4-byte digest word is read as an unsigned network-order 32-bit integer x. For total
 * weight t only x < floor(2^32 / t) * t is accepted (the biased tail above the largest multiple of t is
 * rejected); the accepted x % t selects the variant against ordered cumulative weights. If all eight
 * words of a digest reject, a fresh digest is derived by appending NUL + a one-byte counter 1..4 and the
 * scan repeats; exhausting all five digests returns unenrolled baseline. A 64-bit platform is required
 * for the exact unsigned range — otherwise, unenrolled.
 *
 * Deterministic for (experiment_key, id, revision, subject_key); varies across keys and revisions by
 * construction. The HMAC is injectable so tests can force the rejection/re-hash path with crafted words
 * instead of fishing for inputs that happen to land in the biased tail.
 */
final class HmacCohortAssigner implements CohortAssigner
{
    private const SUBJECT_DOMAIN = "engagement-subject/v1\0";
    private const COHORT_DOMAIN = "engagement-cohort/v1\0";
    private const WORDS_PER_DIGEST = 8;   // SHA-256 = 32 bytes = eight 4-byte words
    private const MAX_COUNTER = 4;         // digest_0 plus counters 1..4
    private const RANGE = 4294967296;      // 2^32

    /** @var callable(string,string):string returns the 32-byte raw HMAC-SHA256 of (key, message) */
    private $hmac;

    public function __construct(?callable $hmac = null)
    {
        $this->hmac = $hmac ?? static fn (string $key, string $message): string =>
            hash_hmac('sha256', $message, $key, true);
    }

    /**
     * Derive the private subject key from the scoped experiment key and the authenticated random value
     * of a verified FP-0308 episode handle (§3.2). Pure; the value is never persisted or emitted.
     */
    public static function subjectKey(string $experimentKey, string $authenticatedRandomValue): string
    {
        return hash_hmac('sha256', self::SUBJECT_DOMAIN . $authenticatedRandomValue, $experimentKey, true);
    }

    public function assign(ExperimentDefinition $definition, string $experimentKey, string $subjectKey): ExperimentDecision
    {
        if (PHP_INT_SIZE !== 8) {
            return ExperimentDecision::baseline(BaselineReason::PLATFORM_UNSUPPORTED);
        }
        // The counter re-hash appends NUL + a 1-byte counter to the message; the collision-free framing
        // relies on a fixed-length subject key as the trailing field. The only producer (subjectKey())
        // returns a 32-byte raw HMAC — reject anything else so a future non-conforming caller can't
        // introduce a cross-subject ambiguity.
        if (strlen($subjectKey) !== 32 || strlen($experimentKey) < 32) {
            return ExperimentDecision::baseline(BaselineReason::ASSIGNER_FAULT);
        }
        $t = $definition->totalWeight();
        if ($t < 1) {
            return ExperimentDecision::baseline(BaselineReason::ASSIGNER_FAULT);
        }
        $limit = intdiv(self::RANGE, $t) * $t; // largest multiple of t <= 2^32

        $base = self::COHORT_DOMAIN . $definition->experimentId . "\0" . $definition->revision . "\0" . $subjectKey;

        for ($counter = 0; $counter <= self::MAX_COUNTER; $counter++) {
            $message = $counter === 0 ? $base : $base . "\0" . chr($counter);
            $digest = ($this->hmac)($experimentKey, $message);
            if (!is_string($digest) || strlen($digest) < self::WORDS_PER_DIGEST * 4) {
                return ExperimentDecision::baseline(BaselineReason::ASSIGNER_FAULT);
            }
            for ($w = 0; $w < self::WORDS_PER_DIGEST; $w++) {
                /** @var array{1:int} $u */
                $u = unpack('N', substr($digest, $w * 4, 4));
                $x = $u[1];
                if ($x >= $limit) {
                    continue; // biased tail — reject and try the next word
                }

                return ExperimentDecision::enrolled($definition, $this->pick($definition, $x % $t));
            }
        }

        return ExperimentDecision::baseline(BaselineReason::SAMPLING_EXHAUSTED);
    }

    private function pick(ExperimentDefinition $definition, int $point): ExperimentVariant
    {
        $cumulative = 0;
        foreach ($definition->variants as $variant) {
            $cumulative += $variant->weight;
            if ($point < $cumulative) {
                return $variant;
            }
        }

        // Unreachable while $point < totalWeight(); return the last arm as a defensive fallback.
        return $definition->variants[count($definition->variants) - 1];
    }
}
