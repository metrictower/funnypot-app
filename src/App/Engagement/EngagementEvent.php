<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement;

use InvalidArgumentException;

/**
 * One typed engagement event — the only shape the store accepts. Every field is validated here, so
 * a row can never carry an unknown stage/kind, an attacker-chosen lure or artifact key, a negative
 * cost, or an oversized id. Nothing about the request itself (path, body, headers, IP, UA, cookie,
 * prompt) is a field: those stay in the separately retained hit log and are never duplicated here.
 *
 * LLM usage is nullable on purpose: `serverLlmUsageAvailable=false` means unknown and both counts
 * MUST be null; `true` means observed, and `0` then means "observed zero". Recording unknown as 0
 * is rejected so the aggregates can keep unknown distinct from zero all the way through.
 */
final class EngagementEvent
{
    /** Cap for every id/enum column (bytes). */
    public const FIELD_MAX = 64;

    public function __construct(
        public string $stage,
        public string $eventKind,
        public int $bytesOut,
        public int $serverWallMs,
        public ?string $lureId = null,
        public ?string $artifactId = null,
        public bool $serverLlmUsageAvailable = false,
        public ?int $serverLlmCalls = null,
        public ?int $serverLlmTokens = null,
        public int $attackerRequestUnits = 1,
        public int $attackerToolTurns = 0,
    ) {
        if (!Stage::isValid($stage)) {
            throw new InvalidArgumentException('unknown stage');
        }
        if (!EventKind::isValid($eventKind)) {
            throw new InvalidArgumentException('unknown event kind');
        }
        if ($lureId !== null && !LureId::isValid($lureId)) {
            throw new InvalidArgumentException('unknown lure id');
        }
        // An artifact id is only ever an install-local HMAC id (hex, 128–256 bits) minted by the
        // resolver from a verified handle — never a handle, path or attacker string.
        if ($artifactId !== null && (strlen($artifactId) > self::FIELD_MAX || preg_match('/^[a-f0-9]{32,64}$/', $artifactId) !== 1)) {
            throw new InvalidArgumentException('artifact id is not a stored id');
        }
        foreach ([$bytesOut, $serverWallMs, $attackerRequestUnits, $attackerToolTurns] as $n) {
            if ($n < 0) {
                throw new InvalidArgumentException('negative cost');
            }
        }
        if ($serverLlmUsageAvailable) {
            if ($serverLlmCalls === null || $serverLlmTokens === null || $serverLlmCalls < 0 || $serverLlmTokens < 0) {
                throw new InvalidArgumentException('available LLM usage needs non-negative calls and tokens');
            }
        } elseif ($serverLlmCalls !== null || $serverLlmTokens !== null) {
            throw new InvalidArgumentException('unknown LLM usage must stay null, not zero');
        }
    }

    /**
     * A deterministic estimate of the context the SERVED bytes would occupy (bytes / 4). It is an
     * estimate of what was handed to the client, never a measurement of the client's own token use,
     * and every surface that shows it labels it as an estimate.
     */
    public function estimatedContextTokens(): int
    {
        return (int) ceil($this->bytesOut / 4);
    }
}
