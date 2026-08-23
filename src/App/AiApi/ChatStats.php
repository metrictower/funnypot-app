<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Closure;

/**
 * Fabricates the believable per-response metadata (ids, timestamps, timing/eval counters) that a real
 * ollama / OpenAI / Anthropic chat completion carries alongside its text. An attacker probing the fake
 * endpoint for consistency — same id shape every time, timestamps that track wall-clock, durations
 * that scale with how much text came back — sees nothing that reads as synthetic. $now and $rand are
 * injected so tests assert deterministic output instead of wall-clock time / real randomness.
 */
final class ChatStats
{
    private int $now;

    /** @var Closure(int,int):int */
    private Closure $rand;

    /** @param Closure(int,int):int|null $rand min/max inclusive, mirrors random_int()'s signature */
    public function __construct(?int $now = null, ?Closure $rand = null)
    {
        $this->now = $now ?? time();
        $this->rand = $rand ?? static fn (int $min, int $max): int => random_int($min, $max);
    }

    /** Ollama's created_at shape: RFC3339 UTC with 6-digit fractional seconds, e.g.
     *  "2026-08-01T12:00:00.123456Z". */
    public function ollamaCreatedAt(): string
    {
        $micros = str_pad((string) ($this->rand)(0, 999999), 6, '0', STR_PAD_LEFT);

        return gmdate('Y-m-d\TH:i:s', $this->now) . '.' . $micros . 'Z';
    }

    public function openAiId(): string
    {
        return 'chatcmpl-' . $this->randomAlnum(24);
    }

    public function openAiCreated(): int
    {
        return $this->now;
    }

    public function systemFingerprint(): string
    {
        return 'fp_' . $this->randomHex(8);
    }

    public function anthropicId(): string
    {
        return 'msg_' . $this->randomAlnum(24);
    }

    /** Plain RFC3339 UTC, no fractional seconds — for dialects that don't follow ollama's shape. */
    public function nowRfc3339(): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $this->now);
    }

    /**
     * Ollama-shaped timing counters, in nanoseconds, all scaling with how many pieces (tokens/chunks)
     * were "generated" — a fixed value regardless of response size is itself a tell. Keyed to match
     * ollama's own response field names, so a dialect can merge this straight into the response body.
     *
     * @return array{total_duration:int,load_duration:int,prompt_eval_duration:int,eval_duration:int}
     */
    public function durationsNs(int $pieces): array
    {
        $pieces = max(1, $pieces);
        $load = 250_000_000 + ($this->rand)(0, 50_000_000);
        $promptEval = 15_000_000 + ($this->rand)(0, 10_000_000);
        $eval = $pieces * (20_000_000 + ($this->rand)(0, 15_000_000));
        $total = $load + $promptEval + $eval + ($this->rand)(0, 5_000_000);

        return [
            'total_duration' => $total,
            'load_duration' => $load,
            'prompt_eval_duration' => $promptEval,
            'eval_duration' => $eval,
        ];
    }

    /** Token-ish count for the "generated" reply, scaling with piece count. */
    public function evalCount(int $pieces): int
    {
        return max(1, $pieces) + ($this->rand)(0, 3);
    }

    /** A short list of fake context token ids, as ollama's /api/generate echoes back so a client can
     *  carry conversation state into its next request.
     *
     * @return int[]
     */
    public function contextInts(): array
    {
        $count = 5 + ($this->rand)(0, 5);
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = ($this->rand)(1, 50000);
        }

        return $out;
    }

    private function randomHex(int $chars): string
    {
        $out = '';
        for ($i = 0; $i < $chars; $i++) {
            $out .= dechex(($this->rand)(0, 15));
        }

        return $out;
    }

    private function randomAlnum(int $chars): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $out = '';
        for ($i = 0; $i < $chars; $i++) {
            $out .= $alphabet[($this->rand)(0, 61)];
        }

        return $out;
    }
}
