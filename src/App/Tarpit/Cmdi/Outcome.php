<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * What the console answers one command with: an error line, or an "accept" that prints some output.
 * Plain values only, so it can be stored in a source's memo and replayed exactly.
 */
final class Outcome
{
    public const ERROR = 'error';
    public const ACCEPT = 'accept';

    /** Accept sub-kinds. */
    public const FACTS = 'facts';     // a simple command: its table output
    public const ALL = 'all';         // every segment's output, joined (forced by an honoured sleep)
    public const FIRST = 'first';     // only the first segment ran
    public const EMPTY = 'empty';     // ran, printed nothing
    public const RUNTIME = 'runtime'; // the container refused (fork, OOM kill, read-only target)

    /** The only tokens an outcome may carry: the closed set a parser message names. */
    private const TOKEN_EXTRA = ['', 'eof', 'newline', 'redir', 'word'];

    public function __construct(
        public readonly string $kind,
        public readonly string $sub,
        public readonly string $msgId,
        public readonly string $token,
        public readonly ?string $family,
        public readonly string $source,
    ) {
    }

    public function isAccept(): bool
    {
        return $this->kind === self::ACCEPT;
    }

    /** The id the history records: the message for an error, `accept` for an accept. */
    public function historyId(): string
    {
        return $this->isAccept() ? 'accept' : $this->msgId;
    }

    public function withSub(string $sub): self
    {
        return new self($this->kind, $sub, $sub === self::RUNTIME ? $this->msgId : '', $sub === self::RUNTIME ? $this->token : '', $this->family, $this->source);
    }

    /**
     * What a source's memo keeps. Closed-set values only: no attacker text is ever stored, so a stored
     * row stays small and a replay can only print what the current line supplies.
     *
     * @return array{k:string,s:string,m:string,t:string,f:?string}
     */
    public function descriptor(): array
    {
        return ['k' => $this->kind, 's' => $this->sub, 'm' => $this->msgId, 't' => self::closedToken($this->token), 'f' => $this->family];
    }

    public static function closedToken(string $t): string
    {
        return in_array($t, self::TOKEN_EXTRA, true) || in_array($t, AshVocabulary::TOKENS, true) ? $t : '';
    }

    /** @param array<string,mixed> $d */
    public static function fromDescriptor(array $d, string $source = 'memo'): ?self
    {
        $k = $d['k'] ?? null;
        $s = $d['s'] ?? null;
        if (!in_array($k, [self::ERROR, self::ACCEPT], true) || !is_string($s)) {
            return null;
        }
        $m = is_string($d['m'] ?? null) ? $d['m'] : '';
        if ($k === self::ERROR && !in_array($m, AshVocabulary::ids(), true)) {
            return null;
        }
        if (strlen($s) > 16 || strlen($m) > 32 || ($k === self::ACCEPT && !in_array($m, ['', 'fork', 'killed', 'readonly'], true))) {
            return null;
        }
        $f = $d['f'] ?? null;

        return new self($k, $s, $m, self::closedToken(is_string($d['t'] ?? null) ? $d['t'] : ''), is_string($f) && strlen($f) <= 16 ? $f : null, $source);
    }
}
