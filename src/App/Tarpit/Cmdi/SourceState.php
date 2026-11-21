<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/**
 * One source's console history: the shapes it has tried (so a resend replays the same answer), the
 * last few messages (so the console never repeats itself back to back), the syntax features of the
 * last attempt (so the newest "fix" gets blamed), and the extra paths it has used as a console.
 * Immutable; every cap is enforced here.
 */
final class SourceState
{
    public const MEMO_CAP = 64;
    public const RECENT_CAP = 4;
    public const STICKY_CAP = 8;
    public const STICKY_PATH_MAX = 200;

    /** Memo keys carry a prefix: an all-digit shape key would otherwise become an integer array key. */
    private const MEMO_PREFIX = 'm:';

    /**
     * @param array<string,array<string,mixed>> $memo         prefixed shape key => outcome descriptor, oldest first
     * @param list<string>                      $recentMsgIds newest last
     * @param list<string>                      $prevFamilies
     * @param list<string>                      $stickyPaths  oldest first
     */
    public function __construct(
        public readonly array $memo = [],
        public readonly array $recentMsgIds = [],
        public readonly array $prevFamilies = [],
        public readonly bool $lastWasAccept = false,
        public readonly array $stickyPaths = [],
    ) {
    }

    public static function empty(): self
    {
        return new self();
    }

    /** A digest of everything the next pick depends on besides the line itself. */
    public function historyDigest(): string
    {
        $fams = $this->prevFamilies;
        sort($fams);

        return hash('sha256', json_encode([$this->recentMsgIds, $fams, $this->lastWasAccept]) ?: '');
    }

    /** @return array<string,mixed>|null the descriptor this source got for $shapeKey before */
    public function memoFor(string $shapeKey): ?array
    {
        return $this->memo[self::MEMO_PREFIX . $shapeKey] ?? null;
    }

    public function lastMsgId(): ?string
    {
        return $this->recentMsgIds === [] ? null : $this->recentMsgIds[count($this->recentMsgIds) - 1];
    }

    /** The state after the console answered $lex with $o. */
    public function after(LexReport $lex, Outcome $o): self
    {
        if ($o->source === 'simple') {
            return new self($this->memo, $this->recentMsgIds, $this->prevFamilies, false, $this->stickyPaths);
        }
        $memo = $this->memo;
        if ($o->source === 'pick' || $o->source === 'memo') {
            unset($memo[self::MEMO_PREFIX . $lex->shapeKey]);
            $memo[self::MEMO_PREFIX . $lex->shapeKey] = $o->descriptor();
            if (count($memo) > self::MEMO_CAP) {
                $memo = array_slice($memo, -self::MEMO_CAP, null, true);
            }
        }
        $recent = $this->recentMsgIds;
        $recent[] = $o->historyId();
        $recent = array_slice($recent, -self::RECENT_CAP);

        return new self($memo, $recent, $lex->families, $o->isAccept(), $this->stickyPaths);
    }

    public function withSticky(string $path): self
    {
        $p = self::normalisePath($path);
        if ($p === '' || strlen($p) > self::STICKY_PATH_MAX) {
            return $this;
        }
        $paths = array_values(array_filter($this->stickyPaths, static fn (string $s): bool => $s !== $p));
        $paths[] = $p;

        return new self($this->memo, $this->recentMsgIds, $this->prevFamilies, $this->lastWasAccept, array_slice($paths, -self::STICKY_CAP));
    }

    public function isSticky(string $path): bool
    {
        return in_array(self::normalisePath($path), $this->stickyPaths, true);
    }

    /** Lower-cased, dot segments resolved, no trailing slash: `/Up/./a/../Shell.PHP/` → `/up/shell.php`. */
    public static function normalisePath(string $path): string
    {
        $parts = [];
        foreach (explode('/', strtolower($path)) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($parts);
                continue;
            }
            $parts[] = $seg;
        }

        return '/' . implode('/', $parts);
    }

    public function toJson(): string
    {
        return (string) json_encode([
            'memo' => $this->memo,
            'recent' => $this->recentMsgIds,
            'prev' => $this->prevFamilies,
            'acc' => $this->lastWasAccept,
            'sticky' => $this->stickyPaths,
        ], JSON_UNESCAPED_SLASHES);
    }

    /** Anything malformed yields an empty state; a stored row can never break a request. */
    public static function fromJson(string $json): self
    {
        $d = json_decode($json, true);
        if (!is_array($d)) {
            return self::empty();
        }
        $strings = static fn ($v): array => is_array($v) ? array_values(array_filter($v, 'is_string')) : [];
        $memo = [];
        if (is_array($d['memo'] ?? null)) {
            foreach ($d['memo'] as $k => $v) {
                if (is_string($k) && preg_match('~^m:[0-9a-f]{16}$~', $k) === 1 && is_array($v) && Outcome::fromDescriptor($v) !== null) {
                    $memo[$k] = $v;
                }
            }
        }
        $sticky = array_values(array_filter($strings($d['sticky'] ?? []), static fn (string $p): bool => strlen($p) <= self::STICKY_PATH_MAX));

        return new self(
            array_slice($memo, -self::MEMO_CAP, null, true),
            array_slice($strings($d['recent'] ?? []), -self::RECENT_CAP),
            $strings($d['prev'] ?? []),
            ($d['acc'] ?? false) === true,
            array_slice($sticky, -self::STICKY_CAP),
        );
    }
}
