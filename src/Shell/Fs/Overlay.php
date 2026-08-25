<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

/**
 * A session's filesystem mutations as a sparse, path-keyed diff over the generated base. Immutable-style:
 * every with* returns a new Overlay. It is applied AT RESOLVE TIME and never feeds the generation seed,
 * so a mutation at one path can never perturb generation at any other path (the purity invariant).
 * withMove is intentionally absent in Phase 1 — the interpreter composes a move from read + withFile/
 * withDir + withRemoved (it needs the source bytes, which live in the fs, not here).
 *
 * A per-overlay byte ceiling (MAX_BYTES) bounds how large one session's diff can grow: past the ceiling,
 * any net-growth mutation is silently refused (a real disk returning ENOSPC). This matters because the
 * web console persists the overlay across requests keyed by a client-held cookie — without a cap a
 * single session could grow one stored row without bound (disk/CPU/OOM). A running byte counter keeps
 * the check O(1) so it costs nothing on the hot path.
 */
final class Overlay
{
    private const MAX_BYTES = 262144; // 256 KiB — one session's mutations can't exceed this

    private int $bytes;

    /**
     * @param array<string,string> $files  canonical path => bytes (created/overwritten files)
     * @param array<string,bool>   $dirs   canonical path => true (created dirs)
     * @param array<string,bool>   $removed canonical path => true (tombstones)
     */
    public function __construct(
        private array $files = [],
        private array $dirs = [],
        private array $removed = [],
        ?int $bytes = null
    ) {
        $this->bytes = $bytes ?? self::measure($files, $dirs, $removed);
    }

    public function withFile(string $path, string $bytes): self
    {
        $c = PathCanon::canonical($path);
        $newBytes = $this->bytes - $this->keyBytes($c) + strlen($c) + strlen($bytes);
        if ($newBytes > $this->bytes && $newBytes > self::MAX_BYTES) {
            return $this; // ENOSPC: refuse net growth past the ceiling
        }
        $files = $this->files;
        $dirs = $this->dirs;
        $removed = $this->removed;
        $files[$c] = $bytes;
        unset($dirs[$c], $removed[$c]);

        return new self($files, $dirs, $removed, $newBytes);
    }

    public function withDir(string $path): self
    {
        $c = PathCanon::canonical($path);
        $newBytes = $this->bytes - $this->keyBytes($c) + strlen($c);
        if ($newBytes > $this->bytes && $newBytes > self::MAX_BYTES) {
            return $this;
        }
        $files = $this->files;
        $dirs = $this->dirs;
        $removed = $this->removed;
        $dirs[$c] = true;
        unset($files[$c], $removed[$c]);

        return new self($files, $dirs, $removed, $newBytes);
    }

    public function withRemoved(string $path): self
    {
        $c = PathCanon::canonical($path);
        $newBytes = $this->bytes - $this->keyBytes($c) + strlen($c);
        if ($newBytes > $this->bytes && $newBytes > self::MAX_BYTES) {
            return $this;
        }
        $files = $this->files;
        $dirs = $this->dirs;
        $removed = $this->removed;
        unset($files[$c], $dirs[$c]);
        $removed[$c] = true;

        return new self($files, $dirs, $removed, $newBytes);
    }

    /** Bytes currently attributed to one key (a key lives in exactly one of the three maps). */
    private function keyBytes(string $c): int
    {
        if (isset($this->files[$c])) {
            return strlen($c) + strlen($this->files[$c]);
        }
        if (isset($this->dirs[$c]) || isset($this->removed[$c])) {
            return strlen($c);
        }

        return 0;
    }

    /**
     * @param array<string,string> $files
     * @param array<string,bool>   $dirs
     * @param array<string,bool>   $removed
     */
    private static function measure(array $files, array $dirs, array $removed): int
    {
        $n = 0;
        foreach ($files as $k => $v) {
            $n += strlen((string) $k) + strlen((string) $v);
        }
        foreach ($dirs as $k => $_) {
            $n += strlen((string) $k);
        }
        foreach ($removed as $k => $_) {
            $n += strlen((string) $k);
        }

        return $n;
    }

    public function isRemoved(string $canon): bool
    {
        return isset($this->removed[$canon]);
    }

    /** True if the attacker created this dir this session — it must list only its overlay children. */
    public function isCreatedDir(string $canon): bool
    {
        return isset($this->dirs[$canon]);
    }

    public function fileBytes(string $canon): ?string
    {
        return $this->files[$canon] ?? null;
    }

    public function node(string $canon, int $now): ?Node
    {
        $name = PathCanon::basename($canon);
        if (isset($this->files[$canon])) {
            return new Node($name, 'file', 0, 0, strlen($this->files[$canon]), 0o644, $now, null);
        }
        if (isset($this->dirs[$canon])) {
            return new Node($name, 'dir', 0, 0, 4096, 0o755, $now, null);
        }

        return null;
    }

    /** @return Node[] overlay-created files/dirs directly under $parentCanon */
    public function createdChildren(string $parentCanon, int $now): array
    {
        $out = [];
        foreach (array_merge(array_keys($this->files), array_keys($this->dirs)) as $canon) {
            if (PathCanon::parent($canon) === $parentCanon) {
                $node = $this->node($canon, $now);
                if ($node !== null) {
                    $out[$node->name] = $node; // dedupe by name (a file+dir clash can't occur, with* clears)
                }
            }
        }

        return array_values($out);
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return ['files' => $this->files, 'dirs' => $this->dirs, 'removed' => $this->removed];
    }

    /** @param array<string,mixed> $a */
    public static function fromArray(array $a): self
    {
        return new self(
            is_array($a['files'] ?? null) ? $a['files'] : [],
            is_array($a['dirs'] ?? null) ? $a['dirs'] : [],
            is_array($a['removed'] ?? null) ? $a['removed'] : []
        );
    }
}
