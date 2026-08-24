<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

use Funnypot\App\Render\Fake\FrozenClock;

/**
 * Deterministic, inert, procedurally-generated fake Unix filesystem. Any node is a pure function of
 * its path — no materialized tree. Resolution precedence is overlay (Task 8) over pinned (Task 7)
 * over procedural (here). A directory's children are drawn from the dir's own seed; each child's
 * attributes/content come from that child's own seed, so metadata and content never diverge.
 *
 * Invariants: list() and isValidChild() share one code path; walk-validation from root makes a path
 * reachable iff every ancestor generates the next segment; a hard MAX_DEPTH plus depth-decay make
 * descent terminate; names are unique per directory.
 */
class FakeFilesystem
{
    protected const GEN_VERSION = 1;

    // Draw index namespaces (kept apart so fields never share a draw).
    private const COUNT_IDX = 0;
    private const TYPE_BASE = 2000;
    private const NAME_BASE = 4000;
    private const MTIME_IDX = 11;
    protected const SIZE_IDX = 12;
    private const CONTENT_BASE = 5000000;    // content block counter namespace (stays < 2^32)

    private const TWO_YEARS = 63072000;      // seconds; mtimes fall within the last ~2y, never future
    private const BASE_DIR_PERCENT = 35;     // ~35% of children are dirs at depth 0, decaying by depth
    private const REDRAW_LIMIT = 8;

    /** @var array<string,Node[]> buildChildren cache, keyed by canonical dir path */
    private array $childCache = [];

    /** @var array<string,Node> pinned nodes keyed by canonical path */
    private array $pinnedNodes = [];
    /** @var array<string,string> pinned file content keyed by canonical path */
    private array $pinnedContent = [];
    /** @var array<string,Node[]> pinned nodes grouped by parent dir */
    private array $pinnedByParent = [];

    public function __construct(
        protected string $hostSeedBytes,
        protected string $role,
        protected int $maxDepth = 12,
        protected int $perDirMax = 24
    ) {
        Draw::assertEnv();
        $pinned = PinnedNodes::build($hostSeedBytes, $role);
        $this->pinnedNodes = $pinned['nodes'];
        $this->pinnedContent = $pinned['content'];
        foreach ($this->pinnedNodes as $path => $node) {
            $this->pinnedByParent[PathCanon::parent($path)][] = $node;
        }
    }

    /** @return Node[] */
    public function list(string $path): array
    {
        $canon = PathCanon::canonical($path);
        if ($canon === '/') {
            return $this->buildChildren('/');
        }
        $node = $this->resolveNode($canon);
        if ($node === null || !$node->isDir()) {
            throw PathNotFound::for($path);
        }

        return $this->buildChildren($canon);
    }

    public function stat(string $path): Node
    {
        $canon = PathCanon::canonical($path);
        if ($canon === '/') {
            return new Node('/', 'dir', 0, 0, 4096, 0o755, FrozenClock::epoch(), null);
        }
        $node = $this->resolveNode($canon);
        if ($node === null) {
            throw PathNotFound::for($path);
        }

        return $node;
    }

    /** Regenerate exactly stat()->size bytes from the file's own seed (metadata and content agree). */
    public function read(string $path): string
    {
        $canon = PathCanon::canonical($path);
        if (isset($this->pinnedContent[$canon])) {
            return $this->pinnedContent[$canon];
        }
        $node = $this->stat($path);
        if ($node->isDir()) {
            throw IsADirectory::for($path);
        }
        $size = $node->size;
        if ($size <= 0) {
            return '';
        }
        $seed = $this->nodeSeed(PathCanon::canonical($path));
        $out = '';
        $b = 0;
        while (strlen($out) < $size) {
            // base64 keeps it printable/text-ish; deterministic per (seed, block).
            $out .= base64_encode(hash('fnv1a64', $seed . pack('N', self::CONTENT_BASE + $b), true));
            $b++;
        }

        return substr($out, 0, $size);
    }

    public function isValidChild(string $dir, string $name): bool
    {
        try {
            foreach ($this->list($dir) as $node) {
                if ($node->name === $name) {
                    return true;
                }
            }
        } catch (PathNotFound $e) {
            return false;
        }

        return false;
    }

    public function exists(string $path): bool
    {
        $canon = PathCanon::canonical($path);

        return $canon === '/' || $this->resolveNode($canon) !== null;
    }

    public function isDir(string $path): bool
    {
        $canon = PathCanon::canonical($path);
        if ($canon === '/') {
            return true;
        }
        $node = $this->resolveNode($canon);

        return $node !== null && $node->isDir();
    }

    /** Resolve a path to its Node by looking it up in its parent's listing (recursion validates the chain). */
    protected function resolveNode(string $canon): ?Node
    {
        if ($canon === '/') {
            return new Node('/', 'dir', 0, 0, 4096, 0o755, FrozenClock::epoch(), null);
        }
        if (isset($this->pinnedNodes[$canon])) {
            return $this->pinnedNodes[$canon];
        }
        $parent = PathCanon::parent($canon);
        $parentNode = $this->resolveNode($parent);
        if ($parentNode === null || !$parentNode->isDir()) {
            return null;
        }
        $base = PathCanon::basename($canon);
        foreach ($this->buildChildren($parent) as $child) {
            if ($child->name === $base) {
                return $child;
            }
        }

        return null;
    }

    /**
     * Generate a directory's children: scaffold dirs first (declared order), then procedural entries
     * (draw order). Assumes $canonDir is already a valid dir (callers validate). Never reads content.
     *
     * @return Node[]
     */
    protected function buildChildren(string $canonDir): array
    {
        if (isset($this->childCache[$canonDir])) {
            return $this->childCache[$canonDir];
        }
        $seed = $this->nodeSeed($canonDir);
        $depth = count(PathCanon::segments($canonDir));
        $result = [];
        $used = [];

        foreach (Scaffold::childrenOf($canonDir) ?? [] as $name) {
            $result[] = $this->makeNode($canonDir, $name, true);
            $used[$name] = true;
        }

        $dirPool = Pools::dirNames($this->role);
        $filePool = Pools::fileNames($this->role);
        $count = Draw::heavyTailedInt($seed, self::COUNT_IDX, 1, $this->perDirMax);

        for ($i = 0; $i < $count; $i++) {
            $isDir = $depth < $this->maxDepth
                && Draw::chance($seed, self::TYPE_BASE + $i, max(1, self::BASE_DIR_PERCENT - $depth), 100);
            $pool = $isDir ? $dirPool : $filePool;
            $name = $this->pickUnusedName($seed, $i, $pool, $used);
            $used[$name] = true;
            $result[] = $this->makeNode($canonDir, $name, $isDir);
        }

        // Pinned children win over scaffold/procedural entries with the same name.
        foreach ($this->pinnedByParent[$canonDir] ?? [] as $pinned) {
            $result = array_values(array_filter($result, fn (Node $n) => $n->name !== $pinned->name));
            $result[] = $pinned;
        }

        $this->childCache[$canonDir] = $result;

        return $result;
    }

    /** Deterministic collision-free name pick: redraw a bounded number of times, then numeric suffix. */
    private function pickUnusedName(string $seed, int $i, array $pool, array $used): string
    {
        for ($r = 0; $r < self::REDRAW_LIMIT; $r++) {
            $name = (string) Draw::pick($seed, self::NAME_BASE + $i * self::REDRAW_LIMIT + $r, $pool);
            if ($name !== '' && !isset($used[$name])) {
                return $name;
            }
        }
        $base = (string) Draw::pick($seed, self::NAME_BASE + $i * self::REDRAW_LIMIT, $pool);
        $n = 1;
        while (isset($used[$base . '-' . $n])) {
            $n++;
        }

        return $base . '-' . $n;
    }

    /** Build a child Node with attributes drawn from the child's OWN seed (so content can match later). */
    protected function makeNode(string $parentDir, string $name, bool $isDir): Node
    {
        $canon = $parentDir === '/' ? '/' . $name : $parentDir . '/' . $name;
        $s = $this->nodeSeed($canon);
        $uid = Draw::chance($s, 20, 3, 4) ? 0 : 1000 + Draw::intBelow($s, 21, 60); // mostly root-owned system files
        $gid = $uid;
        $mtime = FrozenClock::epoch() - Draw::intBelow($s, self::MTIME_IDX, self::TWO_YEARS);
        if ($isDir) {
            return new Node($name, 'dir', $uid, $gid, 4096, 0o755, $mtime, null);
        }
        $size = Draw::heavyTailedInt($s, self::SIZE_IDX, 0, 65536);

        return new Node($name, 'file', $uid, $gid, $size, 0o644, $mtime, null);
    }

    protected function nodeSeed(string $canon): string
    {
        return Draw::seed($this->hostSeedBytes . "\0" . self::GEN_VERSION . "\0" . $this->role . "\0" . $canon);
    }
}
