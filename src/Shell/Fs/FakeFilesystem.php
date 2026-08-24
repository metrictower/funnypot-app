<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

use Funnypot\App\Render\Fake\FrozenClock;

/**
 * Deterministic, inert, procedurally-generated fake Unix filesystem. Any node is a pure function of
 * its path — no materialized tree. Resolution precedence is overlay (Task 8) over pinned (Task 7)
 * over procedural (here); ALL three are merged inside buildChildren(), and every lookup walks the
 * parent chain through buildChildren(), so resolve() and list() can never disagree and a tombstoned
 * ancestor hides its whole subtree.
 *
 * Invariants: list() and isValidChild() share one code path; a path is valid iff every ancestor
 * generates the next segment; over-long/over-deep paths are rejected before any resolution (no deep
 * recursion, no O(n^2) blow-up); a hard MAX_DEPTH + depth-decay + a global newcount cap make growth
 * bounded; names are unique per directory; a file's size and content come from one seed.
 */
class FakeFilesystem
{
    protected const GEN_VERSION = 1;

    // Dir-seed index namespaces (kept far apart so structure fields never collide, even for large perDirMax).
    private const COUNT_IDX = 0;
    private const TYPE_BASE = 100000;
    private const NAME_BASE = 1000000;
    // Child-seed index namespaces.
    private const MTIME_IDX = 11;
    protected const SIZE_IDX = 12;
    private const UID_ROLL_IDX = 20;
    private const CONTENT_BASE = 5000000;    // content block counter namespace (stays < 2^32)

    private const TWO_YEARS = 63072000;      // seconds; mtimes fall within the last ~2y, never future
    private const BASE_DIR_PERCENT = 35;     // ~35% of children are dirs at depth 0, decaying by depth
    private const REDRAW_LIMIT = 8;
    private const DEPTH_SLACK = 8;           // allow a little past MAX_DEPTH for pinned/overlay paths
    private const MAX_PATH_LEN = 4096;       // PATH_MAX-realistic; reject before canonicalizing
    private const SIZE_CAP = 65536;
    private const CHILD_CACHE_MAX = 4096;    // FIFO-evicted so a long-lived crawler can't grow it unbounded

    /** @var array<string,Node[]> buildChildren cache, keyed by canonical dir path */
    private array $childCache = [];

    /** @var array<string,Node> pinned nodes keyed by canonical path */
    private array $pinnedNodes = [];
    /** @var array<string,string> pinned file content keyed by canonical path */
    private array $pinnedContent = [];
    /** @var array<string,Node[]> pinned nodes grouped by parent dir */
    private array $pinnedByParent = [];

    private ?Overlay $overlay = null;
    private string $distroFam = 'debian';    // from the pinned distro, so uids stay coherent with passwd

    public function __construct(
        protected string $hostSeedBytes,
        protected string $role,
        protected int $identitySeed,       // host-identity int (= panel personaSeed for the this-box host)
        protected int $maxDepth = 12,
        protected int $perDirMax = 24,
        protected int $cacheMax = self::CHILD_CACHE_MAX
    ) {
        Draw::assertEnv();
        $pinned = PinnedNodes::build($hostSeedBytes, $role, $identitySeed);
        $this->pinnedNodes = $pinned['nodes'];
        $this->pinnedContent = $pinned['content'];
        $this->distroFam = $pinned['fam'];
        foreach ($this->pinnedNodes as $path => $node) {
            $this->pinnedByParent[PathCanon::parent($path)][] = $node;
        }
    }

    /** Return a copy of this filesystem with a session overlay applied (base generation is unchanged). */
    public function withOverlay(Overlay $overlay): self
    {
        $new = clone $this;
        $new->overlay = $overlay;
        $new->childCache = [];

        return $new;
    }

    /** @return Node[] */
    public function list(string $path): array
    {
        $canon = $this->guardPath($path);
        if ($canon === '/') {
            return $this->cloneAll($this->buildChildren('/'));
        }
        $node = $this->resolveNode($canon);
        if ($node === null || !$node->isDir()) {
            throw PathNotFound::for($path);
        }

        return $this->cloneAll($this->buildChildren($canon));
    }

    public function stat(string $path): Node
    {
        $canon = $this->guardPath($path);
        if ($canon === '/') {
            return $this->rootNode();
        }
        $node = $this->resolveNode($canon);
        if ($node === null) {
            throw PathNotFound::for($path);
        }

        return clone $node;
    }

    /** Regenerate exactly stat()->size bytes; overlay/pinned content wins; symlinks follow their target. */
    public function read(string $path, int $hops = 0): string
    {
        $canon = $this->guardPath($path);
        $node = $canon === '/' ? $this->rootNode() : $this->resolveNode($canon);
        if ($node === null) {
            throw PathNotFound::for($path);
        }
        if ($node->isDir()) {
            throw IsADirectory::for($path);
        }
        if ($node->isLink()) {
            if ($hops >= 8 || $node->target === null) {
                throw PathNotFound::for($path); // dangling/looping link -> bash "No such file or directory"
            }
            return $this->read($node->target, $hops + 1);
        }
        if ($this->overlay !== null) {
            $ob = $this->overlay->fileBytes($canon);
            if ($ob !== null) {
                return $ob;
            }
        }
        if (isset($this->pinnedContent[$canon])) {
            return $this->pinnedContent[$canon];
        }

        return $this->procContent($canon, $node->size);
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
        try {
            $canon = $this->guardPath($path);
        } catch (PathNotFound $e) {
            return false;
        }

        return $canon === '/' || $this->resolveNode($canon) !== null;
    }

    public function isDir(string $path): bool
    {
        try {
            $canon = $this->guardPath($path);
        } catch (PathNotFound $e) {
            return false;
        }
        if ($canon === '/') {
            return true;
        }
        $node = $this->resolveNode($canon);

        return $node !== null && $node->isDir();
    }

    public function isFile(string $path): bool
    {
        try {
            $canon = $this->guardPath($path);
        } catch (PathNotFound $e) {
            return false;
        }
        if ($canon === '/') {
            return false;
        }
        $node = $this->resolveNode($canon);

        return $node !== null && $node->isFile();
    }

    /** Reject pathological paths BEFORE resolving: length first (cheap), then canonicalize + depth. */
    private function guardPath(string $path): string
    {
        if (strlen($path) > self::MAX_PATH_LEN) {
            throw PathNotFound::for($path);
        }
        $canon = PathCanon::canonical($path);
        if (count(PathCanon::segments($canon)) > $this->maxDepth + self::DEPTH_SLACK) {
            throw PathNotFound::for($path);
        }

        return $canon;
    }

    private function rootNode(): Node
    {
        return new Node('/', 'dir', 0, 0, 4096, 0o755, FrozenClock::epoch() - self::TWO_YEARS, null);
    }

    /** Iterative root->leaf walk (no recursion, no per-level recanonicalization). Applies overlay/pinned
     *  via buildChildren, so a tombstoned or missing ancestor makes the whole subtree unreachable. */
    protected function resolveNode(string $canon): ?Node
    {
        if ($canon === '/') {
            return $this->rootNode();
        }
        $node = $this->rootNode();
        $cur = '/';
        foreach (PathCanon::segments($canon) as $seg) {
            if (!$node->isDir()) {
                return null; // can't descend into a file or symlink
            }
            $found = null;
            foreach ($this->buildChildren($cur) as $child) {
                if ($child->name === $seg) {
                    $found = $child;
                    break;
                }
            }
            if ($found === null) {
                return null;
            }
            $node = $found;
            $cur = $cur === '/' ? '/' . $seg : $cur . '/' . $seg;
        }

        return $node;
    }

    /**
     * Generate a directory's children: scaffold dirs first, procedural next, pinned override, overlay last.
     * Assumes $canonDir is a valid dir (callers validate). Never reads content.
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

        // A dir the attacker just created (overlay withDir) has NO scaffold/procedural content — only what
        // they put in it. Skipping generation here is what makes `mkdir foo && ls foo` show an empty dir.
        $overlayCreated = $this->overlay !== null && $this->overlay->isCreatedDir($canonDir);

        if (!$overlayCreated) {
            foreach (Scaffold::childrenOf($canonDir) ?? [] as $name) {
                $result[] = $this->makeNode($canonDir, $name, true);
                $used[$name] = true;
            }

            $dirPool = Pools::dirNames($this->role);
            $filePool = Pools::fileNames($this->role);
            // Count is a pure function of the dir seed (bounded by perDirMax) — independent of cache/eviction
            // state, so a dir re-listed after eviction regenerates identically (determinism invariant).
            $count = Draw::heavyTailedInt($seed, self::COUNT_IDX, 1, $this->perDirMax);

            for ($i = 0; $i < $count; $i++) {
                $isDir = $depth < $this->maxDepth
                    && Draw::chance($seed, self::TYPE_BASE + $i, max(1, self::BASE_DIR_PERCENT - $depth), 100);
                $pool = $isDir ? $dirPool : $filePool;
                $name = $this->pickUnusedName($seed, $i, $pool, $used);
                $used[$name] = true;
                $result[] = $this->makeNode($canonDir, $name, $isDir);
            }
        }

        foreach ($this->pinnedByParent[$canonDir] ?? [] as $pinned) {
            $result = array_values(array_filter($result, fn (Node $n) => $n->name !== $pinned->name));
            $result[] = $pinned;
        }

        if ($this->overlay !== null) {
            $overlay = $this->overlay;
            $now = FrozenClock::epoch();
            $result = array_values(array_filter($result, static function (Node $n) use ($overlay, $canonDir) {
                $childCanon = $canonDir === '/' ? '/' . $n->name : $canonDir . '/' . $n->name;
                return !$overlay->isRemoved($childCanon);
            }));
            foreach ($overlay->createdChildren($canonDir, $now) as $node) {
                $result = array_values(array_filter($result, fn (Node $n) => $n->name !== $node->name));
                $result[] = $node;
            }
        }

        if (count($this->childCache) >= $this->cacheMax) {
            array_shift($this->childCache); // FIFO evict — a crawler can't grow the cache without bound
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
        // uids stay coherent with the pinned /etc/passwd (root, www-data under /var/www, else the admin user).
        if (Draw::chance($s, self::UID_ROLL_IDX, 3, 4)) {
            $uid = 0;
        } elseif (strncmp($canon, '/var/www', 8) === 0) {
            $uid = $this->distroFam === 'rhel' ? 48 : 33; // apache vs www-data — matches the pinned passwd
        } else {
            $uid = 1000;
        }
        $mtime = FrozenClock::epoch() - Draw::intBelow($s, self::MTIME_IDX, self::TWO_YEARS);
        if ($isDir) {
            return new Node($name, 'dir', $uid, $uid, 4096, 0o755, $mtime, null);
        }
        $size = Draw::heavyTailedInt($s, self::SIZE_IDX, 0, self::SIZE_CAP);

        return new Node($name, 'file', $uid, $uid, $size, 0o644, $mtime, null);
    }

    /** Avalanching, padding-free content: md5 blocks diffuse fully; base64 the whole blob once, then cut. */
    private function procContent(string $canon, int $size): string
    {
        if ($size <= 0) {
            return '';
        }
        $seed = $this->nodeSeed($canon);
        $rawNeeded = intdiv($size, 4) * 3 + 3; // enough raw bytes that base64 length >= size
        $raw = '';
        $b = 0;
        while (strlen($raw) < $rawNeeded) {
            $raw .= md5($seed . pack('N', self::CONTENT_BASE + $b), true); // 16 raw bytes, full avalanche
            $b++;
        }

        return substr(base64_encode($raw), 0, $size); // padding only at the very end, cut away by substr
    }

    protected function nodeSeed(string $canon): string
    {
        return Draw::seed($this->hostSeedBytes . "\0" . self::GEN_VERSION . "\0" . $this->role . "\0" . $canon);
    }

    /** @param Node[] $nodes @return Node[] defensive copies so a caller mutating a Node can't corrupt the cache */
    private function cloneAll(array $nodes): array
    {
        return array_map(static fn (Node $n) => clone $n, $nodes);
    }
}
