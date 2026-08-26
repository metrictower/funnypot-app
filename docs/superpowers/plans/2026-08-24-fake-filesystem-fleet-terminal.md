# FakeFilesystem + Fleet Console + Streaming Web Terminal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, inert, procedurally-generated fake Unix filesystem + shared shell interpreter, reused across the SSH/telnet fake shells and a new streaming web terminal fronted by a server fleet console.

**Architecture:** A pure/stateless `FakeFilesystem` generates any node directly from its path via keyed hashing (no materialized tree), resolved through overlay ▸ pinned ∪ procedural. A shared `ShellInterpreter` (never-execute) drives it for all three front-ends. `HostFacts` is the single per-host coherence source. The streaming web-terminal command endpoint is a Router-level POST route (sibling of `AiApiRouter`) reusing `AiApi\StreamEmitter`; the fleet UI is a GET panel section.

**Tech Stack:** Framework-free PHP 8.0, PSR-4 `Funnypot\` → `src/`, PHPUnit 9.5 (`php vendor/bin/phpunit`), no new composer deps.

**Spec:** `funnypot/docs/superpowers/specs/2026-08-24-fake-filesystem-fleet-terminal-design.md` (rev 2, fable-approved). Read it alongside this plan.

## Global Constraints

- **PHP 8.0**, framework-free, no new composer deps. `Funnypot\` → `src/`; tests `Funnypot\Tests\` → `tests/`.
- **Inert:** never `exec`/`eval`/`proc_open`/`shell_exec`, no real FS access, no outbound socket.
- **Determinism on hash-derived ints:** only `& | ^ << >> %`; never `+ - * /`; always mask `& PHP_INT_MAX` before `%`; never `hexdec()` a 64-bit hex string; `pack('N',$i)` needs `$i < 2^32`. Assert `PHP_INT_SIZE === 8` (degrade, never 500, on the web path). Do NOT "fix" `ServerProfile` to these rules (it lives in a safe ≤60-bit hexdec-int space).
- **Secret handling:** private secret from env `FUNNYPOT_FS_SECRET`; if unset, auto-generate 32 random bytes and persist to `<storage>/fs_secret`, then reuse. Never committed, logged, or echoed. Never go dark for a missing secret.
- **Fingerprint-safety:** generated strings are factual/plausible, never scanner signatures. The CI gate does NOT scan runtime shell/FS/fleet output — enforce via escape-by-construction + new `FingerprintSafetyTest` provider rows against `resources/app-fingerprint-denylist.php`.
- **Two-seed model:** host-IDENTITY seed (for `HostFacts`/`ServerProfile`/process model) vs FS-CONTENT keys (always fold the secret). For the "this-box" host the identity seed = the panel `personaSeed` (so panel/shell/fleet agree); for other fleet hosts identity seed = `fold64(fnv1a64(secret‖'fleet'‖i))`. The existing `crc32($ip)` `ProtocolSession` seed stays ephemeral-only.
- **Response invariant (web terminal):** resolve the full bounded output in `try/catch(\Throwable)` BEFORE `StreamEmitter::begin()`; a fault degrades to a plain error line at 200, never a 500.

---

## Phase 1 — `FakeFilesystem` engine (this plan, full detail)

Self-contained + independently testable: the engine + its tests, no front-end. Namespace `Funnypot\Shell\Fs` → `src/Shell/Fs/`; tests `Funnypot\Tests\Shell\Fs` → `tests/Shell/Fs/`.

### Task 1: `Draw` — deterministic hash draw helper

**Files:**
- Create: `src/Shell/Fs/Draw.php`
- Test: `tests/Shell/Fs/DrawTest.php`

**Interfaces:**
- Produces: `Funnypot\Shell\Fs\Draw` — `static assertEnv(): void`, `static seed(string $material): string` (8 raw bytes), `static at(string $seed, int $i): int` (non-negative 63-bit), `static intBelow(string $seed, int $i, int $n): int`, `static pick(string $seed, int $i, array $pool): mixed`, `static chance(string $seed, int $i, int $num, int $den): bool`, `static heavyTailedInt(string $seed, int $i, int $min, int $max): int`.

- [ ] **Step 1: Write the failing test**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Tests\Shell\Fs;
use Funnypot\Shell\Fs\Draw;
use PHPUnit\Framework\TestCase;

final class DrawTest extends TestCase
{
    public function test_at_is_deterministic_and_non_negative(): void
    {
        $s = Draw::seed("host\0dev\0/home");
        for ($i = 0; $i < 500; $i++) {
            $v = Draw::at($s, $i);
            self::assertGreaterThanOrEqual(0, $v);
            self::assertSame($v, Draw::at($s, $i)); // stable
        }
    }
    public function test_intBelow_never_negative_or_out_of_range(): void
    {
        $s = Draw::seed('x');
        for ($i = 0; $i < 1000; $i++) {
            $v = Draw::intBelow($s, $i, 7);
            self::assertGreaterThanOrEqual(0, $v);
            self::assertLessThan(7, $v);
        }
    }
    public function test_different_seeds_diverge(): void
    {
        self::assertNotSame(Draw::at(Draw::seed('a'), 0), Draw::at(Draw::seed('b'), 0));
    }
    public function test_heavy_tailed_within_bounds(): void
    {
        $s = Draw::seed('sz');
        for ($i = 0; $i < 1000; $i++) {
            $v = Draw::heavyTailedInt($s, $i, 10, 1_000_000);
            self::assertGreaterThanOrEqual(10, $v);
            self::assertLessThanOrEqual(1_000_000, $v);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails** — `php vendor/bin/phpunit --filter DrawTest` → FAIL (class not found).

- [ ] **Step 3: Write minimal implementation**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Shell\Fs;

/**
 * Deterministic, stateless draw primitive for path-seeded generation. Uses fnv1a64 (the only
 * fast hash guaranteed on PHP 8.0 — xxh3/murmur3 are 8.1+). Counter-based: any draw is a pure
 * function of (seed, index) with no shared PRNG state. Only bitwise/modulo on hash output — never
 * +-*/ (silent float promotion breaks determinism); always mask before % (negative index guard).
 */
final class Draw
{
    public static function assertEnv(): void
    {
        if (PHP_INT_SIZE !== 8) {
            throw new \RuntimeException('FakeFilesystem requires 64-bit PHP');
        }
    }
    public static function seed(string $material): string
    {
        return hash('fnv1a64', $material, true); // 8 raw bytes
    }
    public static function at(string $seed, int $i): int
    {
        $bytes = hash('fnv1a64', $seed . pack('N', $i), true);
        return unpack('J', $bytes)[1] & PHP_INT_MAX; // de-sign to [0, 2^63-1]
    }
    public static function intBelow(string $seed, int $i, int $n): int
    {
        return $n > 0 ? self::at($seed, $i) % $n : 0;
    }
    /** @param array<int,mixed> $pool @return mixed */
    public static function pick(string $seed, int $i, array $pool)
    {
        return $pool === [] ? null : $pool[self::at($seed, $i) % count($pool)];
    }
    public static function chance(string $seed, int $i, int $num, int $den): bool
    {
        return $den > 0 && self::at($seed, $i) % $den < $num;
    }
    /** Log-ish heavy tail: mostly small, occasional large, within [min,max] inclusive. */
    public static function heavyTailedInt(string $seed, int $i, int $min, int $max): int
    {
        if ($max <= $min) {
            return $min;
        }
        $span = $max - $min;
        // Guard the reduction's multiply (scaled ≤ 999) against int→float promotion, which would be
        // determinism-fatal AND a TypeError in intdiv. Clamp span so scaled*span < PHP_INT_MAX.
        // Degrade, never fault (the web path must never 500).
        $cap = intdiv(PHP_INT_MAX, 1000);
        if ($span > $cap) {
            $span = $cap;
        }
        $u = self::at($seed, $i) % 1000;   // 0..999
        $scaled = intdiv($u * $u, 999);    // 0..999 inclusive, skewed low
        return $min + intdiv($scaled * $span, 999); // inclusive of max
    }
}
```

- [ ] **Step 4: Run test to verify it passes** — `php vendor/bin/phpunit --filter DrawTest` → PASS.

- [ ] **Step 5: Commit** — `git add src/Shell/Fs/Draw.php tests/Shell/Fs/DrawTest.php && git commit -m "feat(fs): deterministic hash draw primitive (Draw)"`

### Task 2: `PathCanon` — shared path canonicalizer

**Files:**
- Create: `src/Shell/Fs/PathCanon.php`
- Test: `tests/Shell/Fs/PathCanonTest.php`

**Interfaces:**
- Produces: `Funnypot\Shell\Fs\PathCanon` — `static canonical(string $path): string` (absolute, leading `/`, no trailing `/`, `.`/`..` resolved, root = `/`), `static segments(string $path): array` (canonical segments, `[]` for root), `static parent(string $path): string`, `static basename(string $path): string`.
- Consumed by both `list()` and `isValidChild()` in Task 5 (same routine, or the list==validate invariant breaks).

- [ ] **Step 1: Write the failing test**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Tests\Shell\Fs;
use Funnypot\Shell\Fs\PathCanon;
use PHPUnit\Framework\TestCase;

final class PathCanonTest extends TestCase
{
    public function test_canonical_forms(): void
    {
        self::assertSame('/', PathCanon::canonical('/'));
        self::assertSame('/', PathCanon::canonical('///'));
        self::assertSame('/home/bob', PathCanon::canonical('/home/bob/'));
        self::assertSame('/home', PathCanon::canonical('/home/bob/..'));
        self::assertSame('/etc', PathCanon::canonical('/home/../etc/./'));
        self::assertSame('/', PathCanon::canonical('/..')); // can't escape root
    }
    public function test_segments_and_parent(): void
    {
        self::assertSame(['home', 'bob'], PathCanon::segments('/home/bob'));
        self::assertSame([], PathCanon::segments('/'));
        self::assertSame('/home', PathCanon::parent('/home/bob'));
        self::assertSame('/', PathCanon::parent('/home'));
        self::assertSame('bob', PathCanon::basename('/home/bob'));
    }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Shell\Fs;

/** Total, pure path canonicalizer. The single source of truth for both listing and validation. */
final class PathCanon
{
    public static function canonical(string $path): string
    {
        $out = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($out);
                continue;
            }
            $out[] = $seg;
        }
        return '/' . implode('/', $out);
    }
    /** @return string[] */
    public static function segments(string $path): array
    {
        $c = self::canonical($path);
        return $c === '/' ? [] : explode('/', substr($c, 1));
    }
    public static function parent(string $path): string
    {
        $segs = self::segments($path);
        array_pop($segs);
        return $segs === [] ? '/' : '/' . implode('/', $segs);
    }
    public static function basename(string $path): string
    {
        $segs = self::segments($path);
        return $segs === [] ? '/' : (string) end($segs);
    }
}
```
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `git commit -m "feat(fs): shared path canonicalizer (PathCanon)"`

### Task 3: `Node` value object + `PathNotFound` exception

**Files:**
- Create: `src/Shell/Fs/Node.php`, `src/Shell/Fs/PathNotFound.php`
- Test: `tests/Shell/Fs/NodeTest.php`

**Interfaces:**
- Produces: `Funnypot\Shell\Fs\Node` — public typed props `string $name, string $type` (`'dir'|'file'|'link'`), `int $uid, int $gid, int $size, int $mode, int $mtime, ?string $target`, plus `isDir(): bool`, `isFile(): bool`, `isLink(): bool`. `Funnypot\Shell\Fs\PathNotFound extends \RuntimeException` — `static for(string $path): self`.
- Note: PHP 8.0 has no `readonly` props — use public typed props set in a promoted constructor.

- [ ] **Step 1: Write the failing test**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Tests\Shell\Fs;
use Funnypot\Shell\Fs\{Node, PathNotFound};
use PHPUnit\Framework\TestCase;

final class NodeTest extends TestCase
{
    public function test_node_flags(): void
    {
        $d = new Node('etc', 'dir', 0, 0, 4096, 0o755, 1_700_000_000, null);
        self::assertTrue($d->isDir());
        self::assertFalse($d->isFile());
        $f = new Node('x', 'file', 0, 0, 12, 0o644, 1_700_000_000, null);
        self::assertTrue($f->isFile());
    }
    public function test_pathnotfound_message(): void
    {
        $e = PathNotFound::for('/no/such');
        self::assertInstanceOf(\RuntimeException::class, $e);
        self::assertStringContainsString('/no/such', $e->getMessage());
    }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Shell\Fs;

final class Node
{
    public function __construct(
        public string $name,
        public string $type,     // 'dir' | 'file' | 'link'
        public int $uid,
        public int $gid,
        public int $size,
        public int $mode,
        public int $mtime,
        public ?string $target = null
    ) {}
    public function isDir(): bool { return $this->type === 'dir'; }
    public function isFile(): bool { return $this->type === 'file'; }
    public function isLink(): bool { return $this->type === 'link'; }
}
```
```php
<?php
declare(strict_types=1);
namespace Funnypot\Shell\Fs;

final class PathNotFound extends \RuntimeException
{
    public static function for(string $path): self
    {
        return new self($path); // callers render bash-standard text; path carried for logging
    }
}
```
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `git commit -m "feat(fs): Node value object + PathNotFound"`

### Task 4: `Pools` — role-biased factual name catalogs (hundreds deep)

**Files:**
- Create: `src/Shell/Fs/Pools.php` (+ `resources/fs-pools.php` returning the arrays)
- Test: `tests/Shell/Fs/PoolsTest.php`

**Interfaces:**
- Produces: `Funnypot\Shell\Fs\Pools` — `static dirNames(string $role): array`, `static fileNames(string $role): array`, `static extensions(string $role): array`. Roles: `developer|finance|hr|sales|ops|generic`.
- Content is FACTUAL public data (common Unix/dir/file names) — never scanner signatures. Each pool ≥ 150 entries, deduped.

- [ ] **Step 1: Write the failing test**
```php
<?php
declare(strict_types=1);
namespace Funnypot\Tests\Shell\Fs;
use Funnypot\Shell\Fs\Pools;
use PHPUnit\Framework\TestCase;

final class PoolsTest extends TestCase
{
    public function test_pools_are_large_and_unique(): void
    {
        foreach (['developer','finance','hr','sales','ops','generic'] as $role) {
            $dirs = Pools::dirNames($role);
            $files = Pools::fileNames($role);
            self::assertGreaterThanOrEqual(150, count($dirs), "$role dirs");
            self::assertGreaterThanOrEqual(150, count($files), "$role files");
            self::assertSame(array_values(array_unique($dirs)), $dirs, "$role dirs unique");
            self::assertSame(array_values(array_unique($files)), $files, "$role files unique");
        }
    }
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** — `Pools` reads `resources/fs-pools.php` (a `return [...]` of role→dir/file/ext arrays, each ≥150 factual entries: e.g. generic dirs `bin,etc,lib,usr,var,opt,srv,tmp,...`; developer files `main.go,server.js,Dockerfile,requirements.txt,.env.example,...`; finance `Q1-forecast.xlsx,ledger-2025.csv,...`). Merge role pool with `generic` so common OS names always appear. Dedupe with `array_values(array_unique(...))`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `git commit -m "feat(fs): role-biased factual name pools (hundreds deep)"`

### Task 5: `FakeFilesystem` — FHS scaffold + procedural generation + walk-validate

**Files:**
- Create: `src/Shell/Fs/Scaffold.php`, `src/Shell/Fs/FakeFilesystem.php`
- Test: `tests/Shell/Fs/FakeFilesystemGenerationTest.php`

**Interfaces:**
- Consumes: `Draw`, `PathCanon`, `Node`, `PathNotFound`, `Pools`, `Funnypot\App\Render\Fake\FrozenClock`.
- Produces:
  - `Funnypot\Shell\Fs\Scaffold` — `const DIRS` (nested map of ALWAYS-present FHS dirs: root has `bin boot dev etc home lib lib64 media mnt opt proc root run sbin srv tmp usr var`; `/usr` has `bin lib local sbin share include`; `/var` has `log lib backups cache spool www tmp`; `/var/www` has `html`; `/srv` has `app`; `/opt` and `/root` empty). `static childrenOf(string $canonPath): ?array` (declared child names, null if not a scaffold dir), `static isScaffoldDir(string $canonPath): bool`.
  - `Funnypot\Shell\Fs\FakeFilesystem` — ctor `__construct(string $hostSeedBytes, string $role, int $maxDepth = 12, int $perDirMax = 24)` (calls `Draw::assertEnv()`); `list(string $path): Node[]` (throws `PathNotFound` if the path or any ancestor is not a valid dir), `isValidChild(string $dir, string $name): bool`, `exists(string $path): bool`, `isDir(string $path): bool`.
- Constant: `GEN_VERSION = 1` folded into every key.
- **Listing order (documented invariant):** scaffold children first (in `Scaffold::DIRS` declared order), then procedural children in draw order. Deterministic; Task 8's overlay merge must preserve this base order.
- **`isValidChild` contract (all of Phase 1):** membership in `list($dir)`'s names — the SAME resolver Tasks 7/8 extend, so it inherits pinned+overlay. Catches an invalid-parent `PathNotFound` and returns `false` (never throws).
- Every dir yields at least 1 procedural child (`heavyTailedInt(seed,0,1,perDirMax)` min=1), so scaffold dirs are never empty.

- [ ] **Step 1: Write the failing test** — anchored to scaffold paths (guaranteed to exist):
```php
<?php
declare(strict_types=1);
namespace Funnypot\Tests\Shell\Fs;
use Funnypot\Shell\Fs\{FakeFilesystem, Draw, PathNotFound};
use PHPUnit\Framework\TestCase;

final class FakeFilesystemGenerationTest extends TestCase
{
    private function fs(): FakeFilesystem
    {
        return new FakeFilesystem(Draw::seed("secret\0host\0dev"), 'developer');
    }
    public function test_scaffold_dirs_always_present_and_nonempty(): void
    {
        $names = array_map(fn($n) => $n->name, $this->fs()->list('/'));
        foreach (['etc','usr','var','srv','tmp','root','home'] as $d) {
            self::assertContains($d, $names, "root missing scaffold dir $d");
        }
        self::assertNotEmpty($this->fs()->list('/srv/app')); // scaffold dir, >=1 procedural child
        self::assertNotEmpty($this->fs()->list('/usr/lib'));
    }
    public function test_listing_is_deterministic(): void
    {
        self::assertEquals($this->fs()->list('/srv/app'), $this->fs()->list('/srv/app'));
    }
    public function test_list_equals_validate(): void
    {
        $fs = $this->fs();
        foreach ($fs->list('/srv') as $node) {
            self::assertTrue($fs->isValidChild('/srv', $node->name));
        }
        self::assertFalse($fs->isValidChild('/srv', 'definitely-not-a-generated-name-zzz'));
        self::assertFalse($fs->isValidChild('/no/such/parent', 'x')); // invalid parent -> false
    }
    public function test_names_unique_within_dir(): void
    {
        $names = array_map(fn($n) => $n->name, $this->fs()->list('/usr/lib'));
        self::assertSame(array_values(array_unique($names)), $names);
    }
    public function test_invalid_path_throws(): void
    {
        $this->expectException(PathNotFound::class);
        $this->fs()->list('/srv/app/nonexistent-zzz/deeper');
    }
    public function test_depth_cap_bottoms_out(): void
    {
        $fs = $this->fs();
        $path = '/srv/app';
        for ($d = 0; $d < 40; $d++) {          // descend REAL generated child dirs
            $sub = null;
            foreach ($fs->list($path) as $n) {
                if ($n->isDir()) { $sub = $n->name; break; }
            }
            if ($sub === null) { break; }
            $path .= '/' . $sub;
        }
        foreach ($fs->list($path) as $n) {     // deepest reachable dir has no further dirs
            self::assertFalse($n->isDir(), 'no dirs past max depth');
        }
    }
}
```
- [ ] **Step 2: Run test to verify it fails** — `php vendor/bin/phpunit --filter FakeFilesystemGenerationTest` → FAIL.
- [ ] **Step 3: Implement.**
  - `Scaffold`: the const `DIRS` map + `childrenOf`/`isScaffoldDir`.
  - `FakeFilesystem::__construct`: store deps; call `Draw::assertEnv()`.
  - `list($path)`: `$canon = PathCanon::canonical($path)`; walk-validate root to leaf — each ancestor segment must be in its parent's `list()` child names, else throw `PathNotFound::for($path)` (memoize validated dirs per instance). Then build children:
    - `$seed = Draw::seed($hostSeedBytes . "\0" . self::GEN_VERSION . "\0" . $role . "\0" . $canon)`.
    - scaffold children (`Scaffold::childrenOf($canon)`) first, each a dir Node.
    - procedural children: `$count = Draw::heavyTailedInt($seed, 0, 1, min($this->perDirMax, count($pool)))`; for i in 0..count-1 draw a name via `Draw::pick($seed, self::NAME_BASE + $i, $pool)` (`$pool` = `Pools::dirNames`/`fileNames` for the role); skip names already used (scaffold set + earlier procedural); on collision re-draw up to 8 times then append a numeric suffix (bounded — never spins).
    - dir-vs-file: `Draw::chance($seed, self::TYPE_BASE + $i, max(1, $baseDirNumerator - $depth), 100)` AND a hard rule `depth >= maxDepth` forces file (depth = `count(PathCanon::segments($canon))`).
    - per-node uid/gid/mode/mtime from `Draw::at($seed, self::ATTR_BASE + $i*4 + k)`; mtime = `FrozenClock::epoch() - installAge` (drawn, never future). File size is drawn here too (Task 6 sets the cap + `read()`).
    - return scaffold Nodes (declared order) then procedural Nodes (draw order); dedupe by name, first occurrence wins.
  - `isValidChild($dir,$name)`: `try { return in_array($name, array_map(fn($n)=>$n->name, $this->list($dir)), true); } catch (PathNotFound $e) { return false; }`.
  - `exists`/`isDir`: derive from the parent's `list()` (root always exists and isDir).
- [ ] **Step 4: Run test to verify it passes** — `php vendor/bin/phpunit --filter FakeFilesystemGenerationTest` → PASS.
- [ ] **Step 5: Commit** — `git add src/Shell/Fs/Scaffold.php src/Shell/Fs/FakeFilesystem.php tests/Shell/Fs/FakeFilesystemGenerationTest.php && git commit -m "feat(fs): FHS scaffold + procedural generation + walk-validate"`

### Task 6: File content generation (metadata↔content coherence)

**Files:**
- Modify: `src/Shell/Fs/FakeFilesystem.php` (add `read`, `stat`)
- Test: `tests/Shell/Fs/FakeFilesystemContentTest.php`

**Interfaces:**
- Produces: `read(string $path): string`, `stat(string $path): Node`. `read` throws `PathNotFound` for a missing path, and a distinct `IsADirectory` guard message for a directory.
- Constant: `SIZE_CAP = 65536`. File `size` is drawn in Task 5 as `Draw::heavyTailedInt($nodeSeed, self::SIZE_IDX, 0, self::SIZE_CAP)` — mostly small, hard-capped (no OOM/amplification).
- **Contract (guarantees `stat($path)->size === strlen(read($path))`):** `list()` NEVER generates content — it only draws the capped `size` int per file. `read()` generates exactly `size` bytes deterministically from the file's own `nodeSeed`: build a byte/char stream block-by-block (`hash('fnv1a64', $nodeSeed . pack('N', self::CONTENT_BASE + $b), true)` for block `$b`, `$b < 2^32`), map to printable text for text extensions, and return the first `size` bytes. Same `nodeSeed` + same `size` ⇒ identical bytes; `ls` stays O(childcount); `cat` is bounded by `SIZE_CAP`.

- [ ] **Step 1: Write the failing test**
```php
public function test_size_matches_content_length_and_is_capped(): void
{
    $fs = new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    $sawFile = false;
    foreach ($fs->list('/srv/app') as $node) {
        if ($node->isFile()) {
            $sawFile = true;
            self::assertLessThanOrEqual(65536, $node->size);
            self::assertSame($node->size, strlen($fs->read('/srv/app/' . $node->name)));
        }
    }
    self::assertTrue($sawFile, '/srv/app should contain at least one file');
}
public function test_read_is_deterministic(): void
{
    $mk = fn() => new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    $file = null;                                   // anchor to a real generated file under a scaffold dir
    foreach ($mk()->list('/srv/app') as $n) { if ($n->isFile()) { $file = $n->name; break; } }
    self::assertNotNull($file);
    self::assertSame($mk()->read('/srv/app/' . $file), $mk()->read('/srv/app/' . $file));
}
```
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** `read`/`stat` per the contract above: `read()` validates via the resolver, rejects a directory with the `IsADirectory` guard, else regenerates exactly `size` bytes from the file's `nodeSeed` block stream (printable-mapped for text extensions); `stat()` returns the file's Node (size already drawn in `list()`). Never call the content generator from `list()`.
- [ ] **Step 4: Run → PASS.**
- [ ] **Step 5: Commit** — `git add -p && git commit -m "feat(fs): coherent bounded file content (size==strlen invariant)"`

### Task 7: Pinned/curated layer

**Files:**
- Create: `src/Shell/Fs/PinnedNodes.php`
- Modify: `src/Shell/Fs/FakeFilesystem.php` (resolve pinned before procedural)
- Test: `tests/Shell/Fs/PinnedNodesTest.php`

**Interfaces:**
- Produces: `PinnedNodes::forRole(string $role, string $hostSeedBytes): array` (path → Node|content closure) covering `/etc/passwd`, `/etc/shadow`, `/etc/hostname`, `/etc/os-release`, OS-standard symlinks. Pinned content still seeded per host (no shared literals). Precedence: pinned ∪ procedural, pinned wins on conflict; pinned dirs merge their children into the procedural listing.
- [ ] Steps: test that `/etc/passwd` exists, is pinned (stable), lists under `/etc`, and is not a generic procedural file; implement; PASS; commit `feat(fs): pinned curated nodes layer`.

### Task 8: Session overlay layer (purity invariant)

**Files:**
- Create: `src/Shell/Fs/Overlay.php`
- Modify: `src/Shell/Fs/FakeFilesystem.php` (accept overlay; resolve overlay ▸ pinned ∪ procedural)
- Test: `tests/Shell/Fs/OverlayTest.php`

**Interfaces:**
- Produces: `Overlay` — immutable-style: `withFile(path,bytes): Overlay`, `withDir(path): Overlay`, `withRemoved(path): Overlay`, `withMove(from,to): Overlay`; `toArray()/fromArray()` for the store. `FakeFilesystem::withOverlay(Overlay): self`.
- **Purity invariant (tested):** applying an overlay entry at path X never changes generation (name OR any Node field) at any other path Y.
- **Ordering invariant (tested):** overlay-created entries are APPENDED after the base listing; base entries keep their base `list()` order (Task 5). Tombstoned entries are filtered out in place.

- [ ] **Step 1: Failing test**
```php
public function test_overlay_reflects_writes_without_perturbing_siblings(): void
{
    $base = new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    $siblingsBefore = $base->list('/tmp');                       // full Node objects
    $fs = $base->withOverlay((new Overlay())->withFile('/tmp/pwned.sh', "#!/bin/sh\n"));
    self::assertTrue($fs->exists('/tmp/pwned.sh'));
    self::assertSame("#!/bin/sh\n", $fs->read('/tmp/pwned.sh'));
    // siblings unchanged in name AND all fields AND order (new entry appended last):
    $after = $fs->list('/tmp');
    $afterSansNew = array_values(array_filter($after, fn($n) => $n->name !== 'pwned.sh'));
    self::assertEquals($siblingsBefore, $afterSansNew);
    self::assertSame('pwned.sh', end($after)->name);
}
public function test_remove_tombstones(): void
{
    $base = new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    $victim = $base->list('/var')[0]->name;
    $fs = $base->withOverlay((new Overlay())->withRemoved('/var/' . $victim));
    self::assertFalse($fs->exists('/var/' . $victim));
    self::assertFalse($fs->isValidChild('/var', $victim));       // isValidChild honours the tombstone
}
```
- [ ] **Steps 2-5:** implement overlay as a sparse full-path map applied at resolve time — it never feeds `key()`/`nodeSeed` (so it can't perturb any other path); overlay-created entries append after base children (preserving base order); tombstones filter matching base/overlay entries; `read()` returns overlay bytes for overlaid files. PASS; commit `feat(fs): session overlay layer (purity + ordering invariants)`.

### Task 9: Secret bootstrap (persist-once)

**Files:**
- Create: `src/Shell/Fs/HostSecret.php`
- Test: `tests/Shell/Fs/HostSecretTest.php`

**Interfaces:**
- Produces: `HostSecret::resolve(string $storageDir): string` — returns env `FUNNYPOT_FS_SECRET` if set; else reads `<storageDir>/fs_secret`; else generates 32 random bytes (`random_bytes`), writes them 0600, returns them. Idempotent (second call returns the same bytes).
- [ ] **Steps:** test with a temp dir that two calls return identical bytes and a file is created; implement; PASS; commit `feat(fs): persist-once host secret`.

### Task 10: Engine fingerprint-safety provider rows

**Files:**
- Modify: `tests/App/FingerprintSafetyTest.php` (add engine provider rows)
- Test: same file.

**Interfaces:**
- Consumes: the data-provider + `assertClean()`/denylist loader already in `FingerprintSafetyTest`.
- [ ] **Steps:** add provider cases that render engine output — an `ls -la`-shaped listing string built from `FakeFilesystem::list('/root')`, a listing at depth, and a generated file's `read()` — and `assertClean()` each against `resources/app-fingerprint-denylist.php`. Run → PASS. Commit `test(fs): fingerprint-safety rows for engine output`.

### Phase 1 exit criteria
`php vendor/bin/phpunit` green (incl. all new `tests/Shell/Fs/*` + the fingerprint rows); no changes outside `src/Shell/Fs/`, `resources/fs-pools.php`, `tests/Shell/Fs/`, `tests/App/FingerprintSafetyTest.php`; determinism/list==validate/overlay-purity/depth-cap invariants all covered.

---

## Phases 2–6 — outline (fully fleshed against real interfaces as each predecessor lands)

Each becomes its own detailed plan (spec §Phasing) once Phase 1's real signatures exist. Summary so the whole arc is visible:

- **Phase 2 — `HostFacts`** (`src/Shell/Host/HostFacts.php`): wrap `ServerProfile::fromSeed($identitySeed)`; add process table (read-only reuse of `MinerRig::fromSeed()->summary()` + `FakeCron::fromSeed()->processes([...])` — the same generators `ProcessesSection` uses), `/proc/{cpuinfo,meminfo,loadavg,uptime,version,self}` + numeric PID dirs, `df` mounts, `netstat` sockets, `passwd`/uid map. **This-box host: `$identitySeed = personaSeed`** (so panel/shell/fleet `ps` agree — fable residual #1); FS content keys always fold the secret. Coherence tests: fleet number == shell `free`/`df`/`ps`. **Two seed spaces (state explicitly):** the this-box `HostFacts` feeds the INT `personaSeed` to `ServerProfile::fromSeed(int)`, while the FS is built with `hostSeedBytes = Draw::seed($secret . "\0" . $personaSeed . "\0" . $role)` — never pass the int `personaSeed` where raw `hostSeedBytes` is expected. Reuse is read-only: `MinerRig::summary()` and `FakeCron::processes(array $miner=[])` are public (verified) — do not edit them (Agent B WIP).
- **Phase 3 — `ShellInterpreter` + SSH/telnet refactor** (`src/Shell/ShellInterpreter.php`, `ShellSession` iface; modify `src/Protocol/Shell/FakeShell.php`, `src/Protocol/ProtocolEmulator.php`, `src/Protocol/Ssh/SshConnection.php`): two-tier dispatch, broad command set, writes→overlay, `du/df/$?/history/pipes/perms//proc`, fail-loud, pacing metadata; thread the host-identity seed into `FakeShell` (today seedless); per-user `/home/<dept>/<user>` from `Org`. No SSH/telnet regressions; shell fingerprint rows; scanner-in-the-loop.
- **Phase 4 — Fleet console** (`src/App/Render/Panel/FleetSection.php` + `src/App/Render/Fake/Fleet.php`; register in `PanelRegistry` + nav slug): fleet + detail views from `HostFacts` per host, INERT actions, Console POST-launcher button, per-host seeds + "this-box" designation, persona-company breadcrumbs (not the base hardcode). Fleet fingerprint rows.
- **Phase 5 — Streaming web terminal** (`src/App/Http/ConsoleRouter.php` wired in `src/App/Http/Router.php` `public()`+`stealth()` as a POST sibling of `AiApiRouter`; reuse `src/App/AiApi/StreamEmitter.php`; `src/App/Shell/ConsoleSessionStore.php` = SQLite overlay store on the data volume, keyed by an HMAC'd opaque cookie e.g. `sid`; bounded entries+bytes + TTL + LRU):
  - **Status:** BUILT + MULTI-AGENT REVIEWED (review workflow `w2enhj7zu`, 19 agents, 10 confirmed fixes landed in working tree).
  - **Key fixes applied:**
    1. Overlay ENOSPC-style byte-budget cap (256 KiB ceiling) preventing unbounded memory growth.
    2. Non-string coercion for host/command avoiding PHP string warnings.
    3. Reload coherence: dynamic empty POST prompt fetching on client refresh.
    4. Stopped/offline host connect failure handling (`ssh: connect to host ... Connection refused/No route`) + console button gating.
    5. Lazy `ConsoleSessionStore` opening inside fault guard.
    6. Console emitter delay set to 0 (no FPM worker hold).
    7. Clean session exit/logout deletes store row and prints disconnect notice.
    8. Output cap aligned with `FakeShell` (8192 bytes).
    9. Hostname deduplication in `Fleet::fromSeed()` ensuring unique fleet hostnames across all 24 seeds.
  - **Unit tests:** `ConsoleRouterTest` (12 tests), `OverlayTest` (8 tests), `FleetSectionTest` (4 tests) passing.

- **Phase 6 — Procedural Endless Throttled Backup-Download Bait (FP-0051)**:
  - **Spec:** `funnypot/docs/superpowers/specs/2026-08-25-endless-download-design.md` (operator approved).
  - **Status:** BUILT (`AppConfig` knobs + `DownloadRouter` + `sw.js` + `FleetSection` button + Router
    mount, GET-only + gate-exempt + off-disablable). Tests: `AppConfigTest` (+2), `DownloadRouterTest`
    (9). `node --check` clean on `sw.js`. Deviation: download button rendered unconditionally (feature
    gated at the Router mount layer, not in the deep-nested panel section) — see FP-0051 notes.
  - **Architecture:**
    - `AppConfig`: Central configuration knobs (`FUNNYPOT_ENDLESS_DOWNLOAD` default ON, chunk size 100–200 KB, interval 100ms, vary 50%, ease period 20s, fallback cap 50MB) with bounds clamping.
    - `FleetSection`: "Download latest backup" button + scoped JS registering Service Worker `/__dl/sw.js`. On click pings `/__dl/manifest` (logs `event=download`) and triggers download of `/__dl/backup.zip`.
    - `DownloadRouter`: Gate-exempt POST/GET sibling handling `/__dl/sw.js` (application/javascript with `Service-Worker-Allowed: /`), `/__dl/manifest` (JSON seed/files/throttle info), and `/__dl/backup.zip` (non-JS server-side capped fallback; the bare `/backup.zip` stays honeypot surface so its scanners are still reported).
    - Service Worker `src/App/Download/sw.js`: Intercepts `/__dl/backup.zip` and serves a `ReadableStream` emitting endless ZIP local file headers with procedural store-method bytes throttled by a sine-eased breathing formula ($\sim 1\text{--}2\text{ MB/s}$).
    - Intel: Logs hit `event=download` on manifest fetch or fallback download.
    - Safety: Cancelable, non-bomb (CFAA safe), never 500s.

## Self-review (Phases 1–5)
- **Spec coverage:** engine (§Component 1) fully covered by Tasks 1–9; HostFacts/HostIdentity unified; FakeShell live-wired; Fleet console & Streaming web terminal built and multi-agent reviewed; Endless download bait specced and ready.
- **Invariants enforced:** Purity, determinism, never-500, output bounds, fingerprint safety against denylist.

