<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The persisted install master: exactly 32 private CSPRNG bytes, created once per install and never
 * rotated, repaired, replaced or approximated by this code. Serialized as ONE line —
 * `funnypot-install-secret-v1:` + 43 unpadded base64url characters + LF — beneath the private 0700
 * identity directory as a 0600 regular file with link count one.
 *
 * Creation is crash-safe and race-safe: an exclusive lock, an O_EXCL 0600 temp in the same
 * directory, a full write + flush + native fsync, then publication with `link(temp, master)` — which
 * is atomic and FAILS if the master already exists (PHP's rename would silently overwrite) — followed
 * by a directory fsync, the temp unlink and a second directory fsync, and a read-back. Before the
 * link no master is accepted (an orphan temp is never mistaken for one); after it the linked file is
 * authoritative, and the only recovery ever performed is removing a leftover SAME-INODE temp so the
 * link count returns to one. Any other shape — a symlink, a FIFO, a wrong owner/mode, a second hard
 * link to a different inode, malformed or all-zero content, mutation during read — fails closed.
 */
final class InstallSecretStore
{
    public const PREFIX = 'funnypot-install-secret-v1:';
    public const MASTER_BYTES = 32;

    private const ENCODED_LEN = 43;
    private const MAX_READ = 256;
    private const LOCK_WAIT_MS = 5000;
    private const LOCK_POLL_MS = 10;

    private const S_IFMT = 0170000;
    private const S_IFDIR = 0040000;
    private const S_IFREG = 0100000;

    /** Source classes a resolution reports. */
    public const SOURCE_PERSISTED = 'persisted';
    public const SOURCE_GENERATED = 'generated';

    /** Warning codes (never failures). */
    public const WARN_ORPHAN_TEMP = 'orphan-temp-present';

    /** @var list<string> warning codes raised by the last resolution */
    private array $warnings = [];

    public function __construct(private IdentityPaths $paths, private IdentityFileOps $ops)
    {
        if (!$this->ops->supportsFsync()) {
            throw IdentityBootstrapException::withCode('runtime-fsync-unavailable', IdentityBootstrapException::REMEDY_RUNTIME);
        }
    }

    // --- canonical format ---------------------------------------------------------------------------

    public static function serialize(string $master): string
    {
        if (strlen($master) !== self::MASTER_BYTES) {
            throw IdentityBootstrapException::withCode('master-length', IdentityBootstrapException::REMEDY_CONFIG);
        }

        return self::PREFIX . sodium_bin2base64($master, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) . "\n";
    }

    /**
     * Strict inverse of {@see serialize()}: the exact prefix, exactly 43 base64url characters that
     * decode to 32 bytes, one trailing LF, nothing else. Individual zero bytes are valid; the all-zero
     * value is not. $code lets the caller name the input (env, file, persisted) in the failure.
     */
    public static function parse(string $text, string $code = 'master'): string
    {
        $expectedLen = strlen(self::PREFIX) + self::ENCODED_LEN + 1;
        if (strlen($text) !== $expectedLen
            || !str_starts_with($text, self::PREFIX)
            || $text[$expectedLen - 1] !== "\n") {
            throw IdentityBootstrapException::withCode($code . '-malformed', IdentityBootstrapException::REMEDY_CONFIG);
        }
        $encoded = substr($text, strlen(self::PREFIX), self::ENCODED_LEN);
        if (preg_match('/^[A-Za-z0-9_-]{43}$/', $encoded) !== 1) {
            throw IdentityBootstrapException::withCode($code . '-malformed', IdentityBootstrapException::REMEDY_CONFIG);
        }
        try {
            $raw = sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException $e) {
            throw IdentityBootstrapException::withCode($code . '-malformed', IdentityBootstrapException::REMEDY_CONFIG);
        }
        if (strlen($raw) !== self::MASTER_BYTES) {
            throw IdentityBootstrapException::withCode($code . '-malformed', IdentityBootstrapException::REMEDY_CONFIG);
        }
        if ($raw === str_repeat("\0", self::MASTER_BYTES)) {
            throw IdentityBootstrapException::withCode($code . '-all-zero', IdentityBootstrapException::REMEDY_CONFIG);
        }

        return $raw;
    }

    /** @return list<string> */
    public function warnings(): array
    {
        return $this->warnings;
    }

    // --- persistent resolution ---------------------------------------------------------------------

    /**
     * Create the private directories if absent (never repairing an unsafe pre-placed one), take the
     * lock, then read the persisted master or create it once.
     *
     * @return array{0:string,1:string} [master bytes, source class]
     */
    public function resolveOrCreate(): array
    {
        $this->ensurePrivateDirectories();
        $lock = $this->acquireLock();
        try {
            return $this->resolveOrCreateLocked();
        } finally {
            $this->releaseLock($lock);
        }
    }

    /**
     * The exclusive install lock, held by the preparer across its WHOLE transaction (master, TLS
     * generation, manifest, bundles) so concurrent preparers serialize on every persistent artifact,
     * not just the master. flock() is per open file description, so a holder must call
     * {@see resolveOrCreateLocked()} rather than {@see resolveOrCreate()}.
     *
     * @return resource
     */
    public function acquireLock()
    {
        $lock = $this->openLock();
        $this->acquire($lock);

        return $lock;
    }

    /** @param resource $lock */
    public function releaseLock($lock): void
    {
        $this->ops->flock($lock, LOCK_UN);
        $this->ops->close($lock);
    }

    /**
     * Read the persisted master or create it once. The caller holds {@see acquireLock()}.
     *
     * @return array{0:string,1:string} [master bytes, source class]
     */
    public function resolveOrCreateLocked(): array
    {
        $this->warnings = [];
        $temp = null;
        try {
            $existing = $this->readPersisted();
            if ($existing !== null) {
                return [$existing, self::SOURCE_PERSISTED];
            }
            $master = $this->ops->randomBytes(self::MASTER_BYTES);
            if ($master === str_repeat("\0", self::MASTER_BYTES)) {
                throw IdentityBootstrapException::withCode('master-generate', IdentityBootstrapException::REMEDY_RUNTIME);
            }
            $temp = $this->paths->tempPath($this->ops->randomHex(8));
            $this->publish($temp, self::serialize($master));
            $temp = null; // published + unlinked; nothing of this attempt is left to clean

            $back = $this->readPersisted();
            if ($back !== $master) {
                throw IdentityBootstrapException::withCode('master-readback', IdentityBootstrapException::REMEDY_STORAGE);
            }

            return [$master, self::SOURCE_GENERATED];
        } finally {
            if ($temp !== null) {
                $this->ops->unlink($temp); // only THIS attempt's temp, never anything else
            }
        }
    }

    /**
     * The two private components beneath the trusted storage mount, created 0700 when absent and
     * validated (never repaired) when present. Also called by the preparer on the explicit-master
     * path, which writes a manifest and TLS material here without ever creating a master file.
     */
    public function ensurePrivateDirectories(): void
    {
        $root = $this->paths->storageRoot();
        $st = $this->ops->lstat($root);
        if ($st === false) {
            throw IdentityBootstrapException::withCode('storage-root-missing', IdentityBootstrapException::REMEDY_STORAGE);
        }
        foreach ([$this->paths->privateRoot(), $this->paths->persistentRoot()] as $dir) {
            $st = $this->ops->lstat($dir);
            if ($st === false) {
                if (!$this->ops->mkdir($dir, 0700) || !$this->ops->chmod($dir, 0700)) {
                    // Lost a mkdir race, or truly unwritable: re-lstat decides.
                    $st = $this->ops->lstat($dir);
                    if ($st === false) {
                        throw IdentityBootstrapException::withCode('private-dir-create', IdentityBootstrapException::REMEDY_STORAGE);
                    }
                } else {
                    $st = $this->ops->lstat($dir);
                    if ($st === false) {
                        throw IdentityBootstrapException::withCode('private-dir-create', IdentityBootstrapException::REMEDY_STORAGE);
                    }
                }
            }
            $mode = (int) $st['mode'];
            if (($mode & self::S_IFMT) !== self::S_IFDIR
                || (int) $st['uid'] !== $this->ops->euid()
                || ($mode & 0077) !== 0) {
                throw IdentityBootstrapException::withCode('private-dir-unsafe', IdentityBootstrapException::REMEDY_STORAGE);
            }
        }
    }

    /** @return resource */
    private function openLock()
    {
        $path = $this->paths->lockPath();
        $st = $this->ops->lstat($path);
        $h = false;
        if ($st === false) {
            $h = $this->ops->openExclusive($path);
            if ($h === false) {
                $st = $this->ops->lstat($path); // lost the create race: adopt the winner's lock file
            }
        }
        if ($h === false) {
            if ($st === false) {
                throw IdentityBootstrapException::withCode('lock-create', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $this->requireOwnedRegular($st, 0600, 'lock');
            $h = $this->ops->openRead($path);
            if ($h === false) {
                throw IdentityBootstrapException::withCode('lock-open', IdentityBootstrapException::REMEDY_STORAGE);
            }
        }
        $lst = $this->ops->lstat($path);
        $fst = $this->ops->fstat($h);
        if ($lst === false || $fst === false || !$this->sameInode($lst, $fst)) {
            $this->ops->close($h);
            throw IdentityBootstrapException::withCode('lock-changed', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $this->requireOwnedRegular($fst, 0600, 'lock');

        return $h;
    }

    /** @param resource $lock */
    private function acquire($lock): void
    {
        $waited = 0;
        while (!$this->ops->flock($lock, LOCK_EX | LOCK_NB)) {
            if ($waited >= self::LOCK_WAIT_MS) {
                $this->ops->close($lock);
                throw IdentityBootstrapException::withCode('lock-timeout', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $this->ops->sleepMs(self::LOCK_POLL_MS);
            $waited += self::LOCK_POLL_MS;
        }
    }

    /**
     * Read + validate the persisted master under the lock; null when absent. A link count of two is
     * the one recognised crash shape (published, temp not yet unlinked) and is repaired only by
     * removing a same-inode temp.
     */
    private function readPersisted(): ?string
    {
        $path = $this->paths->masterPath();
        $st = $this->ops->lstat($path);
        if ($st === false) {
            return null;
        }
        $this->requireOwnedRegular($st, 0600, 'master');
        if ((int) $st['nlink'] === 2) {
            $this->recoverSameInodeTemp($st);
            $st = $this->ops->lstat($path);
            if ($st === false) {
                throw IdentityBootstrapException::withCode('master-changed', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $this->requireOwnedRegular($st, 0600, 'master');
        }
        if ((int) $st['nlink'] !== 1) {
            throw IdentityBootstrapException::withCode('master-link-count', IdentityBootstrapException::REMEDY_STORAGE);
        }

        $h = $this->ops->openRead($path);
        if ($h === false) {
            throw IdentityBootstrapException::withCode('master-open', IdentityBootstrapException::REMEDY_STORAGE);
        }
        try {
            $fst = $this->ops->fstat($h);
            if ($fst === false || !$this->sameIdentity($st, $fst)) {
                throw IdentityBootstrapException::withCode('master-changed', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $text = $this->ops->readAll($h, self::MAX_READ);
            if ($text === false) {
                throw IdentityBootstrapException::withCode('master-read', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $fst2 = $this->ops->fstat($h);
            if ($fst2 === false || !$this->sameIdentity($st, $fst2) || (int) $fst2['size'] !== strlen($text)) {
                throw IdentityBootstrapException::withCode('master-changed', IdentityBootstrapException::REMEDY_STORAGE);
            }
        } finally {
            $this->ops->close($h);
        }

        return self::parse($text, 'master');
    }

    /** @param array<string,int> $master lstat of the published master (nlink == 2) */
    private function recoverSameInodeTemp(array $master): void
    {
        $dir = $this->paths->persistentRoot();
        $names = $this->ops->scandir($dir);
        if ($names === false) {
            throw IdentityBootstrapException::withCode('master-link-count', IdentityBootstrapException::REMEDY_STORAGE);
        }
        foreach ($names as $name) {
            if (!str_starts_with($name, IdentityPaths::TEMP_PREFIX)) {
                continue;
            }
            $p = $dir . '/' . $name;
            $st = $this->ops->lstat($p);
            if ($st === false) {
                continue;
            }
            $mode = (int) $st['mode'];
            $same = (int) $st['dev'] === (int) $master['dev'] && (int) $st['ino'] === (int) $master['ino'];
            if ($same && ($mode & self::S_IFMT) === self::S_IFREG && (int) $st['uid'] === $this->ops->euid() && ($mode & 0777) === 0600) {
                if (!$this->ops->unlink($p)) {
                    throw IdentityBootstrapException::withCode('master-temp-unlink', IdentityBootstrapException::REMEDY_STORAGE);
                }
                $this->fsyncDir();
            } else {
                // A different inode is not ours to judge: report it, never delete it.
                $this->warnings[] = self::WARN_ORPHAN_TEMP;
            }
        }
    }

    /** Write, durably persist and atomically publish the canonical bytes; then unlink the temp. */
    private function publish(string $temp, string $bytes): void
    {
        $h = $this->ops->openExclusive($temp);
        if ($h === false) {
            throw IdentityBootstrapException::withCode('master-temp-create', IdentityBootstrapException::REMEDY_STORAGE);
        }
        try {
            $n = $this->ops->write($h, $bytes);
            if ($n !== strlen($bytes)) {
                throw IdentityBootstrapException::withCode('master-write-short', IdentityBootstrapException::REMEDY_STORAGE);
            }
            if (!$this->ops->flush($h)) {
                throw IdentityBootstrapException::withCode('master-flush', IdentityBootstrapException::REMEDY_STORAGE);
            }
            if (!$this->ops->fsync($h)) {
                throw IdentityBootstrapException::withCode('master-fsync', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $fst = $this->ops->fstat($h);
            if ($fst === false || (int) $fst['size'] !== strlen($bytes) || (int) $fst['nlink'] !== 1) {
                throw IdentityBootstrapException::withCode('master-temp-unsafe', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $this->requireOwnedRegular($fst, 0600, 'master-temp');
        } finally {
            $this->ops->close($h);
        }

        if (!$this->ops->link($temp, $this->paths->masterPath())) {
            throw IdentityBootstrapException::withCode('master-link', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $this->fsyncDir();
        if (!$this->ops->unlink($temp)) {
            throw IdentityBootstrapException::withCode('master-temp-unlink', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $this->fsyncDir();
    }

    private function fsyncDir(): void
    {
        $d = $this->ops->openDir($this->paths->persistentRoot());
        if ($d === false) {
            throw IdentityBootstrapException::withCode('directory-fsync', IdentityBootstrapException::REMEDY_STORAGE);
        }
        try {
            if (!$this->ops->fsync($d)) {
                throw IdentityBootstrapException::withCode('directory-fsync', IdentityBootstrapException::REMEDY_STORAGE);
            }
        } finally {
            $this->ops->close($d);
        }
    }

    /** @param array<string,int> $st */
    private function requireOwnedRegular(array $st, int $exactMode, string $what): void
    {
        $mode = (int) $st['mode'];
        if (($mode & self::S_IFMT) !== self::S_IFREG) {
            throw IdentityBootstrapException::withCode($what . '-not-regular', IdentityBootstrapException::REMEDY_STORAGE);
        }
        if ((int) $st['uid'] !== $this->ops->euid()) {
            throw IdentityBootstrapException::withCode($what . '-owner', IdentityBootstrapException::REMEDY_STORAGE);
        }
        if (($mode & 0777) !== $exactMode) {
            throw IdentityBootstrapException::withCode($what . '-mode', IdentityBootstrapException::REMEDY_STORAGE);
        }
    }

    /** @param array<string,int> $a @param array<string,int> $b */
    private function sameInode(array $a, array $b): bool
    {
        return (int) $a['dev'] === (int) $b['dev'] && (int) $a['ino'] === (int) $b['ino'];
    }

    /** dev/ino/mode/uid/nlink — the full identity an fstat must reproduce. @param array<string,int> $a @param array<string,int> $b */
    private function sameIdentity(array $a, array $b): bool
    {
        return $this->sameInode($a, $b)
            && (int) $a['mode'] === (int) $b['mode']
            && (int) $a['uid'] === (int) $b['uid']
            && (int) $a['nlink'] === (int) $b['nlink'];
    }
}
