<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\InstallSecretStore;
use Funnypot\App\Identity\ServiceProfileIdentity;
use Funnypot\App\Service\ServiceCapabilityPolicy;
use Funnypot\App\Service\ServiceCatalog;
use Funnypot\App\Service\ServiceProfilePreparer;
use Funnypot\App\Service\ServicePaths;
use Funnypot\App\Service\ServiceProfileStore;
use Funnypot\App\Service\ServiceSqlite;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

/**
 * The permission contract of the PHP-writable desired store. The root preflight must leave a store the
 * unprivileged web tier can actually reach: the shared .funnypot parent traverse-only (0711), the
 * desired store its own 2770 root:www-data setgid directory, the db (and its -wal/-shm sidecars)
 * 0660 root:www-data, while the root-only persistent tree and identity subtree stay fully private. The
 * missing chgrp/traverse is why the shipped admin apply path could not open the store.
 *
 * Root/built-image semantics are exercised on any host through the IdentityFileOps euid seam: a fake
 * ops reports euid 0 and a www-data group, and records the chgrp/chmod the code would issue as root.
 */
final class ServiceProfileStorePermissionsTest extends TestCase
{
    private const WWW_DATA_GID = 33;

    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-sps-perm-' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/storage', 0777, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    /** A fake root: euid 0, a resolvable www-data group, and a record of every chgrp/chmod issued. */
    private function rootOps(): IdentityFileOps
    {
        return new class (self::WWW_DATA_GID) extends IdentityFileOps {
            /** @var array<string,int> path => gid */
            public array $chgrps = [];
            /** @var array<string,int> path => mode */
            public array $chmods = [];

            public function __construct(private int $wwwDataGid)
            {
            }

            public function euid(): int
            {
                return 0;
            }

            public function groupByName(string $name): ?array
            {
                return $name === 'www-data' ? ['name' => 'www-data', 'gid' => $this->wwwDataGid, 'members' => []] : null;
            }

            public function chgrp(string $path, int $gid): bool
            {
                // Record only: a non-root test process cannot really give a file to www-data.
                $this->chgrps[$path] = $gid;

                return true;
            }

            public function chmod(string $path, int $mode): bool
            {
                $this->chmods[$path] = $mode;

                return parent::chmod($path, $mode);
            }
        };
    }

    private function paths(): ServicePaths
    {
        return ServicePaths::forStorage($this->dir . '/storage', $this->dir . '/run', $this->dir . '/status');
    }

    private function preparer(ServicePaths $paths, IdentityFileOps $ops): ServiceProfilePreparer
    {
        return new ServiceProfilePreparer(
            $paths,
            ServiceCatalog::fromPackage(),
            ServiceProfileIdentity::fromDeriver(IdentityTestSupport::deriver('perm')),
            ServiceCapabilityPolicy::create('deploy', ['docker' => false]),
            'deploy',
            'exact',
            'fpph1_' . str_repeat('f', 64),
            $ops,
            null,
            static fn (string $k) => false,
        );
    }

    private static function perms(string $path): int
    {
        clearstatcache(true, $path);

        return fileperms($path) & 07777;
    }

    public function testPreflightLeavesATraversableParentAndAGroupSharedDesiredDir(): void
    {
        $paths = $this->paths();
        $ops = $this->rootOps();
        $this->preparer($paths, $ops)->prepare();

        // The shared parent is traverse-only so www-data can reach the desired store beneath it, but
        // carries no group/other read or write bit.
        self::assertSame(0711, self::perms($paths->privateRoot()));
        // The root-only persistent tree stays fully private.
        self::assertSame(0700, self::perms($paths->persistentDir()));

        // The desired store is its own setgid directory, group-owned by www-data.
        self::assertSame(02770, self::perms($paths->desiredStoreDir()), 'setgid + rwxrws--- expected');
        self::assertArrayHasKey($paths->desiredStoreDir(), $ops->chgrps);
        self::assertSame(self::WWW_DATA_GID, $ops->chgrps[$paths->desiredStoreDir()]);

        // The db itself is 0660 root:www-data.
        self::assertFileExists($paths->desiredDbPath());
        self::assertArrayHasKey($paths->desiredDbPath(), $ops->chgrps);
        self::assertSame(self::WWW_DATA_GID, $ops->chgrps[$paths->desiredDbPath()]);
        self::assertSame(0660, $ops->chmods[$paths->desiredDbPath()] ?? -1);
    }

    public function testDesiredDbAndWalSidecarsBecomeGroupSharedWhenRoot(): void
    {
        // The setgid parent closes the sidecar race, but the opener also re-applies group/mode to any
        // existing -wal/-shm so a sidecar created earlier under a root open cannot lock www-data out.
        $dbDir = $this->dir . '/storage/svc';
        mkdir($dbDir, 02770, true);
        $db = $dbDir . '/service-profile.sqlite';

        // A first live connection creates the real WAL sidecars; keep it open so they persist.
        $keepOpen = ServiceSqlite::open($db, 0660, 'www-data', $this->rootOps());
        $keepOpen->exec('CREATE TABLE t (x INTEGER)');
        $keepOpen->exec('INSERT INTO t (x) VALUES (1)');

        // A second open now sees db + -wal + -shm and re-applies group/mode to all of them.
        $ops = $this->rootOps();
        ServiceSqlite::open($db, 0660, 'www-data', $ops);

        foreach ([$db, $db . '-wal', $db . '-shm'] as $f) {
            self::assertFileExists($f);
            self::assertArrayHasKey($f, $ops->chgrps, $f . ' must be chgrp-ed');
            self::assertSame(self::WWW_DATA_GID, $ops->chgrps[$f]);
            self::assertSame(0660, $ops->chmods[$f] ?? -1, $f . ' must be 0660');
        }
    }

    public function testIdentityToleratesTheTraversableSharedParentButNotAReadableOne(): void
    {
        // The services preflight widens .funnypot to 0711; identity, which reruns every container start
        // and guards the same parent, must accept the traverse bit yet still reject any read/write bit.
        $paths = $this->paths();
        $this->preparer($paths, $this->rootOps())->prepare();
        self::assertSame(0711, self::perms($paths->privateRoot()));

        $idPaths = IdentityPaths::forStorage($this->dir . '/storage', $this->dir . '/id-run');
        $store = new InstallSecretStore($idPaths, new IdentityFileOps());
        $store->ensurePrivateDirectories(); // must NOT throw on a 0711 shared parent

        // The identity subtree beneath it stays fully private.
        self::assertSame(0700, self::perms($idPaths->persistentRoot()));

        // A parent that also exposes read/other bits is still rejected.
        chmod($paths->privateRoot(), 0755);
        $threw = false;
        try {
            $store->ensurePrivateDirectories();
        } catch (\Funnypot\App\Identity\IdentityBootstrapException $e) {
            $threw = $e->errorCode() === 'private-dir-unsafe';
        }
        self::assertTrue($threw, 'a group/other-readable .funnypot must be rejected');
    }
}
