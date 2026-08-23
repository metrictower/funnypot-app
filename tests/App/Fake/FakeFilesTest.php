<?php
declare(strict_types=1);
namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FakeFiles;
use PHPUnit\Framework\TestCase;

final class FakeFilesTest extends TestCase
{
    public function test_is_deterministic_for_same_seed(): void
    {
        $a = FakeFiles::fromSeed(4242)->listing('/home/x/public_html');
        $b = FakeFiles::fromSeed(4242)->listing('/home/x/public_html');
        self::assertSame($a, $b);
    }

    public function test_differs_across_seeds(): void
    {
        $a = FakeFiles::fromSeed(1)->dirs();
        $b = FakeFiles::fromSeed(99999)->dirs();
        self::assertNotSame($a, $b, 'the frozen home user should vary across seeds');
    }

    public function test_dirs_are_the_fixed_coherent_set(): void
    {
        $ff = FakeFiles::fromSeed(7);
        $dirs = $ff->dirs();
        self::assertCount(4, $dirs);
        // The home user is reused between the dir list and its own entry-set — one coherent tree.
        self::assertMatchesRegularExpression('#^/home/[a-z0-9]+/public_html$#', $dirs[0]);
        self::assertContains('/backups', $dirs);
        self::assertContains('/var/backups', $dirs);
        self::assertContains('/root/.ssh', $dirs);
    }

    public function test_entry_shape_and_types(): void
    {
        foreach (FakeFiles::fromSeed(123)->listing('/home/x/public_html') as $row) {
            self::assertSame(
                ['name', 'size', 'modified', 'perms', 'owner', 'isDir', 'isDownload'],
                array_keys($row)
            );
            self::assertIsString($row['name']);
            self::assertIsString($row['size']);
            self::assertIsString($row['perms']);
            self::assertIsString($row['owner']);
            self::assertIsBool($row['isDir']);
            self::assertIsBool($row['isDownload']);
            self::assertMatchesRegularExpression('/^2026-\d{2}-\d{2} \d{2}:\d{2}$/', $row['modified']);
            self::assertMatchesRegularExpression('/^0[0-7]{3}$/', $row['perms']);
            self::assertNotSame('', $row['owner']);
        }
    }

    public function test_credential_decoys_appear(): void
    {
        $names = array_column(FakeFiles::fromSeed(55)->listing('/home/x/public_html'), 'name');
        foreach (['.env', '.env.bak', 'wp-config.php.bak', 'id_rsa', 'credentials.txt', 'backup.zip', 'database.sql.gz', 'OLD_site_do_not_delete.tar.gz'] as $decoy) {
            self::assertContains($decoy, $names, "decoy $decoy should be listed");
        }
    }

    public function test_ssh_dir_lists_key_material(): void
    {
        $names = array_column(FakeFiles::fromSeed(8)->listing('/root/.ssh'), 'name');
        self::assertContains('id_rsa', $names);
        self::assertContains('id_ed25519', $names);
        self::assertContains('authorized_keys', $names);
    }

    public function test_downloadables_are_flagged(): void
    {
        $rows = [];
        foreach (FakeFiles::fromSeed(3)->listing('/home/x/public_html') as $r) {
            $rows[$r['name']] = $r;
        }
        // Archives and private keys route to the decoy handler.
        self::assertTrue($rows['backup.zip']['isDownload']);
        self::assertTrue($rows['database.sql.gz']['isDownload']);
        self::assertTrue($rows['OLD_site_do_not_delete.tar.gz']['isDownload']);
        self::assertTrue($rows['id_rsa']['isDownload']);
        self::assertTrue($rows['wp-config.php.bak']['isDownload']);
        // Text lures and dirs render in place, not as downloads.
        self::assertFalse($rows['.env']['isDownload']);
        self::assertFalse($rows['credentials.txt']['isDownload']);
        self::assertFalse($rows['wp-content']['isDownload']);
    }

    public function test_directories_are_marked_isdir(): void
    {
        foreach (FakeFiles::fromSeed(11)->listing('/home/x/public_html') as $r) {
            if (in_array($r['name'], ['wp-admin', 'wp-content', 'wp-includes', '.git', '.aws'], true)) {
                self::assertTrue($r['isDir'], $r['name'] . ' should be a directory');
                self::assertFalse($r['isDownload']);
            }
        }
    }
}
