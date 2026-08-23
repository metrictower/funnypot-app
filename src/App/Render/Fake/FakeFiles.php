<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT fake web-file-manager tree for the admin-panel skins — the credential-decoy
 * bait that makes an attacker download dead-end archives and paste dead-end secrets.
 *
 * Design rules (from the fake-data research + adversarial critique, docs/research/2026-08-23-*):
 *  - Every attribute (perms, owner, size, modified) is a pure function of the seed + the file name,
 *    so a scanner that re-reads a directory sees the identical listing (D10). No time()/rand().
 *  - The home directory's user is frozen per seed and reused in the /home/<user>/public_html path so
 *    the tree stays coherent with the rest of the host identity.
 *  - Downloadable entries (archives / .bak / .sql.gz / private keys) carry isDownload=true so the skin
 *    routes their link to the inert decoy-archive handler; text lures (.env, credentials.txt) render
 *    in place. Nothing here is real: no working keys, secrets, or credentials.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf/number_format), matching ServerProfile's primitives.
 */
final class FakeFiles
{
    /** @var int */
    private $seed;

    private function __construct(int $seed)
    {
        $this->seed = $seed;
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $this->seed . '|files|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    /** The account name that owns the home tree — frozen per seed, reused in the public_html path. */
    private function user(): string
    {
        return $this->pick(['brightpk', 'nordicav', 'lumensta', 'apexfit', 'maplegrv', 'deploy'], 'user');
    }

    /** The fixed set of directories the skin can browse — one coherent tree per seed. */
    public function dirs(): array
    {
        return [
            '/home/' . $this->user() . '/public_html',
            '/backups',
            '/var/backups',
            '/root/.ssh',
        ];
    }

    /**
     * A believable directory listing. Unknown dirs fall back to public_html so the skin always has
     * something to render.
     *
     * @return list<array{name:string,size:string,modified:string,perms:string,owner:string,isDir:bool,isDownload:bool}>
     */
    public function listing(string $dir): array
    {
        if (strpos($dir, '/.ssh') !== false) {
            $spec = [
                ['id_rsa', false], ['id_rsa.pub', false], ['id_ed25519', false], ['id_ed25519.pub', false],
                ['authorized_keys', false], ['known_hosts', false], ['config', false],
            ];
            $owners = ['root'];
        } elseif (strpos($dir, '/var/backups') !== false) {
            $spec = [
                ['apt.extended_states.0', false], ['dpkg.status.0', false], ['etc.tar.gz', false],
                ['home.tar.gz', false], ['mysql_dump.sql.gz', false], ['shadow.bak', false],
                ['OLD_site_do_not_delete.tar.gz', false],
            ];
            $owners = ['root'];
        } elseif (strpos($dir, '/backups') !== false) {
            $user = $this->user();
            $spec = [
                ['backup.zip', false], ['database.sql.gz', false],
                ['public_html_2026-08-01.tar.gz', false], ['wp-content_2026-08-10.tar.gz', false],
                ['db_backup_20260814.sql.gz', false], ['.env.bak', false],
                ['credentials.txt', false], ['final_final.zip', false],
            ];
            $owners = ['root', 'www-data', $user, 'deploy'];
        } else {
            $user = $this->user();
            $spec = [
                ['wp-admin', true], ['wp-content', true], ['wp-includes', true], ['.git', true],
                ['index.php', false], ['.htaccess', false], ['wp-config.php', false],
                ['wp-config.php.bak', false], ['.env', false], ['.env.bak', false],
                ['credentials.txt', false], ['id_rsa', false], ['backup.zip', false],
                ['database.sql.gz', false], ['OLD_site_do_not_delete.tar.gz', false],
                ['.aws', true],
            ];
            $owners = ['www-data', 'nginx', $user, 'deploy', 'ubuntu'];
        }

        $out = [];
        foreach ($spec as $s) {
            $out[] = $this->entry($s[0], $s[1], $owners);
        }
        return $out;
    }

    /**
     * @param list<string> $owners
     * @return array{name:string,size:string,modified:string,perms:string,owner:string,isDir:bool,isDownload:bool}
     */
    private function entry(string $name, bool $isDir, array $owners): array
    {
        return [
            'name' => $name,
            'size' => $this->sizeFor($name, $isDir),
            'modified' => $this->modifiedFor($name),
            'perms' => $this->permsFor($name, $isDir),
            'owner' => $owners[$this->h('own|' . $name) % count($owners)],
            'isDir' => $isDir,
            'isDownload' => !$isDir && $this->isDownloadable($name),
        ];
    }

    /** Archives, .bak snapshots and private key files link to the decoy-archive handler. */
    private function isDownloadable(string $name): bool
    {
        $keys = ['id_rsa', 'id_ed25519', 'id_rsa.pub', 'id_ed25519.pub'];
        if (in_array($name, $keys, true)) {
            return true;
        }
        $exts = ['.zip', '.gz', '.tar.gz', '.sql.gz', '.bak', '.tgz'];
        foreach ($exts as $ext) {
            if (substr($name, -strlen($ext)) === $ext) {
                return true;
            }
        }
        return false;
    }

    private function permsFor(string $name, bool $isDir): string
    {
        if ($isDir) {
            return $this->pick(['0755', '0750', '0700'], 'perm|' . $name);
        }
        $sensitive = ['id_rsa', 'id_ed25519', 'shadow.bak', 'credentials.txt', 'authorized_keys'];
        if (in_array($name, $sensitive, true) || strpos($name, '.env') === 0) {
            return $this->pick(['0600', '0400', '0640'], 'perm|' . $name);
        }
        return $this->pick(['0644', '0640', '0664'], 'perm|' . $name);
    }

    private function sizeFor(string $name, bool $isDir): string
    {
        if ($isDir) {
            return '4.0 KB';
        }
        // Big loot: full archives in GB.
        if (substr($name, -7) === '.tar.gz' || substr($name, -4) === '.zip') {
            $tenths = $this->intIn(9, 118, 'sz|' . $name);          // 0.9 - 11.8 GB
            return number_format($tenths / 10, 1) . ' GB';
        }
        // DB dumps in MB.
        if (substr($name, -7) === '.sql.gz' || substr($name, -3) === '.gz') {
            $mb = $this->intIn(3, 940, 'sz|' . $name);
            return $mb . '.' . ($this->h('szf|' . $name) % 10) . ' MB';
        }
        // Everything else (configs, keys, text) in bytes/KB.
        $bytes = $this->intIn(48, 8192, 'sz|' . $name);
        if ($bytes >= 1024) {
            return number_format($bytes / 1024, 1) . ' KB';
        }
        return $bytes . ' B';
    }

    private function modifiedFor(string $name): string
    {
        $month = $this->pick(['07', '08'], 'mon|' . $name);
        $day = $this->intIn(1, 22, 'day|' . $name);
        $hour = $this->h('hr|' . $name) % 24;
        $min = $this->h('mn|' . $name) % 60;
        return sprintf('2026-%s-%02d %02d:%02d', $month, $day, $hour, $min);
    }
}
