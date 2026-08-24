<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\Shell\Host\HostIdentity;

/**
 * Curated nodes at paths attackers reach for first — pinned over the procedural fill.
 *
 * Host identity (OS, hostname, distro family) comes from ONE source: ServerProfile::fromSeed($identitySeed)
 * — the same source the System panel and HostFacts use — so /etc/os-release, /etc/hostname, uname, the
 * panel, and the fleet all agree. Per-host SECRETS (the admin shadow salt+digest, the admin username) are
 * seeded from the private-secret-keyed pinned seed, so they vary per install even at the same identity.
 * Inert: the shadow digest is drawn noise in the crypt alphabet, never a real or shared hash.
 */
final class PinnedNodes
{
    private const CRYPT_B64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    private const ADMIN_NAMES = [
        'jmartin', 'akhan', 'dsilva', 'rprice', 'lchen', 'mwilson', 'sokafor', 'tbauer', 'nsingh', 'grossi',
        'pdubois', 'kowalski', 'ahernandez', 'bthompson', 'cmurphy', 'dpatel', 'efischer', 'fgarcia', 'hyamamoto',
        'ivanov', 'jkim', 'lnguyen', 'mrossi', 'nowak', 'operez', 'qzhang', 'rschmidt', 'ssaito', 'tandersen',
        'ubaker', 'vpetrov', 'wjackson', 'xander', 'ylowe', 'zabel', 'amorgan', 'bcarter', 'cdiaz', 'dfoster',
        'ereyes', 'fhoward', 'gwallace', 'hbrooks', 'ihughes', 'jbennett', 'kcole', 'lortiz', 'mgraham',
    ];

    /**
     * @return array{nodes: array<string,Node>, content: array<string,string>, fam: string}
     */
    public static function build(string $hostSeedBytes, string $role, int $identitySeed): array
    {
        $seed = Draw::seed($hostSeedBytes . "\0pinned\0" . $role);
        $now = FrozenClock::epoch();

        // Host identity (OS + hostname + distro family) comes from the shell's own HostIdentity — the same
        // source HostFacts uname uses — so /etc/os-release, /etc/hostname, uname, and /proc/version agree.
        $id = HostIdentity::fromSeed($identitySeed);
        $fam = $id->family();

        $admin = (string) Draw::pick($seed, 1, self::ADMIN_NAMES);
        $lastchg = 19000 + Draw::intBelow($seed, 30, 800);

        $content = [
            '/etc/hostname' => $id->hostname() . "\n",
            '/etc/os-release' => $id->osRelease(),
            '/etc/passwd' => self::passwd($admin, $fam),
            '/etc/shadow' => self::shadow($seed, $admin, $fam, $lastchg),
        ];

        $nodes = [];
        $i = 0;
        foreach ($content as $path => $bytes) {
            $mode = $path === '/etc/shadow' ? 0o640 : 0o644;
            $mtime = $now - Draw::intBelow($seed, 100 + $i, 31536000);
            $nodes[$path] = new Node(PathCanon::basename($path), 'file', 0, 0, strlen($bytes), $mode, $mtime, null);
            $i++;
        }
        $nodes['/etc/localtime'] = new Node('localtime', 'link', 0, 0, 27, 0o777, $now - 31000000, '/usr/share/zoneinfo/Etc/UTC');
        $nodes['/etc/mtab'] = new Node('mtab', 'link', 0, 0, 17, 0o777, $now - 30000000, '/proc/self/mounts');

        return ['nodes' => $nodes, 'content' => $content, 'fam' => $fam];
    }

    private static function cryptB64(string $seed, int $base, int $len): string
    {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= self::CRYPT_B64[Draw::intBelow($seed, $base + $i, 64)];
        }

        return $out;
    }

    /** @return array<string,string> username => full /etc/passwd line, per distro family (shadow mirrors it) */
    private static function users(string $admin, string $fam): array
    {
        if ($fam === 'rhel') {
            return [
                'root' => 'root:x:0:0:root:/root:/bin/bash',
                'bin' => 'bin:x:1:1:bin:/bin:/sbin/nologin',
                'daemon' => 'daemon:x:2:2:daemon:/sbin:/sbin/nologin',
                'adm' => 'adm:x:3:4:adm:/var/adm:/sbin/nologin',
                'nobody' => 'nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin',
                'sshd' => 'sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin',
                'apache' => 'apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin',
                'nginx' => 'nginx:x:988:986:Nginx web server:/var/lib/nginx:/sbin/nologin',
                'postgres' => 'postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash',
                $admin => "{$admin}:x:1000:1000:{$admin}:/home/{$admin}:/bin/bash",
            ];
        }

        // debian / ubuntu family
        return [
            'root' => 'root:x:0:0:root:/root:/bin/bash',
            'daemon' => 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
            'bin' => 'bin:x:2:2:bin:/bin:/usr/sbin/nologin',
            'sys' => 'sys:x:3:3:sys:/dev:/usr/sbin/nologin',
            'sync' => 'sync:x:4:65534:sync:/bin:/bin/sync',
            'man' => 'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin',
            'www-data' => 'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
            'backup' => 'backup:x:34:34:backup:/var/backups:/usr/sbin/nologin',
            'nobody' => 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
            'systemd-network' => 'systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin',
            'sshd' => 'sshd:x:110:65534::/run/sshd:/usr/sbin/nologin',
            $admin => "{$admin}:x:1000:1000:{$admin}:/home/{$admin}:/bin/bash",
        ];
    }

    private static function passwd(string $admin, string $fam): string
    {
        return implode("\n", array_values(self::users($admin, $fam))) . "\n";
    }

    private static function shadow(string $seed, string $admin, string $fam, int $lastchg): string
    {
        // One shadow line per passwd user. Every fabricated secret is seeded per host — the admin digest
        // is drawn noise in the crypt alphabet (a sha512-crypt SHAPE), never a real or shared hash.
        $salt = self::cryptB64($seed, 300, 16);
        $digest = self::cryptB64($seed, 400, 86);
        $adminHash = "\$6\${$salt}\${$digest}";

        $out = '';
        foreach (array_keys(self::users($admin, $fam)) as $name) {
            if ($name === 'root') {
                $secret = '!';
            } elseif ($name === $admin) {
                $secret = $adminHash;
            } else {
                $secret = '*';
            }
            $out .= "{$name}:{$secret}:{$lastchg}:0:99999:7:::\n";
        }

        return $out;
    }
}
