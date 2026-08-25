<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\App\Render\Fake\Org;
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

        // Staff accounts, drawn from the SAME Org roster the web-facing fakes use, so a name found
        // in /etc/passwd or /home also appears in the directory, the mail headers and the tickets.
        // One host is one company; an attacker who cross-references should find agreement.
        $staff = self::staff($seed, $identitySeed);

        $content = [
            '/etc/hostname' => $id->hostname() . "\n",
            '/etc/os-release' => $id->osRelease(),
            '/etc/passwd' => self::passwd($admin, $fam, $staff),
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

        // /home is pinned rather than generated. Left to the generic generator it produced files
        // like ld.so.cache and resolvconf — /etc content sitting in /home, which is exactly the
        // incoherence a careful attacker reads as a tell.
        $uid = 1000;
        foreach (array_merge([$admin], array_keys($staff)) as $user) {
            $home = '/home/' . $user;
            $nodes[$home] = new Node($user, 'dir', $uid, $uid, 4096, 0o750, $now - Draw::intBelow($seed, 400 + $uid, 20000000), null);
            $uid++;
        }

        return ['nodes' => $nodes, 'content' => $content, 'fam' => $fam, 'homes' => array_merge([$admin], array_keys($staff))];
    }

    private static function cryptB64(string $seed, int $base, int $len): string
    {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= self::CRYPT_B64[Draw::intBelow($seed, $base + $i, 64)];
        }

        return $out;
    }

    /** Service accounts the reused process pool runs as — added so every `ps` user has a passwd entry. */
    private const SERVICES = [
        'mysql' => 'mysql:x:110:110:MySQL Server,,,:/nonexistent:/bin/false',
        'redis' => 'redis:x:111:111:redis server,,,:/var/lib/redis:/usr/sbin/nologin',
        'postgres' => 'postgres:x:112:112:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash',
        'mongodb' => 'mongodb:x:113:113:MongoDB server,,,:/var/lib/mongodb:/usr/sbin/nologin',
        'prometheus' => 'prometheus:x:114:114:Prometheus daemon,,,:/var/lib/prometheus:/usr/sbin/nologin',
        'chrony' => 'chrony:x:115:115:chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin',
        'messagebus' => 'messagebus:x:116:116::/nonexistent:/usr/sbin/nologin',
        'systemd-resolve' => 'systemd-resolve:x:117:117:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin',
    ];

    /** @return array<string,string> username => full /etc/passwd line, per distro family (shadow mirrors it) */
    private static function users(string $admin, string $fam): array
    {
        $base = self::baseUsers($admin, $fam);
        // Insert the service accounts before the admin line (admin stays last), skipping any already present.
        $adminLine = $base[$admin];
        unset($base[$admin]);
        foreach (self::SERVICES as $name => $line) {
            if (!isset($base[$name])) {
                $base[$name] = $line;
            }
        }
        $base[$admin] = $adminLine;

        return $base;
    }

    /** @return array<string,string> */
    private static function baseUsers(string $admin, string $fam): array
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

    /** @param array<string,string> $staff username => display name */
    private static function passwd(string $admin, string $fam, array $staff = []): string
    {
        $lines = array_values(self::users($admin, $fam));

        $uid = 1001;
        foreach ($staff as $user => $display) {
            $shell = $fam === 'rhel' ? '/bin/bash' : '/bin/bash';
            $lines[] = "{$user}:x:{$uid}:{$uid}:{$display}:/home/{$user}:{$shell}";
            $uid++;
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * Staff usernames drawn from the Org roster, in the first-initial + surname shape the admin
     * pool already uses. Seeded by the host identity, so the same host always has the same people.
     *
     * @return array<string,string> username => display name
     */
    private static function staff(string $seed, int $identitySeed): array
    {
        $org = Org::fromSeed($identitySeed);
        $count = 3 + Draw::intBelow($seed, 300, 4);
        $out = [];

        foreach ($org->people($count + 2) as $person) {
            if (count($out) >= $count) {
                break;
            }
            $first = isset($person['first']) ? (string) $person['first'] : '';
            $last = isset($person['last']) ? (string) $person['last'] : '';
            if ($first === '' || $last === '') {
                continue;
            }
            $user = strtolower(substr($first, 0, 1) . preg_replace('/[^A-Za-z]/', '', $last));
            // A collision with the admin account would put two entries on one uid.
            if ($user === '' || isset($out[$user])) {
                continue;
            }
            $out[$user] = $first . ' ' . $last;
        }

        return $out;
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
