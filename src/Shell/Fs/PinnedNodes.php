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
 * panel, and the fleet all agree. Per-host SECRETS (the shadow salts+digests, the admin username) are
 * seeded from the private-secret-keyed pinned seed, so they vary per install even at the same identity.
 * Inert: every shadow digest is drawn noise in the crypt alphabet, never a real or shared hash.
 */
final class PinnedNodes
{
    private const CRYPT_B64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    // Draw index namespaces owned here. Two helpers sharing an index are locked together forever, so
    // every helper gets its own band: 1 admin name, 30 shadow lastchg, 100+ one per pinned /etc file,
    // 400+uid home mtimes (uid starts at 1000), 700 staff headcount. Shadow salts/digests do not draw
    // from Draw at all — see cryptB64.
    private const IDX_ADMIN_NAME = 1;
    private const IDX_LASTCHG = 30;
    private const IDX_FILE_MTIME = 100;
    private const IDX_HOME_MTIME = 400;
    private const IDX_STAFF_COUNT = 700;

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

        $admin = (string) Draw::pick($seed, self::IDX_ADMIN_NAME, self::ADMIN_NAMES);
        $lastchg = 19000 + Draw::intBelow($seed, self::IDX_LASTCHG, 800);

        // Staff accounts, drawn from the SAME Org roster the web-facing fakes use, so a name found
        // in /etc/passwd or /home also appears in the directory, the mail headers and the tickets.
        // One host is one company; an attacker who cross-references should find agreement.
        $staff = self::staff($seed, $identitySeed, $admin);

        $content = [
            '/etc/hostname' => $id->hostname() . "\n",
            '/etc/os-release' => $id->osRelease(),
            '/etc/passwd' => self::passwd($admin, $fam, $staff),
            '/etc/shadow' => self::shadow($seed, $admin, $fam, $lastchg, $staff),
        ];

        $nodes = [];
        $i = 0;
        foreach ($content as $path => $bytes) {
            $mode = $path === '/etc/shadow' ? 0o640 : 0o644;
            $mtime = $now - Draw::intBelow($seed, self::IDX_FILE_MTIME + $i, 31536000);
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
            $mtime = $now - Draw::intBelow($seed, self::IDX_HOME_MTIME + $uid, 20000000);
            $nodes[$home] = new Node($user, 'dir', $uid, $uid, 4096, 0o750, $mtime, null);
            $uid++;
        }

        return ['nodes' => $nodes, 'content' => $content, 'fam' => $fam];
    }

    /**
     * A run of characters in the crypt alphabet, cut from a hash stream keyed by $tag.
     *
     * Deliberately NOT a walk of consecutive Draw indices: fnv1a64's low bits follow the last input
     * byte alone, so consecutive indices reduced mod 64 lay down the same alphabet pattern on every
     * install — a digest an attacker can recognise on sight. md5 blocks avalanche fully, and 256 is
     * an exact multiple of 64 so masking the low 6 bits of each byte stays uniform.
     */
    private static function cryptB64(string $seed, string $tag, int $len): string
    {
        $out = '';
        $block = 0;
        while (strlen($out) < $len) {
            $bytes = md5($seed . "\0" . $tag . "\0" . $block, true);
            for ($i = 0; $i < 16 && strlen($out) < $len; $i++) {
                $out .= self::CRYPT_B64[ord($bytes[$i]) & 63];
            }
            $block++;
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
    private static function passwd(string $admin, string $fam, array $staff): string
    {
        $lines = array_values(self::users($admin, $fam));

        $uid = 1001;
        foreach ($staff as $user => $display) {
            $lines[] = "{$user}:x:{$uid}:{$uid}:{$display}:/home/{$user}:/bin/bash";
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
    private static function staff(string $seed, int $identitySeed, string $admin): array
    {
        $org = Org::fromSeed($identitySeed);
        $count = 3 + Draw::intBelow($seed, self::IDX_STAFF_COUNT, 4);
        $out = [];

        // Over-fetch generously: initial+surname collapses distinct people onto one username, and a
        // clash with the admin is skipped too, so a tight window would silently under-fill the roster.
        foreach ($org->people($count * 4 + 8) as $person) {
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
            if ($user === '' || $user === $admin || isset($out[$user])) {
                continue;
            }
            $out[$user] = $first . ' ' . $last;
        }

        return $out;
    }

    /** @param array<string,string> $staff username => display name */
    private static function shadow(string $seed, string $admin, string $fam, int $lastchg, array $staff): string
    {
        // One shadow line per passwd user, in passwd's order — pwck reports any file that enumerates a
        // user the other does not, so the two must be built from the same set. Every fabricated secret
        // is seeded per host: a login digest is noise in the crypt alphabet (a sha512-crypt SHAPE),
        // never a real or shared hash.
        $out = '';
        foreach (array_keys(self::users($admin, $fam)) as $name) {
            if ($name === 'root') {
                $secret = '!';
            } elseif ($name === $admin) {
                $secret = self::sha512Shape($seed, $name);
            } else {
                $secret = '*';
            }
            $out .= "{$name}:{$secret}:{$lastchg}:0:99999:7:::\n";
        }
        foreach (array_keys($staff) as $name) {
            $out .= "{$name}:" . self::sha512Shape($seed, $name) . ":{$lastchg}:0:99999:7:::\n";
        }

        return $out;
    }

    /** An inert sha512-crypt-shaped string for one login, stable per host and per user. */
    private static function sha512Shape(string $seed, string $user): string
    {
        $salt = self::cryptB64($seed, 'shadow-salt:' . $user, 16);
        $digest = self::cryptB64($seed, 'shadow-digest:' . $user, 86);

        return "\$6\${$salt}\${$digest}";
    }
}
