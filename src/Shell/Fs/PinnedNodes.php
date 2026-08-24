<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

use Funnypot\App\Render\Fake\FrozenClock;

/**
 * Curated nodes at paths attackers reach for first — pinned over the procedural fill. Standard system
 * users/paths stay standard (every real box has them, so they are not a fingerprint) and match the drawn
 * distro family, but every fabricated secret (the admin shadow salt+digest, the hostname, the admin user)
 * is seeded per host so no two installs are byte-identical. Inert: the shadow digest is drawn noise in the
 * crypt alphabet, never a real hash.
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
    private const HOST_ENV = ['prod', 'stg', 'app', 'web', 'db', 'api', 'core', 'svc', 'infra', 'edge', 'ops', 'int'];
    private const HOST_SVC = ['db', 'app', 'web', 'cache', 'queue', 'auth', 'gw', 'node', 'worker', 'lb', 'store', 'mail'];

    private const DISTROS = [
        ['id' => 'ubuntu', 'name' => 'Ubuntu', 'ver' => '22.04.4 LTS (Jammy Jellyfish)', 'vid' => '22.04', 'fam' => 'debian'],
        ['id' => 'ubuntu', 'name' => 'Ubuntu', 'ver' => '20.04.6 LTS (Focal Fossa)', 'vid' => '20.04', 'fam' => 'debian'],
        ['id' => 'debian', 'name' => 'Debian GNU/Linux', 'ver' => '12 (bookworm)', 'vid' => '12', 'fam' => 'debian'],
        ['id' => 'centos', 'name' => 'CentOS Stream', 'ver' => '9', 'vid' => '9', 'fam' => 'rhel'],
        ['id' => 'rhel', 'name' => 'Red Hat Enterprise Linux', 'ver' => '9.3 (Plow)', 'vid' => '9.3', 'fam' => 'rhel'],
    ];

    /**
     * @return array{nodes: array<string,Node>, content: array<string,string>}
     */
    public static function build(string $hostSeedBytes, string $role): array
    {
        $seed = Draw::seed($hostSeedBytes . "\0pinned\0" . $role);
        $now = FrozenClock::epoch();

        $admin = (string) Draw::pick($seed, 1, self::ADMIN_NAMES);
        /** @var array{id:string,name:string,ver:string,vid:string,fam:string} $distro */
        $distro = Draw::pick($seed, 20, self::DISTROS);
        $lastchg = 19000 + Draw::intBelow($seed, 30, 800);

        $content = [
            '/etc/hostname' => self::hostname($seed) . "\n",
            '/etc/os-release' => self::osRelease($distro),
            '/etc/passwd' => self::passwd($admin, $distro['fam']),
            '/etc/shadow' => self::shadow($seed, $admin, $distro['fam'], $lastchg),
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
        $nodes['/etc/mtab'] = new Node('mtab', 'link', 0, 0, 12, 0o777, $now - 30000000, '/proc/self/mounts');

        return ['nodes' => $nodes, 'content' => $content];
    }

    private static function cryptB64(string $seed, int $base, int $len): string
    {
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= self::CRYPT_B64[Draw::intBelow($seed, $base + $i, 64)];
        }

        return $out;
    }

    private static function hostname(string $seed): string
    {
        $env = (string) Draw::pick($seed, 10, self::HOST_ENV);
        $svc = (string) Draw::pick($seed, 11, self::HOST_SVC);
        $n = 1 + Draw::intBelow($seed, 12, 40);

        return sprintf('%s-%s-%02d', $env, $svc, $n);
    }

    /** @param array{id:string,name:string,ver:string,vid:string,fam:string} $d */
    private static function osRelease(array $d): string
    {
        return "NAME=\"{$d['name']}\"\n"
            . "VERSION=\"{$d['ver']}\"\n"
            . "ID={$d['id']}\n"
            . "VERSION_ID=\"{$d['vid']}\"\n"
            . "PRETTY_NAME=\"{$d['name']} {$d['ver']}\"\n";
    }

    private static function passwd(string $admin, string $fam): string
    {
        $common = "root:x:0:0:root:/root:/bin/bash\n"
            . "bin:x:1:1:bin:/bin:/sbin/nologin\n"
            . "daemon:x:2:2:daemon:/sbin:/sbin/nologin\n";

        if ($fam === 'rhel') {
            return $common
                . "adm:x:3:4:adm:/var/adm:/sbin/nologin\n"
                . "nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\n"
                . "sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin\n"
                . "apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin\n"
                . "nginx:x:988:986:Nginx web server:/var/lib/nginx:/sbin/nologin\n"
                . "postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n"
                . "{$admin}:x:1000:1000:{$admin}:/home/{$admin}:/bin/bash\n";
        }

        // debian / ubuntu family
        return $common
            . "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            . "sync:x:4:65534:sync:/bin:/bin/sync\n"
            . "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            . "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            . "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            . "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            . "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
            . "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
            . "{$admin}:x:1000:1000:{$admin}:/home/{$admin}:/bin/bash\n";
    }

    private static function shadow(string $seed, string $admin, string $fam, int $lastchg): string
    {
        // Every fabricated secret is seeded per host — the admin digest is drawn noise in the crypt
        // alphabet (a sha512-crypt SHAPE), never a real or shared hash.
        $salt = self::cryptB64($seed, 300, 16);
        $digest = self::cryptB64($seed, 400, 86);
        $adminHash = "\$6\${$salt}\${$digest}";

        $sys = $fam === 'rhel'
            ? ['bin', 'daemon', 'adm', 'sshd', 'apache', 'nginx', 'postgres']
            : ['bin', 'daemon', 'sys', 'www-data', 'backup', 'systemd-network', 'sshd'];

        $out = "root:!:{$lastchg}:0:99999:7:::\n";
        foreach ($sys as $u) {
            $out .= "{$u}:*:{$lastchg}:0:99999:7:::\n";
        }
        $out .= "{$admin}:{$adminHash}:{$lastchg}:0:99999:7:::\n";

        return $out;
    }
}
