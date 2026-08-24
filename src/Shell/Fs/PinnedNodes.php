<?php

declare(strict_types=1);

namespace Funnypot\Shell\Fs;

use Funnypot\App\Render\Fake\FrozenClock;

/**
 * Curated nodes at paths attackers reach for first — pinned over the procedural fill. Content is
 * seeded per host (no shared constants across installs), but standard system users/paths stay standard
 * (every real box has them, so they are not a fingerprint). Inert: shadow hashes are placeholders, no
 * value is a real credential.
 */
final class PinnedNodes
{
    private const ADMIN_NAMES = ['jmartin', 'akhan', 'dsilva', 'rprice', 'lchen', 'mwilson', 'sokafor',
        'tbauer', 'nsingh', 'grossi', 'pdubois', 'kowalski'];
    private const DISTROS = [
        ['id' => 'ubuntu', 'name' => 'Ubuntu', 'ver' => '22.04.4 LTS (Jammy Jellyfish)', 'vid' => '22.04'],
        ['id' => 'ubuntu', 'name' => 'Ubuntu', 'ver' => '20.04.6 LTS (Focal Fossa)', 'vid' => '20.04'],
        ['id' => 'debian', 'name' => 'Debian GNU/Linux', 'ver' => '12 (bookworm)', 'vid' => '12'],
        ['id' => 'centos', 'name' => 'CentOS Stream', 'ver' => '9', 'vid' => '9'],
        ['id' => 'rhel', 'name' => 'Red Hat Enterprise Linux', 'ver' => '9.3 (Plow)', 'vid' => '9.3'],
    ];

    /**
     * @return array{nodes: array<string,Node>, content: array<string,string>}
     */
    public static function build(string $hostSeedBytes, string $role): array
    {
        $seed = Draw::seed($hostSeedBytes . "\0pinned\0" . $role);
        $now = FrozenClock::epoch();

        $admin = (string) Draw::pick($seed, 1, self::ADMIN_NAMES);
        $content = [
            '/etc/hostname' => self::hostname($seed) . "\n",
            '/etc/os-release' => self::osRelease($seed),
            '/etc/passwd' => self::passwd($admin),
            '/etc/shadow' => self::shadow($admin),
        ];

        $nodes = [];
        $i = 0;
        foreach ($content as $path => $bytes) {
            $mode = $path === '/etc/shadow' ? 0o640 : 0o644;
            $mtime = $now - Draw::intBelow($seed, 100 + $i, 31536000);
            $nodes[$path] = new Node(PathCanon::basename($path), 'file', 0, 0, strlen($bytes), $mode, $mtime, null);
            $i++;
        }
        // A couple of OS-standard symlinks so readlink/stat look real.
        $nodes['/etc/localtime'] = new Node('localtime', 'link', 0, 0, 27, 0o777, $now - 31000000, '/usr/share/zoneinfo/Etc/UTC');
        $nodes['/etc/mtab'] = new Node('mtab', 'link', 0, 0, 12, 0o777, $now - 30000000, '/proc/self/mounts');

        return ['nodes' => $nodes, 'content' => $content];
    }

    private static function hostname(string $seed): string
    {
        $envs = ['prod', 'app', 'web', 'db', 'api', 'core', 'svc'];
        $env = (string) Draw::pick($seed, 10, $envs);
        $n = 1 + Draw::intBelow($seed, 11, 12);

        return sprintf('%s-%02d', $env, $n);
    }

    private static function osRelease(string $seed): string
    {
        /** @var array{id:string,name:string,ver:string,vid:string} $d */
        $d = Draw::pick($seed, 20, self::DISTROS);

        return "NAME=\"{$d['name']}\"\n"
            . "VERSION=\"{$d['ver']}\"\n"
            . "ID={$d['id']}\n"
            . "VERSION_ID=\"{$d['vid']}\"\n"
            . "PRETTY_NAME=\"{$d['name']} {$d['ver']}\"\n";
    }

    private static function passwd(string $admin): string
    {
        return "root:x:0:0:root:/root:/bin/bash\n"
            . "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            . "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            . "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            . "sync:x:4:65534:sync:/bin:/bin/sync\n"
            . "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            . "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            . "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            . "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
            . "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
            . "{$admin}:x:1000:1000:{$admin}:/home/{$admin}:/bin/bash\n";
    }

    private static function shadow(string $admin): string
    {
        // All inert placeholders — never real hashes.
        return "root:!:19700:0:99999:7:::\n"
            . "daemon:*:19700:0:99999:7:::\n"
            . "bin:*:19700:0:99999:7:::\n"
            . "sys:*:19700:0:99999:7:::\n"
            . "www-data:*:19700:0:99999:7:::\n"
            . "sshd:*:19700:0:99999:7:::\n"
            . "{$admin}:\$6\$xxxxxxxxxxxxxxxx\$0000000000000000000000000000000000000000000000000000000000000000000000000000000000:19700:0:99999:7:::\n";
    }
}
