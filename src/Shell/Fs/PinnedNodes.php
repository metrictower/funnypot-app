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
    private const IDX_ROOT_MTIME = 800;      // 800+ one per pinned /root file
    private const IDX_HISTORY_LEN = 900;
    private const IDX_HISTORY_LINE = 901;    // 901 + i, one per history line
    private const IDX_AWS_REGION = 990;

    private const TOKEN_B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    private const TOKEN_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    // Plausible root shell history — inert, generic operator commands (no fingerprint markers). One
    // host's history is a seeded subset in a seeded order, so it varies per install but reads real.
    private const HISTORY_CMDS = [
        'ls -la', 'cd /var/www', 'cd /etc/nginx', 'df -h', 'free -m', 'top', 'htop', 'uptime',
        'systemctl restart nginx', 'systemctl status nginx', 'systemctl restart mariadb',
        'journalctl -xe', 'tail -f /var/log/syslog', 'tail -n 100 /var/log/nginx/error.log',
        'apt update', 'apt upgrade -y', 'apt install -y htop', 'docker ps', 'docker compose up -d',
        'docker logs app', 'git pull', 'git status', 'vim /etc/nginx/sites-enabled/default',
        'nginx -t', 'crontab -l', 'ps aux | grep nginx', 'netstat -tlnp', 'ss -tlnp',
        'chown -R www-data:www-data /var/www', 'chmod 640 /etc/ssl/private/server.key',
        'mysql -u root -p', 'redis-cli ping', 'certbot renew --dry-run', 'ufw status',
        'du -sh /var/log/*', 'find /var/www -name "*.php" -mtime -1', 'scp backup.tar.gz backup@10.0.0.9:/srv/',
        'export EDITOR=vim', 'history -c', 'sudo -i', 'exit',
    ];

    private const AWS_REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-2'];

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

        // Root's home: the standard skel dotfiles, a seeded shell history, an inert .ssh key store, and
        // a couple of high-ROI inert loot files (.env + cloud creds) — the bait the old FakeShell curated
        // and the procedural generator dropped. All root-owned; .ssh/.aws are pinned-exclusive dirs so
        // the generator can't sprinkle base64 noise into a key store.
        self::addRootHome($nodes, $content, $seed, $admin, $id->hostname(), $now);

        return ['nodes' => $nodes, 'content' => $content, 'fam' => $fam];
    }

    // Standard root skel — byte-for-byte the Debian defaults, identical on every box, so NOT a
    // fingerprint. Real operators leave these untouched; their presence is what a bare /root lacks.
    private const SKEL_BASHRC = "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
        . "export PS1='\\h:\\w\\\$ '\numask 022\n\n"
        . "# You may uncomment the following lines if you want `ls' to be colorized:\n"
        . "# export LS_OPTIONS='--color=auto'\n# eval \"`dircolors`\"\n# alias ls='ls \$LS_OPTIONS'\n"
        . "# alias ll='ls \$LS_OPTIONS -l'\n# alias l='ls \$LS_OPTIONS -lA'\n#\n"
        . "# Some more alias to avoid making mistakes:\n# alias rm='rm -i'\n# alias cp='cp -i'\n# alias mv='mv -i'\n";
    private const SKEL_PROFILE = "# ~/.profile: executed by Bourne-compatible login shells.\n\n"
        . "if [ \"\$BASH\" ]; then\n  if [ -f ~/.bashrc ]; then\n    . ~/.bashrc\n  fi\nfi\n\n"
        . "mesg n 2> /dev/null || true\n";
    private const SKEL_LOGOUT = "# ~/.bash_logout: executed by bash(1) when login shell exits.\n\n"
        . "# when leaving the console clear the screen to increase privacy\n\n"
        . "if [ \"\$SHLVL\" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n";

    /**
     * Pin root's home: skel dotfiles, .bash_history, .ssh key store, and inert .env / cloud-cred loot.
     *
     * @param array<string,Node>   $nodes   accumulator (by ref)
     * @param array<string,string> $content accumulator (by ref)
     */
    private static function addRootHome(array &$nodes, array &$content, string $seed, string $admin, string $hostname, int $now): void
    {
        $put = static function (string $path, string $bytes, int $mode) use (&$nodes, &$content, $seed, $now): void {
            $mtime = $now - Draw::intBelow($seed, self::IDX_ROOT_MTIME + count($content), 20000000);
            $nodes[$path] = new Node(PathCanon::basename($path), 'file', 0, 0, strlen($bytes), $mode, $mtime, null);
            $content[$path] = $bytes;
        };
        $dir = static function (string $path, int $mode) use (&$nodes, $now): void {
            $nodes[$path] = new Node(PathCanon::basename($path), 'dir', 0, 0, 4096, $mode, $now - 15000000, null);
        };

        // Skel dotfiles (identical everywhere) + a seeded, plausible operator history.
        $put('/root/.bashrc', self::SKEL_BASHRC, 0o644);
        $put('/root/.profile', self::SKEL_PROFILE, 0o644);
        $put('/root/.bash_logout', self::SKEL_LOGOUT, 0o644);
        $put('/root/.bash_history', self::bashHistory($seed), 0o600);

        // .ssh — inert fake keys. The key material is seeded noise in the correct SSH wire shape; a
        // private key is a real-looking OpenSSH PEM block that decodes to nothing usable.
        $dir('/root/.ssh', 0o700);
        $rsaPub = self::rsaPubKey($seed, 'idrsa') . ' root@' . $hostname;
        $edPub = self::ed25519PubKey($seed, 'admin') . ' ' . $admin . '@workstation';
        $put('/root/.ssh/id_rsa', self::opensshPrivateKey($seed, 'idrsa'), 0o600);
        $put('/root/.ssh/id_rsa.pub', $rsaPub . "\n", 0o644);
        $put('/root/.ssh/authorized_keys', $rsaPub . "\n" . $edPub . "\n", 0o600);
        $put('/root/.ssh/known_hosts', self::knownHosts($seed), 0o644);

        // High-ROI loot — inert per-host secrets an attacker reflexively grabs. The AWS pair is shared
        // between .env and ~/.aws/credentials so a cross-referencing attacker finds agreement.
        $awsKeyId = 'AKIA' . self::run($seed, 'awskid', 16, self::TOKEN_UPPER);
        $awsSecret = self::run($seed, 'awssec', 40, self::TOKEN_B62 . '+/');
        $put('/root/.env', self::envLoot($seed, $awsKeyId, $awsSecret), 0o600);

        $dir('/root/.aws', 0o700);
        $region = (string) Draw::pick($seed, self::IDX_AWS_REGION, self::AWS_REGIONS);
        $put('/root/.aws/credentials', "[default]\naws_access_key_id = {$awsKeyId}\naws_secret_access_key = {$awsSecret}\n", 0o600);
        $put('/root/.aws/config', "[default]\nregion = {$region}\noutput = json\n", 0o644);
    }

    /** A seeded subset of the history pool, in a seeded order — inert, generic, believable. */
    private static function bashHistory(string $seed): string
    {
        $n = 18 + Draw::intBelow($seed, self::IDX_HISTORY_LEN, 30);
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $out .= (string) Draw::pick($seed, self::IDX_HISTORY_LINE + $i * 7, self::HISTORY_CMDS) . "\n";
        }

        return $out;
    }

    private static function envLoot(string $seed, string $awsKeyId, string $awsSecret): string
    {
        return "APP_ENV=production\nAPP_DEBUG=false\n"
            . 'DB_HOST=10.0.0.' . (10 + Draw::intBelow($seed, 991, 240)) . "\nDB_PORT=3306\nDB_DATABASE=app_production\nDB_USERNAME=app\n"
            . 'DB_PASSWORD=' . self::run($seed, 'dbpw', 24, self::TOKEN_B62) . "\n"
            . 'REDIS_PASSWORD=' . self::run($seed, 'redispw', 20, self::TOKEN_B62) . "\n"
            . 'JWT_SECRET=' . self::run($seed, 'jwt', 48, self::TOKEN_B62) . "\n"
            . "AWS_ACCESS_KEY_ID={$awsKeyId}\nAWS_SECRET_ACCESS_KEY={$awsSecret}\n"
            . 'STRIPE_SECRET_KEY=sk_live_' . self::run($seed, 'stripe', 24, self::TOKEN_B62) . "\n";
    }

    /** A run of $len chars from $alphabet, avalanching per byte, keyed by (seed, tag). */
    private static function run(string $seed, string $tag, int $len, string $alphabet): string
    {
        $m = strlen($alphabet);
        $out = '';
        $block = 0;
        while (strlen($out) < $len) {
            $bytes = md5($seed . "\0run\0" . $tag . "\0" . $block, true);
            for ($i = 0; $i < 16 && strlen($out) < $len; $i++) {
                $out .= $alphabet[ord($bytes[$i]) % $m];
            }
            $block++;
        }

        return $out;
    }

    private static function rawBytes(string $seed, string $tag, int $n): string
    {
        $out = '';
        $block = 0;
        while (strlen($out) < $n) {
            $out .= md5($seed . "\0raw\0" . $tag . "\0" . $block, true);
            $block++;
        }

        return substr($out, 0, $n);
    }

    private static function sshField(string $s): string
    {
        return pack('N', strlen($s)) . $s;
    }

    /** SSH mpint: big-endian, minimal, a leading 0x00 when the high bit is set. */
    private static function sshMpint(string $raw): string
    {
        $raw = ltrim($raw, "\x00");
        if ($raw === '') {
            $raw = "\x00";
        }
        if (ord($raw[0]) & 0x80) {
            $raw = "\x00" . $raw;
        }

        return pack('N', strlen($raw)) . $raw;
    }

    /** `ssh-ed25519 <base64>` with a correctly-shaped, inert 32-byte public value. */
    private static function ed25519PubKey(string $seed, string $tag): string
    {
        $wire = self::sshField('ssh-ed25519') . self::sshField(self::rawBytes($seed, 'ed:' . $tag, 32));

        return 'ssh-ed25519 ' . base64_encode($wire);
    }

    /** `ssh-rsa <base64>` with e=65537 and an inert 2048-bit-shaped modulus. */
    private static function rsaPubKey(string $seed, string $tag): string
    {
        $mod = self::rawBytes($seed, 'rsa:' . $tag, 256);
        $mod[0] = chr(ord($mod[0]) | 0x80); // top bit set -> a full 2048-bit modulus, not a short one
        $wire = self::sshField('ssh-rsa') . self::sshMpint("\x01\x00\x01") . self::sshMpint($mod);

        return 'ssh-rsa ' . base64_encode($wire);
    }

    /** An OpenSSH-format private-key PEM block — inert base64 body, 70-column wrapped. */
    private static function opensshPrivateKey(string $seed, string $tag): string
    {
        $body = base64_encode(self::rawBytes($seed, 'priv:' . $tag, 384));

        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" . chunk_split($body, 70, "\n")
            . "-----END OPENSSH PRIVATE KEY-----\n";
    }

    /** A few inert known_hosts lines (an internal box + a couple of forges), seeded per host. */
    private static function knownHosts(string $seed): string
    {
        return '10.0.0.' . (5 + Draw::intBelow($seed, 995, 40)) . ' ' . self::ed25519PubKey($seed, 'kh1') . "\n"
            . 'github.com ' . self::rsaPubKey($seed, 'kh2') . "\n"
            . 'gitlab.internal ' . self::ed25519PubKey($seed, 'kh3') . "\n";
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
