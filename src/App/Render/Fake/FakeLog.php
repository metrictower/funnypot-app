<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT fake log scroll-back for the admin-panel skins — the raw auth.log / access.log
 * tail an attacker greps and scrolls for a success line or a leaked key that never pays off.
 *
 * Design rules (from the fake-data research + adversarial critique, docs/research/2026-08-23-*):
 *  - INERT + DETERMINISTIC: every line is a pure function of the seed (no time()/rand()); the same seed
 *    and line count always render byte-identical output so an attacker who re-reads the tail sees it agree.
 *  - SAFE (critique S1): these fabricated lines feed a display only, never the AbuseIPDB report path, so
 *    EVERY source IP is RFC1918 / TEST-NET (10/172.16-31/192.168 + 192.0.2/198.51.100/203.0.113) — never
 *    real routable space. Filing reports against invented third-party IPs is the risk this hard-walls.
 *  - The buried "Accepted publickey for deploy ... SHA256:<43 base64url>" is a key-hunt bait: the
 *    fingerprint is a correct-shape but inert base64url string; no usable key exists behind it.
 *  - Timestamps are monotonic within each call (a 24h+ gradient), syslog format for auth, CLF for access.
 *  - PHP 7.3-clean (plain arrays + hash/sprintf) matching ServerProfile so it can promote into the shared
 *    Funnypot\Support\Fake namespace when the generators consolidate.
 */
final class FakeLog
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
        // 60-bit non-negative int from the seed + salt; abs-safe on 64-bit PHP.
        return (int) hexdec(substr(hash('sha256', $this->seed . '|log|' . $salt), 0, 15));
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

    /**
     * A source IP inside RFC1918 / TEST-NET only (critique S1). The family is seeded so the fleet mixes
     * private and documentation space; no branch can escape into real routable addresses.
     */
    private function privateIp(string $salt): string
    {
        $fam = $this->h('fam|' . $salt) % 6;
        $b = $this->h('b|' . $salt) % 256;
        $c = 1 + ($this->h('c|' . $salt) % 254);
        switch ($fam) {
            case 0:
                return '10.' . ($this->h('a|' . $salt) % 256) . '.' . $b . '.' . $c;
            case 1:
                return '172.' . (16 + ($this->h('a|' . $salt) % 16)) . '.' . $b . '.' . $c;
            case 2:
                return '192.168.' . $b . '.' . $c;
            case 3:
                return '192.0.2.' . $c;       // TEST-NET-1
            case 4:
                return '198.51.100.' . $c;    // TEST-NET-2
            default:
                return '203.0.113.' . $c;     // TEST-NET-3
        }
    }

    private function sshUser(string $salt): string
    {
        // root ~35% of attempts (catalog B.8); the rest from the SSH attacker vocab (C.5).
        if ($this->h('root|' . $salt) % 100 < 35) {
            return 'root';
        }
        return $this->pick(
            [
                'admin', 'ubuntu', 'user', 'test', 'oracle', 'postgres', 'ftpuser', 'git', 'deploy',
                'jenkins', 'www-data', 'mysql', 'nagios', 'pi', 'ubnt', 'guest', 'administrator',
                'support', 'ftp', 'minecraft', 'hadoop', 'elastic', 'backup', 'tomcat', 'docker',
                'redis', 'mongodb', 'webmaster', 'sysadmin', 'zabbix', 'ansible', 'testuser', 'demo',
            ],
            'user|' . $salt
        );
    }

    private function hostname(): string
    {
        return $this->pick(
            ['prod-db-01', 'vhost-04', 'srv-app-02', 'kvm-fra-03', 'pve-node01', 'web-lb-01', 'esx-repl-01'],
            'hostname'
        );
    }

    // --- timestamps (walk backward from FrozenClock "now"; identity ignores wall-clock) ---

    /** @var list<string> */
    private static $months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

    /**
     * Civil month/day/H:M:S for an absolute epoch, off FrozenClock's Hinnant conversion — every log
     * line's date is a real calendar date near "now", never a span unrelated to the frozen instant.
     *
     * @return array{month:string,day:int,h:int,m:int,s:int}
     */
    private function clockAt(int $epoch): array
    {
        $c = FrozenClock::civilFromDays(intdiv($epoch, 86400));
        $secOfDay = $epoch % 86400;
        return [
            'month' => self::$months[$c[1] - 1],
            'day' => $c[2],
            'h' => intdiv($secOfDay, 3600),
            'm' => intdiv($secOfDay % 3600, 60),
            's' => $secOfDay % 60,
        ];
    }

    /** Syslog stamp: "Aug 23 14:32:07" — no year, space-padded day. */
    private function tsSyslog(int $epoch): string
    {
        $c = $this->clockAt($epoch);
        return sprintf('%s %2d %02d:%02d:%02d', $c['month'], $c['day'], $c['h'], $c['m'], $c['s']);
    }

    /** CLF stamp: "[23/Aug/2026:14:32:07 +0000]" — zero-padded day, fixed year. */
    private function tsClf(int $epoch): string
    {
        $c = FrozenClock::civilFromDays(intdiv($epoch, 86400));
        $secOfDay = $epoch % 86400;
        return sprintf(
            '[%02d/%s/%04d:%02d:%02d:%02d +0000]',
            $c[2],
            self::$months[$c[1] - 1],
            $c[0],
            intdiv($secOfDay, 3600),
            intdiv($secOfDay % 3600, 60),
            $secOfDay % 60
        );
    }

    /** Correct-shape but INERT ssh key fingerprint: 43 base64url chars (32 bytes, no padding). */
    private function inertFingerprint(string $salt): string
    {
        $raw = hex2bin(substr(hash('sha256', $this->seed . '|fp|' . $salt), 0, 64));
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    // --- log builders ---

    /**
     * sshd auth.log scroll-back: brute-force failures, invalid users, preauth churn, and a few buried
     * "Accepted publickey for deploy" baits. Every source IP is RFC1918 / TEST-NET (critique S1).
     *
     * @return list<string>
     */
    public function authLog(int $lines): array
    {
        if ($lines < 1) {
            return [];
        }
        $host = $this->hostname();
        $baitOffset = $this->h('baitoff') % 300;   // guarantees ~1 bait per 300 lines
        // Walk the elapsed-seconds counter forward first so the total span is known, then anchor the
        // LAST line to FrozenClock::EPOCH ("now") and derive every earlier line by walking back from
        // it — the newest tail line is always recent, never a span unrelated to the frozen instant.
        $t = 0;
        $offsets = [];
        for ($i = 0; $i < $lines; $i++) {
            $t += $this->intIn(2, 55, 'ag|' . $i);
            $offsets[] = $t;
        }
        $span = $t;
        $out = [];
        for ($i = 0; $i < $lines; $i++) {
            $ts = $this->tsSyslog(FrozenClock::EPOCH - ($span - $offsets[$i]));
            $pid = $this->intIn(2000, 32767, 'pid|' . $i);
            $port = $this->intIn(20000, 65000, 'port|' . $i);
            $ip = $this->privateIp('aip|' . $i);
            $user = $this->sshUser('u|' . $i);

            if (($i % 300) === $baitOffset) {
                $msg = sprintf(
                    'Accepted publickey for deploy from %s port %d ssh2: ED25519 SHA256:%s',
                    $ip,
                    $port,
                    $this->inertFingerprint('bait|' . $i)
                );
            } else {
                $r = $this->h('mv|' . $i) % 100;
                if ($r < 35) {
                    $msg = sprintf('Failed password for %s from %s port %d ssh2', $user, $ip, $port);
                } elseif ($r < 60) {
                    $msg = sprintf('Failed password for invalid user %s from %s port %d ssh2', $user, $ip, $port);
                } elseif ($r < 70) {
                    $msg = sprintf('Invalid user %s from %s port %d', $user, $ip, $port);
                } elseif ($r < 78) {
                    $msg = sprintf('Connection closed by %s port %d [preauth]', $ip, $port);
                } elseif ($r < 85) {
                    $msg = sprintf('Received disconnect from %s port %d:11: Bye Bye [preauth]', $ip, $port);
                } elseif ($r < 90) {
                    $msg = sprintf('Did not receive identification string from %s port %d', $ip, $port);
                } elseif ($r < 94) {
                    $msg = sprintf('maximum authentication attempts exceeded for %s from %s port %d ssh2 [preauth]', $user, $ip, $port);
                } elseif ($r < 98) {
                    $msg = sprintf('pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s user=%s', $ip, $user);
                } else {
                    $msg = sprintf('message repeated %d times: [ Failed password for %s from %s port %d ssh2]', $this->intIn(2, 19, 'rep|' . $i), $user, $ip, $port);
                }
            }
            $out[] = sprintf('%s %s sshd[%d]: %s', $ts, $host, $pid, $msg);
        }
        return $out;
    }

    /**
     * Combined-format access.log scroll-back: probed-path + scanner-UA traffic with weighted statuses.
     * Every client IP is RFC1918 / TEST-NET (critique S1).
     *
     * @return list<string>
     */
    public function accessLog(int $lines): array
    {
        if ($lines < 1) {
            return [];
        }
        $paths = [
            '/wp-login.php', '/xmlrpc.php', '/wp-json/wp/v2/users', '/.env', '/.git/config', '/config.php',
            '/phpinfo.php', '/server-status', '/.aws/credentials', '/backup.zip', '/backup.sql', '/.DS_Store',
            '/administrator/', '/phpmyadmin/', '/adminer.php', '/shell.php', '/solr/', '/actuator/env',
            '/cgi-bin/', '/boaform/admin/formLogin', '/HNAP1/', '/remote/fgt_lang',
            '/autodiscover/autodiscover.xml', '/manager/html', '/robots.txt', '/',
        ];
        $postPaths = ['/wp-login.php', '/xmlrpc.php', '/boaform/admin/formLogin', '/HNAP1/'];
        $uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            'python-requests/2.31.0',
            'curl/8.5.0',
            'Go-http-client/1.1',
            'Mozilla/5.0 zgrab/0.x',
            'masscan/1.3 (https://github.com/robertdavidgraham/masscan)',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.0; +https://openai.com/gptbot',
        ];
        // Same backward-from-"now" anchoring as authLog(): walk elapsed seconds forward to find the
        // span, then the last line lands on FrozenClock::EPOCH and every earlier line walks back from it.
        $t = 0;
        $offsets = [];
        for ($i = 0; $i < $lines; $i++) {
            $t += $this->intIn(0, 12, 'xg|' . $i);
            $offsets[] = $t;
        }
        $span = $t;
        $out = [];
        for ($i = 0; $i < $lines; $i++) {
            $ip = $this->privateIp('xip|' . $i);
            $path = $paths[$this->h('path|' . $i) % count($paths)];
            $method = (in_array($path, $postPaths, true) && $this->h('pm|' . $i) % 100 < 65) ? 'POST' : 'GET';
            $status = $this->statusFor('st|' . $i);
            $bytes = $this->bytesFor($status, 'by|' . $i);
            $ua = $uas[$this->h('ua|' . $i) % count($uas)];
            $out[] = sprintf(
                '%s - - %s "%s %s HTTP/1.1" %d %s "-" "%s"',
                $ip,
                $this->tsClf(FrozenClock::EPOCH - ($span - $offsets[$i])),
                $method,
                $path,
                $status,
                $bytes,
                $ua
            );
        }
        return $out;
    }

    /** Weighted status per the catalog access-log mix (200 heavy, 404 next, rare 500). */
    private function statusFor(string $salt): int
    {
        $r = $this->h($salt) % 1000;
        if ($r < 450) {
            return 200;
        }
        if ($r < 530) {
            return 301;
        }
        if ($r < 580) {
            return 302;
        }
        if ($r < 640) {
            return 403;
        }
        if ($r < 860) {
            return 404;
        }
        if ($r < 950) {
            return 401;
        }
        if ($r < 955) {
            return 500;
        }
        return 304;
    }

    /** Response size string; 404s are the canonical fixed 162, 304 sends no body. */
    private function bytesFor(int $status, string $salt): string
    {
        if ($status === 404) {
            return '162';
        }
        if ($status === 304) {
            return '-';
        }
        if ($status === 301 || $status === 302) {
            return (string) $this->intIn(0, 400, $salt);
        }
        if ($status === 200) {
            return (string) $this->intIn(180, 95000, $salt);
        }
        if ($status === 500) {
            return (string) $this->intIn(500, 2000, $salt);
        }
        return (string) $this->intIn(150, 400, $salt);
    }
}
