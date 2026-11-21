<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\Support\PersonaIdentity;
use Throwable;

/**
 * The one table every fake-shell answer comes from: a minimal Alpine/busybox php-fpm container,
 * seen as one identity. The landing transcript, the panel header and each command's output are all
 * rendered from it, so they cannot drift apart.
 *
 * Nothing runs. Each applet is a small function over a fixed filesystem table. The table is closed:
 * every absolute path an answer prints can itself be listed or read (permission errors aside), and
 * no applet the landing uses ever answers `not found`.
 *
 * Nothing here gives real progress. Every write fails on the read-only root, the network has no
 * egress, root has no capabilities, and the only credential material is core's inert canned shadow
 * file. The deploy file points onward to the gateway, which is where the attacker is meant to go.
 *
 * Attacker text appears in an answer only through slot(): it must arrive in a non-GET body, use a
 * small safe charset and fit a length cap. Otherwise the caller gets null and serves the landing.
 */
final class FootholdFacts
{
    public const HOST_FALLBACK = 'app-prod-01';
    public const CWD = '/var/www/html';
    public const PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
    public const POD_IP = '10.42.3.17';
    public const OVERLAY_LINE = 'overlay on / type overlay (ro,relatime,'
        . 'lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/61/fs,'
        . 'upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/fs,'
        . 'workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/74/work)';

    /** The attacker-text rule: this charset only, then a length cap. */
    public const SAFE_CHARSET = '~^[A-Za-z0-9_.,:@%+=/-]*$~';
    /** Slots also keep a glob or tilde word literal, as the shell does when nothing matches. None is HTML-special. */
    private const SLOT_CHARSET = '~^[A-Za-z0-9_.,:@%+=/*?\[\]\~-]*$~';
    public const ECHO_CAP = 256;
    public const PATH_CAP = 64;

    /** Output beyond this is cut, the way a webshell's capture buffer would be. */
    private const MAX_OUTPUT = 12288;
    private const IMAGE_MTIME = 'Nov  3 09:12';
    private const DEPLOY_MTIME = 'Nov 19 06:40';
    private const BUSYBOX = 'BusyBox v1.36.1 (2024-01-26 10:44:39 UTC) multi-call binary.';

    /**
     * Commands a minimal image does not ship. Their `not found` line names one of these fixed words,
     * so it may be shown even when other attacker text may not.
     */
    public const ABSENT = [
        'curl', 'python', 'python2', 'python3', 'perl', 'ruby', 'node', 'npm', 'pip', 'pip3', 'gcc', 'cc',
        'make', 'git', 'ssh', 'scp', 'sftp', 'rsync', 'socat', 'ncat', 'nmap', 'sudo', 'doas', 'mysql',
        'psql', 'mongo', 'redis-cli', 'docker', 'kubectl', 'systemctl', 'service', 'screen', 'tmux',
        'strace', 'gdb', 'tcpdump', 'zsh', 'go', 'java', 'lua', 'iptables', 'journalctl', 'useradd',
        'sqlite3', 'zip', 'file', 'lsb_release', 'getcap', 'setcap', 'capsh', 'telnet', 'ftp', 'lynx',
        'busctl', 'hostnamectl', 'netcat', 'awk2', 'ifup2',
    ];

    /** Shell builtins: never `not found`, whatever their arguments. */
    public const BUILTINS = [
        'type', 'cd', 'echo', 'pwd', 'export', 'set', 'command', 'true', 'false', 'exit', 'read', 'test',
        '[', '[[', 'printf', 'umask', 'ulimit', 'alias', 'unalias', 'eval', 'exec', 'kill', 'getopts',
        'hash', 'jobs', 'local', 'return', 'shift', 'times', 'trap', 'unset', 'wait', '.', 'source', ':',
    ];

    /** Busybox applet links, by directory, as on a stock Alpine 3.19 image. */
    private const APPLETS = [
        '/bin' => [
            'arch', 'ash', 'base64', 'bbconfig', 'cat', 'chattr', 'chgrp', 'chmod', 'chown', 'cp', 'date', 'dd',
            'df', 'dmesg', 'dnsdomainname', 'echo', 'ed', 'egrep', 'false', 'fgrep', 'fsync', 'getopt', 'grep',
            'gunzip', 'gzip', 'hostname', 'ionice', 'iostat', 'ipcalc', 'kill', 'link', 'ln', 'login', 'ls',
            'lsattr', 'makemime', 'mkdir', 'mknod', 'mktemp', 'more', 'mount', 'mountpoint', 'mpstat', 'mv',
            'netstat', 'nice', 'pidof', 'ping', 'ping6', 'printenv', 'ps', 'pwd', 'rev', 'rm', 'rmdir',
            'run-parts', 'sed', 'setpriv', 'sh', 'sleep', 'stat', 'stty', 'su', 'sync', 'tar', 'touch', 'true',
            'umount', 'uname', 'usleep', 'watch', 'zcat',
        ],
        '/sbin' => [
            'arp', 'blkid', 'fdisk', 'getty', 'halt', 'ifconfig', 'init', 'ip', 'ipaddr', 'iplink', 'iproute',
            'ldconfig', 'losetup', 'lsmod', 'mdev', 'mkswap', 'modprobe', 'pivot_root', 'poweroff', 'reboot',
            'route', 'switch_root', 'sysctl', 'syslogd', 'udhcpc',
        ],
        '/usr/bin' => [
            '[', '[[', 'awk', 'basename', 'bc', 'bunzip2', 'bzcat', 'bzip2', 'cal', 'cksum', 'clear', 'cmp',
            'comm', 'cpio', 'crontab', 'cut', 'dc', 'diff', 'dirname', 'du', 'env', 'expand', 'expr', 'find',
            'flock', 'fold', 'free', 'fuser', 'getconf', 'getent', 'groups', 'hd', 'head', 'hexdump', 'hostid',
            'iconv', 'id', 'install', 'ipcs', 'killall', 'last', 'less', 'logger', 'lsof', 'lsusb', 'md5sum',
            'mkfifo', 'mkpasswd', 'nc', 'nl', 'nohup', 'nproc', 'nsenter', 'nslookup', 'od', 'passwd', 'paste',
            'pgrep', 'pkill', 'pmap', 'printf', 'pstree', 'pwdx', 'readlink', 'realpath', 'renice', 'reset',
            'seq', 'setsid', 'sha1sum', 'sha256sum', 'sha512sum', 'shred', 'shuf', 'sort', 'split', 'strings',
            'sum', 'tac', 'tail', 'tee', 'test', 'time', 'timeout', 'top', 'tr', 'traceroute', 'tree',
            'truncate', 'tty', 'uniq', 'unlink', 'unshare', 'unxz', 'unzip', 'uptime', 'uudecode', 'uuencode',
            'vi', 'w', 'wc', 'wget', 'which', 'who', 'whoami', 'whois', 'xargs', 'xxd', 'xzcat', 'yes',
        ],
        '/usr/sbin' => [
            'addgroup', 'adduser', 'arping', 'chpasswd', 'chroot', 'crond', 'delgroup', 'deluser', 'killall5',
            'nologin', 'ntpd', 'rdate', 'readahead', 'sendmail', 'setlogcons',
        ],
    ];

    /** Real binaries (not applet links) and where they live. */
    private const BINARIES = [
        '/bin/busybox' => 841288,
        '/bin/bash' => 1027416,
        '/sbin/apk' => 104528,
        '/sbin/tini' => 26136,
        '/sbin/ss' => 132376,
        '/usr/local/bin/php' => 18733120,
        '/usr/local/sbin/php-fpm' => 18843416,
    ];

    /** @var array<string,array<string,mixed>> */
    private array $fs = [];
    /** @var array<string,list<string>> */
    private array $children = [];
    private bool $mayReflect = true;
    /** @var callable():int */
    private $clock;

    public function __construct(
        private FootholdIdentity $id,
        private string $host,
        private string $registry,
        private string $phpVersion,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
        $this->buildFs();
    }

    /**
     * Facts for this deployment's persona. The host and registry are the same strings the labyrinth
     * pages and the panel header show; the PHP version is the one the X-Powered-By header claims.
     */
    public static function forPersona(int $personaSeed, FootholdIdentity $id, string $poweredBy = '', ?callable $clock = null): self
    {
        // host.name is not a persona field, so every page that shows a host uses this same fallback.
        $host = self::personaField($personaSeed, 'host.name', self::HOST_FALLBACK);
        $registry = 'registry.int.' . self::personaField($personaSeed, 'company.domain', 'corevance.internal');

        return new self($id, $host, $registry, self::phpVersionFrom($poweredBy, $personaSeed), $clock);
    }

    public static function personaField(int $seed, string $path, string $fallback): string
    {
        try {
            $v = PersonaIdentity::fromSeed($seed)->field($path);

            return ($v !== null && $v !== '') ? $v : $fallback;
        } catch (Throwable $e) {
            return $fallback;
        }
    }

    /** `PHP/x.y.z` from the effective X-Powered-By, else the persona's own PHP version. */
    public static function phpVersionFrom(string $poweredBy, int $seed): string
    {
        if (preg_match('~PHP/(\d+\.\d+\.\d+)~', $poweredBy, $m) === 1) {
            return $m[1];
        }
        try {
            $v = PersonaIdentity::fromSeed($seed)->productVersion('php');
        } catch (Throwable $e) {
            $v = '';
        }

        return preg_match('~^\d+\.\d+\.\d+$~', $v) === 1 ? $v : '8.2.15';
    }

    public function identity(): FootholdIdentity
    {
        return $this->id;
    }

    public function host(): string
    {
        return $this->host;
    }

    public function registry(): string
    {
        return $this->registry;
    }

    /** The panel header's uname line, the same text `uname -a` prints. */
    public function uname(): string
    {
        return 'Linux ' . $this->host . ' 5.15.0 x86_64 Linux';
    }

    /**
     * The probe block the panel shows on load. Every line after a `$ ` prompt is what that command
     * prints from this same table. Root never volunteers who it is or reads shadow unprompted, so the
     * first page never hands over credential material.
     */
    public function landingTranscript(): string
    {
        $steps = $this->id->isRoot()
            ? []
            : [['id'], ['sudo', '-i'], ['cat', '/etc/shadow'], ['ls', '-a', '/root']];
        if ($this->id->isRoot()) {
            $steps[] = ['sudo', '-i'];
        }
        array_push(
            $steps,
            ['cat', '/etc/os-release'],
            ['ls', '-a', '/home', '/srv', '/opt', '/data', '/var/www/html'],
            ['touch', '/var/www/html/probe'],
        );

        $out = '';
        foreach ($steps as $argv) {
            $out .= '$ ' . implode(' ', $argv) . "\n" . $this->run($argv);
        }
        // A pipeline the shell would never accept from a request; on the panel it is the panel's own probe.
        $out .= "\$ mount | grep ' / '\n" . self::OVERLAY_LINE . "\n";
        foreach ([['grep', 'Cap', '/proc/self/status'], ['wget', '-T', '3', '-qO-', 'https://' . $this->registry . '/v2/'], ['cat', '/run/deploy/app.env']] as $argv) {
            $out .= '$ ' . implode(' ', $argv) . "\n" . $this->run($argv);
        }

        return $out . '$ ';
    }

    /**
     * What a simple command prints, stdout and stderr together, as the webshell captures them.
     * Returns null when the answer would have to echo attacker text and the value came from a GET or
     * a query string; attacker text outside the safe charset is never echoed at all.
     *
     * @param list<string> $argv
     */
    public function run(array $argv, bool $mayReflect = true): ?string
    {
        $this->mayReflect = $mayReflect;
        try {
            $out = $this->exec($this->expand($argv), 0);
        } catch (SlotRefused $e) {
            // From a GET the caller serves the landing instead. From a body, the text only failed the
            // charset, and the command simply prints nothing.
            return $mayReflect ? '' : null;
        }

        return strlen($out) > self::MAX_OUTPUT ? substr($out, 0, self::MAX_OUTPUT) : $out;
    }

    /** True when $name runs here: an applet on PATH, a builtin, or a known binary. */
    public function isCommand(string $name): bool
    {
        return in_array($name, self::BUILTINS, true) || $this->which($name) !== null;
    }

    /** Every absolute path in the table, for the closure tests. @return list<string> */
    public function paths(): array
    {
        return array_keys($this->fs);
    }

    /** Every applet and binary name on PATH. @return list<string> */
    public static function commandNames(): array
    {
        $names = [];
        foreach (self::APPLETS as $list) {
            array_push($names, ...$list);
        }
        foreach (array_keys(self::BINARIES) as $p) {
            $names[] = basename($p);
        }

        return array_values(array_unique($names));
    }

    /** True when the table holds $path (normalised, symlinks followed). */
    public function exists(string $path): bool
    {
        return isset($this->fs[$this->resolve($this->abs($path))]);
    }

    // --- dispatch ---------------------------------------------------------------------------------

    /** @param list<string> $argv */
    private function exec(array $argv, int $depth): string
    {
        // Leading NAME=value words only set the environment of the command that follows.
        while ($argv !== [] && preg_match('~^[A-Za-z_][A-Za-z0-9_]*=~', $argv[0]) === 1) {
            array_shift($argv);
        }
        if ($argv === [] || $depth > 8) {
            return '';
        }
        $name = $argv[0];
        $args = array_slice($argv, 1);

        if (str_contains($name, '/')) {
            $abs = $this->abs($name);
            $e = $this->fs[$abs] ?? null;
            if ($e === null) {
                return AshVocabulary::render('not_found', $this->slotPath($name)) . "\n";
            }
            if ($e['t'] === 'd' || ($e['t'] === 'f' && !isset(self::BINARIES[$abs]))) {
                return 'sh: ' . $this->shown($name, $abs) . ": Permission denied\n";
            }
            $name = basename($abs);
        } elseif (!$this->isCommand($name)) {
            $shown = in_array($name, self::ABSENT, true) ? $name : $this->slotWord($name, self::PATH_CAP);

            return AshVocabulary::render('not_found', $shown) . "\n";
        }

        return $this->dispatch($name, $args, $depth);
    }

    /** @param list<string> $a */
    private function dispatch(string $name, array $a, int $depth): string
    {
        switch ($name) {
            case 'id':
                return $this->cmdId($a);
            case 'whoami':
                return $this->id->name . "\n";
            case 'groups':
                return $this->id->name . "\n";
            case 'hostname':
                return (in_array('-i', $a, true) ? self::POD_IP : $this->host) . "\n";
            case 'dnsdomainname':
                return '';
            case 'pwd':
                return self::CWD . "\n";
            case 'uname':
                return $this->cmdUname($a);
            case 'arch':
                return "x86_64\n";
            case 'nproc':
                return "2\n";
            case 'env':
            case 'printenv':
                return $this->cmdEnv($name, $a, $depth);
            case 'export':
                return $this->listVars('export ');
            case 'set':
                return $a === [] ? $this->listVars('') . "IFS=' \t\n'\nOPTIND='1'\nPPID='213'\nPS1='\\w \\\$ '\nPS2='> '\nPS4='+ '\n" : '';
            case 'umask':
                return $a === [] ? "0022\n" : '';
            case 'ulimit':
                return "unlimited\n";
            case 'date':
                return $this->cmdDate($a);
            case 'uptime':
                return $this->uptimeLine() . "\n";
            case 'w':
                return $this->uptimeLine() . "\nUSER\t\tTTY\t\tIDLE\tTIME\t\t HOST\n";
            case 'who':
                return "USER\t\tTTY\t\tIDLE\tTIME\t\t HOST\n";
            case 'ps':
                return $this->cmdPs($a);
            case 'top':
                return $this->cmdPs([]);
            case 'free':
                return $this->cmdFree($a);
            case 'df':
                return $this->cmdDf($a);
            case 'mount':
                return $a === [] ? $this->mountTable() : "mount: permission denied (are you root?)\n";
            case 'umount':
                return "umount: can't unmount " . $this->slotPath($a[0] ?? '/') . ": Operation not permitted\n";
            case 'du':
                return $this->cmdDu($a);
            case 'ip':
            case 'ipaddr':
            case 'iplink':
            case 'iproute':
                return $this->cmdIp($name, $a);
            case 'ifconfig':
                return $this->ifconfig();
            case 'route':
                return "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
                    . "0.0.0.0         10.42.3.1       0.0.0.0         UG    0      0        0 eth0\n"
                    . "10.42.3.0       0.0.0.0         255.255.255.0   U     0      0        0 eth0\n";
            case 'netstat':
                return $this->cmdNetstat($a);
            case 'ss':
                return $this->cmdSs();
            case 'arp':
                return "? (10.42.3.1) at 0a:58:0a:2a:03:01 [ether]  on eth0\n";
            case 'ls':
                return $this->cmdLs($a);
            case 'tree':
                return $this->cmdLs(array_merge(['-1'], $a));
            case 'cat':
            case 'less':
            case 'more':
                return $this->cmdCat($name, $a);
            case 'tac':
            case 'rev':
            case 'nl':
            case 'strings':
            case 'sort':
            case 'uniq':
            case 'head':
            case 'tail':
            case 'cut':
            case 'sed':
            case 'awk':
            case 'base64':
            case 'xxd':
            case 'hd':
            case 'hexdump':
                return $this->cmdFilter($name, $a);
            case 'grep':
            case 'egrep':
            case 'fgrep':
                return $this->cmdGrep($name, $a);
            case 'wc':
                return $this->cmdWc($a);
            case 'md5sum':
            case 'sha1sum':
            case 'sha256sum':
            case 'sha512sum':
                return $this->cmdDigest($name, $a);
            case 'cksum':
                return $a === [] ? "4294967295 0\n" : $this->cmdFilter('cat', []);
            case 'tr':
            case 'xargs':
            case 'od':
            case 'gzip':
            case 'gunzip':
            case 'zcat':
            case 'bzcat':
            case 'xzcat':
            case 'unxz':
            case 'bunzip2':
            case 'bzip2':
            case 'paste':
            case 'fold':
            case 'expand':
            case 'comm':
            case 'cmp':
            case 'diff':
            case 'yes':
            case 'seq':
            case 'shuf':
                return $this->cmdStream($name, $a);
            case 'find':
                return $this->cmdFind($a);
            case 'stat':
                return $this->cmdStat($a);
            case 'readlink':
                return $this->cmdReadlink($a);
            case 'realpath':
                return $this->cmdRealpath($a);
            case 'basename':
                return $a === [] ? '' : $this->slotPath(basename($a[0])) . "\n";
            case 'dirname':
                return $a === [] ? '' : $this->slotPath(dirname($a[0])) . "\n";
            case 'which':
                return $this->cmdWhich($a);
            case 'type':
                return $this->cmdType($a);
            case 'command':
                return $this->cmdCommand($a, $depth);
            case 'getent':
                return $this->cmdGetent($a);
            case 'echo':
                return $this->cmdEcho($a);
            case 'printf':
                return $a === [] ? '' : $this->cmdPrintf($a);
            case 'cd':
                return $this->cmdCd($a);
            case 'touch':
            case 'mkdir':
            case 'rm':
            case 'rmdir':
            case 'cp':
            case 'mv':
            case 'chmod':
            case 'chown':
            case 'chgrp':
            case 'ln':
            case 'link':
            case 'unlink':
            case 'tee':
            case 'truncate':
            case 'mknod':
            case 'mkfifo':
            case 'install':
            case 'shred':
            case 'mktemp':
            case 'chattr':
                return $this->cmdWrite($name, $a);
            case 'tar':
                return $this->cmdTar($a);
            case 'dd':
                return '';
            case 'wget':
                return $this->cmdWget($a);
            case 'nc':
                return $this->cmdNc($a);
            case 'ping':
            case 'ping6':
            case 'traceroute':
            case 'arping':
                return $this->cmdPing($name, $a);
            case 'nslookup':
            case 'whois':
                return $a === [] ? '' : ";; connection timed out; no servers could be reached\n";
            case 'apk':
                return $this->cmdApk($a);
            case 'su':
                return $this->cmdSu($a, $depth);
            case 'passwd':
            case 'chpasswd':
            case 'login':
                return $this->id->isRoot() ? "{$name}: can't open '/etc/shadow': Read-only file system\n" : "{$name}: must be suid to work properly\n";
            case 'adduser':
            case 'addgroup':
            case 'deluser':
            case 'delgroup':
                return $this->id->isRoot() ? "{$name}: /etc/passwd: Read-only file system\n" : "{$name}: need to be root\n";
            case 'crontab':
                return $this->id->isRoot() ? "crontab: chdir(/var/spool/cron/crontabs): No such file or directory\n" : "crontab: must be suid to work properly\n";
            case 'kill':
            case 'killall':
            case 'pkill':
            case 'killall5':
                return $this->cmdKill($name, $a);
            case 'pidof':
            case 'pgrep':
                return $this->cmdPidof($a);
            case 'php':
                return $this->cmdPhp($a);
            case 'php-fpm':
                return $this->id->isRoot() ? "ERROR: unable to bind listening socket for address '9000': Address in use (98)\n" : "ERROR: failed to open error_log (/proc/self/fd/2): Permission denied (13)\n";
            case 'nologin':
                return "This account is not available\n";
            case 'tini':
                return "tini (tini version 0.19.0)\nUsage: tini [OPTIONS] PROGRAM -- [ARGS] | --version\n";
            case 'busybox':
                return $a === [] ? self::BUSYBOX . "\n" : $this->exec($a, $depth + 1);
            case 'sh':
            case 'ash':
            case 'bash':
                return $this->cmdSh($name, $a);
            case 'exec':
            case 'eval':
            case 'nohup':
            case 'nice':
            case 'setsid':
            case 'time':
            case 'chroot':
            case 'nsenter':
            case 'unshare':
            case 'flock':
                return $this->cmdRunner($name, $a, $depth);
            case 'timeout':
                return $this->exec(array_slice(array_values(array_filter($a, static fn ($w) => !str_starts_with($w, '-'))), 1), $depth + 1);
            case 'vi':
            case 'sleep':
            case 'usleep':
            case 'sync':
            case 'true':
            case 'false':
            case 'exit':
            case 'read':
            case 'test':
            case '[':
            case '[[':
            case 'alias':
            case 'unalias':
            case ':':
            case 'hash':
            case 'jobs':
            case 'local':
            case 'return':
            case 'shift':
            case 'trap':
            case 'unset':
            case 'wait':
            case 'getopts':
            case 'clear':
            case 'reset':
            case 'logger':
            case 'stty':
                return '';
            case 'times':
                return "0m0.00s 0m0.00s\n0m0.00s 0m0.00s\n";
            case 'tty':
                return "not a tty\n";
            case '.':
            case 'source':
                return $a === [] ? '' : $this->cmdSh('sh', $a);
            case 'dmesg':
                return "dmesg: klogctl: Operation not permitted\n";
            case 'sysctl':
                return $a === [] ? '' : "sysctl: error: '" . $this->slotPath($a[0]) . "' is an unknown key\n";
            case 'lsmod':
                return "Module                  Size  Used by    Not tainted\n";
            case 'lsof':
                return $this->id->isRoot() ? "1\t/sbin/tini\t/dev/null\n7\t/usr/local/sbin/php-fpm\t/dev/null\n" : '';
            case 'hostid':
                return "2a0a1103\n";
            case 'getconf':
                return $a === [] ? '' : "4096\n";
            case 'unzip':
                return $a === [] ? self::BUSYBOX . "\n" : "unzip: can't open " . $this->slotPath($a[count($a) - 1]) . "[.zip]: No such file or directory\n";
            default:
                // A present applet with nothing to read on stdin prints nothing.
                return '';
        }
    }

    // --- recon ------------------------------------------------------------------------------------

    /** @param list<string> $a */
    private function cmdId(array $a): string
    {
        $who = $this->id;
        $users = array_values(array_filter($a, static fn ($w) => !str_starts_with($w, '-')));
        if ($users !== []) {
            $u = $users[0];
            if ($u === 'root') {
                $who = FootholdIdentity::root();
            } elseif ($u === 'www-data') {
                $who = FootholdIdentity::www();
            } else {
                return 'id: unknown user ' . $this->slotWord($u, self::PATH_CAP) . "\n";
            }
        }
        $flags = implode('', array_filter($a, static fn ($w) => str_starts_with($w, '-')));
        if (str_contains($flags, 'u') || str_contains($flags, 'g') || str_contains($flags, 'G')) {
            return (str_contains($flags, 'n') ? $who->name : (string) $who->uid) . "\n";
        }

        return $who->idLine() . "\n";
    }

    /** @param list<string> $a */
    private function cmdUname(array $a): string
    {
        $f = implode('', $a);
        if ($a === [] || $f === '-s') {
            return "Linux\n";
        }
        if (str_contains($f, 'a')) {
            return $this->uname() . "\n";
        }
        $parts = [];
        foreach (['s' => 'Linux', 'n' => $this->host, 'r' => '5.15.0', 'v' => '#1 SMP', 'm' => 'x86_64', 'o' => 'Linux'] as $k => $v) {
            if (str_contains($f, $k)) {
                $parts[] = $v;
            }
        }

        return ($parts === [] ? 'Linux' : implode(' ', $parts)) . "\n";
    }

    /** @return array<string,string> the worker's environment, in the order /proc/self/environ holds it */
    private function envVars(): array
    {
        return [
            'USER' => $this->id->name,
            'HOME' => $this->id->home,
            'PATH' => self::PATH,
            'PWD' => self::CWD,
            'SHELL' => $this->id->shell,
        ];
    }

    /** @param list<string> $a */
    private function cmdEnv(string $name, array $a, int $depth): string
    {
        $vars = $this->envVars();
        if ($a !== [] && $name === 'printenv') {
            $out = '';
            foreach ($a as $k) {
                if (isset($vars[$k])) {
                    $out .= $vars[$k] . "\n";
                }
            }

            return $out;
        }
        $rest = array_values(array_filter($a, static fn ($w) => $w !== '-i' && $w !== '-' && preg_match('~^[A-Za-z_][A-Za-z0-9_]*=~', $w) !== 1));
        if ($rest !== []) {
            return $this->exec($rest, $depth + 1);
        }
        $out = '';
        foreach ($vars as $k => $v) {
            $out .= "{$k}={$v}\n";
        }

        return $out;
    }

    private function listVars(string $prefix): string
    {
        $vars = $this->envVars();
        ksort($vars);
        $out = '';
        foreach ($vars as $k => $v) {
            $out .= "{$prefix}{$k}='{$v}'\n";
        }

        return $out;
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }

    /** @param list<string> $a */
    private function cmdDate(array $a): string
    {
        $now = $this->now();
        foreach ($a as $w) {
            if ($w !== '' && $w[0] === '+') {
                $map = ['%Y' => 'Y', '%m' => 'm', '%d' => 'd', '%H' => 'H', '%M' => 'i', '%S' => 's', '%F' => 'Y-m-d', '%T' => 'H:i:s', '%s' => 'U', '%a' => 'D', '%b' => 'M', '%y' => 'y', '%Z' => 'T'];
                $out = '';
                foreach (preg_split('~(%[A-Za-z])~', substr($w, 1), -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY) ?: [] as $part) {
                    $out .= isset($map[$part]) ? gmdate($map[$part], $now) : $this->slotWord($part, self::PATH_CAP);
                }

                return $out . "\n";
            }
        }

        return gmdate('D M ', $now) . sprintf('%2d', (int) gmdate('j', $now)) . gmdate(' H:i:s', $now) . ' UTC ' . gmdate('Y', $now) . "\n";
    }

    /**
     * Booted on a fixed ten-day rollout cycle, so uptime grows like a real node's. It always stays
     * above a million seconds, so /proc/uptime never prints a bare six-digit number.
     */
    private function bootEpoch(): int
    {
        $cycle = 10 * 86400;

        return intdiv($this->now(), $cycle) * $cycle - 1000020;
    }

    private function uptimeLine(): string
    {
        $now = $this->now();
        $up = max(60, $now - $this->bootEpoch());
        $days = intdiv($up, 86400);
        $h = intdiv($up % 86400, 3600);
        $m = intdiv($up % 3600, 60);

        return ' ' . gmdate('H:i:s', $now) . ' up ' . $days . ' day' . ($days === 1 ? '' : 's') . ', '
            . sprintf('%2d:%02d', $h, $m) . ',  0 users,  load average: 0.21, 0.18, 0.11';
    }

    /** @param list<string> $a */
    private function cmdPs(array $a): string
    {
        $worker = $this->id->isRoot() ? 'root' : 'www-data';
        $args = implode(' ', $a);
        $self = in_array($args, ['', 'aux', '-ef', 'ax', '-e', '-A', 'auxww', '-aux', 'ef', 'w', '-o pid,user,args'], true) ? trim('ps ' . $args) : 'ps';
        // A root pool needs php-fpm's -R (allow running as root); the pool config agrees (www.conf).
        $rows = [
            [1, 'root', '0:00', '/sbin/tini -- php-fpm' . ($this->id->isRoot() ? ' -R' : '')],
            [7, 'root', '0:41', 'php-fpm: master process (/usr/local/etc/php-fpm.conf)'],
            [12, $worker, '0:09', 'php-fpm: pool www'],
            [13, $worker, '0:08', 'php-fpm: pool www'],
            [14, $worker, '0:08', 'php-fpm: pool www'],
            [213, $worker, '0:00', $self],
        ];
        $out = "PID   USER     TIME  COMMAND\n";
        foreach ($rows as [$pid, $user, $time, $cmd]) {
            $out .= sprintf('%5d %-8s %5s %s', $pid, $user, $time, $cmd) . "\n";
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdFree(array $a): string
    {
        $mb = in_array('-m', $a, true);
        $h = in_array('-h', $a, true);
        $mem = $mb ? [1980, 598, 291, 1, 1090, 1211] : ($h ? ['1.9G', '598.0M', '291.2M', '1.0M', '1.0G', '1.2G'] : [2027664, 612344, 298212, 1024, 1117108, 1240212]);
        $swap = $h ? ['0', '0', '0'] : [0, 0, 0];

        return sprintf('%-6s%12s%12s%12s%12s%12s%12s', '', 'total', 'used', 'free', 'shared', 'buff/cache', 'available') . "\n"
            . vsprintf('%-6s%12s%12s%12s%12s%12s%12s', array_merge(['Mem:'], $mem)) . "\n"
            . vsprintf('%-6s%12s%12s%12s', array_merge(['Swap:'], $swap)) . "\n";
    }

    /** @return list<array{0:string,1:int,2:int,3:string}> filesystem, 1K-blocks, used, mount point */
    private function dfRows(): array
    {
        return [
            ['overlay', 81106868, 23465920, '/'],
            ['tmpfs', 65536, 0, '/dev'],
            ['shm', 64, 64, '/dev/shm'],
            ['tmpfs', 1024, 4, '/run/deploy'],
        ];
    }

    /** @param list<string> $a */
    private function cmdDf(array $a): string
    {
        $human = in_array('-h', $a, true);
        $paths = array_values(array_filter($a, static fn ($w) => !str_starts_with($w, '-')));
        $out = sprintf('%-20s %9s %9s %9s %s %s', 'Filesystem', $human ? 'Size' : '1K-blocks', 'Used', 'Available', 'Use%', 'Mounted on') . "\n";
        $rows = $this->dfRows();
        if ($paths !== []) {
            $sel = [];
            foreach ($paths as $p) {
                $abs = $this->abs($p);
                if (!isset($this->fs[$abs])) {
                    return "df: " . $this->slotPath($p) . ": can't find mount point\n";
                }
                $best = $rows[0];
                foreach ($rows as $r) {
                    if ($abs === $r[3] || str_starts_with($abs, rtrim($r[3], '/') . '/')) {
                        if (strlen($r[3]) >= strlen($best[3])) {
                            $best = $r;
                        }
                    }
                }
                $sel[] = $best;
            }
            $rows = $sel;
        }
        foreach ($rows as [$fs, $blocks, $used, $mnt]) {
            $avail = $blocks - $used;
            $pct = $blocks > 0 ? (int) ceil($used * 100 / $blocks) : 0;
            $out .= sprintf('%-20s %9s %9s %9s %3d%% %s', $fs, $human ? self::human($blocks * 1024) : $blocks, $human ? self::human($used * 1024) : $used, $human ? self::human($avail * 1024) : $avail, $pct, $mnt) . "\n";
        }

        return $out;
    }

    private static function human(int $bytes): string
    {
        if ($bytes < 1024) {
            return (string) $bytes;
        }
        $units = ['K', 'M', 'G', 'T'];
        $v = $bytes / 1024;
        $i = 0;
        while ($v >= 1024 && $i < 3) {
            $v /= 1024;
            $i++;
        }

        return sprintf('%.1f', $v) . $units[$i];
    }

    public function mountTable(): string
    {
        return self::OVERLAY_LINE . "\n"
            . "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            . "tmpfs on /dev type tmpfs (ro,nosuid,size=65536k,mode=755)\n"
            . "devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)\n"
            . "mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)\n"
            . "sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)\n"
            . "cgroup on /sys/fs/cgroup type cgroup2 (ro,nosuid,nodev,noexec,relatime)\n"
            . "shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=64k)\n"
            . "tmpfs on /run/deploy type tmpfs (ro,relatime,size=1024k)\n";
    }

    /** @param list<string> $a */
    private function cmdDu(array $a): string
    {
        $human = str_contains(implode('', array_filter($a, static fn ($w) => str_starts_with($w, '-'))), 'h');
        $paths = array_values(array_filter($a, static fn ($w) => !str_starts_with($w, '-')));
        if ($paths === []) {
            $paths = ['.'];
        }
        $out = '';
        foreach ($paths as $p) {
            $abs = $this->abs($p);
            if (!isset($this->fs[$abs])) {
                $out .= "du: can't open '" . $this->slotPath($p) . "': No such file or directory\n";
                continue;
            }
            if ($this->denied($abs)) {
                $out .= "du: can't open '" . $this->shown($p, $abs) . "': Permission denied\n";
                continue;
            }
            $kb = 4;
            foreach ($this->fs as $path => $e) {
                if ($path !== $abs && str_starts_with($path, rtrim($abs, '/') . '/')) {
                    $kb += max(4, (int) (ceil(($e['size'] ?? 0) / 4096) * 4));
                }
            }
            $out .= ($human ? sprintf('%.1fK', $kb) : (string) $kb) . "\t" . $this->shown($p, $abs) . "\n";
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdIp(string $name, array $a): string
    {
        $obj = $name === 'ipaddr' ? 'a' : ($name === 'iplink' ? 'link' : ($name === 'iproute' ? 'route' : ($a[0] ?? '')));
        if ($obj === '' || in_array($obj, ['help', '-h'], true)) {
            return "Usage: ip [OPTIONS] address|route|link|neigh|rule [ARGS]\n";
        }
        if (str_starts_with('route', $obj) || $obj === 'r') {
            return "default via 10.42.3.1 dev eth0 \n10.42.3.0/24 dev eth0 scope link  src 10.42.3.17 \n";
        }
        if (str_starts_with('neighbour', $obj) || $obj === 'n') {
            return "10.42.3.1 dev eth0 lladdr 0a:58:0a:2a:03:01 ref 1 used 0/0/0 probes 1 REACHABLE\n";
        }
        $link = str_starts_with('link', $obj);
        $out = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000\n"
            . "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n";
        if (!$link) {
            $out .= "    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n";
        }
        $out .= "3: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1450 qdisc noqueue state UP \n"
            . "    link/ether 6a:1f:3c:4e:21:7b brd ff:ff:ff:ff:ff:ff\n";
        if (!$link) {
            $out .= '    inet ' . self::POD_IP . "/24 brd 10.42.3.255 scope global eth0\n       valid_lft forever preferred_lft forever\n";
        }

        return $out;
    }

    private function ifconfig(): string
    {
        return "eth0      Link encap:Ethernet  HWaddr 6A:1F:3C:4E:21:7B  \n"
            . '          inet addr:' . self::POD_IP . "  Bcast:10.42.3.255  Mask:255.255.255.0\n"
            . "          UP BROADCAST RUNNING MULTICAST  MTU:1450  Metric:1\n"
            . "          RX packets:18734 errors:0 dropped:0 overruns:0 frame:0\n"
            . "          TX packets:16021 errors:0 dropped:0 overruns:0 carrier:0\n"
            . "          collisions:0 txqueuelen:0 \n"
            . "          RX bytes:5120334 (4.8 MiB)  TX bytes:7731020 (7.3 MiB)\n\n"
            . "lo        Link encap:Local Loopback  \n"
            . "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
            . "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
            . "          RX packets:42 errors:0 dropped:0 overruns:0 frame:0\n"
            . "          TX packets:42 errors:0 dropped:0 overruns:0 carrier:0\n"
            . "          collisions:0 txqueuelen:1000 \n"
            . "          RX bytes:3528 (3.4 KiB)  TX bytes:3528 (3.4 KiB)\n\n";
    }

    /** @param list<string> $a */
    private function cmdNetstat(array $a): string
    {
        $f = implode('', $a);
        if (str_contains($f, 'r')) {
            return "Kernel IP routing table\nDestination     Gateway         Genmask         Flags   MSS Window  irtt Iface\n"
                . "0.0.0.0         10.42.3.1       0.0.0.0         UG        0 0          0 eth0\n"
                . "10.42.3.0       0.0.0.0         255.255.255.0   U         0 0          0 eth0\n";
        }
        $prog = str_contains($f, 'p');
        $listenOnly = str_contains($f, 'l');
        $out = 'Active Internet connections (' . ($listenOnly ? 'only servers' : 'servers and established') . ")\n"
            . 'Proto Recv-Q Send-Q Local Address           Foreign Address         State       ' . ($prog ? 'PID/Program name' : '') . "\n"
            . 'tcp        0      0 0.0.0.0:9000            0.0.0.0:*               LISTEN      ' . ($prog ? ($this->id->isRoot() ? '7/php-fpm.conf)' : '-') : '') . "\n";
        if (!$listenOnly && (str_contains($f, 'a') || $a === [])) {
            $out .= "Active UNIX domain sockets (servers and established)\nProto RefCnt Flags       Type       State         I-Node Path\n";
        }

        return $out;
    }

    private function cmdSs(): string
    {
        return "State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
            . 'LISTEN 0      511          0.0.0.0:9000      0.0.0.0:*    ' . ($this->id->isRoot() ? 'users:(("php-fpm",pid=7,fd=7))' : '') . "\n";
    }

    // --- filesystem -------------------------------------------------------------------------------

    /** @param list<string> $a @return array{0:string,1:list<string>} */
    private static function split(array $a): array
    {
        $flags = '';
        $rest = [];
        $done = false;
        foreach ($a as $w) {
            if (!$done && $w === '--') {
                $done = true;
                continue;
            }
            if (!$done && strlen($w) > 1 && $w[0] === '-') {
                $flags .= substr($w, 1);
                continue;
            }
            $rest[] = $w;
        }

        return [$flags, $rest];
    }

    /** @param list<string> $a */
    private function cmdLs(array $a): string
    {
        [$flags, $paths] = self::split($a);
        $all = str_contains($flags, 'a');
        $almost = str_contains($flags, 'A');
        $long = str_contains($flags, 'l') || str_contains($flags, 'n');
        $self = str_contains($flags, 'd');
        $human = str_contains($flags, 'h');
        $multi = count($paths) > 1;
        if ($paths === []) {
            $paths = ['.'];
        }

        $out = '';
        $files = [];
        $dirs = [];
        foreach ($paths as $p) {
            $abs = $this->abs($p);
            $e = $this->fs[$abs] ?? null;
            if ($e === null) {
                $out .= 'ls: ' . $this->slotPath($p) . ($this->underDenied($abs) ? ": Permission denied\n" : ": No such file or directory\n");
                continue;
            }
            if ($this->type($abs) === 'd' && !$self) {
                $dirs[] = [$p, $abs];
            } else {
                $files[] = [$p, $abs];
            }
        }
        foreach ($files as [$p, $abs]) {
            $out .= $long ? $this->longLine($this->shown($p, $abs), $abs, $human) : $this->shown($p, $abs) . "\n";
        }
        foreach ($dirs as $i => [$p, $abs]) {
            if ($multi) {
                $out .= ($i > 0 || $files !== [] ? "\n" : '') . $this->shown($p, $abs) . ":\n";
            }
            if ($this->denied($abs)) {
                $out .= 'ls: ' . $this->shown($p, $abs) . ": Permission denied\n";
                continue;
            }
            $real = $this->resolve($abs);
            $names = $this->children[$real] ?? [];
            sort($names, SORT_STRING);
            if (!$all) {
                $names = array_values(array_filter($names, static fn ($n) => $n[0] !== '.'));
            }
            if ($all && !$almost) {
                array_unshift($names, '.', '..');
            }
            if ($long) {
                $out .= 'total ' . (4 * max(1, count($names))) . "\n";
            }
            foreach ($names as $n) {
                $child = $n === '.' ? $real : ($n === '..' ? $this->parent($real) : rtrim($real, '/') . '/' . $n);
                $out .= $long ? $this->longLine($n, $child, $human) : $n . "\n";
            }
        }

        return $out;
    }

    private function longLine(string $name, string $abs, bool $human): string
    {
        $e = $this->fs[$abs] ?? ['t' => 'd', 'm' => 'rwxr-xr-x', 'u' => 'root', 'g' => 'root'];
        $size = $this->size($abs);
        $type = ['d' => 'd', 'l' => 'l', 'c' => 'c', 'f' => '-'][$e['t']];
        $links = $e['t'] === 'd' ? 2 + count(array_filter($this->children[$abs] ?? [], fn ($n) => ($this->fs[rtrim($abs, '/') . '/' . $n]['t'] ?? '') === 'd')) : 1;

        return sprintf('%s %4d %-8s %-8s %9s %s %s', $type . $e['m'], $links, $e['u'], $e['g'], $human ? self::human($size) : (string) $size, $e['mt'] ?? self::IMAGE_MTIME, $name)
            . ($e['t'] === 'l' ? ' -> ' . $e['to'] : '') . "\n";
    }

    /** @param list<string> $a */
    private function cmdCat(string $applet, array $a): string
    {
        [, $paths] = self::split($a);
        $out = '';
        foreach ($paths as $p) {
            if ($p === '-') {
                continue;
            }
            $r = $this->read($applet, $p);
            $out .= $r[0] ?? $r[1];
        }

        return $out;
    }

    /**
     * Read one file the way an applet does: [content, null] on success, [null, error line] on failure.
     *
     * @return array{0:?string,1:?string}
     */
    private function read(string $applet, string $p): array
    {
        $abs = $this->abs($p);
        if (!isset($this->fs[$abs]) && $this->underDenied($abs)) {
            $shown = $this->slotPath($p);

            return [null, $applet === 'cat' || $applet === 'less' || $applet === 'more'
                ? "{$applet}: can't open '{$shown}': Permission denied\n"
                : "{$applet}: {$shown}: Permission denied\n"];
        }
        if (!isset($this->fs[$abs])) {
            $shown = $this->slotPath($p);

            return [null, $applet === 'cat' || $applet === 'less' || $applet === 'more'
                ? "{$applet}: can't open '{$shown}': No such file or directory\n"
                : "{$applet}: {$shown}: No such file or directory\n"];
        }
        if ($this->type($abs) === 'd') {
            return [null, $applet === 'cat' ? "cat: read error: Is a directory\n" : "{$applet}: read error: Is a directory\n"];
        }
        if ($this->denied($abs)) {
            $shown = $this->shown($p, $abs);

            return [null, $applet === 'cat' || $applet === 'less' || $applet === 'more'
                ? "{$applet}: can't open '{$shown}': Permission denied\n"
                : "{$applet}: {$shown}: Permission denied\n"];
        }

        return [$this->content($this->resolve($abs), $applet), null];
    }

    /** @param list<string> $a */
    private function cmdFilter(string $name, array $a): string
    {
        [$flags, $files] = self::split($a);
        $n = 10;
        foreach ($a as $i => $w) {
            if (($w === '-n' || $w === '-c') && isset($a[$i + 1]) && ctype_digit($a[$i + 1])) {
                $n = (int) $a[$i + 1];
                $files = array_values(array_diff($files, [$a[$i + 1]]));
            } elseif (preg_match('~^-n?(\d+)$~', $w, $m) === 1) {
                $n = (int) $m[1];
            }
        }
        if ($name === 'cut' || $name === 'awk' || $name === 'sed') {
            // The first non-flag word of a sed/awk program, and cut's -d/-f values, are not files.
            if ($name !== 'cut' && $files !== [] && !$this->exists($this->abs($files[0]))) {
                array_shift($files);
            }
            $files = array_values(array_filter($files, fn ($f) => $this->exists($this->abs($f)) || str_contains($f, '/')));
        }
        if ($files === []) {
            return '';
        }
        $out = '';
        foreach ($files as $f) {
            [$c, $err] = $this->read($name, $f);
            if ($c === null) {
                $out .= $err;
                continue;
            }
            $lines = $c === '' ? [] : explode("\n", rtrim($c, "\n"));
            switch ($name) {
                case 'head':
                    $out .= self::lines(array_slice($lines, 0, $n));
                    break;
                case 'tail':
                    $out .= self::lines(array_slice($lines, -$n));
                    break;
                case 'tac':
                    $out .= self::lines(array_reverse($lines));
                    break;
                case 'rev':
                    $out .= self::lines(array_map('strrev', $lines));
                    break;
                case 'nl':
                    $i = 0;
                    $out .= self::lines(array_map(static function ($l) use (&$i) {
                        return $l === '' ? '' : sprintf('%6d', ++$i) . "\t" . $l;
                    }, $lines));
                    break;
                case 'sort':
                    sort($lines, SORT_STRING);
                    $out .= self::lines(str_contains($flags, 'u') ? array_values(array_unique($lines)) : $lines);
                    break;
                case 'uniq':
                    $prev = null;
                    $keep = [];
                    foreach ($lines as $l) {
                        if ($l !== $prev) {
                            $keep[] = $l;
                        }
                        $prev = $l;
                    }
                    $out .= self::lines($keep);
                    break;
                case 'cut':
                    $out .= $this->cut($a, $lines);
                    break;
                case 'base64':
                    $out .= str_contains($flags, 'd') ? '' : chunk_split(base64_encode($c), 76, "\n");
                    break;
                case 'xxd':
                case 'hd':
                case 'hexdump':
                    $out .= self::hexdump($c, $name === 'xxd');
                    break;
                case 'strings':
                    $out .= self::lines(array_values(array_filter(preg_split('~[^\x20-\x7e]+~', $c) ?: [], static fn ($s) => strlen($s) >= 4)));
                    break;
                default:
                    $out .= str_contains($flags, 'n') && $name === 'sed' ? '' : $c;
            }
        }

        return $out;
    }

    /** @param list<string> $lines */
    private static function lines(array $lines): string
    {
        return $lines === [] ? '' : implode("\n", $lines) . "\n";
    }

    /** @param list<string> $a @param list<string> $lines */
    private function cut(array $a, array $lines): string
    {
        $delim = "\t";
        $fields = null;
        foreach ($a as $i => $w) {
            if (str_starts_with($w, '-d')) {
                $delim = strlen($w) > 2 ? substr($w, 2, 1) : (string) substr($a[$i + 1] ?? "\t", 0, 1);
            } elseif (str_starts_with($w, '-f')) {
                $spec = strlen($w) > 2 ? substr($w, 2) : ($a[$i + 1] ?? '1');
                $fields = array_map('intval', preg_split('~[,-]~', $spec) ?: ['1']);
            }
        }
        if ($fields === null || $delim === '') {
            return '';
        }
        $out = [];
        foreach ($lines as $l) {
            $parts = explode($delim, $l);
            $pick = [];
            foreach ($fields as $f) {
                if ($f >= 1 && isset($parts[$f - 1])) {
                    $pick[] = $parts[$f - 1];
                }
            }
            $out[] = implode($delim, $pick);
        }

        return self::lines($out);
    }

    private static function hexdump(string $c, bool $xxd): string
    {
        $out = '';
        foreach (str_split(substr($c, 0, 512), 16) as $i => $chunk) {
            $hex = bin2hex($chunk);
            $ascii = (string) preg_replace('~[^\x20-\x7e]~', '.', $chunk);
            if ($xxd) {
                $out .= sprintf('%08x: ', $i * 16) . str_pad(implode(' ', str_split($hex, 4)), 39) . '  ' . $ascii . "\n";
            } else {
                $out .= sprintf('%08x  ', $i * 16) . str_pad(implode(' ', str_split($hex, 2)), 47) . '  |' . $ascii . "|\n";
            }
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdGrep(string $name, array $a): string
    {
        [$flags, $rest] = self::split($a);
        if ($rest === []) {
            return '';
        }
        $pattern = array_shift($rest);
        if ($rest === []) {
            return '';
        }
        $re = '~' . str_replace('\.', '.', preg_quote($pattern, '~')) . '~' . (str_contains($flags, 'i') ? 'i' : '');
        $recurse = str_contains($flags, 'r') || str_contains($flags, 'R');
        $files = [];
        $out = '';
        foreach ($rest as $f) {
            $abs = $this->abs($f);
            if ($recurse && $this->type($abs) === 'd') {
                foreach ($this->walk($abs, $out, 'grep') as $p) {
                    if ($this->type($p) === 'f') {
                        $files[] = $p;
                    }
                }
                continue;
            }
            $files[] = $f;
        }
        $prefix = count($files) > 1 || $recurse;
        foreach ($files as $f) {
            [$c, $err] = $this->read('grep', $f);
            if ($c === null) {
                $out .= $err;
                continue;
            }
            $count = 0;
            foreach (explode("\n", rtrim($c, "\n")) as $line) {
                $hit = preg_match($re, $line) === 1;
                if ($hit !== str_contains($flags, 'v')) {
                    $count++;
                    if (!str_contains($flags, 'c') && !str_contains($flags, 'l')) {
                        $out .= ($prefix ? $this->shown($f, $this->abs($f)) . ':' : '') . $line . "\n";
                    }
                }
            }
            if (str_contains($flags, 'c')) {
                $out .= ($prefix ? $this->shown($f, $this->abs($f)) . ':' : '') . $count . "\n";
            } elseif (str_contains($flags, 'l') && $count > 0) {
                $out .= $this->shown($f, $this->abs($f)) . "\n";
            }
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdWc(array $a): string
    {
        [$flags, $files] = self::split($a);
        $cols = $flags === '' ? ['l', 'w', 'c'] : array_values(array_filter(['l', 'w', 'c'], static fn ($k) => str_contains($flags, $k)));
        $fmt = static function (array $counts) use ($cols): string {
            $parts = [];
            foreach ($cols as $i => $k) {
                $parts[] = sprintf($i === 0 ? '%9d' : ' %9d', $counts[$k]);
            }

            return implode('', $parts);
        };
        if ($files === []) {
            return $fmt(['l' => 0, 'w' => 0, 'c' => 0]) . "\n";
        }
        $out = '';
        foreach ($files as $f) {
            [$c, $err] = $this->read('wc', $f);
            if ($c === null) {
                $out .= $err;
                continue;
            }
            $counts = ['l' => substr_count($c, "\n"), 'w' => count(preg_split('~\s+~', trim($c), -1, PREG_SPLIT_NO_EMPTY) ?: []), 'c' => strlen($c)];
            $out .= $fmt($counts) . ' ' . $this->shown($f, $this->abs($f)) . "\n";
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdDigest(string $name, array $a): string
    {
        $algo = ['md5sum' => 'md5', 'sha1sum' => 'sha1', 'sha256sum' => 'sha256', 'sha512sum' => 'sha512'][$name];
        [, $files] = self::split($a);
        if ($files === []) {
            return hash($algo, '') . "  -\n";
        }
        $out = '';
        foreach ($files as $f) {
            [$c, $err] = $this->read($name, $f);
            $out .= $c === null ? $err : hash($algo, $c) . '  ' . $this->shown($f, $this->abs($f)) . "\n";
        }

        return $out;
    }

    /** Stream applets: nothing on an empty stdin, a missing-file line for a file they cannot open. */
    private function cmdStream(string $name, array $a): string
    {
        [, $files] = self::split($a);
        if ($name === 'tr' || $name === 'xargs' || $name === 'yes' || $name === 'seq' || $name === 'shuf' || $files === []) {
            return '';
        }
        $out = '';
        foreach ($files as $f) {
            [$c, $err] = $this->read($name, $f);
            if ($c === null) {
                $out .= $err;
            } elseif (in_array($name, ['gunzip', 'zcat', 'bzcat', 'xzcat', 'unxz', 'bunzip2'], true)) {
                $out .= "{$name}: invalid magic\n";
            } elseif ($name === 'gzip' || $name === 'bzip2') {
                $out .= "{$name}: can't open '" . $this->shown($f, $this->abs($f)) . ".gz': Read-only file system\n";
            }
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdFind(array $a): string
    {
        $roots = [];
        $i = 0;
        while ($i < count($a) && ($a[$i] === '' || $a[$i][0] !== '-')) {
            $roots[] = $a[$i++];
        }
        if ($roots === []) {
            $roots = ['.'];
        }
        $name = null;
        $type = null;
        $none = false;
        for (; $i < count($a); $i++) {
            if (($a[$i] === '-name' || $a[$i] === '-iname') && isset($a[$i + 1])) {
                $name = $a[++$i];
            } elseif ($a[$i] === '-type' && isset($a[$i + 1])) {
                $type = $a[++$i];
            } elseif (in_array($a[$i], ['-perm', '-user', '-uid', '-writable', '-newer', '-mtime'], true)) {
                // No setuid binaries, no writable paths, nothing newer than the image.
                $none = true;
            }
        }
        $out = '';
        foreach ($roots as $r) {
            $abs = $this->abs($r);
            if (!isset($this->fs[$abs])) {
                $out .= "find: '" . $this->slotPath($r) . "': No such file or directory\n";
                continue;
            }
            $errs = '';
            foreach ($this->walk($abs, $errs, 'find') as $p) {
                if ($none) {
                    continue;
                }
                if ($type !== null && $this->type($p) !== ($type === 'f' ? 'f' : ($type === 'l' ? 'l' : 'd'))) {
                    continue;
                }
                if ($name !== null && !fnmatch($name, basename($p))) {
                    continue;
                }
                $out .= ($r === '.' || $r === './' ? '.' . substr($p, strlen(self::CWD)) : $p) . "\n";
            }
            $out .= $errs;
        }

        return $out;
    }

    /**
     * Every path under $abs, depth first, skipping what this identity cannot read (one error line each).
     *
     * @return list<string>
     */
    private function walk(string $abs, string &$errors, string $applet): array
    {
        $out = [$abs];
        if ($this->type($abs) !== 'd') {
            return $out;
        }
        if ($this->denied($abs)) {
            $errors .= "{$applet}: {$abs}: Permission denied\n";

            return $out;
        }
        $names = $this->children[$abs] ?? [];
        sort($names, SORT_STRING);
        foreach ($names as $n) {
            $child = rtrim($abs, '/') . '/' . $n;
            if ($this->fs[$child]['t'] === 'l') {
                $out[] = $child;
                continue;
            }
            array_push($out, ...$this->walk($child, $errors, $applet));
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdStat(array $a): string
    {
        [, $files] = self::split($a);
        $out = '';
        foreach ($files as $f) {
            $abs = $this->abs($f);
            if (!isset($this->fs[$abs])) {
                $out .= "stat: can't stat '" . $this->slotPath($f) . "': No such file or directory\n";
                continue;
            }
            $e = $this->fs[$abs];
            $kind = ['d' => 'directory', 'l' => 'symbolic link', 'c' => 'character special file', 'f' => $this->size($abs) === 0 ? 'regular empty file' : 'regular file'][$e['t']];
            $mode = ['d' => 'd', 'l' => 'l', 'c' => 'c', 'f' => '-'][$e['t']] . $e['m'];
            $octal = self::octal($e['m']);
            $uid = $e['u'] === 'www-data' ? 33 : 0;
            $gid = $e['g'] === 'www-data' ? 33 : ($e['g'] === 'shadow' ? 42 : 0);
            $out .= '  File: ' . $this->shown($f, $abs) . ($e['t'] === 'l' ? ' -> ' . $e['to'] : '') . "\n"
                . sprintf("  Size: %-10d\tBlocks: %-10d IO Block: 4096   %s", $this->size($abs), (int) ceil($this->size($abs) / 4096) * 8, $kind) . "\n"
                . sprintf("Device: 0,52\tInode: %-11d Links: 1", $e['ino'] ?? 1048612) . "\n"
                . sprintf('Access: (%04o/%s)  Uid: (%5d/%8s)   Gid: (%5d/%8s)', $octal, $mode, $uid, $e['u'], $gid, $e['g']) . "\n"
                . "Access: 2026-11-03 09:12:00.000000000 +0000\nModify: 2026-11-03 09:12:00.000000000 +0000\nChange: 2026-11-03 09:12:00.000000000 +0000\n";
        }

        return $out;
    }

    private static function octal(string $rwx): int
    {
        $v = 0;
        foreach (str_split($rwx) as $i => $c) {
            if ($c !== '-') {
                $v |= 1 << (8 - $i);
            }
        }

        return $v;
    }

    /** @param list<string> $a */
    private function cmdReadlink(array $a): string
    {
        [$flags, $files] = self::split($a);
        $out = '';
        foreach ($files as $f) {
            $abs = $this->abs($f);
            $e = $this->fs[$abs] ?? null;
            if (str_contains($flags, 'f')) {
                $out .= ($e !== null ? $this->resolve($abs) : $this->slotPath($abs)) . "\n";
            } elseif ($e !== null && $e['t'] === 'l') {
                $out .= $e['to'] . "\n";
            }
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdRealpath(array $a): string
    {
        [, $files] = self::split($a);
        $out = '';
        foreach ($files as $f) {
            $abs = $this->abs($f);
            $out .= isset($this->fs[$abs])
                ? $this->resolve($abs) . "\n"
                : 'realpath: ' . $this->slotPath($f) . ": No such file or directory\n";
        }

        return $out;
    }

    private function which(string $name): ?string
    {
        if ($name === '' || str_contains($name, '/')) {
            return null;
        }
        foreach (explode(':', self::PATH) as $dir) {
            $p = $dir . '/' . $name;
            if (isset($this->fs[$p]) && $this->fs[$p]['t'] !== 'd') {
                return $p;
            }
        }

        return null;
    }

    /** @param list<string> $a */
    private function cmdWhich(array $a): string
    {
        $out = '';
        foreach ($a as $n) {
            $p = $this->which($n);
            if ($p !== null) {
                $out .= $p . "\n";
            }
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdType(array $a): string
    {
        $out = '';
        foreach ($a as $n) {
            if (in_array($n, ['if', 'then', 'else', 'elif', 'fi', 'case', 'esac', 'for', 'while', 'until', 'do', 'done', 'in', '!', '{', '}'], true)) {
                $out .= "{$n} is a shell keyword\n";
            } elseif (in_array($n, self::BUILTINS, true)) {
                $out .= "{$n} is a shell builtin\n";
            } elseif (($p = $this->which($n)) !== null) {
                $out .= "{$n} is {$p}\n";
            } else {
                $out .= (in_array($n, self::ABSENT, true) ? $n : $this->slotWord($n, self::PATH_CAP)) . ": not found\n";
            }
        }

        return $out;
    }

    /** @param list<string> $a */
    private function cmdCommand(array $a, int $depth): string
    {
        if (($a[0] ?? '') === '-v' || ($a[0] ?? '') === '-V') {
            $out = '';
            foreach (array_slice($a, 1) as $n) {
                if (in_array($n, self::BUILTINS, true)) {
                    $out .= $n . "\n";
                } elseif (($p = $this->which($n)) !== null) {
                    $out .= $p . "\n";
                }
            }

            return $out;
        }

        return $this->exec($a, $depth + 1);
    }

    /** @param list<string> $a */
    private function cmdGetent(array $a): string
    {
        $db = $a[0] ?? '';
        $src = $db === 'passwd' ? CannedData::PASSWD : ($db === 'group' ? CannedData::GROUP : ($db === 'hosts' ? $this->hostsFile() : null));
        if ($src === null) {
            return '';
        }
        if (!isset($a[1])) {
            return $src;
        }
        foreach (explode("\n", $src) as $line) {
            if ($line !== '' && (str_starts_with($line, $a[1] . ':') || preg_match('~\s' . preg_quote($a[1], '~') . '(\s|$)~', $line) === 1)) {
                return $line . "\n";
            }
        }

        return '';
    }

    /** @param list<string> $a */
    private function cmdEcho(array $a): string
    {
        $nl = true;
        while ($a !== [] && in_array($a[0], ['-n', '-e', '-E', '-ne', '-en'], true)) {
            if (str_contains($a[0], 'n')) {
                $nl = false;
            }
            array_shift($a);
        }
        if ($a === []) {
            return $nl ? "\n" : '';
        }
        $text = implode(' ', $a);

        return $this->slotWord($text, self::ECHO_CAP, true) . ($nl ? "\n" : '');
    }

    /** @param list<string> $a */
    private function cmdPrintf(array $a): string
    {
        $fmt = array_shift($a);
        $out = (string) preg_replace_callback('~%[sd]~', static function () use (&$a) {
            return (string) (array_shift($a) ?? '');
        }, $fmt);

        return $this->slotWord($out, self::ECHO_CAP, true);
    }

    /** @param list<string> $a */
    private function cmdCd(array $a): string
    {
        $dir = $a[0] ?? $this->id->home;
        if ($dir === '-') {
            return self::CWD . "\n";
        }
        $abs = $this->abs($dir);
        if (!isset($this->fs[$abs])) {
            return AshVocabulary::render('cd_fail', $this->slotPath($dir), 'No such file or directory') . "\n";
        }
        if ($this->type($abs) !== 'd') {
            return AshVocabulary::render('cd_fail', $this->shown($dir, $abs), 'Not a directory') . "\n";
        }
        if ($this->denied($abs)) {
            return AshVocabulary::render('cd_fail', $this->shown($dir, $abs), 'Permission denied') . "\n";
        }

        return '';
    }

    // --- writes, network, privilege ---------------------------------------------------------------

    /** @param list<string> $a */
    private function cmdWrite(string $name, array $a): string
    {
        [$flags, $paths] = self::split($a);
        if ($name === 'chmod' || $name === 'chown' || $name === 'chgrp' || $name === 'chattr') {
            array_shift($paths);
        }
        if ($name === 'mktemp') {
            return "mktemp: failed to create file via template '/tmp/tmp.XXXXXX': Read-only file system\n";
        }
        if ($paths === []) {
            return self::BUSYBOX . "\n\nUsage: {$name} [OPTIONS] FILE...\n";
        }
        if (in_array($name, ['cp', 'mv', 'ln', 'install', 'link'], true) && count($paths) >= 2) {
            $src = $paths[0];
            $dst = $paths[count($paths) - 1];
            if (($name === 'cp' || $name === 'mv') && !isset($this->fs[$this->abs($src)])) {
                return "{$name}: can't stat '" . $this->slotPath($src) . "': No such file or directory\n";
            }
            $target = $this->type($this->abs($dst)) === 'd' ? rtrim($this->abs($dst), '/') . '/' . basename($src) : $dst;
            $err = $this->writeError($this->abs($target));

            return match ($name) {
                'cp', 'install' => "{$name}: can't create '" . $this->shownOrSlot($target) . "': {$err}\n",
                'mv' => "mv: can't rename '" . $this->shownOrSlot($src) . "': {$err}\n",
                default => "{$name}: " . $this->shownOrSlot($target) . ": {$err}\n",
            };
        }
        $out = '';
        foreach ($paths as $p) {
            $abs = $this->abs($p);
            $exists = isset($this->fs[$abs]);
            if (!$exists && in_array($name, ['rm', 'rmdir', 'chmod', 'chown', 'chgrp', 'unlink', 'truncate', 'shred', 'chattr'], true)) {
                if ($name === 'rm' && str_contains($flags, 'f')) {
                    continue;
                }
                $out .= ($name === 'rm' ? "rm: can't remove '" . $this->slotPath($p) . "'" : "{$name}: " . $this->slotPath($p)) . ": No such file or directory\n";
                continue;
            }
            if ($name === 'rm' && $this->type($abs) === 'd' && !str_contains($flags, 'r') && !str_contains($flags, 'R')) {
                $out .= "rm: '" . $this->shown($p, $abs) . "' is a directory\n";
                continue;
            }
            if (($name === 'chown' || $name === 'chgrp') && !$this->id->isRoot()) {
                $out .= "{$name}: " . $this->shownOrSlot($p) . ": Operation not permitted\n";
                continue;
            }
            $err = $this->writeError($abs);
            $shown = $this->shownOrSlot($p);
            $out .= match ($name) {
                'mkdir' => "mkdir: can't create directory '{$shown}': {$err}\n",
                'rm' => "rm: can't remove '{$shown}': {$err}\n",
                'rmdir' => "rmdir: '{$shown}': {$err}\n",
                'tee', 'truncate' => "{$name}: {$shown}: {$err}\n",
                default => "{$name}: {$shown}: {$err}\n",
            };
        }

        return $out;
    }

    /** Why a write to $abs fails: the root filesystem and /dev are read-only, /dev/shm is full. */
    private function writeError(string $abs): string
    {
        if ($abs === '/dev/shm' || str_starts_with($abs, '/dev/shm/')) {
            return 'No space left on device';
        }
        if (str_starts_with($abs, '/proc/')) {
            return isset($this->fs[$abs]) ? 'Permission denied' : 'No such file or directory';
        }

        return 'Read-only file system';
    }

    /** @param list<string> $a */
    private function cmdTar(array $a): string
    {
        if ($a === []) {
            return "tar: need -c, -t or -x\n";
        }
        $flags = ltrim($a[0], '-');
        $file = null;
        foreach ($a as $i => $w) {
            if ($w === '-f' || ($i === 0 && str_contains($flags, 'f'))) {
                $file = $a[$i + 1] ?? null;
                break;
            }
        }
        if ($file === null || $file === '-') {
            return '';
        }
        if (str_contains($flags, 'c')) {
            return "tar: can't open '" . $this->shownOrSlot($file) . "': " . $this->writeError($this->abs($file)) . "\n";
        }

        return isset($this->fs[$this->abs($file)])
            ? "tar: invalid tar magic\n"
            : "tar: can't open '" . $this->slotPath($file) . "': No such file or directory\n";
    }

    /** @param list<string> $a */
    private function cmdWget(array $a): string
    {
        $url = null;
        foreach ($a as $i => $w) {
            if ($w !== '' && $w[0] !== '-' && !in_array($a[$i - 1] ?? '', ['-O', '-T', '-o', '-P', '-U', '--header'], true)) {
                $url = $w;
            }
        }
        if ($url === null) {
            return self::BUSYBOX . "\n\nUsage: wget [-cqS] [--spider] [-O FILE] [-o LOGFILE] [--header STR]\n\t[--post-data STR | --post-file FILE] [-Y on/off]\n\t[-P DIR] [-U AGENT] [-T SEC] URL...\n";
        }
        $host = (string) (parse_url(str_contains($url, '://') ? $url : 'http://' . $url, PHP_URL_HOST) ?? '');

        return $this->connectFailure('wget', $host);
    }

    /** Internal names and raw IPs refuse the connection; anything else fails to resolve. */
    private function connectFailure(string $applet, string $host): string
    {
        if ($host === $this->registry || str_ends_with($host, '.internal') || str_ends_with($host, '.local')
            || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return "{$applet}: can't connect to remote host: Connection refused\n";
        }

        return "{$applet}: bad address '" . $this->slotWord($host, self::PATH_CAP) . "'\n";
    }

    /** @param list<string> $a */
    private function cmdNc(array $a): string
    {
        [$flags, $rest] = self::split($a);
        if (str_contains($flags, 'l')) {
            return '';
        }
        if ($rest === []) {
            return self::BUSYBOX . "\n\nUsage: nc [OPTIONS] HOST PORT  - connect\nnc [OPTIONS] -l -p PORT [HOST] [PORT]  - listen\n";
        }

        return $this->connectFailure('nc', $rest[0]);
    }

    /** @param list<string> $a */
    private function cmdPing(string $name, array $a): string
    {
        [, $rest] = self::split($a);
        if ($rest === []) {
            return self::BUSYBOX . "\n\nUsage: {$name} [OPTIONS] HOST\n";
        }
        if (!$this->id->isRoot() && $name !== 'traceroute') {
            return "{$name}: permission denied (are you root?)\n";
        }
        $host = $rest[count($rest) - 1];
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            return "{$name}: bad address '" . $this->slotWord($host, self::PATH_CAP) . "'\n";
        }
        $ip = $this->slotWord($host, self::PATH_CAP);

        return "PING {$ip} ({$ip}): 56 data bytes\n{$name}: sendto: Network unreachable\n";
    }

    /** @param list<string> $a */
    private function cmdApk(array $a): string
    {
        $verb = $a[0] ?? '';
        if ($verb === '' || $verb === '--help' || $verb === '-h') {
            return "apk-tools 2.14.0, compiled for x86_64.\n\nusage: apk [<OPTIONS>...] COMMAND [<ARGUMENTS>...]\n";
        }
        if ($verb === '--version' || $verb === '-V') {
            return "apk-tools 2.14.0, compiled for x86_64.\n";
        }
        if ($verb === 'info' || $verb === 'list') {
            return "alpine-baselayout\nalpine-baselayout-data\nalpine-keys\napk-tools\nbash\nbusybox\nbusybox-binsh\n"
                . "ca-certificates-bundle\niproute2-ss\nlibc-utils\nmusl\nmusl-utils\nscanelf\nssl_client\ntini\nzlib\n";
        }
        $why = $this->id->isRoot() ? 'Read-only file system' : 'Permission denied';

        return "ERROR: Unable to lock database: {$why}\nERROR: Failed to open apk database: {$why}\n";
    }

    /** @param list<string> $a */
    private function cmdSu(array $a, int $depth): string
    {
        if (!$this->id->isRoot()) {
            return "su: must be suid to work properly\n";
        }
        foreach ($a as $i => $w) {
            if ($w === '-c' && isset($a[$i + 1])) {
                return $this->exec([$a[$i + 1]], $depth + 1);
            }
        }

        return '';
    }

    /** @param list<string> $a */
    private function cmdKill(string $name, array $a): string
    {
        [, $rest] = self::split($a);
        if ($rest === []) {
            return $name === 'kill' ? "kill: usage: kill [-s sigspec | -signum | -sigspec] [pid | job]... or\nkill -l [exitstatus]\n" : '';
        }
        if ($this->id->isRoot() || $name !== 'kill') {
            return '';
        }
        $pid = $rest[0];

        return ctype_digit($pid) ? "sh: can't kill pid {$pid}: Operation not permitted\n" : '';
    }

    /** @param list<string> $a */
    private function cmdPidof(array $a): string
    {
        [, $rest] = self::split($a);
        $n = $rest[0] ?? '';

        return match ($n) {
            'php-fpm' => "14 13 12 7\n",
            'tini' => "1\n",
            default => '',
        };
    }

    /** @param list<string> $a */
    private function cmdPhp(array $a): string
    {
        if ($a === []) {
            return '';
        }
        $v = $this->phpVersion;
        [$major, $minor, $patch] = array_map('intval', explode('.', $v) + [0, 0, 0]);
        $zend = $major >= 8 ? "4.{$minor}.{$patch}" : "3.{$minor}.0";
        switch ($a[0]) {
            case '-v':
            case '--version':
                return "PHP {$v} (cli) (built: Nov  3 2026 08:51:20) (NTS)\nCopyright (c) The PHP Group\n"
                    . "Zend Engine v{$zend}, Copyright (c) Zend Technologies\n"
                    . "    with Zend OPcache v{$v}, Copyright (c), by Zend Technologies\n";
            case '-m':
                return "[PHP Modules]\nCore\nctype\ncurl\ndate\ndom\nfileinfo\nfilter\nhash\niconv\njson\nlibxml\nmbstring\nmysqlnd\n"
                    . "openssl\npcre\nPDO\npdo_mysql\npdo_sqlite\nPhar\nposix\nreadline\nReflection\nsession\nSimpleXML\nsodium\nSPL\n"
                    . "sqlite3\nstandard\ntokenizer\nxml\nxmlreader\nxmlwriter\nZend OPcache\nzlib\n\n[Zend Modules]\nZend OPcache\n\n";
            case '-i':
                return "phpinfo()\nPHP Version => {$v}\n\nSystem => " . $this->uname() . "\nBuild Date => Nov  3 2026 08:51:20\n"
                    . "Server API => Command Line Interface\nLoaded Configuration File => (none)\n";
            case '-r':
                return '';
        }
        $file = $a[0];
        $abs = $this->abs($file);
        if (!isset($this->fs[$abs]) || $this->type($abs) === 'd' || $this->denied($abs)) {
            return 'Could not open input file: ' . $this->shownOrSlot($file) . "\n";
        }

        return $abs === '/var/www/html/index.php' ? '' : $this->content($this->resolve($abs), 'php');
    }

    /** @param list<string> $a */
    private function cmdSh(string $name, array $a): string
    {
        [, $rest] = self::split($a);
        if ($rest === []) {
            return '';
        }
        $abs = $this->abs($rest[0]);
        if (!isset($this->fs[$abs])) {
            return "{$name}: can't open '" . $this->slotPath($rest[0]) . "': No such file or directory\n";
        }
        if ($this->denied($abs)) {
            return "{$name}: can't open '" . $this->shown($rest[0], $abs) . "': Permission denied\n";
        }

        return '';
    }

    /** @param list<string> $a */
    private function cmdRunner(string $name, array $a, int $depth): string
    {
        if ($name === 'chroot' || $name === 'nsenter' || $name === 'unshare') {
            return $this->id->isRoot() ? "{$name}: Operation not permitted\n" : "{$name}: Operation not permitted\n";
        }
        while ($a !== [] && $a[0] !== '' && $a[0][0] === '-') {
            array_shift($a);
            if ($name === 'nice' && $a !== [] && ctype_digit($a[0])) {
                array_shift($a);
            }
        }
        if ($name === 'flock' && $a !== []) {
            array_shift($a);
        }
        $out = $this->exec($a, $depth + 1);

        return $name === 'time' ? $out . "real\t0m 0.00s\nuser\t0m 0.00s\nsys\t0m 0.00s\n" : $out;
    }

    // --- table ------------------------------------------------------------------------------------

    private function hostsFile(): string
    {
        return "# Kubernetes-managed hosts file.\n127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
            . "fe00::0\tip6-localnet\nfe00::0\tip6-mcastprefix\nfe00::1\tip6-allnodes\nfe00::2\tip6-allrouters\n"
            . self::POD_IP . "\t" . $this->host . "\n";
    }

    private function appEnv(): string
    {
        return "# rendered by the deploy controller at rollout; application secrets are mounted at runtime, not in this file\n"
            . "APP_ROLE=web\n"
            . "APP_DB_HOST=db.svc.gateway.internal\n"
            . 'APP_REGISTRY=' . $this->registry . "\n"
            . "# admin console + customer DB are reachable only through the egress gateway, not from this pod\n"
            . "# legacy audit-archive export is still live during the SIEM cutover\n";
    }

    private function statusFile(string $applet): string
    {
        $uid = $this->id->uid;

        return "Name:\t" . (preg_match('~^[a-z0-9_-]{1,15}$~', $applet) === 1 ? $applet : 'cat') . "\nUmask:\t0022\nState:\tR (running)\n"
            . "Tgid:\t214\nPid:\t214\nPPid:\t213\nUid:\t{$uid}\t{$uid}\t{$uid}\t{$uid}\nGid:\t{$uid}\t{$uid}\t{$uid}\t{$uid}\n"
            . "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
            . "NoNewPrivs:\t1\nSeccomp:\t2\n";
    }

    private function environ(): string
    {
        if (!$this->id->isRoot()) {
            return CannedData::ENVIRON;
        }
        $out = '';
        foreach ($this->envVars() as $k => $v) {
            $out .= "{$k}={$v}\x00";
        }

        return $out;
    }

    private function content(string $abs, string $applet): string
    {
        $e = $this->fs[$abs] ?? null;
        if ($e === null || $e['t'] === 'd') {
            return '';
        }
        $c = $e['c'] ?? '';

        return match ($c) {
            '@status' => $this->statusFile($applet),
            '@environ' => $this->environ(),
            '@hosts' => $this->hostsFile(),
            '@appenv' => $this->appEnv(),
            '@mounts' => $this->mountTable(),
            '@uptime' => max(60, $this->now() - $this->bootEpoch()) . ".42 1874.20\n",
            default => $c,
        };
    }

    private function size(string $abs): int
    {
        $e = $this->fs[$abs] ?? null;
        if ($e === null) {
            return 0;
        }

        return match ($e['t']) {
            'd' => 4096,
            'l' => strlen((string) $e['to']),
            'c' => 0,
            default => isset($e['size']) ? (int) $e['size'] : strlen($this->content($abs, 'cat')),
        };
    }

    private function buildFs(): void
    {
        $dir = static fn (string $mode = 'rwxr-xr-x', bool $deny = false): array => ['t' => 'd', 'm' => $mode, 'u' => 'root', 'g' => 'root', 'deny' => $deny];
        $file = static fn (string $c, string $mode = 'rw-r--r--', string $mt = self::IMAGE_MTIME, string $u = 'root', string $g = 'root', bool $deny = false): array => ['t' => 'f', 'm' => $mode, 'u' => $u, 'g' => $g, 'c' => $c, 'mt' => $mt, 'deny' => $deny];

        foreach ([
            '/', '/bin', '/dev', '/dev/pts', '/dev/mqueue', '/etc', '/etc/apk', '/etc/profile.d', '/home', '/lib',
            '/media', '/mnt', '/opt', '/run', '/run/sshd', '/run/deploy', '/sbin', '/srv', '/sys', '/sys/fs',
            '/sys/fs/cgroup', '/usr', '/usr/bin', '/usr/lib', '/usr/local', '/usr/local/bin', '/usr/local/etc',
            '/usr/local/etc/php', '/usr/local/etc/php/conf.d', '/usr/local/etc/php-fpm.d', '/usr/local/lib',
            '/usr/local/sbin', '/usr/sbin', '/usr/share', '/var', '/var/cache', '/var/empty', '/var/lib',
            '/var/log', '/var/spool', '/var/tmp', '/var/www', '/var/www/html', '/data',
        ] as $p) {
            $this->fs[$p] = $dir();
        }
        $this->fs['/root'] = $dir('rwx------', true);
        $this->fs['/tmp'] = $dir('rwxrwxrwt');
        $this->fs['/dev/shm'] = $dir('rwxrwxrwt');
        $this->fs['/proc'] = $dir('r-xr-xr-x');
        $this->fs['/proc/self'] = $dir('r-xr-xr-x');
        $this->fs['/proc/self/fd'] = $dir('r-x------');

        $this->fs['/etc/passwd'] = $file(CannedData::PASSWD);
        $this->fs['/etc/group'] = $file(CannedData::GROUP);
        $this->fs['/etc/shadow'] = $file(CannedData::SHADOW, 'rw-r-----', self::IMAGE_MTIME, 'root', 'shadow', true);
        $this->fs['/etc/hostname'] = $file($this->host . "\n", 'rw-r--r--', self::DEPLOY_MTIME);
        $this->fs['/etc/hosts'] = $file('@hosts', 'rw-r--r--', self::DEPLOY_MTIME);
        $this->fs['/etc/resolv.conf'] = $file("search default.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\noptions ndots:5\n", 'rw-r--r--', self::DEPLOY_MTIME);
        $this->fs['/etc/os-release'] = $file("NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME=\"Alpine Linux v3.19\"\n");
        $this->fs['/etc/alpine-release'] = $file("3.19.1\n");
        $this->fs['/etc/shells'] = $file("# valid login shells\n/bin/sh\n/bin/ash\n/bin/bash\n");
        $this->fs['/etc/profile'] = $file("export CHARSET=UTF-8\nexport LANG=C.UTF-8\nexport PAGER=less\nexport PS1='\\h:\\w\\$ '\numask 022\n\nfor script in /etc/profile.d/*.sh ; do\n\tif [ -r \"\$script\" ] ; then\n\t\t. \"\$script\"\n\tfi\ndone\nunset script\n");
        $this->fs['/etc/profile.d/locale.sh'] = $file("export CHARSET=\${CHARSET:-UTF-8}\nexport LANG=\${LANG:-C.UTF-8}\nexport LC_COLLATE=\${LC_COLLATE:-C}\n");
        $this->fs['/etc/apk/world'] = $file("alpine-baselayout\nalpine-keys\napk-tools\nbash\nbusybox\nca-certificates-bundle\niproute2-ss\nlibc-utils\ntini\n");
        $this->fs['/proc/self/status'] = $file('@status', 'r--r--r--');
        $this->fs['/proc/self/environ'] = $file('@environ', 'r--------');
        $this->fs['/proc/self/mounts'] = $file('@mounts', 'r--r--r--');
        $this->fs['/proc/mounts'] = $file('@mounts', 'r--r--r--');
        $this->fs['/proc/version'] = $file("Linux version 5.15.0 (builder@buildkitsandbox) (gcc (GCC) 12.2.0) #1 SMP\n", 'r--r--r--');
        $this->fs['/proc/uptime'] = $file('@uptime', 'r--r--r--');
        $this->fs['/proc/loadavg'] = $file("0.21 0.18 0.11 2/187 214\n", 'r--r--r--');
        $this->fs['/proc/cpuinfo'] = $file("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\ncpu MHz\t\t: 2499.998\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\ncpu MHz\t\t: 2499.998\n", 'r--r--r--');
        $this->fs['/proc/meminfo'] = $file("MemTotal:        2027664 kB\nMemFree:          298212 kB\nMemAvailable:    1240212 kB\nSwapTotal:             0 kB\n", 'r--r--r--');
        $this->fs['/proc/self/fd/0'] = ['t' => 'l', 'm' => 'rwx------', 'u' => $this->id->name, 'g' => $this->id->name, 'to' => '/dev/null'];
        $this->fs['/proc/self/fd/1'] = ['t' => 'l', 'm' => 'rwx------', 'u' => $this->id->name, 'g' => $this->id->name, 'to' => 'pipe:[41813]'];
        $this->fs['/proc/self/fd/2'] = ['t' => 'l', 'm' => 'rwx------', 'u' => $this->id->name, 'g' => $this->id->name, 'to' => 'pipe:[41813]'];
        $this->fs['/sys/fs/cgroup/cgroup.controllers'] = $file("cpu io memory pids\n", 'r--r--r--');
        $this->fs['/sys/fs/cgroup/memory.max'] = $file("2147483648\n", 'rw-r--r--');
        $this->fs['/sys/fs/cgroup/cpu.max'] = $file("200000 100000\n", 'rw-r--r--');
        $this->fs['/sys/fs/cgroup/pids.max'] = $file("4096\n", 'rw-r--r--');
        $this->fs['/run/deploy/app.env'] = $file('@appenv', 'r--r--r--', self::DEPLOY_MTIME);
        $this->fs['/var/www/html/index.php'] = $file("<?php\ndeclare(strict_types=1);\n\n// Application pages are served upstream; this pod only answers the load balancer's health check.\nif (trim(\$_SERVER['REQUEST_URI'] ?? '', '/') === 'healthz') {\n    echo \"ok\\n\";\n    return;\n}\n\nhttp_response_code(404);\n");
        $this->fs['/usr/local/etc/php-fpm.conf'] = $file("[global]\nerror_log = /proc/self/fd/2\ndaemonize = no\n\ninclude=etc/php-fpm.d/*.conf\n");
        // The pool runs as the console's identity, so `ps`, `id` and this file tell one story.
        $pool = $this->id->name;
        $this->fs['/usr/local/etc/php-fpm.d/www.conf'] = $file("[www]\nuser = {$pool}\ngroup = {$pool}\nlisten = 9000\npm = dynamic\npm.max_children = 5\npm.start_servers = 2\npm.min_spare_servers = 1\npm.max_spare_servers = 3\nclear_env = no\n");
        $this->fs['/lib/ld-musl-x86_64.so.1'] = $file("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00", 'rwxr-xr-x');

        // The processes `ps` lists, so /proc agrees with it.
        $worker = $this->id->isRoot() ? 0 : 33;
        foreach ([
            1 => ["/sbin/tini\x00--\x00php-fpm\x00" . ($this->id->isRoot() ? "-R\x00" : ''), 'tini', 0],
            7 => ["php-fpm: master process (/usr/local/etc/php-fpm.conf)\x00", 'php-fpm', 0],
            12 => ["php-fpm: pool www\x00", 'php-fpm', $worker],
            13 => ["php-fpm: pool www\x00", 'php-fpm', $worker],
            14 => ["php-fpm: pool www\x00", 'php-fpm', $worker],
        ] as $pid => [$cmdline, $name, $uid]) {
            $this->fs["/proc/{$pid}"] = $dir('r-xr-xr-x');
            $this->fs["/proc/{$pid}/cmdline"] = $file($cmdline, 'r--r--r--');
            $this->fs["/proc/{$pid}/status"] = $file("Name:\t{$name}\nState:\tS (sleeping)\nPid:\t{$pid}\nUid:\t{$uid}\t{$uid}\t{$uid}\t{$uid}\nGid:\t{$uid}\t{$uid}\t{$uid}\t{$uid}\n"
                . "CapEff:\t0000000000000000\nNoNewPrivs:\t1\n", 'r--r--r--');
        }

        foreach (['null', 'zero', 'random', 'urandom', 'full', 'tty'] as $n) {
            $this->fs['/dev/' . $n] = ['t' => 'c', 'm' => 'rw-rw-rw-', 'u' => 'root', 'g' => 'root'];
        }
        $this->fs['/dev/fd'] = ['t' => 'l', 'm' => 'rwxrwxrwx', 'u' => 'root', 'g' => 'root', 'to' => '/proc/self/fd'];
        foreach (['stdin' => 0, 'stdout' => 1, 'stderr' => 2] as $n => $fd) {
            $this->fs['/dev/' . $n] = ['t' => 'l', 'm' => 'rwxrwxrwx', 'u' => 'root', 'g' => 'root', 'to' => '/proc/self/fd/' . $fd];
        }

        $elf = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00";
        foreach (self::BINARIES as $p => $size) {
            $this->fs[$p] = ['t' => 'f', 'm' => 'rwxr-xr-x', 'u' => 'root', 'g' => 'root', 'c' => $elf, 'size' => $size, 'mt' => self::IMAGE_MTIME];
        }
        foreach (self::APPLETS as $d => $names) {
            foreach ($names as $n) {
                $this->fs[$d . '/' . $n] = ['t' => 'l', 'm' => 'rwxrwxrwx', 'u' => 'root', 'g' => 'root', 'to' => '/bin/busybox'];
            }
        }

        $ino = 1048577;
        foreach ($this->fs as $p => &$e) {
            $e['mt'] ??= self::IMAGE_MTIME;
            $e['ino'] = $ino;
            $ino += 7;
            if ($p !== '/') {
                $this->children[$this->parent($p)][] = basename($p);
            }
        }
        unset($e);
    }

    // --- paths ------------------------------------------------------------------------------------

    /** Absolute, normalised form of a path as typed, relative to the working directory. */
    private function abs(string $p): string
    {
        if ($p === '') {
            return self::CWD;
        }
        $full = $p[0] === '/' ? $p : self::CWD . '/' . $p;
        $parts = [];
        foreach (explode('/', $full) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($parts);
                continue;
            }
            $parts[] = $seg;
        }

        return '/' . implode('/', $parts);
    }

    private function parent(string $abs): string
    {
        $d = dirname($abs);

        return $d === '' ? '/' : $d;
    }

    /** Follow symlinks inside the table (bounded). */
    private function resolve(string $abs): string
    {
        for ($i = 0; $i < 8; $i++) {
            $e = $this->fs[$abs] ?? null;
            if ($e === null || $e['t'] !== 'l' || ($e['to'][0] ?? '') !== '/') {
                return $abs;
            }
            $abs = $e['to'];
        }

        return $abs;
    }

    private function type(string $abs): string
    {
        return $this->fs[$this->resolve($abs)]['t'] ?? '';
    }

    private function denied(string $abs): bool
    {
        return !$this->id->isRoot() && (bool) ($this->fs[$this->resolve($abs)]['deny'] ?? false);
    }

    /** True when a directory above $abs cannot be entered by this identity (so even a missing path is "denied"). */
    private function underDenied(string $abs): bool
    {
        for ($d = $this->parent($abs); $d !== '/'; $d = $this->parent($d)) {
            if (isset($this->fs[$d]) && $this->denied($d)) {
                return true;
            }
        }

        return false;
    }

    /**
     * A path as the user typed it. A path the table knows is shown as typed when that is the table's
     * own spelling; any other spelling is attacker text and goes through the slot rules.
     */
    private function shown(string $typed, string $abs): string
    {
        return ($typed === $abs || $typed === '.' || $typed === basename($abs) && $this->parent($abs) === self::CWD)
            ? $typed
            : $this->slotPath($typed);
    }

    private function shownOrSlot(string $typed): string
    {
        $abs = $this->abs($typed);

        return isset($this->fs[$abs]) ? $this->shown($typed, $abs) : $this->slotPath($typed);
    }

    private function slotPath(string $v): string
    {
        return $this->slotWord($v, self::PATH_CAP);
    }

    /**
     * Attacker text in an answer: only from a non-GET body, only the safe charset, capped, escaped.
     * $spaces allows the single spaces echo puts between its words.
     */
    private function slotWord(string $v, int $cap, bool $spaces = false): string
    {
        if (!$this->mayReflect) {
            throw new SlotRefused();
        }
        $check = $spaces ? str_replace(' ', '', $v) : $v;
        if (preg_match(self::SLOT_CHARSET, $check) !== 1) {
            throw new SlotRefused();
        }
        if (strlen($v) > $cap) {
            $v = substr($v, 0, $cap);
        }

        return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    // --- globs and tilde --------------------------------------------------------------------------

    /**
     * Expand `~` and unquoted globs against the table, the way the shell does before the command
     * runs. An unmatched glob stays literal.
     *
     * @param list<string> $argv
     * @return list<string>
     */
    private function expand(array $argv): array
    {
        $out = [];
        foreach ($argv as $i => $w) {
            if ($w !== '' && $w[0] === '~') {
                $slash = strpos($w, '/');
                $user = substr($w, 1, $slash === false ? null : $slash - 1);
                $home = $user === '' ? $this->id->home : ($user === 'root' ? '/root' : ($user === 'www-data' ? '/var/www' : null));
                if ($home !== null) {
                    $w = $home . ($slash === false ? '' : substr($w, $slash));
                }
            }
            if ($i > 0 && strpbrk($w, '*?[') !== false) {
                $matches = $this->glob($w);
                if ($matches !== []) {
                    array_push($out, ...$matches);
                    continue;
                }
            }
            $out[] = $w;
        }

        return $out;
    }

    /** @return list<string> */
    private function glob(string $pattern): array
    {
        $slash = strrpos($pattern, '/');
        $dirPart = $slash === false ? '' : substr($pattern, 0, $slash + 1);
        $base = $slash === false ? $pattern : substr($pattern, $slash + 1);
        if (strpbrk($dirPart, '*?[') !== false || $base === '') {
            return [];
        }
        $abs = $this->abs($dirPart === '' ? '.' : $dirPart);
        if ($this->type($abs) !== 'd' || $this->denied($abs)) {
            return [];
        }
        $names = $this->children[$abs] ?? [];
        sort($names, SORT_STRING);
        $hits = [];
        foreach ($names as $n) {
            if (($n[0] !== '.' || $base[0] === '.') && fnmatch($base, $n)) {
                $hits[] = $dirPart . $n;
            }
        }

        return $hits;
    }
}
