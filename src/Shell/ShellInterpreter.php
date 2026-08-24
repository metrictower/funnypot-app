<?php

declare(strict_types=1);

namespace Funnypot\Shell;

use Funnypot\App\Render\Fake\FrozenClock;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Fs\IsADirectory;
use Funnypot\Shell\Fs\Node;
use Funnypot\Shell\Fs\Overlay;
use Funnypot\Shell\Fs\PathCanon;
use Funnypot\Shell\Fs\PathNotFound;
use Funnypot\Shell\Host\HostFacts;

/**
 * A shared, never-execute command interpreter over the FakeFilesystem + HostFacts. It is a dispatcher,
 * NOT an interpreter of attacker code: each command parses to canned/seeded output; there is no exec/
 * eval, no real FS, no outbound socket. Reads/writes go through the FakeFilesystem (writes mutate the
 * session overlay); host facts (ps/top/free/df/netstat/uname//proc) come from HostFacts. Unknown input
 * fails loudly and specifically, exactly like bash — over-eager plausible output on garbage is the tell.
 * Output is '\n'-terminated; transport adapters convert line endings and bound length for their wire.
 */
final class ShellInterpreter
{
    private const MAX_OUTPUT = 65536;
    private const FIND_BUDGET = 4000;

    public function __construct(
        private FakeFilesystem $baseFs,
        private HostFacts $facts,
        private int $maxOutput = self::MAX_OUTPUT
    ) {
    }

    /** Run a command line (may chain with ; && || / newlines) and return combined output. */
    public function run(string $line, ShellSession $s): string
    {
        $trimmed = trim($line);
        if ($trimmed !== '') {
            $s->history[] = $trimmed;
        }
        $out = '';
        foreach ($this->split($line) as $stmt) {
            $out .= $this->runStatement($stmt, $s);
            if ($s->close || strlen($out) > $this->maxOutput) {
                break;
            }
        }

        return strlen($out) > $this->maxOutput ? substr($out, 0, $this->maxOutput) : $out;
    }

    /** @return string[] statements split on ; && || and newlines (top level only) */
    private function split(string $line): array
    {
        $parts = preg_split('/\s*(?:&&|\|\||;|\r?\n)\s*/', trim($line)) ?: [];

        return array_slice(array_values(array_filter($parts, static fn (string $p): bool => trim($p) !== '')), 0, 64);
    }

    private function runStatement(string $line, ShellSession $s): string
    {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            return '';
        }
        // Pipes: emulate the producer; apply the common text filters (grep/head/tail/wc/sort) to it.
        $segments = preg_split('/\s*\|\s*/', $line) ?: [$line];
        $producer = trim($segments[0]);
        $out = $this->execOne($producer, $s);
        for ($i = 1; $i < count($segments); $i++) {
            $out = $this->applyFilter(trim($segments[$i]), $out, $s);
        }

        return $out;
    }

    private function execOne(string $line, ShellSession $s): string
    {
        $parts = $this->tokenize($line);
        if ($parts === []) {
            return '';
        }
        // Expand $? against the PREVIOUS command's status, before this command resets it.
        $parts = array_map(static fn (string $t): string => $t === '$?' ? (string) $s->lastExit : $t, $parts);
        $cmd = $parts[0];
        $args = array_slice($parts, 1);

        // A leading `sudo`/`env`-prefix just runs the rest (already root).
        if (($cmd === 'sudo' || $cmd === 'command') && $args !== []) {
            return $this->execOne(implode(' ', $args), $s);
        }

        $s->lastExit = 0;
        switch ($cmd) {
            case 'exit':
            case 'logout':
                $s->close = true;
                return "logout\n";
            case 'pwd':
                return $s->cwd . "\n";
            case 'cd':
                return $this->cd($args, $s);
            case 'ls':
            case 'dir':
            case 'll':
                return $this->ls($cmd === 'll' ? array_merge(['-l'], $args) : $args, $s);
            case 'cat':
            case 'head':
            case 'tail':
            case 'more':
            case 'less':
                return $this->cat($cmd, $args, $s);
            case 'stat':
                return $this->stat($args, $s);
            case 'echo':
                return $this->echo($args, $s);
            case 'whoami':
                return $s->user . "\n";
            case 'id':
                return $this->id($s);
            case 'hostname':
                return $s->host . "\n";
            case 'uname':
                return $this->uname($args);
            case 'ps':
                return $this->ps($args);
            case 'top':
            case 'htop':
                return $this->top($s);
            case 'free':
                return $this->free($args);
            case 'df':
                return $this->df($args);
            case 'netstat':
            case 'ss':
                return $this->netstat($s);
            case 'ifconfig':
            case 'ip':
                return $this->ifconfig($cmd, $args);
            case 'uptime':
                return $this->uptime();
            case 'w':
            case 'who':
                return $this->who($s);
            case 'env':
            case 'printenv':
                return $this->envDump($s);
            case 'export':
            case 'set':
            case 'unset':
            case 'alias':
            case ':':
                return '';
            case 'history':
                return $this->history($s);
            case 'find':
                return $this->find($args, $s);
            case 'grep':
            case 'egrep':
                return $this->grepFiles($args, $s);
            case 'wc':
                return $this->wc($args, $s);
            case 'du':
                return $this->du($args, $s);
            case 'mkdir':
                return $this->mkdir($args, $s);
            case 'touch':
                return $this->touch($args, $s);
            case 'rm':
            case 'rmdir':
                return $this->rm($args, $s);
            case 'mv':
                return $this->mv($args, $s);
            case 'cp':
                return $this->cp($args, $s);
            case 'chmod':
            case 'chown':
                return '';
            case 'wget':
            case 'curl':
                return $this->fetch($cmd, $args);
            case 'clear':
                return "\033[H\033[2J";
            case 'nproc':
                return $this->facts->os() ? ($this->serverCores() . "\n") : "1\n";
            default:
                $s->lastExit = 127;
                return "bash: {$cmd}: command not found\n";
        }
    }

    // ---- filesystem commands (through FakeFilesystem + session overlay) ----

    private function fs(ShellSession $s): FakeFilesystem
    {
        return $this->baseFs->withOverlay($s->overlay);
    }

    private function resolve(string $path, ShellSession $s): string
    {
        if ($path === '' || $path === '~') {
            return $s->env['HOME'] ?? '/root';
        }
        if (strncmp($path, '~/', 2) === 0) {
            $path = ($s->env['HOME'] ?? '/root') . '/' . substr($path, 2);
        }
        if ($path[0] !== '/') {
            $path = rtrim($s->cwd, '/') . '/' . $path;
        }

        return PathCanon::canonical($path);
    }

    /** @param string[] $args */
    private function cd(array $args, ShellSession $s): string
    {
        $target = $this->resolve($args[0] ?? '~', $s);
        $fs = $this->fs($s);
        if ($fs->isDir($target)) {
            $s->cwd = $target;
            $s->env['PWD'] = $target;
            return '';
        }
        $s->lastExit = 1;
        if ($fs->exists($target)) {
            return "bash: cd: " . ($args[0] ?? '') . ": Not a directory\n";
        }
        return "bash: cd: " . ($args[0] ?? '') . ": No such file or directory\n";
    }

    /** @param string[] $args */
    private function ls(array $args, ShellSession $s): string
    {
        $long = false;
        $all = false;
        $paths = [];
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                $long = $long || strpos($a, 'l') !== false;
                $all = $all || strpos($a, 'a') !== false || strpos($a, 'A') !== false;
            } else {
                $paths[] = $a;
            }
        }
        if ($paths === []) {
            $paths = ['.'];
        }
        $fs = $this->fs($s);
        $out = '';
        foreach ($paths as $p) {
            $target = $this->resolve($p, $s);
            if ($fs->isFile($target)) {
                $out .= $p . "\n"; // ls of a single file prints its name
                continue;
            }
            try {
                $nodes = $fs->list($target);
            } catch (PathNotFound $e) {
                $s->lastExit = 2;
                $out .= "ls: cannot access '{$p}': No such file or directory\n";
                continue;
            }
            $out .= $this->renderListing($nodes, $target, $long, $all, $fs);
        }

        return $out;
    }

    /** @param Node[] $nodes */
    private function renderListing(array $nodes, string $dir, bool $long, bool $all, FakeFilesystem $fs): string
    {
        if ($all) {
            // Real ls -a always leads with . and .. (even in an empty dir).
            $self = new Node('.', 'dir', 0, 0, 4096, 0o755, FrozenClock::epoch(), null);
            $parent = new Node('..', 'dir', 0, 0, 4096, 0o755, FrozenClock::epoch(), null);
            $nodes = array_merge([$self, $parent], $nodes);
        }
        if (!$long) {
            $names = array_map(static fn (Node $n): string => $n->name, $nodes);
            return $names === [] ? '' : implode('  ', $names) . "\n";
        }
        $subdirs = 0;
        $blocks = 0;
        foreach ($nodes as $n) {
            if ($n->isDir()) {
                $subdirs++;
            }
            $blocks += (int) (ceil(max($n->size, 1) / 512));
        }
        $out = 'total ' . $blocks . "\n";
        foreach ($nodes as $n) {
            $links = $n->isDir() ? 2 + $this->countChildDirs($n, $dir, $fs) : 1;
            $out .= sprintf(
                "%s %d %-8s %-8s %8d %s %s%s\n",
                $this->modeStr($n),
                $links,
                $this->userName($n->uid),
                $this->userName($n->gid),
                $n->size,
                gmdate('M j H:i', $n->mtime),
                $n->name,
                $n->isLink() && $n->target !== null ? ' -> ' . $n->target : ''
            );
        }

        return $out;
    }

    private function countChildDirs(Node $n, string $parentDir, FakeFilesystem $fs): int
    {
        if (!$n->isDir() || $n->name === '.' || $n->name === '..') {
            return 0;
        }
        $child = $parentDir === '/' ? '/' . $n->name : $parentDir . '/' . $n->name;
        try {
            $c = 0;
            foreach ($fs->list($child) as $g) {
                if ($g->isDir()) {
                    $c++;
                }
            }
            return $c;
        } catch (PathNotFound $e) {
            return 0;
        }
    }

    private function modeStr(Node $n): string
    {
        $type = $n->isDir() ? 'd' : ($n->isLink() ? 'l' : '-');
        $perm = $n->mode & 0o777;
        $rwx = static function (int $bits): string {
            return ($bits & 4 ? 'r' : '-') . ($bits & 2 ? 'w' : '-') . ($bits & 1 ? 'x' : '-');
        };

        return $type . $rwx($perm >> 6 & 7) . $rwx($perm >> 3 & 7) . $rwx($perm & 7);
    }

    private function userName(int $uid): string
    {
        if ($uid === 0) {
            return 'root';
        }
        if ($uid === 33 || $uid === 48) {
            return $uid === 33 ? 'www-data' : 'apache';
        }

        return (string) $uid;
    }

    /** @param string[] $args */
    private function cat(string $cmd, array $args, ShellSession $s): string
    {
        $lineLimit = 0;
        $files = [];
        for ($i = 0; $i < count($args); $i++) {
            $a = $args[$i];
            if ($a === '-n' && isset($args[$i + 1]) && ctype_digit($args[$i + 1])) {
                $lineLimit = (int) $args[++$i];
            } elseif ($a !== '' && $a[0] === '-') {
                if (preg_match('/^-(\d+)$/', $a, $m)) {
                    $lineLimit = (int) $m[1];
                }
            } else {
                $files[] = $a;
            }
        }
        if ($files === []) {
            return '';
        }
        $fs = $this->fs($s);
        $out = '';
        foreach ($files as $f) {
            $target = $this->resolve($f, $s);
            $proc = $this->facts->proc($target);
            if ($proc !== null) {
                $out .= $this->limitLines($proc, $cmd, $lineLimit);
                continue;
            }
            try {
                $out .= $this->limitLines($fs->read($target), $cmd, $lineLimit);
            } catch (IsADirectory $e) {
                $s->lastExit = 1;
                $out .= "cat: {$f}: Is a directory\n";
            } catch (PathNotFound $e) {
                $s->lastExit = 1;
                $out .= "cat: {$f}: No such file or directory\n";
            }
        }

        return $out;
    }

    private function limitLines(string $text, string $cmd, int $limit): string
    {
        if ($limit <= 0 && ($cmd === 'head' || $cmd === 'tail')) {
            $limit = 10;
        }
        if ($limit <= 0) {
            return $text;
        }
        $lines = explode("\n", rtrim($text, "\n"));
        $slice = $cmd === 'tail' ? array_slice($lines, -$limit) : array_slice($lines, 0, $limit);

        return implode("\n", $slice) . "\n";
    }

    /** @param string[] $args */
    private function stat(array $args, ShellSession $s): string
    {
        $p = $args[0] ?? '';
        if ($p === '') {
            $s->lastExit = 1;
            return "stat: missing operand\n";
        }
        $fs = $this->fs($s);
        try {
            $n = $fs->stat($this->resolve($p, $s));
        } catch (PathNotFound $e) {
            $s->lastExit = 1;
            return "stat: cannot statx '{$p}': No such file or directory\n";
        }

        return sprintf(
            "  File: %s\n  Size: %-10d Blocks: %-8d %s\nAccess: (%04o/%s)  Uid: (%5d/%8s)   Gid: (%5d/%8s)\nModify: %s\n",
            $n->name,
            $n->size,
            (int) ceil(max($n->size, 1) / 512),
            $n->isDir() ? 'directory' : ($n->isLink() ? 'symbolic link' : 'regular file'),
            $n->mode & 0o777,
            $this->modeStr($n),
            $n->uid,
            $this->userName($n->uid),
            $n->gid,
            $this->userName($n->gid),
            gmdate('Y-m-d H:i:s', $n->mtime)
        );
    }

    /** @param string[] $args */
    private function echo(array $args, ShellSession $s): string
    {
        $parts = [];
        foreach ($args as $a) {
            if ($a === '$?') {
                $parts[] = (string) $s->lastExit;
            } elseif ($a !== '' && $a[0] === '$' && isset($s->env[substr($a, 1)])) {
                $parts[] = $s->env[substr($a, 1)];
            } else {
                $parts[] = trim($a, '"\'');
            }
        }

        return implode(' ', $parts) . "\n";
    }

    private function id(ShellSession $s): string
    {
        $u = $s->user;
        $uid = $s->uid;
        $gid = $s->gid;

        return $uid === 0
            ? "uid=0(root) gid=0(root) groups=0(root)\n"
            : "uid={$uid}({$u}) gid={$gid}({$u}) groups={$gid}({$u}),27(sudo)\n";
    }

    /** @param string[] $args */
    private function uname(array $args): string
    {
        $flags = implode('', array_filter($args, static fn (string $a): bool => $a !== '' && $a[0] === '-'));
        if (strpos($flags, 'a') !== false) {
            return $this->facts->uname() . "\n";
        }
        $os = $this->facts->os();
        if (strpos($flags, 'r') !== false) {
            return $os['kernel'] . "\n";
        }

        return "Linux\n";
    }

    // ---- host-fact commands (through HostFacts) ----

    private function serverCores(): int
    {
        // via HostFacts' /proc/cpuinfo processor count (kept coherent with ServerProfile).
        return substr_count((string) $this->facts->proc('cpuinfo'), "processor\t:");
    }

    /** @param string[] $args */
    private function ps(array $args): string
    {
        $rows = $this->facts->processTable();
        $flags = implode('', $args);
        $out = strpos($flags, 'ef') !== false
            ? "UID          PID    PPID  C STIME TTY          TIME CMD\n"
            : "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n";
        foreach ($rows as $p) {
            if (strpos($flags, 'ef') !== false) {
                $out .= sprintf("%-12s %5d %6d  0 00:00 ?        00:00:00 %s\n", $p['user'], (int) $p['pid'], 1, $p['command']);
            } else {
                $out .= sprintf(
                    "%-12s %5d %4s %4s %7d %5d ?        Ssl  00:00   0:00 %s\n",
                    $p['user'],
                    (int) $p['pid'],
                    $p['cpu'],
                    $p['mem'],
                    120000 + ((int) $p['pid'] * 37 % 400000),
                    8000 + ((int) $p['pid'] * 13 % 90000),
                    $p['command']
                );
            }
        }

        return $out;
    }

    private function top(ShellSession $s): string
    {
        $rows = array_slice($this->facts->processTable(), 0, 12);
        $out = $this->uptime()
            . "Tasks: " . (count($this->facts->processTable()) + 90) . " total\n"
            . "%Cpu(s): busy\nMiB Mem : " . ($this->facts->free()['mem'][0]) . " total\n\n"
            . "  PID USER      %CPU %MEM COMMAND\n";
        foreach ($rows as $p) {
            $out .= sprintf("%5d %-8s %5s %5s %s\n", (int) $p['pid'], $p['user'], $p['cpu'], $p['mem'], $p['command']);
        }

        return $out;
    }

    /** @param string[] $args */
    private function free(array $args): string
    {
        $f = $this->facts->free();
        $div = strpos(implode('', $args), 'g') !== false ? 1024 : 1;
        $m = array_map(static fn (int $v): int => intdiv($v, $div), $f['mem']);
        $sw = array_map(static fn (int $v): int => intdiv($v, $div), $f['swap']);

        return "               total        used        free      shared  buff/cache   available\n"
            . sprintf("Mem:      %10d  %10d  %10d  %10d  %10d  %10d\n", $m[0], $m[1], $m[2], $m[3], $m[4], $m[5])
            . sprintf("Swap:     %10d  %10d  %10d\n", $sw[0], $sw[1], $sw[2]);
    }

    /** @param string[] $args */
    private function df(array $args): string
    {
        $out = "Filesystem            Size  Used Avail Use% Mounted on\n";
        foreach ($this->facts->df() as $d) {
            $out .= sprintf("%-20s %5s %5s %5s %4s %s\n", $d['fs'], $d['size'], $d['used'], $d['avail'], $d['pct'], $d['mount']);
        }

        return $out;
    }

    private function netstat(ShellSession $s): string
    {
        $out = "Active Internet connections (servers and established)\n"
            . "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n";
        foreach ($this->facts->netstat() as $c) {
            $out .= sprintf("%-5s      0      0 %-23s %-23s %s\n", $c['proto'], $c['local'], $c['foreign'], $c['state']);
        }
        // The attacker's OWN session — not seeing your own connection is the loudest shell-honeypot tell.
        $out .= sprintf(
            "%-5s      0      0 %-23s %-23s %s\n",
            'tcp',
            $this->facts->primaryIp() . ':22',
            $s->peerIp . ':' . (40000 + strlen($s->peerIp) * 111 % 20000),
            'ESTABLISHED'
        );

        return $out;
    }

    /** @param string[] $args */
    private function ifconfig(string $cmd, array $args): string
    {
        $ip = $this->facts->primaryIp();
        if ($cmd === 'ip') {
            return "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                . "    inet {$ip}/24 brd 10.0.0.255 scope global eth0\n";
        }

        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            . "        inet {$ip}  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            . "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n";
    }

    private function uptime(): string
    {
        $days = $this->facts->uptimeDays();
        $load = trim(explode('/', (string) $this->facts->proc('loadavg'))[0]);
        $parts = explode(' ', $load);

        return sprintf(
            " %s up %d days,  2:14,  1 user,  load average: %s, %s, %s\n",
            gmdate('H:i:s', FrozenClock::epoch()),
            $days,
            $parts[0] ?? '0.00',
            $parts[1] ?? '0.00',
            $parts[2] ?? '0.00'
        );
    }

    private function who(ShellSession $s): string
    {
        return sprintf("%-8s pts/0        %s (%s)\n", $s->user, gmdate('Y-m-d H:i', FrozenClock::epoch()), $s->peerIp);
    }

    private function envDump(ShellSession $s): string
    {
        $out = '';
        foreach ($s->env as $k => $v) {
            $out .= "{$k}={$v}\n";
        }

        return $out;
    }

    private function history(ShellSession $s): string
    {
        $out = '';
        $i = 1;
        foreach ($s->history as $h) {
            $out .= sprintf("%5d  %s\n", $i++, $h);
        }

        return $out;
    }

    // ---- traversal / text ----

    /** @param string[] $args */
    private function find(array $args, ShellSession $s): string
    {
        $start = '.';
        $nameGlob = null;
        $typeFilter = null;
        for ($i = 0; $i < count($args); $i++) {
            $a = $args[$i];
            if ($a === '-name' && isset($args[$i + 1])) {
                $nameGlob = $args[++$i];
            } elseif ($a === '-type' && isset($args[$i + 1])) {
                $typeFilter = $args[++$i];
            } elseif ($a !== '' && $a[0] !== '-') {
                $start = $a;
            }
        }
        $root = $this->resolve($start, $s);
        $fs = $this->fs($s);
        if (!$fs->isDir($root) && !$fs->exists($root)) {
            $s->lastExit = 1;
            return "find: '{$start}': No such file or directory\n";
        }
        $out = '';
        $budget = self::FIND_BUDGET;
        $stack = [$root];
        $seen = 0;
        while ($stack !== [] && $seen < $budget && strlen($out) < $this->maxOutput) {
            $dir = array_pop($stack);
            try {
                $nodes = $fs->list($dir);
            } catch (PathNotFound $e) {
                continue;
            }
            foreach ($nodes as $n) {
                $seen++;
                $path = $dir === '/' ? '/' . $n->name : $dir . '/' . $n->name;
                $matchName = $nameGlob === null || fnmatch($nameGlob, $n->name);
                $matchType = $typeFilter === null
                    || ($typeFilter === 'f' && $n->isFile())
                    || ($typeFilter === 'd' && $n->isDir())
                    || ($typeFilter === 'l' && $n->isLink());
                if ($matchName && $matchType) {
                    $out .= $path . "\n";
                }
                if ($n->isDir()) {
                    $stack[] = $path;
                }
            }
        }

        return $out;
    }

    /** @param string[] $args */
    private function grepFiles(array $args, ShellSession $s): string
    {
        $pattern = null;
        $files = [];
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                continue;
            }
            if ($pattern === null) {
                $pattern = trim($a, '"\'');
            } else {
                $files[] = $a;
            }
        }
        if ($pattern === null || $files === []) {
            return '';
        }
        $fs = $this->fs($s);
        $out = '';
        foreach ($files as $f) {
            try {
                $text = $fs->read($this->resolve($f, $s));
            } catch (\RuntimeException $e) {
                continue;
            }
            foreach (explode("\n", $text) as $l) {
                if ($l !== '' && stripos($l, $pattern) !== false) {
                    $out .= (count($files) > 1 ? $f . ':' : '') . $l . "\n";
                }
            }
        }

        return $out;
    }

    /** @param string[] $args */
    private function wc(array $args, ShellSession $s): string
    {
        $linesOnly = false;
        $files = [];
        foreach ($args as $a) {
            if ($a === '-l') {
                $linesOnly = true;
            } elseif ($a !== '' && $a[0] !== '-') {
                $files[] = $a;
            }
        }
        $fs = $this->fs($s);
        $out = '';
        foreach ($files as $f) {
            try {
                $text = $fs->read($this->resolve($f, $s));
            } catch (\RuntimeException $e) {
                $s->lastExit = 1;
                $out .= "wc: {$f}: No such file or directory\n";
                continue;
            }
            $lines = substr_count($text, "\n");
            $out .= $linesOnly
                ? sprintf("%7d %s\n", $lines, $f)
                : sprintf("%7d %7d %7d %s\n", $lines, str_word_count($text), strlen($text), $f);
        }

        return $out;
    }

    /** @param string[] $args */
    private function du(array $args, ShellSession $s): string
    {
        $human = false;
        $summary = false;
        $start = '.';
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                $human = $human || strpos($a, 'h') !== false;
                $summary = $summary || strpos($a, 's') !== false;
            } else {
                $start = $a;
            }
        }
        $root = $this->resolve($start, $s);
        $fs = $this->fs($s);
        $bytes = $this->duBytes($root, $fs, self::FIND_BUDGET);
        $kb = (int) ceil($bytes / 1024);
        $size = $human ? $this->human($bytes) : (string) $kb;

        return sprintf("%s\t%s\n", $size, $start);
    }

    private function duBytes(string $dir, FakeFilesystem $fs, int $budget): int
    {
        $total = 4096;
        $stack = [$dir];
        $seen = 0;
        while ($stack !== [] && $seen < $budget) {
            $d = array_pop($stack);
            try {
                $nodes = $fs->list($d);
            } catch (PathNotFound $e) {
                continue;
            }
            foreach ($nodes as $n) {
                $seen++;
                $total += $n->isDir() ? 4096 : $n->size;
                if ($n->isDir()) {
                    $stack[] = $d === '/' ? '/' . $n->name : $d . '/' . $n->name;
                }
            }
        }

        return $total;
    }

    private function human(int $bytes): string
    {
        $u = ['B', 'K', 'M', 'G', 'T'];
        $i = 0;
        $v = (float) $bytes;
        while ($v >= 1024 && $i < count($u) - 1) {
            $v /= 1024;
            $i++;
        }

        return ($v >= 10 ? (string) (int) round($v) : number_format($v, 1)) . $u[$i];
    }

    // ---- writes (mutate the session overlay; nothing executes) ----

    /** @param string[] $args */
    private function mkdir(array $args, ShellSession $s): string
    {
        $out = '';
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                continue;
            }
            $t = $this->resolve($a, $s);
            if ($deny = $this->denyWrite($t)) {
                $s->lastExit = 1;
                $out .= "mkdir: cannot create directory '{$a}': {$deny}\n";
                continue;
            }
            $s->overlay = $s->overlay->withDir($t);
        }

        return $out;
    }

    /** @param string[] $args */
    private function touch(array $args, ShellSession $s): string
    {
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                continue;
            }
            $t = $this->resolve($a, $s);
            if ($deny = $this->denyWrite($t)) {
                $s->lastExit = 1;
                return "touch: cannot touch '{$a}': {$deny}\n";
            }
            if (!$this->fs($s)->exists($t)) {
                $s->overlay = $s->overlay->withFile($t, '');
            }
        }

        return '';
    }

    /** @param string[] $args */
    private function rm(array $args, ShellSession $s): string
    {
        $out = '';
        foreach ($args as $a) {
            if ($a !== '' && $a[0] === '-') {
                continue;
            }
            $t = $this->resolve($a, $s);
            if (!$this->fs($s)->exists($t)) {
                $s->lastExit = 1;
                $out .= "rm: cannot remove '{$a}': No such file or directory\n";
                continue;
            }
            $s->overlay = $s->overlay->withRemoved($t);
        }

        return $out;
    }

    /** @param string[] $args */
    private function mv(array $args, ShellSession $s): string
    {
        $files = array_values(array_filter($args, static fn (string $a): bool => $a === '' || $a[0] !== '-'));
        if (count($files) < 2) {
            $s->lastExit = 1;
            return "mv: missing destination file operand\n";
        }
        $src = $this->resolve($files[0], $s);
        $dst = $this->resolve($files[1], $s);
        $fs = $this->fs($s);
        if (!$fs->exists($src)) {
            $s->lastExit = 1;
            return "mv: cannot stat '{$files[0]}': No such file or directory\n";
        }
        $bytes = '';
        try {
            $bytes = $fs->read($src);
        } catch (\RuntimeException $e) {
            $bytes = '';
        }
        $s->overlay = $s->overlay->withFile($dst, $bytes)->withRemoved($src);

        return '';
    }

    /** @param string[] $args */
    private function cp(array $args, ShellSession $s): string
    {
        $files = array_values(array_filter($args, static fn (string $a): bool => $a === '' || $a[0] !== '-'));
        if (count($files) < 2) {
            $s->lastExit = 1;
            return "cp: missing destination file operand\n";
        }
        $src = $this->resolve($files[0], $s);
        $dst = $this->resolve($files[1], $s);
        $fs = $this->fs($s);
        try {
            $bytes = $fs->read($src);
        } catch (\RuntimeException $e) {
            $s->lastExit = 1;
            return "cp: cannot stat '{$files[0]}': No such file or directory\n";
        }
        $s->overlay = $s->overlay->withFile($dst, $bytes);

        return '';
    }

    /** Real kernel-backed pseudo-filesystems reject writes. Returns the error text, or '' if allowed. */
    private function denyWrite(string $canon): string
    {
        foreach (['/proc', '/sys', '/dev/pts'] as $ro) {
            if ($canon === $ro || strncmp($canon, $ro . '/', strlen($ro) + 1) === 0) {
                return 'Read-only file system';
            }
        }

        return '';
    }

    /** @param string[] $args */
    private function fetch(string $cmd, array $args): string
    {
        $url = '';
        foreach ($args as $a) {
            if ($a !== '' && $a[0] !== '-') {
                $url = $a;
                break;
            }
        }
        if ($url === '') {
            return "{$cmd}: missing URL\n";
        }
        // NOTHING is fetched — the URL is intel, logged by the listener/endpoint.
        if ($cmd === 'curl') {
            return '';
        }
        $host = parse_url($url, PHP_URL_HOST) ?: 'host';

        return "--{$this->clockStamp()}--  {$url}\n"
            . "Resolving {$host}... 93.184.216.34\n"
            . "Connecting to {$host}|93.184.216.34|:80... connected.\n"
            . "HTTP request sent, awaiting response... 200 OK\n"
            . "Length: unspecified [text/html]\nSaving to: 'index.html'\n\n"
            . "index.html    [ <=> ] 1.42K  --.-KB/s    in 0s\n";
    }

    private function clockStamp(): string
    {
        return gmdate('Y-m-d H:i:s', FrozenClock::epoch());
    }

    // ---- pipe filters (operate on the producer's text) ----

    private function applyFilter(string $filter, string $input, ShellSession $s): string
    {
        $parts = $this->tokenize($filter);
        $cmd = $parts[0] ?? '';
        $args = array_slice($parts, 1);
        switch ($cmd) {
            case 'grep':
            case 'egrep':
                $inv = in_array('-v', $args, true);
                $pat = '';
                foreach ($args as $a) {
                    if ($a !== '' && $a[0] !== '-') {
                        $pat = trim($a, '"\'');
                        break;
                    }
                }
                $out = '';
                foreach (explode("\n", rtrim($input, "\n")) as $l) {
                    $hit = $pat !== '' && stripos($l, $pat) !== false;
                    if ($hit !== $inv) {
                        $out .= $l . "\n";
                    }
                }
                return $out;
            case 'head':
                return $this->limitLines($input, 'head', $this->numArg($args, 10));
            case 'tail':
                return $this->limitLines($input, 'tail', $this->numArg($args, 10));
            case 'wc':
                $n = substr_count($input, "\n");
                return in_array('-l', $args, true) ? "{$n}\n" : sprintf("%7d %7d %7d\n", $n, str_word_count($input), strlen($input));
            case 'sort':
                $lines = explode("\n", rtrim($input, "\n"));
                sort($lines);
                return implode("\n", $lines) . "\n";
            case 'uniq':
                $lines = explode("\n", rtrim($input, "\n"));
                return implode("\n", array_values(array_unique($lines))) . "\n";
            case 'cat':
                return $input;
            case 'awk':
            case 'cut':
            case 'sed':
            case 'less':
            case 'more':
                return $input; // pass through (a filter we don't model returns the producer text)
            default:
                return $input;
        }
    }

    /** @param string[] $args */
    private function numArg(array $args, int $default): int
    {
        foreach ($args as $i => $a) {
            if ($a === '-n' && isset($args[$i + 1]) && ctype_digit($args[$i + 1])) {
                return (int) $args[$i + 1];
            }
            if (preg_match('/^-(\d+)$/', $a, $m)) {
                return (int) $m[1];
            }
        }

        return $default;
    }

    /** @return string[] */
    private function tokenize(string $line): array
    {
        $line = trim($line);
        if ($line === '') {
            return [];
        }
        // Simple whitespace tokenizer that keeps quoted spans together.
        preg_match_all('/"[^"]*"|\'[^\']*\'|\S+/', $line, $m);

        return $m[0] ?? [];
    }
}
