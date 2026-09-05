<?php

declare(strict_types=1);

namespace Funnypot\App\Ops;

use RuntimeException;

/**
 * Proves the five hand-maintained port views agree with demo/ports.json: nginx `listen`s, entrypoint
 * `spawn` lines, Dockerfile EXPOSE, the deploy script's publish flags (obtained by running it in its
 * print-only mode, so the shell's own defaults are what is checked) and compose `ports`. Every
 * problem is one exact line — "surface: missing/extra/duplicate <unit>" — never a summary. The
 * parsers take file CONTENT so fixtures need no filesystem.
 */
final class PortDrift
{
    /**
     * @param array{nginx:string, entrypoint:string, dockerfile:string, compose:string, deploy:string, deploy_opt_in:array<string,string>} $surfaces
     *        file contents; `deploy` is the default printed publish flags, `deploy_opt_in` the flags
     *        printed with each opt-in env var set (keyed by that var)
     * @return list<string> problems; empty means no drift
     */
    public static function check(PortManifest $m, array $surfaces): array
    {
        $p = [];

        // 1. nginx listens == nginx-owned binds.
        $listens = self::nginxListens($surfaces['nginx']);
        $p = array_merge($p, self::diff('demo/nginx.conf', 'listen', $m->nginxListens(), $listens));

        // 2. entrypoint spawn lines == one per listener process.
        $spawns = self::entrypointSpawns($surfaces['entrypoint']);
        $p = array_merge($p, self::diff('demo/entrypoint.sh', 'spawn', $m->spawns(), $spawns));

        // Collisions: a tcp port nginx actually listens on that a listener also binds — per the
        // manifest, or per an actual spawn line the manifest does not know (assumed tcp; the unknown
        // spawn is already reported above, this names the race it would cause).
        $listenerTcp = [];
        foreach ($m->endpoints() as $e) {
            if (PortManifest::isBind($e) && !PortManifest::isNginx($e) && $e['transport'] === 'tcp') {
                $listenerTcp[(int) $e['container_port']] = 'listener process ' . $e['process_id'];
            }
        }
        $known = $m->spawns();
        foreach ($spawns as $s) {
            $port = (int) substr($s, (int) strrpos($s, ':') + 1);
            if (!isset($listenerTcp[$port]) && !in_array($s, $known, true)) {
                $listenerTcp[$port] = "undeclared spawn '{$s}'";
            }
        }
        foreach (PortManifest::sortedUnique($listens) as $l) {
            $port = (int) explode(' ', $l)[0];
            if (isset($listenerTcp[$port])) {
                $p[] = "collision: tcp/{$port} is listened by nginx and bound by {$listenerTcp[$port]}";
            }
        }

        // 3. Dockerfile EXPOSE == every container bind, once.
        $p = array_merge($p, self::diff('demo/Dockerfile', 'EXPOSE', $m->exposes(), self::dockerfileExposes($surfaces['dockerfile'])));

        // 4. compose ports == the compose target.
        $p = array_merge($p, self::diff('demo/docker-compose.yml', 'port', $m->publishes('compose'), self::composePublishes($surfaces['compose'])));

        // 5. deploy publish flags == the deploy target; opt-ins absent by default, present when armed.
        $default = self::publishFlags($surfaces['deploy']);
        $p = array_merge($p, self::diff('scripts/deploy.sh', 'publish', $m->publishes('deploy'), $default));
        foreach ($m->optInPublishes('deploy') as $env => $expected) {
            foreach ($expected as $map) {
                if (in_array($map, $default, true)) {
                    $p[] = "scripts/deploy.sh: opt-in publish {$map} ({$env}) is published by default";
                }
            }
            if (!isset($surfaces['deploy_opt_in'][$env])) {
                $p[] = "scripts/deploy.sh: no printed flags for opt-in {$env}=1";
                continue;
            }
            $armed = self::publishFlags($surfaces['deploy_opt_in'][$env]);
            foreach ($expected as $map) {
                if (!in_array($map, $armed, true)) {
                    $p[] = "scripts/deploy.sh: missing publish {$map} with {$env}=1";
                }
            }
            $extra = array_diff($armed, $default, $expected);
            foreach ($extra as $map) {
                $p[] = "scripts/deploy.sh: extra publish {$map} with {$env}=1";
            }
        }

        return $p;
    }

    /**
     * @param list<string> $expected canonical (unique, sorted)
     * @param list<string> $actual   as parsed, duplicates included
     * @return list<string>
     */
    public static function diff(string $surface, string $unit, array $expected, array $actual): array
    {
        $p = [];
        $counts = array_count_values($actual);
        foreach ($counts as $item => $n) {
            if ($n > 1) {
                $p[] = "{$surface}: duplicate {$unit} {$item} (x{$n})";
            }
        }
        $actualSet = PortManifest::sortedUnique($actual);
        foreach (array_diff($expected, $actualSet) as $item) {
            $p[] = "{$surface}: missing {$unit} {$item}";
        }
        foreach (array_diff($actualSet, $expected) as $item) {
            $p[] = "{$surface}: extra {$unit} {$item}";
        }

        return $p;
    }

    // ---- surface parsers (content in, canonical tokens out) --------------------------------------

    /**
     * `listen <port> [ssl] [default_server];` → "port" / "port ssl" (not sorted, duplicates kept).
     *
     * @return list<string>
     */
    public static function nginxListens(string $conf): array
    {
        $out = [];
        if (preg_match_all('/^\s*listen\s+(\d{1,5})((?:\s+[a-z_]+)*)\s*;/m', self::stripComments($conf), $mm, PREG_SET_ORDER) > 0) {
            foreach ($mm as $x) {
                $out[] = $x[1] . (preg_match('/\bssl\b/', $x[2]) === 1 ? ' ssl' : '');
            }
        }

        return $out;
    }

    /**
     * `spawn <proto> <bind>` lines → "proto bind" (duplicates kept).
     *
     * @return list<string>
     */
    public static function entrypointSpawns(string $sh): array
    {
        $out = [];
        if (preg_match_all('/^\s*spawn\s+([a-z0-9-]+)\s+(\S+)\s*(?:#.*)?$/m', $sh, $mm, PREG_SET_ORDER) > 0) {
            foreach ($mm as $x) {
                $out[] = $x[1] . ' ' . $x[2];
            }
        }

        return $out;
    }

    /**
     * Every token of every `EXPOSE` line → "port" / "port/udp" (duplicates kept).
     *
     * @return list<string>
     */
    public static function dockerfileExposes(string $dockerfile): array
    {
        $out = [];
        if (preg_match_all('/^EXPOSE\s+(.+)$/m', $dockerfile, $mm) > 0) {
            foreach ($mm[1] as $line) {
                foreach (preg_split('/\s+/', trim($line)) ?: [] as $tok) {
                    if (preg_match('/^(\d{1,5})(?:\/(tcp|udp))?$/', $tok, $t) === 1) {
                        $out[] = $t[1] . (($t[2] ?? 'tcp') === 'udp' ? '/udp' : '');
                    }
                }
            }
        }

        return $out;
    }

    /**
     * The `- "host:container[/udp]"` entries of every `ports:` block → "host:container[/udp]"
     * (duplicates kept). Indentation-scoped: only list items nested under a `ports:` key count.
     *
     * @return list<string>
     */
    public static function composePublishes(string $yaml): array
    {
        $out = [];
        $inPorts = false;
        $portsIndent = -1;
        foreach (preg_split('/\R/', $yaml) ?: [] as $line) {
            if (trim($line) === '' || preg_match('/^\s*#/', $line) === 1) {
                continue;
            }
            $indent = strlen($line) - strlen(ltrim($line));
            if (preg_match('/^\s*ports:\s*(#.*)?$/', $line) === 1) {
                $inPorts = true;
                $portsIndent = $indent;
                continue;
            }
            if ($inPorts && $indent <= $portsIndent) {
                $inPorts = false;
            }
            if ($inPorts && preg_match('/^\s*-\s*["\']?(\d{1,5}:\d{1,5}(?:\/udp)?)(?:\/tcp)?["\']?\s*(#.*)?$/', $line, $x) === 1) {
                $out[] = $x[1];
            }
        }

        return $out;
    }

    /**
     * `-p host:container[/udp]` tokens of a docker publish flag string → "host:container[/udp]"
     * (duplicates kept; an explicit /tcp suffix is normalized away).
     *
     * @return list<string>
     */
    public static function publishFlags(string $flags): array
    {
        $out = [];
        if (preg_match_all('/-p\s+(\d{1,5}:\d{1,5})(?:\/(tcp|udp))?(?=\s|$)/', $flags, $mm, PREG_SET_ORDER) > 0) {
            foreach ($mm as $x) {
                $out[] = $x[1] . (($x[2] ?? 'tcp') === 'udp' ? '/udp' : '');
            }
        }

        return $out;
    }

    /**
     * Runs scripts/deploy.sh in its print-only mode (FUNNYPOT_PRINT_PORTS=1: prints the publish flags
     * a bare deploy would use and exits before sourcing deploy.env, validating the host or building
     * anything) and returns what it printed.
     *
     * @param array<string,string> $env extra environment (e.g. an opt-in var set to "1")
     */
    public static function deployPrintedFlags(string $script, array $env = []): string
    {
        if (!function_exists('proc_open')) {
            throw new RuntimeException('proc_open is unavailable; cannot run the deploy script dry-run');
        }
        $env += ['FUNNYPOT_PRINT_PORTS' => '1', 'PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin'), 'HOME' => sys_get_temp_dir()];
        $p = proc_open(['/bin/bash', $script], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname($script), $env);
        if (!is_resource($p)) {
            throw new RuntimeException('cannot start bash for the deploy script dry-run');
        }
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($p);
        if ($rc !== 0) {
            throw new RuntimeException("deploy script dry-run exited {$rc}: " . trim($err));
        }

        return $out;
    }

    private static function stripComments(string $s): string
    {
        return (string) preg_replace('/#.*$/m', '', $s);
    }
}
