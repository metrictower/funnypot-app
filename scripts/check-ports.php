#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * The port-manifest gate: validates demo/ports.json and proves every hand-maintained port view agrees
 * with it — nginx `listen`s, entrypoint `spawn`s, Dockerfile EXPOSE, the deploy script's publish flags
 * (run in its print-only mode) and compose `ports`. Read-only; prints one exact line per problem.
 *
 *   php scripts/check-ports.php              # validate + drift check (exit 1 on any problem)
 *   php scripts/check-ports.php --format     # rewrite demo/ports.json in its canonical form
 *   php scripts/check-ports.php --print sg   # what the host firewall / security group must admit
 *   php scripts/check-ports.php --print nginx|spawn|expose|deploy|compose
 *
 * The security group cannot be read here; `--print sg` is the operator's read-only diff input.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use Funnypot\App\Ops\PortDrift;
use Funnypot\App\Ops\PortManifest;

$root = dirname(__DIR__);
$manifestPath = $root . '/demo/ports.json';
$args = array_slice($argv, 1);
$mode = $args[0] ?? '--check';

try {
    $m = PortManifest::fromFile($manifestPath);
} catch (Throwable $e) {
    fwrite(STDERR, 'ports: ' . $e->getMessage() . "\n");
    exit(1);
}

if ($mode === '--format') {
    $problems = array_filter($m->validate(), static fn (string $p): bool => !str_starts_with($p, 'endpoints are not in canonical order'));
    if ($problems !== []) {
        fwrite(STDERR, "ports: refusing to format an invalid manifest:\n  " . implode("\n  ", $problems) . "\n");
        exit(1);
    }
    file_put_contents($manifestPath, $m->canonicalJson());
    echo "ports: wrote canonical demo/ports.json (" . count($m->endpoints()) . " endpoints)\n";
    exit(0);
}

if ($mode === '--print') {
    $view = $args[1] ?? '';
    switch ($view) {
        case 'nginx':
            echo implode("\n", array_map(static fn (string $l): string => "listen {$l};", $m->nginxListens())), "\n";
            break;
        case 'spawn':
            echo implode("\n", array_map(static fn (string $l): string => "spawn {$l}", $m->spawns())), "\n";
            break;
        case 'expose':
            echo 'EXPOSE ' . implode(' ', $m->exposes()), "\n";
            break;
        case 'deploy':
        case 'compose':
            echo implode("\n", $m->publishes($view)), "\n";
            foreach ($m->optInPublishes($view) as $env => $maps) {
                echo '# with ' . $env . '=1: ' . implode(' ', $maps), "\n";
            }
            break;
        case 'sg':
            echo "# inbound rules the deploy target needs (transport port endpoint) — diff against the security group\n";
            foreach ($m->securityGroupRows() as $r) {
                echo str_pad($r['transport'], 4) . str_pad((string) $r['port'], 6) . $r['endpoint_id'] . ($r['opt_in'] !== null ? '   (only with ' . $r['opt_in'] . '=1)' : '') . "\n";
            }
            break;
        default:
            fwrite(STDERR, "usage: --print nginx|spawn|expose|deploy|compose|sg\n");
            exit(2);
    }
    exit(0);
}

if ($mode !== '--check') {
    fwrite(STDERR, "usage: php scripts/check-ports.php [--check|--format|--print <view>]\n");
    exit(2);
}

$problems = $m->validate();
if ($problems === []) {
    $canonical = $m->canonicalJson();
    if ($canonical !== (string) file_get_contents($manifestPath)) {
        $problems[] = 'demo/ports.json is not in canonical form — run scripts/check-ports.php --format';
    }
}
if ($problems === []) {
    try {
        $surfaces = [
            'nginx' => (string) file_get_contents($root . '/demo/nginx.conf'),
            'entrypoint' => (string) file_get_contents($root . '/demo/entrypoint.sh'),
            'dockerfile' => (string) file_get_contents($root . '/demo/Dockerfile'),
            'compose' => (string) file_get_contents($root . '/demo/docker-compose.yml'),
            'deploy' => PortDrift::deployPrintedFlags($root . '/scripts/deploy.sh'),
            'deploy_opt_in' => [],
        ];
        foreach (array_keys($m->optInPublishes('deploy')) as $env) {
            $surfaces['deploy_opt_in'][$env] = PortDrift::deployPrintedFlags($root . '/scripts/deploy.sh', [$env => '1']);
        }
        $problems = PortDrift::check($m, $surfaces);
    } catch (Throwable $e) {
        $problems[] = 'drift check could not run: ' . $e->getMessage();
    }
}

if ($problems !== []) {
    fwrite(STDERR, "ports: " . count($problems) . " problem(s):\n  " . implode("\n  ", $problems) . "\n");
    exit(1);
}
echo 'ports: OK (' . count($m->endpoints()) . ' endpoints; nginx, entrypoint, Dockerfile, deploy and compose agree with demo/ports.json)' . "\n";
