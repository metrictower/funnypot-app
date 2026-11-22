<?php

declare(strict_types=1);

// Informational timing report for the webshell console's work budget. Runs locally (no Docker, no
// network) and prints one JSON object. The tests assert work units, never time: this script shows
// what the worst lines cost on this host, for sizing FootholdFacts::BUDGET.
//
//   php scripts/bench/cmdi-work-budget.php [--repeat 5]

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Funnypot\App\Tarpit\Cmdi\FootholdFacts;
use Funnypot\App\Tarpit\Cmdi\FootholdIdentity;
use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use Funnypot\Core\Detection;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\Core\RequestContext;
use Funnypot\Core\TemplateMatch;
use Funnypot\Tests\App\Tarpit\Cmdi\ConsoleHarness;

$opts = getopt('', ['repeat:']);
$repeat = max(1, min(50, (int) ($opts['repeat'] ?? 5)));

$fill = static function (string $head, string $unit): string {
    while (strlen($head) + strlen($unit) <= ShellLexer::MAX_INPUT) {
        $head .= $unit;
    }

    return $head;
};
/** Median wall time of $fn in ms, and the value of its last run. */
$time = static function (callable $fn) use ($repeat): array {
    $ms = [];
    $last = null;
    for ($i = 0; $i < $repeat; $i++) {
        $t = hrtime(true);
        $last = $fn();
        $ms[] = (hrtime(true) - $t) / 1e6;
    }
    sort($ms);

    return [round($ms[intdiv(count($ms), 2)], 2), $last];
};

$roots = array_fill(0, 2000, '/');
$facts = [
    'grep -r' => array_merge(['grep', '-r', 'a'], $roots),
    'grep -rv' => array_merge(['grep', '-rv', 'Q'], $roots),
    'find' => array_merge(['find'], $roots),
    'find -name long' => array_merge(['find'], array_fill(0, 3, '/'), ['-name', str_repeat('a', 1100)]),
    'du' => array_merge(['du', '-sh'], $roots),
    'ls -la' => array_merge(['ls', '-la'], array_fill(0, 2000, '/usr/bin')),
    'cat' => array_merge(['cat'], array_fill(0, 2000, '/etc/passwd')),
    'glob' => array_merge(['ls'], array_fill(0, 2000, '/usr/bin/*')),
    'grep long pattern' => ['grep', '-r', str_repeat('a.', 2000), '/'],
    'cat $PATH joined' => ShellLexer::lex($fill('cat ', '$PATH'))->argv,
];
$report = ['repeat' => $repeat, 'budget' => FootholdFacts::BUDGET, 'facts' => []];
foreach ($facts as $name => $argv) {
    foreach ([FootholdIdentity::www(), FootholdIdentity::root()] as $id) {
        $f = null;
        [$ms] = $time(static function () use ($argv, $id, &$f) {
            $f = FootholdFacts::forPersona(1, $id);

            return $f->run($argv);
        });
        $report['facts']["{$name} ({$id->name})"] = ['ms' => $ms, 'work' => $f->work()];
    }
}

// Every applet through the console's own prepare(), with the lines expansion amplifies most.
$forms = [
    '$PATH joined' => static fn (string $a): string => $fill("{$a} ", '$PATH'),
    '$PATH args' => static fn (string $a): string => $fill($a, ' $PATH'),
    '${IFS}$PATH' => static fn (string $a): string => $fill($a, '${IFS}$PATH'),
    'brace' => static fn (string $a): string => $fill("{$a} ", '{a,b}'),
    'segments' => static fn (string $a): string => $fill("{$a} /", ";{$a} /"),
];
$h = ConsoleHarness::build();
$f = tempnam(sys_get_temp_dir(), 'fpv');
file_put_contents($f, json_encode(['vulns' => []]));
$policy = EmulationPolicy::fromPackage($f);
@unlink($f);
$det = new Detection(true, [new TemplateMatch('attack-webshell-panel', 'critical', ['attack', 'webshell'])], 'cluster', 'critical');
$worst = ['ms' => 0.0];
foreach (FootholdFacts::commandNames() as $applet) {
    foreach ($forms as $name => $make) {
        $ctx = new RequestContext('POST', '/admin/root/post', '', ['Content-Type' => 'application/x-www-form-urlencoded'], 'cmd=' . rawurlencode($make($applet)));
        [$ms, $turn] = $time(static fn () => $h->shell->prepare($ctx, '198.51.100.45', $det, $policy));
        if ($ms > $worst['ms']) {
            $worst = ['ms' => $ms, 'line' => "{$applet} / {$name}", 'work' => $turn?->work];
        }
    }
}
$report['prepare_worst'] = $worst;
$h->cleanup();

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
