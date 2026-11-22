<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Http\HoneypotController;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Http\SleepDecoy;
use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmFakeResponder;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmResponseProfiles;
use Funnypot\App\Llm\ProbeClassifier;
use Funnypot\App\Llm\ProbeGate;
use Funnypot\App\Llm\VelocityTracker;
use Funnypot\App\Render\PageShellRenderer;
use Funnypot\App\Render\SkinSet;
use Funnypot\App\Render\Skins\AdminLteSkin;
use Funnypot\App\Render\Skins\GrafanaSkin;
use Funnypot\App\Storage\CmdiShellStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Cmdi\AdaptiveShell;
use Funnypot\App\Tarpit\FootholdRewriter;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Chrome\GenericSkin;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Tests\App\Identity\IdentityTestSupport;

require_once dirname(__DIR__, 4) . '/demo/lib/geo.php';

/**
 * The real request pipeline for console tests: the real engine, the real HoneypotController::handle(),
 * the real foothold rewriter, and a spy console store. Built the way the composition root builds it
 * when the tarpit is on. Options:
 *   catalog   'default' | 'lab' (attack-cmdi-unix off, as the lab overlay) | 'gate-off' (webshell off)
 *   shell     wire the console (false = the static-foothold base composition)
 *   pin       FUNNYPOT_TARPIT_CMDI_IDENTITY
 *   env       extra FUNNYPOT_* values for the AppConfig snapshot
 *   llm       wire a stub LLM responder (panels render without a model)
 *   abuse     wire an AbuseIPDB queue so reports can be compared
 *   sleeps    by-reference array: wires the sleep decoy with a spy sleeper that records ms
 *   store     a console store to use instead of a fresh spy
 *   clock     the facts clock
 *   hrClock   the work backstop's nanosecond clock
 */
final class ConsoleHarness
{
    public const LAB_OFF = ['attack-cmdi-unix'];

    public HoneypotController $controller;
    public SqliteHitStore $hits;
    public CmdiShellStore $store;
    public ?AdaptiveShell $shell = null;
    public FootholdRewriter $rewriter;
    public ?AbuseIpdb $abuse = null;
    public AppConfig $config;
    public string $dir;

    /** @param array<string,mixed> $o */
    public static function build(array $o = [], ?array &$sleeps = null): self
    {
        $h = new self();
        $h->dir = sys_get_temp_dir() . '/fp-console-' . bin2hex(random_bytes(6));
        mkdir($h->dir, 0777, true);

        $catalog = $o['catalog'] ?? 'default';
        $vulns = $h->dir . '/vulns.json';
        if ($catalog === 'lab') {
            file_put_contents($vulns, json_encode(['vulns' => array_fill_keys(self::LAB_OFF, false)]));
        } elseif ($catalog === 'gate-off') {
            file_put_contents($vulns, json_encode(['vulns' => ['attack-webshell-panel' => false]]));
        }
        $env = ($o['env'] ?? []) + [
            'FUNNYPOT_TARPIT' => '1',
            'FUNNYPOT_TARPIT_CMDI_IDENTITY' => $o['pin'] ?? 'www-data',
            'FUNNYPOT_VULNS' => $vulns,
            'FUNNYPOT_SLEEP_DECOY' => $sleeps !== null ? '1' : '0',
            'FUNNYPOT_SLEEP_PER_REQ_CAP_MS' => '2000',
        ];
        foreach ($env as $k => $v) {
            putenv("{$k}={$v}");
        }
        $h->config = AppConfig::fromEnv($h->dir);
        foreach (array_keys($env) as $k) {
            putenv($k);
        }

        $identity = IdentityTestSupport::httpIdentity();
        $h->hits = new SqliteHitStore($h->dir . '/hits.sqlite', $h->dir . '/hits.log');
        $geo = new \Geo($h->dir . '/no-geo.csv');
        $h->rewriter = new FootholdRewriter($identity->personaSeed(), LabyrinthController::entryHint(), $identity->defaultPoweredBy());
        $h->store = $o['store'] ?? new SpyCmdiStore();
        if (($o['shell'] ?? true) === true) {
            [$pick, $idKey] = AdaptiveShell::keysFrom($identity->filesystemKey());
            $h->shell = new AdaptiveShell($h->config, $h->rewriter, $h->store, $pick, $idKey, $o['clock'] ?? null, $o['hrClock'] ?? null);
        }
        if (($o['abuse'] ?? false) === true) {
            $h->abuse = new AbuseIpdb('KEY', $h->dir . '/intel.sqlite', ['10.0.0.1']);
        }

        $sleepDecoy = null;
        if ($sleeps !== null) {
            $sleeper = static function (int $ms) use (&$sleeps): void {
                $sleeps[] = $ms;
            };
            $budget = new TarpitBudget($h->dir . '/tarpit.sqlite', true, 8, 4, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15, static fn (): int => 1_000_000, 0, $sleeper);
            $sleepDecoy = new SleepDecoy($budget, $h->config, new AttackClassifier(), static fn (int $c): int => 0);
        }

        $h->controller = new HoneypotController(
            $h->hits,
            $geo,
            $h->config,
            dirname(__DIR__, 4) . '/demo/decoys',
            IdentityTestSupport::coreConfigFactory(),
            null,
            $h->abuse,
            null,
            ($o['llm'] ?? false) === true ? $h->llm() : null,
            new AttackClassifier(),
            null,
            $sleepDecoy,
            $h->config->tarpitEnabled ? $h->rewriter : null,
            $h->shell,
        );

        return $h;
    }

    private function llm(): LlmFakeResponder
    {
        $skins = new SkinSet([new WordpressSkin(), new PhpMyAdminSkin(), new GrafanaSkin(), new AdminLteSkin()], new GenericSkin());

        return new LlmFakeResponder(
            new ProbeGate(new ProbeClassifier(), new VelocityTracker(), $this->hits),
            new LlmFakeCache($this->dir . '/llm-cache.sqlite'),
            new LlmClient('http://sidecar/completion', 1500, 320, null, static fn (): array => ['status' => 200, 'body' => '{}']),
            new LlmOutputSanitizer(),
            $this->hits,
            new LlmResponseProfiles('nginx', 'root ::= "<"', 'root ::= "{"', new PageShellRenderer($skins), 'root ::= "{"'),
            'v1',
            4,
            7,
            'a1',
        );
    }

    /**
     * One request through handle(). The CLI SAPI cannot observe the status or headers once PHPUnit has
     * written output, so those are asserted on the response object in AdaptiveShellTest instead.
     *
     * @return array{body:string,row:?array<string,mixed>}
     */
    public function fetch(string $method, string $path, string $query = '', ?string $body = null, string $ip = '198.51.100.20'): array
    {
        $headers = ['User-Agent' => 'curl/8.0'];
        if ($body !== null) {
            $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        ob_start();
        @$this->controller->handle(new RequestContext($method, $path, $query, $headers, $body), $ip, 'off');
        $out = (string) ob_get_clean();
        $row = null;
        foreach ($this->hits->delta(0)['rows'] as $r) {
            if (($r['path'] ?? '') === substr($path, 0, 200) && ($r['ip'] ?? '') === $ip) {
                $row = $r;
            }
        }

        return ['body' => $out, 'row' => $row];
    }

    /** POST a `cmd` the way the lure form does, in one of three encodings. */
    public function post(string $path, string $cmd, string $ip = '198.51.100.20', string $enc = 'literal'): array
    {
        return $this->fetch('POST', $path, '', self::form($cmd, $enc), $ip);
    }

    public static function form(string $cmd, string $enc = 'literal'): string
    {
        return 'csrf=a3f9c1e7&cmd=' . match ($enc) {
            'plus' => urlencode($cmd),
            'pct20' => rawurlencode($cmd),
            default => $cmd,
        };
    }

    /** The engine's own first-match rule for a request, with the catalog's disabled ids. @param list<string> $off */
    public static function winner(RequestContext $r, array $off): string
    {
        static $rules = null;
        $rules ??= require dirname(__DIR__, 4) . '/vendor/metrictower/funnypot-core/resources/compiled/funnypot-attack.php';
        $emu = new TemplateAttackEmulator($rules);
        if ($off !== []) {
            $emu->disable($off);
        }
        $m = $emu->matchRule($r);

        return $m === null ? '(none)' : (string) $m['rule']['id'];
    }

    public function cleanup(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }
}
