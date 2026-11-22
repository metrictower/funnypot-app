<?php

declare(strict_types=1);

namespace Funnypot\App\Bench;

use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\LogRabbitHole;
use Funnypot\App\Tarpit\Ssrf\KeyIndexBuilder;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Shell\FakeShell;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;

/**
 * A scripted SSRF-pivot agent against the SSRF decoy, shaped on the live runs: sign up, mint a token,
 * create a hook, ping loopback ports, metadata, its own listener and a public collaborator host, then
 * read every delivery's response for new host:port pairs and re-point the hook at each in turn; import
 * the HTTP ones, mirror a public repository, verify the export destination against metadata, and try
 * the leaked keys of every family against the credential gateways.
 *
 * Every request goes through the real HoneypotController::handle() with both decoys armed and an
 * injected clock that moves 25 seconds a step. Fully deterministic: no wall clock, no randomness, so two
 * runs give the same transcript hash. Every queued target records the sha256 of the body it was read
 * from; only the first targets are seeds.
 */
final class SsrfPivotCrawler
{
    public const IP = '10.213.87.2';
    public const STEP_S = 25;

    private MintHarness $h;
    private string $pat = '';
    private string $hook = '';

    /** @var list<array{target:string,from:string}> */
    public array $queue = [];

    /** @var array<string,true> */
    public array $seen = [];

    /** @var array<string,string> target => sha256 of the body it was read from, or "seed" */
    public array $provenance = [];

    /** @var array<string,true> sha256 of every body the decoy produced */
    public array $bodies = [];

    /** @var list<array{step:int,method:string,path:string,status:int,new:int}> */
    public array $transcript = [];

    /** @var list<array{family:string,gateway:string,outcome:string,status:int}> */
    public array $credentials = [];

    /** @var list<string> every answer body, for the goal-proof scan */
    public array $replies = [];

    public int $faults = 0;
    public int $warnings = 0;
    public int $throttled = 0;

    public function __construct(public readonly bool $advanceClock = true, array $ssrf = [])
    {
        $this->h = new MintHarness(true, ['ssrf' => $ssrf]);
        $this->h->allowFaults = true;
    }

    public function harness(): MintHarness
    {
        return $this->h;
    }

    public function cleanup(): void
    {
        $this->h->cleanup();
    }

    /** @return array{plan:mixed,body:string,status:?int} */
    private function send(string $method, string $path, ?string $json = null): array
    {
        $headers = ['Authorization' => 'Bearer ' . $this->pat, 'User-Agent' => 'python-requests/2.31'];
        if ($json !== null) {
            $headers['Content-Type'] = 'application/json';
        }
        $r = $this->h->request($method, $path, '', $json, $headers, self::IP, 'crawler');
        if ($r['plan'] !== null) {
            $this->bodies[hash('sha256', $r['plan']->body)] = true;
            $data = json_decode($r['plan']->body, true);
            foreach ([$data['response']['body'] ?? null, $data['excerpt'] ?? null] as $inner) {
                if (is_string($inner)) {
                    $this->bodies[hash('sha256', $inner)] = true;
                }
            }
            $this->replies[] = $r['plan']->body;
        }
        if (($r['status'] ?? 0) === 429) {
            $this->throttled++;
        }

        return $r;
    }

    private function queueFrom(string $body, int $step): int
    {
        $from = hash('sha256', $body);
        preg_match_all('~(?<![\w.-])((?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?![\d])~', $body, $m, PREG_SET_ORDER);
        $new = 0;
        foreach ($m as $x) {
            $t = $x[1] . ':' . $x[2];
            if (!isset($this->seen[$t])) {
                $this->seen[$t] = true;
                $this->provenance[$t] = $from;
                $this->queue[] = ['target' => $t, 'from' => $from];
                $new++;
            }
        }

        return $new;
    }

    /** Leaked keys of every family, read from the bodies the surfaces serve. @return array<string,string> family => key */
    private function leakedKeys(): array
    {
        $seed = IdentityTestSupport::httpIdentity()->personaSeed();
        $out = [];
        $env = $this->h->request('GET', '/.env', '', null, [], self::IP, 'loot');
        foreach (KeyIndexBuilder::keysIn($env['body']) as $k) {
            $out[str_starts_with($k, 'AKIA') ? 'persona_aws' : 'core_stripe'] ??= $k;
        }
        $imds = $this->h->request('GET', '/latest/meta-data/iam/security-credentials/web', '', null, [], self::IP, 'loot');
        foreach (KeyIndexBuilder::keysIn($imds['body']) as $k) {
            $out['imds_asia'] ??= $k;
        }
        if (preg_match('/"Token"\s*:\s*"([^"]+)"/', $imds['body'], $tm) === 1) {
            $out['imds_token'] = $tm[1];
        }
        $settings = '';
        foreach ((new ConfigDump($seed, true))->chunks(64 << 10) as $c) {
            $settings .= $c;
        }
        foreach (KeyIndexBuilder::keysIn($settings) as $k) {
            $out[str_starts_with($k, 'AKIA') ? 'configdump_aws' : 'configdump_stripe'] ??= $k;
        }
        $log = new LogRabbitHole($seed);
        foreach ($log->juicyLineIndices() as $i) {
            foreach (KeyIndexBuilder::keysIn($log->secretForLine($i)) as $k) {
                $out[str_starts_with($k, 'AKIA') ? 'log_aws' : 'log_stripe'] ??= $k;
            }
        }
        $servers = Fleet::fromSeed($seed)->servers();
        $shell = new FakeShell((int) $servers[1]['seed'], IdentityTestSupport::httpIdentity()->filesystemKey(), 'ops');
        foreach (KeyIndexBuilder::keysIn($shell->run('cat /root/.aws/credentials', new ProtocolSession(), false)) as $k) {
            $out['shell_aws'] ??= $k;
        }

        return $out;
    }

    /** @return array<string,mixed> */
    public function run(int $steps): array
    {
        $this->h->join('crawler', 'Passw0rd!x', 'crawler', self::IP);
        $this->pat = $this->h->mint(['read:user', 'webhooks:write', 'imports:write', 'storage:write'], 'bench', 'crawler', self::IP, 'Passw0rd!x', 'crawler');
        $r = $this->send('POST', '/api/v2/user/hooks', '{"content_type":"json","events":["token"],"active":true,"url":"http://127.1:22/"}');
        $this->hook = (string) (json_decode($r['body'], true)['id'] ?? '');
        foreach (['127.1:1', '127.1:22', '127.1:6379', '127.1:8080', '127.1:9090', '0xa9fea9fe:80', self::IP . ':8080', 'oob.collab.example.net:443', '127.0.0.1.nip.io:80'] as $seedTarget) {
            $this->seen[$seedTarget] = true;
            $this->provenance[$seedTarget] = 'seed';
            $this->queue[] = ['target' => $seedTarget, 'from' => 'seed'];
        }
        $region = (string) PersonaIdentity::fromSeed(IdentityTestSupport::httpIdentity()->personaSeed())->field('cloud.aws.region');
        $keys = $this->leakedKeys();
        // The hosts an agent has already read in settings.py (served by the polluter, another decoy body).
        $settings = '';
        foreach ((new ConfigDump(IdentityTestSupport::httpIdentity()->personaSeed(), true))->chunks(8 << 10) as $c) {
            $settings .= $c;
        }
        $settings = (string) preg_replace('~https://([a-z0-9.-]+)\'~', '$1:443\'', $settings);
        $this->bodies[hash('sha256', $settings)] = true;
        $this->queueFrom($settings, -1);
        $credPlan = [];
        foreach ($keys as $family => $key) {
            if ($family === 'imds_token') {
                continue;
            }
            $credPlan[] = str_contains($family, 'stripe')
                ? [$family, 'payments', 'http://' . $key . ':@payments-gw.' . $region . '.internal:8443/v1/charges']
                : [$family, 'sts', 'http://sts.' . $region . '.internal/?Action=GetCallerIdentity&X-Amz-Credential=' . $key . '%2F20261122%2F' . $region . '%2Fsts%2Faws4_request'
                    . '&X-Amz-Date=' . gmdate('Ymd\THis\Z', $this->h->now) . '&X-Amz-Expires=3600&X-Amz-Signature=0'
                    . ($family === 'imds_asia' && isset($keys['imds_token']) ? '&X-Amz-Security-Token=' . rawurlencode($keys['imds_token']) : '')];
        }
        $done = 0;
        for ($step = 0; $step < $steps; $step++) {
            if ($this->advanceClock) {
                $this->h->now += self::STEP_S;
            }
            $faults = $this->h->ssrf?->faults() ?? 0;
            $warnings = count($this->h->warnings);
            $new = 0;
            if ($step % 10 === 7 && $credPlan !== []) {
                [$family, $gateway, $url] = $credPlan[intdiv($step, 10) % count($credPlan)];
                $r = $this->send('POST', '/api/v2/user/imports', (string) json_encode(['kind' => 'orders_json', 'source_url' => $url], JSON_UNESCAPED_SLASHES));
                $this->credentials[] = ['family' => $family, 'gateway' => $gateway, 'outcome' => (string) ($r['plan']?->turn['outcome'] ?? ''), 'status' => (int) ($r['status'] ?? 0)];
            } elseif ($step % 25 === 11) {
                $this->send('PUT', '/api/v2/user/storage', '{"bucket":"exports-bench","access_key":"exportbot","secret_key":"Rk2mQ9xLw4","endpoint_url":"http://0xa9fea9fe"}');
                $this->send('POST', '/api/v2/user/storage/verifications', '{}');
            } elseif ($step % 25 === 17) {
                $r = $this->send('POST', '/api/v2/user/imports', '{"kind":"mirror","source_url":"https://github.com/torvalds/linux.git"}');
            } elseif ($this->queue !== []) {
                $next = array_shift($this->queue);
                [$host, $port] = explode(':', $next['target']);
                $url = 'http://' . $host . ':' . $port . '/';
                $import = $step % 5 === 3;
                if ($import) {
                    $r = $this->send('POST', '/api/v2/user/imports', (string) json_encode(['kind' => 'orders_csv', 'source_url' => $url], JSON_UNESCAPED_SLASHES));
                    $id = (string) (json_decode($r['body'], true)['id'] ?? '');
                    if ($this->advanceClock) {
                        $this->h->now += 6;
                    }
                    $v = $this->send('GET', '/api/v2/user/imports/' . $id);
                    $new = $this->queueFrom((string) (json_decode($v['body'], true)['excerpt'] ?? ''), $step);
                } else {
                    $this->send('PATCH', '/api/v2/user/hooks/' . $this->hook, (string) json_encode(['url' => $url], JSON_UNESCAPED_SLASHES));
                    $p = $this->send('POST', '/api/v2/user/hooks/' . $this->hook . '/pings', '{}');
                    $did = (string) (json_decode($p['body'], true)['id'] ?? '');
                    if ($this->advanceClock) {
                        $this->h->now += 4;
                    }
                    $v = $this->send('GET', '/api/v2/user/hooks/' . $this->hook . '/deliveries/' . $did);
                    $new = $this->queueFrom((string) (json_decode($v['body'], true)['response']['body'] ?? ''), $step);
                }
            }
            $this->faults += ($this->h->ssrf?->faults() ?? 0) - $faults;
            $this->warnings += count($this->h->warnings) - $warnings;
            $last = $this->h->last;
            $this->transcript[] = ['step' => $step, 'method' => '', 'path' => '', 'status' => (int) ($last?->status ?? 0), 'new' => $new, 'hash' => hash('crc32b', (string) $last?->body)];
            $done++;
        }

        return [
            'steps' => $done,
            'faults' => $this->faults,
            'warnings' => $this->warnings,
            'throttled' => $this->throttled,
            'distinct_targets' => count($this->seen),
            'transcript_hash' => hash('sha256', (string) json_encode($this->transcript)),
            'credentials' => $this->credentials,
        ];
    }
}
