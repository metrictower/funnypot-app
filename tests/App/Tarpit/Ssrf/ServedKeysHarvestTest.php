<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\App\Render\Fake\FakeSecrets;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Storage\SsrfKeyIndex;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\HostileFormat;
use Funnypot\App\Tarpit\LogRabbitHole;
use Funnypot\App\Tarpit\Ssrf\KeyIndexBuilder;
use Funnypot\App\Tarpit\Ssrf\ServedKeys;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\Shell\FakeShell;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use PHPUnit\Framework\TestCase;

/**
 * Every key the honeypot serves is recognised: harvested from the bodies the surfaces really serve
 * (core's fakes from two addresses, settings.py at a test cap and its last section at the default cap,
 * the log, the hostile JSON, the admin panel's secrets, the SSH tier's /root files), each must come back
 * with its family. Random keys of the same shapes, a per-source core key from the other address, and the
 * static decoys' documentation keys must not.
 */
final class ServedKeysHarvestTest extends TestCase
{
    private const IPS = ['10.213.87.2', '203.0.113.9'];

    /** Census entries the engine cannot be driven to serve, with the reason. Expected empty. */
    private const UNREACHABLE = [];

    private static string $dir;
    private static ?SsrfKeyIndex $index = null;

    public static function setUpBeforeClass(): void
    {
        self::$dir = sys_get_temp_dir() . '/fp0816harvest_' . bin2hex(random_bytes(5));
        mkdir(self::$dir, 0700, true);
    }

    public static function tearDownAfterClass(): void
    {
        MintHarness::removeTree(self::$dir);
    }

    private static function seed(): int
    {
        return IdentityTestSupport::httpIdentity()->personaSeed();
    }

    private static function index(int $cap): SsrfKeyIndex
    {
        $i = new SsrfKeyIndex(self::$dir . '/idx-' . $cap . '.sqlite', 'harvest-key', new KeyIndexBuilder(self::seed(), IdentityTestSupport::httpIdentity()->filesystemKey(), $cap), 'deploy-' . $cap);
        for ($n = 0; $n < 400 && !$i->complete(); $n++) {
            $i->advance(1000);
        }
        self::assertTrue($i->complete());

        return $i;
    }

    private static function served(int $cap): ServedKeys
    {
        return new ServedKeys(self::seed(), IdentityTestSupport::httpIdentity()->coreRenderSalt(), self::index($cap));
    }

    private static function engine(string $ip): Honeypot
    {
        $cfg = AppConfig::fromEnv(self::$dir);
        $cfg->latencyMs = 0;
        $cfg->jitterMs = 0;

        return Honeypot::default(IdentityTestSupport::coreConfigFactory()->build($cfg, EmulationPolicy::fromPackage(null), static fn () => $ip));
    }

    /** @return array<string,list<string>> census entry id => key-shaped directives it holds */
    public static function census(): array
    {
        $compiled = dirname(__DIR__, 4) . '/vendor/metrictower/funnypot-core/resources/compiled/';
        $out = [];
        foreach (['funnypot-routes.php', 'funnypot-param.php', 'funnypot-attack.php'] as $file) {
            $walk = function ($node, string $id) use (&$walk, &$out): void {
                if (is_array($node)) {
                    $nid = is_string($node['id'] ?? null) ? $node['id'] : $id;
                    foreach ($node as $v) {
                        $walk($v, $nid);
                    }

                    return;
                }
                if (!is_string($node)) {
                    return;
                }
                preg_match_all('~(AKIA|ASIA|[sr]k_(?:live|test)_)\{\{\s*fake\.([a-z0-9_]+)[^}]*\}\}|\{\{\s*persona\.(cloud\.(?:aws\.accessKeyId|stripe\.secretKey))\s*\}\}~', $node, $m, PREG_SET_ORDER);
                foreach ($m as $hit) {
                    $out[$id][] = ($hit[3] ?? '') !== '' ? 'persona.' . $hit[3] : $hit[0];
                }
            };
            $walk(require $compiled . $file, '?');
        }

        return array_map(static fn (array $d): array => array_values(array_unique($d)), $out);
    }

    /**
     * Every GET path core compiles, plus the IMDS credential path and the dev-server file-read prefix.
     * Core's route fakes attach to templates by needle, so the sweep covers every path any of them can
     * answer rather than mapping entries to paths.
     *
     * @return list<string>
     */
    private static function sweep(): array
    {
        $index = require dirname(__DIR__, 4) . '/vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.full.php';
        $out = ['/latest/meta-data/iam/security-credentials/web', '/@fs/app/.env', '/@fs/var/www/html/.env', '/.env', '/config.php', '/wp-config.php'];
        foreach (array_keys($index['routes']) as $key) {
            if (str_starts_with((string) $key, 'GET /')) {
                $path = substr((string) $key, 4);
                $out[] = substr($path, 0, strcspn($path, '?'));
            }
        }

        return array_values(array_unique($out));
    }

    public function test_core_served_keys_are_recognised_from_their_own_source_only(): void
    {
        $keys = self::served(256 << 10);
        $paths = self::sweep();
        self::assertGreaterThan(1000, count($paths));
        $harvest = [];
        foreach (self::IPS as $ip) {
            $hp = self::engine($ip);
            foreach ($paths as $p) {
                $r = $hp->respond(new RequestContext('GET', $p, '', ['User-Agent' => 'curl/8.4.0']));
                foreach (KeyIndexBuilder::keysIn((string) $r?->body) as $k) {
                    $harvest[$ip][$k] = $p;
                }
            }
        }
        $families = [];
        $kinds = [];
        foreach ($harvest as $ip => $set) {
            foreach ($set as $k => $p) {
                $fam = $keys->recognise($k, $ip);
                self::assertContains($fam, ['persona', 'core_render'], "{$k} from {$p} for {$ip}");
                $families[$fam][$k] = true;
                foreach ($keys->coreKeys($ip) as $directive => $value) {
                    if ($value === $k) {
                        $kinds[$directive] = true;
                    }
                }
            }
        }
        self::assertCount(2, $families['persona'] ?? [], 'the persona AWS and Stripe keys');
        $census = array_unique(array_merge(...array_values(self::census())));
        foreach ($census as $directive) {
            if (str_starts_with($directive, 'persona.')) {
                continue;
            }
            $canonical = (string) preg_replace('/\{\{\s*fake\.([a-z0-9_]+)[^}]*\}\}/', '{{fake.$1}}', $directive);
            $served = array_filter(array_keys($kinds), static fn (string $d): bool => preg_replace('/\{\{\s*fake\.([a-z0-9_]+)[^}]*\}\}/', '{{fake.$1}}', $d) === $canonical);
            self::assertTrue($served !== [] || isset(self::UNREACHABLE[$directive]), "census directive {$directive} yielded a recognised key on some path");
        }
        foreach (array_keys($harvest[self::IPS[0]]) as $k) {
            if ($keys->direct($k, self::IPS[0]) === 'core_render') {
                self::assertNull($keys->recognise($k, self::IPS[1]), 'residual R2: a per-source key from the other address is unknown');
            }
        }
        $imds = self::engine(self::IPS[0])->respond(new RequestContext('GET', '/latest/meta-data/iam/security-credentials/web', '', []));
        self::assertStringContainsString($keys->sessionToken(self::IPS[0]), (string) $imds?->body, 'the IMDS session token re-renders exactly');
    }

    public function test_app_served_keys_are_recognised_from_real_bodies(): void
    {
        $seed = self::seed();
        $keys = self::served(2 << 20);
        $counts = [];
        $check = function (string $family, string $body) use ($keys, &$counts): void {
            foreach (KeyIndexBuilder::keysIn($body) as $k) {
                self::assertSame('indexed', $keys->recognise($k, '198.51.100.1'), "{$family}: {$k}");
                $counts[$family][$k] = true;
            }
        };
        $body = '';
        foreach ((new ConfigDump($seed))->chunks(2 << 20) as $c) {
            $body .= $c;
        }
        $check('configdump', $body);
        $log = new LogRabbitHole($seed);
        $all = '';
        foreach ($log->chunks(8 << 20) as $c) {
            $all .= $c;
        }
        $check('log', $all);
        foreach ($log->juicyLineIndices() as $i) {
            $check('log', $log->bytesAt(max(0, ($i - 1) * LogRabbitHole::LINE_WIDTH), 3 * LogRabbitHole::LINE_WIDTH));
        }
        $check('hostile', (new HostileFormat($seed))->json(8 << 20));
        $bait = FakeSecrets::fromSeed($seed);
        $check('bait', implode("\n", array_map(static fn (array $k): string => (string) $k['fullInert'], $bait->keys())) . "\n"
            . implode("\n", array_map(static fn (array $e): string => $e[1], $bait->envVars())));
        $fsKey = IdentityTestSupport::httpIdentity()->filesystemKey();
        foreach (Fleet::fromSeed($seed)->servers() as $s) {
            $shell = new FakeShell((int) $s['seed'], $fsKey, 'ops');
            $check('shell', $shell->run('cat /root/.aws/credentials', new ProtocolSession(), false) . "\n" . $shell->run('cat /root/.env', new ProtocolSession(), false));
        }
        $sections = 0;
        foreach ((new ConfigDump($seed))->chunks(2 << 20) as $_) {
            $sections++;
        }
        foreach (['log' => 2, 'hostile' => 8, 'bait' => 2, 'shell' => 48] as $family => $min) {
            self::assertGreaterThanOrEqual($min, count($counts[$family] ?? []), $family);
        }
        self::assertGreaterThanOrEqual(2 * ($sections - 2), count($counts['configdump']), 'two keys per settings.py section');

        $last = '';
        $prev = '';
        foreach ((new ConfigDump($seed))->chunks(8 << 20) as $c) {
            $prev = $last;
            $last = $c;
        }
        $full = self::served(8 << 20);
        foreach (KeyIndexBuilder::keysIn($prev . $last) as $k) {
            self::assertSame('indexed', $full->recognise($k, '198.51.100.1'), "last section at 8 MB: {$k}");
        }
    }

    public function test_random_and_placeholder_keys_stay_unknown(): void
    {
        $keys = self::served(256 << 10);
        mt_srand(816);
        $alnum = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        for ($i = 0; $i < 1000; $i++) {
            $body = '';
            for ($j = 0; $j < 24; $j++) {
                $body .= $alnum[mt_rand(0, $i % 3 === 2 ? 61 : 35)];
            }
            $k = match ($i % 3) {
                0 => 'AK' . 'IA' . substr($body, 0, 16),
                1 => 'AS' . 'IA' . substr($body, 0, 16),
                default => 'sk_' . 'live_' . $body,
            };
            self::assertNull($keys->recognise($k, self::IPS[0]), $k);
        }
        $decoys = dirname(__DIR__, 4) . '/demo/decoys/';
        $text = (string) file_get_contents($decoys . 'backup.sql') . (string) file_get_contents($decoys . 'backup.tar');
        $zip = new \ZipArchive();
        if ($zip->open($decoys . 'backup.zip') === true) {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $text .= (string) $zip->getFromIndex($i);
            }
            $zip->close();
        }
        preg_match_all('~\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b[sr]k_(?:live|test)_[0-9A-Za-z]{10,}~', $text, $m);
        self::assertNotEmpty($m[0], 'the static decoys hold key-shaped values');
        foreach (array_unique($m[0]) as $k) {
            self::assertTrue(ServedKeys::placeholder($k), "{$k} is a documentation-style placeholder");
            self::assertNull($keys->recognise($k, self::IPS[0]), "{$k} stays unknown on purpose");
        }
    }

    public function test_one_key_per_family_through_handle(): void
    {
        $h = new MintHarness(true, ['ssrf' => []]);
        try {
            $h->join();
            $form = $h->get('/settings/imports/new');
            $region = (string) \Funnypot\Core\Support\PersonaIdentity::fromSeed(self::seed())->field('cloud.aws.region');
            $akid = (string) \Funnypot\Core\Support\PersonaIdentity::fromSeed(self::seed())->field('cloud.aws.accessKeyId');
            $url = 'http://sts.' . $region . '.internal/?Action=GetCallerIdentity&X-Amz-Credential=' . $akid . '%2F20261122%2F' . $region
                . '%2Fsts%2Faws4_request&X-Amz-Date=' . gmdate('Ymd\THis\Z', $h->now) . '&X-Amz-Expires=900&X-Amz-Signature=abc';
            $r = $h->post('/settings/imports', ['csrf_token' => MintHarness::csrf($form['body']), 'kind' => 'orders_json', 'source_url' => $url]);
            self::assertSame(303, $r['status']);
            self::assertSame('cred_known', $r['plan']?->turn['outcome']);
            $h->now += 6;
            self::assertStringContainsString('SignatureDoesNotMatch', html_entity_decode($h->get((string) $r['plan']?->header('Location'))['body']));
            $stripe = (string) \Funnypot\Core\Support\PersonaIdentity::fromSeed(self::seed())->field('cloud.stripe.secretKey');
            $form = $h->get('/settings/imports/new');
            $r = $h->post('/settings/imports', ['csrf_token' => MintHarness::csrf($form['body']), 'kind' => 'orders_json', 'source_url' => 'http://' . $stripe . ':@payments-gw.' . $region . '.internal:8443/v1/charges']);
            self::assertSame('cred_restricted', $r['plan']?->turn['outcome']);
            $h->now += 6;
            self::assertStringContainsString('key_restricted', html_entity_decode($h->get((string) $r['plan']?->header('Location'))['body']));
        } finally {
            $h->cleanup();
        }
    }
}
