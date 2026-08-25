<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\CatalogCompiler;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Policy\EmulationCatalog;
use Funnypot\Policy\EmulationPolicy;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The configurable emulation catalog: the compiler derives the full capability list from the
 * templates (auto-registration), the policy overlays the operator's on/off choices, and the engine
 * honours it — a disabled attack class, product decoy, service or the nuclei corpus is never served.
 */
final class EmulationCatalogTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function tearDown(): void
    {
        foreach ($this->tmp as $dir) {
            self::rmrf($dir);
        }
        $this->tmp = [];
    }

    // --- catalog derivation (auto-registration) ---

    public function test_compiler_derives_entries_from_templates(): void
    {
        $root = $this->fixtureRoot();
        $entries = (new CatalogCompiler())->compile($root);

        self::assertArrayHasKey('attack-demo-rce', $entries);
        $a = $entries['attack-demo-rce'];
        self::assertSame('attack', $a['kind']);
        self::assertSame('rce', $a['category']);
        self::assertSame('CVE-2021-12345', $a['cve']);      // lifted from a cve-* tag, upper-cased
        self::assertSame('critical', $a['severity']);
        self::assertTrue($a['default']);
        self::assertStringContainsString('templates/attack/', $a['source']);

        self::assertSame('service', $entries['service-mysql']['kind']);
        self::assertSame([3306], $entries['service-mysql']['ports']);
        self::assertSame('MYSQL', $entries['service-mysql']['title']);

        self::assertSame('route', $entries['route-demo']['kind']);
        self::assertSame('exposure', $entries['route-demo']['category']);

        self::assertSame('corpus', $entries['nuclei-reflection']['kind']);
        self::assertSame(42, $entries['nuclei-reflection']['count']);
    }

    public function test_explicit_catalog_fields_win_over_derivation(): void
    {
        $root = $this->fixtureRoot();
        file_put_contents(
            $root . '/templates/attack/zz-explicit.yaml',
            "id: attack-explicit\ntitle: My Special RCE\ncategory: custom\ndefault: false\ntags: [attack, rce]\nmatch: [{in: request, contains: xyz}]\nresponse: {body: hi}\n"
        );
        $entries = (new CatalogCompiler())->compile($root);

        self::assertSame('My Special RCE', $entries['attack-explicit']['title']);
        self::assertSame('custom', $entries['attack-explicit']['category']);
        self::assertFalse($entries['attack-explicit']['default']);
    }

    // --- policy resolution ---

    public function test_policy_resolution_and_materialize(): void
    {
        $catalog = new EmulationCatalog([
            'a' => ['id' => 'a', 'default' => true],
            'b' => ['id' => 'b', 'default' => false],
            'nuclei-reflection' => ['id' => 'nuclei-reflection', 'default' => true],
        ]);
        $policy = new EmulationPolicy($catalog, ['a' => false]);

        self::assertFalse($policy->isEnabled('a'));            // override wins
        self::assertFalse($policy->isEnabled('b'));            // catalog default
        self::assertTrue($policy->isEnabled('nuclei-reflection'));
        self::assertTrue($policy->isEnabled('unknown-id'));    // absent ⇒ true

        self::assertEqualsCanonicalizing(['a', 'b'], $policy->disabledIds());
        self::assertSame(['a' => false, 'b' => false, 'nuclei-reflection' => true], $policy->materialize());
    }

    public function test_policy_reads_sparse_json_overlay(): void
    {
        $catalog = new EmulationCatalog([
            'a' => ['id' => 'a', 'default' => true],
            'nuclei-reflection' => ['id' => 'nuclei-reflection', 'default' => true],
        ]);
        $file = $this->tmpFile('{"version":1,"vulns":{"a":false,"nuclei-reflection":false}}');
        $policy = EmulationPolicy::fromCatalog($catalog, $file);

        self::assertFalse($policy->isEnabled('a'));
        self::assertFalse($policy->nucleiEnabled());
    }

    public function test_missing_overlay_falls_back_to_defaults(): void
    {
        $catalog = new EmulationCatalog(['a' => ['id' => 'a', 'default' => true]]);
        $policy = EmulationPolicy::fromCatalog($catalog, '/no/such/file.json');

        self::assertTrue($policy->isEnabled('a'));
        self::assertSame([], $policy->disabledIds());
    }

    // --- runtime gates ---

    public function test_attack_emulator_disable_skips_the_rule(): void
    {
        $rule = [
            'id' => 'attack-test',
            'severity' => 'high',
            'status' => 200,
            'match' => [['in' => 'request', 'contains' => 'BOOM']],
            'response' => ['headers' => [], 'body' => 'pwned'],
        ];
        $req = new RequestContext('GET', '/x', 'q=BOOM');

        self::assertNotNull((new TemplateAttackEmulator([$rule]))->emulate($req));
        self::assertNull((new TemplateAttackEmulator([$rule]))->disable(['attack-test'])->emulate($req));
    }

    public function test_honeypot_does_not_serve_a_disabled_attack(): void
    {
        $store = new PhpArrayStore(require __DIR__ . '/../vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.php');
        $catalog = EmulationCatalog::fromPackage();
        $lfi = new RequestContext('GET', '/nope', 'file=../../etc/passwd');
        $mk = static fn (EmulationPolicy $p): Honeypot => new Honeypot($store, new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            attackEmulation: true,
            exclude: $p->disabledIds(),
            nucleiReflection: $p->nucleiEnabled(),
        ));

        // Enabled: the LFI payload is answered with a fake /etc/passwd.
        self::assertNotNull($mk(new EmulationPolicy($catalog, []))->respond($lfi));

        // Disabled in the catalog: the same payload is refused. LFI now has two sources — the
        // hand-authored rule and the broadened CRS class — so fully refusing it means disabling both.
        $off = ['attack-lfi-unix' => false, 'attack-crs-lfi' => false];
        self::assertNull($mk(new EmulationPolicy($catalog, $off))->respond($lfi));
    }

    public function test_honeypot_nuclei_group_toggle_suppresses_corpus(): void
    {
        $store = new PhpArrayStore(require __DIR__ . '/../vendor/metrictower/funnypot-core/resources/compiled/nuclei-index.php');
        $catalog = EmulationCatalog::fromPackage();
        $git = new RequestContext('GET', '/.git/config');
        $mk = static fn (EmulationPolicy $p): Honeypot => new Honeypot($store, new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            exclude: $p->disabledIds(),
            nucleiReflection: $p->nucleiEnabled(),
        ));

        self::assertNotNull($mk(new EmulationPolicy($catalog, []))->respond($git));

        // nuclei-reflection off means corpus bundles (pid != route-*) are no longer candidates.
        self::assertNull($mk(new EmulationPolicy($catalog, ['nuclei-reflection' => false]))->respond($git));
    }

    // --- helpers ---

    private function fixtureRoot(): string
    {
        $root = sys_get_temp_dir() . '/fpcat_' . bin2hex(random_bytes(6));
        $this->tmp[] = $root;
        foreach (['templates/attack', 'templates/route', 'templates/protocol', 'resources/compiled'] as $d) {
            mkdir($root . '/' . $d, 0777, true);
        }
        file_put_contents(
            $root . '/templates/attack/demo.yaml',
            "id: attack-demo-rce\nseverity: critical\ntags: [attack, rce, cve-2021-12345]\n"
            . "match: [{in: request, contains: boom}]\nresponse: {body: 'uid=0(root)'}\n"
        );
        file_put_contents(
            $root . '/templates/route/demo.yaml',
            "id: route-demo\nmatch: {template_needle: [demo]}\nresponse: {body: decoy}\n"
        );
        file_put_contents(
            $root . '/templates/protocol/mysql.yaml',
            "protocol: mysql\nlisten: [3306]\nseverity: high\ntags: [protocol, mysql]\nframing: raw\nbanner: ''\n"
        );
        file_put_contents($root . '/resources/compiled/manifest.json', '{"templates_indexed": 42}');

        return $root;
    }

    private function tmpFile(string $content): string
    {
        $path = sys_get_temp_dir() . '/fpvulns_' . bin2hex(random_bytes(6)) . '.json';
        $this->tmp[] = $path;
        file_put_contents($path, $content);

        return $path;
    }

    private static function rmrf(string $path): void
    {
        if (is_dir($path)) {
            foreach ((array) scandir($path) as $e) {
                if ($e !== '.' && $e !== '..') {
                    self::rmrf($path . '/' . $e);
                }
            }
            @rmdir($path);
        } elseif (is_file($path)) {
            @unlink($path);
        }
    }
}
