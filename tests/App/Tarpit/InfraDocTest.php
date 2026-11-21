<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Http\InfraDocController;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\InertSecret;
use Funnypot\App\Tarpit\InfraWiki;
use Funnypot\App\Tarpit\InfraWikiRenderer;
use Funnypot\App\Tarpit\LlmOnlyLink;
use Funnypot\Core\RequestContext;
use Geo;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/demo/lib/geo.php';

/**
 * FP-0808 — the fake infrastructure-wiki tarpit's own invariants (spec + the plan-review fold):
 * served shape (text/markdown, inline), determinism/coherence, bounded output, MF1 (every serve budget-
 * guarded + charged, incl. the ~256 KB top doc), SF1 (no documented auth returns a success body), SF2
 * (tarpit OFF ⇒ 404), bounded render vs unbounded reference, crawler-unfollowable interior, the 50-port
 * knock + derivation appendix, and the never-a-500 fault path. The dedicated full-prose fingerprint sweep
 * lives in {@see InfraWikiFingerprintTest} (SF3).
 */
final class InfraDocTest extends TestCase
{
    private const TOP = '/INFRASTRUCTURE-NOTES.md';

    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function path(string $tag): string
    {
        $p = sys_get_temp_dir() . '/fp_infra_' . $tag . '_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /**
     * An InfraDocController wired to a real (enabled) budget + hit store, with a capturing emitter.
     *
     * @param array<string,int> $over budget overrides
     * @return array{0:InfraDocController,1:object}
     */
    private function make(array $over = [], bool $enabled = true, ?string $budgetPath = null, int $seed = 4242, int $capKb = 256): array
    {
        $cap = new class {
            public int $status = 0;
            /** @var array<string,string> */
            public array $headers = [];
            public string $body = '';
        };
        $emit = static function (int $s, array $h, string $b) use ($cap): void {
            $cap->status = $s;
            $cap->headers = $h;
            $cap->body = $b;
        };
        $budget = new TarpitBudget(
            $budgetPath ?? $this->path('budget'),
            $enabled,
            $over['maxConcurrent'] ?? 4,
            $over['maxPerIp'] ?? 1,
            $over['bytesPerIpHr'] ?? 64 * 1024 * 1024,
            $over['wallPerIpHrMs'] ?? 120 * 1000,
            $over['globalBytesHr'] ?? 1024 * 1024 * 1024,
            $over['pagesPerIpHr'] ?? 2000,
            15,
        );
        $store = new SqliteHitStore($this->path('hits'));
        $geo = new Geo(sys_get_temp_dir() . '/fp-no-geo-' . uniqid());
        $ctrl = new InfraDocController($store, $geo, $budget, $seed, $capKb, null, $emit, null,
            ['/admin/export/settings.py', '/admin/audit-archive']);

        return [$ctrl, $cap];
    }

    private function get(InfraDocController $c, string $path, string $ip = '203.0.113.9'): void
    {
        $c->handle(new RequestContext('GET', $path), $ip);
    }

    // --- served shape -------------------------------------------------------------------------------

    public function test_top_doc_serves_markdown_inline_at_every_alias(): void
    {
        [$c, $cap] = $this->make();
        $bodies = [];
        $ip = 1;
        foreach (InfraDocController::TOP_PATHS as $p) {
            $this->get($c, $p, '198.51.100.' . $ip++);
            self::assertSame(200, $cap->status, "served: {$p}");
            self::assertSame('text/markdown; charset=utf-8', $cap->headers['Content-Type'] ?? '', "markdown type: {$p}");
            self::assertArrayNotHasKey('Content-Disposition', $cap->headers, "inline (no attachment): {$p}");
            self::assertStringContainsString('infrastructure notes', strtolower($cap->body));
            $bodies[] = $cap->body;
        }
        self::assertSame([$bodies[0]], array_values(array_unique($bodies)), 'all aliases serve the SAME coherent story');
    }

    // --- SF2: OFF ⇒ 404 (engine-miss shape) ---------------------------------------------------------

    public function test_tarpit_off_sheds_every_doc_path_to_a_bounded_404(): void
    {
        [$c, $cap] = $this->make(enabled: false);
        foreach ([self::TOP, '/docs/runbooks/anything.md', '/ops/backup-catalog.md'] as $p) {
            $this->get($c, $p, '198.51.100.9');
            self::assertSame(404, $cap->status, "off ⇒ bounded 404: {$p}");
            self::assertStringContainsString('404 Not Found', $cap->body);
            self::assertStringNotContainsString('infrastructure notes', strtolower($cap->body));
        }
    }

    // --- determinism / coherence --------------------------------------------------------------------

    public function test_same_seed_is_byte_identical_different_seed_differs(): void
    {
        [$a, $capA] = $this->make(seed: 4242);
        $this->get($a, self::TOP, '198.51.100.10');
        $first = $capA->body;

        [$a2, $capA2] = $this->make(seed: 4242);
        $this->get($a2, self::TOP, '198.51.100.11');
        self::assertSame($first, $capA2->body, 'same seed ⇒ byte-identical doc (re-fetches never contradict)');

        [$b, $capB] = $this->make(seed: 77);
        $this->get($b, self::TOP, '198.51.100.12');
        self::assertNotSame($first, $capB->body, 'a different deploy ⇒ a different doc (no fleet constant)');

        // The identifying fields really differ (not just whitespace): company line + a host sample.
        preg_match('~^# (.+?) — internal infrastructure notes~m', $first, $mA);
        preg_match('~^# (.+?) — internal infrastructure notes~m', $capB->body, $mB);
        self::assertNotSame($mA[1] ?? 'x', $mB[1] ?? 'y', 'the company name varies by deploy');
    }

    // --- bounded output -----------------------------------------------------------------------------

    public function test_top_doc_and_subdocs_are_byte_bounded(): void
    {
        foreach ([1, 7, 4242, 99991] as $seed) {
            [$c, $cap] = $this->make(seed: $seed, capKb: 256);
            $this->get($c, self::TOP, '203.0.113.' . ($seed % 240 + 1));
            self::assertSame(200, $cap->status);
            self::assertLessThanOrEqual(256 * 1024, strlen($cap->body), "top doc bounded (seed {$seed})");
        }
        // A tight cap trims exactly.
        [$c, $cap] = $this->make(capKb: 16);
        $this->get($c, self::TOP, '198.51.100.13');
        self::assertLessThanOrEqual(16 * 1024, strlen($cap->body), 'the hard byte cap trims the top doc');
    }

    // --- MF1: every serve is budget-guarded + charged (incl. the top doc) ---------------------------

    public function test_top_doc_is_budget_guarded_and_charges_the_ledger(): void
    {
        // pagesPerIpHr = 1: the FIRST top-doc serve is within budget; the SECOND is over ⇒ shed. This only
        // holds if the top doc BOTH acquires/guards a slot AND charges the ledger (MF1 — it is not exempt).
        [$c, $cap] = $this->make(['pagesPerIpHr' => 1]);
        $this->get($c, self::TOP, '192.0.2.50');
        self::assertSame(200, $cap->status, 'first top-doc serve within budget');
        $this->get($c, self::TOP, '192.0.2.50');
        self::assertSame(404, $cap->status, 'second serve is over the per-IP hourly cap ⇒ bounded 404 (ledger was charged)');
    }

    public function test_top_doc_requires_a_free_slot(): void
    {
        $bpath = $this->path('budget');
        [$c, $cap] = $this->make(['maxConcurrent' => 1], budgetPath: $bpath);
        $occupier = new TarpitBudget($bpath, true, 1, 4, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15);
        $held = $occupier->acquire('10.0.0.1');
        self::assertSame(TarpitBudget::WON, $held['status']);

        $this->get($c, self::TOP, '10.0.0.2');
        self::assertSame(404, $cap->status, 'no free slot ⇒ the top doc sheds to a bounded 404 (it is NOT slot-exempt)');

        $occupier->release($held['slot']);
    }

    public function test_global_byte_budget_sheds_subsequent_serves(): void
    {
        // A global byte ceiling below one top doc: the first serve starts at an empty ledger so it still
        // goes (and charges ~78 KB); the next serve reads the aggregate as over budget ⇒ shed.
        [$c, $cap] = $this->make(['globalBytesHr' => 40 * 1024]);
        $this->get($c, self::TOP, '198.51.100.40');
        self::assertSame(200, $cap->status);
        $this->get($c, '/ops/backup-catalog.md', '198.51.100.41');
        self::assertSame(404, $cap->status, 'the global hourly byte ceiling sheds later tarpit serves');
    }

    // --- references resolve to generated sub-docs (bounded render, unbounded reference) -------------

    public function test_top_doc_references_more_subdocs_than_it_renders_inline_and_they_resolve(): void
    {
        [$c, $cap] = $this->make();
        $this->get($c, self::TOP, '198.51.100.20');
        $doc = $cap->body;

        // Decode every LLM-only reference and keep the sub-doc paths.
        preg_match_all('~<code>([A-Za-z0-9+/=]+)</code>~', $doc, $m);
        $refs = [];
        foreach ($m[1] as $b64) {
            $p = base64_decode($b64, true);
            if ($p !== false && preg_match('~^/(docs/(runbooks|migrations)/|ops/backup-catalog)~', $p) === 1) {
                $refs[$p] = true;
            }
        }
        $inline = count((new InfraWiki(4242))->services());
        self::assertGreaterThan($inline, count($refs), 'the top doc references strictly MORE sub-docs than it renders inline');

        // A referenced runbook path resolves to a generated, non-empty markdown doc.
        $runbook = null;
        foreach (array_keys($refs) as $p) {
            if (strncmp($p, InfraWiki::RUNBOOK_PREFIX, strlen(InfraWiki::RUNBOOK_PREFIX)) === 0) {
                $runbook = $p;
                break;
            }
        }
        self::assertNotNull($runbook, 'the top doc references at least one runbook');
        $this->get($c, $runbook, '198.51.100.21');
        self::assertSame(200, $cap->status, "runbook resolves: {$runbook}");
        self::assertSame('text/markdown; charset=utf-8', $cap->headers['Content-Type'] ?? '');
        self::assertStringContainsString('# Runbook', $cap->body);
        self::assertNotSame('', trim($cap->body));
    }

    public function test_subdoc_paths_resolve_backup_migration_and_unknown_slug(): void
    {
        [$c, $cap] = $this->make();

        $this->get($c, '/ops/backup-catalog.md', '198.51.100.22');
        self::assertSame(200, $cap->status);
        self::assertStringContainsString('Backup snapshot catalog', $cap->body);

        // A well-formed but unknown slug is NON-TERMINAL: a generated "archived" doc, never a dead end/500.
        $this->get($c, '/docs/runbooks/zzzzzzzzzzzz.md', '198.51.100.23');
        self::assertSame(200, $cap->status);
        self::assertStringContainsString('archived service', strtolower($cap->body));

        // A migration path between two real services resolves to a migration guide.
        $pairs = (new InfraWiki(4242))->migratingPairs();
        if ($pairs !== []) {
            $p = InfraWiki::MIGRATION_PREFIX . $pairs[0]['from']['slug'] . '-to-' . $pairs[0]['to']['slug'] . '.md';
            $this->get($c, $p, '198.51.100.24');
            self::assertSame(200, $cap->status);
            self::assertStringContainsString('# Migration', $cap->body);
        }
    }

    // --- crawler-unfollowable interior (anti-Baidu) -------------------------------------------------

    public function test_no_served_doc_exposes_a_followable_link(): void
    {
        [$c, $cap] = $this->make();
        $ip = 100;
        foreach ([self::TOP, '/ops/backup-catalog.md', '/docs/runbooks/zzzzzzzzzzzz.md'] as $p) {
            $this->get($c, $p, '198.51.100.' . $ip++);
            self::assertSame(200, $cap->status, "served: {$p}");
            self::assertFalse(
                LlmOnlyLink::containsFollowableLink($cap->body),
                "infra-wiki doc {$p} must expose NO plain href/src — a regex crawler must find nothing to follow"
            );
        }
    }

    // --- SF1: no documented auth returns a success / compromise body --------------------------------

    public function test_no_served_doc_reads_as_a_terminal_compromise(): void
    {
        $wiki = new InfraWiki(4242);
        $r = new InfraWikiRenderer($wiki);
        $corpus = $r->topDoc() . $r->backupCatalogDoc() . $r->notFoundDoc('x');
        foreach (array_slice($wiki->services(), 0, 10) as $s) {
            $corpus .= $r->runbookDoc($s);
        }
        foreach (array_slice($wiki->migratingPairs(), 0, 4) as $pr) {
            $corpus .= $r->migrationDoc($pr['from'], $pr['to']);
        }
        // SF1 (the FP-0810 lesson): the wiki documents credentials/knock, but exercising them must never
        // read as a clean win — no served body grants access. These phrases are what a "compromised" body
        // would carry; their ABSENCE is the invariant.
        foreach ([
            'access granted', 'login successful', 'authenticated successfully', 'welcome, admin',
            'welcome admin', 'session established', 'root@', '# whoami', 'uid=0(', 'you are now logged in',
            'shell access', 'command executed',
        ] as $terminal) {
            self::assertStringNotContainsStringIgnoringCase($terminal, $corpus, "no doc may read as a terminal win: '{$terminal}'");
        }
        // And the served surface never hands out a session or a non-markdown success response.
        [$c, $cap] = $this->make();
        $this->get($c, self::TOP, '198.51.100.60');
        self::assertArrayNotHasKey('Set-Cookie', $cap->headers, 'the wiki never mints a session');
        self::assertArrayNotHasKey('Location', $cap->headers, 'the wiki never redirects to an authed landing');
    }

    // --- compute-bait: exactly 50 knock ports + derivation appendix, seed-varied --------------------

    public function test_compute_bait_appendix_and_fifty_port_knock(): void
    {
        [$c, $cap] = $this->make(seed: 4242);
        $this->get($c, self::TOP, '198.51.100.70');
        $doc = $cap->body;

        self::assertStringContainsString('Access & secrets', $doc, 'the derivation appendix is present');
        self::assertStringContainsString('port-knock', strtolower($doc));
        self::assertMatchesRegularExpression('/SHA-1 iterated \d+ times/', $doc, 'a credential derivation is documented');

        // The knock is exactly 50 ports (the model is the source of truth for the count).
        $knock = (new InfraWiki(4242))->knockSequence();
        self::assertCount(50, $knock);
        foreach ($knock as $port) {
            self::assertGreaterThan(0, $port);
            self::assertLessThanOrEqual(65535, $port);
        }

        // Constants vary by seed (not a fleet constant).
        $a = (new InfraWiki(4242))->primeIndex('admin-pw');
        $b = (new InfraWiki(123456789))->primeIndex('admin-pw');
        self::assertTrue($a !== $b || (new InfraWiki(4242))->fibIndex('hmac') !== (new InfraWiki(123456789))->fibIndex('hmac'),
            'the compute-bait constants vary across deploys');
    }

    // --- never a 500 --------------------------------------------------------------------------------

    public function test_a_generator_fault_during_render_sheds_to_a_bounded_404(): void
    {
        $budgetPath = $this->path('exhaustion-budget');
        [$c, $cap] = $this->make(['maxConcurrent' => 1], budgetPath: $budgetPath);
        $observer = new TarpitBudget($budgetPath, true, 1, 1, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, PHP_INT_MAX, 15);

        // Poison the InertSecret denylist so slug() derivation exhausts and throws during the doc build —
        // the handler must shed to a bounded 404 (never a 500) and release the slot.
        $property = new \ReflectionProperty(InertSecret::class, 'denylist');
        $property->setAccessible(true);
        $before = $property->getValue();
        try {
            $property->setValue(null, ['literals' => [], 'patterns' => ['.'], 'ownVocabularyPattern' => '']);
            $this->get($c, self::TOP, '192.0.2.77');
            self::assertSame(404, $cap->status, 'a build fault ⇒ bounded 404, never a 500');
            self::assertStringContainsString('404 Not Found', $cap->body);
            self::assertLessThan(1024, strlen($cap->body));
            self::assertSame(0, $observer->inflightCount(), 'the slot was released on the fault path');
        } finally {
            $property->setValue(null, $before);
        }
        // Normal serving resumes once the denylist is restored.
        $this->get($c, self::TOP, '192.0.2.78');
        self::assertSame(200, $cap->status);
    }

    // --- the breadcrumb is crawler-unfollowable + decodes to the doc --------------------------------

    public function test_breadcrumb_carries_no_href_and_decodes_to_the_top_doc(): void
    {
        $crumb = InfraDocController::breadcrumb();
        self::assertFalse(LlmOnlyLink::containsFollowableLink($crumb), 'the breadcrumb is a comment, never a href');
        self::assertStringContainsString('<!--', $crumb, 'the breadcrumb is an HTML comment (crawler-invisible)');
        self::assertSame(1, preg_match('~base64\):\s*([A-Za-z0-9+/=]+)~', $crumb, $m), 'carries a base64 blob');
        self::assertSame(self::TOP, base64_decode($m[1]), 'the base64 decodes to the top-doc path');
        foreach (['honeypot', 'decoy', 'tarpit', 'trap', 'lure', 'bait'] as $tell) {
            self::assertStringNotContainsStringIgnoringCase($tell, $crumb, "breadcrumb must not leak the tell '{$tell}'");
        }
    }
}
