<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Engagement;

use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementStore;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\SignedHandle;
use Funnypot\App\Engagement\Stage;
use Funnypot\Tests\App\Engagement\Support\EngagementTestSnapshot;
use PHPUnit\Framework\TestCase;

/**
 * The test-support snapshot seam: an isolated namespace whose snapshot is the closed aggregate DTO
 * (never raw or high-cardinality fields), whose reset touches only its own rows, and which nothing
 * in production code references.
 */
final class EngagementTestSnapshotTest extends TestCase
{
    /** @var EngagementTestSnapshot[] */
    private array $ns = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->ns as $n) {
            $n->destroy();
        }
        $this->ns = [];
    }

    private function ns(): EngagementTestSnapshot
    {
        return $this->ns[] = EngagementTestSnapshot::create();
    }

    private function ev(): EngagementEvent
    {
        return new EngagementEvent(Stage::ENUMERATE, EventKind::LURE_FOLLOWED, 2048, 4, LureId::LABYRINTH, null, true, 0, 0);
    }

    public function test_snapshot_is_the_closed_aggregate_dto(): void
    {
        $n = $this->ns();
        self::assertSame(EngagementStore::RECORDED, $n->record('203.0.113.5', 'curl/8', $this->ev()));
        $h = (new SignedHandle($n->key()))->mint(SignedHandle::DOMAIN_EPISODE, $n->now(), 600);
        self::assertSame(EngagementStore::RECORDED, $n->record('203.0.113.5', 'curl/8', $this->ev(), $h));

        $s = $n->snapshot();
        self::assertSame([], array_diff(array_keys($s), EngagementTestSnapshot::FIELDS), 'no key outside FIELDS');
        self::assertSame(2, $s['episodes'], 'a valid handle keys its own episode beside the network one');
        self::assertSame(2, $s['deepest_stage'][Stage::ENUMERATE]);
        self::assertTrue($s['timing']['measured']);
        self::assertSame(2, $s['timing']['samples']);
        self::assertIsFloat($s['timing']['p95_ms']);

        $raw = json_encode($s);
        self::assertStringNotContainsString('203.0.113.5', $raw);
        self::assertStringNotContainsString('curl', $raw);
        self::assertStringNotContainsString($h, $raw);
        // Key names only ("cookie" is a legitimate identity-basis VALUE in the closed vocabulary).
        self::assertDoesNotMatchRegularExpression('/"(episode_id|evidence_digest|id_short|path|body|headers?|cookie|token|prompt|ip|ua|user_agent)":/', $raw);
        self::assertDoesNotMatchRegularExpression('/[a-f0-9]{32}/', $raw, 'no 128-bit id anywhere in the snapshot');
    }

    public function test_reset_wipes_only_its_own_namespace(): void
    {
        $a = $this->ns();
        $b = $this->ns();
        $a->record('203.0.113.5', 'curl/8', $this->ev());
        $b->record('203.0.113.5', 'curl/8', $this->ev());

        $a->reset();
        self::assertSame(0, $a->snapshot()['events']);
        self::assertSame(0, $a->snapshot()['timing']['samples']);
        self::assertSame(1, $b->snapshot()['events'], 'the other namespace is untouched');
        self::assertSame(EngagementStore::RECORDED, $a->record('203.0.113.5', 'curl/8', $this->ev()), 'usable again after reset');
    }

    public function test_clock_is_controllable_for_deterministic_boundaries(): void
    {
        $n = $this->ns();
        $n->record('203.0.113.5', 'curl/8', $this->ev());
        $n->advance(601);
        $n->record('203.0.113.5', 'curl/8', $this->ev());
        self::assertSame(2, $n->snapshot()['episodes']);
        self::assertSame(1, $n->snapshot()['returning_keys']);
    }

    public function test_nothing_in_production_code_references_the_seam(): void
    {
        $root = dirname(__DIR__, 3);
        foreach (['src', 'demo', 'scripts', 'bin'] as $dir) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/' . $dir, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if (!$f->isFile() || !in_array($f->getExtension(), ['php', 'js', 'json', 'conf', 'sh'], true)) {
                    continue;
                }
                self::assertStringNotContainsString(
                    'EngagementTestSnapshot',
                    (string) file_get_contents($f->getPathname()),
                    $f->getPathname() . ' references the test-only snapshot seam'
                );
            }
        }
        self::assertFileDoesNotExist($root . '/src/App/Engagement/Support/EngagementTestSnapshot.php');
    }
}
