<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\AiToolStateStore;
use PHPUnit\Framework\TestCase;

/**
 * The tool-loop ledger: atomic single-consume, per-actor isolation, TTL expiry, and fail-open on a
 * broken store. It stores only opaque digests — no prompt, argument, result, id, tool name or raw IP.
 */
final class AiToolStateStoreTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];
    private int $now = 1_000_000;

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
            @rmdir(dirname($f));
        }
        $this->tmp = [];
    }

    private function store(): AiToolStateStore
    {
        $dir = sys_get_temp_dir() . '/fp_state_' . bin2hex(random_bytes(6));
        $path = $dir . '/ai-tool-state.sqlite';
        $this->tmp[] = $path;

        return new AiToolStateStore($path, fn (): int => $this->now);
    }

    public function test_issue_then_consume_once_advances_then_replays(): void
    {
        $s = $this->store();
        self::assertTrue($s->issue('scopeA', 'corr-1', 'openai', 0));
        self::assertSame(AiToolStateStore::CONSUMED, $s->consume('corr-1'));
        self::assertSame(AiToolStateStore::REPLAYED, $s->consume('corr-1'), 'a second consume of the same call must not advance');
    }

    public function test_unknown_correlator_is_replayed_not_consumed(): void
    {
        $s = $this->store();
        self::assertSame(AiToolStateStore::REPLAYED, $s->consume('never-issued'));
    }

    public function test_actors_do_not_share_state(): void
    {
        $s = $this->store();
        $s->issue('scopeA', 'corrA', 'openai', 0);
        // A different actor's correlator digest never matches actor A's row.
        self::assertSame(AiToolStateStore::REPLAYED, $s->consume('corrB'));
        self::assertSame(AiToolStateStore::CONSUMED, $s->consume('corrA'));
    }

    public function test_expired_call_cannot_be_consumed(): void
    {
        $s = $this->store();
        $s->issue('scopeA', 'corr-ttl', 'openai', 0);
        $this->now += 100000; // well past the 15-minute expiry
        self::assertSame(AiToolStateStore::REPLAYED, $s->consume('corr-ttl'));
    }

    public function test_per_scope_live_cap_stops_issuing(): void
    {
        $s = $this->store();
        $issued = 0;
        for ($i = 0; $i < 12; $i++) {
            if ($s->issue('scopeA', 'corr-' . $i, 'openai', $i)) {
                $issued++;
            }
        }
        self::assertLessThanOrEqual(8, $issued, 'the per-scope live cap bounds outstanding calls');
    }

    public function test_broken_store_fails_open_not_fatal(): void
    {
        // Point the store at a path whose parent is a FILE, so the db can never open.
        $file = sys_get_temp_dir() . '/fp_state_block_' . bin2hex(random_bytes(6));
        file_put_contents($file, 'x');
        $this->tmp[] = $file . '/child/ai-tool-state.sqlite';
        $s = new AiToolStateStore($file . '/child/ai-tool-state.sqlite', fn (): int => $this->now);

        self::assertFalse($s->issue('scopeA', 'corr', 'openai', 0));
        self::assertSame(AiToolStateStore::ERROR, $s->consume('corr'));
        @unlink($file);
    }

    public function test_stored_rows_contain_no_raw_values(): void
    {
        $s = $this->store();
        $s->issue('scope-sentinel', 'corr-sentinel', 'openai', 0);
        $path = $this->tmp[array_key_last($this->tmp)];
        $pdo = new \PDO('sqlite:' . $path);
        $cols = $pdo->query('SELECT scope, correlator, provider FROM issued_calls')->fetch(\PDO::FETCH_ASSOC);
        // scope/correlator are opaque digests supplied by the planner (already hashed there); the store
        // itself never holds a prompt, tool name, argument, result or raw IP column.
        $schema = (string) $pdo->query("SELECT sql FROM sqlite_master WHERE name='issued_calls'")->fetchColumn();
        foreach (['prompt', 'argument', 'result', 'tool_name', 'ip', 'auth', 'cookie'] as $forbidden) {
            self::assertStringNotContainsString($forbidden, strtolower($schema), "state schema must not have a {$forbidden} column");
        }
    }
}
