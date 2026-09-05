<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\AiPromptCapture;
use Funnypot\App\AiApi\ChatRequest;
use PHPUnit\Framework\TestCase;

/**
 * The separate opt-in prompt store: it retains ONLY accepted system/user prompt text (with role
 * markers), truncates at 16 KiB with the true length recorded, obeys per-actor/global/row caps and a
 * hard 24-hour retention, uses private 0700/0600 modes, and fails open.
 */
final class AiPromptCaptureTest extends TestCase
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

    private function capture(): AiPromptCapture
    {
        $path = sys_get_temp_dir() . '/fp_cap_' . bin2hex(random_bytes(6)) . '/ai-prompt-capture.sqlite';
        $this->tmp[] = $path;

        return new AiPromptCapture($path, fn (): int => $this->now);
    }

    private function req(array $promptMessages): ChatRequest
    {
        $r = new ChatRequest('openai', 'gpt-oss-120b', 'hi', false, false, false);
        $r->promptMessages = $promptMessages;

        return $r;
    }

    public function test_stores_only_role_marked_system_and_user_text(): void
    {
        $c = $this->capture();
        $c->capture($this->req([
            ['role' => 'system', 'text' => 'SYS-SENTINEL'],
            ['role' => 'user', 'text' => 'USER-SENTINEL'],
        ]), '203.0.113.9');

        $rows = $c->allRows();
        self::assertCount(2, $rows);
        $texts = array_column($rows, 'text');
        self::assertContains('SYS-SENTINEL', $texts);
        self::assertContains('USER-SENTINEL', $texts);
        // opaque actor, never the raw IP
        self::assertNotSame('203.0.113.9', $rows[0]['actor']);
    }

    public function test_truncates_at_16_kib_recording_true_length(): void
    {
        $c = $this->capture();
        $big = str_repeat('a', 20000);
        $c->capture($this->req([['role' => 'user', 'text' => $big]]), '203.0.113.9');
        $rows = $c->allRows();
        self::assertSame(20000, (int) $rows[0]['true_bytes']);
        self::assertSame(16384, (int) $rows[0]['stored_bytes']);
        self::assertSame(16384, strlen((string) $rows[0]['text']));
    }

    public function test_per_actor_hourly_cap_drops_further_capture(): void
    {
        $c = $this->capture();
        for ($i = 0; $i < 40; $i++) {
            $c->capture($this->req([['role' => 'user', 'text' => 'msg ' . $i]]), '203.0.113.9');
        }
        self::assertLessThanOrEqual(30, count($c->allRows()));
    }

    public function test_expired_rows_are_pruned_by_retain(): void
    {
        $c = $this->capture();
        $c->capture($this->req([['role' => 'user', 'text' => 'old']]), '203.0.113.9');
        $this->now += 90000; // > 24h
        $removed = $c->retain();
        self::assertSame(1, $removed);
        self::assertCount(0, $c->allRows());
    }

    public function test_schema_has_no_forbidden_columns(): void
    {
        $c = $this->capture();
        $c->capture($this->req([['role' => 'user', 'text' => 'x']]), '203.0.113.9');
        $path = $this->tmp[array_key_last($this->tmp)];
        $pdo = new \PDO('sqlite:' . $path);
        $schema = strtolower((string) $pdo->query("SELECT sql FROM sqlite_master WHERE name='prompt_capture'")->fetchColumn());
        foreach (['header', 'query', 'auth', 'cookie', 'tool', 'argument', 'result', 'response'] as $forbidden) {
            self::assertStringNotContainsString($forbidden, $schema, "capture schema must not have a {$forbidden} column");
        }
    }

    public function test_db_is_private_mode_0600(): void
    {
        $c = $this->capture();
        $c->capture($this->req([['role' => 'user', 'text' => 'x']]), '203.0.113.9');
        $path = $this->tmp[array_key_last($this->tmp)];
        clearstatcache();
        self::assertSame('0600', substr(sprintf('%o', fileperms($path)), -4));
        self::assertSame('0700', substr(sprintf('%o', fileperms(dirname($path))), -4));
    }

    public function test_symlinked_path_is_refused_fail_open(): void
    {
        $realDir = sys_get_temp_dir() . '/fp_cap_real_' . bin2hex(random_bytes(6));
        @mkdir($realDir, 0700, true);
        $linkDir = sys_get_temp_dir() . '/fp_cap_link_' . bin2hex(random_bytes(6));
        @symlink($realDir, $linkDir);
        $path = $linkDir . '/ai-prompt-capture.sqlite';
        $c = new AiPromptCapture($path, fn (): int => $this->now);
        // Must not throw and must store nothing (symlinked dir refused).
        $c->capture($this->req([['role' => 'user', 'text' => 'x']]), '203.0.113.9');
        self::assertCount(0, $c->allRows());
        @unlink($linkDir);
        @rmdir($realDir);
    }
}
