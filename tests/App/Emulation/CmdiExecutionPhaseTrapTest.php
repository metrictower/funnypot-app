<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Emulation;

use Funnypot\App\Emulation\CmdiExecutionPhaseTrap;
use Funnypot\App\Emulation\CmdiSessionStore;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * FP-0531 pieces 2+3: the stateful Commix execution-phase oracle. A confirm binds the source's tag pair;
 * a follow-up carrying that BOUND pair gets canned recon output bracketed in the tags. Unbound tags, a
 * different source, or an expired binding get nothing (precision gate). INERT, fail-open.
 */
final class CmdiExecutionPhaseTrapTest extends TestCase
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
            @rmdir(\dirname($f));
        }
    }

    private function trap(): CmdiExecutionPhaseTrap
    {
        $path = sys_get_temp_dir() . '/fp0531-' . bin2hex(random_bytes(6)) . '/cmdi.sqlite';
        $this->tmp[] = $path;

        return new CmdiExecutionPhaseTrap(new CmdiSessionStore($path, function (): int { return $this->now; }), 4242);
    }

    private function ctx(string $query): RequestContext
    {
        return new RequestContext('GET', '/a', $query, [], null, 'x.test');
    }

    public function test_confirm_then_execute_returns_bracketed_output(): void
    {
        $t = $this->trap();
        $t->maybeBind($this->ctx('x=' . rawurlencode('ABCD$((11+22))WXYZ')), '10.0.0.1');
        $r = $t->maybeExecute($this->ctx('x=' . rawurlencode('ABCD`whoami`WXYZ')), '10.0.0.1');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('ABCDwww-data' . "\n" . 'WXYZ', $r->body, 'output is bracketed in the bound tags');
    }

    public function test_unbound_tags_get_nothing(): void
    {
        $t = $this->trap();
        // No confirm first -> the follow-up's tags are not bound -> no serve (precision gate).
        self::assertNull($t->maybeExecute($this->ctx('x=' . rawurlencode('ABCD`whoami`WXYZ')), '10.0.0.1'));
    }

    public function test_execute_is_isolated_per_source(): void
    {
        $t = $this->trap();
        $t->maybeBind($this->ctx('x=' . rawurlencode('ABCD$((1+1))WXYZ')), '10.0.0.1');
        self::assertNull($t->maybeExecute($this->ctx('x=' . rawurlencode('ABCD`id`WXYZ')), '10.0.0.2'), 'a different source is not bound to these tags');
        self::assertNotNull($t->maybeExecute($this->ctx('x=' . rawurlencode('ABCD`id`WXYZ')), '10.0.0.1'));
    }

    public function test_binding_expires(): void
    {
        $t = $this->trap();
        $t->maybeBind($this->ctx('x=' . rawurlencode('ABCD$((1+1))WXYZ')), '10.0.0.1');
        $this->now += 601; // > 10 min TTL
        self::assertNull($t->maybeExecute($this->ctx('x=' . rawurlencode('ABCD`whoami`WXYZ')), '10.0.0.1'));
    }

    /**
     * @dataProvider reconCommands
     */
    public function test_recon_commands_map_to_coherent_output(string $cmd, string $needle): void
    {
        $t = $this->trap();
        $t->maybeBind($this->ctx('x=' . rawurlencode('q7x9$((2+2))k3p2')), '10.0.0.5');
        $r = $t->maybeExecute($this->ctx('x=' . rawurlencode('q7x9`' . $cmd . '`k3p2')), '10.0.0.5');
        self::assertNotNull($r, "{$cmd} must serve for a bound source");
        self::assertStringContainsString('q7x9', $r->body);
        self::assertStringContainsString('k3p2', $r->body);
        self::assertStringContainsString($needle, $r->body);
    }

    /** @return array<string,array{0:string,1:string}> */
    public function reconCommands(): array
    {
        return [
            'whoami'   => ['whoami', 'www-data'],
            'id'       => ['id', 'uid=33(www-data)'],
            'uname'    => ['uname -a', 'Linux '],
            'hostname' => ['hostname', '-'],       // role-env-nn
            'pwd'      => ['pwd', '/var/www/html'],
            'ls'       => ['ls -la', 'wp-config.php'],
            'cat-pw'   => ['cat /etc/passwd', 'www-data:x:33:33'],
        ];
    }

    public function test_unknown_command_for_bound_source_serves_nothing(): void
    {
        $t = $this->trap();
        $t->maybeBind($this->ctx('x=' . rawurlencode('q7x9$((2+2))k3p2')), '10.0.0.5');
        self::assertNull($t->maybeExecute($this->ctx('x=' . rawurlencode('q7x9`curl evil`k3p2')), '10.0.0.5'),
            'a non-recon command is not answered by the execution-phase oracle');
    }

    public function test_fail_open_on_broken_store(): void
    {
        $file = sys_get_temp_dir() . '/fp0531-file-' . bin2hex(random_bytes(6));
        file_put_contents($file, 'x');
        $this->tmp[] = $file;
        $t = new CmdiExecutionPhaseTrap(new CmdiSessionStore($file . '/nope/x.sqlite'), 1);
        $t->maybeBind($this->ctx('x=' . rawurlencode('ABCD$((1+1))WXYZ')), '10.0.0.1'); // must not throw
        self::assertNull($t->maybeExecute($this->ctx('x=' . rawurlencode('ABCD`whoami`WXYZ')), '10.0.0.1'));
    }
}
