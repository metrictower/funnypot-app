<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Http\ConsoleRouter;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Shell\ConsoleSessionStore;
use Funnypot\App\Storage\HitStore;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * The streaming-terminal front-controller seam: it owns only its POST path, runs a command through the
 * seeded shell, streams the output ending in the next prompt, persists cwd across requests keyed by the
 * HMAC'd session cookie, logs every command as intel (event=shell), and never faults into a 500.
 */
final class ConsoleRouterTest extends TestCase
{
    private const SEED = 4242;
    private const SECRET = 'test-secret-abcdef';

    private string $dbPath = '';
    private string $host = '';
    private TestHitSpy $hits;

    protected function setUp(): void
    {
        $this->dbPath = tempnam(sys_get_temp_dir(), 'fpconsole') ?: '';
        $this->hits = new TestHitSpy();
        // Host 0 of the fleet is always "this box" — guaranteed present and running.
        $this->host = (string) Fleet::fromSeed(self::SEED)->servers()[0]['host'];
    }

    protected function tearDown(): void
    {
        if ($this->dbPath !== '' && is_file($this->dbPath)) {
            @unlink($this->dbPath);
        }
    }

    public function testMatchesOnlyItsOwnPath(): void
    {
        $r = $this->router();
        $this->assertTrue($r->matches('/__console/exec'));
        $this->assertFalse($r->matches('/__console'));
        $this->assertFalse($r->matches('/'));
    }

    public function testRunsCommandAndStreamsPromptEnding(): void
    {
        $out = $this->exec('whoami');
        $this->assertStringContainsString('root', $out);
        // A real shell re-prints the prompt after output; the client never fabricates it.
        $this->assertStringEndsWith('# ', $out);
        $this->assertStringContainsStringIgnoringCase('@' . $this->host, $out);
    }

    public function testSessionPersistsCwdAcrossCalls(): void
    {
        $cookie = $this->validCookie('sess000cwd');
        $this->exec('cd /var', $cookie);
        $out = $this->exec('pwd', $cookie);
        $this->assertStringContainsString('/var', $out);
    }

    public function testFreshSessionsDoNotShareState(): void
    {
        $this->exec('cd /var', $this->validCookie('sessAAAAAA11'));
        $out = $this->exec('pwd', $this->validCookie('sessBBBBBB22'));
        // A different browser session starts at ~ (/root), not the other session's cwd.
        $this->assertStringNotContainsString('/var', $out);
    }

    public function testUnknownHostReturnsResolveError(): void
    {
        $out = $this->exec('id', null, 'no-such-host-here');
        $this->assertStringContainsString('Could not resolve hostname', $out);
    }

    public function testLogsCommandAsShellEvent(): void
    {
        $this->exec('uname -a');
        $shell = array_values(array_filter($this->hits->appended, static fn (array $e): bool => ($e['event'] ?? '') === 'shell'));
        $this->assertCount(1, $shell);
        $this->assertSame('uname -a', $shell[0]['body']);
        $this->assertTrue($shell[0]['served']);
    }

    public function testBlankCommandIsNotLogged(): void
    {
        $this->exec('   ');
        $shell = array_filter($this->hits->appended, static fn (array $e): bool => ($e['event'] ?? '') === 'shell');
        $this->assertCount(0, $shell);
    }

    public function testNonStringHostAndCommandDoNotLeakWarning(): void
    {
        // A JSON array where a string is expected must never hit a string cast (Array to string warning).
        $body = (string) json_encode(['host' => ['x'], 'command' => ['a', 'b']]);
        $out = $this->handle($body, []);
        $this->assertStringNotContainsString('Array to string', $out);
        $this->assertStringNotContainsString('Warning', $out);
        // Empty host -> the plain resolve error, no fault.
        $this->assertStringContainsString('Could not resolve hostname', $out);
    }

    public function testStoppedHostRefusesConnection(): void
    {
        $host = $this->hostWithStatus('stopped');
        if ($host === null) {
            $this->markTestSkipped('no stopped host in this fleet seed');
        }
        $out = $this->exec('id', null, $host);
        $this->assertStringContainsString('Connection refused', $out);
        $this->assertStringNotContainsString('uid=', $out); // the shell never ran
    }

    public function testOfflineHostHasNoRoute(): void
    {
        $host = $this->hostWithStatus('offline');
        if ($host === null) {
            $this->markTestSkipped('no offline host in this fleet seed');
        }
        $out = $this->exec('id', null, $host);
        $this->assertStringContainsString('No route to host', $out);
        $this->assertStringNotContainsString('uid=', $out);
    }

    public function testExitEndsSessionAndStartsFreshLogin(): void
    {
        $cookie = $this->validCookie('sessEXIT0001');
        $this->exec('cd /var', $cookie);
        $bye = $this->exec('exit', $cookie);
        $this->assertStringContainsString('closed.', $bye);
        $this->assertStringNotContainsString('# ', $bye); // no trailing prompt -> client disables input
        // Session was dropped: the next command with the same cookie is a fresh login at /root.
        $out = $this->exec('pwd', $cookie);
        $this->assertStringContainsString('/root', $out);
        $this->assertStringNotContainsString('/var', $out);
    }

    public function testMalformedBodyNeverFaults(): void
    {
        // Garbage in → no throw, no PHP fault leaking to the stream: an empty host resolves to the
        // plain ssh "could not resolve" line, exactly as a real client typo would.
        $out = $this->handle('not-json-at-all', []);
        $this->assertStringNotContainsString('Fatal', $out);
        $this->assertStringNotContainsString('Exception', $out);
        $this->assertStringContainsString('Could not resolve hostname', $out);
    }

    // --- helpers -------------------------------------------------------------

    private function router(): ConsoleRouter
    {
        return new ConsoleRouter(new ConsoleSessionStore($this->dbPath), $this->hits, self::SEED, self::SECRET);
    }

    private function exec(string $command, ?string $cookie = null, ?string $host = null): string
    {
        $headers = $cookie !== null ? ['Cookie' => $cookie] : [];
        $body = (string) json_encode(['host' => $host ?? $this->host, 'command' => $command]);

        return $this->handle($body, $headers);
    }

    /** @param array<string,string> $headers */
    private function handle(string $body, array $headers): string
    {
        $captured = '';
        $factory = static function () use (&$captured): StreamEmitter {
            return new StreamEmitter(static function (string $b) use (&$captured): void { $captured .= $b; }, 0);
        };
        // A fresh router each call; session state persists via the on-disk store shared by dbPath.
        $router = new ConsoleRouter(new ConsoleSessionStore($this->dbPath), $this->hits, self::SEED, self::SECRET, $factory);
        $router->handle(new RequestContext('POST', '/__console/exec', '', $headers, $body), '203.0.113.7');

        return $captured;
    }

    private function validCookie(string $sid): string
    {
        return 'sid=' . $sid . '.' . hash_hmac('sha256', $sid, self::SECRET);
    }

    private function hostWithStatus(string $status): ?string
    {
        foreach (Fleet::fromSeed(self::SEED)->servers() as $s) {
            if (($s['status'] ?? '') === $status) {
                return (string) $s['host'];
            }
        }

        return null;
    }
}

/** Minimal HitStore that records appended entries; every other method is an inert stub. */
final class TestHitSpy implements HitStore
{
    /** @var array<int,array<string,mixed>> */
    public array $appended = [];

    public function append(array $entry): void
    {
        $this->appended[] = $entry;
    }

    public function delta(int $cursor, array $filters = []): array
    {
        return ['cursor' => 0, 'reset' => false, 'rows' => []];
    }

    public function older(int $skip, array $filters = []): array
    {
        return ['rows' => [], 'more' => false];
    }

    public function stats(): array
    {
        return [];
    }

    public function widgets(): array
    {
        return [];
    }

    public function prune(int $keep): void
    {
    }

    public function clear(): void
    {
    }

    public function import(): int
    {
        return 0;
    }

    public function probeVelocity(string $ip): array
    {
        return ['recent' => 0, 'extended' => 0];
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return false;
    }
}
