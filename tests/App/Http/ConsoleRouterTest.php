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
    // Two DISTINCT keys, as the web bundle carries them: the filesystem key seeds the procedural
    // filesystem (shared with the SSH/telnet shell), the MAC key only authenticates the cookie.
    private const FS_KEY = 'test-filesystem-key-abcdef';
    private const MAC_KEY = 'test-session-mac-key-012345';

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

    /**
     * A cookie MAC'd under the FILESYSTEM key must be rejected (re-minted): the two domains never
     * cross, so learning one key can neither forge a session nor replay the filesystem oracle.
     */
    public function testCookieSignedUnderTheFilesystemKeyIsNotTrusted(): void
    {
        $sid = str_repeat('a', 32);
        $forged = 'sid=' . $sid . '.' . hash_hmac('sha256', $sid, self::FS_KEY);
        $captured = $this->execCapturing('pwd', $forged);
        $this->assertNotNull($captured['setCookie'] ?? null, 'a cross-key cookie must be replaced by a freshly minted one');
        $this->assertStringNotContainsString('sid=' . $sid . '.', (string) ($captured['setCookie'] ?? ''), 'the forged sid must not be adopted');

        $genuine = $this->execCapturing('pwd', $this->validCookie($sid));
        $this->assertNull($genuine['setCookie'] ?? null, 'a cookie under the MAC key is trusted as-is');
    }

    /** @return array{setCookie:?string} */
    private function execCapturing(string $command, string $cookie): array
    {
        $emitter = null;
        $factory = static function () use (&$emitter): StreamEmitter {
            return $emitter = new StreamEmitter(static fn (string $b): string => $b, 0);
        };
        $router = new ConsoleRouter(new ConsoleSessionStore($this->dbPath), $this->hits, self::SEED, self::FS_KEY, self::MAC_KEY, $factory);
        $body = (string) json_encode(['host' => $this->host, 'command' => $command]);
        $router->handle(new RequestContext('POST', '/__console/exec', '', ['Cookie' => $cookie], $body), '203.0.113.7');
        $headers = $emitter instanceof StreamEmitter ? $emitter->headers() : [];

        return ['setCookie' => $headers['Set-Cookie'] ?? null];
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
        // ts is stored as TEXT and retention compares it lexicographically, so it must be ISO-8601.
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T/', (string) $shell[0]['ts']);
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
        return new ConsoleRouter(new ConsoleSessionStore($this->dbPath), $this->hits, self::SEED, self::FS_KEY, self::MAC_KEY);
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
        $router = new ConsoleRouter(new ConsoleSessionStore($this->dbPath), $this->hits, self::SEED, self::FS_KEY, self::MAC_KEY, $factory);
        $router->handle(new RequestContext('POST', '/__console/exec', '', $headers, $body), '203.0.113.7');

        return $captured;
    }

    private function validCookie(string $sid): string
    {
        return 'sid=' . $sid . '.' . hash_hmac('sha256', $sid, self::MAC_KEY);
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

    public function recentEventCount(string $ip, string $event, int $sinceSeconds): int
    {
        return 0;
    }

    public function flagBulkScan(string $ip, int $hours): void
    {
    }

    public function isBulkFlagged(string $ip): bool
    {
        return false;
    }
}
