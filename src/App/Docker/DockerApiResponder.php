<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\App\ThreatIntel\ReportComment;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use Funnypot\Core\RequestContext;

/**
 * Serves one fake Docker Engine API turn end to end: build the daemon payload for the matched
 * endpoint, emit it, then log + report the hit. The point is capturing the container-deploy and
 * container-ESCAPE intent — a bot's create/pull/exec carries the image, command, bind mounts,
 * --privileged / --pid=host escape config and registry auth it wanted to use — while running
 * absolutely NOTHING. Every verb is a simulated, non-executing response computed purely from
 * (seed, request bytes, phantom record, now). No process is ever spawned, no socket opened, no
 * registry contacted, no host path touched; the "pull" is a seeded, bounded, non-blocking fake
 * jsonmessage stream that never resolves the named registry.
 *
 * Cross-request coherence (create → pull → create → start → inspect → logs → exec) is backed by the
 * {@see PhantomStore}, a bounded/TTL'd record over the app's own SQLite — never real container state.
 */
// Not final: the router unit test spies on respond().
class DockerApiResponder
{
    /** Headers a real dockerd stamps on every API response (Server is left to the edge proxy). */
    private const DAEMON_HEADERS = [
        'Api-Version' => '1.43',
        'Docker-Experimental' => 'false',
        'Ostype' => 'linux',
        'Cache-Control' => 'no-cache, no-store, must-revalidate',
        'Pragma' => 'no-cache',
    ];

    /** Read-only recon kinds — logged (docker_recon/medium) but NEVER reported (see report policy). */
    private const RECON_KINDS = [
        'ping', 'version', 'info', 'containers', 'images', 'inspect', 'logs', 'wait',
        'attach', 'exec-inspect', 'image-inspect', 'noop-list', 'page-not-found',
    ];

    /** Container control verbs — logged (docker_api/high) but not container-deploy INTENT, so not reported. */
    private const CONTROL_KINDS = ['stop', 'kill', 'restart', 'remove'];

    private DockerDaemon $daemon;
    private EscapeIntent $intent;

    /** @var callable():int */
    private $clock;

    /** @var callable(int,array<string,string>,string):void|null */
    private $emit;

    /** @var callable():StreamEmitter|null */
    private $emitterFactory;

    /**
     * @param callable():int|null $clock live unix-time source for /info SystemTime; null = time().
     * @param callable(int,array<string,string>,string):void|null $emit buffered [status,headers,body]
     *        sink; null = the real header()/echo path. Injected as a capturing sink in tests.
     * @param callable():StreamEmitter|null $emitterFactory builds the pull-stream emitter; null = a
     *        real one (small pacing). Tests inject a factory returning a sink-backed, capturing emitter.
     */
    public function __construct(
        private HitStore $store,
        int $personaSeed,
        private ?AbuseIpdb $abuse = null,
        ?callable $clock = null,
        ?callable $emit = null,
        private ?ThreatIntelReporter $threatIntel = null,
        private ?PhantomStore $phantoms = null,
        ?callable $emitterFactory = null,
        private int $port = 0,
    ) {
        $this->daemon = DockerDaemon::fromSeed($personaSeed);
        $this->intent = new EscapeIntent($personaSeed);
        $this->clock = $clock ?? static fn (): int => time();
        $this->emit = $emit;
        $this->emitterFactory = $emitterFactory;
    }

    public function respond(RequestContext $ctx, string $ip): void
    {
        $kind = DockerApiRouter::endpoint($ctx->path, $ctx->method);
        if ($kind === null) {
            if (DockerApiRouter::isDockerPort($this->port)) {
                $this->json(404, ['message' => 'page not found']);
                $this->logHit($ctx, $ip, 'page-not-found', AttackClassifier::DOCKER_RECON);
            }

            return; // not a Docker path (and not a Docker port); callers guard with matches() first
        }

        switch ($kind) {
            case 'ping':
                $this->emitTuple(200, ['Content-Type' => 'text/plain; charset=utf-8'], 'OK');
                $this->logHit($ctx, $ip, $kind, AttackClassifier::DOCKER_RECON);
                break;
            case 'version':
                $this->json(200, $this->daemon->version());
                $this->logHit($ctx, $ip, $kind, AttackClassifier::DOCKER_RECON);
                break;
            case 'info':
                $this->info($ctx, $ip);
                break;
            case 'containers':
                $this->listContainers($ctx, $ip);
                break;
            case 'images':
                $this->listImages($ctx, $ip);
                break;
            case 'create':
                $this->create($ctx, $ip);
                break;
            case 'pull':
                $this->pull($ctx, $ip);
                break;
            case 'start':
                $this->start($ctx, $ip);
                break;
            case 'inspect':
                $this->inspect($ctx, $ip);
                break;
            case 'logs':
                $this->logs($ctx, $ip);
                break;
            case 'wait':
                $this->emitTuple(200, ['Content-Type' => 'application/json'], (string) json_encode(['StatusCode' => 0, 'Error' => null], JSON_UNESCAPED_SLASHES));
                $this->logHit($ctx, $ip, $kind, AttackClassifier::DOCKER_RECON);
                break;
            case 'attach':
                $this->emitTuple(200, ['Content-Type' => 'application/vnd.docker.raw-stream'], '');
                $this->logHit($ctx, $ip, $kind, AttackClassifier::DOCKER_RECON);
                break;
            case 'stop':
            case 'kill':
            case 'restart':
                $this->control($ctx, $ip, $kind);
                break;
            case 'remove':
                $this->remove($ctx, $ip);
                break;
            case 'exec-create':
                $this->execCreate($ctx, $ip);
                break;
            case 'exec-start':
                $this->emitTuple(200, ['Content-Type' => 'application/vnd.docker.raw-stream'], '');
                $this->logHit($ctx, $ip, $kind, AttackClassifier::DOCKER_RECON);
                break;
            case 'exec-inspect':
                $this->execInspect($ctx, $ip);
                break;
            case 'image-inspect':
                $this->imageInspect($ctx, $ip);
                break;
            case 'noop-list':
                $this->noopList($ctx, $ip);
                break;
        }
    }

    // --- recon reads ---

    private function info(RequestContext $ctx, string $ip): void
    {
        [$running, $created, $images, $hiddenFleet] = $this->counts($ip);
        $this->json(200, $this->daemon->info(($this->clock)(), $running, $created, $images, $hiddenFleet));
        $this->logHit($ctx, $ip, 'info', AttackClassifier::DOCKER_RECON);
    }

    private function listContainers(RequestContext $ctx, string $ip): void
    {
        $all = $this->flag($ctx->query, 'all');
        $this->json(200, $this->daemon->containers($this->livePhantoms($ip), $this->hiddenFleet($ip), $all));
        $this->logHit($ctx, $ip, 'containers', AttackClassifier::DOCKER_RECON);
    }

    private function listImages(RequestContext $ctx, string $ip): void
    {
        $this->json(200, $this->daemon->images($this->phantoms?->pulled($ip) ?? []));
        $this->logHit($ctx, $ip, 'images', AttackClassifier::DOCKER_RECON);
    }

    private function inspect(RequestContext $ctx, string $ip): void
    {
        $target = DockerApiRouter::target($ctx->path);
        $fleet = $this->daemon->fleetIndex($target);
        if ($fleet !== null && !in_array($target, $this->hiddenFleet($ip), true) && !in_array($this->daemon->fleetId($fleet), $this->hiddenFleet($ip), true)) {
            $this->json(200, $this->daemon->inspectFleet($fleet, ($this->clock)()));
        } elseif (($spec = $this->resolvePhantom($ip, $target)) !== null) {
            $this->json(200, $this->daemon->inspectPhantom($spec, ($this->clock)()));
        } else {
            $this->json(404, $this->daemon->notFound('container', $target));
        }
        $this->logHit($ctx, $ip, 'inspect', AttackClassifier::DOCKER_RECON);
    }

    private function logs(RequestContext $ctx, string $ip): void
    {
        $target = DockerApiRouter::target($ctx->path);
        $fleet = $this->daemon->fleetIndex($target);
        if ($fleet !== null) {
            $this->emitTuple(200, ['Content-Type' => 'application/vnd.docker.multiplexed-stream'], $this->multiplex($this->daemon->logsFleet($fleet)));
        } elseif (($spec = $this->resolvePhantom($ip, $target)) !== null) {
            // Started, no output yet — an empty multiplexed stream. follow=1 returns immediately (no hold).
            $ct = ($spec['tty'] ?? false) ? 'application/vnd.docker.raw-stream' : 'application/vnd.docker.multiplexed-stream';
            $this->emitTuple(200, ['Content-Type' => $ct], '');
        } else {
            $this->json(404, $this->daemon->notFound('container', $target));
        }
        $this->logHit($ctx, $ip, 'logs', AttackClassifier::DOCKER_RECON);
    }

    private function execInspect(RequestContext $ctx, string $ip): void
    {
        $execId = DockerApiRouter::target($ctx->path);
        $rec = $this->phantoms?->execRecord($execId);
        $cmd = $rec !== null ? array_values(array_filter(explode(' ', (string) ($rec['command'] ?? '')))) : [];
        $this->json(200, $this->daemon->execInspect($execId, (string) ($rec['container'] ?? ''), $cmd));
        $this->logHit($ctx, $ip, 'exec-inspect', AttackClassifier::DOCKER_RECON);
    }

    private function imageInspect(RequestContext $ctx, string $ip): void
    {
        $name = DockerApiRouter::target($ctx->path);
        if ($this->daemon->isLocalImage($name) || in_array(ImageRef::parse($name)['canonical'], $this->phantoms?->pulled($ip) ?? [], true)) {
            $this->json(200, $this->daemon->inspectImage($name, ($this->clock)()));
        } else {
            $this->json(404, $this->daemon->notFound('image', ImageRef::parse($name)['display']));
        }
        $this->logHit($ctx, $ip, 'image-inspect', AttackClassifier::DOCKER_RECON);
    }

    private function noopList(RequestContext $ctx, string $ip): void
    {
        // A minimal, plausible response for the surfaces we claim but don't deeply model.
        $this->json(200, []);
        $this->logHit($ctx, $ip, 'noop-list', AttackClassifier::DOCKER_RECON);
    }

    // --- container-deploy intent (captured + reported) ---

    private function create(RequestContext $ctx, string $ip): void
    {
        $body = EscapeIntent::decodeBody($ctx->rawBody);
        $intel = $this->intent->fromCreate($body, $ctx->query, $ctx->headers);
        $display = (string) $intel['image_ref']['display'];

        // Order matches real moby daemon.create(): image resolution (GetImage → "No such image") runs
        // BEFORE name reservation (reserveName → the 409). So a missing image + a taken name returns the
        // 404 first — which also keeps the pull induction working when a bot's --name collides.
        // (FP-0264 review A #3: reordered from the plan's §2.2 assumption, citing moby's ordering.)
        $local = ImageRef::isLocal((string) $intel['image'], $this->daemon->localCanonicals(), $this->phantoms?->pulled($ip) ?? []);
        if (!$local) {
            // No such image — but the FULL escape config is in THIS body, so intel is captured even if
            // the bot never pulls. This 404 is exactly what induces the bot's POST /images/create.
            $this->json(404, $this->daemon->notFound('image', $display));
            $this->logHit($ctx, $ip, 'create', (string) $intel['class'], $intel);
            $this->reportIntent($ctx, $ip, 'create', $intel);

            return;
        }

        // Name conflict — the image exists, so a duplicate --name now 409s (real dockerd wording,
        // including `by container "<id>"`, with the colliding fleet/phantom id filled in).
        $name = (string) $intel['name'];
        $collidingId = $name !== '' ? $this->nameOwner($ip, $name) : '';
        if ($collidingId !== '') {
            $this->json(409, ['message' => sprintf(
                'Conflict. The container name "/%s" is already in use by container "%s". You have to remove (or rename) that container to be able to reuse that name.',
                ltrim($name, '/'),
                $collidingId
            )]);
            $this->logHit($ctx, $ip, 'create', (string) $intel['class'], $intel);
            $this->reportIntent($ctx, $ip, 'create', $intel);

            return;
        }

        $id = $this->daemon->createdId((string) $intel['image'], (string) $intel['command']);
        $this->phantoms?->createContainer($ip, $id, [
            'image' => $intel['image'], 'command' => $intel['command'],
            'entrypoint' => $intel['entrypoint'], 'cmd' => $intel['cmd'], 'env' => $intel['env'],
            'binds' => $intel['binds'], 'mounts' => $intel['mounts'], 'name' => $intel['name'],
            'created' => ($this->clock)(), 'user' => $intel['user'], 'hostname' => $intel['hostname'],
            'tty' => $intel['tty'], 'privileged' => $intel['privileged'],
            'pid_mode' => $intel['pid_mode'], 'network_mode' => $intel['network_mode'],
        ]);
        // Warnings: GATE-ON-REAL-CAPTURE — a modern daemon likely emits [] for a clean create, but that
        // is unverified against a live 24.0.x here and a wrong guess would add a tell, so keep null.
        $this->json(201, ['Id' => $id, 'Warnings' => null]);
        $this->logHit($ctx, $ip, 'create', (string) $intel['class'], $intel);
        $this->reportIntent($ctx, $ip, 'create', $intel);
    }

    private function pull(RequestContext $ctx, string $ip): void
    {
        parse_str($ctx->query, $q);
        $fromImage = is_string($q['fromImage'] ?? null) ? $q['fromImage'] : '';
        $fromSrc = is_string($q['fromSrc'] ?? null) ? $q['fromSrc'] : '';
        $tag = is_string($q['tag'] ?? null) ? $q['tag'] : '';
        $ref = $fromImage !== '' ? ($tag !== '' && strpos($fromImage, ':') === false && strpos($fromImage, '@') === false ? $fromImage . ':' . $tag : $fromImage) : $fromSrc;

        $parsed = ImageRef::parse($ref);
        $verb = $fromSrc !== '' && $fromImage === '' ? 'import' : 'pull';

        // Stream the seeded fake pull. The registry named in $ref is NEVER resolved or contacted.
        $emitter = $this->emitterFactory !== null ? ($this->emitterFactory)() : new StreamEmitter(null, 15);
        $emitter->begin(200, ['Content-Type' => 'application/json'] + self::DAEMON_HEADERS);
        foreach ($this->daemon->pullStream($ref) as $msg) {
            $emitter->chunk((string) json_encode($msg, JSON_UNESCAPED_SLASHES) . "\n");
        }
        if ($parsed['valid']) {
            $this->phantoms?->recordPull($ip, $parsed['canonical']);
        }

        // Intel: the image being pulled + any X-Registry-Auth (username/serveraddress kept, password
        // reduced to a seed-keyed HMAC token, identity-token presence only).
        $intel = [
            'image' => (string) substr($ref, 0, 255),
            'image_ref' => ['registry' => $parsed['registry'], 'repo' => $parsed['repo'], 'tag' => $parsed['tag'], 'digest' => $parsed['digest'], 'display' => $parsed['display']],
            'command' => '', 'cmd' => [], 'env' => [], 'binds' => [], 'signals' => [],
            'class' => AttackClassifier::DOCKER_API,
            'registry_auth' => $this->intent->fromCreate([], '', $ctx->headers)['registry_auth'],
        ];
        $this->logHit($ctx, $ip, 'pull', AttackClassifier::DOCKER_API, $intel);
        $this->reportIntent($ctx, $ip, $verb, $intel);
    }

    private function start(RequestContext $ctx, string $ip): void
    {
        $target = DockerApiRouter::target($ctx->path);
        if ($this->daemon->fleetIndex($target) !== null) {
            $this->emitTuple(304, [], '');   // fleet container is already running
        } elseif (($spec = $this->resolvePhantom($ip, $target)) !== null) {
            $started = $this->phantoms !== null && $this->phantoms->markStarted((string) $spec['id']);
            $this->emitTuple($started ? 204 : 304, [], '');
        } else {
            $this->json(404, $this->daemon->notFound('container', $target));
            $this->logHit($ctx, $ip, 'start', AttackClassifier::DOCKER_API);

            return;
        }
        $this->logHit($ctx, $ip, 'start', AttackClassifier::DOCKER_API);
        $this->reportIntent($ctx, $ip, 'start', ['class' => AttackClassifier::DOCKER_API, 'signals' => [], 'command' => '', 'image_ref' => ['display' => ''], 'target' => $target]);
    }

    private function execCreate(RequestContext $ctx, string $ip): void
    {
        $target = DockerApiRouter::target($ctx->path);
        $containerId = '';
        if (($fi = $this->daemon->fleetIndex($target)) !== null) {
            $containerId = $this->daemon->fleetId($fi);
        } elseif (($spec = $this->resolvePhantom($ip, $target)) !== null) {
            $containerId = (string) $spec['id'];
        } else {
            $this->json(404, $this->daemon->notFound('container', $target));
            $this->logHit($ctx, $ip, 'exec-create', AttackClassifier::DOCKER_RECON);

            return;
        }

        $body = EscapeIntent::decodeBody($ctx->rawBody);
        $intel = $this->intent->fromExec($body);
        $execId = $this->daemon->execId($containerId, (string) $intel['command']);
        $this->phantoms?->recordExec($execId, ['command' => $intel['command'], 'user' => $intel['user'], 'container' => $containerId]);
        $this->json(201, ['Id' => $execId]);
        $this->logHit($ctx, $ip, 'exec-create', (string) $intel['class'], $intel);
        $this->reportIntent($ctx, $ip, 'exec', $intel);
    }

    // --- container control (logged, not reported) ---

    private function control(RequestContext $ctx, string $ip, string $kind): void
    {
        $target = DockerApiRouter::target($ctx->path);
        if (($fi = $this->daemon->fleetIndex($target)) !== null) {
            if ($kind !== 'restart') {
                $this->phantoms?->hide($ip, $this->daemon->fleetId($fi));
            }
            $this->emitTuple(204, [], '');
        } elseif (($spec = $this->resolvePhantom($ip, $target)) !== null) {
            $running = (bool) ($spec['started'] ?? false);
            if ($kind === 'kill' && !$running) {
                $this->json(409, ['message' => sprintf('Container %s is not running', (string) $spec['id'])]);
            } elseif ($kind === 'stop' && !$running) {
                $this->emitTuple(304, [], '');   // already stopped
            } else {
                if ($kind !== 'restart') {
                    $this->phantoms?->hide($ip, (string) $spec['id']);
                }
                $this->emitTuple(204, [], '');
            }
        } else {
            $this->json(404, $this->daemon->notFound('container', $target));
        }
        $this->logHit($ctx, $ip, $kind, AttackClassifier::DOCKER_API);
    }

    private function remove(RequestContext $ctx, string $ip): void
    {
        $target = DockerApiRouter::target($ctx->path);
        $force = $this->flag($ctx->query, 'force');
        if (($fi = $this->daemon->fleetIndex($target)) !== null) {
            if (!$force) {
                $id = $this->daemon->fleetId($fi);
                $this->json(409, ['message' => sprintf(
                    'You cannot remove a running container %s. Stop the container before attempting removal or force remove',
                    $id
                )]);
            } else {
                $this->phantoms?->hide($ip, $this->daemon->fleetId($fi));
                $this->emitTuple(204, [], '');
            }
        } elseif (($spec = $this->resolvePhantom($ip, $target)) !== null) {
            $running = (bool) ($spec['started'] ?? false);
            if ($running && !$force) {
                $this->json(409, ['message' => sprintf(
                    'You cannot remove a running container %s. Stop the container before attempting removal or force remove',
                    (string) $spec['id']
                )]);
            } else {
                $this->phantoms?->hide($ip, (string) $spec['id']);
                $this->emitTuple(204, [], '');
            }
        } else {
            $this->json(404, $this->daemon->notFound('container', $target));
        }
        $this->logHit($ctx, $ip, 'remove', AttackClassifier::DOCKER_API);
    }

    // --- phantom helpers ---

    /** @return array{0:int,1:int,2:int,3:int} [runningExtra, createdExtra, imagesExtra, hiddenFleetCount] */
    private function counts(string $ip): array
    {
        if ($this->phantoms === null) {
            return [0, 0, 0, 0];
        }
        $live = $this->livePhantoms($ip);
        $running = 0;
        $created = 0;
        foreach ($live as $spec) {
            if ($spec['started'] ?? false) {
                $running++;
            } else {
                $created++;
            }
        }
        $images = count($this->phantoms->pulled($ip));

        return [$running, $created, $images, count($this->hiddenFleet($ip))];
    }

    /** This IP's phantom specs that are not hidden. @return list<array<string,mixed>> */
    private function livePhantoms(string $ip): array
    {
        if ($this->phantoms === null) {
            return [];
        }
        $hidden = $this->phantoms->hidden($ip);
        $out = [];
        foreach ($this->phantoms->phantoms($ip, null) as $spec) {
            if (!in_array((string) $spec['id'], $hidden, true)) {
                $out[] = $spec;
            }
        }

        return $out;
    }

    /** Fleet ids/names this IP has stopped or removed. @return list<string> */
    private function hiddenFleet(string $ip): array
    {
        $out = [];
        foreach ($this->phantoms?->hidden($ip) ?? [] as $h) {
            if ($this->daemon->fleetIndex($h) !== null) {
                $out[] = $h;
            }
        }

        return $out;
    }

    /** @return array<string,mixed>|null a live (non-hidden) phantom for this IP by id/prefix/name */
    private function resolvePhantom(string $ip, string $target): ?array
    {
        if ($this->phantoms === null) {
            return null;
        }
        $spec = $this->phantoms->resolve($ip, $target);
        if ($spec === null) {
            return null;
        }

        return in_array((string) $spec['id'], $this->phantoms->hidden($ip), true) ? null : $spec;
    }

    /** The id of the fleet/phantom container already holding $name for this IP, or '' if free. */
    private function nameOwner(string $ip, string $name): string
    {
        $n = ltrim($name, '/');
        if ($n === '') {
            return '';
        }
        $fi = $this->daemon->fleetIndex($n);
        if ($fi !== null) {
            return $this->daemon->fleetId($fi);
        }
        foreach ($this->livePhantoms($ip) as $spec) {
            if (ltrim((string) $spec['name'], '/') === $n) {
                return (string) $spec['id'];
            }
        }

        return '';
    }

    // --- emit / encode ---

    /** Build a docker multiplexed-stream body (8-byte frame header + payload) for a list of lines. */
    private function multiplex(array $lines): string
    {
        $out = '';
        foreach ($lines as $line) {
            $payload = (string) $line . "\n";
            $out .= pack('C', 1) . "\x00\x00\x00" . pack('N', strlen($payload)) . $payload;   // stream 1 = stdout
        }

        return $out;
    }

    private function flag(string $query, string $name): bool
    {
        if ($query === '') {
            return false;
        }
        parse_str($query, $q);
        $v = $q[$name] ?? null;

        return $v === '1' || $v === 'true' || $v === 'True';
    }

    /** @param array<int|string,mixed> $payload */
    private function json(int $status, array $payload): void
    {
        $this->emitTuple(
            $status,
            ['Content-Type' => 'application/json'],
            (string) json_encode($payload, JSON_UNESCAPED_SLASHES)
        );
    }

    /** @param array<string,string> $headers */
    private function emitTuple(int $status, array $headers, string $body): void
    {
        $headers += self::DAEMON_HEADERS;

        if ($this->emit !== null) {
            ($this->emit)($status, $headers, $body);

            return;
        }

        // A real Docker daemon sends no X-Powered-By; strip the app's global persona header on this
        // path (the front controller also skips setting it for Docker paths — belt-and-suspenders).
        header_remove('X-Powered-By');
        http_response_code($status);
        foreach ($headers as $name => $value) {
            header("{$name}: {$value}");
        }
        echo $body;
    }

    /**
     * Log one Docker hit. event='docker' (enables the dashboard Docker quick-view); severity is
     * class-driven (docker_escape ⇒ critical, docker_api ⇒ high, docker_recon ⇒ medium); the
     * structured intel record rides the JSON-lines export under the 'docker' key (no schema change),
     * and the FULL raw body is stored (the store caps at 2000 — the old 300 B pre-truncation dropped
     * exactly the HostConfig escape tail).
     *
     * @param array<string,mixed>|null $intel
     */
    private function logHit(RequestContext $ctx, string $ip, string $kind, string $class, ?array $intel = null): void
    {
        $badges = ['payload-' . $class];
        foreach ((array) ($intel['signals'] ?? []) as $sig) {
            $badges[] = 'docker-' . $sig;
        }
        $badges = array_slice(array_values(array_unique($badges)), 0, 8);

        $path = $ctx->path;
        if (in_array($kind, ['create', 'pull'], true) && $ctx->query !== '') {
            $path .= '?' . $ctx->query;
        }

        $entry = [
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => $ctx->method,
            'path' => substr($path, 0, 400),
            'ua' => substr($ctx->headers['User-Agent'] ?? '', 0, 160),
            'matched' => true,
            'severity' => AttackClassifier::severityFor($class),
            'templates' => $badges,
            'served' => true,
            'event' => 'docker',
            'endpoint' => $kind,
            'image' => (string) ($intel['image'] ?? ''),
            'cmd' => (string) ($intel['command'] ?? ''),
            'body' => $ctx->rawBody,
        ];
        if ($intel !== null) {
            $entry['docker'] = $intel;   // rides the export line + stderr; no dedicated SQLite column
        }
        $this->store->append($entry);
    }

    /**
     * Report container-deploy INTENT (create / pull / start / exec) — never recon. The public AbuseIPDB
     * comment carries only a TRUSTED, bounded prefix (class + verb + fixed signal tokens) and a
     * ReportComment-sanitised `image=`/`cmd=` detail; env values, registry-auth secrets, names and full
     * bind paths NEVER enter it. The private mainnet reporter additionally gets the full structured
     * record + a confidence score.
     *
     * @param array<string,mixed> $intel
     */
    private function reportIntent(RequestContext $ctx, string $ip, string $verb, array $intel): void
    {
        if ($this->abuse === null && $this->threatIntel === null) {
            return;
        }
        $class = (string) ($intel['class'] ?? AttackClassifier::DOCKER_API);
        $signals = array_slice(array_values((array) ($intel['signals'] ?? [])), 0, 8);
        $display = (string) ($intel['image_ref']['display'] ?? ($intel['image'] ?? ''));
        $prefix = $class . ' container-' . $verb . ' [' . implode(',', $signals) . ']';
        $detail = 'image=' . $display . ' cmd=' . substr((string) ($intel['command'] ?? ''), 0, 120);
        $comment = ReportComment::build($prefix, $detail);
        $categories = AbuseIpdb::categoriesForWebClass($class);

        $this->abuse?->enqueue($ip, $comment, $categories);
        $this->threatIntel?->enqueue($ip, $comment, $categories, $intel, EscapeIntent::confidenceFor($intel));
    }
}
