<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\AttackClassifier;
use Funnypot\Core\RequestContext;

/**
 * Serves one fake Docker Engine API turn: build the daemon payload for the matched endpoint, emit it,
 * then log + report the hit so it lands on the dashboard like any probe. The whole point is capturing
 * the container-deploy intent — a miner bot's POST /containers/create carries the image (XMRig, …) and
 * command it wanted to run — while running absolutely nothing. Every verb is simulated success only;
 * no container is created, started or persisted, and no process is ever spawned.
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

    private DockerDaemon $daemon;

    /** @var callable():int */
    private $clock;

    /** @var callable(int,array<string,string>,string):void|null */
    private $emit;

    /**
     * @param callable():int|null $clock live unix-time source for /info SystemTime; null = time().
     * @param callable(int,array<string,string>,string):void|null $emit buffered [status,headers,body]
     *        sink; null = the real header()/echo path. Injected as a capturing sink in tests.
     */
    public function __construct(
        private HitStore $store,
        int $personaSeed,
        private ?AbuseIpdb $abuse = null,
        ?callable $clock = null,
        ?callable $emit = null,
    ) {
        $this->daemon = DockerDaemon::fromSeed($personaSeed);
        $this->clock = $clock ?? static fn (): int => time();
        $this->emit = $emit;
    }

    public function respond(RequestContext $ctx, string $ip): void
    {
        $kind = DockerApiRouter::endpoint($ctx->path);
        if ($kind === null) {
            return; // not a Docker path; callers guard with matches() first
        }

        $image = '';
        $cmd = '';

        switch ($kind) {
            case 'ping':
                $this->emitTuple(200, ['Content-Type' => 'text/plain; charset=utf-8'], 'OK');
                break;
            case 'version':
                $this->json(200, $this->daemon->version());
                break;
            case 'info':
                $this->json(200, $this->daemon->info(($this->clock)()));
                break;
            case 'containers':
                $this->json(200, $this->daemon->containers());
                break;
            case 'images':
                $this->json(200, $this->daemon->images());
                break;
            case 'create':
                [$image, $cmd] = $this->parseCreate($ctx->rawBody);
                // Simulated create only — a plausible fresh container id, but nothing is created.
                $this->json(201, ['Id' => $this->daemon->createdId($image, $cmd), 'Warnings' => null]);
                break;
            case 'start':
                // Simulated start — 204 No Content, exactly as a real daemon returns; nothing runs.
                $this->emitTuple(204, [], '');
                break;
        }

        $this->logHit($ctx, $ip, $kind, $image, $cmd);
        $this->report($ctx, $ip, $kind, $image);
    }

    /**
     * Pull the attacker's requested image and command out of a /containers/create body — the intel we
     * exist to capture. Entrypoint + Cmd are joined into one readable command; a malformed body yields
     * empty strings (the raw body is logged separately, so nothing is lost).
     *
     * @return array{0:string,1:string} [image, command]
     */
    private function parseCreate(?string $rawBody): array
    {
        $body = json_decode((string) $rawBody, true);
        if (!is_array($body)) {
            return ['', ''];
        }
        $image = is_string($body['Image'] ?? null) ? $body['Image'] : '';
        $parts = array_merge($this->wordsOf($body['Entrypoint'] ?? null), $this->wordsOf($body['Cmd'] ?? null));

        return [substr($image, 0, 200), substr(implode(' ', $parts), 0, 400)];
    }

    /** @param mixed $v @return list<string> a Docker Cmd/Entrypoint may be a string or a string array. */
    private function wordsOf($v): array
    {
        if (is_string($v)) {
            return [$v];
        }
        if (is_array($v)) {
            return array_values(array_map('strval', array_filter($v, 'is_scalar')));
        }

        return [];
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

    private function logHit(RequestContext $ctx, string $ip, string $kind, string $image, string $cmd): void
    {
        // Same store method HoneypotController::handle() uses, so Docker probes show in the feed + count
        // toward the per-IP velocity gate. The requested image + command on a create are the recon intel,
        // recorded on the entry (they ride the JSON-lines export even without dedicated columns).
        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $ip,
            'method' => $ctx->method,
            'path' => substr($ctx->path, 0, 200),
            'ua' => substr($ctx->headers['User-Agent'] ?? '', 0, 160),
            'matched' => true,
            'severity' => AttackClassifier::severityFor(AttackClassifier::DOCKER_API),
            'templates' => ['payload-' . AttackClassifier::DOCKER_API],
            'served' => true,
            'endpoint' => $kind,
            'image' => $image,
            'cmd' => $cmd,
            'body' => $ctx->rawBody !== null ? substr($ctx->rawBody, 0, 300) : null,
        ]);
    }

    private function report(RequestContext $ctx, string $ip, string $kind, string $image): void
    {
        // Web-app-attack category; the self-guard (FUNNYPOT_SELF_IPS) lives inside enqueue(). A create
        // carries the image the attacker tried to deploy, which is the useful bit of the report.
        $comment = $kind === 'create' && $image !== ''
            ? AttackClassifier::DOCKER_API . ' container-create image=' . substr($image, 0, 160)
            : AttackClassifier::DOCKER_API . ' ' . $ctx->method . ' ' . substr($ctx->path, 0, 160);
        $this->abuse?->enqueue($ip, $comment, '21');
    }
}
