<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Funnypot\App\Engagement\EngagementEvent;
use Funnypot\App\Engagement\EngagementRecorder;
use Funnypot\App\Engagement\EventKind;
use Funnypot\App\Engagement\LureId;
use Funnypot\App\Engagement\Stage;
use Funnypot\App\Storage\TarpitBudget;
use Funnypot\App\Tarpit\Attrition\AttritionArtifactRenderer;
use Funnypot\App\Tarpit\Attrition\AttritionHandle;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionProgress;
use Funnypot\App\Tarpit\Attrition\AttritionStateCost;
use Funnypot\App\Tarpit\Attrition\AttritionStore;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\App\Tarpit\Attrition\JobCandidate;
use Funnypot\App\Tarpit\Attrition\ManifestCommit;
use Funnypot\Core\RequestContext;
use Throwable;

/**
 * The bounded async-export attrition journey handler (FP-0272 §6). It owns exactly the four owned
 * requests under three prefixes and runs the same order on every one: shared {@see TarpitBudget::guard()}
 * FIRST, then shape/token validation, then state access only for a valid typed handle, then a fully
 * buffered response, one emit, and finally charge/release/observe. Every failure after the guard emits the
 * exact ordinary 404 (byte-identical to {@see HoneypotController::serveBelievable404()}) through the
 * injected emitter — no attrition-only header, no timing, no 500. Invalid inputs allocate no attrition row
 * or engagement event; only the mandatory budget slot/ledger is ever touched by them.
 *
 * Every request is promptly completed and buffered: it never sleeps, streams, waits on a background job,
 * decompresses, or performs a filesystem/URL/socket/subprocess action. Responses are hard-capped (job/
 * manifest JSON ≤ 4 KiB, NDJSON artifact ≤ 32 KiB) and every URL is same-origin relative.
 *
 * A server-issued handle recurs verbatim in the job id/relative URLs/ETag rather than through the
 * served-fingerprint reject-sampler ({@see \Funnypot\App\Tarpit\InertSecret}): a handle is
 * cryptographically fixed, so it cannot be re-derived to dodge a signature. The renderer's generated
 * body IS routed through that gate; the ~117-byte opaque base64url handle is not, and could carry a
 * `9\d{5}` run that the app denylist's bare-CRS heuristic would flag. That is a benign false positive,
 * not a tell: a scanner cannot distinguish a coincidental digit run inside an opaque token from a rule-id
 * echo, and the token surface is deliberately not scanned by the served-fingerprint gates.
 */
final class AttritionController
{
    public const JOBS_PREFIX = '/admin/export/jobs/';
    public const MANIFESTS_PREFIX = '/admin/export/manifests/';
    public const ARTIFACTS_PREFIX = '/admin/export/artifacts/';

    private const JOB_SCHEMA = 'audit-export-job/v1';
    private const MANIFEST_FILENAME = 'MANIFEST.sha256';
    private const ARTIFACT_FILENAME = 'audit-export.ndjson';

    /** @var callable():int */
    private $clock;

    private Closure $emitter;

    /**
     * @param Closure(int,array<string,string>,string):void|null $emitter injectable for tests
     */
    public function __construct(
        private AttritionStore $store,
        private AttritionTokenCodec $codec,
        private AttritionArtifactRenderer $renderer,
        private TarpitBudget $budget,
        private int $personaSeed,
        ?Closure $emitter = null,
        private ?EngagementRecorder $engagement = null,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
        $this->emitter = $emitter ?? static function (int $status, array $headers, string $body): void {
            foreach ($headers as $name => $value) {
                header($name . ': ' . $value);
            }
            // PHP's Location header can implicitly select 302; the explicit job contract is 202.
            http_response_code($status);
            echo $body;
        };
    }

    /** Owns all three prefixes regardless of method, so a wrong method cannot fall into another emulator. */
    public function matches(string $path): bool
    {
        $p = substr($path, 0, strcspn($path, "?#"));

        return strncmp($p, self::JOBS_PREFIX, strlen(self::JOBS_PREFIX)) === 0
            || strncmp($p, self::MANIFESTS_PREFIX, strlen(self::MANIFESTS_PREFIX)) === 0
            || strncmp($p, self::ARTIFACTS_PREFIX, strlen(self::ARTIFACTS_PREFIX)) === 0;
    }

    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $slot = $this->budget->guard($clientIp);
        if ($slot === null) {
            $this->bounded404();

            return;
        }
        $startNs = hrtime(true);
        $bytes = 0;
        $record = null;
        try {
            $outcome = $this->route($ctx, ($this->clock)());
            if ($outcome === null) {
                $this->bounded404();
            } else {
                $bytes = strlen($outcome['body']);
                $this->emit($outcome['status'], $outcome['headers'], $outcome['body']);
                $record = $outcome['record'];
            }
        } catch (Throwable $e) {
            // The whole response is built before the first byte, so a fault here has emitted nothing:
            // shed to the ordinary 404, never a 500 (the honeypot-wide invariant).
            $this->bounded404();
            $bytes = 0;
            $record = null;
        } finally {
            $wallMs = (int) ((hrtime(true) - $startNs) / 1_000_000);
            $this->budget->charge($clientIp, $bytes, $wallMs, 1);
            $this->budget->release($slot);
            if ($record !== null) {
                $this->observe($ctx, $clientIp, $record, $bytes, $wallMs);
            }
        }
    }

    /**
     * Validate the request and produce the complete buffered response, or null to shed the ordinary 404.
     * No token verification, state read, or render happens before this — the guard already ran in handle().
     *
     * @return array{status:int,headers:array<string,string>,body:string,record:array{0:string,1:string,2:?string}|null}|null
     */
    private function route(RequestContext $ctx, int $now): ?array
    {
        if ($ctx->query !== '' || $ctx->rawBody !== null) {
            return null;
        }
        $path = substr($ctx->path, 0, strcspn($ctx->path, "?#"));
        $method = $ctx->method;

        if (strncmp($path, self::JOBS_PREFIX, strlen(self::JOBS_PREFIX)) === 0) {
            $token = substr($path, strlen(self::JOBS_PREFIX));
            if ($method === 'POST') {
                return $this->create($token, $now);
            }
            if ($method === 'GET') {
                return $this->poll($token, $now);
            }

            return null;
        }
        if (strncmp($path, self::MANIFESTS_PREFIX, strlen(self::MANIFESTS_PREFIX)) === 0) {
            return $method === 'GET' ? $this->manifest(substr($path, strlen(self::MANIFESTS_PREFIX)), $now) : null;
        }
        if (strncmp($path, self::ARTIFACTS_PREFIX, strlen(self::ARTIFACTS_PREFIX)) === 0) {
            return $method === 'GET' ? $this->artifact(substr($path, strlen(self::ARTIFACTS_PREFIX)), $now) : null;
        }

        return null;
    }

    /** @return array{status:int,headers:array<string,string>,body:string,record:array{0:string,1:string,2:?string}|null}|null */
    private function create(string $token, int $now): ?array
    {
        $entry = $this->codec->verifyExpectedKind($token, AttritionHandle::KIND_ENTRY, $now);
        if ($entry === null) {
            return null;
        }
        $jobToken = $this->codec->deriveJob($entry);
        $jobHandle = $this->codec->verifyExpectedKind($jobToken, AttritionHandle::KIND_JOB, $now);
        if ($jobHandle === null) {
            return null;
        }
        $firstManifestToken = $this->codec->deriveFirstManifest($jobHandle);
        $jobId = $this->codec->storedId($jobToken, AttritionHandle::KIND_JOB);
        $candidate = new JobCandidate(
            $this->codec->journeyId($entry),
            $this->codec->storedId($token, AttritionHandle::KIND_ENTRY),
            $jobId,
            $this->codec->storedId($firstManifestToken, AttritionHandle::KIND_MANIFEST),
            AttritionStore::JOB_REVISION,
            $entry->expiresAt,
        );
        if ($this->store->createJob($candidate, $now) === null) {
            return null;
        }
        $statusUrl = self::JOBS_PREFIX . $jobToken;
        $body = self::json([
            'schema' => self::JOB_SCHEMA,
            'id' => $jobToken,
            'state' => 'queued',
            'progress' => 1,
            'poll' => 0,
            'status_url' => $statusUrl,
        ]);
        if ($body === null) {
            return null;
        }

        return [
            'status' => 202,
            'headers' => self::successHeaders('application/json; charset=utf-8') + ['Location' => $statusUrl, 'Retry-After' => '2'],
            'body' => $body,
            'record' => [Stage::COLLECT, EventKind::LURE_FOLLOWED, $jobId],
        ];
    }

    /** @return array{status:int,headers:array<string,string>,body:string,record:array{0:string,1:string,2:?string}|null}|null */
    private function poll(string $token, int $now): ?array
    {
        $job = $this->codec->verifyExpectedKind($token, AttritionHandle::KIND_JOB, $now);
        if ($job === null) {
            return null;
        }
        $jobId = $this->codec->storedId($token, AttritionHandle::KIND_JOB);
        $state = $this->store->advancePoll($jobId, $now);
        if ($state === null) {
            return null;
        }
        $row = AttritionProgress::forPoll($state->poll);
        $payload = [
            'schema' => self::JOB_SCHEMA,
            'id' => $token,
            'state' => $row['state'],
            'progress' => $row['progress'],
            'poll' => $state->poll,
            'status_url' => self::JOBS_PREFIX . $token,
        ];
        $headers = self::successHeaders('application/json; charset=utf-8');
        if ($state->poll >= AttritionLimits::POLLS) {
            $payload['manifest_url'] = self::MANIFESTS_PREFIX . $this->codec->deriveFirstManifest($job);
        } else {
            $headers['Retry-After'] = (string) $row['retry'];
        }
        $body = self::json($payload);
        if ($body === null) {
            return null;
        }
        $stage = $state->poll >= 8 ? Stage::VERIFY : Stage::COLLECT;

        return [
            'status' => 200,
            'headers' => $headers,
            'body' => $body,
            'record' => [$stage, EventKind::JOB_POLLED, $jobId],
        ];
    }

    /** @return array{status:int,headers:array<string,string>,body:string,record:array{0:string,1:string,2:?string}|null}|null */
    private function manifest(string $token, int $now): ?array
    {
        $handle = $this->codec->verifyExpectedKind($token, AttritionHandle::KIND_MANIFEST, $now);
        if ($handle === null) {
            return null;
        }
        $manifestId = $this->codec->storedId($token, AttritionHandle::KIND_MANIFEST);
        $candidate = $this->store->prepareManifest($manifestId, $now);
        if ($candidate === null) {
            return null;
        }
        $generation = $candidate->generation;
        $artifactToken = $this->codec->deriveArtifact($handle, $generation);
        $artifactUrl = self::ARTIFACTS_PREFIX . $artifactToken;

        $nextManifestUrl = null;
        $nextManifestId = null;
        if ($generation + 1 < AttritionLimits::GENERATIONS) {
            $nextManifestToken = $this->codec->deriveNextManifest($handle, $generation + 1);
            $nextManifestUrl = self::MANIFESTS_PREFIX . $nextManifestToken;
            $nextManifestId = $this->codec->storedId($nextManifestToken, AttritionHandle::KIND_MANIFEST);
        }

        $declaredHash = $this->renderer->renderSnapshot($this->personaSeed, $candidate->jobId, $generation)->sha256;
        $manifest = $this->renderer->renderManifest($declaredHash, $artifactUrl, $nextManifestUrl, $generation);
        if ($manifest === null) {
            return null;
        }

        $record = null;
        if (!$candidate->alreadyCommitted) {
            $artifactId = $this->codec->storedId($artifactToken, AttritionHandle::KIND_ARTIFACT);
            $commit = new ManifestCommit(
                $this->codec->journeyId($handle),
                $candidate->jobId,
                $this->codec->generationId($handle, $generation),
                $generation,
                $manifestId,
                $artifactId,
                $nextManifestId,
                $candidate->rendererRevision,
                $candidate->expiresAt,
                AttritionStateCost::GENERATION,
            );
            if ($this->store->commitManifest($commit, $now) === null) {
                return null;
            }
            $record = [Stage::VERIFY, EventKind::ARTIFACT_ISSUED, $artifactId];
        }

        return [
            'status' => 200,
            'headers' => self::successHeaders('text/plain; charset=utf-8')
                + ['Content-Disposition' => 'attachment; filename="' . self::MANIFEST_FILENAME . '"'],
            'body' => $manifest->body,
            'record' => $record,
        ];
    }

    /** @return array{status:int,headers:array<string,string>,body:string,record:array{0:string,1:string,2:?string}|null}|null */
    private function artifact(string $token, int $now): ?array
    {
        $handle = $this->codec->verifyExpectedKind($token, AttritionHandle::KIND_ARTIFACT, $now);
        if ($handle === null) {
            return null;
        }
        $artifactId = $this->codec->storedId($token, AttritionHandle::KIND_ARTIFACT);
        $candidate = $this->store->prepareArtifact($artifactId, $now);
        if ($candidate === null) {
            return null;
        }
        $snapshot = AttritionArtifactRenderer::artifactSnapshotIndex($candidate->generation);
        $artifact = $this->renderer->renderSnapshot($this->personaSeed, $candidate->jobId, $snapshot);
        if ($artifact->length > AttritionLimits::ARTIFACT_MAX_BYTES) {
            return null;
        }
        $transition = $this->store->commitArtifactFetch($artifactId, $now);
        if ($transition === null) {
            return null;
        }
        $kind = $transition->isFirst ? EventKind::ARTIFACT_FETCHED : EventKind::ARTIFACT_REUSED;

        return [
            'status' => 200,
            'headers' => self::successHeaders('application/x-ndjson')
                + [
                    'Content-Disposition' => 'attachment; filename="' . self::ARTIFACT_FILENAME . '"',
                    'Content-Length' => (string) $artifact->length,
                    'ETag' => '"' . $artifact->sha256 . '"',
                ],
            'body' => $artifact->body,
            'record' => [Stage::VERIFY, $kind, $artifactId],
        ];
    }

    /** @return array<string,string> the two headers every successful attrition response carries */
    private static function successHeaders(string $contentType): array
    {
        return [
            'Content-Type' => $contentType,
            'Cache-Control' => 'no-store',
            'X-Content-Type-Options' => 'nosniff',
        ];
    }

    /** Canonical JSON body (fixed field order) plus exactly one trailing LF, or null if over the 4 KiB cap. */
    private static function json(array $payload): ?string
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($body === false) {
            return null;
        }
        $body .= "\n";

        return strlen($body) <= AttritionLimits::JSON_MAX_BYTES ? $body : null;
    }

    /**
     * @param array{0:string,1:string,2:?string} $record stage, event kind, relationship id
     */
    private function observe(RequestContext $ctx, string $clientIp, array $record, int $bytes, int $wallMs): void
    {
        if ($this->engagement === null) {
            return;
        }
        try {
            $this->engagement->record($clientIp, EngagementRecorder::userAgentOf($ctx), new EngagementEvent(
                $record[0],
                $record[1],
                $bytes,
                $wallMs,
                LureId::ATTRITION_EXPORT,
                $record[2],
            ));
        } catch (Throwable $e) {
            // observer-only: a metrics fault never changes the served response
        }
    }

    private function emit(int $status, array $headers, string $body): void
    {
        ($this->emitter)($status, $headers, $body);
    }

    /** The believable nginx 404 — byte-identical to {@see HoneypotController::serveBelievable404()}. */
    private function bounded404(): void
    {
        $this->emit(404, ['Content-Type' => 'text/html'],
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n"
            . "<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
            . "<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n");
    }
}
