<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\VisualPersona;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\Storage\LlmFakeCache;
use Funnypot\Detection;
use Funnypot\RequestContext;
use Funnypot\Support\PathNormalizer;
use Funnypot\SynthesizedResponse;

/**
 * Orchestrates an LLM-generated fake for a request the engine could not match. Cache first (the
 * common, cheap case), then the gate, then a single-flight generation, sanitize, cache, and build a
 * response. Every decline or failure returns null, which the controller turns into the unchanged
 * plain 404 — the feature is purely additive and can only ever upgrade a 404 into a convincing fake.
 *
 * Status and Content-Type are app-chosen (never model-chosen): no 3xx, so a hallucinated Location
 * can never make the honeypot an open redirect.
 */
final class LlmFakeResponder
{
    public function __construct(
        private ProbeGate $gate,
        private LlmFakeCache $cache,
        private LlmClient $client,
        private LlmOutputSanitizer $sanitizer,
        private HitStore $store,
        private LlmResponseProfiles $profiles,
        private string $promptVersion = 'v1',
        private int $maxConcurrent = 4,
        private int $personaSeed = 0,
        private string $htmlArtifactVersion = '',
    ) {
    }

    public function respond(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        // Invariant: this feature can only ever upgrade a 404. Any fault anywhere below — a store
        // error in the gate, a bad prepared statement, anything — must degrade to null (the plain
        // 404), never escape as a 500 that a scanner could use to tell the honeypot apart.
        try {
            $response = $this->attempt($context, $clientIp);
        } catch (\Throwable $e) {
            return null;
        }

        // Log every served fake (cache hit or fresh) with the exact body the attacker got, so the
        // operator can see what the model returned. Logging must never suppress a valid response.
        if ($response !== null) {
            try {
                $this->logServed($context, $clientIp, $response);
            } catch (\Throwable $e) {
                // best-effort
            }
        }

        return $response;
    }

    private function attempt(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        $key = PathNormalizer::key($context->method, $context->path);
        // The extension decides the fake's shape (Content-Type, prompt, grammar, sanitizer rules): a
        // .js gets JavaScript, a .json gets JSON, an .env plaintext — not an HTML page every time.
        $profile = $this->profiles->resolve($context->path);
        // The rendered-page path caches under the artifact version (the renderer's own output
        // format), not the prompt version, so a shell/skin change invalidates without needing a new
        // prompt. Resolved once so get/awaitOther/put below all agree on the same cache key.
        $version = ($profile->renderer !== null && $this->htmlArtifactVersion !== '')
            ? $this->htmlArtifactVersion
            : $this->promptVersion;

        // A "live" panel view renders a real-time value on every request (the staking rewards feed's
        // "Nh ago" ages). It must be re-rendered per request — neither served from nor written to the
        // byte-identical panel cache below, since caching would freeze the live value (the tell it avoids).
        $isLive = $profile->renderer !== null && $profile->renderer->isLivePath($context->path);

        // 1. Cache hit — the common case, served byte-identical, no model call, no gate query. The
        //    stored Content-Type is authoritative (a path's kind is fixed), so serve it, not a guess.
        //    Skipped for live paths (they must re-render).
        if (!$isLive) {
            $hit = $this->cache->get($key, $version);
            if ($hit !== null) {
                return $this->build($hit['status'], $hit['content_type'], $hit['body']);
            }
        }

        // A coherent product panel (admin/wp/phpmyadmin/grafana chrome) is the honeypot's deep-engagement
        // lure: every sub-path under it is legitimate navigation (the operator wants HOURS of exploration
        // across a dense sidebar), not a probe. It renders DETERMINISTICALLY from its seeded skin —
        // generated chrome + seeded Fake\* data, no model call — so it must never depend on a flaky
        // generation, and it must NOT be rate-gated: a human clicking a few dozen links would otherwise
        // trip the per-IP velocity window, get bulk-scan-pinned, and watch the whole panel collapse to
        // plain 404s. Cheap render + cache means exempting it costs nothing.
        $isPanel = $profile->renderer !== null && $profile->renderer->matchesProductSkin($context->path);

        // 2. Panel path: served HERE, before and INSTEAD OF the gate. ProbeGate::decide() *creates* the
        //    bulk-scan pin as a side effect, so it must not even be consulted for panel navigation. Served
        //    200 (you are "in" the panel), byte-identical per deploy, cached like any other fake. The plain
        //    velocity/bulk-scan gate below still governs every NON-panel path (anti-DoS + anti-enumeration).
        if ($isPanel && $profile->renderer !== null) {
            $body = $profile->renderer->render(
                PageSlots::fromArray([]),
                VisualPersona::fromSeed($this->personaSeed),
                $context
            );
            if (!$this->sanitizer->pageBodyOk($body, true)) {
                return null;                                  // defensive: our own chrome should always pass
            }
            if (!$isLive) {                                   // a live view re-renders every request; never cache it
                $this->cache->put($key, 200, $profile->contentType, $body, $version);
            }

            return $this->build(200, $profile->contentType, $body);
        }

        // 3. Gate (non-panel paths only; paid on a cache miss). Sheds the probe/scan 404s before they can
        //    consume a generation slot, so the cap below is only ever spent on genuinely plausible paths.
        $decision = $this->gate->decide($context->method, $context->path, $clientIp);
        if (!$decision['generate']) {
            return null;
        }

        // 4. Atomic single-flight + concurrency cap. Over the cap (FULL) goes straight to the plain
        //    404 — never queued. A peer already generating this same path (BUSY) waits briefly for
        //    its result, then also falls back. Only the winner (WON) actually calls the model.
        $lock = $this->cache->acquire($key, $this->maxConcurrent);
        if ($lock === LlmFakeCache::ACQUIRE_FULL) {
            return null;
        }
        if ($lock === LlmFakeCache::ACQUIRE_BUSY) {
            $peer = $this->cache->awaitOther($key, $version);

            return $peer !== null ? $this->build($peer['status'], $peer['content_type'], $peer['body']) : null;
        }

        try {
            $raw = $this->client->generate($profile->prompt->build($context->method, $context->path), $profile->grammar);
            if ($raw === null) {
                return null;                                  // failure is never cached
            }
            if ($profile->renderer !== null) {
                // Slot-based path: the model supplies typed field values (not markup), the trusted
                // skin assembles the page. Validate the decoded slots, render, then re-validate the
                // WHOLE assembled page — chrome + model text can combine into something neither half
                // was individually.
                $decoded = $this->sanitizer->sanitizeToArray($raw);
                if ($decoded === null) {
                    return null;
                }
                $body = $profile->renderer->render(
                    PageSlots::fromArray($decoded),
                    VisualPersona::fromSeed($this->personaSeed),
                    $context
                );
                if (!$this->sanitizer->pageBodyOk($body)) {
                    return null;
                }
            } else {
                $body = $this->sanitizer->sanitize($raw, $profile->kind);
                if ($body === null) {
                    return null;
                }
            }
            $status = $this->chooseStatus($context->path);
            $this->cache->put($key, $status, $profile->contentType, $body, $version);

            return $this->build($status, $profile->contentType, $body);
        } finally {
            $this->cache->release($key);
        }
    }

    private function build(int $status, string $contentType, string $body): SynthesizedResponse
    {
        // X-Powered-By is set globally by the front controller for every response, so it already
        // reaches this tier unchanged — nothing to add here. X-Request-Id, by contrast, is emitted
        // per response by the template tier (ResponseSynthesizer), so an LLM fake without one would
        // be a header-distinct minority among app-generated content; mirror it here so both tiers of
        // synthesized content share the same shape. The plain 404 is styled as nginx's own error
        // page (bypassing the app), so it carries neither — that split is expected, not a gap.
        return new SynthesizedResponse(
            $status,
            ['Content-Type' => $contentType, 'X-Request-Id' => bin2hex(random_bytes(8))],
            $body,
            Detection::none()
        );
    }

    /** App-chosen status (never the model's). Panels are served earlier (always 200, gate-exempt), so this
     *  governs only the remaining non-panel fakes: auth-looking paths bias to 401 so not every plausible
     *  path returns 200 (that itself is a fingerprint under distributed probing). */
    private function chooseStatus(string $path): int
    {
        $p = strtolower($path);
        foreach (['admin', 'manage', 'console', 'secure', 'private', 'internal', 'dashboard', 'actuator'] as $auth) {
            if (strpos($p, $auth) !== false) {
                return 401;
            }
        }

        return 200;
    }

    private function logServed(RequestContext $context, string $clientIp, SynthesizedResponse $response): void
    {
        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => $context->method,
            'path' => substr($context->path, 0, 200),
            'event' => 'llm-fake',
            'matched' => true,
            'severity' => 'info',
            'served' => true,
            'templates' => ['llm-fake'],
            // The exact HTML the attacker received, so the operator can review what the model wrote.
            // The store escapes non-printable bytes; the dashboard must render this as text, not HTML.
            'body' => $response->body,
        ]);
    }
}
