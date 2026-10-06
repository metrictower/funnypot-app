<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;

/**
 * FP-0467 phase 2b/3: the semi-blind file-write / verify trap, wiring WriteRedirectExtractor +
 * WriteCaptureStore into a request-pair deception. On a request whose cmdi payload writes a sentinel to a
 * webroot file (`echo TAG > /var/www/html/out.txt`), maybeCapture() records (url-path -> content) for the
 * apparent source; a later GET to that url-path (maybeServe()) returns the stored sentinel, so the
 * scanner's own blind write-then-fetch verification "confirms" RCE.
 *
 * All logic lives here so HoneypotController only makes two guarded one-line calls, both behind the
 * dormant FUNNYPOT_WRITE_CAPTURE flag — off by default, so the handler stays byte-identical unless an
 * operator opts in on the dedicated box. INERT: only the attacker's OWN sentinel bytes, memory-bounded by
 * the store, nothing executed, never the real disk. The source scope is an opaque digest (no raw IP). The
 * serve is the designed deception and belongs only on the isolated-origin dedicated box — the caller
 * gates that (never alters a real embedded site).
 */
final class WriteCaptureTrap
{
    /** Common webroots: a captured FS path under one maps to the URL path a verify GET uses. */
    private const WEBROOTS = [
        '/var/www/html', '/var/www', '/usr/share/nginx/html', '/usr/local/apache2/htdocs',
        '/srv/www', '/srv/http', '/app/public', '/var/www/public', '/home/www',
    ];

    public function __construct(private WriteCaptureStore $store)
    {
    }

    /** Opaque per-source scope — never stores the raw IP. */
    public function scopeFor(string $clientIp): string
    {
        return hash('sha256', 'fp0467|' . $clientIp);
    }

    /**
     * Map a captured filesystem write path to the URL path a verify GET would use, or null if no verify
     * GET could ever reach it. Only a file UNDER a known webroot is HTTP-servable: a real webserver never
     * serves `/tmp/x` or `/etc/passwd`, so a write there is not captured (serving it back would be a tell —
     * the trap would 200 any absolute path the source "wrote"). A write AT the webroot dir itself (not a
     * file under it) is likewise not servable. The FS path is canonicalised FIRST so a `..` traversal
     * resolves within it, THEN the webroot prefix is stripped.
     */
    public function urlPathFor(string $fsPath): ?string
    {
        $raw = trim($fsPath);
        if ($raw === '') {
            return null;
        }
        $isAbsolute = $raw[0] === '/';
        $p = $this->canonicalise('/' . ltrim($raw, '/'));

        if (!$isAbsolute) {
            // A relative write resolves against the process cwd, which for a dropped webshell is the
            // webroot — so it maps directly to that URL path (e.g. `echo X > shell.php` → `/shell.php`).
            return ($p === '/' ) ? null : $p;
        }

        foreach (self::WEBROOTS as $root) {
            if ($p === $root) {
                return null; // a write AT the docroot dir is not a servable file
            }
            if (strncmp($p, $root . '/', strlen($root) + 1) === 0) {
                $url = substr($p, strlen($root));

                return ($url === '' || $url === '/') ? null : $url;
            }
        }

        return null; // absolute path outside every known webroot — not HTTP-reachable, never capture
    }

    /** Record a write-stager if the request carries one. No-op for a non-write (extractor returns null). */
    public function maybeCapture(RequestContext $context, string $clientIp): void
    {
        $surface = rawurldecode((string) $context->query) . ' ' . rawurldecode((string) ($context->rawBody ?? ''));
        $write = WriteRedirectExtractor::extract($surface);
        // Only literal writes carry a known sentinel to serve back; a command-output / fetch redirect
        // (kind=dynamic) has no static content, so it is not captured (deferred — a verify GET 404s).
        if ($write === null || $write['kind'] !== WriteRedirectExtractor::KIND_LITERAL || $write['content'] === null) {
            return;
        }
        $urlPath = $this->urlPathFor($write['path']);
        if ($urlPath === null) {
            return; // the write target is not HTTP-reachable (outside any webroot) — nothing to verify
        }
        $this->store->capture($this->scopeFor($clientIp), $urlPath, $write['content'], $this->contentTypeFor($urlPath));
    }

    /**
     * On a GET whose path matches a captured write for this source, return the stored sentinel as a 200;
     * else null (the caller serves its normal 404/decoy). GET/HEAD only — a verify fetch is never a POST.
     */
    public function maybeServe(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        $method = strtoupper($context->method);
        if ($method !== 'GET' && $method !== 'HEAD') {
            return null;
        }
        $hit = $this->store->verify($this->scopeFor($clientIp), $this->canonicalise('/' . ltrim($context->path, '/')));
        if ($hit === null) {
            return null;
        }

        return new SynthesizedResponse(
            200,
            ['Content-Type' => $hit['content_type']],
            $method === 'HEAD' ? '' : $hit['content'],
            Detection::none()
        );
    }

    private function canonicalise(string $path): string
    {
        $out = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($out);
                continue;
            }
            $out[] = $seg;
        }

        return '/' . implode('/', $out);
    }

    private function contentTypeFor(string $urlPath): string
    {
        $ext = strtolower((string) pathinfo($urlPath, PATHINFO_EXTENSION));

        switch ($ext) {
            case 'html':
            case 'htm':
            case 'php':
            case 'phtml':
                return 'text/html; charset=utf-8';
            case 'js':
                return 'application/javascript; charset=utf-8';
            case 'css':
                return 'text/css; charset=utf-8';
            case 'json':
                return 'application/json';
            case 'xml':
                return 'text/xml; charset=utf-8';
            default:
                return 'text/plain; charset=utf-8';
        }
    }
}
