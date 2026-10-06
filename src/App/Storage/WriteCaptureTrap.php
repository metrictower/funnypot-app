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
     * Map a captured filesystem write path to the URL path a verify GET would use: strip a known webroot
     * prefix, collapse `..`/`.`, force a single leading slash. A path already outside any webroot (e.g.
     * `/tmp/x`) is returned canonicalised as-is (a GET to it still 404s, so it simply never verifies).
     */
    public function urlPathFor(string $fsPath): string
    {
        // Canonicalise the full FS path FIRST so a `..` traversal resolves within it, THEN strip a known
        // webroot prefix to get the URL path a verify GET uses.
        $p = $this->canonicalise('/' . ltrim(trim($fsPath), '/'));
        foreach (self::WEBROOTS as $root) {
            if ($p === $root) {
                return '/';
            }
            if (strncmp($p, $root . '/', strlen($root) + 1) === 0) {
                return substr($p, strlen($root));
            }
        }

        return $p;
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
        $path = $this->canonicalise('/' . ltrim($context->path, '/'));
        $hit = $this->store->verify($this->scopeFor($clientIp), $path);
        if ($hit === null) {
            return null;
        }

        // FP-0149: a dropped .php webshell accessed WITH a command-execution attempt gets a persona-coherent
        // PHP disabled_functions EXECUTION FAILURE (PHP runs, dangerous functions disabled) instead of the
        // literal source — it confirms the shell is present but inert, encouraging bypass attempts while
        // executing nothing and reflecting no captured byte. A bare view (no command) still returns the
        // stored source (the "PHP not parsing" miss).
        if ($method === 'GET' && self::isPhp($path) && ($fn = $this->execAttempt($context)) !== null) {
            return new SynthesizedResponse(
                200,
                ['Content-Type' => 'text/html; charset=utf-8'],
                $this->execFailure($fn, $path),
                Detection::none()
            );
        }

        return new SynthesizedResponse(
            200,
            ['Content-Type' => $hit['content_type']],
            $method === 'HEAD' ? '' : $hit['content'],
            Detection::none()
        );
    }

    private static function isPhp(string $urlPath): bool
    {
        return (bool) preg_match('~\.(?:php|phtml|php[57]|phar)$~i', $urlPath);
    }

    /**
     * Does the request try to RUN a command through the dropped shell? Returns the PHP exec function to
     * name in the disabled_functions warning (from a FIXED set — never attacker-echoed), or null for a
     * benign view. A bare webshell command param (cmd=/c=/x=…) with no named function defaults to system().
     */
    private function execAttempt(RequestContext $context): ?string
    {
        $surface = rawurldecode((string) $context->query) . ' ' . rawurldecode((string) ($context->rawBody ?? ''));
        if ($surface === ' ') {
            return null;
        }
        if (preg_match('~\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|eval|assert)\b~i', $surface, $m) === 1) {
            return strtolower($m[1]);
        }
        if (preg_match('~(?:^|[?&])(?:cmd|c|exec|command|cmdfile|0|1|x|shell|run|act|do|download)=~i', '?' . (string) $context->query) === 1) {
            return 'system';
        }

        return null;
    }

    /** The exact PHP disabled_functions warning line, with the filesystem path (not the URL). No reflection. */
    private function execFailure(string $fn, string $urlPath): string
    {
        $fsPath = '/var/www/html' . $urlPath;

        return "<br />\n<b>Warning</b>:  {$fn}() has been disabled for security reasons in <b>{$fsPath}</b> on line <b>1</b><br />\n";
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
