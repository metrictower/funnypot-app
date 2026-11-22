<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

use LogicException;

/**
 * One response of the account surface, built in full before anything is sent: status, headers and
 * body, whether it serves content (for the hit row's `served` flag) and the attribution facts.
 *
 * The status, the header names and every redirect target come from closed sets, enforced here so no
 * code path can emit anything else: no 5xx, no 302, no header a response did not name, and no
 * Location outside the surface's own pages.
 */
final class MintPlan
{
    public const STATUSES = [200, 204, 303, 400, 401, 403, 404, 405, 409, 413, 422, 429];

    public const HEADER_NAMES = [
        'Content-Type', 'Cache-Control', 'Set-Cookie', 'Location', 'Retry-After', 'Allow', 'WWW-Authenticate',
        'X-Content-Type-Options', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset',
        'X-Token-Scopes', 'X-Required-Scopes', 'X-SSO', 'Deprecation',
    ];

    public const HTML = 'text/html; charset=utf-8';
    public const JSON = 'application/json; charset=utf-8';

    /** @var list<array{0:string,1:string}> */
    private array $headers = [];

    /** @var array<string,string> */
    public array $turn = [];

    private function __construct(public readonly int $status, public readonly string $body, public bool $served)
    {
        if (!in_array($status, self::STATUSES, true)) {
            throw new LogicException('status outside the closed set');
        }
    }

    public static function html(int $status, string $body, bool $served = true): self
    {
        return (new self($status, $body, $served))->with('Content-Type', self::HTML);
    }

    /** @param array<mixed>|object $data */
    public static function json(int $status, array|object $data, bool $served = true): self
    {
        $body = (string) json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

        return (new self($status, $body, $served))
            ->with('Content-Type', self::JSON)
            ->with('Cache-Control', 'no-store')
            ->with('X-Content-Type-Options', 'nosniff');
    }

    /** A 303 to one of the surface's own pages, with the tiny HTML body browsers never show. */
    public static function redirect(string $location, MintPersona $persona, bool $served = true): self
    {
        if (!self::allowedLocation($location, $persona)) {
            throw new LogicException('redirect target outside the closed set');
        }
        $esc = htmlspecialchars($location, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return (new self(303, '<!doctype html><title>See Other</title><p>See <a href="' . $esc . '">' . $esc . '</a>.</p>', $served))
            ->with('Content-Type', self::HTML)
            ->with('Location', $location);
    }

    public static function empty(int $status, string $contentType): self
    {
        return (new self($status, '', true))->with('Content-Type', $contentType);
    }

    /** The on-site pages a redirect may name. */
    public static function allowedLocation(string $location, MintPersona $persona): bool
    {
        if (in_array($location, ['/', '/settings/confirm', '/settings/tokens', '/settings/applications', '/settings/security', '/idp/' . $persona->slug . '/signin'], true)) {
            return true;
        }

        return preg_match('~\A/settings/applications/[a-f0-9]{12}\z~', $location) === 1;
    }

    public function with(string $name, string $value): self
    {
        if (!in_array($name, self::HEADER_NAMES, true) || preg_match('/[\r\n\x00]/', $value) === 1) {
            throw new LogicException('header outside the closed set');
        }
        if ($name !== 'Set-Cookie') {
            $this->headers = array_values(array_filter($this->headers, static fn (array $h): bool => $h[0] !== $name));
        }
        $this->headers[] = [$name, $value];

        return $this;
    }

    public function header(string $name): ?string
    {
        foreach ($this->headers as [$n, $v]) {
            if (strcasecmp($n, $name) === 0) {
                return $v;
            }
        }

        return null;
    }

    /** @return list<array{0:string,1:string}> */
    public function headers(): array
    {
        return $this->headers;
    }

    /** @param array<string,string> $facts */
    public function attribute(array $facts): self
    {
        $this->turn = $facts + $this->turn;

        return $this;
    }

    /** The response a HEAD of the same request gets: same status and headers, no body. */
    public function forHead(): self
    {
        $p = new self($this->status, '', $this->served);
        $p->headers = $this->headers;
        $p->turn = $this->turn;

        return $p;
    }

    public function emit(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as [$name, $value]) {
            header($name . ': ' . $value, $name !== 'Set-Cookie');
        }
        echo $this->body;
    }
}
