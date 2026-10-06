<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

/**
 * FP-0375 — never leak a real stack-identifying header on the HTTP front-controller surface.
 *
 * A live prod check returned the REAL stack (`Server: nginx`, and `X-Powered-By: PHP/<real>` on any
 * path that skipped the persona override). This is the application-level BELT (the edge config is the
 * suspenders): a `header_register_callback` registered at the top of the front controller fires once
 * just before headers flush on EVERY path — including the pre-identity 414 / identity-fault 404 closures
 * and any header a surface or the vendored-core ResponseEmitter added late — and NORMALIZES:
 *
 *   1. forces `Server` to the operator/persona banner (never the real edge `nginx`/version), and
 *   2. header_remove()s the known stack-identifier family (X-AspNet-Version, X-Runtime, …).
 *
 * It does NOT allowlist: a deception app's core templates legitimately emit product-specific headers
 * (WWW-Authenticate for the panel 401 oracles, Allow, Accept-Ranges/Content-Range, X-Accel-Buffering,
 * Service-Worker-Allowed); stripping those would break shipped deception and add tells. `X-Powered-By`
 * is handled separately at the front controller (a top-of-file header_remove clears expose_php's
 * startup default; the existing persona override re-adds it on the deception surfaces; the AI-API /
 * Docker surfaces deliberately leave it absent) — so this normalizer never touches it.
 *
 * The normalize LOGIC is a pure static method driven by injected set/remove callables, so it is unit-
 * testable without the SAPI; register() wires it to the real header()/header_remove() via the callback.
 */
final class StackHeaderGuard
{
    /** Built-in Server banner when FUNNYPOT_SERVER_BANNER is unset. A plausible nginx value (coherent
     *  with the believable-404 body), NOT the real deployed version. Operators tune it per persona. */
    public const DEFAULT_SERVER = 'nginx/1.27.2';

    /**
     * Stack-identifier headers to strip on every flush. NOT X-Powered-By (handled at the front
     * controller) and NOT Server (forced, not stripped). No allowlist — only these named leak-vectors
     * are removed, so every functional/persona header a surface or core template sets survives.
     */
    public const FAMILY = [
        'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Runtime', 'X-Generator',
        'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache', 'Via', 'X-Varnish', 'X-Powered-CMS',
        'X-Backend-Server', 'X-Served-By', 'X-Cache', 'X-Cache-Hits', 'Liferay-Portal',
        'X-Turbo-Charged-By', 'X-LiteSpeed-Cache', 'X-Mod-Pagespeed', 'X-Page-Speed',
        'X-Redirect-By', 'X-Pingback', 'Server-Timing',
    ];

    private static ?string $serverBanner = null;
    private static bool $registered = false;

    /**
     * Register the flush-time normalizer. Call ONCE at the very top of the front controller (right after
     * autoload), BEFORE any surface emits — so the callback covers the fault closures too. $banner is the
     * configured Server value ('' => the built-in default). Idempotent.
     */
    public static function register(string $banner = ''): void
    {
        self::$serverBanner = $banner !== '' ? $banner : self::DEFAULT_SERVER;
        if (self::$registered || !\function_exists('header_register_callback')) {
            return;
        }
        self::$registered = true;
        @\header_register_callback(static function (): void {
            if (\headers_sent()) {
                return;
            }
            self::apply(
                static fn (string $name, string $value): mixed => \header($name . ': ' . $value),
                static fn (string $name): mixed => \header_remove($name),
                self::$serverBanner ?? self::DEFAULT_SERVER,
                self::currentServerHeader()
            );
        });
    }

    /**
     * The pure normalize step, driven by injected callables so it is unit-testable (tests pass recording
     * mocks; register() passes header()/header_remove()). It:
     *  - forces `Server` to $banner ONLY when the current value is absent or is the honeypot's OWN real
     *    stack (nginx/Apache/PHP-shaped). A core template's device banner (boa, RomPager, KM-MFP, a
     *    Microsoft-IIS persona, …) is LEFT intact — forcing one box banner there would clobber per-
     *    product `part: server` deception on the poly-stack surface; the real leak is only on the
     *    admin/404/error/fault paths that set no Server at all; and
     *  - strips the known stack-identifier family (never functional/persona headers; no allowlist).
     *
     * @param callable(string,string):mixed $setHeader
     * @param callable(string):mixed        $removeHeader
     */
    public static function apply(callable $setHeader, callable $removeHeader, string $banner, ?string $currentServer = null): void
    {
        if ($currentServer === null || self::isRealStackServer($currentServer)) {
            $setHeader('Server', $banner !== '' ? $banner : self::DEFAULT_SERVER);
        }
        foreach (self::FAMILY as $name) {
            $removeHeader($name);
        }
    }

    /** Is $server the honeypot's OWN real stack (so it must be replaced), vs a deliberate device/persona
     *  banner (left intact)? The real leak is the edge nginx or the php-fpm/Apache SAPI. */
    public static function isRealStackServer(string $server): bool
    {
        return (bool) \preg_match('~^(?:nginx|apache|php)(?:[/ ]|$)~i', trim($server));
    }

    /** The Server value PHP currently has queued for this response, or null if none. */
    private static function currentServerHeader(): ?string
    {
        foreach (\headers_list() as $line) {
            if (\stripos($line, 'Server:') === 0) {
                return trim(substr($line, 7));
            }
        }

        return null;
    }

    /** Reset the one-time registration guard + banner (tests only). */
    public static function resetForTests(): void
    {
        self::$registered = false;
        self::$serverBanner = null;
    }
}
