<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\Blocklist;
use Geo;

/**
 * The public front door (/) in public mode: a plausible, GENERIC sign-in page a human sees, with no
 * funnypot branding — the operator dashboard lives at its own configurable path ({@see AppConfig::$funnypotPath}).
 *
 * Hidden in the markup are three bot-only lures, each pointing at an /admin/root/* path the router
 * forwards to the honeypot's detect+log+report seam, so a crawler that takes the bait is flagged like
 * any probe:
 *   1. a leaked URL in an HTML comment  -> /admin/root/html
 *   2. an invisible off-screen link     -> /admin/root/link
 *   3. a hidden auto-submittable form    -> /admin/root/post
 * A credential POST on the visible form is captured (record-only), like the corporate login.
 */
final class HomeController
{
    public function __construct(
        private HitStore $store,
        private Geo $geo,
        private AppConfig $config,
        private string $assetsDir,
        private ?Blocklist $blocklist = null,
    ) {
    }

    public function index(): void
    {
        header('Content-Type: text/html; charset=utf-8');
        echo $this->page('Sign in', $this->loginForm(''));
    }

    /** POST /: capture the credential attempt (record-only) and re-render with a generic error. */
    public function login(string $clientIp): void
    {
        header('Content-Type: text/html; charset=utf-8');
        $user = substr((string) ($_POST['username'] ?? $_POST['email'] ?? ''), 0, 120);
        $pass = substr((string) ($_POST['password'] ?? ''), 0, 120);
        $this->log($clientIp, 'POST', '/', 'login', 'high', 'home-login', 'user=' . $user . ' pass=' . $pass);
        echo $this->page('Sign in', $this->loginForm('<p class=err>Invalid username or password.</p>'));
    }

    // --- views ---

    private function page(string $title, string $body): string
    {
        $skin = (string) @file_get_contents($this->assetsDir . '/home.css'); // optional operator override

        return '<!doctype html><html lang=en><head><meta charset=utf-8>'
            . "<meta name=viewport content='width=device-width,initial-scale=1'>"
            . '<title>' . htmlspecialchars($title) . '</title>'
            . '<style>' . $this->baseCss() . $skin . '</style>'
            // Lure 1: a leaked internal URL in an HTML comment — scanners scrape comments for endpoints.
            . "\n<!-- TODO: retire the legacy admin console at /admin/root/html once the SSO migration completes -->\n"
            . '</head><body>'
            . '<main class=card><h1>Sign in</h1>' . $body . '</main>'
            // Lure 2: an invisible off-screen link only a DOM crawler follows; a sighted user never sees it.
            . "<a href='/admin/root/link' style='position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden' tabindex=-1 aria-hidden=true rel=nofollow>Admin console</a>"
            // Lure 3: a hidden form a form-submitting bot posts; invisible to humans.
            . "<form action='/admin/root/post' method=post style='display:none' aria-hidden=true>"
            . "<input type=hidden name=csrf value='a3f9c1e7'><input name=cmd><button type=submit>Run</button></form>"
            . '</body></html>';
    }

    private function loginForm(string $error): string
    {
        return $error
            . "<form method=post action='/'>"
            . '<label>Username<input name=username autocomplete=username></label>'
            . '<label>Password<input name=password type=password autocomplete=current-password></label>'
            . '<button type=submit>Sign in</button></form>';
    }

    private function baseCss(): string
    {
        return 'body{font-family:system-ui,-apple-system,sans-serif;background:#f4f5f7;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}'
            . '.card{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);width:320px}'
            . 'h1{font-size:1.25rem;margin:0 0 1rem;color:#111}'
            . 'label{display:block;margin:0 0 .75rem;font-size:.85rem;color:#333}'
            . 'input{display:block;width:100%;padding:.5rem;margin-top:.25rem;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}'
            . 'button{width:100%;padding:.6rem;background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer;font-size:.95rem}'
            . '.err{color:#b91c1c;font-size:.85rem;margin:0 0 .75rem}';
    }

    /** @param string $body */
    private function log(string $clientIp, string $method, string $path, string $event, string $severity, string $template, string $body): void
    {
        $this->store->append([
            'ts' => gmdate('c'),
            'ip' => $clientIp,
            'method' => $method,
            'path' => $path,
            'event' => $event,
            'matched' => true,
            'severity' => $severity,
            'served' => false,
            'templates' => [$template],
            'body' => $body !== '' ? $body : null,
            'geo' => $this->geo->lookup($clientIp),
            'known_attacker' => $this->blocklist !== null && $this->blocklist->isKnown($clientIp),
        ]);
    }
}
