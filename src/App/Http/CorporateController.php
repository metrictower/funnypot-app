<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Storage\HitStore;
use Funnypot\App\ThreatIntel\Blocklist;
use Funnypot\Core\RequestContext;
use Geo;

/**
 * The stealth-mode front: a believable "Globex Corporation" marketing site and employee login that
 * a human sees, with hidden bot-only links leading to a spider trap. Real traffic sees a boring
 * company site; a crawler that follows the invisible links, or a tool that POSTs the login, is
 * scored and logged. The honeypot deception itself still runs on every other path (the router sends
 * it there); this class only owns the disguise and the trap.
 *
 * The trap technique mirrors iCabbiTools' spider trap (MAD_PATHS + a hidden visibility:hidden link
 * to a random slug, GET = soft signal, POST = hard signal), rebuilt here as a self-referential
 * tarpit: each trap page dangles more fresh trap links, so a crawler keeps walking into it.
 */
final class CorporateController
{
    /** Path prefixes that only a link-following bot ever reaches. Kept clear of real app paths. */
    private const TRAP_PREFIXES = ['frontend', 'backend', 'controlpanel', 'console', 'portal'];

    public function __construct(
        private HitStore $store,
        private Geo $geo,
        private AppConfig $config,
        private string $assetsDir,
        private ?Blocklist $blocklist = null,
        /** FP-0245e: the same LLM-only labyrinth ENTRY hint HomeController carries in public mode (an
         *  HTML comment with a base64 root + a construct instruction), planted on the STEALTH
         *  credential-submission (login POST) response below ONLY when the tarpit is on — the composition
         *  root passes LabyrinthController::entryHint() then, else null. Stealth serves / and /login here,
         *  so without this the merged labyrinth is inert in a stealth deployment. It is NOT a plain href
         *  and NOT in robots/sitemap, so a crawler cannot discover the maze; a GET-only crawler never
         *  POSTs, so it never even sees this response; an LLM that submitted the login decodes it. */
        private ?string $labyrinthEntryHint = null,
    ) {
    }

    /** Does this path look like one of our hidden bot-only trap URLs? */
    public function isTrapPath(string $path): bool
    {
        return preg_match('#^/(' . implode('|', self::TRAP_PREFIXES) . ')-#', $path) === 1;
    }

    public function homepage(): void
    {
        header('Content-Type: text/html; charset=utf-8');
        echo $this->page('Globex Corporation', $this->home());
    }

    /** GET renders the login form; POST logs the credential attempt and re-renders with an error. */
    public function login(string $method, string $clientIp): void
    {
        header('Content-Type: text/html; charset=utf-8');
        $error = '';
        $hint = '';
        if ($method === 'POST') {
            $user = substr((string) ($_POST['username'] ?? $_POST['email'] ?? ''), 0, 120);
            $pass = substr((string) ($_POST['password'] ?? ''), 0, 120);
            $this->log($clientIp, 'POST', '/login', 'login', 'high', 'globex-login', 'user=' . $user . ' pass=' . $pass);
            $error = '<p class=err>Invalid username or password.</p>';
            // FP-0245e: the LLM-only labyrinth entry hint rides the credential-submission (POST) response
            // — the stealth analogue of HomeController's public login-success funnel. A crawler is GET-only
            // so never reaches this branch; the hint is an HTML comment (no href), so a regex link
            // extractor finds nothing to follow, while an LLM that "logged in" decodes the base64 root.
            $hint = $this->labyrinthEntryHint ?? '';
        }
        echo $this->page('Sign in — Globex Corporation', $this->loginForm($error)) . $hint;
    }

    /**
     * A crawler followed a hidden link. Log it high-signal, then serve a tarpit page of more trap
     * links (bounded, a time sink not a resource bomb). A POST here is a bot that filled a hidden
     * form: the hardest signal, logged critical.
     */
    public function trap(RequestContext $ctx, string $clientIp, string $method): void
    {
        $hard = $method === 'POST';
        $this->log(
            $clientIp,
            $method,
            substr($ctx->path, 0, 200),
            'trap',
            $hard ? 'critical' : 'high',
            'spider-trap',
            $hard ? substr((string) ($ctx->rawBody ?? ''), 0, 300) : ''
        );

        header('Content-Type: text/html; charset=utf-8');
        // A believable "loading" shell whose only real content is more trap links for the crawler.
        $links = '';
        for ($i = 0; $i < 120; $i++) {
            $links .= '<li><a href="' . $this->trapSlug() . '">' . self::TRAP_PREFIXES[$i % count(self::TRAP_PREFIXES)] . ' resource ' . $i . '</a></li>';
        }
        echo "<!doctype html><html><head><title>Loading…</title></head><body>"
            . "<p>Loading internal resources…</p><ul>{$links}</ul></body></html>";
    }

    // --- views ---

    private function page(string $title, string $body): string
    {
        $css = (string) @file_get_contents($this->assetsDir . '/corporate.css');
        $trap = $this->hiddenTrap();

        return "<!doctype html><html lang=en><head><meta charset=utf-8>"
            . "<meta name=viewport content='width=device-width,initial-scale=1'>"
            . '<title>' . htmlspecialchars($title) . "</title><style>{$css}</style></head><body>"
            . "<header class=nav><div class=brand>GLOBEX<span>CORP</span></div>"
            . "<nav><a href='#products'>Products</a><a href='#solutions'>Solutions</a>"
            . "<a href='#about'>About</a><a href='#careers'>Careers</a><a href='/login'>Sign in</a></nav></header>"
            . $trap
            . "<main>{$body}</main>"
            . "<footer><div>&copy; " . gmdate('Y') . " Globex Corporation. All rights reserved.</div>"
            . "<div class=fnav><a href='#privacy'>Privacy</a> · <a href='#terms'>Terms</a> · <a href='#contact'>Contact</a></div>"
            . $this->hiddenTrap()
            . "</footer></body></html>";
    }

    private function home(): string
    {
        return "<section class=hero><h1>Enterprise infrastructure, quietly reliable.</h1>"
            . "<p>Globex Corporation builds the platforms the world's operations run on. "
            . "Trusted by teams in 40 countries.</p><a class=cta href='/login'>Employee portal</a></section>"
            . "<section id=products class=cards>"
            . "<div class=card><h3>GlobexCloud</h3><p>Managed compute and storage with a 99.99% SLA.</p></div>"
            . "<div class=card><h3>Nexus ERP</h3><p>Finance, supply chain and HR in one system of record.</p></div>"
            . "<div class=card><h3>Sentinel</h3><p>Unified monitoring and incident response.</p></div>"
            . "</section>"
            . "<section id=about class=about><h2>About</h2><p>Founded in 1989, Globex Corporation "
            . "serves enterprise customers across manufacturing, logistics and finance.</p></section>";
    }

    private function loginForm(string $error): string
    {
        return "<section class=login><div class=logincard><h2>Employee portal</h2>{$error}"
            . "<form method=post action='/login'>"
            . "<label>Username<input name=username autocomplete=username></label>"
            . "<label>Password<input name=password type=password autocomplete=current-password></label>"
            . "<button type=submit>Sign in</button></form>"
            . "<p class=sub><a href='#reset'>Forgot your password?</a></p></div></section>";
    }

    /** A hidden anchor no sighted user clicks but a crawler following hrefs does. */
    private function hiddenTrap(): string
    {
        return "<a href='" . $this->trapSlug() . "' style='visibility:hidden;position:absolute;left:-9999px' aria-hidden=true tabindex=-1>Internal directory</a>";
    }

    /** A random /<prefix>-<prefix>-<n> slug matching {@see isTrapPath}. */
    private function trapSlug(): string
    {
        $a = self::TRAP_PREFIXES[random_int(0, count(self::TRAP_PREFIXES) - 1)];
        $b = self::TRAP_PREFIXES[random_int(0, count(self::TRAP_PREFIXES) - 1)];

        return '/' . $a . '-' . $b . '-' . random_int(1000, 9999);
    }

    /** @param string $severity */
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
