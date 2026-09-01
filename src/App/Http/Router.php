<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Funnypot\App\AiApi\AiApiRouter;
use Funnypot\App\Config\AppConfig;
use Funnypot\App\Docker\DockerApiRouter;
use Funnypot\Core\RequestContext;

/**
 * Front-controller routing. Two route tables selected by FUNNYPOT_MODE: public (today's behaviour,
 * honeypot forward + dashboard at /) and stealth (a fake corporate front, honeypot + dashboard on
 * hidden paths). Both tables call the same honeypot dispatch and the same store, so there is no
 * duplicated honeypot logic, only wiring.
 */
final class Router
{
    public function __construct(
        private AppConfig $config,
        private HoneypotController $honeypot,
        private DashboardController $dashboard,
        private CorporateController $corporate,
        private HomeController $home,
        private ?AiApiRouter $aiApi = null,
        private ?ConsoleRouter $console = null,
        private ?DownloadRouter $download = null,
        private ?DockerApiRouter $docker = null,
        private ?LabyrinthController $labyrinth = null,
    ) {
    }

    public function dispatch(RequestContext $ctx, string $clientIp, string $tokenVerdict): void
    {
        if ($this->config->mode === 'stealth') {
            $this->stealth($ctx, $clientIp, $tokenVerdict);

            return;
        }
        $this->public($ctx, $clientIp, $tokenVerdict);
    }

    /**
     * Stealth: a fake corporate site out front, the operator dashboard on a hidden path, and the
     * honeypot on everything else (so scanners still get their fakes). Hidden links from the
     * corporate pages lead crawlers into the spider trap.
     */
    private function stealth(RequestContext $ctx, string $clientIp, string $tokenVerdict): void
    {
        $method = $ctx->method;
        $path = $ctx->path;

        // Fake AI inference API (POST chat endpoints). Ahead of the honeypot catch-all so a real
        // OpenAI/ollama client gets a proper stream; unmatched paths fall through unchanged.
        if ($method === 'POST' && $this->aiApi !== null && $this->aiApi->matches($path)) {
            $this->aiApi->handle($ctx, $clientIp);

            return;
        }
        // Streaming web terminal (fleet console). Also ahead of the catch-all so interactive typing
        // (many POSTs) never trips the per-IP velocity/bulk-scan gate.
        if ($method === 'POST' && $this->console !== null && $this->console->matches($path)) {
            $this->console->handle($ctx, $clientIp);

            return;
        }
        // Endless backup-download bait (fleet console). GET-only seam, gate-exempt, mounted only when
        // the feature is on; otherwise these paths fall through to the honeypot like any probe.
        if ($method === 'GET' && $this->download !== null && $this->download->matches($path)) {
            $this->download->handle($ctx, $clientIp);

            return;
        }
        // Fake Docker Engine API (exposed-daemon decoy). Ahead of the honeypot catch-all so a Docker
        // client's probes get a coherent daemon; unmatched paths fall through unchanged. Owns both GET
        // (recon) and POST (container create/start) on the Docker path shape, so no method guard here.
        if ($this->docker !== null && $this->docker->matches($path)) {
            $this->docker->handle($ctx, $clientIp);

            return;
        }
        // LLM-only labyrinth (FP-0245b). GET-only, gate-exempt (so the per-IP velocity gate never
        // 404-pins a descending LLM), mounted only when the tarpit master switch is on; otherwise these
        // paths fall through to the honeypot like any probe. Every hit is guarded by TarpitBudget first.
        if ($method === 'GET' && $this->labyrinth !== null && $this->labyrinth->matches($path)) {
            $this->labyrinth->handle($ctx, $clientIp);

            return;
        }
        $dash = rtrim($this->config->dashboardPath, '/');   // e.g. /__fp
        $p = rtrim($path, '/');
        if ($p === '') {
            $p = '/';
        }

        // Operator dashboard on the hidden path (feed / admin / shell).
        if ($p === $dash) {
            // Login-form knock (FP-0242b): a GET ?admin=login renders the login form even when
            // dashboard.public_view=none 404s the bare dashboard GET, so the operator always has a way
            // in. Bound INSIDE this dashboard-path guard — never on the decoy surface.
            if ($method === 'GET' && ($_GET['admin'] ?? '') === 'login') {
                $this->dashboard->loginForm($this->config->dashboardPath);

                return;
            }
            if ($method === 'POST' && isset($_GET['admin'])) {
                $this->dashboard->admin((string) $_GET['admin']);

                return;
            }
            if ($method === 'GET' && isset($_GET['feed'])) {
                $this->dashboard->feed();

                return;
            }
            if ($method === 'GET' && isset($_GET['recording'])) {
                $this->dashboard->recording((string) $_GET['recording']);

                return;
            }
            if ($method === 'GET') {
                $this->dashboard->shell($this->config->dashboardPath);

                return;
            }
        }

        if ($method === 'GET' && $path === '/robots.txt') {
            $this->honeypot->robots();

            return;
        }
        if ($path === '/favicon.ico' && $this->honeypot->faviconSameOrigin()) {
            return;
        }

        // Corporate disguise.
        if ($method === 'GET' && $p === '/') {
            $this->corporate->homepage();

            return;
        }
        if ($p === '/login') {
            $this->corporate->login($method, $clientIp);

            return;
        }

        // A crawler that followed a hidden link lands in the trap.
        if ($this->corporate->isTrapPath($path)) {
            $this->corporate->trap($ctx, $clientIp, $method);

            return;
        }

        // Everything else is honeypot surface (scanner probes, /honeypot, /.git, LFI, ...).
        $this->honeypot->handle($ctx, $clientIp, $tokenVerdict);
    }

    private function public(RequestContext $ctx, string $clientIp, string $tokenVerdict): void
    {
        $method = $ctx->method;
        $path = $ctx->path;

        // Fake AI inference API (POST chat endpoints). Ahead of the honeypot catch-all so a real
        // OpenAI/ollama client gets a proper stream; unmatched paths fall through unchanged.
        if ($method === 'POST' && $this->aiApi !== null && $this->aiApi->matches($path)) {
            $this->aiApi->handle($ctx, $clientIp);

            return;
        }
        // Streaming web terminal (fleet console). Also ahead of the catch-all so interactive typing
        // (many POSTs) never trips the per-IP velocity/bulk-scan gate.
        if ($method === 'POST' && $this->console !== null && $this->console->matches($path)) {
            $this->console->handle($ctx, $clientIp);

            return;
        }
        // Endless backup-download bait (fleet console). GET-only seam, gate-exempt, mounted only when
        // the feature is on; otherwise these paths fall through to the honeypot like any probe.
        if ($method === 'GET' && $this->download !== null && $this->download->matches($path)) {
            $this->download->handle($ctx, $clientIp);

            return;
        }
        // Fake Docker Engine API (exposed-daemon decoy). Ahead of the honeypot catch-all so a Docker
        // client's probes get a coherent daemon; unmatched paths fall through unchanged. Owns both GET
        // (recon) and POST (container create/start) on the Docker path shape, so no method guard here.
        if ($this->docker !== null && $this->docker->matches($path)) {
            $this->docker->handle($ctx, $clientIp);

            return;
        }
        // LLM-only labyrinth (FP-0245b). GET-only, gate-exempt (so the per-IP velocity gate never
        // 404-pins a descending LLM), mounted only when the tarpit master switch is on; otherwise these
        // paths fall through to the honeypot like any probe. Every hit is guarded by TarpitBudget first.
        if ($method === 'GET' && $this->labyrinth !== null && $this->labyrinth->matches($path)) {
            $this->labyrinth->handle($ctx, $clientIp);

            return;
        }

        // Bait robots.txt.
        if ($method === 'GET' && $path === '/robots.txt') {
            $this->honeypot->robots();

            return;
        }

        // Our own dashboard's favicon request (same-origin) is dropped; a scanner probing favicon
        // directly falls through to be served + logged like any other path.
        if ($path === '/favicon.ico' && $this->honeypot->faviconSameOrigin()) {
            return;
        }

        // The funnypot dashboard lives at its own configurable path (default /funnypot), not /, so the
        // public front door never announces a honeypot. Its live feed + password-gated admin ride the
        // same path; the shell's JS reads window.FP_BASE for them. FUNNYPOT_HIDE_MAIN hides it entirely,
        // so the path then falls through to the honeypot like any probe.
        $fp = rtrim($this->config->funnypotPath, '/');
        if (!$this->config->hideMainPage && $fp !== '' && rtrim($path, '/') === $fp) {
            // Login-form knock (FP-0242b) — see the stealth branch. Bound inside this dashboard-path
            // guard, so a ?admin=login on any other path never reaches loginForm/admin.
            if ($method === 'GET' && ($_GET['admin'] ?? '') === 'login') {
                $this->dashboard->loginForm($this->config->funnypotPath);

                return;
            }
            if ($method === 'POST' && isset($_GET['admin'])) {
                $this->dashboard->admin((string) $_GET['admin']);

                return;
            }
            if ($method === 'GET' && isset($_GET['feed'])) {
                $this->dashboard->feed();

                return;
            }
            if ($method === 'GET' && isset($_GET['recording'])) {
                $this->dashboard->recording((string) $_GET['recording']);

                return;
            }
            if ($method === 'GET') {
                $this->dashboard->shell($this->config->funnypotPath);

                return;
            }
        }

        // Direct recording URL e.g. /funnypot/recording?id=...
        if (($method === 'GET' || $method === 'HEAD') && (rtrim($path, '/') === $fp . '/recording' || $path === '/funnypot/recording')) {
            $recId = (string) ($_GET['id'] ?? ($_GET['recording'] ?? ''));
            if ($recId !== '') {
                $this->dashboard->recording($recId);

                return;
            }
        }

        // The generic decoy home at / — a plausible sign-in page hiding three bot-only lures that point
        // at the /admin/root/* decoys below. A credential POST is captured; a scanner never gets the
        // dashboard back here.
        if ($path === '/' && !isset($_GET['admin'])) {
            if ($method === 'GET' && $_GET === []) {
                $this->home->index();

                return;
            }
            if ($method === 'POST') {
                $this->home->login($clientIp);

                return;
            }
        }

        // The home page's lures (a URL in an HTML comment, an invisible link, a hidden form) route to the
        // honeypot's detect+log+report seam, so a crawler that follows any of them is scored like a probe.
        if (in_array($path, ['/admin/root/html', '/admin/root/post', '/admin/root/link'], true)) {
            $this->honeypot->handle($ctx, $clientIp, $tokenVerdict);

            return;
        }

        // Everything else is honeypot surface.
        $this->honeypot->handle($ctx, $clientIp, $tokenVerdict);
    }
}
