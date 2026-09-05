<?php

declare(strict_types=1);

namespace Funnypot\App\Http;

use Closure;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Shell\ConsoleSessionStore;
use Funnypot\App\Storage\HitStore;
use Funnypot\Core\RequestContext;
use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Host\HostFacts;
use Funnypot\Shell\ShellInterpreter;
use Funnypot\Shell\ShellSession;

/**
 * Front-controller seam for the streaming web terminal (the fleet console's live shell). A Router-level
 * POST route, sibling of AiApiRouter and ahead of the honeypot catch-all — so interactive typing (many
 * POSTs) never trips the per-IP velocity/bulk-scan gate. Each POST carries {host, command}; the endpoint
 * runs the command through the SAME ShellInterpreter/FakeFilesystem the SSH/telnet shell uses (seeded per
 * fleet host), logs it as intel (event=shell), and streams the output via StreamEmitter.
 *
 * Safety: the full output is resolved (bounded, in try/catch) BEFORE the first byte is flushed, so a
 * fault can never become a half-stream or a 500. Session state (overlay/cwd/history) lives server-side
 * keyed by an HMAC'd session cookie — the browser holds no filesystem state. Nothing executes.
 *
 * Two distinct keys: the filesystem key is the SAME one the SSH/telnet shell uses (so a host's web
 * console equals its shell); the session-MAC key only authenticates the cookie. A cookie forged under
 * the filesystem key — or a filesystem oracle keyed on the cookie key — is therefore impossible.
 */
final class ConsoleRouter
{
    public const PATH = '/__console/exec';
    // Match the SSH/telnet shell's output cap (FakeShell::MAX_OUTPUT) so the same command truncates
    // identically on both tiers — a divergent cap would let a scanner tell the web console apart.
    private const MAX_OUTPUT = 8192;

    private Closure $emitterFactory;

    public function __construct(
        private ConsoleSessionStore $store,
        private HitStore $hits,
        private int $personaSeed,
        private string $filesystemKey,
        private string $sessionMacKey,
        ?Closure $emitterFactory = null
    ) {
        // No artificial per-chunk pacing: a local web terminal has no token-by-token delay, and a delay
        // here would pin an fpm worker sleeping for the whole (gate-exempt) response.
        $this->emitterFactory = $emitterFactory ?? static fn (): StreamEmitter => new StreamEmitter(null, 0);
    }

    public function matches(string $path): bool
    {
        return $path === self::PATH;
    }

    public function handle(RequestContext $ctx, string $clientIp): void
    {
        $body = json_decode((string) ($ctx->rawBody ?? ''), true);
        // Coerce only real strings — a non-string host/command (e.g. a JSON array) must never hit a
        // string cast, which would leak an "Array to string conversion" warning into the stream.
        $host = '';
        $command = '';
        if (is_array($body)) {
            $host = is_string($body['host'] ?? null) ? substr($body['host'], 0, 64) : '';
            $command = is_string($body['command'] ?? null) ? $body['command'] : '';
        }
        [$sid, $setCookie] = $this->resolveSid($ctx);

        // Resolve the FULL output before any byte is flushed — a fault here degrades to empty, never 500.
        $out = '';
        try {
            $out = $this->runCommand($sid, $host, $command, $clientIp, $ctx->method);
        } catch (\Throwable $e) {
            $out = '';
        }

        $emitter = ($this->emitterFactory)();
        $headers = ['Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store'];
        if ($setCookie !== null) {
            $headers['Set-Cookie'] = $setCookie;
        }
        $emitter->begin(200, $headers);
        if ($out === '') {
            return;
        }
        foreach (str_split($out, 512) as $chunk) {
            $emitter->chunk($chunk);
        }
    }

    private function runCommand(string $sid, string $host, string $command, string $ip, string $method): string
    {
        $detail = Fleet::fromSeed($this->personaSeed)->detail($host);
        if ($detail === null) {
            return 'ssh: Could not resolve hostname ' . $host . ": Name or service not known\n";
        }
        $seed = (int) $detail['summary']['seed'];
        $hostname = (string) $detail['summary']['host'];
        $status = (string) ($detail['summary']['status'] ?? 'running');

        // Log the attempt as threat intel (event=shell) even against a dead host — someone poking a
        // stopped/offline box's console is still signal.
        if (trim($command) !== '') {
            $this->hits->append([
                'ts' => gmdate('c'),
                'ip' => $ip,
                'method' => $method,
                'path' => '/console/' . strtolower($hostname),
                'matched' => true,
                'served' => true,
                'severity' => 'info',
                'event' => 'shell',
                'body' => substr($command, 0, 2000),
            ]);
        }

        // A host the fleet reports as down must not answer a fully live shell — that mismatch is a tell.
        if ($status === 'offline') {
            return 'ssh: connect to host ' . $hostname . " port 22: No route to host\n";
        }
        if ($status === 'stopped') {
            return 'ssh: connect to host ' . $hostname . " port 22: Connection refused\n";
        }

        $facts = new HostFacts($seed);
        $interp = new ShellInterpreter(
            new FakeFilesystem(Draw::seed($this->filesystemKey . "\0" . $seed . "\0ops"), 'ops', $seed),
            $facts,
            self::MAX_OUTPUT
        );

        $key = hash('sha256', $sid . '|' . $seed);
        $st = $this->store->load($key);
        $ss = new ShellSession(
            $facts->hostname(),
            'root',
            0,
            0,
            $st === null ? '/root' : $st['cwd'],
            $ip !== '' ? $ip : '10.0.0.1'
        );
        if ($st !== null) {
            $ss->overlay = $st['overlay'];
            $ss->env = $st['env'];
            $ss->history = $st['history'];
            $ss->lastExit = $st['lastExit'];
        }

        $out = $interp->run($command, $ss);
        // On exit/logout, end the session for real: drop the stored row (next keystroke = fresh login)
        // and print the closing line WITHOUT a trailing prompt — the client keys off the missing prompt
        // to disable its input.
        if ($ss->close) {
            $this->store->delete($key);

            return $out . 'logout' . "\n" . 'Connection to ' . $facts->hostname() . " closed.\n";
        }

        // Emit the NEXT prompt after the output (like a real shell), so it tracks cwd across cd — the
        // client never fabricates a prompt.
        $cwd = $ss->cwd === '/root' ? '~' : $ss->cwd;
        $out .= 'root@' . $facts->hostname() . ':' . $cwd . '# ';

        $this->store->save($key, [
            'host' => $facts->hostname(),
            'cwd' => $ss->cwd,
            'overlay' => $ss->overlay,
            'env' => $ss->env,
            'history' => $ss->history,
            'lastExit' => $ss->lastExit,
        ]);

        return $out;
    }

    /**
     * Resolve the browser session id from the HMAC'd cookie, minting a new one (with a Set-Cookie) if
     * absent/invalid. A plain session cookie is what every real web app has — zero fingerprint — and the
     * HMAC means the server only trusts a session id it issued.
     *
     * @return array{0:string,1:?string} [sid, setCookieHeaderOrNull]
     */
    private function resolveSid(RequestContext $ctx): array
    {
        $cookie = '';
        foreach ($ctx->headers as $k => $v) {
            if (strcasecmp((string) $k, 'cookie') === 0) {
                $cookie = (string) $v;
                break;
            }
        }
        if (preg_match('/(?:^|;\s*)sid=([A-Za-z0-9]{8,64})\.([a-f0-9]{64})/', $cookie, $m)
            && hash_equals($this->hmac($m[1]), $m[2])) {
            return [$m[1], null];
        }
        $sid = bin2hex(random_bytes(16));

        return [$sid, 'sid=' . $sid . '.' . $this->hmac($sid) . '; Path=/; HttpOnly; SameSite=Lax'];
    }

    private function hmac(string $sid): string
    {
        return hash_hmac('sha256', $sid, $this->sessionMacKey);
    }
}
