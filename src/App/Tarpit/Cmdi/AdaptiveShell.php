<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Emulation\EmulationPolicy;
use Funnypot\App\Storage\CmdiShellStore;
use Funnypot\App\Tarpit\FootholdRewriter;
use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Severity;
use Funnypot\Core\SynthesizedResponse;
use Throwable;

/**
 * The interactive console behind the fake webshell. A simple command gets coherent output from the
 * foothold's facts table; anything with shell syntax gets a believable error that blames whatever
 * the attacker just changed, or now and then a useless "success". An agent that keeps fixing its
 * quoting never gets anywhere, and nothing ever executes.
 *
 * Where it answers:
 *  - Only when the tarpit and the console flag are on, the catalog has the webshell decoy enabled,
 *    and the severity ceiling admits it. Otherwise the request takes exactly the path it took before.
 *  - It only ever replaces the body of a response the engine already chose to serve. When the
 *    engine serves nothing, nothing here runs: the 404/LLM path, logging and reporting are untouched.
 *  - Rule A: on a console path (the /admin/root lure, a webshell file name, or a path this source has
 *    already used as a console) it answers whatever rule the engine matched, so a SQL-shaped command
 *    never switches the console into a MySQL error page.
 *  - Rule B: on any other path it answers when the engine's rule was the webshell, command-injection
 *    or LFI decoy, and that path then joins the source's console paths.
 *  - Static-asset paths are left alone: an HTML shell for `/x.js` would be a tell.
 *
 * The response's Detection is never touched, so the hit logs and reports as what the engine matched.
 * prepare() and serve() swallow every fault, so a failure here falls back to the static foothold and
 * then to the engine's own body; it can never produce a 500.
 */
final class AdaptiveShell
{
    public const OWNED_RULES = ['attack-webshell-panel', 'attack-cmdi-unix', 'attack-crs-rce'];
    public const OWNED_TAGS = ['webshell', 'command-injection', 'lfi'];
    public const CONSOLE_PATHS = ['/admin/root/html', '/admin/root/post', '/admin/root/link'];
    private const SHELL_FILE = '~/(?:c99|wso|r57|b374k|shell|cmd|alfa|indoxploit)\.php$~i';
    private const MAX_BODY = 16384;
    private const MAX_PRE = 12288;
    private const MAX_SLEEP_S = 300;
    /** Headers the engine puts on every response; the only ones a console page keeps. */
    private const KEPT_HEADERS = ['X-Powered-By', 'X-Request-Id'];

    /** @var callable():int|null */
    private $clock;

    public function __construct(
        private AppConfig $config,
        private FootholdRewriter $page,
        private CmdiShellStore $store,
        private string $pickKey,
        private string $identityKey,
        ?callable $clock = null,
    ) {
        $this->clock = $clock;
    }

    /**
     * The three private keys this console needs, each derived with its own label from the shell's
     * existing filesystem key. The visible persona seed is never used as a key.
     *
     * @return array{0:string,1:string,2:string} pick, identity, store
     */
    public static function keysFrom(string $filesystemKey): array
    {
        $k = static fn (string $label): string => hash_hmac('sha256', 'funnypot-app/cmdi-shell/' . $label . '/v1', $filesystemKey, true);

        return [$k('pick'), $k('identity'), bin2hex($k('store'))];
    }

    /** This source's console identity. Never throws. */
    public function identityFor(string $ip): FootholdIdentity
    {
        try {
            return FootholdIdentity::resolve($this->config->tarpitCmdiIdentity, $this->identityKey, $ip);
        } catch (Throwable $e) {
            return FootholdIdentity::www();
        }
    }

    /** The identity the static foothold should show when the console stands down; null when it is not armed. */
    public function fallbackIdentity(string $ip, EmulationPolicy $policy): ?FootholdIdentity
    {
        try {
            return $this->armed($policy) ? $this->identityFor($ip) : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    /** The console runs only inside the gates the engine already applies to the webshell decoy. */
    public function armed(EmulationPolicy $policy): bool
    {
        return $this->config->tarpitEnabled
            && $this->config->tarpitCmdiSyntax
            && $policy->isEnabled('attack-webshell-panel')
            && !Severity::exceeds('critical', $this->config->severityCeiling);
    }

    public static function isConsolePath(string $path): bool
    {
        return in_array(SourceState::normalisePath($path), self::CONSOLE_PATHS, true) || preg_match(self::SHELL_FILE, $path) === 1;
    }

    public static function ownsDetection(Detection $d): bool
    {
        foreach ($d->templateIds() as $id) {
            if (in_array($id, self::OWNED_RULES, true) || str_starts_with($id, 'attack-lfi-')) {
                return true;
            }
        }

        return array_intersect(self::OWNED_TAGS, $d->tags()) !== [];
    }

    /**
     * Decide this request's turn before the engine answers, or null when the console does not apply.
     * Ownership is predicted here and confirmed in serve() against the rule the engine served.
     */
    public function prepare(RequestContext $ctx, string $ip, Detection $detection, EmulationPolicy $policy): ?ShellTurn
    {
        try {
            if (!$this->armed($policy) || StaticPath::is($ctx->path)) {
                return null;
            }
            $cmd = CmdParam::fromContext($ctx);
            if ($cmd === null) {
                return null;
            }
            $state = $this->store->load($ip);
            $inConsole = self::isConsolePath($ctx->path) || $state->isSticky($ctx->path);
            if (!$inConsole && !self::ownsDetection($detection)) {
                return null;
            }
            $identity = $this->identityFor($ip);
            // Attacker text is echoed only from the body of a non-GET request.
            $mayReflect = $cmd['source'] === 'body' && strtoupper($ctx->method) !== 'GET';

            $lex = ShellLexer::lex($cmd['value']);
            if ($lex->isEmpty()) {
                return new ShellTurn($ip, $ctx->path, $identity, $cmd['source'], $inConsole, true, false, null, '', null, false, $state);
            }
            $picked = OutcomePicker::pick($lex, $state, $this->pickKey);
            [$output, $outcome, $executes, $sleep] = $this->answer($lex, $picked, $this->page->facts($identity, $this->clock), $mayReflect);

            return new ShellTurn(
                $ip,
                $ctx->path,
                $identity,
                $cmd['source'],
                $inConsole,
                $output === null,
                $executes,
                $sleep,
                (string) $output,
                $outcome,
                $lex->simple,
                // The memo keeps what the picker chose. A sleep that forced this turn to run every
                // segment changes this answer only, so a later resend of the shape answers as before.
                $state->after($lex, $picked),
            );
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * Replace the engine's response with this turn's page when the shell owns the request. Returns
     * false, leaving the response untouched, when it does not or on any fault.
     */
    public function serve(ShellTurn $turn, SynthesizedResponse $response): bool
    {
        try {
            $rule = $turn->pathInConsole ? 'A' : (self::ownsDetection($response->satisfies) ? 'B' : null);
            if ($rule === null) {
                return false;
            }
            $this->render($turn, $response);
            $turn->served = true;
            $turn->consoleRule = $rule;
            $turn->coreRule = $response->satisfies->templateIds()[0] ?? '';

            return true;
        } catch (Throwable $e) {
            return false;
        }
    }

    /** Write the page into $core. The new body is built in full before anything on $core changes. */
    public function render(ShellTurn $turn, SynthesizedResponse $core): void
    {
        if ($turn->landingOnly) {
            $body = $this->page->landing($turn->identity);
        } else {
            $body = $this->page->page($turn->identity, self::cut($turn->output, self::MAX_PRE));
            if (strlen($body) > self::MAX_BODY) {
                $body = $this->page->page($turn->identity, self::cut($turn->output, intdiv(self::MAX_PRE, 4)));
            }
        }
        // The page's headers are built from scratch. The replaced rule's own headers (a Location, a
        // command-output header, ...) belong to a different answer and would contradict this page; only
        // the engine's every-response headers carry over, so the console looks like the rest of the site.
        $headers = ['Content-Type' => 'text/html; charset=utf-8'];
        foreach ($core->headers as $name => $value) {
            foreach (self::KEPT_HEADERS as $kept) {
                if (strcasecmp((string) $name, $kept) === 0) {
                    $headers[$kept] = $value;
                }
            }
        }

        $core->body = $body;
        $core->status = 200;
        $core->headers = $headers;
    }

    /** Record the turn once the response is out. Best effort; never throws. */
    public function commit(ShellTurn $turn, int $delayMs): void
    {
        if (!$turn->served) {
            return;
        }
        try {
            $state = $turn->consoleRule === 'B' ? $turn->stateAfter->withSticky($turn->path) : $turn->stateAfter;
            $this->store->save($turn->ip, $state, $turn->row($delayMs));
        } catch (Throwable $e) {
            // The answer is already out; losing one history write only makes the next turn stateless.
        }
    }

    /**
     * The text for the page's <pre>, or null when it would have to echo attacker text that may not
     * be reflected (the caller then serves the landing).
     *
     * @return array{0:?string,1:Outcome,2:bool,3:?int} output, final outcome, executes, sleep seconds
     */
    private function answer(LexReport $lex, Outcome $o, FootholdFacts $facts, bool $mayReflect): array
    {
        if (!$o->isAccept()) {
            // Closed-set tokens only: a parser message never needs a reflection slot.
            return [AshVocabulary::render($o->msgId, $o->token) . "\n", $o, false, null];
        }
        if ($o->sub === Outcome::FACTS) {
            return [$facts->run($lex->argv, $mayReflect), $o, true, self::sleepOf($lex->argv)];
        }

        // A compound that "ran" and slept really sleeps, so the delay and the output agree.
        $sleep = null;
        foreach ($lex->segments as $seg) {
            if ($seg !== null && ($sleep = self::sleepOf($seg)) !== null) {
                $o = $o->withSub(Outcome::ALL);
                break;
            }
        }

        switch ($o->sub) {
            case Outcome::ALL:
                $out = '';
                foreach ($lex->segments as $seg) {
                    $r = $seg === null ? '' : $facts->run($seg, $mayReflect);
                    if ($r === null) {
                        return [null, $o, true, $sleep];
                    }
                    $out .= $r;
                }

                return [$out, $o, true, $sleep];
            case Outcome::FIRST:
                $seg = $lex->segments[0] ?? null;

                return [$seg === null ? '' : $facts->run($seg, $mayReflect), $o, true, null];
            case Outcome::EMPTY:
                return ['', $o, true, null];
        }

        // A container failure: nothing ran. A failed write names this line's target, never a stored one.
        if ($o->msgId === 'readonly') {
            $target = $lex->redirectTargets[0] ?? '';
            if ($target !== '' && !$mayReflect) {
                return [null, $o, false, null];
            }
            if (preg_match(FootholdFacts::SAFE_CHARSET, $target) === 1 && $target !== '' && strlen($target) <= FootholdFacts::PATH_CAP) {
                return [AshVocabulary::render('readonly', htmlspecialchars($target, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')) . "\n", $o, false, null];
            }

            return [AshVocabulary::render('fork') . "\n", $o, false, null];
        }

        return [AshVocabulary::render($o->msgId === 'killed' ? 'killed' : 'fork') . "\n", $o, false, null];
    }

    /** The seconds a literal `sleep N` asks for, or null. @param list<string> $argv */
    private static function sleepOf(array $argv): ?int
    {
        while ($argv !== [] && preg_match('~^[A-Za-z_][A-Za-z0-9_]*=~', $argv[0]) === 1) {
            array_shift($argv);
        }
        if (($argv[0] ?? '') !== 'sleep' || preg_match('~^\d+(?:\.\d+)?$~', $argv[1] ?? '') !== 1) {
            return null;
        }

        return max(0, min(self::MAX_SLEEP_S, (int) $argv[1]));
    }

    private static function cut(string $s, int $max): string
    {
        return strlen($s) > $max ? substr($s, 0, $max) : $s;
    }
}
