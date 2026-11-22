<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Tarpit\Cmdi\FootholdFacts;
use Funnypot\App\Tarpit\Cmdi\FootholdIdentity;
use Funnypot\App\Tarpit\Cmdi\StaticPath;
use Funnypot\Core\Detection;

/**
 * Denies the terminal quick win. Core's `attack-webshell-panel` decoy answers a cmdi probe with a
 * working shell, and an AI pentester that sees it reads the engagement as won and stops. This
 * rewrites only that served body (app tier, core untouched) into a believable foothold that fires
 * but goes nowhere: the command mechanism works, while every privilege-escalation or exfiltration
 * path fails for an ordinary hardened-container reason (no sudo, no capabilities, read-only rootfs,
 * no egress). A deploy-rendered config file names the gateway and the still-live audit-archive
 * export, so the attractive next hop is the labyrinth.
 *
 * It also owns the console chrome (header, prompt, onward hint), which the interactive console in
 * {@see Cmdi\AdaptiveShell} reuses, so a landing and a command answer always look like one panel.
 *
 * Invariants (the coherence window is the point; review at max):
 *  - The landing never echoes the attacker's input. It is rendered from {@see FootholdFacts} for one
 *    identity and is the same bytes for every probe from that source.
 *  - The identity is www-data unless a caller passes another. A root landing never shows `id`,
 *    shadow or /root unprompted, so the first page never hands over credential material.
 *  - It serves no real secret and no working credential, and carries no honeypot-tell wording or
 *    upstream detector vocabulary (app-authored, so it joins the app's own fingerprint gate).
 *  - Persona-coherent: it names the same company and host the labyrinth pages show.
 *
 * The caller leaves the response's {@see Detection} untouched, so the hit still logs and reports as
 * a critical webshell probe; only the bytes the attacker sees change.
 *
 * Built only when the tarpit is on. If a future core release makes the webshell template
 * non-terminal itself, its body stops matching the known signature below and rewrite() becomes a
 * no-op, so the two tiers can never double-rewrite one response.
 */
final class FootholdRewriter
{
    /**
     * The signature of the known terminal `attack-webshell-panel` body: the non-root identity inside
     * the shell-panel chrome. If either marker is gone, rewrite() stands down and serves the core body.
     */
    private const TERMINAL_ID = 'uid=33(www-data)';
    private const TERMINAL_CHROME = '<title>Shell</title>';

    public function __construct(
        private int $personaSeed,
        /** The LLM-only labyrinth entry hint ({@see LabyrinthController::entryHint()}): a base64 path in
         *  an HTML comment. Reused verbatim so the foothold's onward pointer and the GET-recon breadcrumb
         *  converge on the SAME maze root, and so the pointer carries no crawler-followable href. */
        private string $onwardHint,
        /** The effective X-Powered-By, so `php -v` on the console names the same PHP version. */
        private string $poweredBy = '',
    ) {
    }

    /**
     * True when the engine's answer is the terminal webshell quick win on a path where an HTML panel
     * makes sense. Kept to a tiny explicit allowlist rather than all `attack` matches. A static-asset
     * path is left alone: an HTML shell for `/x.js` would itself be a tell.
     */
    public function appliesTo(Detection $satisfies, ?string $path = null): bool
    {
        if ($path !== null && StaticPath::is($path)) {
            return false;
        }

        return in_array('attack-webshell-panel', $satisfies->templateIds(), true)
            || in_array('webshell', $satisfies->tags(), true);
    }

    /**
     * Rewrite the served body into the locked-down-container foothold. A no-op (returns $coreBody
     * unchanged) when the body is not the known terminal webshell signature.
     */
    public function rewrite(string $coreBody, ?FootholdIdentity $id = null): string
    {
        if (strpos($coreBody, self::TERMINAL_ID) === false || strpos($coreBody, self::TERMINAL_CHROME) === false) {
            return $coreBody;
        }

        return $this->landing($id);
    }

    /**
     * The panel as it loads: the header plus an auto-run probe transcript. Every line comes from the
     * same {@see FootholdFacts} table a later command is answered from.
     */
    public function landing(?FootholdIdentity $id = null): string
    {
        $facts = $this->facts($id ?? FootholdIdentity::www());

        return $this->chrome($facts, $facts->landingTranscript());
    }

    /** The panel after a command: the same chrome, with that command's output and a fresh prompt. */
    public function page(FootholdIdentity $id, string $output): string
    {
        return $this->chrome($this->facts($id), $output . '$ ');
    }

    /**
     * @param callable():int|null $clock
     * @param callable():int|null $hrClock monotonic nanoseconds for the work backstop
     */
    public function facts(FootholdIdentity $id, ?callable $clock = null, ?callable $hrClock = null): FootholdFacts
    {
        return FootholdFacts::forPersona($this->personaSeed, $id, $this->poweredBy, $clock, $hrClock);
    }

    private function chrome(FootholdFacts $facts, string $pre): string
    {
        $company = FootholdFacts::personaField($this->personaSeed, 'company.name', 'Corevance');
        $id = $facts->identity();

        // A webshell landing panel (c99/wso-style). The container is a minimal Alpine/busybox image
        // (not "distroless": a distroless image has no shell, which would contradict a shell that runs
        // id/cat/ls/mount). busybox `uname -a` on musl prints a trailing "Linux", never "GNU/Linux".
        // Root shows no user line: the panel does not volunteer that it runs as root.
        return '<html><head><title>Shell</title></head><body bgcolor="black" text="green">' . "\n"
            . '<b>uname:</b> ' . $this->esc($facts->uname()) . '<br>' . "\n"
            . ($id->isRoot() ? '' : '<b>user:</b> ' . $this->esc($id->idLine()) . '<br>' . "\n")
            . '<b>deployment:</b> ' . $this->esc($company) . ' &middot; minimal container image (read-only rootfs)<br>' . "\n"
            . '<pre>' . $this->esc($pre) . '</pre>' . "\n"
            // Onward pointer: the same LLM-only base64 breadcrumb GET recon carries. No href, so a
            // crawler finds nothing to follow; an agent decodes it and heads into the labyrinth.
            . $this->onwardHint
            . '</body></html>' . "\n";
    }

    private function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
