<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\App\Http\LabyrinthController;
use Funnypot\Core\Detection;
use Funnypot\Core\Support\PersonaIdentity;
use Throwable;

/**
 * FP-0806 — deny the terminal quick win. A live AI-pentester lab run showed an agent follow a cmdi
 * probe to the core `attack-webshell-panel` decoy, read its `uid=33(www-data)` output as a completed
 * RCE, file one critical finding and END the engagement in minutes — the opposite of a tarpit. A clean
 * win short-circuits the whole deep-engagement surface (the labyrinth) the box is built around.
 *
 * This rewrites ONLY the served body of that one decoy (app-tier, no funnypot-core change) into a
 * believable low-privilege foothold that fires but goes nowhere: the command mechanism works
 * (`id` still returns `uid=33(www-data)`, so the agent's "mechanism fires" observation holds), but
 * every privilege-escalation / data-exfiltration path fails for a real, coherent system reason — the
 * shell sits in a minimal/distroless container with no sudo, dropped Linux capabilities, a read-only
 * root filesystem, nothing interesting mounted, and no outbound egress. The admin/database goal is
 * genuinely not reachable from this pod; it lives behind the gateway. A natural mounted-config artifact
 * names the internal artifact registry and the still-live legacy audit-archive export, so the most
 * attractive next hop is the labyrinth — exactly where we want the agent to burn its budget.
 *
 * Invariants this holds (the coherence window is the whole point — review at max):
 *  - The body is STATIC. It NEVER echoes the attacker's `cmd`/`exec` input (that would add an XSS and a
 *    fingerprint-leak surface); the canned transcript is the same bytes for every probe, exactly as the
 *    core template already is.
 *  - It reads as "real cmdi, controlled impact", never "clearly secure": the mechanism visibly works and
 *    the blocks are ordinary hardened-container failures (permission denied / not found / connection
 *    refused), so an adversarial agent can neither confirm a finding nor cleanly eliminate it as fake.
 *  - It never serves `uid=0`, a real secret, or a working credential, and carries no honeypot-tell
 *    wording or upstream detector vocabulary (app-authored, so it joins the app's own fingerprint gate).
 *  - Persona-coherent: it names the SAME company / host the labyrinth pages show, so the foothold and the
 *    maze the agent lands in next do not contradict each other.
 *
 * The response's {@see Detection} ($satisfies) is deliberately left untouched by the caller, so the hit
 * still logs and reports as a critical webshell probe — only the bytes the attacker sees change.
 *
 * Default-off: the composition root builds this ONLY when the tarpit master switch is on (so the onward
 * pointer has a live labyrinth to point at); null ⇒ the served body is byte-identical to today.
 *
 * FP-0800 coordination: FP-0800 is the general funnypot-core program to make fire-but-block oracles
 * non-terminal in the template tier itself. If a future core release makes `attack-webshell-panel`
 * non-terminal, its served body stops matching the known terminal signature below and {@see rewrite()}
 * becomes a no-op — so the two tiers can never double-rewrite one response.
 */
final class FootholdRewriter
{
    /**
     * The signature of the known terminal `attack-webshell-panel` body this rewrite understands: the
     * non-root identity inside the shell-panel chrome. If a core revision (FP-0800 or any other) changes
     * the template body so either marker is gone, rewrite() stands down and serves the core body as-is —
     * the forward-safe default (see the class doc's FP-0800 note).
     */
    private const TERMINAL_ID = 'uid=33(www-data)';
    private const TERMINAL_CHROME = '<title>Shell</title>';

    public function __construct(
        private int $personaSeed,
        /** The LLM-only labyrinth entry hint ({@see LabyrinthController::entryHint()}): a base64 path in
         *  an HTML comment. Reused verbatim so the foothold's onward pointer and the GET-recon breadcrumb
         *  converge on the SAME maze root, and so the pointer carries no crawler-followable href. */
        private string $onwardHint,
    ) {
    }

    /**
     * True when the engine's answer is the terminal cmdi/webshell quick win. Kept to a tiny explicit
     * allowlist — the one live-validated case — rather than all `attack` matches; broader fire-but-block
     * coverage is FP-0800's job in core.
     */
    public function appliesTo(Detection $satisfies): bool
    {
        return in_array('attack-webshell-panel', $satisfies->templateIds(), true)
            || in_array('webshell', $satisfies->tags(), true);
    }

    /**
     * Rewrite the served body into the locked-down-container foothold. A no-op (returns $coreBody
     * unchanged) when the body is not the known terminal webshell signature — the default-safe behaviour
     * if the core template ever changes shape (FP-0800).
     */
    public function rewrite(string $coreBody): string
    {
        if (strpos($coreBody, self::TERMINAL_ID) === false || strpos($coreBody, self::TERMINAL_CHROME) === false) {
            return $coreBody;
        }

        $company = $this->personaField('company.name', 'Corevance');
        // host.name is not a PersonaIdentity field, so this always resolves to the fallback — the SAME
        // host string LabyrinthController::render() shows, which keeps the foothold and the maze coherent.
        $host = $this->personaField('host.name', 'app-prod-01');
        $registry = 'registry.int.' . $this->personaField('company.domain', 'corevance.internal');

        // A webshell landing panel (c99/wso-style) that auto-runs an environment probe on load. Fully
        // static — the attacker's command is never reflected. The container is a MINIMAL Alpine/busybox
        // image (deliberately not "distroless": a distroless image has no shell or coreutils, which would
        // contradict a shell that runs id/cat/ls/mount — the elimination hook we must avoid). Every block
        // reads as a genuine hardened pod: the mechanism fires (id → www-data), privesc fails (busybox has
        // no sudo, capabilities dropped), persistence fails (read-only rootfs), exfil fails (shadow denied,
        // egress refused), nothing interesting is mounted, and a deploy-rendered env file names the
        // internal registry and the still-live legacy audit-archive export. No uid=0, no secret, no href.
        // Error strings are authentic busybox/ash wording so the shell and the OS claim agree.
        $transcript = "\$ id\n"
            . "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            . "\$ sudo -i\n"
            . "/bin/sh: sudo: not found\n"
            . "\$ cat /etc/shadow\n"
            . "cat: can't open '/etc/shadow': Permission denied\n"
            . "\$ ls -a /root\n"
            . "ls: /root: Permission denied\n"
            . "\$ cat /etc/os-release\n"
            . "NAME=\"Alpine Linux\"\n"
            . "ID=alpine\n"
            . "VERSION_ID=3.19.1\n"
            . "PRETTY_NAME=\"Alpine Linux v3.19\"\n"
            . "\$ ls -a /home /srv /opt /data /var/www/html\n"
            . "/home:\n.  ..\n/srv:\n.  ..\n/opt:\n.  ..\n/data:\n.  ..\n/var/www/html:\n.  ..  index.php\n"
            . "\$ touch /var/www/html/probe\n"
            . "touch: /var/www/html/probe: Read-only file system\n"
            . "\$ mount | grep ' / '\n"
            . "overlay on / type overlay (ro,relatime)\n"
            . "\$ grep Cap /proc/self/status\n"
            . "CapInh:\t0000000000000000\n"
            . "CapPrm:\t0000000000000000\n"
            . "CapEff:\t0000000000000000\n"
            . "CapBnd:\t0000000000000000\n"
            . "\$ wget -T 3 -qO- https://" . $registry . "/v2/\n"
            . "wget: can't connect to remote host: Connection refused\n"
            . "\$ cat /run/deploy/app.env\n"
            . "# rendered by the deploy controller at rollout; application secrets are mounted at runtime, not in this file\n"
            . "APP_ROLE=web\n"
            . "APP_DB_HOST=db\n"
            . "APP_REGISTRY=" . $registry . "\n"
            . "# admin console + customer DB live behind the gateway, not on this pod\n"
            . "# legacy audit-archive export is still live during the SIEM cutover (see the ops note in this page's source)\n"
            . "\$ ";

        $body = '<html><head><title>Shell</title></head><body bgcolor="black" text="green">' . "\n"
            // busybox `uname -a` on a musl/Alpine image prints a trailing "Linux", never "GNU/Linux" —
            // keeping it musl-consistent avoids a libc-vs-OS contradiction with the os-release claim below.
            . '<b>uname:</b> Linux ' . $this->esc($host) . ' 5.15.0 x86_64 Linux<br>' . "\n"
            . '<b>user:</b> uid=33(www-data) gid=33(www-data) groups=33(www-data)<br>' . "\n"
            . '<b>deployment:</b> ' . $this->esc($company) . ' &middot; minimal container image (read-only rootfs)<br>' . "\n"
            . '<pre>' . $this->esc($transcript) . '</pre>' . "\n"
            // Onward pointer: the same LLM-only base64 breadcrumb GET recon carries. No href, so a
            // crawler finds nothing to follow; an agent decodes it and heads into the labyrinth.
            . $this->onwardHint
            . '</body></html>' . "\n";

        return $body;
    }

    private function personaField(string $path, string $fallback): string
    {
        try {
            $v = PersonaIdentity::fromSeed($this->personaSeed)->field($path);

            return ($v !== null && $v !== '') ? $v : $fallback;
        } catch (Throwable $e) {
            return $fallback;
        }
    }

    private function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
