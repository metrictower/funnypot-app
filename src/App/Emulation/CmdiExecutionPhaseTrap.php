<?php

declare(strict_types=1);

namespace Funnypot\App\Emulation;

use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Detection;

/**
 * FP-0531 piece 3: the stateful command-injection EXECUTION-PHASE oracle. After funnypot-core's stateless
 * arithmetic oracle confirms a Commix/Artemis probe (`<LEFT>$((a op b))<RIGHT>` -> the sum), the scanner
 * sends execution follow-ups wrapping a real recon command in the SAME tags (`<LEFT>`whoami`<RIGHT>`),
 * expecting the command output bracketed in those tags. This trap:
 *   - maybeBind(): on a confirm probe, binds the source's {left,right} tags (CmdiSessionStore).
 *   - maybeExecute(): on a follow-up whose tags are BOUND to this source, returns a persona-coherent canned
 *     recon output BRACKETED in the same tags, so the scanner "extracts" it and the engagement deepens.
 *
 * The source+tag binding (not matching bare tag-wrapped commands statelessly) is the precision gate that
 * keeps this low-FP. INERT: no command is run, only canned recon bytes bracketed in the attacker's own
 * tags; output is seeded (per-deploy consistent), the recon set is a fixed web-context identity (whoami ->
 * www-data, not root — a web cmdi runs as the web user). Gated to the dedicated/isolated-origin box by the
 * caller; any fault degrades to null -> the caller's normal 404 (only-upgrade invariant).
 */
final class CmdiExecutionPhaseTrap
{
    public function __construct(private CmdiSessionStore $store, private int $seed = 0)
    {
    }

    /** Opaque per-source scope — never the raw IP. */
    public function scopeFor(string $clientIp): string
    {
        return hash('sha256', 'fp0531|' . $clientIp);
    }

    /** On a Commix arithmetic confirm, bind this source's tag pair. No-op otherwise. */
    public function maybeBind(RequestContext $context, string $clientIp): void
    {
        $surface = $this->surface($context);
        $confirm = CommixTagProbe::parseConfirm($surface);
        if ($confirm !== null) {
            $this->store->bind($this->scopeFor($clientIp), $confirm['left'], $confirm['right']);
        }
    }

    /**
     * On a follow-up whose {left,right} tags are bound to this source and whose command is a recognised
     * recon command, return the output bracketed in those tags. Null otherwise (caller serves its 404).
     */
    public function maybeExecute(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        $surface = $this->surface($context);
        $fu = CommixTagProbe::parseFollowup($surface);
        if ($fu === null) {
            return null;
        }
        if (!$this->store->isBound($this->scopeFor($clientIp), $fu['left'], $fu['right'])) {
            return null;
        }
        $out = $this->recon($fu['cmd']);
        if ($out === null) {
            return null;
        }

        return new SynthesizedResponse(
            200,
            ['Content-Type' => 'text/html; charset=utf-8'],
            $fu['left'] . $out . $fu['right'],
            Detection::none()
        );
    }

    private function surface(RequestContext $context): string
    {
        return rawurldecode((string) $context->query) . ' ' . rawurldecode((string) ($context->rawBody ?? ''));
    }

    /** Map a recon command to seeded, inert, web-context output. Null = not a recon command we answer. */
    private function recon(string $cmd): ?string
    {
        $c = strtolower(trim($cmd));
        // normalise "cmd args" to the leading token for dispatch, keep a couple of distinctive multi-word forms
        $head = preg_split('~\s+~', $c)[0] ?? $c;

        switch (true) {
            case $head === 'whoami':
                return "www-data\n";
            case $head === 'id':
                return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n";
            case $head === 'hostname':
                return $this->hostname() . "\n";
            case $head === 'pwd':
                return "/var/www/html\n";
            case $head === 'uname':
                return 'Linux ' . $this->hostname() . ' ' . $this->pick(['5.15.0-91-generic', '5.4.0-169-generic', '6.1.0-17-amd64'], 'kernel')
                    . ' #' . (1 + $this->idx('build', 200)) . "-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux\n";
            case $head === 'ls' || $head === 'dir':
                return "index.php  wp-config.php  wp-content  wp-includes  .htaccess  uploads\n";
            case $head === 'cat' && strpos($c, '/etc/passwd') !== false:
                return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n";
            default:
                return null;
        }
    }

    private function hostname(): string
    {
        $role = $this->pick(['web', 'app', 'api', 'srv'], 'host|role');
        $env = $this->pick(['prod', 'stg', 'ops'], 'host|env');

        return $role . '-' . $env . '-' . sprintf('%02d', 1 + $this->idx('host|nn', 42));
    }

    /** @param string[] $opts */
    private function pick(array $opts, string $field): string
    {
        return $opts[$this->idx($field, count($opts))];
    }

    private function idx(string $field, int $mod): int
    {
        return (int) (hexdec(substr(hash('sha256', $this->seed . '|' . $field), 0, 8)) % max(1, $mod));
    }
}
