<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use Funnypot\Core\RequestContext;

/**
 * A last-resort attack-class classifier for requests the engine did not match — the fall-through to
 * an LLM fake or a plain 404. The nuclei corpus and the CRS/attack emulator handle everything they
 * recognise (and serve a canned response); this only fires when neither did, so an obvious attack
 * payload aimed at a path we have no template for is still labelled (for the dashboard) and reported
 * (to AbuseIPDB), rather than slipping through as an unremarkable 404.
 *
 * Deliberately HIGH-PRECISION, not high-recall: each pattern is a strong, rarely-benign tell, because
 * a false positive here mislabels a hit and — worse — reports an innocent IP. Recall is the engine's
 * job; this is the safety net for the long tail. It matches the same request surface the attack
 * emulator uses (path + query + body, raw and URL-decoded) so encoded payloads are caught.
 */
final class AttackClassifier
{
    /** AI-inference-API reconnaissance (a client probing our fake ollama/OpenAI/Anthropic chat
     *  endpoints). Labelled directly by the AI-API handler by path, not via the payload-regex
     *  classify() below — hence no PATTERNS entry. */
    public const AI_API_RECON = 'ai_api_recon';

    /** Exposed-Docker-daemon abuse (a client probing our fake Docker Engine API — /version, /info,
     *  /containers/create, …). The create/start verbs are a remote-code-execution attempt: a miner
     *  bot deploying a container on what it reads as an unauthenticated daemon. Labelled directly by
     *  the Docker responder by path, not via the payload-regex classify() below — hence no PATTERNS entry. */
    public const DOCKER_API = 'docker_api';

    /** Read-only Docker recon (a client probing /version, /info, /containers/json, an inspect/logs).
     *  Distinct from DOCKER_API so the dashboard and report priority separate a harmless fingerprint
     *  from a container-deploy attempt. Label-only, no PATTERNS entry (set by the Docker responder). */
    public const DOCKER_RECON = 'docker_recon';

    /** Container-escape intent (a create/exec carrying a host bind-mount, --privileged, --pid=host,
     *  a docker-socket mount, cap SYS_ADMIN, …): the daemon is being used to break out onto the host.
     *  Label-only, no PATTERNS entry (derived by {@see \Funnypot\App\Docker\EscapeIntent}). */
    public const DOCKER_ESCAPE = 'docker_escape';

    /** class => [regex, ...]; first class with any match wins. Ordered most-severe first. */
    private const PATTERNS = [
        'rce' => [
            '~;\s*(?:id|whoami|uname|cat|ls|pwd|nc|bash|sh)\b~',
            '~\|\s*(?:id|whoami|nc|bash|sh|curl|wget)\b~',
            '~&&\s*(?:id|whoami|cat|curl|wget)\b~',
            '~\$\(\s*[a-z]~',
            '~\b(?:wget|curl)\s+https?://~',
            // Time-based command injection (FP-0228): a shell `sleep N` (space-separated arg, unlike the
            // SQL sleep(N) below) reached through an injection context. High-precision — the metachar +
            // `\s+\d` keeps it off benign prose and off the paren form, so `;sleep(5)` stays sqli.
            '~[;|&]\s*sleep\s+\d~',
            '~\x60\s*sleep\s+\d~',
        ],
        'sqli' => [
            '~\bunion\b[\s/*]+\bselect\b~',
            '~\bor\b\s+1\s*=\s*1\b~',
            "~'\s*or\s*'1'\s*=\s*'1~",
            '~\bsleep\s*\(\s*\d~',
            // Other SQL time-based blind-injection primitives (FP-0228): Postgres pg_sleep() and Oracle
            // dbms_pipe.receive_message() — strong, rarely-benign tells the bare sleep( above misses.
            '~\bpg_sleep\s*\(~',
            '~\breceive_message\s*\(~',
            '~\bbenchmark\s*\(~',
            '~\binformation_schema\b~',
            '~\bwaitfor\s+delay\b~',
            '~;\s*drop\s+table\b~',
            '~\bselect\b.{0,80}\bfrom\b.{0,40}(?:users|sqlite_master|pg_)~',
        ],
        'lfi' => [
            '~\.\./\.\./~',
            '~\.\.\\\\\.\.\\\\~',
            '~/etc/passwd\b~',
            '~/etc/shadow\b~',
            '~\bphp://filter~',
            '~\bfile:///~',
            '~/proc/self/environ~',
        ],
        'xss' => [
            '~<script[\s>]~',
            '~\bon(?:error|load|mouseover|click|focus)\s*=~',
            '~javascript:~',
            '~<svg[^>]*\bonload~',
            '~<img[^>]+\bonerror~',
        ],
    ];

    private const SEVERITY = ['rce' => 'critical', 'sqli' => 'high', 'lfi' => 'high', 'xss' => 'medium', 'ai_api_recon' => 'medium', 'docker_api' => 'high', 'docker_recon' => 'medium', 'docker_escape' => 'critical'];

    /** The attack class present in the request, or null. */
    public function classify(RequestContext $r): ?string
    {
        $raw = $r->path . ' ' . $r->query . ' ' . (string) ($r->rawBody ?? '');
        // A second decode pass recovers double-encoded WAF-evasion payloads (%252e -> %2e -> .),
        // added only when an encoded octet survived the first pass so benign input is left as-is.
        $once = rawurldecode($raw);
        $surface = $raw . ' ' . $once;
        if (preg_match('~%[0-9A-Fa-f]{2}~', $once) === 1) {
            $surface .= ' ' . rawurldecode($once);
        }
        $surface = strtolower($surface);

        foreach (self::PATTERNS as $class => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $surface) === 1) {
                    return $class;
                }
            }
        }

        return null;
    }

    /** Severity funnypot assigns to a detected class (drives the dashboard badge + report priority). */
    public static function severityFor(string $class): string
    {
        return self::SEVERITY[$class] ?? 'medium';
    }
}
