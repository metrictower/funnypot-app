<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use Funnypot\RequestContext;

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
    /** class => [regex, ...]; first class with any match wins. Ordered most-severe first. */
    private const PATTERNS = [
        'rce' => [
            '~;\s*(?:id|whoami|uname|cat|ls|pwd|nc|bash|sh)\b~',
            '~\|\s*(?:id|whoami|nc|bash|sh|curl|wget)\b~',
            '~&&\s*(?:id|whoami|cat|curl|wget)\b~',
            '~\$\(\s*[a-z]~',
            '~\b(?:wget|curl)\s+https?://~',
        ],
        'sqli' => [
            '~\bunion\b[\s/*]+\bselect\b~',
            '~\bor\b\s+1\s*=\s*1\b~',
            "~'\s*or\s*'1'\s*=\s*'1~",
            '~\bsleep\s*\(\s*\d~',
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

    private const SEVERITY = ['rce' => 'critical', 'sqli' => 'high', 'lfi' => 'high', 'xss' => 'medium'];

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
