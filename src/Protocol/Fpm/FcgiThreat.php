<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Fpm;

/**
 * Pure classifier for a completed FastCGI request (FP-0204). Given the decoded PARAMS map and the
 * STDIN body, it decides whether the request is a direct PHP-FPM code-execution attempt
 * (CVE-2019-11043-style PHP_VALUE injection, auto_prepend_file=php://input + a STDIN webshell) or a
 * bare capability/recon probe. No I/O, no execution — it inspects structure only, so it is unit-testable.
 *
 * Clean-room: detection keys on PHP ini-directive names and wrapper structure (durable protocol facts),
 * never on scanner/matcher signature strings — a leak of those would let an attacker fingerprint the box.
 */
final class FcgiThreat
{
    public const CLASS_RCE = 'fpm_rce';
    public const CLASS_RECON = 'fpm_recon';

    /**
     * @param array<string,string> $params decoded FastCGI PARAMS
     * @return array{class: string, critical: bool, reasons: list<string>}
     */
    public static function classify(array $params, string $stdin): array
    {
        $reasons = [];

        // PHP_VALUE / PHP_ADMIN_VALUE carrying an ini override that turns the daemon into a code loader.
        $iniBlob = '';
        foreach (['PHP_VALUE', 'PHP_ADMIN_VALUE'] as $k) {
            if (isset($params[$k])) {
                $iniBlob .= "\n" . $params[$k];
            }
        }
        if ($iniBlob !== '') {
            $lower = \strtolower($iniBlob);
            foreach (['auto_prepend_file', 'auto_append_file', 'allow_url_include', 'disable_functions'] as $directive) {
                if (\strpos($lower, $directive) !== false) {
                    $reasons[] = 'php_value:' . $directive;
                }
            }
        }

        // SCRIPT_FILENAME pointing at a PHP input wrapper or an upload path is the execution target.
        $scriptFilename = $params['SCRIPT_FILENAME'] ?? ($params['SCRIPT_NAME'] ?? '');
        if ($scriptFilename !== '') {
            $sfLower = \strtolower($scriptFilename);
            if (\strpos($sfLower, 'php://') !== false || \strpos($sfLower, 'data://') !== false) {
                $reasons[] = 'script_filename:wrapper';
            }
        }

        // A non-empty STDIN that carries a PHP open tag or an obvious shell-exec payload = the webshell body.
        if ($stdin !== '') {
            if (\strpos($stdin, '<?php') !== false || \strpos($stdin, '<?=') !== false) {
                $reasons[] = 'stdin:php_open_tag';
            }
        }

        $critical = $reasons !== [];

        return [
            'class' => $critical ? self::CLASS_RCE : self::CLASS_RECON,
            'critical' => $critical,
            'reasons' => $reasons,
        ];
    }
}
