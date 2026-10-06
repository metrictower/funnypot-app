<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Fpm;

use Funnypot\Core\Support\PersonaIdentity;

/**
 * Configuration/persona for the PHP-FPM FastCGI honeypot (FP-0204, port 9000).
 *
 * Every value is cosmetic persona — it shapes the PHP-FPM identity the box presents, never real
 * execution. The daemon decodes FastCGI records, captures any injected PHP, and answers with a
 * plausible inert FCGI_STDOUT; nothing here runs, includes, or reflects attacker input.
 *
 * Version coherence invariant: the served `X-Powered-By`/`Server` PHP version is derived from the
 * install persona (the SAME derivation HttpIdentity uses for /phpinfo.php), NOT the box's real PHP
 * (8.2.x). Serving the real runtime version would self-fingerprint the honeypot.
 */
final class FcgiConfig
{
    public function __construct(
        // Persona PHP version, e.g. "8.1.27" — decoupled from the box's real PHP for fingerprint safety.
        public string $phpVersion = '8.1.27',
        // Server software banner echoed in the SERVER_SOFTWARE/Server header shape.
        public string $serverSoftware = 'nginx/1.24.0',
        // Where captured STDIN payloads are quarantined (never executed; .php.bin suffix is load-bearing).
        public string $quarantineDir = '',
        // Cap on stored STDIN bytes per request; beyond it we keep draining but stop storing.
        public int $maxStdin = 262144,
        // Cap on a single captured payload persisted to quarantine.
        public int $quarantineCap = 65536
    ) {
    }

    /**
     * @param string $installPersonaMaterial the install's visible persona material; the PHP version is
     *        derived from it (stable per install, different across installs) unless FUNNYPOT_FPM_PHP_VERSION
     *        overrides it — never a fleet-wide literal and never the box's real PHP version.
     */
    public static function fromEnv(string $installPersonaMaterial): self
    {
        $version = getenv('FUNNYPOT_FPM_PHP_VERSION');
        if (!is_string($version) || $version === '') {
            $seed = PersonaIdentity::seedFromMaterial($installPersonaMaterial);
            $version = PersonaIdentity::fromSeed($seed)->productVersion('php');
        }

        $software = getenv('FUNNYPOT_FPM_SERVER_SOFTWARE') ?: 'nginx/1.24.0';

        $dir = getenv('FUNNYPOT_FPM_QUARANTINE_DIR');
        if (!is_string($dir) || $dir === '') {
            $dir = \dirname(__DIR__, 2) . '/demo/storage/quarantine';
        }

        return new self(
            phpVersion: $version,
            serverSoftware: $software,
            quarantineDir: $dir
        );
    }

    /** The X-Powered-By header value a real PHP-FPM emits, persona-coherent. */
    public function poweredBy(): string
    {
        return 'PHP/' . $this->phpVersion;
    }
}
