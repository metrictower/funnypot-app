<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Oracle;

/**
 * Configuration for the low-interaction Oracle TNS listener honeypot (port 1521).
 *
 * The service parses a client CONNECT, captures the connect descriptor (the target SERVICE_NAME/SID
 * plus the PROGRAM/HOST/USER the tool announces) and answers with a plausible TNS packet. It never
 * grants a database connection, so every value here is cosmetic persona: it shapes the listener
 * identity the box presents — the version advertised in a version-command banner and the VSNNUM/ALIAS
 * echoed in refusals — never real access.
 */
final class OracleConfig
{
    // Reply strategy for a CONNECT that carries a real connect descriptor.
    public const MODE_REFUSE = 'refuse'; // deny with a TNS REFUSE (a hardened listener that doesn't know the service)
    public const MODE_ACCEPT = 'accept'; // send a TNS ACCEPT, then capture the unmodelled native follow-up
    public const MODE_RESEND = 'resend'; // ask the client to resend once, then refuse

    public function __construct(
        // Advertised TNS listener version (persona). Defaults to a widely deployed, heavily scanned release.
        public string $version = '11.2.0.4.0',
        // Listener alias echoed in version banners and refuse descriptors.
        public string $alias = 'LISTENER',
        // Version-banner line template; %s is filled with the version string.
        public string $banner = 'TNSLSNR for Linux: Version %s - Production',
        // Reply strategy for a real connect descriptor.
        public string $mode = self::MODE_REFUSE
    ) {
    }

    public static function fromEnv(): self
    {
        $mode = strtolower((string) (getenv('FUNNYPOT_ORACLE_MODE') ?: self::MODE_REFUSE));
        if (!in_array($mode, [self::MODE_REFUSE, self::MODE_ACCEPT, self::MODE_RESEND], true)) {
            $mode = self::MODE_REFUSE;
        }

        return new self(
            version: getenv('FUNNYPOT_ORACLE_VERSION') ?: '11.2.0.4.0',
            alias: getenv('FUNNYPOT_ORACLE_ALIAS') ?: 'LISTENER',
            banner: getenv('FUNNYPOT_ORACLE_BANNER') ?: 'TNSLSNR for Linux: Version %s - Production',
            mode: $mode
        );
    }

    /**
     * Oracle's VSNNUM: the dotted version packed into one integer as
     * (major<<24) | (minor<<20) | (patch<<12) | (sub<<8) | subsub — the form a real listener reports.
     */
    public function vsnnum(): int
    {
        $p = array_map('intval', explode('.', $this->version));
        $major = $p[0] ?? 0;
        $minor = $p[1] ?? 0;
        $patch = $p[2] ?? 0;
        $sub = $p[3] ?? 0;
        $subsub = $p[4] ?? 0;

        return (($major & 0xFF) << 24)
            | (($minor & 0x0F) << 20)
            | (($patch & 0xFF) << 12)
            | (($sub & 0x0F) << 8)
            | ($subsub & 0xFF);
    }

    /** The listener version-banner line (persona) returned to a version/status command. */
    public function versionBanner(): string
    {
        return sprintf($this->banner, $this->version);
    }
}
