<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Smb;

/**
 * Configuration for the low-interaction SMB honeypot (port 445).
 *
 * The service answers an SMB2 NEGOTIATE + SESSION_SETUP exchange far enough to harvest the
 * NTLM material a scanner offers, then denies the logon. It never serves a share, touches a
 * filesystem, or grants a session, so every value here is cosmetic persona: it shapes the
 * believable identity the box presents (a domain-joined file server), never real access.
 *
 * The server GUID is derived deterministically from a seed so it stays stable across restarts
 * of one deployment (a real server keeps its GUID); only the per-session NTLM challenge is random.
 */
final class SmbConfig
{
    public function __construct(
        // NetBIOS domain + computer name the box claims (advertised in the NTLM CHALLENGE target info).
        public string $domain = 'CORP',
        public string $computerName = 'FILE01',
        // DNS names for the NTLM target-info AV pairs. Kept coherent with the NetBIOS pair.
        public string $dnsDomain = 'corp.local',
        public string $dnsComputer = 'file01.corp.local',
        // Seed for the stable per-deploy server GUID. Empty means derive it from domain + computer.
        public string $serverGuidSeed = '',
        // Advertised OS in the NTLM Version field. Defaults track the chosen dialect persona
        // (Windows Server 2008 R2 / SMB 2.1) so the version and dialect stay consistent.
        public int $osMajor = 6,
        public int $osMinor = 1,
        public int $osBuild = 7601,
        // Signing offered but not required — a common, unremarkable posture.
        public bool $signingRequired = false
    ) {
    }

    public static function fromEnv(): self
    {
        $domain = getenv('FUNNYPOT_SMB_DOMAIN') ?: 'CORP';
        $computer = getenv('FUNNYPOT_SMB_COMPUTER') ?: 'FILE01';

        $dnsDomain = getenv('FUNNYPOT_SMB_DNS_DOMAIN') ?: strtolower($domain) . '.local';
        $dnsComputer = getenv('FUNNYPOT_SMB_DNS_COMPUTER') ?: strtolower($computer) . '.' . $dnsDomain;

        $seed = getenv('FUNNYPOT_SMB_GUID_SEED') ?: '';

        $signingRaw = getenv('FUNNYPOT_SMB_SIGNING_REQUIRED');
        $signingRequired = ($signingRaw !== false) ? filter_var($signingRaw, FILTER_VALIDATE_BOOLEAN) : false;

        return new self(
            domain: $domain,
            computerName: $computer,
            dnsDomain: $dnsDomain,
            dnsComputer: $dnsComputer,
            serverGuidSeed: $seed,
            signingRequired: $signingRequired
        );
    }

    /**
     * Stable 16-byte server GUID for this deployment. A real server keeps a fixed GUID, so it is
     * derived from a seed (never random) — only the NTLM challenge varies per session.
     */
    public function serverGuid(): string
    {
        $seed = $this->serverGuidSeed !== '' ? $this->serverGuidSeed : ($this->domain . '\\' . $this->computerName);

        return substr(hash('sha256', 'funnypot-smb-guid:' . $seed, true), 0, 16);
    }
}
