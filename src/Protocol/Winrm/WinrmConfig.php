<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Winrm;

/**
 * Configuration for the low-interaction WinRM / WS-Management honeypot (TCP 5985, HTTP).
 *
 * WinRM's HTTP listener speaks over HTTP.sys, so the box impersonates that stack: the whole purpose
 * is to log the scanners hunting for remote-management endpoints and to harvest the credentials
 * brute-forcers spray at the /wsman endpoint. It never runs a command and never grants a session.
 *
 * The meaningful knobs shape the believable server (the HTTP.sys Server banner and the Basic realm a
 * real WinRM listener quotes) and which WWW-Authenticate schemes the 401 challenge offers. Basic is
 * offered by default alongside Negotiate because the Basic challenge is exactly what elicits the
 * cleartext user:pass we want to capture; a real hardened listener would disable Basic, but the
 * honeypot trades that realism for the credential.
 */
final class WinrmConfig
{
    // Authentication schemes offered in the WWW-Authenticate challenge.
    public const AUTH_NEGOTIATE = 'negotiate';
    public const AUTH_BASIC = 'basic';
    public const AUTH_BOTH = 'both';

    public function __construct(
        // Server banner advertised in every response — the real HTTP.sys / WinRM stack identifier.
        public string $serverName = 'Microsoft-HTTPAPI/2.0',
        // Realm quoted in the Basic WWW-Authenticate challenge (a real WinRM listener uses "WSMAN").
        public string $realm = 'WSMAN',
        // Which challenge to send: Negotiate only, Basic only, or both (default).
        public string $authScheme = self::AUTH_BOTH,
        // NetBIOS name embedded in the NTLM type-2 CHALLENGE, so the type-3 the client returns (which
        // carries the account name) looks like it is answering a real server.
        public string $computerName = 'WIN-WINRM01'
    ) {
    }

    public static function fromEnv(): self
    {
        $serverName = getenv('FUNNYPOT_WINRM_SERVER') ?: 'Microsoft-HTTPAPI/2.0';
        $realm = getenv('FUNNYPOT_WINRM_REALM') ?: 'WSMAN';

        $scheme = strtolower((string) (getenv('FUNNYPOT_WINRM_AUTH') ?: 'both'));
        $authScheme = match ($scheme) {
            'negotiate', 'ntlm' => self::AUTH_NEGOTIATE,
            'basic' => self::AUTH_BASIC,
            default => self::AUTH_BOTH,
        };

        $computerName = getenv('FUNNYPOT_WINRM_COMPUTER') ?: 'WIN-WINRM01';

        return new self(
            serverName: $serverName,
            realm: $realm,
            authScheme: $authScheme,
            computerName: $computerName
        );
    }
}
