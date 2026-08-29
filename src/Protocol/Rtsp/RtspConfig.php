<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rtsp;

/**
 * Configuration for the low-interaction RTSP honeypot (TCP 554).
 *
 * The box impersonates a network camera / DVR — the prime Mirai and camera-scanner target. It never
 * streams real video: its whole purpose is to log scanners and harvest the credentials brute-forcers
 * spray at RTSP cameras. The meaningful knobs shape the believable device (the Server banner and the
 * authentication realm a real camera advertises) and whether DESCRIBE demands credentials before it
 * hands over a stream description.
 *
 * The default is to challenge with authentication (like a real camera), because the 401 challenge is
 * exactly what elicits the cleartext Basic / Digest credential we want to capture.
 */
final class RtspConfig
{
    // Authentication schemes offered in the WWW-Authenticate challenge.
    public const AUTH_DIGEST = 'digest';
    public const AUTH_BASIC = 'basic';
    public const AUTH_BOTH = 'both';

    public function __construct(
        // Server banner advertised in every response. A camera-ish persona, never a framework tell.
        public string $serverName = 'Rtsp Server',
        // Realm quoted in the WWW-Authenticate challenge — the string a real camera shows.
        public string $realm = 'IP Camera',
        // Which challenge to send: Digest (camera default), Basic, or both.
        public string $authScheme = self::AUTH_DIGEST,
        // Whether DESCRIBE demands authentication first (the 401 that elicits the credential).
        public bool $requireAuth = true
    ) {
    }

    public static function fromEnv(): self
    {
        $serverName = getenv('FUNNYPOT_RTSP_SERVER') ?: 'Rtsp Server';
        $realm = getenv('FUNNYPOT_RTSP_REALM') ?: 'IP Camera';

        $scheme = strtolower((string) (getenv('FUNNYPOT_RTSP_AUTH') ?: 'digest'));
        $authScheme = match ($scheme) {
            'basic' => self::AUTH_BASIC,
            'both', 'digest+basic' => self::AUTH_BOTH,
            default => self::AUTH_DIGEST,
        };

        // Any explicit falsey value turns the challenge off; the default is to challenge.
        $requireRaw = getenv('FUNNYPOT_RTSP_REQUIRE_AUTH');
        $requireAuth = !($requireRaw !== false && in_array(strtolower($requireRaw), ['0', 'false', 'no', 'off'], true));

        return new self(
            serverName: $serverName,
            realm: $realm,
            authScheme: $authScheme,
            requireAuth: $requireAuth
        );
    }
}
