<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The explicit inputs one preparation may consume, read from the environment exactly once (or
 * constructor-injected by a test — the ONLY way fixed test bytes enter, there is no production
 * test-mode switch). The master is never accepted from argv. Values are unset (null) when the
 * variable is absent or empty.
 */
final class IdentityInputs
{
    public const ENV_SECRET_FILE = 'FUNNYPOT_INSTALL_SECRET_FILE';
    public const ENV_SECRET = 'FUNNYPOT_INSTALL_SECRET';
    public const ENV_PERSONA_SEED = 'FUNNYPOT_PERSONA_SEED';
    public const ENV_PERSONA_SECRET = 'FUNNYPOT_PERSONA_SECRET';
    public const ENV_FS_SECRET = 'FUNNYPOT_FS_SECRET';
    public const ENV_TLS_CERT = 'FUNNYPOT_TLS_CERT_FILE';
    public const ENV_TLS_KEY = 'FUNNYPOT_TLS_KEY_FILE';
    public const ENV_CN = 'FUNNYPOT_CN';
    public const ENV_PUBLIC_DNS = 'FUNNYPOT_PUBLIC_DNS';
    public const ENV_LE_DOMAIN = 'FUNNYPOT_LE_DOMAIN';

    /** Every sensitive source variable the entrypoint must remove before any child starts. @var list<string> */
    public const SCRUBBED = [
        self::ENV_SECRET_FILE, self::ENV_SECRET, self::ENV_PERSONA_SEED, self::ENV_PERSONA_SECRET,
        self::ENV_TLS_CERT, self::ENV_TLS_KEY, self::ENV_FS_SECRET,
    ];

    public function __construct(
        public readonly ?string $secretFile = null,
        public readonly ?string $secretEnv = null,
        public readonly ?string $personaSeed = null,
        public readonly ?string $personaSecret = null,
        public readonly bool $legacyFsSecretEnvSet = false,
        public readonly ?string $tlsCertFile = null,
        public readonly ?string $tlsKeyFile = null,
        public readonly ?string $cn = null,
        public readonly ?string $publicDns = null,
        public readonly ?string $leDomain = null,
    ) {
    }

    /** @param callable(string):(string|false)|null $env getenv()-shaped */
    public static function fromEnvironment(?callable $env = null): self
    {
        $env ??= static fn (string $k) => getenv($k);
        $get = static function (string $k) use ($env): ?string {
            $v = $env($k);

            return is_string($v) && $v !== '' ? $v : null;
        };

        return new self(
            secretFile: $get(self::ENV_SECRET_FILE),
            secretEnv: $get(self::ENV_SECRET),
            personaSeed: $get(self::ENV_PERSONA_SEED),
            personaSecret: $get(self::ENV_PERSONA_SECRET),
            legacyFsSecretEnvSet: $get(self::ENV_FS_SECRET) !== null,
            tlsCertFile: $get(self::ENV_TLS_CERT),
            tlsKeyFile: $get(self::ENV_TLS_KEY),
            cn: $get(self::ENV_CN),
            publicDns: $get(self::ENV_PUBLIC_DNS),
            leDomain: $get(self::ENV_LE_DOMAIN),
        );
    }
}
