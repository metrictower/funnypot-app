<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rsync;

/**
 * Persona for the rsync daemon honeypot (FP-0164, port 873). The advertised version/digest list and the
 * decoy module table are derived from the install persona material (deterministic per install, different
 * across installs), never fleet-wide literals. Nothing here touches a real filesystem.
 */
final class RsyncConfig
{
    public function __construct(
        public string $version = '31.0',
        public string $digests = 'sha512 sha256 sha1 md5 md4',
        /** @var array<string,string> lowercased module name => description */
        public array $modules = []
    ) {
    }

    public static function fromEnv(string $installPersonaMaterial): self
    {
        $seed = \getenv('FUNNYPOT_RSYNC_SEED') ?: $installPersonaMaterial;

        // Version from a small pool of plausible modern rsync protocol banners.
        $versions = ['31.0', '30.0'];
        $version = $versions[self::h('ver:' . $seed) % \count($versions)];

        return new self(
            version: $version,
            digests: $version === '30.0' ? 'sha1 md5 md4' : 'sha512 sha256 sha1 md5 md4',
            modules: self::deriveModules($seed)
        );
    }

    /** The greeting line a real rsync 3.x daemon sends (version + digest list on proto 30+). */
    public function greeting(): string
    {
        return '@RSYNCD: ' . $this->version . ' ' . $this->digests . "\n";
    }

    /**
     * Seeded decoy module table (name => description). Deterministic subset of a plausible pool so a
     * replayed enumeration is byte-stable; never a fleet-wide literal.
     *
     * @return array<string,string>
     */
    private static function deriveModules(string $seed): array
    {
        $pool = [
            'backup' => 'Production server backups and database snapshots',
            'www' => 'Web application source files (/var/www/html)',
            'configs' => 'Infrastructure environment configs and SSL certificates',
            'data' => 'Shared application data exports',
            'media' => 'User-uploaded media assets',
            'logs' => 'Aggregated service logs',
            'home' => 'User home directories',
        ];
        $keys = \array_keys($pool);
        $count = 3 + (self::h('n:' . $seed) % 3); // 3..5 modules
        $start = self::h('s:' . $seed) % \count($keys);

        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $k = $keys[($start + $i) % \count($keys)];
            $out[$k] = $pool[$k];
        }

        return $out;
    }

    /** Non-negative hash (masks crc32's sign bit so the modulo is 32/64-bit safe). */
    private static function h(string $m): int
    {
        return \crc32($m) & 0x7FFFFFFF;
    }
}
