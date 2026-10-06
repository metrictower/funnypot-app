<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Minecraft;

/**
 * Persona for the Minecraft honeypot (FP-0206, port 25565). The Server-List-Ping status JSON — version
 * name/protocol, MOTD, player counts, and the player `sample` — is derived from the install persona
 * material (deterministic per install, different across installs), never a fleet-wide literal. No
 * attacker input is ever reflected into it.
 */
final class MinecraftConfig
{
    public function __construct(
        public string $versionName = 'Paper 1.20.4',
        public int $protocol = 765,
        public string $motd = 'Private server',
        public int $maxPlayers = 60,
        public int $onlinePlayers = 7,
        /** @var list<array{name:string,id:string}> */
        public array $sample = []
    ) {
    }

    public static function fromEnv(string $installPersonaMaterial): self
    {
        $seed = \getenv('FUNNYPOT_MC_SEED') ?: $installPersonaMaterial;

        // Seeded version (name + matching protocol number) from a small pool of plausible builds.
        $builds = [
            ['Paper 1.20.4', 765], ['Paper 1.20.1', 763], ['Spigot 1.19.4', 762],
            ['Paper 1.21.1', 767], ['Fabric 1.20.2', 764],
        ];
        [$name, $proto] = $builds[\crc32('ver:' . $seed) % \count($builds)];

        $motds = ['Private server', 'Welcome', 'Members only', 'Survival realm', 'Community server'];
        $motd = $motds[\crc32('motd:' . $seed) % \count($motds)];

        $max = 20 + (\crc32('max:' . $seed) % 80);           // 20..99
        $online = \crc32('on:' . $seed) % (int) \max(1, $max / 2); // < half

        return new self(
            versionName: $name,
            protocol: $proto,
            motd: $motd,
            maxPlayers: $max,
            onlinePlayers: $online,
            sample: self::deriveSample($seed, $online)
        );
    }

    /**
     * Seeded player sample (names + deterministic UUIDs) — never the spec's hardcoded ops_lead/infra_admin
     * literals, which would be a cross-install fingerprint.
     *
     * @return list<array{name:string,id:string}>
     */
    private static function deriveSample(string $seed, int $online): array
    {
        $pool = ['Steve', 'Alex', 'Notch', 'Herobrine', 'Creeper', 'Enderman', 'builder42', 'miner_joe', 'redstoner'];
        $n = \min(3, \max(0, $online));
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $name = $pool[\crc32('p' . $i . ':' . $seed) % \count($pool)];
            $out[] = ['name' => $name, 'id' => self::seededUuid($seed . ':' . $i . ':' . $name)];
        }

        return $out;
    }

    /** A deterministic RFC4122-shaped UUID from the seed (format only — not a real account id). */
    private static function seededUuid(string $material): string
    {
        $h = \hash('sha256', $material);

        return \sprintf(
            '%s-%s-4%s-%s-%s',
            \substr($h, 0, 8),
            \substr($h, 8, 4),
            \substr($h, 13, 3),
            \substr($h, 16, 4),
            \substr($h, 20, 12)
        );
    }

    /** The persona Server-List-Ping status JSON (string). Built app-side; no attacker bytes. */
    public function statusJson(): string
    {
        return (string) \json_encode([
            'version' => ['name' => $this->versionName, 'protocol' => $this->protocol],
            'players' => [
                'max' => $this->maxPlayers,
                'online' => $this->onlinePlayers,
                'sample' => $this->sample,
            ],
            'description' => ['text' => $this->motd],
        ], JSON_UNESCAPED_SLASHES);
    }
}
