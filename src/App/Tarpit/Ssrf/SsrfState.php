<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * One account's SSRF-surface state, serialized as one JSON row: its webhooks (each with up to three
 * URL versions and ten recent deliveries), its imports and its export destination, plus the times of
 * its recent costly actions for the ten-minute rate.
 *
 * Every collection is capped and every stored string has a capped length, so the worst case at every
 * cap at once fits ROW_CAP without eviction. URLs are stored masked; a credential in a URL is kept only
 * as a reference (kind, keyed hash, presign facts). The hook secret is the one raw secret stored,
 * because signatures need it, and it is never shown. Short keys keep the row small; the layout is
 * documented in docs/DATA-LAYER-DECISION.md.
 */
final class SsrfState
{
    public const VERSION = 1;
    public const ROW_CAP = 32768;
    public const MAX_HOOKS = 5;
    public const MAX_VERSIONS = 3;
    public const MAX_DELIVERIES = 10;
    public const MAX_IMPORTS = 5;
    public const MAX_VERIFICATIONS = 5;
    public const MAX_RETRIES = 5;
    public const RATE_WINDOW_S = 600;
    public const RATE_MAX = 30;
    public const MAX_URL = 560;
    public const MAX_HOST = 64;

    /** @param array<string,mixed> $d */
    private function __construct(public array $d)
    {
    }

    public static function fresh(int $now): self
    {
        return new self(['v' => self::VERSION, 'c' => $now, 'hn' => 0, 'h' => [], 'in' => 0, 'i' => [], 'st' => null, 'vn' => 0, 'rt' => []]);
    }

    public static function fromJson(string $json): ?self
    {
        $d = json_decode($json, true, 12);
        if (!is_array($d) || ($d['v'] ?? null) !== self::VERSION || !is_array($d['h'] ?? null) || !is_array($d['i'] ?? null)) {
            return null;
        }
        foreach (['hn' => 0, 'in' => 0, 'vn' => 0, 'rt' => [], 'c' => 0] as $k => $default) {
            if (!isset($d[$k]) || gettype($d[$k]) !== gettype($default)) {
                $d[$k] = $default;
            }
        }
        if (!array_key_exists('st', $d) || ($d['st'] !== null && !is_array($d['st']))) {
            $d['st'] = null;
        }

        return new self($d);
    }

    public function toJson(): string
    {
        return (string) json_encode($this->d, JSON_UNESCAPED_SLASHES);
    }

    public function fits(): bool
    {
        return strlen($this->toJson()) <= self::ROW_CAP;
    }

    // --- hooks -------------------------------------------------------------------------------------

    public function hookPos(string $id): ?int
    {
        foreach ($this->d['h'] as $i => $h) {
            if (hash_equals((string) $h['id'], $id)) {
                return $i;
            }
        }

        return null;
    }

    public function nextHookSerial(): int
    {
        $n = (int) $this->d['hn'];
        $this->d['hn'] = $n + 1;

        return $n;
    }

    /**
     * @param list<string> $events
     * @param array<string,mixed> $version
     */
    public function addHook(string $id, int $serial, string $contentType, string $secret, array $events, bool $active, array $version, int $now): int
    {
        $this->d['h'][] = [
            'id' => $id, 'n' => $serial, 'ct' => $contentType, 'sc' => $secret, 'ev' => $events, 'a' => $active ? 1 : 0,
            'c' => $now, 't' => $now, 'vn' => 1, 'u' => [['n' => 0] + $version], 'dn' => 0, 'd' => [],
        ];

        return count($this->d['h']) - 1;
    }

    /** @param array<string,mixed> $version */
    public function addVersion(int $pos, array $version, int $now): void
    {
        $h = &$this->d['h'][$pos];
        $n = (int) $h['vn'];
        $h['vn'] = $n + 1;
        $h['u'][] = ['n' => $n] + $version;
        while (count($h['u']) > self::MAX_VERSIONS) {
            $dropped = (int) array_shift($h['u'])['n'];
            $h['d'] = array_values(array_filter($h['d'], static fn (array $dl): bool => (int) $dl['vi'] !== $dropped));
        }
        $h['t'] = $now;
        unset($h);
    }

    /** @return array<string,mixed> the hook's current URL version */
    public function currentVersion(int $pos): array
    {
        $u = $this->d['h'][$pos]['u'];

        return $u[count($u) - 1];
    }

    /** @return array<string,mixed>|null */
    public function version(int $pos, int $n): ?array
    {
        foreach ($this->d['h'][$pos]['u'] as $v) {
            if ((int) $v['n'] === $n) {
                return $v;
            }
        }

        return null;
    }

    public function nextDeliverySerial(int $pos): int
    {
        $n = (int) $this->d['h'][$pos]['dn'];
        $this->d['h'][$pos]['dn'] = $n + 1;

        return $n;
    }

    /** @param array<string,mixed> $delivery */
    public function addDelivery(int $pos, array $delivery): void
    {
        $this->d['h'][$pos]['d'][] = $delivery;
        $this->d['h'][$pos]['d'] = array_slice($this->d['h'][$pos]['d'], -self::MAX_DELIVERIES);
    }

    public function deliveryPos(int $pos, string $id): ?int
    {
        foreach ($this->d['h'][$pos]['d'] as $i => $dl) {
            if (hash_equals((string) $dl['id'], $id)) {
                return $i;
            }
        }

        return null;
    }

    public function removeHook(int $pos): void
    {
        array_splice($this->d['h'], $pos, 1);
    }

    // --- imports -----------------------------------------------------------------------------------

    public function importPos(string $id): ?int
    {
        foreach ($this->d['i'] as $i => $im) {
            if (hash_equals((string) $im['id'], $id)) {
                return $i;
            }
        }

        return null;
    }

    public function nextImportSerial(): int
    {
        $n = (int) $this->d['in'];
        $this->d['in'] = $n + 1;

        return $n;
    }

    /** @param array<string,mixed> $import */
    public function addImport(array $import): void
    {
        $this->d['i'][] = $import;
        $this->d['i'] = array_slice($this->d['i'], -self::MAX_IMPORTS);
    }

    // --- storage -----------------------------------------------------------------------------------

    public function nextVerificationSerial(): int
    {
        $n = (int) $this->d['vn'];
        $this->d['vn'] = $n + 1;

        return $n;
    }

    /** @param array<string,mixed> $v */
    public function addVerification(array $v): void
    {
        $this->d['st']['v'][] = $v;
        $this->d['st']['v'] = array_slice($this->d['st']['v'], -self::MAX_VERIFICATIONS);
    }

    // --- rate --------------------------------------------------------------------------------------

    /** Whether one more costly action (a ping, redelivery, import, retry or verify) fits the ten-minute rate. */
    public function rateAllows(int $now): bool
    {
        return count(array_filter($this->d['rt'], static fn ($t): bool => (int) $t > $now - self::RATE_WINDOW_S)) < self::RATE_MAX;
    }

    public function pushRate(int $now): void
    {
        $this->d['rt'][] = $now;
        $this->d['rt'] = array_values(array_slice(array_filter($this->d['rt'], static fn ($t): bool => (int) $t > $now - self::RATE_WINDOW_S), -self::RATE_MAX));
    }
}
