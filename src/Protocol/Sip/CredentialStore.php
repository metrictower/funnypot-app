<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Smart Credential Latching Cache (APCu + File/Memory).
 * Once an attacker IP tests a password for an extension, it latches success for that single credential,
 * rejecting all subsequent conflicting password attempts with 403 Forbidden.
 * This fools automated scanners (svcrack) into believing the PBX has a single vulnerable secret,
 * avoiding the telltale honeypot signature of accepting all passwords indiscriminately.
 */
final class CredentialStore
{
    /** Cap on distinct tracked keys/IPs; oldest are evicted so a spoofed-source flood can't grow memory unbounded. */
    private const MAX_TRACKED = 5000;

    /** @var array<string, string> In-memory cache: "ip:user" => responseHash */
    private array $memoryCache = [];

    /** @var array<string, int> In-memory cache: ip => callCount */
    private array $callCounts = [];

    public function __construct(
        private readonly string $storagePath = '',
        private readonly int $ttl = 86400 // 24 hours
    ) {
        $this->loadPersisted();
    }

    /**
     * Retrieves the call sequence count for a caller IP.
     */
    public function getCallCountForIp(string $ip): int
    {
        $key = "fp_sip_calls_{$ip}";
        if (function_exists('apcu_fetch')) {
            $val = apcu_fetch($key, $success);
            if ($success && is_int($val)) {
                return $val;
            }
        }

        return $this->callCounts[$ip] ?? 0;
    }

    /**
     * Increments the call sequence count for a caller IP.
     */
    public function incrementCallCountForIp(string $ip): int
    {
        $count = $this->getCallCountForIp($ip) + 1;
        $this->callCounts[$ip] = $count;
        if (count($this->callCounts) > self::MAX_TRACKED) {
            array_shift($this->callCounts); // evict oldest-seen IP
        }

        $key = "fp_sip_calls_{$ip}";
        if (function_exists('apcu_store')) {
            @apcu_store($key, $count, $this->ttl);
        }

        // No disk write here: this runs on EVERY INVITE (pre-handshake), and a full-file rewrite per
        // spoofed packet is a self-DoS. Call counts stay in memory/APCu — they only pick the persona,
        // so losing them on restart is harmless. Credentials still persist on latch().
        return $count;
    }

    /**
     * Checks if credentials have already been latched for this IP and extension.
     */
    public function hasLatched(string $ip, string $user): bool
    {
        $key = $this->key($ip, $user);

        if (function_exists('apcu_exists') && apcu_exists($key)) {
            return true;
        }

        return isset($this->memoryCache[$key]);
    }

    /**
     * Retrieves the latched response hash for this IP and extension.
     */
    public function getLatched(string $ip, string $user): ?string
    {
        $key = $this->key($ip, $user);

        if (function_exists('apcu_fetch')) {
            $val = apcu_fetch($key, $success);
            if ($success && is_string($val)) {
                return $val;
            }
        }

        return $this->memoryCache[$key] ?? null;
    }

    /**
     * Latches the successful credential hash for this IP and extension.
     */
    public function latch(string $ip, string $user, string $responseHash): void
    {
        $key = $this->key($ip, $user);
        $this->memoryCache[$key] = $responseHash;
        if (count($this->memoryCache) > self::MAX_TRACKED) {
            array_shift($this->memoryCache); // evict oldest latched credential
        }

        if (function_exists('apcu_store')) {
            @apcu_store($key, $responseHash, $this->ttl);
        }

        $this->savePersisted();
    }

    /**
     * Checks whether an incoming response hash matches the latched credential.
     */
    public function matches(string $ip, string $user, string $responseHash): bool
    {
        $latched = $this->getLatched($ip, $user);
        if ($latched === null) {
            return false;
        }

        return hash_equals($latched, $responseHash);
    }

    /**
     * Clears latched credentials and counters (for testing / admin clear).
     */
    public function clear(): void
    {
        $this->memoryCache = [];
        $this->callCounts = [];
        if ($this->storagePath !== '' && is_file($this->storagePath)) {
            @unlink($this->storagePath);
        }
    }

    private function key(string $ip, string $user): string
    {
        return "fp_sip_cred_{$ip}_{$user}";
    }

    private function loadPersisted(): void
    {
        if ($this->storagePath === '' || !is_file($this->storagePath)) {
            return;
        }

        $content = @file_get_contents($this->storagePath);
        if ($content) {
            $data = json_decode($content, true);
            if (is_array($data)) {
                if (isset($data['credentials']) || isset($data['call_counts'])) {
                    $this->memoryCache = (array) ($data['credentials'] ?? []);
                    $this->callCounts = (array) ($data['call_counts'] ?? []);
                } else {
                    $this->memoryCache = $data;
                }
            }
        }
    }

    private function savePersisted(): void
    {
        if ($this->storagePath === '') {
            return;
        }

        $dir = dirname($this->storagePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        $payload = [
            'credentials' => $this->memoryCache,
            'call_counts' => $this->callCounts,
        ];

        @file_put_contents($this->storagePath, json_encode($payload, JSON_PRETTY_PRINT));
    }
}
