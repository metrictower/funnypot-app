<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Smart Credential Latching Cache (APCu + File/Memory).
 * Once an IP has "cracked" a password for an extension (immediately for a correct weak password, or —
 * under permissive crack resistance, FP-0225 — after the first few guesses are 403'd), that credential
 * is latched and subsequent REGISTERs on the AOR are accepted + captured as intel. This fools automated
 * scanners (svcrack) into a believable weak-PBX story instead of the telltale honeypot signature of
 * accepting the very first password guess. Also holds the per-(IP,ext) pre-latch guess counter that
 * drives that crack resistance, and a per-IP call-sequence counter for persona cycling.
 */
final class CredentialStore
{
    /** Cap on distinct tracked keys/IPs; oldest are evicted so a spoofed-source flood can't grow memory unbounded. */
    private const MAX_TRACKED = 5000;

    /** @var array<string, string> In-memory cache: "ip:user" => responseHash */
    private array $memoryCache = [];

    /** @var array<string, int> In-memory cache: ip => callCount */
    private array $callCounts = [];

    /** @var array<string, int> In-memory: "ip\0user" => credential-guess count before latch (crack resistance) */
    private array $crackAttempts = [];

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
     * Increment + return the count of credential guesses seen for (IP, extension) before it latches.
     * Drives permissive-mode crack resistance: the first few guesses are rejected so the "crack" takes a
     * believable few tries instead of succeeding on guess #1. In-memory only (a crack sequence is short;
     * losing it on restart is harmless), bounded like callCounts.
     */
    public function incrementCrackAttempt(string $ip, string $user): int
    {
        $k = $ip . "\0" . $user;
        $n = ($this->crackAttempts[$k] ?? 0) + 1;
        $this->crackAttempts[$k] = $n;
        if (count($this->crackAttempts) > self::MAX_TRACKED) {
            array_shift($this->crackAttempts); // evict oldest-seen (IP,ext)
        }

        return $n;
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
        $this->crackAttempts = [];
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
