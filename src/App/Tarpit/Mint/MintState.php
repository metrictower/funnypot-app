<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * One source's account-surface state: its accounts (each with tokens, OAuth apps, sessions and 2FA),
 * plus per-source history (recent outcomes, mint and API timestamps, pending SSO/approval/consent
 * requests, identity-provider failures). Serialized as one JSON row.
 *
 * Every collection is capped and every stored string has a capped length in a charset JSON never
 * escapes, so the worst-case row at every cap at once fits ROW_CAP without eviction. fit() still
 * evicts, in a fixed order, as a guard: expired tokens, then dead sessions, then the least recently
 * active account. No raw secret is ever stored: tokens and secrets are re-derived from their serials,
 * and only keyed hashes of passwords, client secrets and recovery codes are kept.
 *
 * Short keys keep the row small; the layout is documented in docs/DATA-LAYER-DECISION.md.
 */
final class MintState
{
    public const VERSION = 1;
    public const ROW_CAP = 49152;
    public const MAX_ACCOUNTS = 6;
    /** Personal access tokens per account; with MAX_OAUTH_TOKENS that is eight tokens in all. */
    public const MAX_TOKENS = 6;
    public const MAX_OAUTH_TOKENS = 2;
    public const MAX_APPS = 3;
    public const MAX_SECRETS = 2;
    public const MAX_SIDS = 4;
    public const RECOVERY_CODES = 10;
    public const MAX_OUTCOMES = 8;
    public const MAX_MINT_TS = 16;
    public const MAX_API_TS = 32;
    public const MAX_REQUESTS = 8;
    public const MAX_IDP_FAILS = 5;

    /** @param array<string,mixed> $d */
    private function __construct(public array $d)
    {
    }

    public static function fresh(int $now, string $epoch): self
    {
        return new self(['v' => self::VERSION, 'c' => $now, 'e' => $epoch, 'an' => 0, 'a' => [], 'o' => [], 'm' => [], 'p' => [], 'r' => [], 'rn' => 0, 'f' => [], 'sn' => 0]);
    }

    public static function fromJson(string $json): ?self
    {
        $d = json_decode($json, true, 16);
        if (!is_array($d) || ($d['v'] ?? null) !== self::VERSION || !is_array($d['a'] ?? null) || !is_string($d['e'] ?? null)) {
            return null;
        }
        foreach (['an' => 0, 'o' => [], 'm' => [], 'p' => [], 'r' => [], 'rn' => 0, 'f' => [], 'sn' => 0, 'c' => 0] as $k => $default) {
            if (!isset($d[$k]) || gettype($d[$k]) !== gettype($default)) {
                $d[$k] = $default;
            }
        }

        return new self($d);
    }

    public function toJson(): string
    {
        return (string) json_encode($this->d, JSON_UNESCAPED_SLASHES);
    }

    public function epoch(): string
    {
        return (string) $this->d['e'];
    }

    // --- accounts --------------------------------------------------------------------------------

    /** Position of the live account a codec index names. */
    public function accountPos(int $idx): ?int
    {
        foreach ($this->d['a'] as $i => $a) {
            if (((int) $a['i']) % 256 === $idx) {
                return $i;
            }
        }

        return null;
    }

    public function accountPosBySerial(int $serial): ?int
    {
        foreach ($this->d['a'] as $i => $a) {
            if ((int) $a['i'] === $serial) {
                return $i;
            }
        }

        return null;
    }

    public function accountPosByUsername(string $username): ?int
    {
        foreach ($this->d['a'] as $i => $a) {
            if (strcasecmp((string) $a['u'], $username) === 0) {
                return $i;
            }
        }

        return null;
    }

    public function accountPosByLogin(string $login): ?int
    {
        foreach ($this->d['a'] as $i => $a) {
            if (strcasecmp((string) $a['u'], $login) === 0 || strcasecmp((string) $a['em'], $login) === 0) {
                return $i;
            }
        }

        return null;
    }

    public function emailTaken(string $email): bool
    {
        foreach ($this->d['a'] as $a) {
            if (strcasecmp((string) $a['em'], $email) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add an account, evicting the least recently active one at the cap. The serial skips any
     * value whose codec index a live account already uses, so an index always names one account.
     *
     * @return int the new account's position
     */
    public function addAccount(string $username, string $email, string $pwHash, int $now): int
    {
        if (count($this->d['a']) >= self::MAX_ACCOUNTS) {
            $this->evictLruAccount();
        }
        $serial = (int) $this->d['an'];
        $used = array_map(static fn (array $a): int => ((int) $a['i']) % 256, $this->d['a']);
        while (in_array($serial % 256, $used, true)) {
            $serial++;
        }
        $this->d['an'] = $serial + 1;
        $this->d['a'][] = [
            'i' => $serial, 'u' => $username, 'em' => $email, 'pw' => $pwHash, 'c' => $now, 't' => $now,
            'nm' => '', 'bi' => '', 'ce' => 0, 'ch' => 0, 'tf' => null, 'te' => 0, 'cu' => 0, 'ru' => 0, 'rt' => '',
            'mn' => 0, 'k' => [], 'apn' => 0, 'ap' => [], 'sn' => 0, 's' => [], 'fl' => null, 'rl' => [0, 0],
        ];

        return count($this->d['a']) - 1;
    }

    public function evictLruAccount(): void
    {
        if ($this->d['a'] === []) {
            return;
        }
        $lru = 0;
        foreach ($this->d['a'] as $i => $a) {
            if ((int) $a['t'] < (int) $this->d['a'][$lru]['t']) {
                $lru = $i;
            }
        }
        $serial = (int) $this->d['a'][$lru]['i'];
        array_splice($this->d['a'], $lru, 1);
        $this->d['r'] = array_values(array_filter($this->d['r'], static fn (array $r): bool => (int) $r['a'] !== $serial));
    }

    /** A new token serial for an account: its lifetime mint counter, skipping live indexes. */
    public function nextTokenSerial(int $pos): int
    {
        $n = (int) $this->d['a'][$pos]['mn'];
        $used = array_map(static fn (array $t): int => ((int) $t['n']) % 256, $this->d['a'][$pos]['k']);
        while (in_array($n % 256, $used, true)) {
            $n++;
        }
        $this->d['a'][$pos]['mn'] = $n + 1;

        return $n;
    }

    public function tokenPos(int $pos, int $idx, string $kind): ?int
    {
        foreach ($this->d['a'][$pos]['k'] as $i => $t) {
            if (((int) $t['n']) % 256 === $idx && $t['k'] === $kind) {
                return $i;
            }
        }

        return null;
    }

    public function tokenPosById(int $pos, string $id): ?int
    {
        foreach ($this->d['a'][$pos]['k'] as $i => $t) {
            if (hash_equals((string) $t['id'], $id)) {
                return $i;
            }
        }

        return null;
    }

    public function appPosById(int $pos, string $id): ?int
    {
        foreach ($this->d['a'][$pos]['ap'] as $i => $a) {
            if (hash_equals((string) $a['id'], $id)) {
                return $i;
            }
        }

        return null;
    }

    public function appPosByClientId(int $pos, string $clientId): ?int
    {
        foreach ($this->d['a'][$pos]['ap'] as $i => $a) {
            if (hash_equals((string) $a['ci'], $clientId)) {
                return $i;
            }
        }

        return null;
    }

    public function appPosBySerial(int $pos, int $serial): ?int
    {
        foreach ($this->d['a'][$pos]['ap'] as $i => $a) {
            if ((int) $a['n'] === $serial) {
                return $i;
            }
        }

        return null;
    }

    public function sidPos(int $pos, string $sidHex): ?int
    {
        foreach ($this->d['a'][$pos]['s'] as $i => $s) {
            if (hash_equals((string) $s['id'], $sidHex)) {
                return $i;
            }
        }

        return null;
    }

    // --- per-source history ----------------------------------------------------------------------

    public function pushOutcome(int $acct, string $kind, int $now): void
    {
        $this->d['o'][] = [$acct, $kind, $now];
        $this->d['o'] = array_slice($this->d['o'], -self::MAX_OUTCOMES);
    }

    /** @return list<string> the account's recent outcome kinds, oldest first */
    public function history(int $acct): array
    {
        $out = [];
        foreach ($this->d['o'] as $o) {
            if ((int) $o[0] === $acct) {
                $out[] = (string) $o[1];
            }
        }

        return $out;
    }

    public function successes(int $acct): int
    {
        return count(array_filter($this->history($acct), static fn (string $k): bool => $k === FrictionPicker::SUCCESS));
    }

    public function pushMintPost(int $acct, int $now): void
    {
        $this->d['m'][] = [$acct, $now];
        $this->d['m'] = array_slice($this->d['m'], -self::MAX_MINT_TS);
    }

    public function mintPosts(int $acct, int $now, int $window): int
    {
        return count(array_filter($this->d['m'], static fn (array $m): bool => (int) $m[0] === $acct && (int) $m[1] > $now - $window));
    }

    public function pushApi(int $acct, int $now): void
    {
        $this->d['p'][] = [$acct, $now];
        $this->d['p'] = array_slice($this->d['p'], -self::MAX_API_TS);
    }

    public function apiCalls(int $acct, int $now, int $window): int
    {
        return count(array_filter($this->d['p'], static fn (array $p): bool => (int) $p[0] === $acct && (int) $p[1] > $now - $window));
    }

    /** @param array<string,mixed> $req */
    public function addRequest(array $req): void
    {
        $this->d['r'][] = $req;
        $this->d['r'] = array_slice($this->d['r'], -self::MAX_REQUESTS);
    }

    public function requestPos(string $id, int $acct): ?int
    {
        foreach ($this->d['r'] as $i => $r) {
            if ((int) $r['a'] === $acct && hash_equals((string) $r['id'], $id)) {
                return $i;
            }
        }

        return null;
    }

    public function pushIdpFail(int $now): void
    {
        $this->d['f'][] = $now;
        $this->d['f'] = array_slice($this->d['f'], -self::MAX_IDP_FAILS);
    }

    public function idpFails(int $now, int $window): int
    {
        return count(array_filter($this->d['f'], static fn ($t): bool => (int) $t > $now - $window));
    }

    // --- bounds ----------------------------------------------------------------------------------

    /**
     * Shrink the serialized row to $budget bytes, in the fixed order: expired tokens, then dead
     * sessions, then the least recently active account. Returns false only if it still cannot fit.
     */
    public function fit(int $now, int $budget = self::ROW_CAP): bool
    {
        if (strlen($this->toJson()) <= $budget) {
            return true;
        }
        foreach ($this->d['a'] as $i => $a) {
            $this->d['a'][$i]['k'] = array_values(array_filter($a['k'], static fn (array $t): bool => (int) $t['x'] === 0 || (int) $t['x'] > $now));
        }
        if (strlen($this->toJson()) <= $budget) {
            return true;
        }
        foreach ($this->d['a'] as $i => $a) {
            $this->d['a'][$i]['s'] = array_values(array_filter($a['s'], static fn (array $s): bool => self::sidLive($s, $now)));
        }
        while (strlen($this->toJson()) > $budget && $this->d['a'] !== []) {
            $this->evictLruAccount();
        }

        return strlen($this->toJson()) <= $budget;
    }

    /** @param array<string,mixed> $s */
    public static function sidLive(array $s, int $now): bool
    {
        return $now - (int) $s['c'] <= SessionCodec::ABSOLUTE_S && $now - (int) $s['l'] <= SessionCodec::IDLE_S;
    }
}
