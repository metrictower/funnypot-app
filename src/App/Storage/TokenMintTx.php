<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

use PDO;

/**
 * The side-table operations a token-mint transaction body may run, on the connection that holds the
 * open BEGIN IMMEDIATE. Single-use values are consumed by `UPDATE … WHERE used = 0 AND expires > now`
 * and a row count, so two racing redemptions of one code have exactly one winner.
 */
final class TokenMintTx
{
    public int $sideWrites = 0;

    /** @param array<string,int> $limits */
    public function __construct(
        private PDO $db,
        public readonly string $k,
        public readonly int $now,
        public readonly int $unitsUsed,
        public readonly bool $capReached,
        private array $limits,
    ) {
    }

    /** @param list<string> $scopes */
    public function insertCode(string $h, int $acct, int $app, array $scopes, string $stateRef, int $expires): void
    {
        $this->trimOwner('mint_codes', $acct, $this->limits['codes_per_account']);
        $this->db->prepare('INSERT OR REPLACE INTO mint_codes (h, k, acct, app, scopes, state_ref, expires, used) VALUES (:h, :k, :a, :app, :s, :r, :x, 0)')
            ->execute([':h' => $h, ':k' => $this->k, ':a' => $acct, ':app' => $app, ':s' => implode(' ', $scopes), ':r' => $stateRef, ':x' => $expires]);
        $this->trimTable('mint_codes', $this->limits['codes']);
        $this->sideWrites++;
    }

    /** @return array<string,mixed>|null the code's row when this call consumed it */
    public function consumeCode(string $h): ?array
    {
        return $this->consume('mint_codes', $h);
    }

    /** @param list<string> $scopes */
    public function insertRefresh(string $h, int $acct, int $app, array $scopes, int $expires): void
    {
        $this->trimOwner('mint_refresh', $acct, $this->limits['refresh_per_account']);
        $this->db->prepare('INSERT OR REPLACE INTO mint_refresh (h, k, acct, app, scopes, expires, used) VALUES (:h, :k, :a, :app, :s, :x, 0)')
            ->execute([':h' => $h, ':k' => $this->k, ':a' => $acct, ':app' => $app, ':s' => implode(' ', $scopes), ':x' => $expires]);
        $this->trimTable('mint_refresh', $this->limits['refresh']);
        $this->sideWrites++;
    }

    /** @return array<string,mixed>|null */
    public function consumeRefresh(string $h): ?array
    {
        return $this->consume('mint_refresh', $h);
    }

    /** Drop every live code and refresh token of an app (it was deleted). */
    public function revokeApp(int $acct, int $app): void
    {
        foreach (['mint_codes', 'mint_refresh'] as $t) {
            $this->db->prepare("UPDATE {$t} SET used = 1 WHERE k = :k AND acct = :a AND app = :app")
                ->execute([':k' => $this->k, ':a' => $acct, ':app' => $app]);
        }
        $this->sideWrites++;
    }

    /** @return array<string,mixed>|null */
    private function consume(string $table, string $h): ?array
    {
        $up = $this->db->prepare("UPDATE {$table} SET used = 1 WHERE h = :h AND k = :k AND used = 0 AND expires > :now");
        $up->execute([':h' => $h, ':k' => $this->k, ':now' => $this->now]);
        if ($up->rowCount() !== 1) {
            return null;
        }
        $this->sideWrites++;
        $st = $this->db->prepare("SELECT * FROM {$table} WHERE h = :h");
        $st->execute([':h' => $h]);
        $r = $st->fetch(PDO::FETCH_ASSOC);

        return is_array($r) ? $r : null;
    }

    private function trimOwner(string $table, int $acct, int $keep): void
    {
        $this->db->prepare("DELETE FROM {$table} WHERE k = :k AND (expires <= :now OR used = 1) AND rowid IN (SELECT rowid FROM {$table} WHERE k = :k2 LIMIT 64)")
            ->execute([':k' => $this->k, ':now' => $this->now, ':k2' => $this->k]);
        $st = $this->db->prepare("SELECT COUNT(*) FROM {$table} WHERE k = :k AND acct = :a AND used = 0 AND expires > :now");
        $st->execute([':k' => $this->k, ':a' => $acct, ':now' => $this->now]);
        $over = (int) $st->fetchColumn() - ($keep - 1);
        if ($over > 0) {
            $this->db->prepare("DELETE FROM {$table} WHERE rowid IN (SELECT rowid FROM {$table} WHERE k = :k AND acct = :a AND used = 0 ORDER BY expires ASC LIMIT :n)")
                ->execute([':k' => $this->k, ':a' => $acct, ':n' => $over]);
        }
    }

    private function trimTable(string $table, int $cap): void
    {
        $over = (int) $this->db->query("SELECT COUNT(*) FROM {$table}")->fetchColumn() - $cap;
        if ($over > 0) {
            $this->db->prepare("DELETE FROM {$table} WHERE rowid IN (SELECT rowid FROM {$table} ORDER BY used DESC, expires ASC LIMIT :n)")
                ->execute([':n' => $over]);
        }
    }
}
