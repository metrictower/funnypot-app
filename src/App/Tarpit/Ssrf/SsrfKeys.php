<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The SSRF decoy's sub-keys, all derived from the token-mint key so no new identity material is
 * needed. The visible persona seed is never a key: it is printed on pages, while these never leave
 * the process.
 */
final class SsrfKeys
{
    public const PURPOSES = ['owner', 'ledger', 'ids', 'sig', 'netname', 'subnet', 'keyidx'];

    /** @var array<string,string> */
    private array $keys = [];

    public function __construct(string $tokenMintKey)
    {
        foreach (self::PURPOSES as $p) {
            $this->keys[$p] = hash_hmac('sha256', 'funnypot-app/ssrf-decoy/' . $p . '/v1', $tokenMintKey, true);
        }
    }

    public function key(string $purpose): string
    {
        if (!isset($this->keys[$purpose])) {
            throw new \LogicException('unknown key purpose');
        }

        return $this->keys[$purpose];
    }

    /** A lowercase hex value of $chars characters keyed for $purpose. */
    public function hex(string $purpose, string $label, int $chars): string
    {
        return substr(hash_hmac('sha256', $label, $this->key($purpose)), 0, $chars);
    }

    /** The account a request acts as: the token-mint row, its epoch and the account serial. */
    public function owner(string $rowKeyHex, string $epoch, int $accountSerial): string
    {
        return $this->hex('owner', $rowKeyHex . "\0" . $epoch . "\0" . $accountSerial, 32);
    }

    /** The request source's ledger key; no raw address is ever stored. */
    public function ledger(string $ip): string
    {
        return $this->hex('ledger', $ip, 32);
    }
}
