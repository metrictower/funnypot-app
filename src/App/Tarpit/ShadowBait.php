<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\Core\Support\Fake\FakeSecrets;

/**
 * C4 — the bounded `/etc/shadow` bcrypt bait (FP-0245c). A fixed, small `/etc/shadow`-shaped file whose
 * password fields are {@see FakeSecrets}::bcryptHash tokens: correct `$2y$10$…` shape, seeded and
 * deterministic per deploy, and — the whole point — they authenticate to NOTHING. An attacker who feeds
 * them to hashcat/john burns GPU-hours cracking hashes that were never derived from any password, so
 * even a "successful" crack yields a string that logs in nowhere (a hash-crack tarpit, high cost to
 * them, zero risk to anyone).
 *
 * BOUNDED + STATIC: a fixed roster of accounts, generated once per request into a small buffered string
 * (never a generated tree) — crawler-safe and trivially byte-capped. Inert: no real user, no real host,
 * no real or crackable credential; the hashes are dead by construction.
 */
final class ShadowBait
{
    /** A believable but fixed system/service account roster. */
    private const ACCOUNTS = [
        'root', 'daemon', 'bin', 'sys', 'sync', 'www-data', 'backup', 'postgres',
        'redis', 'deploy', 'jenkins', 'admin', 'svc-api', 'svc-worker',
    ];

    public function __construct(private int $personaSeed)
    {
    }

    /**
     * The rendered /etc/shadow, hard-capped to $capBytes (a backstop — the natural size is < 2 KiB).
     * Locked system accounts get `*`/`!` (as a real shadow file does); human/service accounts get a
     * dead bcrypt hash. Standard 9-colon shadow layout; ASCII only, no CR.
     */
    public function render(int $capBytes = 65536): string
    {
        $lastChange = 19700; // days since epoch — a fixed, plausible value (no real clock)
        $locked = ['daemon', 'bin', 'sys', 'sync'];
        $lines = [];
        foreach (self::ACCOUNTS as $user) {
            if (in_array($user, $locked, true)) {
                $pw = $user === 'daemon' ? '*' : '!';
            } else {
                $pw = FakeSecrets::bcryptHash($this->personaSeed, 'shadow|' . $user);
            }
            $lines[] = $user . ':' . $pw . ':' . $lastChange . ':0:99999:7:::';
        }
        $out = implode("\n", $lines) . "\n";

        return strlen($out) > $capBytes ? substr($out, 0, max(0, $capBytes)) : $out;
    }

    /** The account names carrying a bcrypt hash (i.e. not the locked `*`/`!` accounts). @return list<string> */
    public function hashedAccounts(): array
    {
        return array_values(array_filter(
            self::ACCOUNTS,
            static fn (string $u): bool => !in_array($u, ['daemon', 'bin', 'sys', 'sync'], true)
        ));
    }

    /** The (dead) bcrypt hash for one account — for tests that assert it verifies against no password. */
    public function hashFor(string $user): string
    {
        return FakeSecrets::bcryptHash($this->personaSeed, 'shadow|' . $user);
    }
}
