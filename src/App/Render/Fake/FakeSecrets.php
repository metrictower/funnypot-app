<?php

declare(strict_types=1);

namespace Funnypot\App\Render\Fake;

/**
 * Deterministic, INERT fake credentials for an "API Keys" / Settings panel — the top-ROI bait an
 * attacker reflexively tries to steal (docs/research/2026-08-23-admin-panel-fake-data-*).
 *
 * Design rules:
 *  - Every value is a pure function of the seed (no time()/rand()); two instances of one seed agree
 *    byte-for-byte across every panel read.
 *  - Each secret is CORRECT-SHAPE but random and non-working: it looks real enough that the attacker
 *    burns time trying it, yet it fails against the real Stripe/AWS/etc. API. Never the giveaway
 *    "...EXAMPLE" placeholder (critique T6) — that unmasks the trap the instant it is revealed.
 *  - The table shows a masked form (prefix + last few chars); the full inert value is what a
 *    Reveal/Copy control hands back.
 *  - PHP 7.3-clean (plain arrays + hash/substr/sprintf) so it can promote into the shared Fake
 *    namespace alongside ServerProfile.
 */
final class FakeSecrets
{
    /** @var int */
    private $seed;

    private const MIXED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    private const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    private const DIGIT = '0123456789';
    // AWS secret keys are base64-ish; the extra symbols keep the length/charset believable.
    private const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    private function __construct(int $seed)
    {
        $this->seed = $seed;
    }

    public static function fromSeed(int $seed): self
    {
        return new self($seed);
    }

    // --- deterministic seeded primitives (frozen per seed) ---

    private function h(string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $this->seed . '|sec|' . $salt), 0, 15));
    }

    /** @param list<string> $options */
    private function pick(array $options, string $salt): string
    {
        return $options[$this->h($salt) % count($options)];
    }

    private function intIn(int $min, int $max, string $salt): int
    {
        return $min + ($this->h($salt) % (($max - $min) + 1));
    }

    private function hex(int $len, string $salt): string
    {
        return substr(hash('sha256', $this->seed . '|hex|' . $salt), 0, $len);
    }

    /** A run of characters from $alphabet, as long as needed, drawn from a seeded byte stream. */
    private function chars(int $len, string $alphabet, string $salt): string
    {
        $m = strlen($alphabet);
        $out = '';
        $block = 0;
        while (strlen($out) < $len) {
            $stream = hash('sha256', $this->seed . '|chars|' . $salt . '|' . $block);
            for ($k = 0; $k < 64 && strlen($out) < $len; $k += 2) {
                $out .= $alphabet[hexdec(substr($stream, $k, 2)) % $m];
            }
            $block++;
        }
        return $out;
    }

    // --- provider catalogue: recognisable prefix -> correct-shape inert value ---

    /**
     * One correct-shape, random, non-working credential for a provider.
     * The 'front' is how many leading chars stay visible when masked (the recognisable prefix).
     *
     * @return array{full:string,front:int}
     */
    private function forProvider(string $provider, string $salt): array
    {
        switch ($provider) {
            case 'Stripe':
                return ['full' => 'sk_live_' . $this->chars(24, self::MIXED, 'stripe' . $salt), 'front' => 8];
            case 'AWS':
                return ['full' => 'AKIA' . $this->chars(16, self::UPPER, 'aws' . $salt), 'front' => 4];
            case 'SendGrid':
                return [
                    'full' => 'SG.' . $this->chars(22, self::MIXED, 'sg1' . $salt) . '.' . $this->chars(43, self::MIXED, 'sg2' . $salt),
                    'front' => 3,
                ];
            case 'GitHub':
                return ['full' => 'ghp_' . $this->chars(36, self::MIXED, 'gh' . $salt), 'front' => 4];
            case 'OpenAI':
                return ['full' => 'sk-' . $this->chars(48, self::MIXED, 'oai' . $salt), 'front' => 3];
            case 'Slack':
                return [
                    'full' => 'xoxb-' . $this->chars(11, self::DIGIT, 'sl1' . $salt) . '-'
                        . $this->chars(12, self::DIGIT, 'sl2' . $salt) . '-' . $this->chars(24, self::MIXED, 'sl3' . $salt),
                    'front' => 5,
                ];
            case 'Twilio':
            default:
                return ['full' => 'SK' . $this->hex(32, 'tw' . $salt), 'front' => 2];
        }
    }

    private function mask(string $full, int $front): string
    {
        return substr($full, 0, $front) . '****' . substr($full, -4);
    }

    private function created(string $salt): string
    {
        return sprintf('%04d-%02d-%02d', $this->intIn(2024, 2026, 'y' . $salt), $this->intIn(1, 12, 'm' . $salt), $this->intIn(1, 28, 'd' . $salt));
    }

    private function lastUsed(string $salt): string
    {
        $when = [
            '2 minutes ago', '17 minutes ago', '3 hours ago', 'yesterday', '4 days ago',
            '2 weeks ago', 'Never',
            sprintf('%04d-%02d-%02d', 2025, $this->intIn(1, 12, 'lm' . $salt), $this->intIn(1, 28, 'ld' . $salt)),
        ];
        return $this->pick($when, 'lu' . $salt);
    }

    // --- panel data ---

    /**
     * The "API Keys" table: 6-12 rows, each a labelled provider credential. `masked` is what the
     * table shows; `fullInert` is what Reveal/Copy hands back — correct-shape, random, non-working.
     *
     * @return list<array{label:string,masked:string,created:string,lastUsed:string,fullInert:string}>
     */
    public function keys(): array
    {
        $providers = ['Stripe', 'AWS', 'SendGrid', 'GitHub', 'OpenAI', 'Slack', 'Twilio'];
        $labels = [
            'Production Server', 'CI/CD Pipeline', 'Data Warehouse Sync', 'Backup Service',
            'Grafana Metrics', 'Billing Webhook', 'Mobile App', 'Staging Server',
            'Analytics Export', 'Support Bot', 'Nightly ETL', 'Ops Dashboard',
        ];
        $count = $this->intIn(6, 12, 'count');
        $rows = [];
        for ($i = 0; $i < $count; $i++) {
            $provider = $providers[$this->h('prov' . $i) % count($providers)];
            $c = $this->forProvider($provider, (string) $i);
            $rows[] = [
                'label' => $labels[$i % count($labels)] . ' (' . $provider . ')',
                'masked' => $this->mask($c['full'], $c['front']),
                'created' => $this->created((string) $i),
                'lastUsed' => $this->lastUsed((string) $i),
                'fullInert' => $c['full'],
            ];
        }
        return $rows;
    }

    /**
     * A .env-style dump for a Settings / "leaked config" view — every value inert and random.
     *
     * @return list<array{0:string,1:string}>
     */
    public function envVars(): array
    {
        return [
            ['DB_PASSWORD', $this->chars(24, self::MIXED, 'dbpw')],
            ['REDIS_PASSWORD', $this->chars(20, self::MIXED, 'redispw')],
            ['JWT_SECRET', $this->chars(48, self::MIXED, 'jwt')],
            ['APP_KEY', 'base64:' . $this->chars(44, self::B64, 'appkey')],
            ['AWS_SECRET_ACCESS_KEY', $this->chars(40, self::B64, 'awssecret')],
            ['STRIPE_SECRET_KEY', 'sk_live_' . $this->chars(24, self::MIXED, 'envstripe')],
            ['MAIL_PASSWORD', $this->chars(18, self::MIXED, 'mailpw')],
        ];
    }
}
