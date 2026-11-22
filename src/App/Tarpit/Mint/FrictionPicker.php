<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Mint;

/**
 * Picks what a valid mint submission gets: success, or one plausible obstacle a real service shows
 * (a stale form, a lapsed session or confirm window, a throttle, an edit conflict, a transient save
 * failure). It runs only after every true check has passed.
 *
 * Each obstacle is eligible only when its story is true of the moment (the form really is two minutes
 * old, three mint posts really landed in ten minutes), and the caller turns the pick into a real state
 * change, so the next observation agrees with it. The pick is a keyed hash of a closed list of state
 * fields, the submission's shape and the recent outcomes: no source key, account serial, sid or name
 * feeds it, so the same history gives the same outcome on any source, and every outcome changes the
 * next pick's inputs, so a resend never cycles.
 */
final class FrictionPicker
{
    public const SUCCESS = 'success';
    public const KINDS = ['form_stale', 'session_lapsed', 'confirm_lapsed', 'throttled', 'edit_conflict', 'transient'];

    /** The only state fields the pick reads. */
    public const STATE_FIELDS = ['csrf_epoch', 'two_factor_enabled', 'confirm_active', 'rate_active', 'mint_posts_10min', 'successes_total', 'account_age_bucket'];

    private const WEIGHTS = [
        'form_stale' => 1.0,
        'session_lapsed' => 0.8,
        'confirm_lapsed' => 0.8,
        'throttled' => 0.6,
        'edit_conflict' => 0.7,
        'transient' => 0.4,
    ];

    public function __construct(private string $key, private bool $enabled = true)
    {
    }

    /**
     * The obstacles whose story is true right now.
     *
     * @param array{form_age:int,session_age:int,sensitive:bool,confirm_age:?int,mint_posts_10min:int,changed_since_form:bool} $facts
     * @return list<string>
     */
    public static function eligible(array $facts): array
    {
        $out = [];
        if ($facts['form_age'] >= 120) {
            $out[] = 'form_stale';
        }
        if ($facts['session_age'] >= 600) {
            $out[] = 'session_lapsed';
        }
        if ($facts['sensitive'] && $facts['confirm_age'] !== null && $facts['confirm_age'] >= 120) {
            $out[] = 'confirm_lapsed';
        }
        if ($facts['mint_posts_10min'] >= 3) {
            $out[] = 'throttled';
        }
        if ($facts['changed_since_form']) {
            $out[] = 'edit_conflict';
        }
        $out[] = 'transient';

        return $out;
    }

    /**
     * Digest of the closed state field list. Any other key in $state is ignored.
     *
     * @param array<string,int|bool> $state
     */
    public static function stateDigest(array $state): string
    {
        $parts = [];
        foreach (self::STATE_FIELDS as $f) {
            $v = $state[$f] ?? 0;
            $parts[] = $f . '=' . (is_bool($v) ? ($v ? '1' : '0') : (string) (int) $v);
        }

        return implode(';', $parts);
    }

    /**
     * @param array<string,int|bool> $state   closed fields, see STATE_FIELDS
     * @param list<string> $eligible          from eligible()
     * @param list<string> $history           the account's recent outcome kinds, oldest first
     */
    public function pick(array $state, string $submissionShape, array $history, array $eligible, bool $sensitive): string
    {
        if (!$this->enabled) {
            return self::SUCCESS;
        }
        $recent = array_slice($history, -4);
        $lastPhantom = null;
        for ($i = count($history) - 1; $i >= 0; $i--) {
            if ($history[$i] !== self::SUCCESS) {
                $lastPhantom = $history[$i];
                break;
            }
        }
        $candidates = [self::SUCCESS => $sensitive ? 0.5 : 1.0];
        foreach (self::KINDS as $kind) {
            if (!in_array($kind, $eligible, true) || $kind === $lastPhantom) {
                continue;
            }
            $w = self::WEIGHTS[$kind];
            if (in_array($kind, $recent, true)) {
                $w *= 0.3;
            }
            $candidates[$kind] = $w;
        }
        $u = $this->unit(self::stateDigest($state) . '|' . $submissionShape . '|' . implode(',', $recent));
        $total = array_sum($candidates);
        $acc = 0.0;
        foreach ($candidates as $kind => $w) {
            $acc += $w;
            if ($u * $total < $acc) {
                return $kind;
            }
        }

        return self::SUCCESS;
    }

    /** A second deterministic draw on the same inputs, for the throttle length. */
    public function draw(string $label, array $state, string $submissionShape, array $history, int $n): int
    {
        $u = $this->unit($label . '|' . self::stateDigest($state) . '|' . $submissionShape . '|' . implode(',', array_slice($history, -4)));

        return min($n - 1, (int) floor($u * $n));
    }

    /** A value in [0, 1) from a keyed hash. */
    private function unit(string $input): float
    {
        $h = hash_hmac('sha256', $input, $this->key);

        return hexdec(substr($h, 0, 13)) / 4503599627370496.0;
    }
}
