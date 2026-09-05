<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use InvalidArgumentException;

/**
 * The one typed, closed-vocabulary desired input an operator or startup environment may submit. It
 * carries no port number, bind address, command, path or ranking key — only ids from the catalog and
 * a bounded exposure budget. Malformed, oversized or shape-inconsistent input is rejected here before
 * anything is resolved or written.
 */
final class ServiceProfileInput
{
    public const SCHEMA = 'funnypot-service-profile-input/v1';
    public const MODES = ['named', 'manual', 'all'];
    public const MAX_JSON_BYTES = 32768;
    private const ID_RE = '/^[a-z0-9][a-z0-9-]*$/';

    /**
     * @param list<string>              $manualServiceIds sorted, unique (manual mode)
     * @param array<string,string>      $conflictVariants group id => chosen member id (all mode)
     */
    private function __construct(
        public readonly string $mode,
        public readonly ?string $bundleId,
        public readonly ?string $baseFamily,
        public readonly array $manualServiceIds,
        public readonly array $conflictVariants,
        public readonly int $maxExposure,
    ) {
    }

    /**
     * @param array<string,mixed> $a
     * @throws InvalidArgumentException with a ServiceResolutionReason code as message
     */
    public static function fromArray(array $a): self
    {
        $mode = $a['mode'] ?? null;
        if (!is_string($mode) || !in_array($mode, self::MODES, true)) {
            throw new InvalidArgumentException(ServiceResolutionReason::MODE_INVALID);
        }
        $maxExposure = $a['max_exposure'] ?? 0;
        if (!is_int($maxExposure) && !(is_string($maxExposure) && ctype_digit($maxExposure))) {
            throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
        }
        $maxExposure = (int) $maxExposure;
        if ($maxExposure < 0 || $maxExposure > 65535) {
            throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
        }

        $bundleId = null;
        $baseFamily = null;
        $manual = [];
        $variants = [];

        if ($mode === 'named') {
            $bundleId = $a['bundle_id'] ?? null;
            if (!is_string($bundleId) || preg_match(self::ID_RE, $bundleId) !== 1) {
                throw new InvalidArgumentException(ServiceResolutionReason::BUNDLE_UNKNOWN);
            }
            self::rejectExtras($a, ['mode', 'bundle_id', 'max_exposure', 'schema']);
        } else {
            $baseFamily = $a['base_family'] ?? null;
            if (!is_string($baseFamily) || preg_match(self::ID_RE, $baseFamily) !== 1) {
                throw new InvalidArgumentException(ServiceResolutionReason::BASE_FAMILY_MISSING);
            }
            if ($mode === 'manual') {
                $ids = $a['manual_service_ids'] ?? null;
                if (!is_array($ids)) {
                    throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
                }
                $seen = [];
                foreach ($ids as $id) {
                    if (!is_string($id) || preg_match(self::ID_RE, $id) !== 1) {
                        throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
                    }
                    if (isset($seen[$id])) {
                        throw new InvalidArgumentException(ServiceResolutionReason::DUPLICATE_ID);
                    }
                    $seen[$id] = true;
                    $manual[] = $id;
                }
                sort($manual);
                self::rejectExtras($a, ['mode', 'base_family', 'manual_service_ids', 'max_exposure', 'schema']);
            } else { // all
                $cv = $a['conflict_variants'] ?? [];
                if (!is_array($cv)) {
                    throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
                }
                foreach ($cv as $group => $member) {
                    if (!is_string($group) || preg_match(self::ID_RE, $group) !== 1
                        || !is_string($member) || preg_match(self::ID_RE, $member) !== 1) {
                        throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
                    }
                    $variants[$group] = $member;
                }
                ksort($variants);
                self::rejectExtras($a, ['mode', 'base_family', 'conflict_variants', 'max_exposure', 'schema']);
            }
        }

        return new self($mode, $bundleId, $baseFamily, $manual, $variants, $maxExposure);
    }

    /**
     * @throws InvalidArgumentException ServiceResolutionReason::INPUT_TOO_LARGE / INPUT_MALFORMED
     */
    public static function fromJson(string $json): self
    {
        if (strlen($json) > self::MAX_JSON_BYTES) {
            throw new InvalidArgumentException(ServiceResolutionReason::INPUT_TOO_LARGE);
        }
        $a = json_decode($json, true);
        if (!is_array($a)) {
            throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
        }

        return self::fromArray($a);
    }

    /**
     * First-boot environment aggregate. Returns null when no service env is set at all (so the caller
     * falls through to the seeded bootstrap chooser); throws on a partial/inapplicable combination.
     *
     * @param callable(string):(string|false) $env
     */
    public static function fromEnvironment(callable $env): ?self
    {
        $mode = $env('FUNNYPOT_SERVICE_MODE');
        if (!is_string($mode) || $mode === '') {
            return null;
        }
        $a = ['mode' => $mode];
        $bundle = $env('FUNNYPOT_SERVICE_BUNDLE');
        $family = $env('FUNNYPOT_SERVICE_BASE_FAMILY');
        $ids = $env('FUNNYPOT_SERVICE_IDS');
        $variants = $env('FUNNYPOT_SERVICE_CONFLICT_VARIANTS');
        $max = $env('FUNNYPOT_SERVICE_MAX_EXPOSURE');
        if (is_string($bundle) && $bundle !== '') {
            $a['bundle_id'] = $bundle;
        }
        if (is_string($family) && $family !== '') {
            $a['base_family'] = $family;
        }
        if (is_string($ids) && $ids !== '') {
            $a['manual_service_ids'] = array_values(array_filter(array_map('trim', explode(',', $ids)), static fn (string $s): bool => $s !== ''));
        }
        if (is_string($variants) && $variants !== '') {
            $map = [];
            foreach (explode(',', $variants) as $pair) {
                $kv = explode('=', $pair, 2);
                if (count($kv) === 2) {
                    $map[trim($kv[0])] = trim($kv[1]);
                }
            }
            $a['conflict_variants'] = $map;
        }
        if (is_string($max) && $max !== '') {
            $a['max_exposure'] = ctype_digit($max) ? (int) $max : $max;
        }

        return self::fromArray($a);
    }

    /** @return array<string,mixed> the canonical input for hashing/audit (ranking key never included) */
    public function toArray(): array
    {
        $out = ['schema' => self::SCHEMA, 'mode' => $this->mode, 'max_exposure' => $this->maxExposure];
        if ($this->mode === 'named') {
            $out['bundle_id'] = $this->bundleId;
        } else {
            $out['base_family'] = $this->baseFamily;
            if ($this->mode === 'manual') {
                $out['manual_service_ids'] = $this->manualServiceIds;
            } else {
                $out['conflict_variants'] = $this->conflictVariants;
            }
        }

        return $out;
    }

    public function canonicalJson(): string
    {
        return CanonicalJson::encode($this->toArray());
    }

    /**
     * @param array<string,mixed> $a
     * @param list<string>        $allowed
     */
    private static function rejectExtras(array $a, array $allowed): void
    {
        foreach (array_keys($a) as $k) {
            if (!in_array($k, $allowed, true)) {
                throw new InvalidArgumentException(ServiceResolutionReason::INPUT_MALFORMED);
            }
        }
    }
}
