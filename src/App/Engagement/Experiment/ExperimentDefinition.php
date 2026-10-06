<?php

declare(strict_types=1);

namespace Funnypot\App\Engagement\Experiment;

/**
 * An immutable, fully-validated experiment definition (FP-0311 §2.1). Built only via fromLedgerEntry(),
 * which enforces the closed schema and verifies the stored config_hash against freshly recomputed
 * canonical bytes (constant-time). Downstream code receives this typed object, never a loose array it
 * could reinterpret.
 *
 * Semantic bytes = every field below EXCEPT config_hash, serialised in a FIXED order (§2.2): one JSON
 * object, fixed-order variant objects, integer weights, UTF-8, no insignificant whitespace,
 * JSON_UNESCAPED_SLASHES, and a trailing newline. Changing any semantic field (behaviour, eligibility,
 * safety gate, ordering, control identity, a weight) changes the hash and requires a NEW revision — so a
 * historical result keyed on (id, revision, config_hash) never silently changes meaning.
 */
final class ExperimentDefinition
{
    private const ID_RX = '/^[a-z][a-z0-9._-]{0,47}$/';
    private const VARIANT_ID_RX = '/^[a-z][a-z0-9._-]{0,31}$/';
    private const MAX_WEIGHT = 10000;
    private const MAX_WEIGHT_SUM = 40000;
    private const MIN_VARIANTS = 2;
    private const MAX_VARIANTS = 4;

    /** @param ExperimentVariant[] $variants ordered */
    private function __construct(
        public readonly string $experimentId,
        public readonly int $revision,
        public readonly string $seam,
        public readonly string $controlVariant,
        public readonly array $variants,
        public readonly string $eligibilityVersion,
        public readonly string $safetyContractVersion,
        public readonly string $configHash
    ) {
    }

    /**
     * Build + fully validate from one ledger entry (a decoded JSON object with the §2.1 fields plus
     * config_hash). Throws InvalidExperimentException on ANY violation; the registry drops such an entry.
     *
     * @param array<string,mixed> $e
     */
    public static function fromLedgerEntry(array $e): self
    {
        $allowed = [
            'experiment_id', 'revision', 'seam', 'control_variant', 'variants',
            'eligibility_version', 'safety_contract_version', 'config_hash',
        ];
        foreach (array_keys($e) as $k) {
            if (!in_array($k, $allowed, true)) {
                throw new InvalidExperimentException("unsupported key '{$k}'");
            }
        }

        $id = self::str($e, 'experiment_id');
        if (preg_match(self::ID_RX, $id) !== 1) {
            throw new InvalidExperimentException('bad experiment_id grammar');
        }
        $revision = self::intField($e, 'revision');
        if ($revision < 1 || $revision > 2147483647) {
            throw new InvalidExperimentException('revision out of range');
        }
        $seam = self::str($e, 'seam');
        if (preg_match(self::ID_RX, $seam) !== 1) {
            throw new InvalidExperimentException('bad seam grammar');
        }
        $eligibility = self::str($e, 'eligibility_version');
        $safety = self::str($e, 'safety_contract_version');
        if ($eligibility === '' || strlen($eligibility) > 64 || $safety === '' || strlen($safety) > 64) {
            throw new InvalidExperimentException('bad eligibility/safety id');
        }

        if (!isset($e['variants']) || !is_array($e['variants']) || !array_is_list($e['variants'])) {
            throw new InvalidExperimentException('variants must be an ordered list');
        }
        $count = count($e['variants']);
        if ($count < self::MIN_VARIANTS || $count > self::MAX_VARIANTS) {
            throw new InvalidExperimentException('variant count out of 2..4');
        }
        $variants = [];
        $seenIds = [];
        $sum = 0;
        foreach ($e['variants'] as $v) {
            if (!is_array($v)) {
                throw new InvalidExperimentException('variant must be an object');
            }
            foreach (array_keys($v) as $vk) {
                if (!in_array($vk, ['id', 'weight', 'implementation_id'], true)) {
                    throw new InvalidExperimentException("unsupported variant key '{$vk}'");
                }
            }
            $vid = self::str($v, 'id');
            if (preg_match(self::VARIANT_ID_RX, $vid) !== 1) {
                throw new InvalidExperimentException('bad variant id grammar');
            }
            if (isset($seenIds[$vid])) {
                throw new InvalidExperimentException('duplicate variant id');
            }
            $seenIds[$vid] = true;
            $weight = self::intField($v, 'weight');
            if ($weight < 1 || $weight > self::MAX_WEIGHT) {
                throw new InvalidExperimentException('variant weight out of 1..10000');
            }
            $sum += $weight;
            $impl = self::str($v, 'implementation_id');
            if ($impl === '' || strlen($impl) > 64) {
                throw new InvalidExperimentException('bad implementation_id');
            }
            $variants[] = new ExperimentVariant($vid, $weight, $impl);
        }
        if ($sum > self::MAX_WEIGHT_SUM) {
            throw new InvalidExperimentException('weight sum exceeds 40000');
        }

        $control = self::str($e, 'control_variant');
        if (!isset($seenIds[$control])) {
            throw new InvalidExperimentException('control_variant is not one of the variants');
        }

        $storedHash = self::str($e, 'config_hash');
        $def = new self($id, $revision, $seam, $control, $variants, $eligibility, $safety, $storedHash);

        // Recompute + constant-time compare: a tampered semantic field fails here.
        $expected = $def->expectedHash();
        if (!hash_equals($expected, strtolower($storedHash))) {
            throw new InvalidExperimentException('config_hash mismatch');
        }

        return $def;
    }

    /** "id@revision" — the tuple key used by activation and the ledger index. */
    public function tuple(): string
    {
        return $this->experimentId . '@' . $this->revision;
    }

    public function totalWeight(): int
    {
        $t = 0;
        foreach ($this->variants as $v) {
            $t += $v->weight;
        }

        return $t;
    }

    /**
     * The canonical semantic bytes (§2.2): fixed key order, integer weights, no insignificant whitespace,
     * unescaped slashes, trailing newline. Deterministic — the ledger hash is generated from exactly this.
     */
    public function canonicalBytes(): string
    {
        $obj = [
            'experiment_id' => $this->experimentId,
            'revision' => $this->revision,
            'seam' => $this->seam,
            'control_variant' => $this->controlVariant,
            'variants' => array_map(
                static fn (ExperimentVariant $v): array => [
                    'id' => $v->id,
                    'weight' => $v->weight,
                    'implementation_id' => $v->implementationId,
                ],
                $this->variants
            ),
            'eligibility_version' => $this->eligibilityVersion,
            'safety_contract_version' => $this->safetyContractVersion,
        ];

        return json_encode($obj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    }

    /** Lowercase SHA-256 of the canonical bytes. */
    public function expectedHash(): string
    {
        return strtolower(hash('sha256', $this->canonicalBytes()));
    }

    /** @param array<string,mixed> $a */
    private static function str(array $a, string $k): string
    {
        if (!isset($a[$k]) || !is_string($a[$k])) {
            throw new InvalidExperimentException("missing/non-string '{$k}'");
        }
        if (!mb_check_encoding($a[$k], 'UTF-8')) {
            throw new InvalidExperimentException("non-UTF-8 '{$k}'");
        }

        return $a[$k];
    }

    /** @param array<string,mixed> $a strict integer (reject float/string/bool so canonical bytes are stable) */
    private static function intField(array $a, string $k): int
    {
        if (!isset($a[$k]) || !is_int($a[$k])) {
            throw new InvalidExperimentException("missing/non-integer '{$k}'");
        }

        return $a[$k];
    }
}
