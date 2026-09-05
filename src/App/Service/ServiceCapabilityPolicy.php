<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * Target support, resolved app-feature capabilities and the hard environment ceilings a stored/admin
 * profile can never widen. A web-backed service does not own its underlying feature toggle: this
 * policy only reports whether a capability is currently enabled; the operator flips the feature
 * through the existing config/restart path and reapplies, avoiding a torn cross-store write.
 *
 * Hard ceilings (always win over a stored profile):
 *   - FUNNYPOT_PROTOCOLS=0        -> no non-canonical service may run at all
 *   - FUNNYPOT_SERVICE_ALLOWED_IDS-> optional allowlist of selectable ids
 *   - FUNNYPOT_SERVICE_MAX_EXPOSURE_CEILING -> optional hard cap on max_exposure
 */
final class ServiceCapabilityPolicy
{
    /**
     * @param array<string,bool> $capabilities capability name => enabled
     * @param list<string>|null  $allowedIds   null = no allowlist
     */
    private function __construct(
        public readonly string $target,
        private array $capabilities,
        private bool $protocolsDisabled,
        private ?array $allowedIds,
        private ?int $maxExposureCeiling,
    ) {
    }

    /**
     * @param array<string,bool> $capabilities
     * @param list<string>|null  $allowedIds
     */
    public static function create(string $target, array $capabilities, bool $protocolsDisabled = false, ?array $allowedIds = null, ?int $maxExposureCeiling = null): self
    {
        return new self($target, $capabilities, $protocolsDisabled, $allowedIds, $maxExposureCeiling);
    }

    /**
     * Build from the resolved app feature flags and the raw environment ceilings.
     *
     * @param callable(string):(string|false) $env
     */
    public static function fromEnvironment(string $target, bool $dockerApiEnabled, callable $env): self
    {
        $protocols = $env('FUNNYPOT_PROTOCOLS');
        $protocolsDisabled = is_string($protocols) && $protocols === '0';

        $allowed = null;
        $allowedRaw = $env('FUNNYPOT_SERVICE_ALLOWED_IDS');
        if (is_string($allowedRaw) && $allowedRaw !== '') {
            $allowed = array_values(array_filter(array_map('trim', explode(',', $allowedRaw)), static fn (string $s): bool => $s !== ''));
        }

        $ceiling = null;
        $ceilingRaw = $env('FUNNYPOT_SERVICE_MAX_EXPOSURE_CEILING');
        if (is_string($ceilingRaw) && ctype_digit($ceilingRaw)) {
            $ceiling = (int) $ceilingRaw;
        }

        return new self($target, ['docker' => $dockerApiEnabled], $protocolsDisabled, $allowed, $ceiling);
    }

    public function capabilityEnabled(string $capability): bool
    {
        return $this->capabilities[$capability] ?? false;
    }

    public function protocolsDisabled(): bool
    {
        return $this->protocolsDisabled;
    }

    public function idAllowed(string $id): bool
    {
        return $this->allowedIds === null || in_array($id, $this->allowedIds, true);
    }

    public function maxExposureCeiling(): ?int
    {
        return $this->maxExposureCeiling;
    }

    /** A service published for this target only if any of its endpoints target it. */
    public function endpointOnTarget(ServiceEndpoint $ep): bool
    {
        return $ep->publishedOn($this->target);
    }
}
