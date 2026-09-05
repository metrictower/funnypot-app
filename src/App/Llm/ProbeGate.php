<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use Funnypot\App\Storage\HitStore;

/**
 * The LLM decision gate: both checks AND'd, default-deny. Invoke the model only when the IP is not
 * bulk-scanning (Gate A) AND the path is positively a plausible app path (Gate B). Everything else
 * gets the existing byte-identical plain 404.
 *
 * Gate A has two layers: a persistent pin (an IP that tripped the velocity window stays blocked for
 * a cooldown even after it goes quiet, so it cannot burst then slow-probe) and the live sliding
 * window that trips the pin. Behind both sits the global generations/hour budget: Gate A is per-IP,
 * so a rotating-IP flood never trips it — the budget is what bounds that case.
 */
final class ProbeGate
{
    /**
     * @param int      $pinHours how long a tripped IP stays pinned to plain-404 (the bulk-scan cooldown)
     * @param string[] $allowIps IPs / IPv4 CIDRs exempt from Gate A (velocity + pin + budget). For
     *                           operator testing: an allowlisted IP can generate unlimited fakes and is
     *                           never pinned. Gate B (plausibility) still applies. Keep empty in normal prod.
     * @param LlmGenBudget|null $budget the global generations/hour ledger; exhausted ⇒ deny (cache-only)
     */
    public function __construct(
        private ProbeClassifier $lexical,
        private VelocityTracker $velocity,
        private HitStore $store,
        private int $pinHours = 24,
        private array $allowIps = [],
        private ?LlmGenBudget $budget = null,
    ) {
    }

    /**
     * @return array{generate:bool,reason:string} reason is logged so the gate can be tuned on real traffic
     */
    public function decide(string $method, string $path, string $ip): array
    {
        // Gate A (per-IP velocity + pin) is skipped for allowlisted operator IPs so they can test
        // freely; the pin check is skipped too, so an already-pinned test IP recovers immediately.
        $exempt = self::ipMatches($ip, $this->allowIps);
        if (!$exempt) {
            if ($this->store->isBulkFlagged($ip)) {
                return ['generate' => false, 'reason' => 'bulk-scan-pinned'];
            }
            if ($this->velocity->isBulkScan($this->store->probeVelocity($ip))) {
                $this->store->flagBulkScan($ip, $this->pinHours);  // pin so a quiet-then-probe cannot dodge it
                return ['generate' => false, 'reason' => 'bulk-scan'];
            }
            // After the pin/velocity block so a bulk scanner is still pinned while the hour is spent.
            // Fail-closed inside exhausted(): a ledger fault stops fresh generation, never cached serving.
            if ($this->budget !== null && $this->budget->exhausted()) {
                return ['generate' => false, 'reason' => 'gen-budget'];
            }
        }
        if ($this->lexical->classify($method, $path) !== 'plausible') {
            return ['generate' => false, 'reason' => 'probe'];
        }

        return ['generate' => true, 'reason' => $exempt ? 'allowlisted' : 'plausible'];
    }

    /** True if $ip exactly equals, or falls inside an IPv4 CIDR from, any entry in $list. */
    private static function ipMatches(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            if ($entry === $ip) {
                return true;
            }
            if (strpos($entry, '/') !== false && self::inCidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    /** IPv4 CIDR membership. Non-IPv4 inputs never match. */
    private static function inCidr(string $ip, string $cidr): bool
    {
        [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, '32');
        $ipL = ip2long($ip);
        $netL = ip2long($net);
        $bits = (int) $bits;
        if ($ipL === false || $netL === false || $bits < 0 || $bits > 32) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask = -1 << (32 - $bits);

        return ($ipL & $mask) === ($netL & $mask);
    }
}
