<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\ThreatIntel;

use Funnypot\App\ThreatIntel\BenignScanners;
use PHPUnit\Framework\TestCase;

/**
 * The benign-scanner never-report allowlist (FP-0247, Fix C). match() returns the org label for a
 * known research scanner, null otherwise. The resource file is validated for CIDR shape so a typo
 * cannot silently disable an entry.
 */
final class BenignScannersTest extends TestCase
{
    public function test_known_scanner_matches_with_org_label(): void
    {
        self::assertSame('Censys', BenignScanners::match('162.142.125.10'));
        // FP-0247 (fable #2): the Shadowserver exemption is now its narrow /24, not the whole HE block.
        self::assertSame('Shadowserver', BenignScanners::match('74.82.47.10'));
    }

    public function test_ordinary_ip_is_not_a_scanner(): void
    {
        self::assertNull(BenignScanners::match('45.9.148.1'));
        self::assertNull(BenignScanners::match(''));
    }

    /**
     * FP-0247 (fable #2): the broad Hurricane Electric parent blocks were removed from the Shadowserver
     * entry — HE is a large transit provider, so exempting a whole /16-/17 gave every attacker renting
     * that space a free pass. An HE-block address that is NOT in Shadowserver's narrow /24 must now be
     * reportable (fail-safe: a benign-scanner exemption lost is safer than an attacker exempted).
     */
    public function test_broad_he_blocks_are_no_longer_exempted(): void
    {
        self::assertNull(BenignScanners::match('184.105.10.20'));   // was 184.105.0.0/16
        self::assertNull(BenignScanners::match('64.62.200.1'));     // was 64.62.128.0/17
        self::assertNull(BenignScanners::match('216.218.200.1'));   // was 216.218.128.0/17
    }

    public function test_resource_file_shapes_are_valid_cidrs_or_ips(): void
    {
        $data = require dirname(__DIR__, 3) . '/resources/benign-scanners.php';
        self::assertIsArray($data);
        self::assertNotSame([], $data);
        foreach ($data as $org => $ranges) {
            self::assertIsString($org);
            self::assertIsArray($ranges);
            foreach ($ranges as $entry) {
                self::assertIsString($entry);
                if (strpos($entry, '/') !== false) {
                    [$net, $bits] = explode('/', $entry, 2);
                    self::assertNotFalse(filter_var($net, FILTER_VALIDATE_IP), "bad network in {$org}: {$entry}");
                    self::assertTrue(ctype_digit($bits), "bad prefix in {$org}: {$entry}");
                    self::assertLessThanOrEqual(128, (int) $bits, "prefix too large in {$org}: {$entry}");
                } else {
                    self::assertNotFalse(filter_var($entry, FILTER_VALIDATE_IP), "bad IP in {$org}: {$entry}");
                }
            }
        }
    }
}
