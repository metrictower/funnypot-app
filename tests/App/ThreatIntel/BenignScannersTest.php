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
        self::assertSame('Shadowserver', BenignScanners::match('184.105.10.20'));
    }

    public function test_ordinary_ip_is_not_a_scanner(): void
    {
        self::assertNull(BenignScanners::match('45.9.148.1'));
        self::assertNull(BenignScanners::match(''));
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
