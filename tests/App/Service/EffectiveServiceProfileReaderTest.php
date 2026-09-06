<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\EffectiveServiceProfileReader;
use PHPUnit\Framework\TestCase;

/**
 * The request-path seam must never throw: a malformed environment can make path resolution itself
 * fail before {@see EffectiveServiceProfileReader::profile()} could guard it, which at the front
 * controller would be an attacker-facing 500 tell. It degrades to the family-neutral profile instead.
 */
final class EffectiveServiceProfileReaderTest extends TestCase
{
    public function testMalformedStatusDirEnvDegradesToFamilyNeutralInsteadOfThrowing(): void
    {
        // '..' is rejected by ServicePaths::fromEnvironment, so fromEnvironment() itself throws.
        $env = static fn (string $k): string|false => $k === 'FUNNYPOT_SERVICE_STATUS_DIR' ? '../evil' : false;

        $profile = EffectiveServiceProfileReader::profileFromEnvironment(sys_get_temp_dir(), $env);

        self::assertSame('neutral', $profile->baseFamily());
    }

    public function testMissingStatusFileDegradesToFamilyNeutral(): void
    {
        $dir = sys_get_temp_dir() . '/fp-esr-' . bin2hex(random_bytes(6));
        mkdir($dir, 0777, true);
        try {
            $env = static fn (string $k): string|false => $k === 'FUNNYPOT_DB' ? $dir . '/funnypot.sqlite' : false;
            $profile = EffectiveServiceProfileReader::profileFromEnvironment($dir, $env);
            self::assertSame('neutral', $profile->baseFamily());
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }
}
