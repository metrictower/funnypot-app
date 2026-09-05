<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\ServiceProfileInput;
use Funnypot\App\Service\ServiceResolutionReason;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ServiceProfileInputTest extends TestCase
{
    public function testNamedInputCanonicalizes(): void
    {
        $in = ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'max_exposure' => 5]);
        self::assertSame('named', $in->mode);
        self::assertSame('linux-web', $in->bundleId);
        self::assertSame(['schema' => ServiceProfileInput::SCHEMA, 'mode' => 'named', 'max_exposure' => 5, 'bundle_id' => 'linux-web'], $in->toArray());
    }

    public function testManualSortsIdsAndRejectsDuplicates(): void
    {
        $in = ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'linux', 'manual_service_ids' => ['smb', 'adb'], 'max_exposure' => 5]);
        self::assertSame(['adb', 'smb'], $in->manualServiceIds);
        $this->expectException(InvalidArgumentException::class);
        ServiceProfileInput::fromArray(['mode' => 'manual', 'base_family' => 'linux', 'manual_service_ids' => ['smb', 'smb'], 'max_exposure' => 5]);
    }

    public function testModeShapeMismatchIsRejected(): void
    {
        // named must not carry manual ids
        $this->expectException(InvalidArgumentException::class);
        ServiceProfileInput::fromArray(['mode' => 'named', 'bundle_id' => 'linux-web', 'manual_service_ids' => ['ssh'], 'max_exposure' => 5]);
    }

    public function testMissingBaseFamilyForManualIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ServiceProfileInput::fromArray(['mode' => 'manual', 'manual_service_ids' => ['ssh'], 'max_exposure' => 5]);
    }

    public function testInvalidModeIsRejected(): void
    {
        $this->expectExceptionMessage(ServiceResolutionReason::MODE_INVALID);
        ServiceProfileInput::fromArray(['mode' => 'bananas', 'max_exposure' => 1]);
    }

    public function testOversizedJsonIsRejected(): void
    {
        $this->expectExceptionMessage(ServiceResolutionReason::INPUT_TOO_LARGE);
        ServiceProfileInput::fromJson('{"mode":"manual","base_family":"linux","manual_service_ids":["' . str_repeat('a', 33000) . '"]}');
    }

    public function testAllModeConflictVariantsAreSortedAndValidated(): void
    {
        $in = ServiceProfileInput::fromArray(['mode' => 'all', 'base_family' => 'devops', 'conflict_variants' => ['docker-api' => 'docker-api-2375'], 'max_exposure' => 100]);
        self::assertSame(['docker-api' => 'docker-api-2375'], $in->conflictVariants);
    }

    public function testFromEnvironmentReturnsNullWithoutMode(): void
    {
        self::assertNull(ServiceProfileInput::fromEnvironment(static fn (string $k) => false));
    }

    public function testFromEnvironmentBuildsNamed(): void
    {
        $env = static fn (string $k) => match ($k) {
            'FUNNYPOT_SERVICE_MODE' => 'named',
            'FUNNYPOT_SERVICE_BUNDLE' => 'linux-web',
            'FUNNYPOT_SERVICE_MAX_EXPOSURE' => '8',
            default => false,
        };
        $in = ServiceProfileInput::fromEnvironment($env);
        self::assertNotNull($in);
        self::assertSame('named', $in->mode);
        self::assertSame('linux-web', $in->bundleId);
        self::assertSame(8, $in->maxExposure);
    }

    public function testFromEnvironmentParsesManualIdsAndVariants(): void
    {
        $env = static fn (string $k) => match ($k) {
            'FUNNYPOT_SERVICE_MODE' => 'all',
            'FUNNYPOT_SERVICE_BASE_FAMILY' => 'devops',
            'FUNNYPOT_SERVICE_CONFLICT_VARIANTS' => 'docker-api=docker-api-2375',
            'FUNNYPOT_SERVICE_MAX_EXPOSURE' => '100',
            default => false,
        };
        $in = ServiceProfileInput::fromEnvironment($env);
        self::assertSame(['docker-api' => 'docker-api-2375'], $in->conflictVariants);
    }
}
