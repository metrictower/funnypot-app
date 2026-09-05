<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * demo/docker-compose.yml runs the identity preflight as a no-network one-shot on the SAME volume
 * the public service uses, and the public service cannot start unless it succeeded.
 */
final class ComposeBootstrapTest extends TestCase
{
    public function test_prepare_one_shot_gates_the_public_service(): void
    {
        $doc = Yaml::parseFile(dirname(__DIR__, 3) . '/demo/docker-compose.yml');
        $prep = $doc['services']['funnypot-prepare'] ?? null;
        $pub = $doc['services']['funnypot'] ?? null;
        self::assertIsArray($prep, 'funnypot-prepare service');
        self::assertIsArray($pub, 'funnypot service');

        self::assertSame('none', $prep['network_mode'] ?? null, 'preflight has no network');
        self::assertArrayNotHasKey('ports', $prep, 'preflight publishes no port');
        self::assertSame(['php', '/app/bin/funnypot', 'identity:prepare'], $prep['entrypoint'] ?? null, 'exact entrypoint/argv separation');
        self::assertSame($pub['volumes'], $prep['volumes'], 'same persistent volume as the public service');
        self::assertSame(['funnypot-storage:/app/demo/storage'], $prep['volumes']);
        self::assertSame($pub['image'] ?? null, $prep['image'] ?? null, 'same built image');
        self::assertSame($pub['build'] ?? null, $prep['build'] ?? null);

        self::assertSame(
            'service_completed_successfully',
            $pub['depends_on']['funnypot-prepare']['condition'] ?? null,
            'the public service must depend on a SUCCESSFUL preflight'
        );
        self::assertArrayNotHasKey('restart', $prep, 'a failing preflight must not be restarted into success');
        foreach ($prep as $k => $v) {
            self::assertArrayNotHasKey('environment', $prep, 'no identity input is placed in compose environment');
        }
    }
}
