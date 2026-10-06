<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

use Funnypot\App\Http\StackHeaderGuard;
use PHPUnit\Framework\TestCase;

final class StackHeaderGuardTest extends TestCase
{
    /** @return array{set: array<string,string>, removed: string[]} */
    private function drive(string $banner): array
    {
        $set = [];
        $removed = [];
        StackHeaderGuard::apply(
            static function (string $name, string $value) use (&$set): void { $set[$name] = $value; },
            static function (string $name) use (&$removed): void { $removed[] = $name; },
            $banner
        );

        return ['set' => $set, 'removed' => $removed];
    }

    public function test_forces_the_configured_server_banner(): void
    {
        $r = $this->drive('nginx/9.9.9');
        self::assertSame('nginx/9.9.9', $r['set']['Server']);
    }

    public function test_empty_banner_uses_the_built_in_default(): void
    {
        $r = $this->drive('');
        self::assertSame(StackHeaderGuard::DEFAULT_SERVER, $r['set']['Server']);
        self::assertStringStartsWith('nginx/', $r['set']['Server'], 'default is nginx-coherent with the believable-404 body');
    }

    public function test_strips_the_whole_stack_identifier_family(): void
    {
        $r = $this->drive('nginx/1.0');
        foreach (StackHeaderGuard::FAMILY as $name) {
            self::assertContains($name, $r['removed'], "{$name} must be stripped");
        }
        // The real-stack leak vectors are covered.
        self::assertContains('X-AspNet-Version', $r['removed']);
        self::assertContains('X-Runtime', $r['removed']);
        self::assertContains('Via', $r['removed']);
    }

    public function test_does_not_strip_functional_or_persona_headers(): void
    {
        // The normalizer must NOT allowlist: deception/core headers survive. None of these appears in
        // the strip list, so apply() never removes them.
        foreach ([
            'WWW-Authenticate', 'Allow', 'Accept-Ranges', 'Content-Range', 'X-Accel-Buffering',
            'Service-Worker-Allowed', 'Set-Cookie', 'Location', 'Content-Type', 'Cache-Control',
            'Referrer-Policy',
        ] as $keep) {
            self::assertNotContains($keep, StackHeaderGuard::FAMILY, "{$keep} must NOT be stripped");
        }
    }

    public function test_does_not_touch_x_powered_by(): void
    {
        // X-Powered-By is handled at the front controller (top-level header_remove + persona override),
        // never by the normalizer — so it is neither forced nor in the strip list here.
        $r = $this->drive('nginx/1.0');
        self::assertArrayNotHasKey('X-Powered-By', $r['set']);
        self::assertNotContains('X-Powered-By', $r['removed']);
        self::assertNotContains('X-Powered-By', StackHeaderGuard::FAMILY);
        // And Server is never in the strip list (it is forced, not removed).
        self::assertNotContains('Server', StackHeaderGuard::FAMILY);
    }

    public function test_register_is_idempotent_and_safe(): void
    {
        StackHeaderGuard::resetForTests();
        StackHeaderGuard::register('nginx/1.0');
        StackHeaderGuard::register('nginx/1.0'); // second call is a no-op, must not throw
        self::assertTrue(true);
        StackHeaderGuard::resetForTests();
    }
}
