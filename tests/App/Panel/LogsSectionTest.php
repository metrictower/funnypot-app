<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\App\Render\Panel\LogsSection;
use Funnypot\App\Render\PanelRoute;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * The auth.log card's path must match the OS this seed's ServerProfile picked (RHEL-family logs to
 * /var/log/secure, Debian-family to /var/log/auth.log) — a hardcoded path regardless of OS is a tell.
 */
final class LogsSectionTest extends TestCase
{
    private function render(int $seed): string
    {
        $route = PanelRoute::parse('/admin/logs');
        return (new LogsSection())->render($route, VisualPersona::fromSeed($seed), '/admin');
    }

    public function test_auth_log_path_matches_the_hosts_own_os(): void
    {
        for ($seed = 1; $seed <= 30; $seed++) {
            $expected = ServerProfile::fromSeed($seed)->authLogPath();
            $html = $this->render($seed);
            self::assertStringContainsString($expected, $html, "seed {$seed}: auth.log card must show its own host's path");
            // Only ONE of the two paths should appear — never both (that would itself be ambiguous).
            $other = $expected === '/var/log/secure' ? '/var/log/auth.log' : '/var/log/secure';
            self::assertStringNotContainsString($other, $html, "seed {$seed}: must not also show the other family's path");
        }
    }

    public function test_is_byte_identical_per_seed(): void
    {
        self::assertSame($this->render(77), $this->render(77));
    }
}
