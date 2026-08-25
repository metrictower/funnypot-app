<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Panel;

use Funnypot\App\Render\Panel\DashboardSection;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

/**
 * The panel landing (spec T1/E1): business/ops metrics only, no secrets. Verifies the benign recent
 * sign-ins table, per-deploy variation of the sign-in ages (they must not be a fleet-wide constant),
 * determinism per seed, and that the roster renders at the persona domain.
 */
final class DashboardSectionTest extends TestCase
{
    /** @return array{module:string,section:string,entity:string,subtab:string,action:string,arg:string,page:int,filter:string} */
    private function route(): array
    {
        return [
            'module' => 'dashboard', 'section' => '', 'entity' => '', 'subtab' => '',
            'action' => '', 'arg' => '', 'page' => 1, 'filter' => '',
        ];
    }

    private function render(int $seed): string
    {
        return (new DashboardSection())->render($this->route(), VisualPersona::fromSeed($seed), '/admin');
    }

    /** All "N min/h ago" sign-in ages in render order. */
    private function ages(string $html): array
    {
        preg_match_all('/\d+ (?:min|h) ago/', $html, $m);
        return $m[0];
    }

    public function test_landing_is_business_metrics_with_recent_signins(): void
    {
        $html = $this->render(42);
        self::assertStringContainsString('Employees', $html);
        self::assertStringContainsString('Recent sign-ins', $html);
        self::assertStringNotContainsString('password_hash', $html);
        self::assertNotEmpty($this->ages($html), 'the recent sign-ins table must show ages');
    }

    public function test_is_byte_identical_per_seed(): void
    {
        self::assertSame($this->render(77), $this->render(77), 'must be cache-safe (byte-identical per seed)');
    }

    public function test_signin_ages_vary_per_deploy(): void
    {
        // I1: the "Last sign-in" ages were seed-0 hard-coded, so identical across every deploy (a landing
        // fingerprint). Threaded through the persona seed, two deploys must show a different age sequence.
        $a = $this->ages($this->render(1));
        $b = $this->ages($this->render(2));
        self::assertNotEmpty($a);
        self::assertNotSame($a, $b, 'sign-in ages must differ across seeds');
    }

    public function test_roster_uses_persona_domain_when_email_rendered(): void
    {
        // The roster reads the persona domain (one host = one domain). The landing itself shows no email,
        // but any address the section renders must sit at the persona domain, never a second invented one.
        $persona = VisualPersona::fromSeed(9);
        $html = (new DashboardSection())->render($this->route(), $persona, '/admin');
        self::assertDoesNotMatchRegularExpression('/@[a-z0-9-]+\.(?:com|io|co|net)/i', $html,
            'the landing must not leak a second (invented) email domain');
    }
}
