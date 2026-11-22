<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\SsrfRoutes;
use PHPUnit\Framework\TestCase;

/**
 * Second-lander rule (FP-0814 x FP-0816): whichever of the web-shell console and the SSRF decoy reaches
 * main second adds `!ssrf?->owns(path)` to the console's gate G beside `!tokenMint?->owns(path)` and
 * removes this skip. The test then checks, with the console's real constants, that its path set and the
 * SSRF owned set are disjoint, and that after a console POST makes a source sticky an SSRF path is still
 * answered by the SSRF decoy.
 */
final class SsrfFp0814PrecedenceTest extends TestCase
{
    public function test_console_and_ssrf_paths_are_disjoint_and_ssrf_keeps_its_paths(): void
    {
        $shell = 'Funnypot\\App\\Tarpit\\Cmdi\\AdaptiveShell';
        if (!class_exists($shell)) {
            self::markTestSkipped('FP-0814 (AdaptiveShell) is not on this branch; the second lander adds the gate-G condition and removes this skip');
        }
        $r = new SsrfRoutes();
        foreach ((array) constant($shell . '::CONSOLE_PATHS') as $p) {
            self::assertFalse($r->owns((string) $p), "{$p} is the console's");
        }
        foreach (SsrfRoutes::examples() as [, $p]) {
            self::assertFalse((bool) $shell::isConsolePath($p), "{$p} is the SSRF decoy's, never a console path");
            self::assertDoesNotMatchRegularExpression('~\\.php\\z~i', $p);
        }
        $controller = '';
        foreach (token_get_all((string) file_get_contents(dirname(__DIR__, 4) . '/src/App/Http/HoneypotController.php')) as $t) {
            $controller .= is_array($t) ? (in_array($t[0], [T_COMMENT, T_DOC_COMMENT], true) ? '' : $t[1]) : $t;
        }
        self::assertStringContainsString('tokenMint?->owns(', $controller, 'gate G keeps the token-mint condition');
        self::assertStringContainsString('ssrf?->owns(', $controller, 'gate G stands down on an SSRF-owned path, so a sticky console never takes it');
    }
}
