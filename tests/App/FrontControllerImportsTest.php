<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use PHPUnit\Framework\TestCase;

/**
 * Deploy-safety guard for the front controllers. Neither the unit suite nor the Docker build ever
 * executes demo/index.php or demo/listen.php, so a stale/moved `use` import (e.g. the Funnypot\ ->
 * Funnypot\Core\ namespace migration) ships green and then throws an uncaught Error on every request —
 * a public PHP fatal. This test parses every `use ...;` import out of those entrypoints and asserts each
 * one actually resolves through the autoloader, catching a broken import before it can reach prod.
 */
final class FrontControllerImportsTest extends TestCase
{
    /** @return array<string,array{0:string}> */
    public static function entrypoints(): array
    {
        $root = dirname(__DIR__, 2);

        return [
            'demo/index.php' => [$root . '/demo/index.php'],
            'demo/listen.php' => [$root . '/demo/listen.php'],
        ];
    }

    /** @dataProvider entrypoints */
    public function test_every_use_import_resolves(string $file): void
    {
        self::assertFileExists($file);
        $src = (string) file_get_contents($file);

        $imports = self::classImports($src);
        self::assertNotEmpty($imports, "no class imports parsed from {$file} — parser or file changed");

        foreach ($imports as $fqcn) {
            self::assertTrue(
                class_exists($fqcn) || interface_exists($fqcn) || trait_exists($fqcn),
                "unresolved import in {$file}: `use {$fqcn};` — the class does not autoload "
                . '(a stale namespace after a migration would throw a public PHP fatal at runtime)'
            );
        }
    }

    /**
     * Class/interface/trait imports only — skips `use function` / `use const`, strips `as Alias`, and
     * ignores grouped/inline uses inside closures (the entrypoints use plain single-line imports).
     *
     * @return list<string>
     */
    private static function classImports(string $src): array
    {
        $out = [];
        if (preg_match_all('/^use\s+([^;]+);/m', $src, $m) === false) {
            return $out;
        }
        foreach ($m[1] as $clause) {
            $clause = trim($clause);
            if (stripos($clause, 'function ') === 0 || stripos($clause, 'const ') === 0) {
                continue; // symbol imports, not classes
            }
            // strip an `as Alias` suffix
            if (($pos = stripos($clause, ' as ')) !== false) {
                $clause = substr($clause, 0, $pos);
            }
            $clause = ltrim(trim($clause), '\\');
            if ($clause !== '' && strpos($clause, ',') === false) {
                $out[] = $clause;
            }
        }

        return $out;
    }
}
