<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Cmdi;

use Funnypot\App\Tarpit\Cmdi\AshVocabulary;
use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use PHPUnit\Framework\TestCase;

/**
 * The console's wording and lexer verdicts against busybox ash itself, from the fixtures that
 * scripts/bench/capture-ash-errors.sh records on Alpine 3.19 (whole stderr lines, prefix included).
 *
 * Before a capture exists the test is skipped. Once AshVocabulary::GOLDEN_VERIFIED is set it must
 * pass, so the flag cannot be flipped without fixtures. Whenever fixtures exist they are checked.
 */
final class AshVocabularyGoldenTest extends TestCase
{
    private const DIR = __DIR__ . '/../../../Fixtures/cmdi';

    /** @return array<string,list<string>> key => tab-separated fields after the key */
    private static function fixture(string $name): ?array
    {
        $path = self::DIR . '/' . $name;
        if (!is_file($path)) {
            return null;
        }
        $out = [];
        foreach (explode("\n", rtrim((string) file_get_contents($path), "\n")) as $line) {
            $parts = explode("\t", $line);
            $out[(string) array_shift($parts)] = $parts;
        }

        return $out;
    }

    private static function requireFixture(string $name): array
    {
        $f = self::fixture($name);
        if ($f === null) {
            if (AshVocabulary::GOLDEN_VERIFIED) {
                self::fail("GOLDEN_VERIFIED is set but tests/Fixtures/cmdi/{$name} is missing");
            }
            self::markTestSkipped("no golden capture yet: run scripts/bench/capture-ash-errors.sh (Docker, operator/CI) to create tests/Fixtures/cmdi/{$name}");
        }

        return $f;
    }

    public function test_every_message_is_the_line_ash_prints(): void
    {
        $golden = self::requireFixture('ash-errors.golden.txt');
        foreach (AshVocabulary::goldenProbes() as $key => [$payload, $msgId, $arg, $arg2]) {
            self::assertArrayHasKey($key, $golden, "capture is missing {$key}");
            self::assertSame($golden[$key][0] ?? '', AshVocabulary::render($msgId, $arg, $arg2), "{$key}: sh -c " . json_encode($payload));
        }
    }

    public function test_every_lexer_verdict_is_what_ash_decides(): void
    {
        $golden = self::requireFixture('ash-parse.golden.txt');
        foreach (require self::DIR . '/lexer-cases.php' as $key => [$input]) {
            self::assertArrayHasKey($key, $golden, "capture is missing {$key}");
            [$rc, $line] = $golden[$key] + [1 => ''];
            $lex = ShellLexer::lex($input);
            self::assertSame((int) $rc !== 0, $lex->trueDefect !== null, "{$key}: defect verdict for " . json_encode($input));
            if ($lex->trueDefect !== null) {
                self::assertSame($line, AshVocabulary::render($lex->trueDefect['id'], $lex->trueDefect['token']), "{$key}: the first error ash prints");
            }
        }
    }
}
