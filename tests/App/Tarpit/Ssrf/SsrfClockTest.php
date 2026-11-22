<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use PHPUnit\Framework\TestCase;

/**
 * The SSRF namespaces read no clock and draw no randomness: time comes only from the token-mint
 * surface's injected clock. A second, explicit list next to the allowlist, each entry with a planted
 * positive control.
 */
final class SsrfClockTest extends TestCase
{
    private const FORBIDDEN = ['time', 'hrtime', 'microtime', 'usleep', 'sleep', 'time_nanosleep', 'strtotime', 'mktime', 'gmmktime', 'gettimeofday',
        'uniqid', 'random_int', 'random_bytes', 'mt_rand', 'rand', 'shuffle', 'array_rand', 'str_shuffle', 'lcg_value', 'mt_srand', 'srand'];

    /** @return list<string> the clock and randomness uses in one source */
    public static function uses(string $code): array
    {
        $out = [];
        $toks = CallScan::tokens($code);
        foreach ($toks as $i => [$id, $text]) {
            $next = $toks[$i + 1][0] ?? null;
            $prev = $toks[$i - 1][0] ?? null;
            if ($id === T_STRING && $next === '(' && !in_array($prev, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true)) {
                $fn = strtolower(ltrim($text, '\\'));
                if (in_array($fn, self::FORBIDDEN, true)) {
                    $out[] = $fn;
                }
                if (in_array($fn, ['date', 'gmdate'], true)) {
                    $depth = 0;
                    $commas = 0;
                    for ($j = $i + 1; $j < count($toks); $j++) {
                        $t = $toks[$j][0];
                        if ($t === '(' || $t === '[') {
                            $depth++;
                        } elseif ($t === ')' || $t === ']') {
                            if (--$depth === 0) {
                                break;
                            }
                        } elseif ($t === ',' && $depth === 1) {
                            $commas++;
                        }
                    }
                    if ($commas === 0) {
                        $out[] = $fn . ' without a timestamp';
                    }
                }
            }
            if ($id === T_NEW && in_array(strtolower(ltrim((string) ($toks[$i + 1][1] ?? ''), '\\')), ['datetime', 'datetimeimmutable'], true)) {
                $out[] = 'new ' . ltrim((string) $toks[$i + 1][1], '\\');
            }
            if ($id === T_CONSTANT_ENCAPSED_STRING && preg_match('/REQUEST_TIME/', $text) === 1) {
                $out[] = 'REQUEST_TIME';
            }
        }

        return $out;
    }

    public function test_the_namespaces_read_no_clock(): void
    {
        $root = dirname(__DIR__, 4);
        $files = [...glob($root . '/src/App/Tarpit/Ssrf/*.php'), ...glob($root . '/src/App/Storage/Ssrf*.php'), $root . '/src/App/Tarpit/Mint/SurfaceExtension.php'];
        self::assertGreaterThanOrEqual(35, count($files));
        foreach ($files as $f) {
            self::assertSame([], self::uses((string) file_get_contents($f)), basename($f));
        }
        $surface = (string) file_get_contents($root . '/src/App/Tarpit/Mint/SurfaceExtension.php');
        self::assertDoesNotMatchRegularExpression('/TarpitBudget|hrtime|microtime|usleep|\bsleep\(|\btime\(\)/', $surface, 'the token-mint directory text scan stays clean, comments included');
    }

    public function test_each_entry_has_a_positive_control(): void
    {
        foreach (self::FORBIDDEN as $fn) {
            self::assertContains($fn, self::uses("<?php\n\$x = {$fn}(1);\n"), $fn);
        }
        self::assertContains('gmdate without a timestamp', self::uses("<?php\n\$x = gmdate('Y');\n"));
        self::assertSame([], self::uses("<?php\n\$x = gmdate('Y', \$now);\n"));
        self::assertContains('date without a timestamp', self::uses("<?php\n\$x = date('Y');\n"));
        self::assertContains('new DateTimeImmutable', self::uses("<?php\n\$x = new \\DateTimeImmutable();\n"));
        self::assertContains('new DateTime', self::uses("<?php\n\$x = new DateTime('now');\n"));
        self::assertContains('REQUEST_TIME', self::uses("<?php\n\$x = \$s['REQUEST_TIME_FLOAT'];\n"));
    }
}
