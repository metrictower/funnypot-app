<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\ServedKeys;
use Funnypot\Tests\App\Identity\IdentityTestSupport;
use PHPUnit\Framework\TestCase;

/**
 * A new source of served keys fails here before it can serve a key the credential gateways would not
 * recognise: a key-shaped directive in core's compiled artifacts, or an app file that holds a
 * key-shaped literal or calls a key generator, must be one ServedKeys knows.
 */
final class ServedKeysCensusTest extends TestCase
{
    public function test_core_directives_match_the_compiled_artifacts(): void
    {
        $found = [];
        foreach (ServedKeysHarvestTest::census() as $directives) {
            foreach ($directives as $d) {
                $found[$d] = true;
            }
        }
        $want = [...ServedKeys::CORE_DIRECTIVES, ...array_map(static fn (string $f): string => 'persona.' . $f, ServedKeys::PERSONA_FIELDS)];
        $found = array_keys($found);
        sort($found);
        sort($want);
        self::assertSame($want, $found, 'core serves exactly the key directives ServedKeys renders');
    }

    /**
     * The files of $root that hold a key-shaped string literal (adjacent concatenated literals joined) or
     * call a key generator.
     *
     * @return list<string>
     */
    public static function keyFiles(array $files): array
    {
        $out = [];
        foreach ($files as $file) {
            $toks = token_get_all((string) file_get_contents($file));
            $lit = '';
            $hit = false;
            $n = count($toks);
            for ($i = 0; $i < $n; $i++) {
                $t = $toks[$i];
                if (is_array($t) && $t[0] === T_CONSTANT_ENCAPSED_STRING) {
                    $lit .= substr($t[1], 1, -1);
                    if (preg_match('/\A(?:AKIA|ASIA|sk_live_|sk_test_|rk_live_)/', $lit) === 1) {
                        $hit = true;
                    }
                    continue;
                }
                if ($t === '.' || (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT], true))) {
                    continue;
                }
                $lit = '';
                if (is_array($t) && $t[0] === T_STRING && in_array($t[1], ['apiKey', 'stripeKey', 'awsKey'], true)) {
                    $prev = $toks[$i - 1] ?? null;
                    if (is_array($prev) && in_array($prev[0], [T_DOUBLE_COLON, T_OBJECT_OPERATOR], true) && ($toks[$i + 1] ?? null) === '(') {
                        $hit = true;
                    }
                }
            }
            if ($hit) {
                $out[] = $file;
            }
        }

        return $out;
    }

    public function test_every_key_emitting_app_file_is_a_source(): void
    {
        $root = dirname(__DIR__, 4);
        $files = [$root . '/demo/index.php'];
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/src', \FilesystemIterator::SKIP_DOTS)) as $f) {
            if (str_ends_with($f->getPathname(), '.php')) {
                $files[] = $f->getPathname();
            }
        }
        self::assertGreaterThan(200, count($files));
        $found = array_map(static fn (string $f): string => substr($f, strlen($root) + 1), self::keyFiles($files));
        self::assertNotEmpty($found);
        foreach ($found as $f) {
            self::assertArrayHasKey($f, ServedKeys::SOURCE_FILES, "{$f} emits keys but is not a ServedKeys source");
        }
        foreach (ServedKeys::SOURCE_FILES as $f => $why) {
            self::assertFileExists($root . '/' . $f);
            self::assertMatchesRegularExpression('/\A(?:configdump|log|hostile|bait|shell|persona|generator|not_served)\b/', $why, $f);
        }
        self::assertSame([$root . '/tests/Fixtures/ssrf/census/SplitKeyLiteral.php'], self::keyFiles([$root . '/tests/Fixtures/ssrf/census/SplitKeyLiteral.php']), 'positive control: a split literal is flagged');
    }

    public function test_core_mock_auth_tables_stay_dormant(): void
    {
        $cfg = IdentityTestSupport::coreConfigFactory()->build(\Funnypot\App\Config\AppConfig::fromEnv(sys_get_temp_dir()), \Funnypot\App\Emulation\EmulationPolicy::fromPackage(null), static fn (): string => 'x');
        self::assertNull($cfg->decoySessionKey, 'enabling core mock-auth would serve FakeRecords keys; add them as a family first');
        self::assertArrayHasKey('Funnypot\\Core\\Support\\Fake\\FakeRecords::apiKeys', ServedKeys::CORE_DORMANT);
    }

    public function test_static_decoys_hold_only_placeholders(): void
    {
        $text = (string) file_get_contents(dirname(__DIR__, 4) . '/demo/decoys/backup.sql');
        preg_match_all('~\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b[sr]k_(?:live|test)_[0-9A-Za-z]{10,}~', $text, $m);
        self::assertNotEmpty($m[0]);
        foreach ($m[0] as $k) {
            self::assertTrue(ServedKeys::placeholder($k), $k);
        }
    }
}
