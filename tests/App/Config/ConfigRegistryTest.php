<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Config;

use Funnypot\App\Config\AppConfig;
use Funnypot\App\Config\ConfigRegistry;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * The typed config registry: it stays in lock-step with AppConfig's fields (T4), and its validate()
 * coerces + clamps exactly like AppConfig::build() does on read (the write-side of the same rules).
 */
final class ConfigRegistryTest extends TestCase
{
    /**
     * The AppConfig fields that are deliberately NOT in the registry — filesystem paths, secrets /
     * identity, and network topology. These stay env-sourced inside fromStore (spec §2.3, §5). This
     * allow-list is the documented boundary; adding an AppConfig field lands it here or in the
     * registry, or T4 fails.
     *
     * @var string[]
     */
    private const ENV_ONLY = [
        'dbPath', 'logPath', 'geoDbPath', 'vulnsPath', 'intelDbPath', 'llmCacheDb', 'tarpitDbPath', // paths
        'honeytokenKey', 'adminPassword', 'abuseIpdbKey', 'threatIntelKey',         // secrets
        'personaSeed', 'personaMaterial', 'adminUser', 'adminKnock',                // identity
        'selfIps', 'trustedProxies',                                                // network topology
    ];

    /** T4: every AppConfig constructor param is either a registry field or in the env-only allow-list. */
    public function test_every_appconfig_field_is_covered(): void
    {
        $registryFields = array_column(ConfigRegistry::schema(), 'field');
        $ctorParams = (new ReflectionClass(AppConfig::class))->getConstructor()->getParameters();

        foreach ($ctorParams as $p) {
            $name = $p->getName();
            $covered = in_array($name, $registryFields, true) || in_array($name, self::ENV_ONLY, true);
            self::assertTrue(
                $covered,
                "AppConfig field '{$name}' has no ConfigRegistry entry and is not in the env-only allow-list — "
                . 'add a registry entry (or extend ENV_ONLY if it is a path/secret/identity/network field).'
            );
        }
    }

    /** T4 (reverse): every registry field maps to a real AppConfig constructor param. */
    public function test_every_registry_field_is_a_real_appconfig_param(): void
    {
        $ctorNames = array_map(
            static fn ($p) => $p->getName(),
            (new ReflectionClass(AppConfig::class))->getConstructor()->getParameters()
        );
        foreach (ConfigRegistry::schema() as $key => $e) {
            self::assertContains($e['field'], $ctorNames, "registry key '{$key}' names a non-existent AppConfig field '{$e['field']}'");
        }
    }

    /** The registry and the env-only allow-list must not overlap (a field is in exactly one place). */
    public function test_registry_and_env_only_are_disjoint(): void
    {
        $registryFields = array_column(ConfigRegistry::schema(), 'field');
        foreach (self::ENV_ONLY as $f) {
            self::assertNotContains($f, $registryFields, "field '{$f}' is both a registry entry and env-only");
        }
    }

    /** Every registry field name is unique (no two keys claim the same AppConfig field). */
    public function test_field_names_are_unique(): void
    {
        $fields = array_column(ConfigRegistry::schema(), 'field');
        self::assertSame(count($fields), count(array_unique($fields)), 'duplicate AppConfig field in the registry');
    }

    public function test_key_for_env_reverse_maps(): void
    {
        $reg = new ConfigRegistry();
        self::assertSame('style', $reg->keyForEnv('FUNNYPOT_STYLE'));
        self::assertSame('dl.chunk_min_kb', $reg->keyForEnv('FUNNYPOT_DL_CHUNK_MIN_KB'));
        self::assertNull($reg->keyForEnv('FUNNYPOT_DB')); // env-only, not a knob
        self::assertNull($reg->keyForEnv('NOPE'));
    }

    public function test_validate_enum(): void
    {
        $reg = new ConfigRegistry();
        self::assertSame([true, 'taunt'], $reg->validate('style', 'taunt'));
        [$ok, $err] = $reg->validate('style', 'nonsense');
        self::assertFalse($ok);
        self::assertStringContainsString('one of', $err);
    }

    public function test_validate_unknown_key_is_rejected(): void
    {
        [$ok, $err] = (new ConfigRegistry())->validate('no.such.key', 'x');
        self::assertFalse($ok);
        self::assertStringContainsString('unknown config key', $err);
    }

    public function test_validate_int_clamps_to_bounds(): void
    {
        $reg = new ConfigRegistry();
        // dl.chunk_min_kb bounds are [1,1024] (AppConfig.php:257).
        self::assertSame([true, '1024'], $reg->validate('dl.chunk_min_kb', '99999'));
        self::assertSame([true, '1'], $reg->validate('dl.chunk_min_kb', '-5'));
        self::assertSame([true, '256'], $reg->validate('dl.chunk_min_kb', '256'));
        [$ok] = $reg->validate('dl.chunk_min_kb', 'notint');
        self::assertFalse($ok);
    }

    public function test_validate_bool_normalises_both_styles_to_canonical(): void
    {
        $reg = new ConfigRegistry();
        // opt-in flag
        self::assertSame([true, '1'], $reg->validate('llm_enabled', 'yes'));
        self::assertSame([true, '0'], $reg->validate('llm_enabled', 'off'));
        // on-unless-0 flag — stored representation is the same canonical '1'/'0'
        self::assertSame([true, '0'], $reg->validate('attack_emulation', '0'));
        self::assertSame([true, '1'], $reg->validate('attack_emulation', 'true'));
        [$ok] = $reg->validate('llm_enabled', 'maybe');
        self::assertFalse($ok);
    }

    public function test_validate_csv_trims_and_drops_empties(): void
    {
        $reg = new ConfigRegistry();
        self::assertSame([true, '1.2.3.4,5.6.7.8'], $reg->validate('llm.gate_allow', ' 1.2.3.4 , ,5.6.7.8 '));
    }
}
