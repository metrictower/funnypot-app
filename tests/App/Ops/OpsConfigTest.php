<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Ops;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * Static ops bounds on the shipped config: production opcache never stats source files (the dev
 * override is opt-in and named to win), and container logs rotate in both deploy paths.
 */
final class OpsConfigTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    public function test_production_opcache_freezes_timestamps_and_the_dev_override_wins_by_name(): void
    {
        $ini = (string) file_get_contents(self::root() . '/demo/opcache.ini');
        self::assertMatchesRegularExpression('/^opcache\.validate_timestamps=0$/m', $ini);
        self::assertDoesNotMatchRegularExpression('/^opcache\.validate_timestamps=1/m', $ini);
        self::assertMatchesRegularExpression('/^opcache\.enable=1$/m', $ini);

        $dockerfile = (string) file_get_contents(self::root() . '/demo/Dockerfile');
        self::assertSame(1, preg_match('#COPY demo/opcache\.ini\s+/usr/local/etc/php/conf\.d/(\S+)#', $dockerfile, $m), 'the production ini is installed under conf.d');
        $prodIni = $m[1];

        $sh = (string) file_get_contents(self::root() . '/demo/entrypoint.sh');
        self::assertSame(1, preg_match('#FUNNYPOT_DEV:-0}" = "1" \]; then\s*\n\s*printf \'opcache\.validate_timestamps=1\\\\nopcache\.revalidate_freq=0\\\\n\' > "\$PHP_CONFD/(\S+)"\s*\n\s*else\s*\n\s*rm -f "\$PHP_CONFD/(\S+)"#', $sh, $d), 'FUNNYPOT_DEV=1 writes the override, anything else removes it');
        self::assertSame($d[1], $d[2], 'the same file is written and removed');
        // PHP loads conf.d in byte order; the override must sort after the production ini to win.
        self::assertGreaterThan(0, strcmp($d[1], $prodIni), "{$d[1]} must sort after {$prodIni}");
        self::assertSame(1, preg_match('/^PHP_CONFD="\$\{FUNNYPOT_PHP_CONFD:-\/usr\/local\/etc\/php\/conf\.d\}"$/m', $sh));
        self::assertLessThan(strpos($sh, 'php-fpm --daemonize'), strpos($sh, 'FUNNYPOT_DEV'), 'the override is settled before php-fpm reads its config');
    }

    public function test_compose_rotates_container_logs_and_documents_the_dev_flag(): void
    {
        $doc = Yaml::parseFile(self::root() . '/demo/docker-compose.yml');
        $pub = $doc['services']['funnypot'];
        self::assertSame('json-file', $pub['logging']['driver'] ?? null);
        self::assertSame('10m', $pub['logging']['options']['max-size'] ?? null);
        self::assertSame('5', (string) ($pub['logging']['options']['max-file'] ?? ''));
        $raw = (string) file_get_contents(self::root() . '/demo/docker-compose.yml');
        self::assertStringContainsString('# FUNNYPOT_DEV: "1"', $raw, 'the dev flag is documented next to the bind-mount recipe');
    }

    public function test_deploy_rotates_logs_on_both_containers(): void
    {
        $sh = (string) file_get_contents(self::root() . '/scripts/deploy.sh');
        self::assertSame(1, preg_match('/^LOG_FLAGS="([^"]+)"$/m', $sh, $m));
        self::assertStringContainsString('--log-driver json-file', $m[1]);
        self::assertStringContainsString('--log-opt max-size=10m', $m[1]);
        self::assertStringContainsString('--log-opt max-file=5', $m[1]);
        self::assertMatchesRegularExpression('/docker run -d --name funnypot --restart unless-stopped \$LOG_FLAGS /', $sh, 'the honeypot container');
        self::assertMatchesRegularExpression('/docker run -d --name funnypot-llm --restart unless-stopped \$LOG_FLAGS /', $sh, 'the LLM sidecar');
    }
}
