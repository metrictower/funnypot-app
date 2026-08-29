<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\ProcContent;
use PHPUnit\Framework\TestCase;

final class ProcContentTest extends TestCase
{
    /** Every kind, every size in a wide range, must land on EXACTLY the requested byte count — the
     *  node's ls-l size is drawn before the body, so read() has to match it to the byte. */
    public function test_output_is_always_exactly_the_requested_size(): void
    {
        $names = ['.env', 'config.json', 'nginx.conf', 'app.yaml', 'server.log', 'dump.sql',
            'id_rsa', 'key.pem', 'random.bin', 'noext', 'x.toml', 'settings.ini', 'a.tfvars'];
        foreach ($names as $name) {
            for ($size = 0; $size <= 1200; $size += 3) {
                $body = ProcContent::generate(Draw::seed("t\0{$name}\0{$size}"), $name, $size);
                self::assertSame($size, strlen($body), "size mismatch: {$name} @ {$size}");
            }
        }
    }

    public function test_deterministic_per_seed(): void
    {
        $a = ProcContent::generate(Draw::seed('same'), 'config.json', 800);
        $b = ProcContent::generate(Draw::seed('same'), 'config.json', 800);
        $c = ProcContent::generate(Draw::seed('other'), 'config.json', 800);
        self::assertSame($a, $b);
        self::assertNotSame($a, $c);
    }

    public function test_env_and_conf_read_as_key_value(): void
    {
        foreach (['.env', 'nginx.conf', 'settings.ini'] as $name) {
            $body = ProcContent::generate(Draw::seed("kv\0{$name}"), $name, 400);
            self::assertMatchesRegularExpression('/^[A-Z0-9_]+=.+/m', $body, "{$name} should have KEY=value lines");
        }
    }

    public function test_yaml_reads_as_mapping(): void
    {
        $body = ProcContent::generate(Draw::seed('y'), 'app.yaml', 400);
        self::assertMatchesRegularExpression('/^[A-Z0-9_]+: .+/m', $body);
    }

    public function test_json_is_valid_and_exact(): void
    {
        for ($size = 40; $size <= 2000; $size += 11) {
            $body = ProcContent::generate(Draw::seed("j\0{$size}"), 'config.json', $size);
            self::assertSame($size, strlen($body));
            self::assertSame('{', $body[0], "json @ {$size} should be a wrapped object");
            self::assertNotNull(json_decode($body), "invalid JSON @ {$size}");
        }
    }

    public function test_log_reads_as_timestamped_lines(): void
    {
        $body = ProcContent::generate(Draw::seed('l'), 'server.log', 600);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z (INFO|WARN|ERROR|DEBUG|NOTICE) /m', $body);
    }

    public function test_pem_is_a_wrapped_block(): void
    {
        $body = ProcContent::generate(Draw::seed('p'), 'server.key', 500);
        self::assertStringStartsWith('-----BEGIN', $body);
        self::assertStringContainsString('-----END', $body);
    }

    public function test_unknown_extension_stays_base64_noise(): void
    {
        // Binary/unknown extensions fall through to the padding-free base64 generator (no '=').
        $body = ProcContent::generate(Draw::seed('n'), 'archive.bin', 600);
        self::assertMatchesRegularExpression('#^[A-Za-z0-9+/]+$#', $body);
    }

    public function test_content_is_inert_no_real_key_markers(): void
    {
        // A generated PEM must never carry a working key or the AWS example-key marker.
        $pem = ProcContent::generate(Draw::seed('k'), 'id_rsa.pem', 800);
        self::assertStringNotContainsString('AKIAIOSFODNN7EXAMPLE', $pem);
    }
}
