<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Config;

use Funnypot\App\Config\BuildStamp;
use Funnypot\Tests\App\Tarpit\Mint\MintHarness;
use Funnypot\Tests\App\Tarpit\Ssrf\CallScan;
use PHPUnit\Framework\TestCase;

final class BuildStampTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp0816stamp_' . bin2hex(random_bytes(5));
        foreach (BuildStamp::GENERATOR_FILES as $f) {
            @mkdir(dirname($this->dir . '/' . $f), 0700, true);
            file_put_contents($this->dir . '/' . $f, '<?php // ' . $f);
        }
    }

    protected function tearDown(): void
    {
        MintHarness::removeTree($this->dir);
    }

    public function test_every_generator_file_exists(): void
    {
        foreach (BuildStamp::GENERATOR_FILES as $f) {
            self::assertFileExists(dirname(__DIR__, 3) . '/' . $f);
        }
    }

    public function test_a_source_checkout_hashes_the_generators(): void
    {
        $a = BuildStamp::value($this->dir);
        self::assertStringStartsWith('src:', $a);
        file_put_contents($this->dir . '/src/App/Tarpit/InertSecret.php', '<?php // changed');
        self::assertNotSame($a, BuildStamp::value($this->dir), 'an app-only change to a generator moves the stamp');
    }

    public function test_the_image_build_id_wins(): void
    {
        file_put_contents($this->dir . '/build-id', str_repeat('ab', 32) . "\n");
        self::assertSame('image:' . str_repeat('ab', 32), BuildStamp::value($this->dir));
        file_put_contents($this->dir . '/build-id', 'not-an-id');
        self::assertStringStartsWith('src:', BuildStamp::value($this->dir), 'a malformed build id falls back');
        self::assertStringContainsString('> /app/build-id', (string) file_get_contents(dirname(__DIR__, 3) . '/demo/Dockerfile'), 'the image bakes one');
    }

    public function test_it_reads_only_local_files(): void
    {
        $x = CallScan::extract((string) file_get_contents(dirname(__DIR__, 3) . '/src/App/Config/BuildStamp.php'));
        self::assertSame(['file_get_contents', 'hash_file', 'hash_final', 'hash_init', 'hash_update', 'is_file', 'preg_match', 'trim'], $x['calls']);
        self::assertSame([], $x['new']);
    }
}
