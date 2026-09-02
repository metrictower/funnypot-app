<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\Docker\ImageRef;
use PHPUnit\Framework\TestCase;

/**
 * The pure image-reference parser: docker's own normalisation rules (implicit docker.io + library/,
 * default :latest, registry detection by dot/colon/localhost, digest split), and bounded rejection of
 * anything outside the ref charset. It never resolves or contacts anything.
 */
final class ImageRefTest extends TestCase
{
    public function test_bare_name_gets_hub_registry_and_library_namespace(): void
    {
        $p = ImageRef::parse('alpine');
        self::assertTrue($p['valid']);
        self::assertSame('docker.io', $p['registry']);
        self::assertSame('library/alpine', $p['repo']);
        self::assertSame('latest', $p['tag']);
        self::assertSame('alpine:latest', $p['display']);
        self::assertSame('docker.io/library/alpine:latest', $p['canonical']);
    }

    public function test_namespaced_hub_repo_and_tag(): void
    {
        $p = ImageRef::parse('xmrig/xmrig:6.20');
        self::assertSame('docker.io', $p['registry']);
        self::assertSame('xmrig/xmrig', $p['repo']);
        self::assertSame('6.20', $p['tag']);
        self::assertSame('xmrig/xmrig:6.20', $p['display']);
    }

    public function test_private_registry_with_port_is_not_mistaken_for_a_tag(): void
    {
        $p = ImageRef::parse('evil.example:5000/x/miner');
        self::assertSame('evil.example:5000', $p['registry']);
        self::assertSame('x/miner', $p['repo']);
        self::assertSame('latest', $p['tag']);
        self::assertSame('evil.example:5000/x/miner:latest', $p['display']);
    }

    public function test_digest_pin(): void
    {
        $p = ImageRef::parse('alpine@sha256:' . str_repeat('a', 64));
        self::assertTrue($p['valid']);
        self::assertSame('sha256:' . str_repeat('a', 64), $p['digest']);
        self::assertSame('', $p['tag'], 'a digest pin has no default tag');
    }

    public function test_localhost_registry(): void
    {
        $p = ImageRef::parse('localhost:5000/app:1');
        self::assertSame('localhost:5000', $p['registry']);
        self::assertSame('app', $p['repo']);
    }

    public function test_out_of_charset_ref_is_invalid_but_kept_raw(): void
    {
        $p = ImageRef::parse('alpine; rm -rf /');
        self::assertFalse($p['valid']);
        self::assertSame('', $p['canonical']);
        self::assertSame('alpine; rm -rf /', $p['display'], 'raw kept for logging, never used as a path/host');
    }

    public function test_overlong_ref_is_invalid(): void
    {
        self::assertFalse(ImageRef::parse(str_repeat('a', 300))['valid']);
    }

    public function test_is_local_matches_on_canonical_form(): void
    {
        $local = [ImageRef::parse('postgres:15.4')['canonical'], ImageRef::parse('alpine:3.18')['canonical']];
        self::assertTrue(ImageRef::isLocal('postgres:15.4', $local, []));
        self::assertFalse(ImageRef::isLocal('alpine', $local, []), 'alpine:latest != alpine:3.18');
        self::assertTrue(ImageRef::isLocal('alpine', $local, [ImageRef::parse('alpine')['canonical']]), 'pulled makes it local');
    }
}
