<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Fpm;

use Funnypot\Protocol\Fpm\FastCgiRecord;
use Funnypot\Protocol\Fpm\FcgiConfig;
use Funnypot\Protocol\Fpm\FcgiSession;
use Funnypot\Protocol\Fpm\FcgiThreat;
use PHPUnit\Framework\TestCase;

/**
 * FP-0204 Phase 2+3: the session classifies a PHP-FPM RCE attempt, quarantines the payload, and
 * answers with a plausible inert response — executing nothing.
 */
final class FcgiRceTrapTest extends TestCase
{
    private function config(): FcgiConfig
    {
        // Explicit persona version (NOT the box's real PHP) so the test is deterministic.
        return new FcgiConfig(phpVersion: '8.1.27', quarantineDir: sys_get_temp_dir());
    }

    public function test_metasploit_shaped_rce_is_classified_quarantined_and_answered_inertly(): void
    {
        $logged = [];
        $quarantined = [];
        $session = new FcgiSession(
            $this->config(),
            function (array $e) use (&$logged): void { $logged[] = $e; },
            function (string $payload, array $params) use (&$quarantined): ?string {
                $quarantined[] = $payload;

                return '/tmp/fpm_deadbeef.php.bin';
            },
            '203.0.113.9'
        );

        $webshell = '<?php system($_GET[0]); ?>';
        $wire = self::beginRequest(1)
            . self::params(1, [
                'SCRIPT_FILENAME' => 'php://input',
                'PHP_VALUE' => "allow_url_include=1\nauto_prepend_file=php://input",
                'REQUEST_METHOD' => 'POST',
            ])
            . FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 1, $webshell)
            . FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 1, ''); // STDIN EOF completes the request

        $out = $session->receive($wire);

        // Classified fpm_rce, critical, payload quarantined.
        self::assertCount(1, $logged);
        self::assertSame(FcgiThreat::CLASS_RCE, $logged[0]['event']);
        self::assertTrue($logged[0]['critical']);
        self::assertContains('php_value:auto_prepend_file', $logged[0]['reasons']);
        self::assertSame([$webshell], $quarantined, 'the webshell was captured to quarantine');

        // Response is a well-formed inert FCGI_STDOUT + END_REQUEST on the same requestId.
        [$records] = FastCgiRecord::decode($out);
        $types = array_map(static fn ($r) => $r->type, $records);
        self::assertContains(FastCgiRecord::TYPE_STDOUT, $types);
        self::assertContains(FastCgiRecord::TYPE_END_REQUEST, $types);
        foreach ($records as $r) {
            self::assertSame(1, $r->requestId, 'response echoes the client requestId');
        }

        $stdout = '';
        foreach ($records as $r) {
            if ($r->type === FastCgiRecord::TYPE_STDOUT) {
                $stdout .= $r->content;
            }
        }
        self::assertStringContainsString('X-Powered-By: PHP/8.1.27', $stdout, 'persona version, not the real 8.2.x');
        self::assertStringNotContainsString('8.2.16', $stdout, 'never serves the box real PHP version');
        self::assertStringNotContainsString('system(', $stdout, 'attacker payload is NOT reflected into the body');
        self::assertStringNotContainsString($webshell, $stdout);
    }

    public function test_bare_get_values_is_recon_and_answered_with_result(): void
    {
        $logged = [];
        $session = new FcgiSession($this->config(), function (array $e) use (&$logged): void { $logged[] = $e; });

        // GET_VALUES management record (requestId 0), empty body.
        $out = $session->receive(FastCgiRecord::encode(FastCgiRecord::TYPE_GET_VALUES, 0, ''));

        [$records] = FastCgiRecord::decode($out);
        self::assertCount(1, $records);
        self::assertSame(FastCgiRecord::TYPE_GET_VALUES_RESULT, $records[0]->type);
        self::assertSame(0, $records[0]->requestId, 'management record uses requestId 0');
        $vals = FastCgiRecord::decodeParams($records[0]->content);
        self::assertSame('0', $vals['FCGI_MPXS_CONNS'], 'advertises non-multiplexing like real FPM');
    }

    public function test_benign_request_is_recon_not_rce(): void
    {
        $logged = [];
        $session = new FcgiSession($this->config(), function (array $e) use (&$logged): void { $logged[] = $e; });

        $wire = self::beginRequest(7)
            . self::params(7, ['SCRIPT_FILENAME' => '/var/www/html/index.php', 'REQUEST_METHOD' => 'GET'])
            . FastCgiRecord::encode(FastCgiRecord::TYPE_STDIN, 7, '');

        $session->receive($wire);
        self::assertSame(FcgiThreat::CLASS_RECON, $logged[0]['event']);
        self::assertFalse($logged[0]['critical']);
    }

    public function test_source_is_inert_no_execution_sinks(): void
    {
        $dir = \dirname(__DIR__, 3) . '/src/Protocol/Fpm';
        $sinks = ['eval(', 'assert(', 'shell_exec', 'passthru', 'proc_open', 'popen(', 'system(', 'exec(', 'include ', 'include(', 'require ', 'require('];
        foreach (glob($dir . '/*.php') ?: [] as $file) {
            $src = (string) file_get_contents($file);
            foreach ($sinks as $sink) {
                self::assertStringNotContainsString($sink, $src, "inertness: {$sink} must not appear in " . basename($file));
            }
        }
    }

    // --- frame builders ---

    private static function beginRequest(int $requestId): string
    {
        $content = \chr(0) . \chr(FastCgiRecord::ROLE_RESPONDER) . "\x00\x00\x00\x00\x00\x00"; // role(2 BE), flags, reserved(5)

        return FastCgiRecord::encode(FastCgiRecord::TYPE_BEGIN_REQUEST, $requestId, $content);
    }

    /** @param array<string,string> $params */
    private static function params(int $requestId, array $params): string
    {
        $stream = '';
        foreach ($params as $name => $value) {
            $stream .= self::len(\strlen($name)) . self::len(\strlen($value)) . $name . $value;
        }

        return FastCgiRecord::encode(FastCgiRecord::TYPE_PARAMS, $requestId, $stream)
            . FastCgiRecord::encode(FastCgiRecord::TYPE_PARAMS, $requestId, ''); // PARAMS EOF
    }

    private static function len(int $n): string
    {
        if ($n < 128) {
            return \chr($n);
        }

        return \chr((($n >> 24) & 0x7F) | 0x80) . \chr(($n >> 16) & 0xFF) . \chr(($n >> 8) & 0xFF) . \chr($n & 0xFF);
    }
}
