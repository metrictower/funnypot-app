<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use PHPUnit\Framework\TestCase;

/**
 * The SSRF decoy never makes an outbound request or a DNS lookup. There is no fetch code, and this file
 * keeps it that way.
 *
 * Check (4), the edited-file call pin: every file outside the SSRF namespaces that this work edits may
 * gain no function call, no instantiated class, no static call and no parent class beyond what it had
 * on the base commit, except the names listed in DELTA. The base sets were recorded from the base tree
 * into tests/Fixtures/ssrf/edited-files-base.json.
 */
final class SsrfNoOutboundTest extends TestCase
{
    private const BASE_FIXTURE = 'tests/Fixtures/ssrf/edited-files-base.json';

    /** Names an edited file may gain, per kind. Only the SSRF decoy's own classes and pure helpers. */
    private const DELTA = [
        'calls' => [],
        'new' => [],
        'static' => [],
        'extends' => [],
    ];

    private static function root(): string
    {
        return dirname(__DIR__, 4);
    }

    public function test_edited_files_add_no_new_calls(): void
    {
        $base = json_decode((string) file_get_contents(self::root() . '/' . self::BASE_FIXTURE), true);
        self::assertIsArray($base);
        self::assertGreaterThanOrEqual(15, count($base['files']), 'every edited file has a recorded base');
        $checked = 0;
        foreach ($base['files'] as $file => $sets) {
            $now = CallScan::extract((string) file_get_contents(self::root() . '/' . $file));
            foreach (['calls', 'new', 'static', 'extends'] as $kind) {
                $gained = array_values(array_diff($now[$kind], $sets[$kind], self::DELTA[$kind]));
                self::assertSame([], $gained, "{$file} gained {$kind} not in the base or the listed delta");
                $checked += count($now[$kind]);
            }
        }
        self::assertGreaterThan(300, $checked, 'the pin read the files');
    }

    public function test_the_call_pin_sees_a_planted_call(): void
    {
        $planted = CallScan::extract("<?php\nnamespace A;\nuse B\\C;\nfunction f() { curl_init(); new C(); \\D\\E::open(); }\nclass X extends \\SoapClient {}\n");
        self::assertContains('curl_init', $planted['calls']);
        self::assertContains('B\\C', $planted['new']);
        self::assertContains('D\\E::open', $planted['static']);
        self::assertContains('SoapClient', $planted['extends']);
    }
}
