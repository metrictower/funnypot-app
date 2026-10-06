<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Dns;

use PHPUnit\Framework\TestCase;

/** FP-0182: the DNS emulator source must contain no code-execution sink (inert by construction). */
final class DnsInertnessTest extends TestCase
{
    public function test_no_execution_sinks_in_dns_source(): void
    {
        $dir = \dirname(__DIR__, 3) . '/src/Protocol/Dns';
        $sinks = ['eval(', 'assert(', 'shell_exec', 'passthru', 'proc_open', 'popen(', 'system(', 'exec(', 'include ', 'include(', 'require ', 'require('];
        foreach (glob($dir . '/*.php') ?: [] as $file) {
            $src = (string) file_get_contents($file);
            foreach ($sinks as $sink) {
                self::assertStringNotContainsString($sink, $src, "inertness: {$sink} must not appear in " . basename($file));
            }
        }
    }
}
