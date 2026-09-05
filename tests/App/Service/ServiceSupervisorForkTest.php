<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\PcntlServiceProcessControl;
use PHPUnit\Framework\TestCase;

/**
 * Real-fork proof that the supervisor can start/stop/reap listeners through pcntl without exec/proc_open
 * and never signals a non-child PID. Annotated @group fork and self-skipping under paratest (which sets
 * TEST_TOKEN in every worker), so it never runs inside `composer test`; run it single-process with
 * `php vendor/bin/phpunit --group fork`.
 *
 * @group fork
 */
final class ServiceSupervisorForkTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('pcntl') || !function_exists('posix_kill')) {
            self::markTestSkipped('needs ext-pcntl and ext-posix');
        }
        if (getenv('TEST_TOKEN') !== false) {
            self::markTestSkipped('fork tests do not run under paratest (TEST_TOKEN set)');
        }
    }

    public function testStartStopReapWithoutExec(): void
    {
        $child = static function (string $processId): void {
            // Harmless fixture listener: just wait to be terminated.
            sleep(30);
        };
        $ctl = new PcntlServiceProcessControl($child, 1000);

        $ctl->start('ftp');
        self::assertContains('ftp', $ctl->running());
        self::assertTrue($ctl->isAlive('ftp'));

        $ctl->stop('ftp');
        self::assertNotContains('ftp', $ctl->running());
        self::assertFalse($ctl->isAlive('ftp'));
    }

    public function testStoppingAnUnknownIdIsANoOp(): void
    {
        $ctl = new PcntlServiceProcessControl(static fn (string $p) => sleep(1));
        // never started; must not signal any PID
        $ctl->stop('never-started');
        self::assertSame([], $ctl->running());
    }

    public function testAFreshControlOwnsNoOrphan(): void
    {
        $ctl1 = new PcntlServiceProcessControl(static fn (string $p) => sleep(30), 1000);
        $ctl1->start('telnet');
        self::assertTrue($ctl1->isAlive('telnet'));

        // A fresh control in the same process tree owns nothing — no orphan to reclaim.
        $ctl2 = new PcntlServiceProcessControl(static fn (string $p) => sleep(30), 1000);
        self::assertSame([], $ctl2->running());
        self::assertFalse($ctl2->isAlive('telnet'));

        $ctl1->stop('telnet');
    }
}
