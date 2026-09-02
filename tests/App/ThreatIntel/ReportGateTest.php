<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\ThreatIntel;

use Funnypot\App\ThreatIntel\AbuseIpdb;
use Funnypot\App\ThreatIntel\ReportGate;
use Funnypot\App\ThreatIntel\ThreatIntelReporter;
use PHPUnit\Framework\TestCase;

/**
 * The fail-closed report gate (FP-0247, Fix A) — the ticket's paramount invariant: a spoofed /
 * unverified source is NEVER reported. These tests drive the REAL wiring demo/listen.php calls
 * ({@see ReportGate::maybeReport()}) against real reporters backed by temp SQLite, so a passing
 * test means nothing was queued for a forged datagram — not merely that a boolean returned false.
 */
final class ReportGateTest extends TestCase
{
    /** @var string[] */
    private array $tmp = [];

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('ext-pdo_sqlite not loaded');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $f) {
            foreach (['', '-wal', '-shm'] as $s) {
                @unlink($f . $s);
            }
        }
        $this->tmp = [];
    }

    private function dbPath(): string
    {
        $p = sys_get_temp_dir() . '/fp_gate_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->tmp[] = $p;

        return $p;
    }

    /** @return array{0:AbuseIpdb,1:ThreatIntelReporter} both armed, self-ip configured, one shared db */
    private function reporters(): array
    {
        $db = $this->dbPath();

        return [
            new AbuseIpdb('KEY', $db, ['203.0.113.9']),
            new ThreatIntelReporter('https://ti.example', 'KEY', $db, ['203.0.113.9']),
        ];
    }

    /**
     * THE HEADLINE PROOF: an event shaped exactly like SnmpServer::logEvent() output but MISSING the
     * `reportable` key (a UDP emitter that forgot the flag) must queue nothing on either reporter.
     * A single forged SNMP datagram must never get its spoofed source reported.
     */
    public function test_udp_emitter_that_forgets_the_flag_never_reports(): void
    {
        [$abuse, $ti] = $this->reporters();
        $entry = [
            'ts' => gmdate('c'),
            'ip' => '45.9.148.1',   // an innocent IP a spoofer could forge as the source
            'method' => 'SNMP',
            'proto' => 'snmp',
            'port' => 161,
            'event' => 'community-guess',
            'path' => 'SNMP GET public 1.3.6.1.2.1.1',
            'matched' => 1,
            'served' => 1,
            // NOTE: no 'reportable' key — exactly what a forgetful new UDP emitter produces.
        ];

        self::assertFalse(ReportGate::shouldReport($entry));
        ReportGate::maybeReport($entry, $abuse, $ti, 'snmp', 161, '14,15');

        self::assertSame(0, $abuse->queueCount(), 'a flagless UDP event must never queue an AbuseIPDB report');
        self::assertSame(0, $ti->queueCount(), 'a flagless UDP event must never queue a Threat Intel report');
    }

    public function test_reportable_false_never_reports(): void
    {
        [$abuse, $ti] = $this->reporters();
        $entry = ['ip' => '45.9.148.1', 'event' => 'x', 'path' => 'p', 'reportable' => false];

        self::assertFalse(ReportGate::shouldReport($entry));
        ReportGate::maybeReport($entry, $abuse, $ti, 'sip', 5060, '8,18');
        self::assertSame(0, $abuse->queueCount());
        self::assertSame(0, $ti->queueCount());
    }

    public function test_missing_ip_never_reports(): void
    {
        [$abuse, $ti] = $this->reporters();
        $entry = ['event' => 'x', 'path' => 'p', 'reportable' => true];   // verified but no IP

        self::assertFalse(ReportGate::shouldReport($entry));
        ReportGate::maybeReport($entry, $abuse, $ti, 'ssh', 22, '18,22');
        self::assertSame(0, $abuse->queueCount());
        self::assertSame(0, $ti->queueCount());
    }

    public function test_reportable_true_with_ip_reports(): void
    {
        [$abuse, $ti] = $this->reporters();
        $entry = ['ip' => '45.9.148.1', 'event' => 'command', 'path' => 'GET /.git/config', 'reportable' => true];

        self::assertTrue(ReportGate::shouldReport($entry));
        ReportGate::maybeReport($entry, $abuse, $ti, 'redis', 6379, '14,15');
        self::assertSame(1, $abuse->queueCount(), 'a verified event with an IP must queue exactly one report');
        self::assertSame(1, $ti->queueCount());
    }

    /** A non-boolean truthy value must NOT satisfy the strict-true gate (fail-closed on shape). */
    public function test_non_boolean_true_is_not_reportable(): void
    {
        self::assertFalse(ReportGate::shouldReport(['ip' => '45.9.148.1', 'reportable' => 1]));
        self::assertFalse(ReportGate::shouldReport(['ip' => '45.9.148.1', 'reportable' => 'true']));
    }
}
