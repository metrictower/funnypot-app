<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol;

use PHPUnit\Framework\TestCase;

/**
 * Source-scanning lint (FingerprintSafetyTest style) enforcing the FP-0247 fail-closed reporting
 * invariant at the emitter layer. demo/listen.php now DROPS any event without an explicit
 * `reportable => true` (Fix A), so a new protocol server that forgets to set the flag would silently
 * report nothing — or, worse for a UDP server, could only ever be made reportable by a spoofable
 * datagram. This lint makes that omission a hard CI failure instead of a silent behaviour change:
 * every protocol emitter must state its verification stance explicitly.
 *
 * Matches an ASSIGNMENT shape (`'reportable' =>` or `$entry['reportable'] ??=`/`=`), never a bare
 * `reportable` substring — SipServer carries comment-only mentions of the flag that a substring check
 * would be fooled by.
 *
 * NOTE: this lint proves the PRESENCE of a reportable assertion, not its CORRECTNESS — it cannot tell
 * a safe gate (`'reportable' => ($transport === 'tcp')`) from an unsafe blanket `'reportable' => true`
 * on a spoofable UDP path. Per-path correctness is covered by behavioural tests (e.g.
 * SipServerSecurityTest's anti-spoof cases), not here.
 */
final class ReportableAssertionLintTest extends TestCase
{
    private static function repoRoot(): string
    {
        return dirname(__DIR__, 2);
    }

    /** @return list<string> absolute paths to every src/Protocol/**\/*Server.php */
    private static function serverFiles(): array
    {
        $root = self::repoRoot() . '/src/Protocol';
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        $files = [];
        foreach ($it as $f) {
            if ($f->isFile() && preg_match('/Server\.php$/', $f->getFilename()) === 1) {
                $files[] = $f->getPathname();
            }
        }
        sort($files);
        self::assertNotSame([], $files, 'expected to find protocol *Server.php files');

        return $files;
    }

    /** An assignment-shape reportable declaration (not a comment mention). */
    private static function assertsReportable(string $src): bool
    {
        return preg_match('/[\'"]reportable[\'"]\s*=>/', $src) === 1
            || preg_match('/\[[\'"]reportable[\'"]\]\s*(?:\?\?=|=)[^=]/', $src) === 1;
    }

    /**
     * Every UDP-binding protocol server must state a reportable stance explicitly — a single UDP
     * datagram is spoofable, so its default must be an explicit fail-closed `false`, never the gate's
     * absence-of-flag path.
     */
    public function test_every_udp_server_asserts_reportable_explicitly(): void
    {
        foreach (self::serverFiles() as $path) {
            $src = (string) file_get_contents($path);
            if (strpos($src, 'udp://') === false) {
                continue;
            }
            self::assertTrue(
                self::assertsReportable($src),
                'UDP server ' . basename($path) . ' must set a reportable flag explicitly (assignment shape)'
            );
        }
    }

    /**
     * Every protocol server (and the shared Listener) that emits an event to the log/report closure
     * must assert a reportable stance in an assignment shape.
     */
    public function test_every_protocol_log_helper_asserts_reportable(): void
    {
        $emitters = self::serverFiles();
        $emitters[] = self::repoRoot() . '/src/Protocol/Listener.php';   // the shared TCP emulator emitter
        foreach ($emitters as $path) {
            $src = (string) file_get_contents($path);
            if (strpos($src, '($this->logger)(') === false) {
                continue;   // not an emitter to the report path
            }
            self::assertTrue(
                self::assertsReportable($src),
                'emitter ' . basename($path) . ' must set a reportable flag explicitly (assignment shape)'
            );
        }
    }

    /** The listen.php gate must be fail-closed AND wired to the real ReportGate. */
    public function test_listen_gate_is_fail_closed(): void
    {
        $listen = (string) file_get_contents(self::repoRoot() . '/demo/listen.php');
        self::assertStringNotContainsString(
            "reportable'] ?? true",
            $listen,
            'demo/listen.php must not fall open on a missing reportable flag'
        );
        self::assertStringContainsString(
            'ReportGate::shouldReport(',
            $listen,
            'demo/listen.php must gate reporting through ReportGate::shouldReport()'
        );
    }
}
