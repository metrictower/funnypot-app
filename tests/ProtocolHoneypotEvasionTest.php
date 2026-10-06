<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\Ssh\SshConnection;
use PHPUnit\Framework\ExpectationFailedException;
use PHPUnit\Framework\TestCase;

/**
 * Inverse regression: proves funnypot's own protocol emulators do NOT trip the nuclei
 * honeypot-detector templates that target the services we emulate. The pass condition is the
 * opposite of an ordinary template test — a detector's tell strings must NEVER appear in what
 * our emulator sends, whether swept statically across every canned reply or fed the detector's
 * own probe bytes through the real engine.
 *
 * Ground truth for every tell string and probe below is read straight from
 * nuclei-templates/network/honeypot/*.yaml. Re-read the named template if a string here ever
 * needs re-verifying — do not paraphrase from memory.
 *
 * SCOPE (corrected, FP-0371 — the prior docstring falsely claimed funnypot had no MySQL/SMB/MQTT/
 * ADB/S7comm/EtherNet-IP emulator; all of those now exist, so those detectors are IN scope):
 *  - Covered by the static sweep + behavioral probe below, because they are TEMPLATE protocols
 *    (templates/protocol/*.yaml, driven through ProtocolTemplateSet): redis, ssh, ftp, smtp, and now
 *    mysql (dionaea-mysql-honeypot-detect) and ethernet-ip (cpppo-ethernetip-cip-honeypot).
 *  - NOT yet covered here, because they are BESPOKE code servers (src/Protocol/{Smb,Mqtt,Adb,S7comm})
 *    with their own Server/Session API, which neither the ProtocolTemplateSet static sweep nor the
 *    behavioral probe can drive: dionaea-smb/mqtt-honeypot-detect, adbhoney-honeypot-{cnxn,shell}-detect,
 *    conpot-siemens-honeypot-detect, snap7-honeypot-default-config. These need a per-server live-probe
 *    mechanism — tracked in FP-0604. They are believed clean (each emulator's own test asserts its
 *    persona), but are not yet asserted against the detector tells HERE.
 *  - Genuinely out of scope: gaspot-honeypot-detect (Veeder-Root gas-pump controller) — funnypot has
 *    no such emulator, so there is nothing to detect.
 *
 * CAVEAT: the static sweep inspects the compiled template's PRE-RENDER literal (its `{{hex:..}}` blocks
 * are NOT byte-expanded), so it catches an ASCII literal tell (a version/product/salt string) but not a
 * tell hex-encoded inside a `{{hex:..}}` block. That is sufficient for every tell asserted here (all
 * ASCII literals), but a future binary-protocol tell would need a behavioral/byte-level probe (FP-0604).
 */
final class ProtocolHoneypotEvasionTest extends TestCase
{
    // ------------------------------------------------------------------------------------------
    // Part 1 — static sweep: every canned reply a compiled protocol can ever produce (banner +
    // every rule's `send` + the default `send`) must never carry a detector's tell string. This
    // catches a leak introduced anywhere in a protocol template, not just on the exact command
    // the detector happens to probe with.
    // ------------------------------------------------------------------------------------------

    /**
     * protocol id => [tell words from that detector's `matchers`, the template file they came from].
     *
     * @return array<string, array{0:string, 1:string[], 2:string}>
     */
    public static function staticSweepCases(): array
    {
        return [
            'redis-honeypot-detect' => [
                'redis',
                ["-ERR unknown command `QUIT`, with args beginning with:"],
                'nuclei-templates/network/honeypot/redis-honeypot-detect.yaml',
            ],
            'dionaea-ftp-honeypot-detect' => [
                'ftp',
                ['500 Syntax error: PASS requires an argument'],
                'nuclei-templates/network/honeypot/dionaea-ftp-honeypot-detect.yaml',
            ],
            'mailoney-honeypot-detect' => [
                'smtp',
                ['502 Error: command "HELP" not implemented'],
                'nuclei-templates/network/honeypot/mailoney-honeypot-detect.yaml',
            ],
            // The word half of cowrie's matcher — see Part 3 for the AND-with-regex replication
            // against the real crypto SSH server. Swept here against the generic rule-engine ssh
            // template too (port 2222), since that template can also change independently.
            'cowrie-ssh-honeypot-detect (generic ssh template)' => [
                'ssh',
                ['Protocol major versions differ.', 'bad version 1337'],
                'nuclei-templates/network/honeypot/cowrie-ssh-honeypot-detect.yaml',
            ],
            // FP-0371: MySQL + EtherNet-IP ARE funnypot template emulators (the old docstring wrongly
            // excluded them). Dionaea's MySQL honeypot is fingerprinted by the static greeting
            // version 5.7.16 AND the fixed scramble salt "aaaaaaaa"; funnypot's greeting is 8.0.36 with
            // a varied salt, so neither tell may appear in its served bytes.
            'dionaea-mysql-honeypot-detect' => [
                'mysql',
                ['5.7.16', 'aaaaaaaa'],
                'nuclei-templates/network/honeypot/dionaea-mysql-honeypot-detect.yaml',
            ],
            // cpppo's EtherNet-IP honeypot ships the default CIP product name "1756-L61/B"; funnypot's
            // identity is a "1769-" CompactLogix, so the "1756-L61" signature must never appear.
            'cpppo-ethernetip-cip-honeypot' => [
                'ethernet-ip',
                ['1756-L61/B', '1756-L61'],
                'nuclei-templates/network/honeypot/cpppo-ethernetip-cip-honeypot.yaml',
            ],
        ];
    }

    /**
     * Non-vacuity / gate-bite: the sweep must actually INSPECT served bytes, so an "absent" assertion
     * is meaningful rather than passing on empty content. Prove it by confirming the sweep sees a string
     * that genuinely IS in the mysql greeting, and that it would FLAG a planted tell.
     */
    public function test_static_sweep_actually_inspects_served_bytes(): void
    {
        $joined = implode("\n", $this->allSendableStrings($this->compiledProtocol('mysql')));
        self::assertStringContainsString('mysql_native_password', $joined, 'the sweep must see the real greeting');
        self::assertStringContainsString('8.0.36', $joined, 'funnypot presents 8.0.36, not the dionaea 5.7.16');
        // ethernet-ip non-vacuity: its banner is empty, so coverage rests on the identity send — confirm
        // the sweep actually sees it (else the 1756-L61 absent-assertion could pass on empty content).
        $eip = implode("\n", $this->allSendableStrings($this->compiledProtocol('ethernet-ip')));
        self::assertStringContainsString('1769-', $eip, 'the sweep must see the ethernet-ip CompactLogix identity');

        // Gate-bite: prove the sweep's OWN assertion (assertStringNotContainsString) FIRES on a planted
        // tell — so the absent-assertions above are a real guard, not theater. Real content is clean;
        // the same content with a tell appended must trip the assertion.
        self::assertStringNotContainsString('5.7.16', $joined);
        $tripped = false;
        try {
            self::assertStringNotContainsString('5.7.16', $joined . "\n5.7.16");
        } catch (ExpectationFailedException $e) {
            $tripped = true;
        }
        self::assertTrue($tripped, 'the evasion sweep would not have caught a planted dionaea tell');
    }

    /**
     * @dataProvider staticSweepCases
     * @param string[] $tellWords
     */
    public function test_no_canned_reply_ever_carries_a_detectors_tell(string $protocolId, array $tellWords, string $source): void
    {
        $strings = $this->allSendableStrings($this->compiledProtocol($protocolId));

        foreach ($tellWords as $tell) {
            foreach ($strings as $label => $text) {
                self::assertStringNotContainsString(
                    $tell,
                    $text,
                    "funnypot's '{$protocolId}' protocol leaks {$source}'s honeypot tell string via {$label}"
                );
            }
        }
    }

    /** @return array<string,mixed> */
    private function compiledProtocol(string $id): array
    {
        $all = require __DIR__ . '/../resources/compiled/funnypot-protocols.php';
        self::assertArrayHasKey($id, $all, "no compiled '{$id}' protocol — run \`funnypot compile-protocols\`");

        return $all[$id];
    }

    /**
     * Flatten a compiled protocol's banner + every rule's `send` + the default `send` (each a
     * plain string, or a codec spec like `bulk`/`bulk_array` for RESP) into label => text.
     *
     * @param array<string,mixed> $protocol
     * @return array<string,string>
     */
    private function allSendableStrings(array $protocol): array
    {
        $out = ['banner' => (string) ($protocol['banner'] ?? '')];
        foreach ((array) ($protocol['rules'] ?? []) as $i => $rule) {
            foreach ($this->flattenSend($rule['send'] ?? '') as $j => $text) {
                $out["rules[{$i}].send#{$j}"] = $text;
            }
        }
        foreach ($this->flattenSend($protocol['default']['send'] ?? '') as $j => $text) {
            $out["default.send#{$j}"] = $text;
        }

        return $out;
    }

    /**
     * @param mixed $send
     * @return string[]
     */
    private function flattenSend($send): array
    {
        if (is_string($send)) {
            return [$send];
        }
        if (!is_array($send)) {
            return [];
        }
        $out = [];
        foreach ($send as $v) {
            if (is_string($v)) {
                $out[] = $v;
            } elseif (is_array($v)) {
                foreach ($v as $item) {
                    $out[] = (string) $item;
                }
            }
        }

        return $out;
    }

    // ------------------------------------------------------------------------------------------
    // Part 2 — behavioral: feed the detector's own probe bytes through the real ProtocolEmulator
    // (banner + feed(), the same seam Listener drives) and check the actual wire response. This
    // is closer to what nuclei itself observes than the static sweep, and would catch a codec- or
    // framing-level regression the static sweep can't see.
    // ------------------------------------------------------------------------------------------

    /**
     * label => [protocol id, probe bytes (CRLF-terminated, as a real client completes the line),
     * tell words, source template].
     *
     * @return array<string, array{0:string, 1:string, 2:string[], 3:string}>
     */
    public static function behavioralProbeCases(): array
    {
        return [
            'redis-honeypot-detect (QUIT)' => [
                'redis',
                "QUIT\r\n",
                ["-ERR unknown command `QUIT`, with args beginning with:"],
                'nuclei-templates/network/honeypot/redis-honeypot-detect.yaml',
            ],
            'dionaea-ftp-honeypot-detect (USER root / PASS)' => [
                'ftp',
                "USER root\r\nPASS \r\n",
                ['500 Syntax error: PASS requires an argument'],
                'nuclei-templates/network/honeypot/dionaea-ftp-honeypot-detect.yaml',
            ],
            'mailoney-honeypot-detect (HELP)' => [
                'smtp',
                "HELP\r\n",
                ['502 Error: command "HELP" not implemented'],
                'nuclei-templates/network/honeypot/mailoney-honeypot-detect.yaml',
            ],
        ];
    }

    /**
     * @dataProvider behavioralProbeCases
     * @param string[] $tellWords
     */
    public function test_live_response_to_the_detectors_own_probe_never_leaks_the_tell(
        string $protocolId,
        string $probe,
        array $tellWords,
        string $source
    ): void {
        $emulator = ProtocolTemplateSet::fromPackage()->emulator($protocolId);
        self::assertNotNull($emulator, "no '{$protocolId}' emulator compiled");

        $session = new ProtocolSession(1);
        $response = $emulator->banner($session) . $emulator->feed($probe, $session);

        foreach ($tellWords as $tell) {
            self::assertStringNotContainsString(
                $tell,
                $response,
                "funnypot's live '{$protocolId}' response matches {$source}'s honeypot tell string"
            );
        }
    }

    public function test_redis_evades_even_with_nucleis_literal_unterminated_probe(): void
    {
        // redis-honeypot-detect's own `data:` is the bare bytes "QUIT" with no line terminator.
        // Our RESP codec — like real Redis's inline-command parser — only completes a request on
        // a line terminator, so this exact wire payload never yields a response at all here,
        // never mind one carrying the tell.
        $emulator = ProtocolTemplateSet::fromPackage()->emulator('redis');
        self::assertNotNull($emulator);

        $session = new ProtocolSession(1);
        $response = $emulator->banner($session) . $emulator->feed('QUIT', $session);

        self::assertStringNotContainsString("-ERR unknown command `QUIT`, with args beginning with:", $response);
    }

    // ------------------------------------------------------------------------------------------
    // Part 3 — cowrie-ssh-honeypot-detect vs the real pure-PHP SSH server (src/Protocol/Ssh/*),
    // not the generic rule-engine template. The detector's matcher is `and` across two groups:
    // a regex on the response body, and a word group (`or`) of the tell strings. The regex half
    // is satisfied by virtually any real "SSH-x.y-..." banner, so the whole match lives or dies
    // on the word group — which is why proving those words are absent is a sufficient proof of
    // non-detection on its own, and why this test also replicates the full boolean once for the
    // record.
    // ------------------------------------------------------------------------------------------

    public function test_ssh_servers_silent_close_never_matches_cowrie_detector(): void
    {
        $log = [];
        $connection = $this->freshSshConnection($log);

        $connection->onConnect();
        $banner = $connection->takeOut(); // our identification line + KEXINIT, sent before we read anything

        $connection->feed("SSH-1337-OpenSSH_9.0\r\n"); // cowrie-ssh-honeypot-detect's own probe
        $reply = $connection->takeOut();

        self::assertTrue($connection->isClosed(), 'a malformed client version string must be dropped');
        self::assertSame(
            '',
            $reply,
            'an unauthenticated version-mismatch disconnect must be silent, like real OpenSSH — no diagnostic text on the wire'
        );

        $wire = $banner . $reply;
        self::assertStringNotContainsString('Protocol major versions differ.', $wire, 'that is cowrie/twisted diagnostic text, not OpenSSH');
        self::assertStringNotContainsString('bad version 1337', $wire);
    }

    public function test_cowrie_detectors_full_and_matcher_never_fires_against_the_real_ssh_server(): void
    {
        $log = [];
        $connection = $this->freshSshConnection($log);

        $connection->onConnect();
        $wire = $connection->takeOut();
        $connection->feed("SSH-1337-OpenSSH_9.0\r\n");
        $wire .= $connection->takeOut();

        // Group 1 (regex, part: body) from cowrie-ssh-honeypot-detect.yaml, verbatim.
        $regexMatches = preg_match('~SSH\-([0-9.-A-Za-z_ ]+)~', $wire) === 1;
        // Group 2 (word, condition: or) from the same template, verbatim.
        $wordMatches = str_contains($wire, 'Protocol major versions differ.') || str_contains($wire, 'bad version 1337');
        // matchers-condition: and
        $detectorFires = $regexMatches && $wordMatches;

        self::assertFalse($detectorFires, 'cowrie-ssh-honeypot-detect would flag the real SSH server as a honeypot');
    }

    /** @param array<int,string> $log */
    private function freshSshConnection(array &$log): SshConnection
    {
        // No explicit server-version arg: this pins the real production default
        // ('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10') rather than a test-only stand-in.
        return new SshConnection(
            SshHostKeyFixture::set(),
            new ProtocolSession(1),
            static function (string $event, string $detail) use (&$log): void {
                $log[] = $event . ':' . $detail;
            }
        );
    }
}
