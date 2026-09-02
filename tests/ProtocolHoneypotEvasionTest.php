<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Protocol\ProtocolTemplateSet;
use Funnypot\Protocol\Ssh\SshConnection;
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
 * Of the 13 templates in that directory, only four target a service funnypot emulates (redis,
 * ssh, ftp, smtp). The rest — dionaea-mysql/smb/mqtt-honeypot-detect, adbhoney-honeypot-{cnxn,
 * shell}-detect, conpot-siemens-honeypot-detect, cpppo-ethernetip-cip-honeypot,
 * gaspot-honeypot-detect, snap7-honeypot-default-config — probe MySQL, SMB, MQTT, Android ADB,
 * Siemens S7comm/CIP, and Veeder-Root gas-pump-controller protocols funnypot has no emulator
 * for, so they are out of scope: there is nothing on our side for them to detect or evade.
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
        ];
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
        $banner = $connection->takeOut(); // our identification line — nothing else is sent before we read the client's
        // FP-0290: the KEXINIT now follows the client's ident line, so a bare connection sees only the banner.
        self::assertSame(
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
            $banner,
            'banner only before the client speaks (production default), no KEXINIT'
        );

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
