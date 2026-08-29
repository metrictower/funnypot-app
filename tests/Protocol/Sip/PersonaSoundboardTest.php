<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\PersonaSoundboard;
use Funnypot\Protocol\Sip\SipSession;
use PHPUnit\Framework\TestCase;

final class PersonaSoundboardTest extends TestCase
{
    private string $audioDir;

    /**
     * Build a self-contained fixture so the framework is tested without depending on the real
     * (licence-encumbered, gitignored) persona audio: four voice folders, a fax special, and one
     * folder opted out of the cycle via persona.json.
     */
    protected function setUp(): void
    {
        $this->audioDir = sys_get_temp_dir() . '/fp_sb_' . bin2hex(random_bytes(4));
        $clip = str_repeat(chr(0xff), 480); // 3 slices of mu-law silence

        $make = function (string $name, array $meta = null) use ($clip): void {
            $dir = $this->audioDir . '/' . $name;
            @mkdir($dir, 0777, true);
            file_put_contents($dir . '/01.ulaw', $clip);
            if ($meta !== null) {
                file_put_contents($dir . '/persona.json', json_encode($meta));
            }
        };

        $make('zebra');
        $make('aardvark');
        $make('middle');
        $make('ordered', ['order' => 1, 'pauseSeconds' => 2.0]); // sorts first via order
        $make('skipme', ['cycle' => false]);                      // discovered but never cycled
        $make('fax');                                             // special: excluded from the cycle
    }

    protected function tearDown(): void
    {
        if (is_dir($this->audioDir)) {
            foreach (glob($this->audioDir . '/*/*') ?: [] as $f) {
                @unlink($f);
            }
            foreach (glob($this->audioDir . '/*', GLOB_ONLYDIR) ?: [] as $d) {
                @rmdir($d);
            }
            @rmdir($this->audioDir);
        }
    }

    public function test_folders_are_discovered_as_personas(): void
    {
        $sb = new PersonaSoundboard($this->audioDir);
        foreach (['zebra', 'aardvark', 'middle', 'ordered', 'skipme', 'fax'] as $p) {
            $this->assertTrue($sb->hasClips($p), "{$p} must be discovered");
        }
    }

    public function test_auto_mode_cycles_discovered_voices_in_order(): void
    {
        $sb = new PersonaSoundboard($this->audioDir);

        // order:1 puts 'ordered' first; the rest are alphabetical; fax + skipme are excluded.
        $this->assertSame(['ordered', 'aardvark', 'middle', 'zebra'], $sb->cyclePersonas());

        $cycle = $sb->cyclePersonas();
        foreach ($cycle as $i => $persona) {
            $this->assertSame($persona, $sb->resolvePersona('auto', '101', $i + 1));
        }
        // Wrap-around, and zero/unset falls back to the first persona.
        $this->assertSame($cycle[0], $sb->resolvePersona('auto', '101', count($cycle) + 1));
        $this->assertSame($cycle[0], $sb->resolvePersona('auto', '101'));
    }

    public function test_explicit_mode_and_special_numbers(): void
    {
        $sb = new PersonaSoundboard($this->audioDir);

        // Any discovered persona can be forced explicitly, even one excluded from the cycle.
        $this->assertSame('zebra', $sb->resolvePersona('zebra', '101'));
        $this->assertSame('skipme', $sb->resolvePersona('skipme', '101'));
        $this->assertSame('ring', $sb->resolvePersona('ring', '101'));

        // Special dialed numbers short-circuit the cycle.
        $this->assertSame('fax', $sb->resolvePersona('auto', '999', 2));
        $this->assertSame('ring', $sb->resolvePersona('auto', '888', 3));
    }

    public function test_slice_streaming_ringback_then_clip(): void
    {
        $sb = new PersonaSoundboard($this->audioDir);
        $s = new SipSession('call-sb', '192.168.1.50', 5060);
        $s->persona = 'zebra';

        // First 150 packets (3.0s) are ringback tone.
        $this->assertSame(160, strlen($sb->getNextSlice($s)));

        // After answer, real clip bytes stream.
        $s->rtpPacketsSent = 150;
        $this->assertSame(160, strlen($sb->getNextSlice($s)));
        $this->assertGreaterThan(0, $s->personaClipOffset);
    }
}
