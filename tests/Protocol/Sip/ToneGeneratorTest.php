<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\ToneGenerator;
use PHPUnit\Framework\TestCase;

final class ToneGeneratorTest extends TestCase
{
    public function test_linear_16_to_mulaw_companding(): void
    {
        // In G.711 mu-law, zero or near zero maps to 0xff (or 0x7f)
        $zeroByte = ToneGenerator::linear16ToMuLaw(0);
        $this->assertSame(0xff, $zeroByte);

        // Positive full scale (32767) maps to 0x80
        $maxByte = ToneGenerator::linear16ToMuLaw(32767);
        $this->assertSame(0x80, $maxByte);

        // Negative full scale (-32768) maps to 0x00
        $minByte = ToneGenerator::linear16ToMuLaw(-32768);
        $this->assertSame(0x00, $minByte);
    }

    public function test_ring_slice_dimensions_and_cadence(): void
    {
        $gen = new ToneGenerator(440.0, 480.0, 2.0, 4.0); // 6s cycle = 300 slices

        $this->assertSame(300, $gen->getCycleSliceCount());

        // First slice (t=0s, during sound phase) must be exactly 160 bytes
        $slice0 = $gen->getRingSlice(0);
        $this->assertSame(160, strlen($slice0));
        $this->assertNotSame(str_repeat(chr(0xff), 160), $slice0, 'Sound phase must not be pure silence');

        // Slice at tick 120 (t=2.4s, during silence phase of 2s on / 4s off) must be pure silence
        $slice120 = $gen->getRingSlice(120);
        $this->assertSame(160, strlen($slice120));
        $this->assertSame(str_repeat(chr(0xff), 160), $slice120, 'Silence phase must be G.711u zero');

        // Check rollover at tick 300 (should equal tick 0)
        $slice300 = $gen->getRingSlice(300);
        $this->assertSame($slice0, $slice300);
    }
}
