<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Sip;

use Funnypot\Protocol\Sip\ToneGenerator;
use Funnypot\Protocol\Sip\WavWriter;
use PHPUnit\Framework\TestCase;

final class WavWriterTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/funnypot_test_' . bin2hex(random_bytes(4)) . '.wav';
    }

    protected function tearDown(): void
    {
        if (is_file($this->tempFile)) {
            @unlink($this->tempFile);
        }
    }

    public function test_ulaw_to_linear_pcm_conversion(): void
    {
        // 0xff in G.711 mu-law is zero
        $pcm = WavWriter::ulawToLinearPcm(chr(0xff));
        $this->assertSame(2, strlen($pcm)); // 16-bit = 2 bytes

        $unpacked = unpack('s', $pcm); // signed 16-bit
        $this->assertSame(0, $unpacked[1]);
    }

    public function test_write_valid_riff_wav_file(): void
    {
        // 1 second of 8000 Hz tone
        $gen = new ToneGenerator(440.0, 480.0);
        $rawUlaw = '';
        for ($i = 0; $i < 50; $i++) {
            $rawUlaw .= $gen->getRingSlice($i);
        }
        $this->assertSame(8000, strlen($rawUlaw));

        $ok = WavWriter::writeWav($this->tempFile, $rawUlaw);
        $this->assertTrue($ok);
        $this->assertFileExists($this->tempFile);

        $contents = file_get_contents($this->tempFile);
        $this->assertNotFalse($contents);

        // Header assertions
        $this->assertStringStartsWith('RIFF', $contents);
        $this->assertSame('WAVE', substr($contents, 8, 4));
        $this->assertSame('fmt ', substr($contents, 12, 4));

        // Subchunk 1 format: PCM (1), 1 channel, 8000 Hz, 16000 bytes/sec, 2 block align, 16 bits/sample
        $fmt = unpack('Vaudiolen/vformat/vchannels/Vsamplerate/Vbyterate/valign/vbits', substr($contents, 16, 24));
        $this->assertSame(1, $fmt['format']);       // PCM
        $this->assertSame(1, $fmt['channels']);     // Mono
        $this->assertSame(8000, $fmt['samplerate']);
        $this->assertSame(16000, $fmt['byterate']);
        $this->assertSame(16, $fmt['bits']);

        // Data chunk
        $this->assertSame('data', substr($contents, 36, 4));
        $dataLen = unpack('Vlen', substr($contents, 40, 4))['len'];
        $this->assertSame(16000, $dataLen); // 8000 samples * 2 bytes = 16000 bytes
        $this->assertSame(44 + 16000, strlen($contents));
    }

    public function test_stereo_wav_two_channels_padded(): void
    {
        $left = str_repeat("\x00", 320);  // caller: 320 mu-law samples
        $right = str_repeat("\xff", 160); // persona: shorter, silence-padded to match

        $wav = WavWriter::stereoWavBytes($left, $right);

        $this->assertStringStartsWith('RIFF', $wav);
        $this->assertSame('WAVE', substr($wav, 8, 4));
        $fmt = unpack('Vaudiolen/vformat/vchannels/Vsamplerate/Vbyterate/valign/vbits', substr($wav, 16, 24));
        $this->assertSame(2, $fmt['channels']);  // stereo
        $this->assertSame(8000, $fmt['samplerate']);
        $this->assertSame(16, $fmt['bits']);
        $this->assertSame(4, $fmt['align']);     // 2ch * 2 bytes

        // data = max(320,160) frames * 2 channels * 2 bytes
        $dataLen = unpack('Vlen', substr($wav, 40, 4))['len'];
        $this->assertSame(320 * 2 * 2, $dataLen);
    }
}
