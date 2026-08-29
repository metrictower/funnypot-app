<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Converts raw 8000 Hz G.711 mu-law audio streams into universally playable 16-bit linear PCM .wav files.
 */
final class WavWriter
{
    /** @var list<int> 256-element lookup table mapping 8-bit mu-law to signed 16-bit PCM */
    private static ?array $ulawToPcmTable = null;

    /**
     * Initializes the mu-law expansion lookup table according to ITU-T G.711 specifications.
     */
    private static function initTable(): void
    {
        if (self::$ulawToPcmTable !== null) {
            return;
        }

        self::$ulawToPcmTable = [];
        for ($i = 0; $i < 256; $i++) {
            $input = ~$i;
            $sign = ($input & 0x80) ? -1 : 1;
            $exponent = ($input >> 4) & 0x07;
            $mantissa = $input & 0x0f;

            $sample = (($mantissa << 3) + 0x84) << $exponent;
            $sample -= 0x84;

            self::$ulawToPcmTable[$i] = $sign * $sample;
        }
    }

    /**
     * Converts a string of raw 8-bit G.711 mu-law bytes into 16-bit little-endian linear PCM bytes.
     */
    public static function ulawToLinearPcm(string $ulawData): string
    {
        self::initTable();

        $len = strlen($ulawData);
        $pcm = '';
        for ($i = 0; $i < $len; $i++) {
            $byte = ord($ulawData[$i]);
            $sample = self::$ulawToPcmTable[$byte];
            $pcm .= pack('v', $sample & 0xffff);
        }

        return $pcm;
    }

    /**
     * Builds a complete 16-bit, 8000 Hz mono PCM .wav byte string from raw G.711 mu-law audio.
     * Recordings are stored on disk as raw mu-law (half the size); this expands them to a
     * universally playable WAV only when served.
     */
    public static function wavBytes(string $ulawData): string
    {
        $pcm = self::ulawToLinearPcm($ulawData);
        $dataLen = strlen($pcm);
        $riffLen = 36 + $dataLen;

        // RIFF header
        $header = 'RIFF' . pack('V', $riffLen) . 'WAVE';

        // 'fmt ' subchunk: 16 bytes for standard PCM format
        // AudioFormat=1 (PCM), NumChannels=1, SampleRate=8000, ByteRate=16000, BlockAlign=2, BitsPerSample=16
        $header .= 'fmt ' . pack('VvvVVvv', 16, 1, 1, 8000, 16000, 2, 16);

        // 'data' subchunk
        $header .= 'data' . pack('V', $dataLen);

        return $header . $pcm;
    }

    /**
     * Builds a 16-bit, 8000 Hz STEREO PCM .wav from two raw mu-law streams — left channel is the
     * caller, right is the honeypot persona — so a conversation can be heard with both sides
     * separable. The shorter stream is padded with silence.
     */
    public static function stereoWavBytes(string $leftUlaw, string $rightUlaw): string
    {
        self::initTable();
        $ll = strlen($leftUlaw);
        $rl = strlen($rightUlaw);
        $n = max($ll, $rl);

        $pcm = '';
        for ($i = 0; $i < $n; $i++) {
            $l = $i < $ll ? self::$ulawToPcmTable[ord($leftUlaw[$i])] : 0;
            $r = $i < $rl ? self::$ulawToPcmTable[ord($rightUlaw[$i])] : 0;
            $pcm .= pack('vv', $l & 0xffff, $r & 0xffff);
        }

        $dataLen = strlen($pcm);
        $header = 'RIFF' . pack('V', 36 + $dataLen) . 'WAVE';
        // fmt: PCM, 2 channels, 8000 Hz, ByteRate 32000, BlockAlign 4, 16 bits
        $header .= 'fmt ' . pack('VvvVVvv', 16, 1, 2, 8000, 32000, 4, 16);
        $header .= 'data' . pack('V', $dataLen);

        return $header . $pcm;
    }

    /**
     * Saves raw G.711 mu-law audio data to a valid 16-bit, 8000 Hz mono PCM .wav file.
     */
    public static function writeWav(string $filePath, string $ulawData): bool
    {
        $dir = dirname($filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        return @file_put_contents($filePath, self::wavBytes($ulawData)) !== false;
    }
}
