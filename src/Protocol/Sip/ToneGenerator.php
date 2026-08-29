<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Pure-PHP mathematical audio synthesis and G.711 mu-law (PCMU) compander.
 * Generates authentic dual-frequency telephone ringback tones with zero external files.
 */
final class ToneGenerator
{
    /** @var list<string> Pre-computed 160-byte G.711u audio chunks for one full cadence cycle */
    private array $ringSlices = [];

    public function __construct(
        private readonly float $f1 = 440.0,
        private readonly float $f2 = 480.0,
        private readonly float $cadenceOn = 2.0,
        private readonly float $cadenceOff = 4.0,
        private readonly int $sampleRate = 8000,
    ) {
        $this->precomputeRingCycle();
    }

    /**
     * Converts a signed 16-bit linear PCM sample (-32768 to 32767) to an 8-bit G.711 mu-law byte (RFC 3551).
     */
    public static function linear16ToMuLaw(int $pcm16): int
    {
        $sign = ($pcm16 < 0) ? 0x80 : 0;
        if ($pcm16 < 0) {
            $pcm16 = -$pcm16;
        }

        // Bias for mu-law companding
        $pcm16 += 0x84;
        if ($pcm16 > 0x7fff) {
            $pcm16 = 0x7fff;
        }

        $exponent = 7;
        for ($mask = 0x4000; ($pcm16 & $mask) === 0 && $exponent > 0; $mask >>= 1) {
            $exponent--;
        }

        $mantissa = ($pcm16 >> ($exponent + 3)) & 0x0f;
        $ulaw = ~($sign | ($exponent << 4) | $mantissa) & 0xff;

        return $ulaw;
    }

    /**
     * Precomputes an entire ring cadence cycle into 160-byte (20ms) slices.
     */
    private function precomputeRingCycle(): void
    {
        $cycleDuration = $this->cadenceOn + $this->cadenceOff;
        $totalSlices = (int) round($cycleDuration / 0.020); // 50 slices per second
        $samplesPerSlice = 160; // 20ms @ 8000 Hz

        $silenceByte = chr(self::linear16ToMuLaw(0));
        $silenceSlice = str_repeat($silenceByte, $samplesPerSlice);

        for ($sliceIdx = 0; $sliceIdx < $totalSlices; $sliceIdx++) {
            $timeStart = $sliceIdx * 0.020;
            $timeInCycle = fmod($timeStart, $cycleDuration);

            if ($timeInCycle >= $this->cadenceOn) {
                // Cadence silence phase
                $this->ringSlices[] = $silenceSlice;
                continue;
            }

            $bytes = '';
            for ($i = 0; $i < $samplesPerSlice; $i++) {
                $t = $timeStart + ($i / (float) $this->sampleRate);
                // Combine the two frequencies with 50% amplitude each
                $wave1 = sin(2.0 * M_PI * $this->f1 * $t);
                $wave2 = sin(2.0 * M_PI * $this->f2 * $t);
                $combined = ($wave1 + $wave2) * 0.5;

                // Scale to ~60% of 16-bit range to avoid clipping
                $pcm16 = (int) round($combined * 20000.0);
                $bytes .= chr(self::linear16ToMuLaw($pcm16));
            }

            $this->ringSlices[] = $bytes;
        }
    }

    /**
     * Returns the 160-byte G.711u audio slice for the given tick index.
     */
    public function getRingSlice(int $tick): string
    {
        if (empty($this->ringSlices)) {
            return str_repeat(chr(0xff), 160);
        }

        return $this->ringSlices[$tick % count($this->ringSlices)];
    }

    /**
     * Total number of 20ms slices in one ring cycle.
     */
    public function getCycleSliceCount(): int
    {
        return count($this->ringSlices);
    }

    /**
     * A 160-byte slice of faint line hiss (comfort noise) for the gaps between clips. Pure 0xff
     * (mu-law digital zero) is dead silence — a synthetic tell that answering-machine / human
     * detection heuristics flag instantly; a real phone line is never perfectly silent. The bytes are
     * chosen to decode to small magnitudes around both mu-law zeros (0xff / 0x7f), so it reads as a
     * quiet live line, not a tone. Cheap and inert.
     */
    public function getComfortNoiseSlice(): string
    {
        // Low-magnitude mu-law bytes: 0xF8..0xFF (small +) and 0x78..0x7F (small -).
        $out = '';
        for ($i = 0; $i < 160; $i++) {
            $mag = mt_rand(0, 7);                 // 0..7 -> very low amplitude
            $out .= chr((mt_rand(0, 1) ? 0xF8 : 0x78) | $mag);
        }

        return $out;
    }
}
