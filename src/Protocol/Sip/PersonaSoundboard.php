<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Drop-in multi-persona soundboard for the SIP honeypot's audio tarpit.
 *
 * Each subdirectory of the audio dir that holds `*.ulaw` clips is discovered as a persona at
 * boot — drop a new folder of clips in and it automatically joins the per-caller cycle, no code
 * change. An optional `persona.json` in the folder tunes it:
 *   { "pauseSeconds": 3.5, "ringback": true, "cycle": true, "order": 10 }
 * Clips are raw headerless 8 kHz mono G.711 mu-law (what RTP sends and what recordings store).
 *
 * Auto mode cycles a fresh voice persona per caller IP; `fax` and `ring` are specials reached by
 * dialed number or an explicit mode, never dealt into the voice cycle.
 */
final class PersonaSoundboard
{
    /** Personas never dealt into the auto voice cycle (a tone and a procedural ringback). */
    private const NEVER_CYCLE = ['fax', 'ring'];

    /** Built-in pause defaults (seconds between clips) for the shipped personas; overridable per folder. */
    private const DEFAULT_PAUSE = [
        'lenny' => 5.5, 'scambaiter' => 5.5, 'scammer' => 3.5,
        'allison' => 3.0, 'operator' => 1.5, 'breather' => 1.0, 'fax' => 0.5,
    ];

    private ToneGenerator $toneGen;

    /** @var array<string, list<string>> raw clip contents keyed by persona */
    private array $personaClips = [];

    /** @var array<string, array{pause: float, ringback: bool, cycle: bool, order: int}> */
    private array $meta = [];

    /** @var list<string> ordered personas dealt into auto mode */
    private array $cycle = [];

    public function __construct(
        private readonly string $audioDir,
        ToneGenerator $toneGen = null,
    ) {
        $this->toneGen = $toneGen ?? new ToneGenerator();
        $this->loadClips();
    }

    /**
     * Resolves the persona for a call. An explicit mode forces one persona; otherwise auto mode
     * deals the next voice in the cycle by the caller's per-IP call count (1-based; 0/unset falls
     * back to the first). Dialed 999/"fax" -> fax tone, 888 -> procedural ring.
     */
    public function resolvePersona(string $mode, string $dialedNumber, int $callCount = 0): string
    {
        $mode = strtolower(trim($mode));
        if ($mode !== 'auto' && ($mode === 'ring' || isset($this->personaClips[$mode]))) {
            return $mode;
        }

        if (str_contains(strtolower($dialedNumber), 'fax') || $dialedNumber === '999') {
            return 'fax';
        }
        if ($dialedNumber === '888') {
            return 'ring';
        }

        if ($this->cycle === []) {
            return 'ring';
        }
        $idx = $callCount < 1 ? 0 : ($callCount - 1) % count($this->cycle);

        return $this->cycle[$idx];
    }

    /** The ordered personas dealt into auto mode (for diagnostics/tests). */
    public function cyclePersonas(): array
    {
        return $this->cycle;
    }

    public function hasClips(string $persona): bool
    {
        return !empty($this->personaClips[$persona]);
    }

    /**
     * Discovers every persona folder (a subdir with `*.ulaw` clips), loads its clips + metadata,
     * and builds the auto cycle.
     */
    private function loadClips(): void
    {
        $dirs = glob($this->audioDir . '/*', GLOB_ONLYDIR) ?: [];
        foreach ($dirs as $dir) {
            $name = basename($dir);
            $files = glob($dir . '/*.ulaw') ?: [];
            if ($files === []) {
                continue;
            }
            sort($files, SORT_NATURAL);

            $clips = [];
            foreach ($files as $f) {
                $content = @file_get_contents($f);
                if ($content !== false && $content !== '') {
                    $clips[] = $content;
                }
            }
            if ($clips === []) {
                continue;
            }

            $this->personaClips[$name] = $clips;
            $this->meta[$name] = $this->readMeta($name, $dir);
        }

        $cycle = [];
        foreach ($this->meta as $name => $m) {
            if (in_array($name, self::NEVER_CYCLE, true) || !$m['cycle']) {
                continue;
            }
            $cycle[] = $name;
        }
        usort($cycle, fn (string $a, string $b): int => [$this->meta[$a]['order'], $a] <=> [$this->meta[$b]['order'], $b]);
        $this->cycle = $cycle;
    }

    /**
     * @return array{pause: float, ringback: bool, cycle: bool, order: int}
     */
    private function readMeta(string $name, string $dir): array
    {
        $meta = [
            'pause' => self::DEFAULT_PAUSE[$name] ?? 4.0,
            'ringback' => $name !== 'fax', // the fax tone answers immediately; voices get a ringback first
            'cycle' => true,
            'order' => 100,
        ];

        $jsonPath = $dir . '/persona.json';
        if (is_file($jsonPath)) {
            $j = json_decode((string) @file_get_contents($jsonPath), true);
            if (is_array($j)) {
                if (isset($j['pauseSeconds'])) {
                    $meta['pause'] = max(0.0, (float) $j['pauseSeconds']);
                }
                if (isset($j['ringback'])) {
                    $meta['ringback'] = (bool) $j['ringback'];
                }
                if (isset($j['cycle'])) {
                    $meta['cycle'] = (bool) $j['cycle'];
                }
                if (isset($j['order'])) {
                    $meta['order'] = (int) $j['order'];
                }
            }
        }

        return $meta;
    }

    /**
     * Returns the next 160-byte (20ms) G.711u slice for the given session: a ringback while the
     * call "rings", then the persona's clips with a natural pause between each.
     */
    public function getNextSlice(SipSession $s): string
    {
        $persona = $s->persona;

        if ($persona === 'ring' || empty($this->personaClips[$persona])) {
            return $this->toneGen->getRingSlice($s->rtpPacketsSent);
        }

        // 3.0s of ringback tone (150 * 20ms) before the persona "answers", unless it opts out.
        if (($this->meta[$persona]['ringback'] ?? true) && $s->rtpPacketsSent < 150) {
            return $this->toneGen->getRingSlice($s->rtpPacketsSent);
        }

        $clips = $this->personaClips[$persona];
        $activeClip = $clips[$s->personaClipIndex % count($clips)];

        // In a natural silence pause between clips (0xff is mu-law zero/silence).
        if ($s->personaPauseRemaining > 0) {
            $s->personaPauseRemaining--;

            return str_repeat(chr(0xff), 160);
        }

        $offset = $s->personaClipOffset;
        if ($offset + 160 <= strlen($activeClip)) {
            $slice = substr($activeClip, $offset, 160);
            $s->personaClipOffset += 160;

            return $slice;
        }

        // Clip finished: pad the tail, advance to the next clip, and insert the persona's pause.
        $slice = str_pad(substr($activeClip, $offset), 160, chr(0xff));
        $s->personaClipIndex++;
        $s->personaClipOffset = 0;
        $s->personaPauseRemaining = (int) round(($this->meta[$persona]['pause'] ?? 4.0) / 0.020);

        return $slice;
    }
}
