<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\App\AiApi\StreamEmitter;

/**
 * A4 — the log rabbit-hole (FP-0245c context-polluter). A synthetic multi-thousand-line `app.log`
 * whose few "interesting" lines (a leaked credential-shaped token) sit at seed-derived DEEP offsets,
 * far past the head/tail an agent would sample — so a reasoning agent that wants the key must ingest
 * (and re-bill) the whole file, or reconstruct a Range request, to find it.
 *
 * The asymmetry the ticket rests on:
 *   - FIXED-WIDTH lines ⇒ the byte at any offset is a pure function of its line index, so the log is
 *     fully OFFSET-ADDRESSABLE: {@see bytesAt()} builds only the lines spanning a window, and a
 *     `Range: bytes=X-Y` around the deep key is served in O(window) memory — the fable A4 property
 *     (the key at "line ~1.4M" costs nothing extra to reach). Each line's filler is a cheap per-line
 *     hash (deterministic); the juicy credential lines are injected at fixed, seed-derived indices.
 *   - STREAMED + HARD BYTE-CAPPED for a full-body GET: fabricated line-by-line, flushed, never
 *     materialised; connection_aborted() halts fabrication.
 *   - INERT: the juicy tokens are {@see FakeSecrets} shapes (AWS/Stripe/reset/JWT) that authenticate to
 *     nothing, plus dead FLAG{...} honeytokens; no real host/ARN/third-party endpoint anywhere.
 */
final class LogRabbitHole
{
    /** Every line is exactly this many bytes INCLUDING the trailing "\n" — the offset-addressable key.
     *  Wide enough that the longest juicy token (a 40-hex reset token) fits after its line prefix. */
    public const LINE_WIDTH = 160;

    /** The log's logical line count. ~6 MiB at 160 B/line — comfortably larger than any head/tail sample. */
    private const LINES = 40000;

    /** How many juicy (credential-bearing) lines are injected. */
    private const JUICY = 4;

    /** @var list<int>|null memoised juicy line indices */
    private ?array $juicy = null;

    /** @var array<int,int>|null memoised line-index => juicy rank, for O(1) secretForLine() */
    private ?array $juicyRank = null;

    public function __construct(private int $personaSeed)
    {
    }

    /** The log's total logical byte size (LINES * LINE_WIDTH). */
    public function size(): int
    {
        return self::LINES * self::LINE_WIDTH;
    }

    /**
     * The line indices carrying the juicy credential tokens — seed-derived and confined to the MIDDLE
     * band [LINES/4, 3·LINES/4), so they can never fall inside a head or tail sample. Public so a test
     * can prove the key is absent from head/tail but present at its true offset.
     *
     * @return list<int>
     */
    public function juicyLineIndices(): array
    {
        if ($this->juicy !== null) {
            return $this->juicy;
        }
        $lo = intdiv(self::LINES, 4);
        $span = intdiv(self::LINES, 2);
        $out = [];
        for ($j = 0; $j < self::JUICY; $j++) {
            $h = hexdec(substr(hash('sha256', $this->personaSeed . '|applog|juicy|' . $j), 0, 12));
            $out[] = $lo + (int) ($h % $span);
        }
        sort($out);
        $this->juicy = array_values(array_unique($out));
        $this->juicyRank = array_flip($this->juicy);

        return $this->juicy;
    }

    /**
     * The credential-shaped token embedded on juicy line $i (empty if $i is not a juicy line). Public so
     * a test can assert exactly this token appears at its offset and nowhere in the head/tail. Every
     * value is an inert FakeSecrets shape that authenticates to nothing.
     */
    public function secretForLine(int $i): string
    {
        $this->juicyLineIndices(); // ensure the rank lookup is built
        $idx = $this->juicyRank[$i] ?? null;
        if ($idx === null) {
            return '';
        }
        switch ($idx % 4) {
            case 0:
                return InertSecret::apiKey($this->personaSeed, 'applog|leak|' . $i);
            case 1:
                return InertSecret::stripeKey($this->personaSeed, 'applog|leak|' . $i);
            case 2:
                return InertSecret::resetToken($this->personaSeed, 'applog|leak|' . $i);
            default:
                return InertSecret::flag($this->personaSeed, 'applog|' . $i);
        }
    }

    /**
     * The generated log bytes over [offset, offset+len). Pure + offset-addressable: computes only the
     * lines spanning the window (O(window) memory, independent of $offset), so a Range near the end is
     * exactly as cheap as one at the start. Overlapping windows agree byte-for-byte.
     */
    public function bytesAt(int $offset, int $len): string
    {
        $size = $this->size();
        if ($len <= 0 || $offset < 0 || $offset >= $size) {
            return '';
        }
        $len = min($len, $size - $offset);
        $firstLine = intdiv($offset, self::LINE_WIDTH);
        $lastLine = intdiv($offset + $len - 1, self::LINE_WIDTH);
        $buf = '';
        for ($i = $firstLine; $i <= $lastLine; $i++) {
            $buf .= $this->lineAt($i);
        }

        return substr($buf, $offset - $firstLine * self::LINE_WIDTH, $len);
    }

    /**
     * Stream the whole log through the emitter up to $capBytes (or the log's size, whichever is smaller),
     * halting on client hang-up. Returns bytes emitted. Line-by-line, so memory is O(one line).
     *
     * @param callable():int|null $aborted
     */
    public function stream(StreamEmitter $e, int $capBytes, ?callable $aborted = null): int
    {
        $aborted ??= static fn (): int => connection_aborted();
        $sent = 0;
        foreach ($this->chunks($capBytes) as $chunk) {
            $e->chunk($chunk);
            $sent += strlen($chunk);
            if ($aborted() !== 0) {
                break;
            }
        }

        return $sent;
    }

    /**
     * Yield the log line-by-line up to min($capBytes, size()). A \Generator so tests drain summing
     * strlen() and discarding — the honest O(line) memory measure.
     *
     * @return \Generator<int,string>
     */
    public function chunks(int $capBytes): \Generator
    {
        if ($capBytes <= 0) {
            return;
        }
        $cap = min($capBytes, $this->size());
        $sent = 0;
        for ($i = 0; $i < self::LINES && $sent < $cap; $i++) {
            $line = $this->lineAt($i);
            if ($sent + strlen($line) > $cap) {
                $line = substr($line, 0, $cap - $sent);
            }
            $sent += strlen($line);
            yield $line;
        }
    }

    /** One log line, exactly LINE_WIDTH bytes (content padded/truncated + a single trailing "\n"). */
    private function lineAt(int $i): string
    {
        $secret = $this->secretForLine($i);
        if ($secret !== '') {
            // A "recovered legacy credential" WARNING — the juicy line the whole file exists to bury.
            // Kept short so the token itself fits within LINE_WIDTH (never truncated).
            $content = $this->timestamp($i) . ' [WARN ] auth.legacy recovered stale credential: ' . $secret;
        } else {
            $lvl = ['INFO ', 'DEBUG', 'INFO ', 'INFO ', 'WARN '][$i % 5];
            $reqId = $this->hexToken('applog|req|' . $i, 16);
            $obj = $this->hexToken('applog|obj|' . $i, 12);
            $status = [200, 200, 200, 201, 204, 302, 404][$i % 7];
            $dur = 1 + ($i * 7 % 900);
            $content = $this->timestamp($i) . ' [' . $lvl . '] http.access req=' . $reqId
                . ' method=GET path=/api/v2/records/' . $obj . ' status=' . $status . ' dur=' . $dur . 'ms';
        }

        // Fixed width: pad short lines with '.' filler, hard-truncate long ones, then the newline.
        $content = substr($content, 0, self::LINE_WIDTH - 1);
        $content = str_pad($content, self::LINE_WIDTH - 1, '.');

        return $content . "\n";
    }

    /** A synthetic ISO-ish timestamp that advances by line index (deterministic, no real clock). */
    private function timestamp(int $i): string
    {
        // Fixed base epoch (2026-01-01T00:00:00Z) + i seconds, formatted deterministically.
        $t = 1767225600 + $i;

        return gmdate('Y-m-d\TH:i:s', $t) . '.000Z';
    }

    /**
     * A fixed-width lowercase-hex token, deterministic in ($label). One sha256 per token (cheap) — the
     * log stays offset-addressable because {@see lineAt()} is itself deterministic and fixed-width, so
     * bytesAt() needs no 4 KiB block model to seek; keeping a full log serve well under the slot TTL.
     */
    private function hexToken(string $label, int $len): string
    {
        return substr(hash('sha256', $this->personaSeed . '|' . $label), 0, $len);
    }
}
