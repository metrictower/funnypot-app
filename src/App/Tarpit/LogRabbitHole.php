<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\Core\Support\Fake\FakeSecrets;

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
 *     (the key at "line ~1.4M" costs nothing extra to reach). Normal filler is drawn from
 *     {@see SeededStream} (deterministic, O(block)); the juicy lines are injected at fixed indices.
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

    private SeededStream $stream;

    public function __construct(private int $personaSeed, private ?SeededStream $seeded = null)
    {
        $this->stream = $seeded ?? new SeededStream();
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
        $lo = intdiv(self::LINES, 4);
        $span = intdiv(self::LINES, 2);
        $out = [];
        for ($j = 0; $j < self::JUICY; $j++) {
            $h = hexdec(substr(hash('sha256', $this->personaSeed . '|applog|juicy|' . $j), 0, 12));
            $out[] = $lo + (int) ($h % $span);
        }
        sort($out);

        return array_values(array_unique($out));
    }

    /**
     * The credential-shaped token embedded on juicy line $i (empty if $i is not a juicy line). Public so
     * a test can assert exactly this token appears at its offset and nowhere in the head/tail. Every
     * value is an inert FakeSecrets shape that authenticates to nothing.
     */
    public function secretForLine(int $i): string
    {
        $idx = array_search($i, $this->juicyLineIndices(), true);
        if ($idx === false) {
            return '';
        }
        switch ($idx % 4) {
            case 0:
                return FakeSecrets::apiKey($this->personaSeed, 'applog|leak|' . $i);
            case 1:
                return FakeSecrets::stripeKey($this->personaSeed, 'applog|leak|' . $i);
            case 2:
                return FakeSecrets::resetToken($this->personaSeed, 'applog|leak|' . $i);
            default:
                return 'FLAG{' . substr(hash('sha256', $this->personaSeed . '|applog|flag|' . $i), 0, 32) . '}';
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

    /** A fixed-width lowercase-hex token, deterministic in ($label). Inert text. */
    private function hexToken(string $label, int $len): string
    {
        $raw = $this->stream->bytesAt($this->personaSeed, $label, 0, $len * 2);
        $hex = 'abcdef0123456789';
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= $hex[ord($raw[$i % strlen($raw)]) % 16];
        }

        return $out;
    }
}
