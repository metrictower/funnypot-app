<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Closure;

/**
 * Writes an HTTP response as a raw byte stream (NDJSON / SSE chunks), one dialect turn at a time.
 * begin() sets the status + headers and drains any output buffering so bytes reach the client as
 * they're written, not batched at request end; chunk() writes + flushes each piece with a small
 * pacing delay so the stream reads like a model generating token-by-token rather than a single burst.
 * Headers passed to begin() must never include Content-Length — the whole point of streaming is that
 * the body length isn't known upfront.
 *
 * A $sink closure is injectable for tests: when present, begin()/chunk() write through the closure
 * instead of calling the real header()/http_response_code()/echo functions, so a test process never
 * tries to emit real HTTP headers.
 */
final class StreamEmitter
{
    private int $status = 200;

    /** @var array<string,string> */
    private array $headers = [];

    private string $captured = '';

    /** @param Closure(string):void|null $sink */
    public function __construct(private ?Closure $sink = null, private int $delayMs = 20)
    {
    }

    /** @param array<string,string> $headers */
    public function begin(int $status, array $headers): void
    {
        $this->status = $status;
        $this->headers = $headers;

        if ($this->sink !== null) {
            return;
        }

        // Real AI APIs send no X-Powered-By; strip the app's global persona header here too, so the
        // streaming path matches the buffered path even if the front-controller skip ever changes.
        header_remove('X-Powered-By');
        while (ob_get_level() > 0) {
            ob_end_flush();
        }
        http_response_code($status);
        foreach ($headers as $name => $value) {
            header("{$name}: {$value}");
        }
        if (!array_key_exists('X-Accel-Buffering', $headers)) {
            header('X-Accel-Buffering: no');
        }
    }

    public function chunk(string $bytes): void
    {
        if ($this->sink !== null) {
            ($this->sink)($bytes);
        } else {
            print $bytes;
            flush();
        }
        $this->captured .= $bytes;

        if ($this->delayMs !== 0) {
            usleep($this->delayMs * 1000);
        }
    }

    /** Test-only: every byte written so far, in order. */
    public function captured(): string
    {
        return $this->captured;
    }

    /** Test-only: the status recorded by begin(). */
    public function status(): int
    {
        return $this->status;
    }

    /** Test-only: the headers recorded by begin().
     *  @return array<string,string> */
    public function headers(): array
    {
        return $this->headers;
    }
}
