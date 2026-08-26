<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\StreamEmitter;
use PHPUnit\Framework\TestCase;

final class StreamEmitterTest extends TestCase
{
    public function test_streams_chunks_through_the_injected_sink_and_records_status_headers(): void
    {
        $written = '';
        $emitter = new StreamEmitter(function (string $bytes) use (&$written): void {
            $written .= $bytes;
        }, 0);

        $emitter->begin(200, ['Content-Type' => 'application/x-ndjson']);
        $emitter->chunk('a');
        $emitter->chunk('b');

        self::assertSame('ab', $emitter->captured());
        self::assertSame('ab', $written);
        self::assertSame(200, $emitter->status());
        self::assertSame(['Content-Type' => 'application/x-ndjson'], $emitter->headers());
    }

    public function test_real_response_path_keeps_no_copy_of_the_body(): void
    {
        // Memory guard: without a sink the bytes go straight out. A response can be tens of MB (the
        // download bait), so retaining it would hold the whole body in the worker for the transfer.
        $emitter = new StreamEmitter(null, 0);

        ob_start();
        $emitter->chunk('xy');
        $printed = (string) ob_get_clean();

        self::assertSame('xy', $printed);
        self::assertSame('', $emitter->captured());
    }

    public function test_sink_path_never_calls_real_header_functions(): void
    {
        // Regression guard: begin() with a sink injected must not call header()/http_response_code(),
        // which would emit "headers already sent" noise (or fail outright) under the CLI test runner.
        $emitter = new StreamEmitter(function (): void {
        }, 0);

        $emitter->begin(204, []);

        self::assertSame(204, $emitter->status());
        self::assertSame([], $emitter->headers());
    }
}
