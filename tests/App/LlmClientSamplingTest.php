<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmClient;
use PHPUnit\Framework\TestCase;

/**
 * The optional sampling override on LlmClient::generate(). Null (the page-generation default) must
 * keep the exact low-temp, fixed-seed request the deterministic HTML fakes depend on; an override map
 * (the chat path) may crank temperature / min_p and randomise the seed without disturbing page-gen.
 */
final class LlmClientSamplingTest extends TestCase
{
    /** @return array{0:LlmClient,1:callable():?array<string,mixed>} client + a captor for the last request */
    private function make(): array
    {
        $captured = null;
        $transport = function (string $url, string $body) use (&$captured): array {
            $captured = json_decode($body, true);

            return ['status' => 200, 'body' => (string) json_encode(['content' => 'ok'])];
        };
        $client = new LlmClient('http://sidecar/completion', 1500, 320, null, $transport);
        $last = function () use (&$captured): ?array {
            return $captured;
        };

        return [$client, $last];
    }

    public function test_null_sampling_keeps_the_page_gen_defaults(): void
    {
        [$client, $last] = $this->make();
        $client->generate('PROMPT', 'root ::= "<"');   // page-gen path: no sampling arg

        $p = $last();
        self::assertSame(0.4, $p['temperature']);
        self::assertSame(0.9, $p['top_p']);
        self::assertSame(1.1, $p['repeat_penalty']);
        self::assertSame(42, $p['seed']);
        self::assertSame(320, $p['n_predict']);
        self::assertArrayNotHasKey('min_p', $p);   // page-gen never sends min_p
        self::assertArrayNotHasKey('top_k', $p);
    }

    public function test_override_applies_chat_sampling_and_keeps_n_predict(): void
    {
        [$client, $last] = $this->make();
        $client->generate('PROMPT', '', [
            'temperature' => 1.5,
            'min_p' => 0.0,
            'top_p' => 1.0,
            'top_k' => 0,
            'seed' => 987654321,
        ]);

        $p = $last();
        self::assertSame(1.5, $p['temperature']);
        // JSON collapses whole-number floats (0.0 -> 0, 1.0 -> 1) on the wire; cast before comparing.
        self::assertSame(0.0, (float) $p['min_p']);
        self::assertSame(1.0, (float) $p['top_p']);
        self::assertSame(0, $p['top_k']);
        self::assertSame(987654321, $p['seed']);
        self::assertSame(320, $p['n_predict']);   // n_predict stays as configured
    }

    public function test_override_ignores_unknown_keys(): void
    {
        [$client, $last] = $this->make();
        $client->generate('PROMPT', '', ['temperature' => 1.2, 'prompt' => 'HACK', 'stop' => ['x']]);

        $p = $last();
        self::assertSame(1.2, $p['temperature']);
        self::assertSame('PROMPT', $p['prompt']);              // not overridable
        self::assertSame(['<|im_end|>', '</html>'], $p['stop']);   // not overridable
    }
}
