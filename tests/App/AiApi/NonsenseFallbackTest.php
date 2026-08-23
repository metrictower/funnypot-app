<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\NonsenseFallback;
use PHPUnit\Framework\TestCase;

final class NonsenseFallbackTest extends TestCase
{
    /** Markers unique to the CODE set — kept in sync with NonsenseFallback's own list, one per entry. */
    private const CODE_MARKERS = ['MOV', '+++', 'GOTO 10', 'PROCEDURE DIVISION', '01001000', 'RESULT :='];

    private NonsenseFallback $fallback;

    protected function setUp(): void
    {
        $this->fallback = new NonsenseFallback();
    }

    private function req(string $userText): ChatRequest
    {
        return new ChatRequest('ollama-chat', 'llama3', $userText, false, true, false);
    }

    public function test_never_empty(): void
    {
        self::assertNotSame('', $this->fallback->text($this->req('')));
        self::assertNotSame('', $this->fallback->text($this->req('hello there')));
    }

    public function test_code_request_returns_a_code_set_snippet(): void
    {
        $result = $this->fallback->text($this->req('write me a python script that sorts a list'));

        $found = false;
        foreach (self::CODE_MARKERS as $marker) {
            if (str_contains($result, $marker)) {
                $found = true;
                break;
            }
        }
        self::assertTrue($found, 'expected a code-set marker in: ' . $result);
    }

    public function test_deterministic_for_the_same_input(): void
    {
        $first = $this->fallback->text($this->req('what is the capital of France?'));
        $second = $this->fallback->text($this->req('what is the capital of France?'));
        self::assertSame($first, $second);
    }

    public function test_plain_question_returns_a_generic_set_answer(): void
    {
        $result = $this->fallback->text($this->req('what is the capital of France?'));

        foreach (self::CODE_MARKERS as $marker) {
            self::assertStringNotContainsString($marker, $result);
        }
    }
}
