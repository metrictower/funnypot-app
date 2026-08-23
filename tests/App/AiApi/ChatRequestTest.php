<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ChatRequest;
use PHPUnit\Framework\TestCase;

final class ChatRequestTest extends TestCase
{
    public function test_holds_the_fields_it_was_constructed_with(): void
    {
        $req = new ChatRequest('openai', 'gpt-4o', 'hello', true, false, true);

        self::assertSame('openai', $req->dialect);
        self::assertSame('gpt-4o', $req->model);
        self::assertSame('hello', $req->userText);
        self::assertTrue($req->stream);
        self::assertFalse($req->hasAuth);
        self::assertTrue($req->includeUsage);
    }
}
