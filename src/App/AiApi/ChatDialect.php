<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\Core\RequestContext;

/**
 * One provider's on-the-wire chat protocol. A dialect parses that provider's request shape into the
 * normalised ChatRequest, and turns a resolved answer string back into the provider's byte-exact
 * response framing — Ollama NDJSON, OpenAI SSE with a [DONE] sentinel, Anthropic named-event SSE.
 *
 * Fidelity is the whole point: a scanner diffs these bytes against a real server, so the framing,
 * field order, terminators and Content-Types must match the real thing exactly. The concrete dialects
 * live under Dialect/.
 */
interface ChatDialect
{
    /** Parse this provider's request body/headers into the normalised request DTO. */
    public function parse(RequestContext $ctx): ChatRequest;

    /** Whether a missing/empty auth credential should be answered with the auth error (ollama=false). */
    public function needsAuth(): bool;

    /** Emit the full streaming response for $text as this provider's chunk framing. */
    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void;

    /**
     * Build the non-streaming response for $text.
     *
     * @return array{0:int,1:array<string,string>,2:string} [status, headers, body]
     */
    public function bufferedOk(string $text, ChatRequest $req): array;

    /**
     * Build a provider-shaped error response.
     *
     * @param string $kind 'auth'|'model'|'bad'
     * @return array{0:int,1:array<string,string>,2:string} [status, headers, body]
     */
    public function error(string $kind, ChatRequest $req): array;

    /** Content-Type sent for the streaming response (NDJSON vs SSE). */
    public function contentTypeStream(): string;
}
