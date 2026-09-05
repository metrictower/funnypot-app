<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\App\AiApi\Value\ToolCall;
use Funnypot\Core\RequestContext;

/**
 * One provider's on-the-wire chat protocol. A dialect parses that provider's request shape into the
 * normalised ChatRequest, and turns a resolved answer (text, an inert tool call, or a length stop) back
 * into the provider's byte-exact response framing — Ollama NDJSON, OpenAI SSE with a [DONE] sentinel,
 * Anthropic named-event SSE.
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

    /** A provider-shaped id for a fabricated tool call ('' for Ollama, whose shape has none). */
    public function toolCallId(): string;

    /** Emit the full streaming response for $text as this provider's chunk framing. */
    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void;

    /**
     * Build the non-streaming response for $text.
     *
     * @return array{0:int,1:array<string,string>,2:string} [status, headers, body]
     */
    public function bufferedOk(string $text, ChatRequest $req): array;

    /**
     * Build the non-streaming response carrying one inert tool call, with the provider's tool-call stop
     * reason.
     *
     * @return array{0:int,1:array<string,string>,2:string} [status, headers, body]
     */
    public function bufferedTool(ToolCall $call, ChatRequest $req): array;

    /** Emit the streaming response carrying one inert tool call, argument fragments reassembling to the
     *  call's single canonical JSON, with the provider's tool-call stop reason. */
    public function streamTool(ToolCall $call, ChatRequest $req, StreamEmitter $out): void;

    /**
     * Build the non-streaming response for a length stop (output budget could not fit the reply): no
     * content, the provider's length stop reason, no partial tool block.
     *
     * @return array{0:int,1:array<string,string>,2:string} [status, headers, body]
     */
    public function bufferedLength(ChatRequest $req): array;

    /** Emit the streaming response for a length stop, with structurally valid terminal markers only. */
    public function streamLength(ChatRequest $req, StreamEmitter $out): void;

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
