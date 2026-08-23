<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi\Dialect;

use Funnypot\App\AiApi\ChatRequest;
use Funnypot\App\AiApi\StreamEmitter;
use Funnypot\RequestContext;

/**
 * Ollama's native API — both /api/chat (message array) and /api/generate (single prompt), told apart
 * by the request path. Streaming is newline-delimited JSON (one object per line, no framing prefix,
 * no terminator) and defaults ON; the done object carries the timing/eval counters.
 */
final class OllamaDialect extends AbstractDialect
{
    private const CT_JSON = 'application/json; charset=utf-8';
    private const CT_STREAM = 'application/x-ndjson';

    public function parse(RequestContext $ctx): ChatRequest
    {
        $data = $this->decodeBody($ctx->rawBody);
        $isGenerate = strpos($ctx->path, '/api/generate') !== false;

        $userText = $isGenerate
            ? (string) ($data['prompt'] ?? '')
            : $this->lastUserText(is_array($data['messages'] ?? null) ? $data['messages'] : []);

        return new ChatRequest(
            $isGenerate ? 'ollama-generate' : 'ollama-chat',
            (string) ($data['model'] ?? ''),
            $userText,
            array_key_exists('stream', $data) ? (bool) $data['stream'] : true,
            false,
            false
        );
    }

    public function needsAuth(): bool
    {
        return false;
    }

    public function contentTypeStream(): string
    {
        return self::CT_STREAM;
    }

    public function streamOk(string $text, ChatRequest $req, StreamEmitter $out): void
    {
        $out->begin(200, ['Content-Type' => self::CT_STREAM]);

        $isGenerate = $req->dialect === 'ollama-generate';
        $pieces = $this->chunks($text);

        foreach ($pieces as $piece) {
            $out->chunk($this->json($this->progress($req->model, $piece, $isGenerate)) . "\n");
        }

        $out->chunk($this->json($this->done($req->model, '', count($pieces), $isGenerate)) . "\n");
    }

    public function bufferedOk(string $text, ChatRequest $req): array
    {
        $isGenerate = $req->dialect === 'ollama-generate';
        $body = $this->done($req->model, $text, count($this->chunks($text)), $isGenerate);

        return [200, ['Content-Type' => self::CT_JSON], $this->json($body)];
    }

    public function error(string $kind, ChatRequest $req): array
    {
        if ($kind === 'model') {
            return [404, ['Content-Type' => self::CT_JSON], $this->json([
                'error' => "model '{$req->model}' not found",
            ])];
        }

        return [400, ['Content-Type' => self::CT_JSON], $this->json(['error' => 'invalid request'])];
    }

    /** @return array<string,mixed> */
    private function progress(string $model, string $piece, bool $isGenerate): array
    {
        $obj = ['model' => $model, 'created_at' => $this->stats->ollamaCreatedAt()];
        if ($isGenerate) {
            $obj['response'] = $piece;
        } else {
            $obj['message'] = ['role' => 'assistant', 'content' => $piece];
        }
        $obj['done'] = false;

        return $obj;
    }

    /**
     * The done object — full text for the buffered case, empty for the final streamed line. Field order
     * matches real ollama exactly (prompt_eval_count sits between load_duration and prompt_eval_duration;
     * /api/generate carries a context array right after done_reason).
     *
     * @return array<string,mixed>
     */
    private function done(string $model, string $text, int $pieces, bool $isGenerate): array
    {
        $d = $this->stats->durationsNs($pieces);

        $obj = ['model' => $model, 'created_at' => $this->stats->ollamaCreatedAt()];
        if ($isGenerate) {
            $obj['response'] = $text;
        } else {
            $obj['message'] = ['role' => 'assistant', 'content' => $text];
        }
        $obj['done'] = true;
        $obj['done_reason'] = 'stop';
        if ($isGenerate) {
            $obj['context'] = $this->stats->contextInts();
        }
        $obj['total_duration'] = $d['total_duration'];
        $obj['load_duration'] = $d['load_duration'];
        $obj['prompt_eval_count'] = 26;
        $obj['prompt_eval_duration'] = $d['prompt_eval_duration'];
        $obj['eval_count'] = $this->stats->evalCount($pieces);
        $obj['eval_duration'] = $d['eval_duration'];

        return $obj;
    }
}
