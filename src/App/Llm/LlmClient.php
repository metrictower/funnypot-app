<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use Throwable;

/**
 * HTTP client for the funnypot-llm sidecar (llama-server native /completion). Mirrors
 * AbuseIpdb::httpPost (stream_context, ignore_errors, hard timeout) with an injectable transport so
 * tests never touch the network. Every failure — open breaker, connection refused, non-2xx, bad
 * JSON, missing/empty content — returns null so the caller falls through to the plain 404. The
 * timeout plus the n_predict cap keep a slow model from holding a php-fpm worker.
 */
final class LlmClient
{
    /** @param callable(string,string):array{status:int,body:string}|null $transport */
    public function __construct(
        private string $url,
        private int $timeoutMs = 1500,
        private int $nPredict = 320,
        private ?CircuitBreaker $breaker = null,
        private $transport = null,
    ) {
    }

    /**
     * Raw generation. Returns the model body, or null on any failure / open breaker.
     *
     * $sampling is null for the bare default: low-temp sampling with an inert fixed seed. The page
     * responder always overrides the seed with one derived from the install persona + path (a fixed
     * fleet-wide seed made persona-less kinds byte-identical on every install); the chat path cranks
     * temperature / min_p and randomises the seed for real nonsense. Only these keys are honoured:
     * temperature, min_p, top_p, top_k, repeat_penalty, seed. n_predict stays as configured.
     *
     * @param array<string,mixed>|null $sampling
     */
    public function generate(string $prompt, string $grammar, ?array $sampling = null): ?string
    {
        if ($this->breaker !== null && !$this->breaker->allow()) {
            return null;
        }
        $params = [
            'prompt' => $prompt,
            'grammar' => $grammar,
            'n_predict' => $this->nPredict,
            'temperature' => 0.4,
            'top_p' => 0.9,
            'repeat_penalty' => 1.1,
            'cache_prompt' => true,
            'stop' => ['<|im_end|>', '</html>'],
            'seed' => 42,
        ];
        if ($sampling !== null) {
            foreach (['temperature', 'min_p', 'top_p', 'top_k', 'repeat_penalty', 'seed'] as $key) {
                if (array_key_exists($key, $sampling)) {
                    $params[$key] = $sampling[$key];
                }
            }
        }
        $payload = json_encode($params, JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            return null;
        }

        $send = $this->transport ?? [$this, 'httpPost'];
        try {
            $res = $send($this->url, $payload);
            $status = (int) ($res['status'] ?? 0);
            if ($status < 200 || $status >= 300) {
                $this->breaker?->recordFailure();

                return null;
            }
            $json = json_decode((string) ($res['body'] ?? ''), true);
            $content = is_array($json) ? ($json['content'] ?? null) : null;
            if (!is_string($content) || trim($content) === '') {
                $this->breaker?->recordFailure();

                return null;
            }
            $this->breaker?->recordSuccess();

            // llama-server returns only the continuation; the grammar makes it a full document.
            return $content;
        } catch (Throwable $e) {
            $this->breaker?->recordFailure();

            return null;
        }
    }

    /** Cheap liveness probe (GET /health next to the completion endpoint). */
    public function healthy(): bool
    {
        try {
            $health = preg_replace('#/completion/?$#', '/health', $this->url) ?? $this->url;
            $ctx = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 2, 'ignore_errors' => true]]);
            $body = @file_get_contents($health, false, $ctx);

            return is_string($body) && strpos($body, '"ok"') !== false;
        } catch (Throwable $e) {
            return false;
        }
    }

    /**
     * @return array{status:int,body:string}
     */
    private function httpPost(string $url, string $body): array
    {
        $ctx = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => $body,
            'timeout' => max(1, $this->timeoutMs / 1000),
            'ignore_errors' => true,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        return ['status' => $status, 'body' => $resp === false ? '' : $resp];
    }
}
