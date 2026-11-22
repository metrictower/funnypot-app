<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The member API's JSON shapes for webhooks, imports and the export destination: our own field names,
 * byte-identical under /api/v2/ and /v2/. URLs are the stored, masked strings.
 */
final class SsrfApi
{
    public static function iso(int $ts): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $ts);
    }

    /** @param array<string,mixed> $h a stored hook @return array<string,mixed> */
    public static function hook(array $h, string $prefix, ?array $last): array
    {
        $v = $h['u'][count($h['u']) - 1];

        return [
            'id' => (string) $h['id'],
            'url' => (string) $v['url'],
            'content_type' => (string) $h['ct'],
            'events' => (array) $h['ev'],
            'active' => (int) $h['a'] === 1,
            'created_at' => self::iso((int) $h['c']),
            'updated_at' => self::iso((int) $h['t']),
            'last_delivery' => $last,
            'links' => [
                'pings' => $prefix . 'user/hooks/' . $h['id'] . '/pings',
                'deliveries' => $prefix . 'user/hooks/' . $h['id'] . '/deliveries',
            ],
        ];
    }

    /** @param array<string,mixed> $d a stored delivery @return array<string,mixed> */
    public static function deliverySummary(array $d, FetchResult $r, string $url): array
    {
        return [
            'id' => (string) $d['id'],
            'event' => (string) $d['ev'],
            'redelivery' => (int) ($d['rd'] ?? 0) === 1,
            'status' => $r->state,
            'status_code' => $r->reply?->ok() ? $r->reply->status : null,
            'duration_ms' => $r->durationMs,
            'error' => $r->error,
            'url' => $url,
            'sent_at' => self::iso((int) $d['c']),
        ];
    }

    /**
     * @param array<string,mixed> $d
     * @param list<array{0:string,1:string}> $headers
     * @return array<string,mixed>
     */
    public static function delivery(array $d, FetchResult $r, string $url, array $headers, string $body): array
    {
        $req = [];
        foreach ($headers as [$n, $v]) {
            $req[$n] = $v;
        }

        return self::deliverySummary($d, $r, $url) + [
            'request' => ['headers' => $req, 'body' => $body],
            'response' => $r->reply === null ? null : [
                'status' => $r->reply->status,
                'content_type' => $r->reply->contentType,
                'body' => $r->reply->body,
                'error' => $r->reply->error,
            ],
            'attempts' => array_map(static fn (array $a): array => ['at' => self::iso($a['at']), 'state' => $a['state'], 'duration_ms' => $a['ms'], 'error' => $a['error']], $r->attempts),
        ];
    }

    /** @param array<string,mixed> $im @return array<string,mixed> */
    public static function import(array $im, FetchResult $r): array
    {
        return [
            'id' => (string) $im['id'],
            'kind' => (string) $im['k'],
            'source_url' => (string) $im['url'],
            'status' => $r->state,
            'error' => $r->error,
            'excerpt' => $r->reply !== null && $r->state === 'failed' ? substr($r->reply->body, 0, 512) : null,
            'retries' => (int) $im['r'],
            'created_at' => self::iso((int) $im['c']),
            'started_at' => self::iso((int) $im['rs']),
        ];
    }

    /**
     * @param array<string,mixed>|null $st
     * @param list<array<string,mixed>> $verifications
     * @return array<string,mixed>
     */
    public static function storage(?array $st, array $verifications): array
    {
        if ($st === null) {
            return ['configured' => false];
        }

        return ['configured' => true, 'bucket' => (string) $st['b'], 'endpoint_url' => (string) $st['url'], 'updated_at' => self::iso((int) $st['t']), 'verifications' => $verifications];
    }
}
