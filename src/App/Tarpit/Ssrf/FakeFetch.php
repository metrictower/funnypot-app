<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The state of a fake delivery, import or verification at a given moment, from the facts stored when
 * it was sent and the injected clock. Nothing is fetched: the facts say where the request would have
 * gone, and the state machine says how far it has got.
 *
 * A refused or unreachable target is done within a second, an open one in one to three seconds, and a
 * proxy denial or resolver failure at once. A timeout is done at ten seconds, then retried at +30 s,
 * +2 min, +10 min and +1 h, each timing out, then fails for good; those retries are attempts inside the
 * one delivery, derived at view time, so a view issues nothing and stores nothing.
 */
final class FakeFetch
{
    public const RETRY_OFFSETS = [0, 30, 120, 600, 3600];
    public const TIMEOUT_S = 10;
    public const CLONE_S = 600;

    private const IMMEDIATE = ['proxy_denied', 'nxdomain', 'dns_transient', 'unroutable', 'no_route', 'validation', 'code_host'];

    public function __construct(private NodeAnswers $answers)
    {
    }

    /**
     * The compact facts a fetch stores: outcome, egress class, the node reached (kind and key; the key
     * names the host), port, path class, method and the credential verdict.
     *
     * @return array<string,mixed>
     */
    public static function facts(Resolution $r, string $method, PathClass $pc, ?string $verdict = null): array
    {
        return [
            'o' => $r->outcome, 'e' => $r->egress, 'k' => $r->node?->kind ?? '', 'n' => substr($r->node?->key ?? '', 0, 3 + SsrfState::MAX_HOST),
            'p' => $r->port, 'pc' => $pc->value, 'm' => $method, 'vd' => $verdict,
        ];
    }

    /** @param array<string,mixed> $f */
    public function reply(array $f, string $requestId): ?Reply
    {
        $key = (string) ($f['n'] ?? '');
        $node = $key !== '' ? new NetNode($key, (string) $f['k'], $this->answers->hostOf($key), [(int) $f['p']]) : null;
        $r = new Resolution((string) $f['e'], (string) $f['o'], $node, (int) $f['p']);

        return $this->answers->reply($r, (string) $f['m'], PathClass::tryFrom((string) $f['pc']) ?? PathClass::Other, is_string($f['vd'] ?? null) ? $f['vd'] : null, $requestId);
    }

    /** A request id in the gateways' style, derived from the fetch's own id. */
    public static function requestId(string $id): string
    {
        $h = hash('sha256', 'rid|' . $id);

        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20, 12);
    }

    /** How long a fetch with this outcome took, in milliseconds, seeded by its id. */
    public static function durationMs(string $outcome, string $id): int
    {
        $u = (int) hexdec(substr(hash('sha256', 'ms|' . $id), 0, 6));

        return match (true) {
            in_array($outcome, self::IMMEDIATE, true) => 2 + $u % 39,
            $outcome === 'refused' => 5 + $u % 896,
            $outcome === 'timeout' => self::TIMEOUT_S * 1000,
            default => 1000 + $u % 2001,
        };
    }

    /** @param array<string,mixed> $f */
    public function delivery(array $f, int $t0, int $now, string $id): FetchResult
    {
        $o = (string) $f['o'];
        if ($o === 'timeout') {
            return $this->retries($t0, $now, (string) NodeAnswers::error('timeout'));
        }
        $ms = self::durationMs($o, $id);
        if (!in_array($o, self::IMMEDIATE, true) && ($now - $t0) * 1000 < $ms) {
            return new FetchResult('pending', null, null, 0, [['at' => $t0, 'state' => 'pending', 'error' => null, 'ms' => 0]]);
        }
        $reply = $this->reply($f, $id);
        $error = NodeAnswers::error($o) ?? $reply?->error;
        $ok = $reply !== null && $reply->ok() && $reply->status !== null && $reply->status < 300;
        if ($reply !== null && $reply->ok() && !$ok) {
            $error = 'HTTP ' . $reply->status;
        }

        return new FetchResult($ok ? 'delivered' : 'failed', $reply, $ok ? null : ($error ?? 'Delivery failed'), $ms, [['at' => $t0, 'state' => $ok ? 'delivered' : 'failed', 'error' => $ok ? null : $error, 'ms' => $ms]]);
    }

    private function retries(int $t0, int $now, string $error): FetchResult
    {
        $attempts = [];
        foreach (self::RETRY_OFFSETS as $off) {
            $at = $t0 + $off;
            if ($now < $at) {
                break;
            }
            $done = $now >= $at + self::TIMEOUT_S;
            $attempts[] = ['at' => $at, 'state' => $done ? 'timed_out' : 'pending', 'error' => $done ? $error : null, 'ms' => $done ? self::TIMEOUT_S * 1000 : 0];
        }
        $last = $attempts[count($attempts) - 1] ?? ['state' => 'pending'];
        $state = $last['state'] === 'pending' ? (count($attempts) <= 1 ? 'pending' : 'retrying')
            : (count($attempts) === count(self::RETRY_OFFSETS) ? 'failed' : 'retrying');

        return new FetchResult($state, null, $state === 'pending' ? null : $error, $last['state'] === 'pending' ? 0 : self::TIMEOUT_S * 1000, $attempts);
    }

    /**
     * An import at a moment. An orders import that reaches an HTTP answer fails validation at +5 s with
     * an excerpt; a mirror of an internal host fails as "not a Git repository"; a mirror of the code host
     * waits for a worker, clones for ten minutes and times out with no data, never claiming progress.
     *
     * @param array<string,mixed> $f
     */
    public function import(string $kind, array $f, int $t0, int $now, string $id): FetchResult
    {
        $o = (string) $f['o'];
        if ($o === 'code_host') {
            $wait = 60 * (2 + (int) (hexdec(substr(hash('sha256', 'q|' . $id), 0, 6)) % 14));
            if ($now < $t0 + $wait) {
                return new FetchResult('waiting', null, null, 0, []);
            }
            if ($now < $t0 + $wait + self::CLONE_S) {
                return new FetchResult('cloning', null, null, 0, []);
            }

            return new FetchResult('failed', null, 'timed out after ' . self::CLONE_S . ' s with no data received from github.com', 0, []);
        }
        if ($o === 'timeout') {
            return $now < $t0 + self::TIMEOUT_S
                ? new FetchResult('fetching', null, null, 0, [])
                : new FetchResult('failed', null, (string) NodeAnswers::error('timeout'), self::TIMEOUT_S * 1000, []);
        }
        if (in_array($o, self::IMMEDIATE, true) || $o === 'refused') {
            $ms = self::durationMs($o, $id);
            if ($o === 'refused' && ($now - $t0) * 1000 < $ms) {
                return new FetchResult('fetching', null, null, 0, []);
            }
            $reply = $o === 'proxy_denied' ? $this->reply($f, $id) : null;

            return new FetchResult('failed', $reply, $o === 'proxy_denied' ? 'HTTP 403: ' . NodeAnswers::PROXY_DENIED : (string) NodeAnswers::error($o), $ms, []);
        }
        if ($now < $t0 + 1) {
            return new FetchResult('queued', null, null, 0, []);
        }
        $reply = $this->reply($f, $id);
        if ($reply === null || !$reply->ok()) {
            return $now < $t0 + 2
                ? new FetchResult('fetching', null, null, 0, [])
                : new FetchResult('failed', $reply, $reply?->error ?? 'Delivery failed', 2000, []);
        }
        if ($kind === 'mirror') {
            return $now < $t0 + 3
                ? new FetchResult('fetching', null, null, 0, [])
                : new FetchResult('failed', $reply, 'the remote did not answer as a Git repository (HTTP ' . $reply->status . ')', 3000, []);
        }
        if ($now < $t0 + 5) {
            return new FetchResult('fetching', null, null, 0, []);
        }

        return new FetchResult('failed', $reply, 'validation: Row 1: expected header `order_id`', 5000, []);
    }
}
