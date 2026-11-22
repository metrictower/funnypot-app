<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

/**
 * The two internal credential gateways settings.py points at: an STS-compatible gateway at
 * sts.<region>.internal and a card-processor gateway at payments-gw.<region>.internal:8443.
 *
 * They decide, for a presented key, a verdict that never authenticates. A key this honeypot served is
 * known but never signs (SignatureDoesNotMatch) or is restricted (key_restricted); a key it never served
 * is invalid once the key index is complete, and rate limited while it is not, so an early "unknown"
 * is never contradicted. No answer is a 2xx, an ARN, an account id or an object.
 *
 * A credential reference is computed when a URL is saved and stored with it: the key kind, its keyed
 * hash, the family that recognised it directly (persona or per-source core keys), the presign date
 * and expiry, and whether a session token matched. No credential byte is stored.
 */
final class CredentialEndpoints implements HostDirectory
{
    public const VERDICTS = ['missing', 'unknown', 'throttled', 'expired', 'known', 'token'];

    public function __construct(private string $region)
    {
    }

    public function stsHost(): string
    {
        return 'sts.' . $this->region . '.internal';
    }

    public function paymentsHost(): string
    {
        return 'payments-gw.' . $this->region . '.internal';
    }

    public function lookup(string $host): ?NetNode
    {
        if ($host === $this->stsHost()) {
            return new NetNode('sts', 'sts', $host, [80, 443]);
        }
        if ($host === $this->paymentsHost()) {
            return new NetNode('pay', 'payments', $host, [8443]);
        }

        return null;
    }

    public function sample(string $label, int $n): array
    {
        return [];
    }

    /** @return list<string> the gateways, as the dependency listings name them */
    public function pointers(): array
    {
        return [$this->stsHost() . ':80', $this->paymentsHost() . ':8443'];
    }

    /**
     * @param array<string,mixed>|null $ref the stored credential reference
     */
    public static function stsVerdict(?array $ref, KeyIndexView $index, int $attemptAt): string
    {
        if ($ref === null || ($ref['w'] ?? '') !== 'query') {
            return 'missing';
        }
        $kind = (string) ($ref['k'] ?? '');
        if ($kind === 'stripe' || !self::recognised($ref, $index)) {
            return $index->complete() ? 'unknown' : 'throttled';
        }
        $d = (int) ($ref['d'] ?? 0);
        $x = (int) ($ref['x'] ?? 0);
        if ($d > 0 && $attemptAt > $d + ($x > 0 ? $x : 900)) {
            return 'expired';
        }
        if ($kind === 'asia') {
            return ($ref['st'] ?? 'none') === 'match' ? 'known' : 'token';
        }

        return 'known';
    }

    /** @param array<string,mixed>|null $ref */
    public static function paymentsVerdict(?array $ref, KeyIndexView $index): string
    {
        if ($ref === null || ($ref['w'] ?? '') !== 'userinfo') {
            return 'missing';
        }
        if (($ref['k'] ?? '') !== 'stripe' || !self::recognised($ref, $index)) {
            return $index->complete() ? 'unknown' : 'throttled';
        }

        return 'known';
    }

    /** @param array<string,mixed> $ref */
    private static function recognised(array $ref, KeyIndexView $index): bool
    {
        return ($ref['f'] ?? null) !== null || (is_string($ref['h'] ?? null) && $index->containsHash($ref['h']));
    }

    /** The STS gateway's answer: an XML error document, our own wording. */
    public static function stsReply(string $verdict, string $requestId): Reply
    {
        [$status, $code, $msg] = match ($verdict) {
            'missing' => [403, 'MissingAuthenticationToken', 'The request carries no access key or signature.'],
            'throttled' => [400, 'Throttling', 'Too many requests from this gateway client; retry later.'],
            'expired' => [403, 'RequestExpired', 'The request timestamp is outside the accepted window.'],
            'known' => [403, 'SignatureDoesNotMatch', 'The signature in this request was not made with the current secret for this access key.'],
            'token' => [403, 'InvalidClientTokenId', 'The session token in this request does not belong to this access key.'],
            default => [403, 'InvalidClientTokenId', 'No access key matches the one in this request.'],
        };
        $body = "<ErrorResponse>\n  <Error>\n    <Type>Sender</Type>\n    <Code>{$code}</Code>\n    <Message>{$msg}</Message>\n  </Error>\n"
            . "  <RequestId>{$requestId}</RequestId>\n</ErrorResponse>\n";

        return Reply::http($status, 'text/xml', $body);
    }

    /** The payments gateway's answer: a JSON error, our own wording and shape. */
    public static function paymentsReply(string $verdict): Reply
    {
        [$status, $code, $msg] = match ($verdict) {
            'missing' => [401, 'missing_api_key', 'Send the API key as the username of HTTP basic auth.'],
            'throttled' => [429, 'rate_limit', 'Too many requests; retry shortly.'],
            'known' => [403, 'key_restricted', 'This key is restricted to the billing-worker egress range.'],
            default => [401, 'invalid_api_key', 'This API key is not recognised.'],
        };

        return Reply::http($status, 'application/json', (string) json_encode(['error' => ['code' => $code, 'message' => $msg]]) . "\n");
    }

    /** The turn outcome a verdict records. */
    public static function outcome(string $verdict, bool $payments): string
    {
        return match ($verdict) {
            'known' => $payments ? 'cred_restricted' : 'cred_known',
            'expired' => 'cred_expired',
            'throttled' => 'cred_throttled',
            'missing' => 'cred_missing',
            default => 'cred_unknown',
        };
    }
}
