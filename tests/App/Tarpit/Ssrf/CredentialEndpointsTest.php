<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\CredentialEndpoints;
use PHPUnit\Framework\TestCase;

final class CredentialEndpointsTest extends TestCase
{
    private static function ref(string $kind, ?string $fam, string $h = 'aaaaaaaaaaaaaaaaaaaaaaaa', int $d = 0, int $x = 0, string $st = 'none', string $w = 'query'): array
    {
        return ['k' => $kind, 'h' => $h, 'f' => $fam, 'd' => $d, 'x' => $x, 'st' => $st, 'w' => $w];
    }

    public function test_sts_verdict_table(): void
    {
        $idx = new MemoryKeyIndex(true);
        $idx->hashes['bbbbbbbbbbbbbbbbbbbbbbbb'] = true;
        self::assertSame('missing', CredentialEndpoints::stsVerdict(null, $idx, 100));
        self::assertSame('missing', CredentialEndpoints::stsVerdict(self::ref('aws', 'persona', w: 'userinfo'), $idx, 100), 'a key in userinfo is no query auth');
        self::assertSame('unknown', CredentialEndpoints::stsVerdict(self::ref('aws', null), $idx, 100));
        self::assertSame('known', CredentialEndpoints::stsVerdict(self::ref('aws', null, 'bbbbbbbbbbbbbbbbbbbbbbbb'), $idx, 100), 'recognised through the index');
        self::assertSame('known', CredentialEndpoints::stsVerdict(self::ref('aws', 'persona'), $idx, 100), 'recognised directly');
        self::assertSame('expired', CredentialEndpoints::stsVerdict(self::ref('aws', 'persona', d: 1000, x: 60), $idx, 1061));
        self::assertSame('known', CredentialEndpoints::stsVerdict(self::ref('aws', 'persona', d: 1000, x: 60), $idx, 1060));
        self::assertSame('expired', CredentialEndpoints::stsVerdict(self::ref('aws', 'persona', d: 1000), $idx, 1901), 'the default window is 900 s');
        self::assertSame('unknown', CredentialEndpoints::stsVerdict(self::ref('stripe', 'persona'), $idx, 100), 'a card key is no AWS key');
        $codes = [];
        foreach (CredentialEndpoints::VERDICTS as $v) {
            $reply = CredentialEndpoints::stsReply($v, 'rid');
            self::assertGreaterThanOrEqual(400, $reply->status);
            preg_match('~<Code>([A-Za-z]+)</Code>~', $reply->body, $m);
            $codes[$v] = $m[1];
        }
        self::assertSame(['missing' => 'MissingAuthenticationToken', 'unknown' => 'InvalidClientTokenId', 'throttled' => 'Throttling', 'expired' => 'RequestExpired', 'known' => 'SignatureDoesNotMatch', 'token' => 'InvalidClientTokenId'], $codes);
    }

    public function test_asia_needs_its_own_token(): void
    {
        $idx = new MemoryKeyIndex(true);
        self::assertSame('known', CredentialEndpoints::stsVerdict(self::ref('asia', 'core_render', st: 'match'), $idx, 100));
        self::assertSame('token', CredentialEndpoints::stsVerdict(self::ref('asia', 'core_render', st: 'mismatch'), $idx, 100));
        self::assertSame('token', CredentialEndpoints::stsVerdict(self::ref('asia', 'core_render', st: 'none'), $idx, 100));
    }

    public function test_expiry_uses_the_attempt_time(): void
    {
        $idx = new MemoryKeyIndex(true);
        $ref = self::ref('aws', 'persona', d: 5000, x: 900);
        $attemptAt = 5100;
        $first = CredentialEndpoints::stsVerdict($ref, $idx, $attemptAt);
        self::assertSame('known', $first);
        self::assertSame($first, CredentialEndpoints::stsVerdict($ref, $idx, $attemptAt), 'a re-view 16 minutes later reads the same attempt time');
    }

    public function test_unknown_while_incomplete_is_transient_then_definitive(): void
    {
        $idx = new MemoryKeyIndex(false);
        $ref = self::ref('aws', null, 'cccccccccccccccccccccccc');
        self::assertSame('throttled', CredentialEndpoints::stsVerdict($ref, $idx, 1));
        self::assertSame('throttled', CredentialEndpoints::paymentsVerdict(self::ref('stripe', null, w: 'userinfo'), $idx));
        $idx->hashes['cccccccccccccccccccccccc'] = true;
        self::assertSame('known', CredentialEndpoints::stsVerdict($ref, $idx, 2), 'indexed later: known, never contradicting an earlier unknown');
        $idx->complete = true;
        self::assertSame('unknown', CredentialEndpoints::stsVerdict(self::ref('aws', null, 'dddddddddddddddddddddddd'), $idx, 3));
    }

    public function test_payments_gateway_never_returns_an_object(): void
    {
        $idx = new MemoryKeyIndex(true);
        self::assertSame('missing', CredentialEndpoints::paymentsVerdict(null, $idx));
        self::assertSame('missing', CredentialEndpoints::paymentsVerdict(self::ref('stripe', 'persona'), $idx), 'a key in the query is not basic auth');
        self::assertSame('known', CredentialEndpoints::paymentsVerdict(self::ref('stripe', 'log', w: 'userinfo'), $idx));
        self::assertSame('unknown', CredentialEndpoints::paymentsVerdict(self::ref('aws', 'persona', w: 'userinfo'), $idx));
        foreach (CredentialEndpoints::VERDICTS as $v) {
            $r = CredentialEndpoints::paymentsReply($v);
            $data = json_decode($r->body, true);
            self::assertSame(['error'], array_keys($data));
            self::assertGreaterThanOrEqual(400, $r->status);
        }
        self::assertSame(403, CredentialEndpoints::paymentsReply('known')->status);
        self::assertStringContainsString('key_restricted', CredentialEndpoints::paymentsReply('known')->body);
    }

    public function test_no_2xx_over_1000_variants(): void
    {
        mt_srand(816);
        foreach ([true, false] as $complete) {
            $idx = new MemoryKeyIndex($complete);
            for ($i = 0; $i < 500; $i++) {
                $ref = mt_rand(0, 9) === 0 ? null : self::ref(['aws', 'asia', 'stripe'][mt_rand(0, 2)], mt_rand(0, 1) ? 'persona' : null, str_pad(dechex($i), 24, '0'), mt_rand(0, 1) * mt_rand(1, 9000), mt_rand(0, 3600), ['none', 'match', 'mismatch'][mt_rand(0, 2)], mt_rand(0, 1) ? 'query' : 'userinfo');
                if ($ref !== null && mt_rand(0, 1)) {
                    $idx->hashes[$ref['h']] = true;
                }
                $sts = CredentialEndpoints::stsReply(CredentialEndpoints::stsVerdict($ref, $idx, mt_rand(0, 10000)), 'r');
                $pay = CredentialEndpoints::paymentsReply(CredentialEndpoints::paymentsVerdict($ref, $idx));
                self::assertGreaterThanOrEqual(400, $sts->status);
                self::assertGreaterThanOrEqual(400, $pay->status);
                self::assertDoesNotMatchRegularExpression('/arn:|Account|AssumedRole|GetCallerIdentityResult|"object"/', $sts->body . $pay->body);
            }
        }
    }

    public function test_credential_bytes_never_appear_in_an_answer(): void
    {
        foreach (CredentialEndpoints::VERDICTS as $v) {
            $body = CredentialEndpoints::stsReply($v, 'rid')->body . CredentialEndpoints::paymentsReply($v)->body;
            self::assertDoesNotMatchRegularExpression('/AKIA|ASIA|sk_live|sk_test/', $body);
        }
    }
}
