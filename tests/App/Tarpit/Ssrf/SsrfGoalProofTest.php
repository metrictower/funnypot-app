<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\CredentialEndpoints;
use PHPUnit\Framework\TestCase;

/**
 * No answer the SSRF surface renders, for eight personas, closes a goal: no working credentials, no STS
 * success, no payment object, no order records, no clone, and no 2xx from either credential gateway.
 * Each shape the scanner looks for has a planted positive control.
 */
final class SsrfGoalProofTest extends TestCase
{
    public function test_no_answer_is_goal_proof(): void
    {
        $bodies = 0;
        $gateway = 0;
        foreach (range(1, 8) as $seed) {
            $kinds = [];
            foreach (SsrfTour::networkCorpus($seed) as [$kind, $label, $body]) {
                self::assertTrue(SsrfGoalProof::clean($body), "seed {$seed} network answer {$label}: " . substr($body, 0, 200));
                $kinds[$kind] = ($kinds[$kind] ?? 0) + 1;
                $bodies++;
            }
            SsrfTour::assertEveryKind($kinds, "seed {$seed} network corpus");
            $tour = (new SsrfTour($seed))->run();
            try {
                SsrfTour::assertEveryKind($tour->kinds, "seed {$seed} tour");
                foreach ($tour->plans as [$label, $plan]) {
                    self::assertTrue(SsrfGoalProof::clean($plan->body), "seed {$seed} {$label}: " . substr($plan->body, 0, 200));
                    $bodies++;
                    $j = json_decode($plan->body, true);
                    $resp = is_array($j) ? ($j['response'] ?? null) : null;
                    if (is_array($resp) && preg_match('/<ErrorResponse>|"error":\{"code"/', (string) ($resp['body'] ?? '')) === 1) {
                        self::assertGreaterThanOrEqual(400, (int) $resp['status'], "seed {$seed}: a gateway answered 2xx");
                        $gateway++;
                    }
                    if (preg_match('~SignatureDoesNotMatch|key_restricted|InvalidClientTokenId~', html_entity_decode($plan->body)) === 1) {
                        $gateway++;
                    }
                }
            } finally {
                $tour->cleanup();
            }
        }
        self::assertGreaterThan(900, $bodies);
        foreach (SsrfTour::networkCorpus(1) as [$kind, , $body]) {
            if ($kind === 'metadata') {
                self::assertFalse(SsrfGoalProof::clean($body . '{"Code":"Success","AccessKeyId":"x","SecretAccessKey":"y"}'), 'positive control: planted in a metadata answer, the scan flags it');
                break;
            }
        }
        self::assertGreaterThan(8, $gateway, 'the tours reached the credential gateways');
    }

    public function test_every_shape_has_a_positive_control(): void
    {
        $planted = [
            'imds credentials' => '{"Code":"Success","AccessKeyId":"x","SecretAccessKey":"y"}',
            'sts success' => '<GetCallerIdentityResult><Arn>x</Arn></GetCallerIdentityResult>',
            'account id' => '{"Account":"123456789012"}',
            'payment object' => '{"object":"charge","id":"ch_1"}',
            'order rows' => "order_id,total\n1,9.99",
            'clone' => 'Receiving objects: 100% (5/5), done.',
            'imds token' => '{"Token":"AQoDYXdzEJr1K2NpZ2V4YW1wbGU="}',
        ];
        self::assertSame(array_keys(SsrfGoalProof::SHAPES), array_keys($planted));
        foreach ($planted as $shape => $body) {
            self::assertFalse(SsrfGoalProof::clean($body), $shape);
        }
        foreach (CredentialEndpoints::VERDICTS as $v) {
            self::assertTrue(SsrfGoalProof::clean(CredentialEndpoints::stsReply($v, 'r')->body . CredentialEndpoints::paymentsReply($v)->body), $v);
        }
    }
}
