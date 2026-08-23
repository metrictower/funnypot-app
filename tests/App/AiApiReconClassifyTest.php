<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\ThreatIntel\AttackClassifier;
use PHPUnit\Framework\TestCase;

/**
 * The ai_api_recon label the AI-API handler stamps on hits. It is not a payload-regex class (AI recon
 * is identified by path, not payload), so it only needs to exist as a const + carry a severity.
 */
final class AiApiReconClassifyTest extends TestCase
{
    public function test_ai_api_recon_const_value(): void
    {
        self::assertSame('ai_api_recon', AttackClassifier::AI_API_RECON);
    }

    public function test_ai_api_recon_has_a_severity(): void
    {
        self::assertNotSame('', (new AttackClassifier())->severityFor('ai_api_recon'));
        self::assertSame('medium', AttackClassifier::severityFor(AttackClassifier::AI_API_RECON));
    }

    public function test_ai_api_recon_is_not_a_payload_regex_class(): void
    {
        // Path-labelled only: a request body that merely mentions the words must not classify() as an
        // attack (that path stays the engine's / the other patterns' job).
        $ctx = new \Funnypot\RequestContext('POST', '/v1/chat/completions', '', [], '{"model":"x"}');
        self::assertNull((new AttackClassifier())->classify($ctx));
    }
}
