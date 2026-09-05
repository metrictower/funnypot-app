<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\AiApi;

use Funnypot\App\AiApi\ModelIdentityResponder;
use Funnypot\Core\Ai\ModelCatalog;
use PHPUnit\Framework\TestCase;

/**
 * Identity coherence: the answer's vendor must agree with the requested model's real owner, and version
 * + cutoff appear when asked. The bug this closes was claiming Anthropic for a non-Anthropic model.
 */
final class ModelIdentityResponderTest extends TestCase
{
    private function responder(): ModelIdentityResponder
    {
        return new ModelIdentityResponder(ModelCatalog::fromPackage());
    }

    public function test_every_catalog_owner_has_identity_metadata(): void
    {
        foreach (ModelCatalog::fromPackage()->all() as $entry) {
            $owner = (string) ($entry['owned_by'] ?? '');
            self::assertNotNull(
                ModelIdentityResponder::ownerMeta($owner),
                "catalog owner '{$owner}' (model {$entry['name']}) has no identity metadata — add it"
            );
        }
    }

    public function test_kimi_names_moonshot_not_anthropic_or_openai(): void
    {
        $answer = $this->responder()->answer('what model are you exactly?', 'kimi-k3');
        self::assertStringContainsString('Moonshot AI', $answer);
        self::assertStringNotContainsString('Anthropic', $answer);
        self::assertStringNotContainsString('OpenAI', $answer);
    }

    public function test_gpt_oss_maps_to_openai(): void
    {
        $answer = $this->responder()->answer('which model are you', 'gpt-oss-120b');
        self::assertStringContainsString('OpenAI', $answer);
    }

    public function test_house_mythos_follows_its_catalog_owner(): void
    {
        $answer = $this->responder()->answer('who made you', 'mythos');
        self::assertStringContainsString('Anthropic', $answer);
    }

    public function test_version_and_cutoff_present_when_asked(): void
    {
        $answer = $this->responder()->answer('what model are you exactly? version + knowledge cutoff', 'kimi-k3');
        self::assertStringContainsString('kimi-k3', $answer);       // exact requested version
        self::assertStringContainsString('Knowledge cutoff', $answer);
    }

    public function test_cutoff_not_volunteered_when_not_asked(): void
    {
        $answer = $this->responder()->answer('what model are you', 'kimi-k3');
        self::assertStringNotContainsString('Knowledge cutoff', $answer);
    }

    public function test_unknown_model_makes_no_false_vendor_claim(): void
    {
        $answer = $this->responder()->answer('what model are you', 'totally-made-up-9000');
        self::assertStringNotContainsString('Anthropic', $answer);
        self::assertStringNotContainsString('OpenAI', $answer);
        self::assertStringContainsString('inference endpoint', $answer);
    }

    public function test_family_prefix_identifies_an_unlisted_well_known_family(): void
    {
        self::assertStringContainsString('Anthropic', $this->responder()->answer('which model', 'claude-3-5-sonnet-latest'));
        self::assertStringContainsString('Meta', $this->responder()->answer('which model', 'llama3.3:70b'));
    }

    public function test_bundled_arithmetic_is_answered(): void
    {
        $answer = $this->responder()->answer('what model are you, and what is 1+1', 'gpt-oss-120b');
        self::assertStringContainsString('1 + 1 = 2', $answer);
    }

    public function test_deterministic_for_the_same_probe(): void
    {
        $a = $this->responder()->answer('who made you', 'kimi-k3');
        $b = $this->responder()->answer('who made you', 'kimi-k3');
        self::assertSame($a, $b);
    }
}
