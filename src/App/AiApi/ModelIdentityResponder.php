<?php

declare(strict_types=1);

namespace Funnypot\App\AiApi;

use Funnypot\Core\Ai\ModelCatalog;

/**
 * Model-aware identity answers. A tool-using scanner cross-checks "what model are you exactly?" against
 * the model it requested, so a fixed house line that claims Anthropic for a `kimi-k3` request is an
 * instant tell. This resolves the vendor from the requested model — the installed catalog's `owned_by`
 * is the source of truth, with a closed family-prefix fallback for an unlisted (open-box) model — and
 * answers version + knowledge cutoff when the probe asks for them. Still hardcoded and sidecar-free, and
 * still subject to the handler's believable-first / troll-after engagement policy.
 */
final class ModelIdentityResponder
{
    /** Human vendor label + a reviewed knowledge-cutoff string per catalog `owned_by`. */
    private const OWNER_META = [
        'anthropic' => ['Anthropic', 'early 2025'],
        'moonshotai' => ['Moonshot AI', 'mid 2024'],
        'qwen' => ['Alibaba', 'late 2024'],
        'zai-org' => ['Zhipu AI', '2024'],
        'deepseek-ai' => ['DeepSeek', 'mid 2024'],
        'mistralai' => ['Mistral AI', '2024'],
        'nvidia' => ['NVIDIA', '2024'],
        'openai' => ['OpenAI', 'late 2024'],
        'google' => ['Google', 'early 2025'],
        'opencode-zen' => ['OpenCode', '2024'],
    ];

    /** Closed family-prefix map for an unlisted model name (strict-model mode is off if we reach here). */
    private const FAMILY_PREFIX = [
        'claude' => ['Anthropic', 'early 2025'],
        'gpt-oss' => ['OpenAI', 'late 2024'],
        'gpt' => ['OpenAI', 'late 2024'],
        'o1' => ['OpenAI', 'late 2024'],
        'o3' => ['OpenAI', 'late 2024'],
        'gemma' => ['Google', 'early 2025'],
        'llama' => ['Meta', '2024'],
        'mistral' => ['Mistral AI', '2024'],
        'deepseek' => ['DeepSeek', 'mid 2024'],
        'qwen' => ['Alibaba', 'late 2024'],
        'kimi' => ['Moonshot AI', 'mid 2024'],
        'glm' => ['Zhipu AI', '2024'],
        'nemotron' => ['NVIDIA', '2024'],
    ];

    public function __construct(private ModelCatalog $catalog)
    {
    }

    /** True when the text reads as an identity / capability probe (shared with the house responder). */
    public function matches(string $userText): bool
    {
        return IdentityResponder::matches($userText);
    }

    /** The vendor + cutoff metadata for a catalog `owned_by`, or null when unknown (for tests). */
    public static function ownerMeta(string $ownedBy): ?array
    {
        return self::OWNER_META[$ownedBy] ?? null;
    }

    /**
     * A believable, deterministic identity answer coherent with the requested model. Version + cutoff are
     * included only when the probe asks; a bundled arithmetic sanity check is answered.
     */
    public function answer(string $userText, string $model): string
    {
        $model = substr($model, 0, 128);
        [$vendor, $cutoff, $known] = $this->resolve($model);
        $modelLabel = $model !== '' ? $model : 'the model on this endpoint';

        if ($known) {
            $line = "I'm {$modelLabel}, a large language model from {$vendor}.";
        } else {
            // Never guess a vendor for an unknown name.
            $line = "I'm {$modelLabel}, the requested model on this inference endpoint.";
        }

        if ($this->asksVersionOrCutoff($userText)) {
            $version = $model !== '' ? $model : 'unspecified';
            $line .= " Version: {$version}.";
            if ($cutoff !== null) {
                $line .= " Knowledge cutoff: {$cutoff}.";
            }
        }

        $math = IdentityResponder::mathClause($userText);

        return $math === null ? $line : $line . ' And ' . $math . '.';
    }

    /**
     * @return array{0:string,1:?string,2:bool} [vendor, cutoff, known]
     */
    private function resolve(string $model): array
    {
        $entry = $model !== '' ? $this->catalog->find($model) : null;
        if ($entry !== null && is_string($entry['owned_by'] ?? null)) {
            $meta = self::OWNER_META[$entry['owned_by']] ?? null;
            if ($meta !== null) {
                return [$meta[0], $meta[1], true];
            }
        }

        $lower = strtolower($model);
        foreach (self::FAMILY_PREFIX as $prefix => $meta) {
            if ($lower !== '' && strncmp($lower, $prefix, strlen($prefix)) === 0) {
                return [$meta[0], $meta[1], true];
            }
        }

        return ['', null, false];
    }

    private function asksVersionOrCutoff(string $userText): bool
    {
        return preg_match(
            '/\b(version|knowledge\s*cut[\s-]?off|cut[\s-]?off|training\s*data|trained\s+(?:up\s+)?(?:to|until)|what\s+year|exact(?:ly)?)\b/i',
            $userText
        ) === 1;
    }
}
