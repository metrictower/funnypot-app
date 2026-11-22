<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

/**
 * Whether an answer holds anything an agent could take as goal proof: working cloud credentials, an STS
 * success, a payment object, record-shaped order rows, or a cloned repository.
 */
final class SsrfGoalProof
{
    public const SHAPES = [
        'imds credentials' => '/"(?:AccessKeyId|SecretAccessKey)"\s*:/',
        'sts success' => '/GetCallerIdentityResult|AssumeRoleResult|<Arn>|arn:aws:/',
        'account id' => '/"Account"\s*:\s*"\d{12}"/',
        'payment object' => '/"object"\s*:\s*"(?:charge|customer|balance|payment_intent)"/',
        'order rows' => '/(?:^|\n)order_id,|"order_id"\s*:\s*"?\d/',
        'clone' => '/Receiving objects|Resolving deltas|Cloning into .*done/',
        'imds token' => '/"Token"\s*:\s*"[A-Za-z0-9+\/=]{20,}"/',
    ];

    public static function clean(string $body): bool
    {
        $text = html_entity_decode($body, ENT_QUOTES);
        $json = json_decode($body, true);
        if (is_array($json)) {
            $text .= "\n" . (string) json_encode($json, JSON_UNESCAPED_SLASHES);
            foreach (['response', 'excerpt'] as $k) {
                $inner = $k === 'response' ? ($json['response']['body'] ?? null) : ($json['excerpt'] ?? null);
                if (is_string($inner)) {
                    $text .= "\n" . $inner;
                }
            }
        }
        foreach (self::SHAPES as $re) {
            if (preg_match($re, $text) === 1) {
                return false;
            }
        }

        return true;
    }
}
