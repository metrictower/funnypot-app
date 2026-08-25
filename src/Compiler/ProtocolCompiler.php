<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Core\Template\DirectiveRenderer;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * Compiles funnypot protocol templates (YAML) into the frozen array the runtime
 * ProtocolEmulator interprets. Build-time only (needs symfony/yaml); the emitted PHP array is
 * pure data, so the runtime stays PHP-only.
 *
 * Same safety posture as the HTTP compilers: unique ids, a closed directive vocabulary in
 * every response, valid regex, a known framing, and a hard per-response byte cap (a honeypot
 * must never emit an unbounded/amplifying reply).
 */
final class ProtocolCompiler
{
    private const FRAMINGS = ['line', 'resp', 'raw'];
    private const MAX_RESPONSE_BYTES = 16384;

    /**
     * @return array<string,array<string,mixed>> protocols keyed by id
     */
    public function compile(string $dir): array
    {
        $files = glob(rtrim($dir, '/') . '/*.yaml') ?: [];
        sort($files);

        $out = [];
        foreach ($files as $file) {
            $doc = Yaml::parseFile($file);
            if (!is_array($doc)) {
                throw new RuntimeException("Protocol template is not a mapping: {$file}");
            }
            $id = (string) ($doc['protocol'] ?? '');
            if ($id === '') {
                throw new RuntimeException("Protocol template {$file} missing 'protocol' id.");
            }
            if (isset($out[$id])) {
                throw new RuntimeException("Duplicate protocol id '{$id}' in {$file}.");
            }
            $out[$id] = $this->normalize($doc, $file);
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    private function normalize(array $doc, string $file): array
    {
        $framing = (string) ($doc['framing'] ?? 'line');
        if (!in_array($framing, self::FRAMINGS, true)) {
            throw new RuntimeException("Protocol template {$file}: framing must be one of " . implode(', ', self::FRAMINGS) . ".");
        }

        $banner = (string) ($doc['banner'] ?? '');
        $this->assertKnownDirectives($banner, $file);
        $this->assertBytes($banner, $file);

        $rules = [];
        foreach ((array) ($doc['rules'] ?? []) as $i => $rule) {
            $rules[] = $this->normalizeRule((array) $rule, $file, (int) $i);
        }

        $default = null;
        if (isset($doc['default']['send'])) {
            $default = ['send' => $this->normalizeSend($doc['default']['send'], $file)];
        }

        $out = [
            'listen' => array_values(array_map('intval', (array) ($doc['listen'] ?? []))),
            'severity' => (string) ($doc['severity'] ?? 'medium'),
            'tags' => array_values(array_map('strval', (array) ($doc['tags'] ?? []))),
            'banner' => $banner,
            'framing' => $framing,
            'rules' => $rules,
            'default' => $default,
        ];

        // Optional interactive fake-shell (accept-all login then a canned command shell).
        if (isset($doc['shell'])) {
            $shell = (array) $doc['shell'];
            foreach (['password_prompt', 'motd', 'fail'] as $k) {
                if (isset($shell[$k])) {
                    $this->assertKnownDirectives((string) $shell[$k], $file);
                    $this->assertBytes((string) $shell[$k], $file);
                }
            }
            $out['shell'] = $shell;
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $rule
     * @return array<string,mixed>
     */
    private function normalizeRule(array $rule, string $file, int $i): array
    {
        $match = (array) ($rule['match'] ?? []);
        $keys = array_intersect(['equals', 'prefix', 'contains', 'regex'], array_keys($match));
        if ($keys === []) {
            throw new RuntimeException("Protocol template {$file}: rule #{$i} match needs equals|prefix|contains|regex.");
        }
        if (isset($match['regex']) && @preg_match('~' . $match['regex'] . '~i', '') === false) {
            throw new RuntimeException("Protocol template {$file}: rule #{$i} invalid regex: {$match['regex']}");
        }
        if (!isset($rule['send'])) {
            throw new RuntimeException("Protocol template {$file}: rule #{$i} missing 'send'.");
        }

        $out = ['match' => $match, 'send' => $this->normalizeSend($rule['send'], $file)];
        if (!empty($rule['close'])) {
            $out['close'] = true;
        }

        return $out;
    }

    /**
     * @param mixed $send
     * @return string|array<string,mixed>
     */
    private function normalizeSend($send, string $file)
    {
        foreach ($this->sendStrings($send) as $s) {
            $this->assertKnownDirectives($s, $file);
            $this->assertBytes($s, $file);
        }

        return is_array($send) ? $send : (string) $send;
    }

    /**
     * Every literal string inside a send spec (raw string, or bulk/bulk_array/simple/error text).
     *
     * @param mixed $send
     * @return string[]
     */
    private function sendStrings($send): array
    {
        if (!is_array($send)) {
            return [(string) $send];
        }
        $out = [];
        foreach ($send as $v) {
            if (is_string($v)) {
                $out[] = $v;
            } elseif (is_array($v)) {
                foreach ($v as $x) {
                    $out[] = (string) $x;
                }
            }
        }

        return $out;
    }

    private function assertKnownDirectives(string $text, string $file): void
    {
        $text = strtr($text, ['{{{{' => '', '}}}}' => '']);
        if (!preg_match_all('/\{\{\s*([^}]+?)\s*\}\}/', $text, $all)) {
            return;
        }
        foreach ($all[1] as $expr) {
            foreach (array_map('trim', explode('|', $expr)) as $part) {
                $known = false;
                foreach (DirectiveRenderer::KNOWN_PREFIXES as $prefix) {
                    if (strpos($part, $prefix) === 0) {
                        $known = true;
                        break;
                    }
                }
                if (!$known) {
                    throw new RuntimeException("Protocol template {$file}: unknown directive '{{{$part}}}'.");
                }
            }
        }
    }

    private function assertBytes(string $text, string $file): void
    {
        // Bound the static size; directives expand to short fixed values, so the rendered
        // response stays bounded too (no amplification).
        if (strlen($text) > self::MAX_RESPONSE_BYTES) {
            throw new RuntimeException("Protocol template {$file}: a response exceeds " . self::MAX_RESPONSE_BYTES . " bytes.");
        }
    }
}
