<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use Funnypot\App\Render\PageShellRenderer;
use Funnypot\Core\Support\VisualPersona;

/**
 * Maps a request path's file extension to the shape of fake to synthesize. A real server answers a
 * .js with application/javascript, a .json with JSON, an .env with plaintext — wrapping all of them
 * in an HTML page at text/html is itself a fingerprint tell. This only decides the *shape*; Gate B
 * (ProbeClassifier) already decided the path was worth a fake at all.
 *
 * Unknown / no-extension / "dangerous" extensions (archives, keys, backups, binaries) fall back to
 * the HTML profile — today's behaviour, and the safe default. Archives are normally intercepted
 * before the LLM by HoneypotController::serveDecoyArchive(); key/cert material stays on the HTML path
 * on purpose, since synthesising convincing fake PEM is the one plaintext shape actively worth not
 * doing (LlmOutputSanitizer already blocks "-----BEGIN").
 */
final class LlmResponseProfiles
{
    private const EXT_KIND = [
        'json' => 'json',
        'css' => 'css',
        'js' => 'js',
        'xml' => 'xml',
        'env' => 'text', 'conf' => 'text', 'config' => 'text', 'ini' => 'text', 'yml' => 'text',
        'yaml' => 'text', 'txt' => 'text', 'sql' => 'text', 'properties' => 'text', 'log' => 'text',
        'md' => 'text',
    ];

    /** @var array<string,LlmResponseProfile> keyed by kind */
    private array $byKind;

    public function __construct(
        string $serverStack,
        string $htmlGrammar,
        string $jsonGrammar,
        ?PageShellRenderer $renderer = null,
        string $pageSlotsGrammar = '',
        string $company = 'Internal',
        ?VisualPersona $persona = null,
    ) {
        $this->byKind = [
            'html' => $renderer !== null
                ? new LlmResponseProfile('html', 'text/html; charset=utf-8', LlmPromptBuilder::forHtmlSlots($serverStack, $company), $pageSlotsGrammar, $renderer)
                : new LlmResponseProfile('html', 'text/html; charset=utf-8', LlmPromptBuilder::forHtml($serverStack), $htmlGrammar),
            'json' => new LlmResponseProfile('json', 'application/json', LlmPromptBuilder::forJson($serverStack, $persona), $jsonGrammar),
            'css' => new LlmResponseProfile('css', 'text/css; charset=utf-8', LlmPromptBuilder::forCss($serverStack), ''),
            'js' => new LlmResponseProfile('js', 'application/javascript', LlmPromptBuilder::forJs($serverStack, $persona), ''),
            'xml' => new LlmResponseProfile('xml', 'application/xml; charset=utf-8', LlmPromptBuilder::forXml($serverStack, $persona), ''),
            'text' => new LlmResponseProfile('text', 'text/plain; charset=utf-8', LlmPromptBuilder::forPlaintext($serverStack, $persona), ''),
        ];
    }

    public function resolve(string $path): LlmResponseProfile
    {
        return $this->byKind[self::EXT_KIND[$this->ext($path)] ?? 'html'];
    }

    /** Lower-cased extension of the last path segment, or '' (query stripped; a leading-dot dotfile
     *  has no extension). Only the final segment's last dot counts, so app.js.bak reads as 'bak'. */
    private function ext(string $path): string
    {
        $q = strpos($path, '?');
        if ($q !== false) {
            $path = substr($path, 0, $q);
        }
        $slash = strrpos($path, '/');
        $leaf = $slash === false ? $path : substr($path, $slash + 1);
        $dot = strrpos($leaf, '.');

        return $dot === false || $dot === 0 ? '' : strtolower(substr($leaf, $dot + 1));
    }
}
