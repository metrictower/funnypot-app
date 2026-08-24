<?php

declare(strict_types=1);

namespace Funnypot\App\Llm;

use DOMDocument;

/**
 * Treats LLM output as hostile. The grammar (where one is used) constrains structure, but not
 * semantics, so every generated body is validated here before it can be served. Returns null on ANY
 * violation, which the responder treats identically to a generation failure: fall through to the
 * plain 404. Never truncates (a truncated body is malformed, and malformed is its own tell) and never
 * executes the string — it only ever reaches output as a response body.
 *
 * Validation is per content kind. A shared prelude (size band, UTF-8, no control bytes, exploit-code
 * substrings) runs for every kind; then a kind-specific check enforces that the body reads as that
 * type and carries nothing weaponised. The grammar-backed kinds (html, json) also get a first-byte
 * check; the grammar-free kinds (css, js, xml, text) instead reject a leading refusal/fence, since
 * they have no grammar to make a preamble structurally unreachable.
 *
 * Caveat on JS: JavaScript is Turing-complete, so "is this body inert" is not decidable by a
 * substring blocklist alone. The JS path is defence-in-depth (a data-only exemplar upstream + the
 * blocklist here), not a proof of inertness the way "no <script> tag exists" is for HTML.
 */
final class LlmOutputSanitizer
{
    /** Tags that must never appear in HTML (active content / redirect-y / structural injection). */
    private const BAD_TAGS = ['<script', '<iframe', '<object', '<embed', '<link', '<style', '<base'];

    /** Exploit-shaped substrings that no fake body of any kind legitimately contains. */
    private const BAD_SUBSTRINGS = [
        '<?php', '<?=', '#!/bin/', 'eval(', 'base64_decode(', 'system(', 'exec(', 'passthru(',
        'proc_open(', 'shell_exec(', '-----begin', '../../', '..\\..\\',
    ];

    /** Self-disclosure the honeypot must never reveal in a body — a probe like /are-you-a-honeypot
     *  can otherwise coax the model into echoing its own framing (the system prompt itself names
     *  "honeypot" / "defensive security-research"). Scanned over the WHOLE body, not just the opening
     *  like the refusal check, since the leak can surface mid-page. A rare false reject just 404s. */
    private const META_DISCLOSURE = [
        'honeypot', 'security research', 'security-research', 'defensive security',
        'as an ai', 'as a language model', 'i am an ai', "i'm an ai", 'system prompt',
        // Paraphrase leaks the model reaches for when a probe coaxes it into denying/describing what
        // it is. Every entry is a multi-word compound so a legit page ("API Server Status") still
        // passes — bare 'server'/'fake'/'ai' would false-reject.
        'fake server', 'fake web server', 'decoy', 'pretending to be', 'simulated response',
    ];

    /** A leading refusal / self-identification / fence — the tell a grammar-free body must not open
     *  with (grammar-backed kinds can't reach these). Checked over the first 80 chars only. */
    private const REFUSAL_MARKERS = [
        '```', 'sorry', 'i cannot', "i can't", 'i am unable', "i'm unable", 'as an ai',
        'as a language model', 'here is', "here's", 'sure!', 'certainly', 'unfortunately',
    ];

    /**
     * @param string $kind html|json|css|js|xml|text (unknown kinds validate as html)
     * @return string|null the validated body, or null on any violation
     */
    public function sanitize(string $raw, string $kind = 'html', int $maxBytes = 8192): ?string
    {
        $s = trim($raw);
        if (!$this->prelude($s, $maxBytes)) {
            return null;
        }
        $low = strtolower($s);

        switch ($kind) {
            case 'json':
                return $this->sanitizeJson($s);
            case 'css':
                return $this->sanitizeCss($s, $low);
            case 'js':
                return $this->sanitizeJs($s, $low);
            case 'xml':
                return $this->sanitizeXml($s, $low);
            case 'text':
                return $this->sanitizeText($s, $low);
            case 'html':
            default:
                return $this->sanitizeHtml($s, $low);
        }
    }

    /**
     * Same shared prelude as sanitize(), then validates the body as slot-JSON and returns the
     * DECODED array (not the string) — the render step consumes fields, not raw text. Used for the
     * page-slots payload, where the caller needs typed access to each slot rather than a body to
     * pass straight through.
     *
     * @return array<mixed>|null the decoded array, or null on any violation
     */
    public function sanitizeToArray(string $raw, int $maxBytes = 8192): ?array
    {
        $s = trim($raw);
        if (!$this->prelude($s, $maxBytes)) {
            return null;
        }
        // First non-whitespace byte must open an object/array (the grammar guarantees this; kept as
        // a floor for a degraded/grammar-free fallback path).
        $first = ltrim($s)[0] ?? '';
        if ($first !== '{' && $first !== '[') {
            return null;
        }
        $decoded = json_decode($s, true, 32);
        if ($decoded === null && strtolower(trim($s)) !== 'null') {
            return null;                                    // malformed / too deep
        }
        // Belt-and-braces recursion cap even though the grammar already bounds nesting.
        if ($this->jsonTooDeep($decoded, 6) || $this->jsonHasBadValue($decoded)) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * The whole-assembled-page pass. Slot values are validated individually, but the ASSEMBLED page
     * must be re-checked as a whole: a disclosure word or active tag can arise purely from how
     * trusted chrome concatenates with model-supplied slot text (a disclosure word split across
     * adjacent cells, e.g., reads intact to a human even though no single slot contains it).
     * Deliberately does NOT run the full HTML arm (sanitizeHtml) — the trusted page chrome
     * legitimately uses <style>/<link> and relative URLs that sanitizeHtml would reject.
     */
    public function pageBodyOk(string $html, bool $trustedChrome = false): bool
    {
        $low = strtolower($html);
        foreach (self::META_DISCLOSURE as $tell) {
            if (strpos($low, $tell) !== false) {
                return false;
            }
        }
        // The active-content checks (<script>/<iframe>/on-handlers) guard UNTRUSTED, model-supplied markup.
        // Trusted panel chrome is escape-by-construction with no model text in it, so its own scoped inline
        // JS/handlers (the deep panel's interactivity) are safe and exempt — but the disclosure-tell scans
        // above and below still run on it, to catch an accidental leak in our own authored chrome.
        if (!$trustedChrome) {
            if (strpos($low, '<script') !== false || strpos($low, '<iframe') !== false) {
                return false;
            }
            if (preg_match('~[\s/]on[a-z]+\s*=~i', $html) === 1) {
                return false;
            }
        }
        // Re-scan the visible text with tags stripped and whitespace collapsed: a disclosure word
        // can be split across cells (e.g. <td>honey</td><td>pot</td> reads as "honeypot" to a human
        // even though it's absent from the raw markup).
        $text = preg_replace('/<[^>]*>/', '', $html) ?? '';
        $text = strtolower(preg_replace('/\s+/', ' ', $text) ?? '');
        foreach (self::META_DISCLOSURE as $tell) {
            if (strpos($text, $tell) !== false) {
                return false;
            }
        }

        return true;
    }

    /** True if the text carries any exploit-shaped substring (the shared BAD_SUBSTRINGS denylist —
     *  `#!/bin/`, `system(`, `shell_exec(`, `eval(`, `-----begin`, `../../`, ...). Exposed WITHOUT the
     *  size floor so a short body (e.g. a one-line chat reply) can be gated on the same denylist that
     *  the full prelude applies. */
    public function hasExploitSubstring(string $s): bool
    {
        $low = strtolower($s);
        foreach (self::BAD_SUBSTRINGS as $bad) {
            if (strpos($low, $bad) !== false) {
                return true;
            }
        }

        return false;
    }

    /** Shared validation run before any kind-specific check: realistic size band, valid UTF-8, no
     *  control bytes, no exploit-code substrings, no self-disclosure. Used by both sanitize() and
     *  sanitizeToArray() so the two paths can never drift out of sync. */
    private function prelude(string $s, int $maxBytes): bool
    {
        $len = strlen($s);

        // Realistic size band: reject a 12-byte stub and an oversized dump alike.
        if ($len < 32 || $len > $maxBytes) {
            return false;
        }
        if (!mb_check_encoding($s, 'UTF-8')) {
            return false;
        }
        // No control bytes (a real response body has none); tab / newline / carriage-return allowed.
        if (preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $s) === 1) {
            return false;
        }
        $low = strtolower($s);
        foreach (self::BAD_SUBSTRINGS as $bad) {
            if (strpos($low, $bad) !== false) {
                return false;
            }
        }
        foreach (self::META_DISCLOSURE as $tell) {
            if (strpos($low, $tell) !== false) {
                return false;
            }
        }

        return true;
    }

    private function sanitizeHtml(string $s, string $low): ?string
    {
        // Must be markup from the first byte: no "Sure! ", no ```html fence, no refusal sentence.
        if ($s[0] !== '<') {
            return null;
        }
        foreach (self::BAD_TAGS as $tag) {
            if (strpos($low, $tag) !== false) {
                return null;
            }
        }
        // A <meta> carrying http-equiv (meta-refresh redirect / CSP games) — any whitespace, any order.
        if (preg_match('~<meta\b[^>]*http-equiv~i', $s) === 1) {
            return null;
        }
        // Event-handler attributes (onload, onerror, ...). The separator before the handler can be
        // whitespace OR '/', so <body/onload=…> is caught, not only <body onload=…>.
        if (preg_match('~[\s/]on[a-z]+\s*=~i', $s) === 1) {
            return null;
        }
        // URL-bearing attributes may hold only same-origin relative URLs. Reject absolute /
        // protocol-relative links (off-site beacon / SSRF) AND the active-content schemes
        // javascript:/vbscript:/data:, which the grammar's attribute charset can still emit.
        if (preg_match('~\b(?:href|src|action|formaction)\s*=\s*["\']?\s*(?:(?:https?|javascript|vbscript|data)\s*:|//)~i', $s) === 1) {
            return null;
        }
        if ($this->hasBadCssUrl($s)) {
            return null;
        }

        return $s;
    }

    private function sanitizeJson(string $s): ?string
    {
        // First non-whitespace byte must open an object/array (the grammar guarantees this; kept as a
        // floor for a degraded/grammar-free fallback path).
        $first = ltrim($s)[0] ?? '';
        if ($first !== '{' && $first !== '[') {
            return null;
        }
        $decoded = json_decode($s, true, 32);
        if ($decoded === null && strtolower(trim($s)) !== 'null') {
            return null;                                    // malformed / too deep
        }
        // Belt-and-braces recursion cap even though the grammar already bounds nesting.
        if ($this->jsonTooDeep($decoded, 6) || $this->jsonHasBadValue($decoded)) {
            return null;
        }

        return $s;
    }

    private function sanitizeCss(string $s, string $low): ?string
    {
        if ($this->opensWithRefusal($low)) {
            return null;
        }
        // A stylesheet has no legitimate markup, no remote import, and none of the CSS-as-code vectors.
        if (strpos($s, '<') !== false || strpos($s, '>') !== false) {
            return null;
        }
        foreach (['@import', 'expression(', '-moz-binding', 'behavior:'] as $bad) {
            if (strpos($low, $bad) !== false) {
                return null;
            }
        }
        if ($this->hasBadCssUrl($s)) {
            return null;
        }
        // Malformed (unbalanced) CSS is its own tell.
        if (substr_count($s, '{') !== substr_count($s, '}')) {
            return null;
        }

        return $s;
    }

    private function sanitizeJs(string $s, string $low): ?string
    {
        if ($this->opensWithRefusal($low)) {
            return null;
        }
        // No markup breakout, no template literals, no obfuscation escapes.
        if (strpos($s, '<') !== false || strpos($s, '>') !== false || strpos($s, '`') !== false) {
            return null;
        }
        if (preg_match('/\\\\[xu]/', $s) === 1) {
            return null;
        }
        // Off-site / active-content references and event-handler shapes.
        if (preg_match('~(?:https?|javascript|vbscript|data)\s*:~i', $s) === 1) {
            return null;
        }
        if (preg_match('~[\s/]on[a-z]+\s*=~i', $s) === 1) {
            return null;
        }
        // Runtime / network / DOM primitives — data-only config JS needs none of these. (eval( is
        // already blocked by the shared BAD_SUBSTRINGS.)
        foreach ([
            'function(', 'new function', 'document.', 'window.', 'location', 'cookie', 'fetch(',
            'xmlhttprequest', 'websocket', 'import(', 'require(', 'settimeout(', 'setinterval(',
            'atob(', 'btoa(', 'string.fromcharcode(',
        ] as $bad) {
            if (strpos($low, $bad) !== false) {
                return null;
            }
        }

        return $s;
    }

    private function sanitizeXml(string $s, string $low): ?string
    {
        if ($s[0] !== '<') {
            return null;
        }
        // XXE / entity-expansion vectors — XML's own risk class.
        foreach (['<!doctype', '<!entity', '<![cdata['] as $bad) {
            if (strpos($low, $bad) !== false) {
                return null;
            }
        }
        // Absolute/protocol-relative URL in an attribute value (off-site reference).
        if (preg_match('~=\s*["\']?\s*(?:https?\s*:|//)~i', $s) === 1) {
            return null;
        }
        // Real-parser well-formedness (mismatched tags, unescaped &/<, bad nesting). LIBXML_NONET
        // blocks network fetches; PHP 8 does not resolve external entities by default (and we don't
        // pass LIBXML_NOENT, which would expand them).
        $prev = libxml_use_internal_errors(true);
        $doc = new DOMDocument();
        $ok = $doc->loadXML($s, LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);

        return $ok === true ? $s : null;
    }

    private function sanitizeText(string $s, string $low): ?string
    {
        if ($this->opensWithRefusal($low)) {
            return null;
        }
        // A real .env/.ini/.sql/.txt/.yaml never contains markup — its presence means the model broke
        // out of plaintext into HTML/XML.
        if (strpos($s, '<') !== false || strpos($s, '>') !== false) {
            return null;
        }

        return $s;
    }

    /** True if the first 80 chars open with a refusal / self-identification / markdown fence. */
    private function opensWithRefusal(string $low): bool
    {
        $head = substr($low, 0, 80);
        foreach (self::REFUSAL_MARKERS as $m) {
            if (strpos($head, $m) !== false) {
                return true;
            }
        }

        return false;
    }

    /** An absolute / protocol-relative / active-scheme URL inside a CSS url(...). Content-agnostic,
     *  so it is reused by both the html and css paths. */
    private function hasBadCssUrl(string $s): bool
    {
        return preg_match('~url\(\s*["\']?\s*(?:(?:https?|javascript|vbscript|data)\s*:|//)~i', $s) === 1;
    }

    /** @param mixed $v */
    private function jsonTooDeep($v, int $left): bool
    {
        if (!is_array($v)) {
            return false;
        }
        if ($left <= 0) {
            return true;
        }
        foreach ($v as $child) {
            if ($this->jsonTooDeep($child, $left - 1)) {
                return true;
            }
        }

        return false;
    }

    /** Recursively reject a string value that reads as a script tag, an active-content scheme, or an
     *  absolute URL — inert as JSON, but a plausibility/safety tell if the value is templated onward.
     *  Also mirrors the HTML arm's ban set (bad tags, event handlers, meta http-equiv) as defense-in-depth
     *  since the slot-JSON will be rendered into HTML.
     *  @param mixed $v */
    private function jsonHasBadValue($v): bool
    {
        if (is_string($v)) {
            $l = strtolower($v);
            if (strpos($l, '<script') !== false || preg_match('~(?:javascript|vbscript|data)\s*:~i', $v) === 1) {
                return true;
            }
            if (preg_match('~(?:https?\s*:)?//~i', $v) === 1) {
                return true;
            }
            // Mirror the HTML arm's tag/handler/meta bans as defense-in-depth.
            foreach (self::BAD_TAGS as $tag) {
                if (strpos($l, $tag) !== false) {
                    return true;
                }
            }
            if (preg_match('~[\s/]on[a-z]+\s*=~i', $v) === 1) {
                return true;
            }
            if (preg_match('~<meta\b[^>]*http-equiv~i', $v) === 1) {
                return true;
            }

            return false;
        }
        if (is_array($v)) {
            foreach ($v as $child) {
                if ($this->jsonHasBadValue($child)) {
                    return true;
                }
            }
        }

        return false;
    }
}
