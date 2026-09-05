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
 * Every tell scan runs over the raw bytes AND an entity-decoded view: `&#104;oneypot` passes a plain
 * strpos but renders as the tell in a browser. Decoding is detection-only — the body that is cached
 * and served is always the original bytes, or nothing. The sanitizer also carries the deploy's real
 * secret values as canaries (rejected wherever they appear) and, on raw model output only, rejects
 * live-credential shapes the model could only have invented or memorised.
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
     *  like the refusal check, since the leak can surface mid-page. A rare false reject just 404s.
     *  Plain (non-word-boundary) substring match on purpose: a false reject just falls through to the
     *  plain 404, so erring toward over-rejection is the safe direction here — 'honeypot' and 'decoy'
     *  therefore also catch any suffixed form (honeypotted, decoyed, …) as a side effect of matching
     *  substring-not-whole-token. FP-0112 review #1: do not remove or narrow either entry. */
    private const META_DISCLOSURE = [
        'honeypot', 'security research', 'security-research', 'defensive security',
        'as an ai', 'as a language model', 'i am an ai', "i'm an ai", 'system prompt',
        // Paraphrase leaks the model reaches for when a probe coaxes it into denying/describing what
        // it is. Every entry is a multi-word compound so a legit page ("API Server Status") still
        // passes — bare 'server'/'fake'/'ai' would false-reject.
        'fake server', 'fake web server', 'decoy', 'pretending to be', 'simulated response',
    ];

    /** FP-0112 review #1: this project's OWN remaining self-identifying vocabulary — funnypot, bait,
     *  lure(s), tarpit(s), metrictower, troll(s|ing), sabotage, deception — the same leak-OUT terms
     *  resources/app-fingerprint-denylist.php's `own_vocabulary` guards on every OTHER served surface.
     *  This is the runtime LLM path (live sidecar-model output via LlmFakeResponder / AiChatHandler),
     *  the least-controllable surface of all, and it had NO parity with that list until this fix — a
     *  reply like "this looks like a funnypot" or "you're in a tarpit" would have passed unblocked.
     *
     *  Sourced from the SAME resource file at construction (never duplicated as a literal here) so the
     *  two lists cannot drift apart again; see loadSharedOwnVocabularyStems(). Unlike META_DISCLOSURE
     *  above, this is matched delimiter-safe / whole-token (see hasSharedOwnVocabularyLeak()) — plain
     *  substring matching on 'troll'/'lure' would false-reject every legitimate "…Controller" class
     *  name or "failure" mention a generated admin page routinely contains, which would quietly gut
     *  this app's plausibility. 'honeypot'/'decoy' stay OUT of this second list — they are already
     *  covered, more strictly, by the substring entries above; duplicating them here would not add
     *  coverage and would risk two matchers disagreeing on the same term. */
    private const SHARED_OWN_VOCABULARY_EXCLUDE = ['honeypot', 'decoy'];

    /** Compiled once per process: the delimiter-safe, whole-token regex over the shared own_vocabulary
     *  stems (funnypot/bait/lure/tarpit/metrictower/troll/sabotage/deception — honeypot/decoy excluded,
     *  see SHARED_OWN_VOCABULARY_EXCLUDE), read from the same resources/app-fingerprint-denylist.php
     *  the served-surface tests scan. Mirrors FingerprintSafetyTest::ownVocabularyPattern() exactly,
     *  digits-stay-word-characters included (a stem glued to a digit, e.g. `decoy2`, is a deliberate
     *  non-catch — see that resource file's own_vocabulary doc comment for the false-positive this
     *  avoids against this app's own random-token generation). */
    private static ?string $ownVocabularyPattern = null;

    /** @return list<string> the own_vocabulary stems, minus SHARED_OWN_VOCABULARY_EXCLUDE */
    private static function loadSharedOwnVocabularyStems(): array
    {
        $d = require dirname(__DIR__, 3) . '/resources/app-fingerprint-denylist.php';
        $stems = array_values((array) ($d['own_vocabulary'] ?? []));

        return array_values(array_filter($stems, static function ($stem): bool {
            foreach (self::SHARED_OWN_VOCABULARY_EXCLUDE as $excluded) {
                if (strpos((string) $stem, $excluded) === 0) {
                    return false;
                }
            }

            return true;
        }));
    }

    /** True if $text (already lower-cased by the caller is NOT assumed — this matches case-insensitively
     *  itself) carries any shared own_vocabulary term as a whole token. */
    private static function hasSharedOwnVocabularyLeak(string $text): bool
    {
        if (self::$ownVocabularyPattern === null) {
            $stems = self::loadSharedOwnVocabularyStems();
            self::$ownVocabularyPattern = $stems === []
                ? ''
                : '/(?<![a-zA-Z0-9])(' . implode('|', $stems) . ')(?![a-zA-Z0-9])/i';
        }

        return self::$ownVocabularyPattern !== '' && preg_match(self::$ownVocabularyPattern, $text) === 1;
    }

    /** A leading refusal / self-identification / fence — the tell a grammar-free body must not open
     *  with (grammar-backed kinds can't reach these). Checked over the first 80 chars only. */
    private const REFUSAL_MARKERS = [
        '```', 'sorry', 'i cannot', "i can't", 'i am unable', "i'm unable", 'as an ai',
        'as a language model', 'here is', "here's", 'sure!', 'certainly', 'unfortunately',
    ];

    /** Live-credential shapes raw MODEL output must never carry: the prompts ask for fake tokens
     *  (`tok_…`, `changeme_…`, slot markers), so a real-looking key can only be invented (a rare false
     *  reject just 404s) or memorised from somewhere real (must never ship). Scanned in prelude() ONLY,
     *  never in the assembled-page pass: the trusted chrome's own bait (VisualPersona::awsKey(),
     *  FakeSecrets) emits exactly these shapes by design, and a shape scan there would 404 our own pages. */
    private const LIVE_KEY_SHAPES = [
        '/AKIA[0-9A-Z]{16}/',
        '/sk_live_[0-9a-zA-Z]{10,}/',
        '/ghp_[0-9a-zA-Z]{20,}/',
        '/xoxb-\d/',
        '/eyJ[A-Za-z0-9_-]{20,}\.eyJ/',
    ];

    /** A canary shorter than this is dropped: a short or common value would reject most bodies. */
    private const MIN_CANARY_LEN = 8;

    /**
     * @param string[] $canaries    the deploy's REAL secret values (AppConfig::secretCanaries()). A body
     *                              carrying one, raw or entity-encoded, is rejected in every arm — real
     *                              secrets have no legitimate presence anywhere, trusted chrome included.
     * @param string[] $shapeExempt persona-derived FAKE credentials the deploy's own bait emits (the
     *                              persona AWS key, FakeSecrets values); excluded from the live-key shape
     *                              scan so a bait value reaching raw output can never 404 its own page.
     */
    public function __construct(array $canaries = [], array $shapeExempt = [])
    {
        $keep = static fn (int $min): callable => static fn ($v): bool => is_string($v) && strlen($v) >= $min;
        $this->canaries = array_values(array_unique(array_filter($canaries, $keep(self::MIN_CANARY_LEN))));
        $this->shapeExempt = array_values(array_unique(array_filter($shapeExempt, $keep(1))));
    }

    /** @var string[] */
    private array $canaries;

    /** @var string[] */
    private array $shapeExempt;

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
        $decoded = self::decodedLower($html);
        if (self::containsAny($low, self::META_DISCLOSURE) || self::containsAny($decoded, self::META_DISCLOSURE)) {
            return false;
        }
        // FP-0112 review #1: same shared own_vocabulary parity as prelude() (see that call site's
        // comment); pageBodyOk() is the whole-assembled-page pass so this must run here too, not just
        // per-slot, and both the raw-markup pass here and the tag-stripped pass below.
        if (self::hasSharedOwnVocabularyLeak($html) || self::hasSharedOwnVocabularyLeak($decoded)) {
            return false;
        }
        // The deploy's real secrets are rejected here too (unlike the key-SHAPE scan, which is
        // prelude-only — see LIVE_KEY_SHAPES): no trusted chrome legitimately carries a real value.
        if ($this->hasCanary($html)) {
            return false;
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
        // even though it's absent from the raw markup). The entity-decoded pass is IN ADDITION to the
        // raw one and decodes AFTER the tag strip: decoding first would let `&lt;script` materialise
        // a `<` the strip regex then eats along with the text behind it.
        $stripped = preg_replace('/<[^>]*>/', '', $html) ?? '';
        $text = strtolower(preg_replace('/\s+/', ' ', $stripped) ?? '');
        $textDecoded = preg_replace('/\s+/', ' ', self::decodedLower($stripped)) ?? '';
        foreach ([$text, $textDecoded] as $view) {
            if (self::containsAny($view, self::META_DISCLOSURE) || self::hasSharedOwnVocabularyLeak($view)) {
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
        // Both views for every list: `&#101;val(` is the same trick against the exploit list as
        // `&#104;oneypot` is against the disclosure list.
        foreach ([strtolower($s), self::decodedLower($s)] as $view) {
            if (self::containsAny($view, self::BAD_SUBSTRINGS) || self::containsAny($view, self::META_DISCLOSURE)) {
                return false;
            }
            // FP-0112 review #1: parity with resources/app-fingerprint-denylist.php's own_vocabulary —
            // the runtime path had none until this check (funnypot/bait/lure/tarpit/metrictower/troll/
            // sabotage/deception). Runs for EVERY kind, same as META_DISCLOSURE above.
            if (self::hasSharedOwnVocabularyLeak($view)) {
                return false;
            }
        }
        // Raw model output is the one surface where a live-key shape cannot be our own bait.
        if ($this->hasCanary($s) || $this->hasLiveKeyShape($s)) {
            return false;
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

    /** Lower-cased, entity-decoded view of $s for the tell scans, with the no-break space folded to a
     *  plain one (a browser renders `as&nbsp;an&nbsp;ai` as the tell). Detection-only: never served. */
    private static function decodedLower(string $s): string
    {
        return strtolower(str_replace("\xc2\xa0", ' ', html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8')));
    }

    /** @param string[] $needles plain substrings, already in the haystack's case */
    private static function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (strpos($haystack, $needle) !== false) {
                return true;
            }
        }

        return false;
    }

    /** True if the body carries one of the deploy's real secret values, raw or entity-encoded. */
    private function hasCanary(string $s): bool
    {
        if ($this->canaries === []) {
            return false;
        }
        $decoded = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        foreach ($this->canaries as $secret) {
            if (stripos($s, $secret) !== false || stripos($decoded, $secret) !== false) {
                return true;
            }
        }

        return false;
    }

    /** True if the body carries a live-credential shape (LIVE_KEY_SHAPES), raw or entity-encoded,
     *  once the deploy's own persona-derived fake values are blanked out. */
    private function hasLiveKeyShape(string $s): bool
    {
        foreach ([$s, html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8')] as $view) {
            if ($this->shapeExempt !== []) {
                $view = str_replace($this->shapeExempt, '', $view);
            }
            foreach (self::LIVE_KEY_SHAPES as $shape) {
                if (preg_match($shape, $view) === 1) {
                    return true;
                }
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
