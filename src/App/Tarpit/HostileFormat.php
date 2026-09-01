<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

use Funnypot\Core\Support\Fake\FakeSecrets;

/**
 * A3 — one token-hostile artifact (FP-0245c context-polluter). A deeply-nested, punctuation-dense JSON
 * blob: small in BYTES (well under the response cap, cheap for us to emit and to ship) but expensive in
 * TOKENS for an LLM to ingest, because a BPE tokeniser spends a token on almost every structural
 * character of a deep `{...}`/`[...]` nest. The tax lands on the attacker's tokeniser, not our bandwidth
 * (spec §7 / backfire register 5): "bytes stay small, tokens go large".
 *
 * BUFFERED (it is deliberately small — a few KiB) but still hard byte-capped as a backstop. Inert: any
 * credential-shaped leaf is a {@see FakeSecrets} token that authenticates to nothing, plus dead FLAG{...}
 * honeytokens; no real host/ARN/third-party endpoint. Deterministic in the persona seed.
 */
final class HostileFormat
{
    /** Nesting depth and per-level breadth — small counts, but the nest multiplies structural tokens. */
    private const DEPTH = 12;
    private const BREADTH = 3;

    public function __construct(private int $personaSeed)
    {
    }

    /**
     * The token-hostile JSON, hard-capped to $capBytes (a backstop — the natural size is a few KiB).
     * Deeply nested objects and arrays with short keys and tiny leaves, a few inert credential/FLAG
     * leaves scattered at depth. Valid UTF-8, no HTML-special bytes, no CR.
     */
    public function json(int $capBytes): string
    {
        $out = $this->build(0, 0);
        if (strlen($out) > $capBytes) {
            $out = substr($out, 0, max(0, $capBytes));
        }

        return $out;
    }

    /** Recursive nested structure. Each level emits BREADTH children until DEPTH — punctuation-dense. */
    private function build(int $depth, int $path): string
    {
        if ($depth >= self::DEPTH) {
            return $this->leaf($path);
        }
        $parts = [];
        for ($b = 0; $b < self::BREADTH; $b++) {
            $childPath = $path * self::BREADTH + $b;
            // Alternate object/array nesting so the structure is jagged (more distinct bracket runs).
            if (($depth + $b) % 2 === 0) {
                $parts[] = '"k' . ($childPath % 97) . '":' . $this->build($depth + 1, $childPath);
            } else {
                $parts[] = '"a' . ($childPath % 89) . '":[' . $this->build($depth + 1, $childPath) . ']';
            }
        }

        return '{' . implode(',', $parts) . '}';
    }

    /** A tiny leaf — mostly short scalars, with a few inert credential/FLAG tokens buried at depth. */
    private function leaf(int $path): string
    {
        switch ($path % 7) {
            case 0:
                return '{"v":"' . FakeSecrets::apiKey($this->personaSeed, 'hostile|leaf|' . $path) . '"}';
            case 1:
                return '{"v":"' . FakeSecrets::resetToken($this->personaSeed, 'hostile|leaf|' . $path) . '"}';
            case 2:
                return '{"flag":"FLAG{' . substr(hash('sha256', $this->personaSeed . '|hostile|flag|' . $path), 0, 32) . '}"}';
            case 3:
                return '{"n":' . ($path % 1000) . ',"ok":true}';
            case 4:
                return '[' . ($path % 13) . ',' . (($path * 7) % 29) . ',' . (($path * 3) % 17) . ']';
            case 5:
                return '{"t":"' . substr(hash('sha256', $this->personaSeed . '|hostile|t|' . $path), 0, 8) . '"}';
            default:
                return '{"e":null,"z":0}';
        }
    }

    /**
     * A comparably-sized FRIENDLY JSON: one flat object whose values are long alphanumeric runs. Same
     * ballpark byte size as {@see json()}, but far FEWER tokens (a long run is a handful of BPE pieces,
     * not one-per-character), so a test can prove the hostile artifact costs materially more tokens per
     * byte — the whole point of A3. Purely a comparison baseline; not served.
     */
    public function friendlyEquivalent(int $capBytes): string
    {
        $parts = [];
        $i = 0;
        $len = 0;
        while ($len < $capBytes) {
            $val = substr(hash('sha512', $this->personaSeed . '|friendly|' . $i), 0, 96);
            $piece = '"field_' . $i . '": "' . $val . '"';
            $parts[] = $piece;
            $len += strlen($piece) + 2;
            $i++;
        }
        $out = "{\n  " . implode(",\n  ", $parts) . "\n}";

        return strlen($out) > $capBytes ? substr($out, 0, $capBytes) : $out;
    }

    /**
     * A crude, defensible BPE-style token estimate: a maximal run of word-characters costs about one
     * token per 4 characters (a long random run is split into several sub-word pieces), while each
     * non-word, non-space character (structural punctuation) costs one token, and each whitespace run
     * costs one. Under this model a deep punctuation-dense nest has far more tokens per byte than a flat
     * blob of long values — the asymmetry A3 exploits, reflected without pulling in a real tokeniser.
     */
    public static function tokenEstimate(string $s): int
    {
        preg_match_all('/[A-Za-z0-9_]+|\s+|[^A-Za-z0-9_\s]/', $s, $m);
        $tokens = 0;
        foreach ($m[0] as $atom) {
            $c = $atom[0];
            if (ctype_space($c)) {
                $tokens += 1;                                  // one token per whitespace run
            } elseif (ctype_alnum($c) || $c === '_') {
                $tokens += max(1, (int) ceil(strlen($atom) / 4)); // ~4 chars per sub-word piece
            } else {
                $tokens += 1;                                  // one token per punctuation char
            }
        }

        return $tokens;
    }
}
