<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit;

/**
 * The LLM-only link constructor (FP-0245b, the anti-Baidu control). The labyrinth's flagship property
 * is that its deep, UNBOUNDED surface is reachable ONLY by an agent that reads a page and reasons a URL
 * out of its content — never by an href/regex crawler. The operator was burned by the opposite: a
 * link-generating maze whose next-page links were plain <a href> (and whose entry sat in a robots.txt
 * Disallow line), so Baidu's bot treated it as a target list and crawled it into a self-DoS. robots.txt
 * and nofollow are advisory-only and are NOT a containment mechanism; the ONLY things that keep a
 * misbehaving crawler out of the maze are (a) that no plain href or robots line ever resolves to it and
 * (b) the per-IP/global {@see \Funnypot\App\Storage\TarpitBudget} caps.
 *
 * This class centralises the four obfuscation shapes (spec §4) so a coder cannot accidentally emit a
 * plain crawler-followable href to unbounded labyrinth surface — every method here emits a form that a
 * `href="([^"]*)"` extractor (or a bare-URL scraper) cannot turn into a followable request, while an LLM
 * reading the prose trivially can:
 *
 *   1. computeStep()  — prose describing a path to CONSTRUCT (increment/append a segment). No URL at all.
 *   2. base64Step()   — the next path embedded as base64 in visible prose for the LLM to decode.
 *   3. commentSplit() — the path inside an HTML comment AND whitespace-split, so a naive extractor grabs
 *                       a truncated/invalid token and a comment-stripping crawler sees nothing.
 *   4. hexStep()      — the next path as hex in prose (a second trivial-decode variant).
 *
 * Every dynamic value is passed through {@see esc()} (htmlspecialchars) so the fragment is inert HTML;
 * the encodings (base64/hex) only ever produce [A-Za-z0-9+/=] / [0-9a-f], which carry no HTML-special
 * byte and no CR/LF — size- and CRLF-safe for any transport.
 */
final class LlmOnlyLink
{
    /**
     * Shape 1 — a compute step. Pure prose: an instruction to construct the next path (e.g. "increment
     * the 6-digit page counter"). Emits NO URL and NO href, so neither an href extractor nor a bare-URL
     * scraper has anything to follow; only an agent that reasons about the instruction proceeds.
     */
    public static function computeStep(string $instruction): string
    {
        return '<p class="lab-nav lab-nav-compute">' . self::esc($instruction) . '</p>';
    }

    /**
     * Shape 2 — a trivial base64 decode. The next path is shown as base64 in visible prose; a crawler
     * sees an opaque token, an LLM decodes it to a path and requests it. $path is the real path the token
     * decodes to (never rendered verbatim as a URL).
     */
    public static function base64Step(string $label, string $path): string
    {
        return '<p class="lab-nav lab-nav-b64">' . self::esc($label) . ' <code>'
            . self::esc(base64_encode($path)) . '</code></p>';
    }

    /**
     * Shape 3 — a comment-split URL. The path is placed inside an HTML comment AND broken by whitespace
     * so it is doubly crawler-hostile: a comment-stripping parser never sees it, and a naive
     * `href|src`-or-bare-URL extractor that does read comment text grabs only a truncated, invalid token.
     * An LLM removes the interior whitespace and requests the normalised path. The path is split at fixed
     * structural boundaries ('/', '-') into space-separated pieces; only [A-Za-z0-9/_.-] paths are split
     * (the labyrinth's own paths), and each piece is escaped.
     */
    public static function commentSplit(string $path): string
    {
        $pieces = preg_split('~(?<=[/-])~', $path) ?: [$path];
        $broken = implode(' ', array_map([self::class, 'esc'], $pieces));

        return "<!-- archive continues at: " . $broken . " (join the segments) -->";
    }

    /**
     * Shape 4 — a trivial hex decode (a second decode variant so the maze is not single-shaped). The
     * next path is shown as lowercase hex in visible prose.
     */
    public static function hexStep(string $label, string $path): string
    {
        return '<p class="lab-nav lab-nav-hex">' . self::esc($label) . ' <code>'
            . self::esc(bin2hex($path)) . '</code></p>';
    }

    /**
     * True if $html contains a plain, crawler-followable link attribute (href/src) — the exact thing a
     * regex link-extractor follows. The labyrinth's own tests assert every generated page returns FALSE
     * here for any labyrinth-interior path: the maze must expose no plain link into its unbounded depth.
     * A defensive, self-documenting guard, not used on the serve path.
     */
    public static function containsFollowableLink(string $html): bool
    {
        return preg_match('/\b(?:href|src)\s*=/i', $html) === 1;
    }

    private static function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
