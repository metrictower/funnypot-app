<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * The "malformed" style for the interactive socket honeypots (SSH / telnet). Under
 * FUNNYPOT_STYLE=malformed a connection is answered not with a login/shell but with an ENDLESS-looking
 * (but bounded) trickle designed to jam automated clients and analyst terminals:
 *
 *   frame 0      — one opening BURST: invalid UTF-8, random unicode, screen/cursor ANSI disruption, an
 *                  OSC-52 clipboard WRITE ("access denied :)"), and an OSC-52 clipboard READ query.
 *   frames 1..N  — the SKULL / TROLL animation, reused verbatim from {@see TrollStream} (frames past its
 *                  FLASH_FRAMES opening), pushed once per second by the driver.
 *   at frame CAP — the driver stops and CLOSES the connection. Never forever: a bounded time/attention
 *                  sink, so a hung client can't pin a worker indefinitely.
 *
 * The OSC-52 read reply arrives on the INBOUND stream; the driver feeds it to {@see parseClipboard}
 * which decodes it and the driver logs it as intel (event=clipboard). All output is built from static
 * tables — zero attacker-input reflection, O(1) memory + CPU. Fingerprint-safe: no scanner/matcher
 * signature strings.
 */
final class MalformedStream
{
    /** Frame count at which the driver stops and closes (~1 frame/sec => ~120s). */
    public const CAP_FRAMES = 120;

    /** OSC-52 clipboard WRITE: overwrite the client clipboard with base64("access denied :)"). */
    private const OSC52_WRITE = "\e]52;c;YWNjZXNzIGRlbmllZCA6KQ==\x07";

    /** OSC-52 clipboard READ query: a capable terminal replies inbound with \e]52;c;<base64>BEL. */
    private const OSC52_READ = "\e]52;c;?\x07";

    public static function enabled(): bool
    {
        return (getenv('FUNNYPOT_STYLE') ?: '') === 'malformed';
    }

    /** True once the bounded session has emitted its cap of frames — the driver then closes. */
    public static function done(int $n): bool
    {
        return $n >= self::CAP_FRAMES;
    }

    /**
     * Frame $n of the malformed stream. $n === 0 is the one-shot opening burst; every later frame reuses
     * the TrollStream SKULL/TROLL animation (past its login-flash opening), so the two styles share art.
     */
    public static function frame(int $n): string
    {
        if ($n <= 0) {
            return self::openingBurst();
        }

        // Reuse the SKULL/TROLL animation frames (TrollStream::frame >= FLASH_FRAMES skips the taunt's
        // "ENABLE REVERSE CONNECTION" flash and returns the art + bar cycle).
        return TrollStream::frame(TrollStream::FLASH_FRAMES + ($n - 1));
    }

    /**
     * The opening burst, sent all at once on connect: RFC-3629-violating UTF-8, a random-unicode run,
     * terminal-disrupting ANSI/CSI, then the OSC-52 write + read. Static — deterministic and bounded.
     */
    public static function openingBurst(): string
    {
        return self::invalidUtf8()
            . self::randomUnicode()
            . self::ansiDisruption()
            . self::OSC52_WRITE
            . self::OSC52_READ
            . "\r\n";
    }

    /** Invalid UTF-8 that trips strict decoders (UnicodeDecodeError / Utf8Error / decode panics). */
    public static function invalidUtf8(): string
    {
        return "\xc3\x28"                 // truncated 2-byte
            . "\xe2\x28\xa1"              // truncated 3-byte
            . "\xf0\x28\x8c\xbc"         // truncated 4-byte
            . "\xc0\xaf"                 // overlong '/'
            . "\xe0\x80\xaf"             // overlong 3-byte
            . "\xf0\x80\x80\xaf"         // overlong 4-byte
            . "\xed\xa0\x80"             // lone surrogate U+D800
            . "\xed\xbf\xbf"             // lone surrogate U+DFFF
            . "\xef\xb7\x90"             // non-character U+FDD0
            . "\xef\xbf\xbe\xef\xbf\xbf" // non-characters U+FFFE / U+FFFF
            . "\x80\x81\x82\xbf\xc1\xf5\xfe\xff" // continuation storm + illegal bytes
            . "\x00\x00";                // embedded NULs
    }

    /** A run of assorted high codepoints encoded raw + a bidi override, to churn text shapers. */
    public static function randomUnicode(): string
    {
        // Zalgo-ish combining marks, RTL override, zero-width + wide/emoji-range bytes — all valid UTF-8
        // but hostile to naive line/column accounting.
        return "\u{202E}"                                   // RIGHT-TO-LEFT OVERRIDE
            . str_repeat("\u{0301}\u{0489}\u{20DD}", 24)   // stacked combining marks (zalgo)
            . "\u{200B}\u{FEFF}\u{2029}"                    // zero-width space, BOM, paragraph sep
            . str_repeat("\u{1F480}\u{FFFD}", 16);         // 💀 + replacement char run
    }

    /** Screen/cursor/title ANSI that garbles the analyst's view of the session (no host-side effect). */
    public static function ansiDisruption(): string
    {
        return "\e[2J\e[H"          // clear + home
            . "\e[?1049h"           // switch to alternate screen buffer
            . "\e[?25l"             // hide cursor
            . str_repeat("\e]0;" . str_repeat('X', 200) . "\x07", 4) // title storm
            . "\e[8;1;1t";          // ask to resize window to 1x1
    }

    /**
     * Extract a clipboard value from an OSC-52 reply on the inbound stream. A capable terminal answers
     * the read query with `\e]52;c;<base64>` terminated by BEL or ST. Returns the decoded text (capped),
     * or null when there is no reply or it is just the query echo. Never throws.
     *
     * @return string|null decoded clipboard text (<= 4096 bytes), or null
     */
    public static function parseClipboard(string $inbound): ?string
    {
        if (!preg_match('/\x1b\]52;[cpqs01234567]*;([A-Za-z0-9+\/=]+)(?:\x07|\x1b\\\\)/', $inbound, $m)) {
            return null;
        }
        $b64 = $m[1];
        if ($b64 === '?' || $b64 === '') {
            return null; // the query itself, not a value
        }
        $decoded = base64_decode($b64, true);
        if ($decoded === false || $decoded === '') {
            return null;
        }

        return substr($decoded, 0, 4096);
    }
}
