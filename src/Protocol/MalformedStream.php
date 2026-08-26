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

    /** Bright green / red / cyan on black, rotated per frame. */
    private const COLORS = ["\e[40;92m", "\e[40;91m", "\e[40;96m"];

    /** Window-resize CSI (\e[8;rows;cols t): every frame jumps between big and tiny. */
    private const RESIZE_BIG = "\e[8;50;200t";
    private const RESIZE_SMALL = "\e[8;6;20t";

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

        // Per frame: clear the screen, RESIZE the window (alternating big<->tiny every frame so it
        // constantly jumps), draw one face (alternating SKULL<->TROLL so both keep showing), then a
        // fresh malformed junk chunk. Gives the loop: resize -> SKULL -> junk -> resize -> TROLL ->
        // junk -> ... — the terminal thrashes while the stream stays invalid-UTF-8 throughout.
        $even = ($n % 2) === 0;
        $resize = $even ? self::RESIZE_BIG : self::RESIZE_SMALL;
        $art = $even ? TrollStream::TROLL : TrollStream::SKULL;
        $color = self::COLORS[$n % 3];

        $out = "\e[2J\e[H" . $resize . $color;
        foreach (explode("\n", $art) as $line) {
            $out .= $line . "\r\n";
        }
        $out .= "\e[0m" . self::junk($n);

        return $out;
    }

    /**
     * A modest, per-frame-varied malformed chunk to interleave with each SKULL/TROLL frame: invalid
     * UTF-8, embedded NULs, illegal/continuation bytes, and a slice of combining-mark churn. Varied by
     * $n so frames are not byte-identical. Bounded (~150-250 bytes) to keep the ~1/sec trickle a
     * trickle. Deterministic — no RNG.
     */
    public static function junk(int $n): string
    {
        $iu = self::invalidUtf8();
        $rot = ($n * 7) % max(1, strlen($iu));

        return substr($iu . $iu, $rot, 48)
            . str_repeat("\x00", 4 + ($n % 5))
            . "\xf5\xfe\xff" . str_repeat("\x80", 3 + ($n % 6))
            . substr(self::randomUnicode(), 0, 60 + ($n % 30))
            . "\r\n";
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
        // No alternate-screen buffer and no static 1x1 resize here — the per-frame loop does the
        // (visible, alternating) window resizing, so the burst stays on the main screen.
        return "\e[2J\e[H"          // clear + home
            . "\e[?25l"             // hide cursor
            . str_repeat("\e]0;" . str_repeat('X', 200) . "\x07", 4); // title storm (BEL-terminated)
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
