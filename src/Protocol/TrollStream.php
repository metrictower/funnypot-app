<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * The taunt-mode troll animation for the interactive socket honeypots (SSH / telnet). In taunt
 * style (FUNNYPOT_STYLE=taunt) a successful login is answered not with a shell but with an endless
 * full-screen animation: ASCII art on a black background, its colour rotating matrix-green / blue /
 * red every frame, over a fake "installing reverse shell" progress bar that fills and restarts. The
 * server loops push one frame() every tick and ignore the attacker's keystrokes, so the session is
 * a pure time-sink. Any other style shows nothing extra and the shell stays believable.
 */
final class TrollStream
{
    /** Frames per full progress-bar cycle; the art flips between the two faces each cycle. */
    private const STEPS = 24;

    /** Opening full-red "alert" screen, held this many frames (~2s at the loop's frame interval). */
    // Public so the malformed style can reuse the SKULL/TROLL animation (frames >= FLASH_FRAMES) after
    // its own opening burst, instead of duplicating the art.
    public const FLASH_FRAMES = 16;

    private const BAR_WIDTH = 32;

    /** Bright green / blue / red on a black background (matrix palette), rotated per frame. */
    private const COLORS = ["\e[40;92m", "\e[40;94m", "\e[40;91m"];

    /** Fallback if the messages file is missing/empty; the full editable list lives in the file. */
    private const DEFAULT_MESSAGES = ['installing reverse shell'];

    /** @var string[]|null memoised progress-bar labels */
    private static ?array $messages = null;

    private const SKULL = <<<'ART'
                          ud$$$**$$$$$$$bc.
                       u@**"        4$$$$$$$Nu
                     J                ""#$$$$$$r
                    @                       $$$$b
                  .F                        ^*3$$$
                 :% 4                         J$$$N
                 $  :F                       :$$$$$
                4F  9                       J$$$$$$$
                4$   k             4$$$$bed$$$$$$$$$
                $$r  'F            $$$$$$$$$$$$$$$$$r
                $$$   b.           $$$$$$$$$$$$$$$$$N
                $$$$$k 3eeed$$b    $$$Euec."$$$$$$$$$
 .@$**N.        $$$$$" $$$$$$F'L $$$$$$$$$$$  $$$$$$$
 :$$L  'L       $$$$$ 4$$$$$$  * $$$$$$$$$$F  $$$$$$F         edNc
@$$$$N  ^k      $$$$$  3$$$$*%   $F4$$$$$$$   $$$$$"        d"  z$N
$$$$$$   ^k     '$$$"   #$$$F   .$  $$$$$c.u@$$$          J"  @$$$$r
$$$$$$$b   *u    ^$L            $$  $$$$$$$$$$$$u@       $$  d$$$$$$
 ^$$$$$$.    "NL   "N. z@*     $$$  $$$$$$$$$$$$$P      $P  d$$$$$$$
    ^"*$$$$b   '*L   9$E      4$$$  d$$$$$$$$$$$"     d*   J$$$$$r
         ^$$$$u  '$.  $$$L     "#" d$$$$$$".@$$    .@$"  z$$$$*"
           ^$$$$. ^$N.3$$$       4u$$$$$$$ 4$$$  u$*" z$$$"
             '*$$$$$$$$ *$b      J$$$$$$$b u$$P $"  d$$P
                #$$$$$$ 4$ 3*$"$*$ $"$'c@@$$$$ .u@$$$P
                  "$$$$  ""F~$ $uNr$$$^&J$$$$F $$$$#
                    "$$    "$$$bd$.$W$$$$$$$$F $$"
                      ?k         ?$$$$$$$$$$$F'*
                       9$$bL     z$$$$$$$$$$$F
                        $$$$    $$$$$$$$$$$$$
                         '#$$c  '$$$$$$$$$"
                          .@"#$$$$$$$$$$$$b
                        z*      $$$$$$$$$$$$N.
                      e"      z$$"  #$$$k  '*$$.
                  .u*      u@$P"      '#$$c   "$$c
           u@$*"""       d$$"            "$$$u  ^*$$b.
         :$F           J$P"                ^$$$c   '"$$$$$$bL
        d$$  ..      @$#                      #$$b         '#$
        9$$$$$$b   4$$                          ^$$k         '$
         "$$6""$b u$$                             '$    d$$$$$P
           '$F $$$$$"                              ^b  ^$$$$b$
            '$W$$$$"                                'b@$$$$"
                                                     ^$$$*
ART;

    private const TROLL = <<<'ART'
⠀⠀⠀⠀⠀⣀⣠⠤⠶⠶⣖⡛⠛⠿⠿⠯⠭⠍⠉⣉⠛⠚⠛⠲⣄⠀⠀⠀⠀⠀
⠀⠀⢀⡴⠋⠁⠀⡉⠁⢐⣒⠒⠈⠁⠀⠀⠀⠈⠁⢂⢅⡂⠀⠀⠘⣧⠀⠀⠀⠀
⠀⠀⣼⠀⠀⠀⠁⠀⠀⠀⠂⠀⠀⠀⠀⢀⣀⣤⣤⣄⡈⠈⠀⠀⠀⠘⣇⠀⠀⠀
⢠⡾⠡⠄⠀⠀⠾⠿⠿⣷⣦⣤⠀⠀⣾⣋⡤⠿⠿⠿⠿⠆⠠⢀⣀⡒⠼⢷⣄⠀
⣿⠊⠊⠶⠶⢦⣄⡄⠀⢀⣿⠀⠀⠀⠈⠁⠀⠀⠙⠳⠦⠶⠞⢋⣍⠉⢳⡄⠈⣧
⢹⣆⡂⢀⣿⠀⠀⡀⢴⣟⠁⠀⢀⣠⣘⢳⡖⠀⠀⣀⣠⡴⠞⠋⣽⠷⢠⠇⠀⣼
⠀⢻⡀⢸⣿⣷⢦⣄⣀⣈⣳⣆⣀⣀⣤⣭⣴⠚⠛⠉⣹⣧⡴⣾⠋⠀⠀⣘⡼⠃
⠀⢸⡇⢸⣷⣿⣤⣏⣉⣙⣏⣉⣹⣁⣀⣠⣼⣶⡾⠟⢻⣇⡼⠁⠀⠀⣰⠋⠀⠀
⠀⢸⡇⠸⣿⡿⣿⢿⡿⢿⣿⠿⠿⣿⠛⠉⠉⢧⠀⣠⡴⠋⠀⠀⠀⣠⠇⠀⠀⠀
⠀⢸⠀⠀⠹⢯⣽⣆⣷⣀⣻⣀⣀⣿⣄⣤⣴⠾⢛⡉⢄⡢⢔⣠⠞⠁⠀⠀⠀⠀
⠀⢸⠀⠀⠀⠢⣀⠀⠈⠉⠉⠉⠉⣉⣀⠠⣐⠦⠑⣊⡥⠞⠋⠀⠀⠀⠀⠀⠀⠀
⠀⢸⡀⠀⠁⠂⠀⠀⠀⠀⠀⠀⠒⠈⠁⣀⡤⠞⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⠶⢤⣤⣤⣤⣤⡤⠴⠖⠚⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
ART;

    public static function enabled(): bool
    {
        return (getenv('FUNNYPOT_STYLE') ?: '') === 'taunt';
    }

    /**
     * The progress-bar labels, one per bar. Loaded once from a plain text file so they are easy to
     * edit without touching code — one message per line, blank lines and #-comments ignored. Set
     * FUNNYPOT_TROLL_MESSAGES to a file path (e.g. a mounted volume, editable live), otherwise the
     * shipped resources/troll-messages.txt is used; falls back to DEFAULT_MESSAGES if neither has a
     * usable line.
     *
     * @return string[]
     */
    private static function messages(): array
    {
        if (self::$messages !== null) {
            return self::$messages;
        }
        $path = getenv('FUNNYPOT_TROLL_MESSAGES') ?: dirname(__DIR__, 2) . '/resources/troll-messages.txt';
        $lines = is_file($path) ? (array) @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
        $out = [];
        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line !== '' && $line[0] !== '#') {
                $out[] = $line;
            }
        }

        return self::$messages = $out !== [] ? $out : self::DEFAULT_MESSAGES;
    }

    /**
     * One animation frame (a full-screen redraw), CRLF-terminated for a raw terminal. Frame N picks
     * the colour (rotates per frame), the art (flips per progress cycle) and the bar position, so
     * the caller only has to keep a monotonic counter and push frames on a timer.
     */
    public static function frame(int $n): string
    {
        // Open on a full red "alert" screen (bg red + clear fills the whole screen) for ~2s, with a
        // beep, before the animation starts.
        if ($n < self::FLASH_FRAMES) {
            $bel = $n === 0 ? "\x07\x07\x07" : '';
            return $bel . "\e[41m\e[2J\e[H\e[41;1;97m\r\n\r\n"
                   . "    ENABLE REVERSE CONNECTION  Y/N ?\r\n\r\n";

        }
        $m = $n - self::FLASH_FRAMES;                      // animation frame index (post red flash)

        $cycle = intdiv($m, self::STEPS);
        $messages = self::messages();
        $label = $messages[$cycle % count($messages)];
        $color = self::COLORS[$m % 3];
        $art = $cycle % 2 === 0 ? self::SKULL : self::TROLL;
        $pct = (int) round(($m % self::STEPS) / (self::STEPS - 1) * 100);
        $filled = (int) round($pct / 100 * self::BAR_WIDTH);
        $bar = str_repeat('#', $filled) . str_repeat('.', self::BAR_WIDTH - $filled);
        $dots = str_repeat('.', 1 + ($m % 3));
        // Beep at the top of every loop (each new bar / message) as an audible alert.
        $bel = $m % self::STEPS === 0 ? "\x07\x07" : '';

        $out = $bel . "\e[2J\e[H" . $color;                // clear screen, home cursor, colour on black
        foreach (explode("\n", $art) as $line) {
            $out .= $line . "\r\n";
        }
        $out .= "\e[40;97m\r\n";                            // white on black for the label
        $out .= $label . $dots . "\r\n";
        $out .= $color . '[' . $bar . "]\e[40;97m " . $pct . "%\e[0m\r\n";

        return $out;
    }
}
