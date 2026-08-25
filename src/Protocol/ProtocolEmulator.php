<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

use Funnypot\Protocol\Shell\FakeShell;
use Funnypot\Template\DirectiveRenderer;

/**
 * Interprets one compiled protocol against a connection's bytes: send the banner on connect,
 * then for each framed request, first-match-wins over the rule list → render the reply through
 * the bounded DirectiveRenderer → frame it via the codec. Pure lookup + template: it never
 * executes input, never reflects unbounded bytes, and caps buffer + request count per session.
 *
 * Stateless across connections (one shared emulator per protocol); per-connection state lives
 * in ProtocolSession.
 */
final class ProtocolEmulator
{
    /** Hard per-connection bounds — a hostile client can't grow memory or loop us forever. */
    private const MAX_BUFFER = 65536;
    private const MAX_REQUESTS = 500;

    private DirectiveRenderer $renderer;
    private Codec $codec;
    private ?FakeShell $shell = null;

    /** @param array<string,mixed> $protocol compiled protocol rules */
    public function __construct(
        private array $protocol,
        ?DirectiveRenderer $renderer = null,
        private ?int $identitySeed = null,
        private ?string $secret = null
    ) {
        $this->renderer = $renderer ?? new DirectiveRenderer();
        $this->codec = self::codecFor((string) ($protocol['framing'] ?? 'line'));
    }

    /** Bytes to send the moment a connection opens (before any input), or '' for silent. */
    public function banner(ProtocolSession $s): string
    {
        $banner = $this->renderer->render((string) ($this->protocol['banner'] ?? ''), [], $s->seed);
        // Interactive shell (telnet): negotiate server-side echo + character-at-a-time (IAC WILL
        // ECHO, IAC WILL SGA) so a real telnet client hands us each keystroke and we own the line
        // editing — otherwise the client's Enter (a bare CR) never terminates a line for us.
        if (isset($this->protocol['shell'])) {
            return "\xff\xfb\x01\xff\xfb\x03" . $banner;
        }

        return $banner;
    }

    /**
     * Feed inbound bytes; return the bytes to write back (may be ''). Sets $s->close when done.
     *
     * $onRequest, if given, is called once per decoded request as $onRequest(string $command,
     * string $response) — the seam the listener uses to LOG every command an attacker sends
     * (redis/ftp/smtp/ssh…) into the same hit log the dashboard shows. The emulator itself does
     * no I/O; the callback owns logging.
     */
    public function feed(string $bytes, ProtocolSession $s, ?callable $onRequest = null): string
    {
        $s->buffer .= $bytes;
        if (strlen($s->buffer) > self::MAX_BUFFER) {
            $s->buffer = '';
            $s->close = true; // drop a flooding client rather than buffer it

            return '';
        }

        // Taunt mode: once trolling, discard the attacker's keystrokes — the animation streams
        // from the listener loop's frame timer, not in response to input.
        if ($s->trolling) {
            $s->buffer = '';

            return '';
        }

        // A shell protocol (telnet) is character-interactive: strip telnet IAC, edit the line, and
        // echo — not the line-codec request/response loop the data protocols use.
        if (isset($this->protocol['shell'])) {
            return $this->interactiveFeed($s, $onRequest);
        }

        $out = '';
        foreach ($this->codec->extract($s->buffer) as $request) {
            $s->requests++;
            $response = $this->respond($request, $s);
            $out .= $response;
            if ($onRequest !== null) {
                $onRequest($request, $response);
            }
            if ($s->close || $s->requests >= self::MAX_REQUESTS) {
                $s->close = true;
                break;
            }
        }

        return $out;
    }

    /** Whether this session is streaming the taunt animation (drives the loop's frame timer). */
    public function isTrolling(ProtocolSession $s): bool
    {
        return $s->trolling && !$s->close;
    }

    /** The next troll frame for a session (the listener loop calls this on a timer). */
    public function trollFrame(ProtocolSession $s): string
    {
        return TrollStream::frame($s->trollFrame++);
    }

    private function respond(string $request, ProtocolSession $s): string
    {
        foreach ((array) ($this->protocol['rules'] ?? []) as $rule) {
            $caps = $this->match((array) ($rule['match'] ?? []), $request);
            if ($caps !== null) {
                if (!empty($rule['close'])) {
                    $s->close = true;
                }

                return $this->codec->wrap($this->renderSend($rule['send'] ?? '', $caps, $s->seed));
            }
        }

        $default = $this->protocol['default']['send'] ?? null;

        return $default === null ? '' : $this->codec->wrap($this->renderSend($default, [], $s->seed));
    }

    /**
     * Character-interactive shell (telnet): consume the raw byte buffer, stripping telnet IAC
     * negotiation, echoing input, and editing a line until Enter — then run the completed line
     * through the login -> password -> shell state machine. A real telnet client sends each
     * keystroke and terminates a line with a bare CR (\r), which the line codec never saw; this
     * handles CR / CRLF / LF alike, plus backspace and Ctrl-C/D. Passwords are not echoed. Every
     * completed line (creds + commands) is logged via $onRequest; the shell never executes input.
     */
    private function interactiveFeed(ProtocolSession $s, ?callable $onRequest): string
    {
        $cfg = (array) $this->protocol['shell'];
        $host = (string) ($cfg['hostname'] ?? 'server');
        $buf = $s->buffer;
        $len = strlen($buf);
        $i = 0;
        $out = '';

        while ($i < $len) {
            $ch = $buf[$i];
            $b = ord($ch);

            // Telnet IAC (0xFF): consume the command/negotiation sequence, never treat it as input.
            if ($b === 0xff) {
                if ($i + 1 >= $len) {
                    break; // incomplete IAC — leave it buffered for the next chunk
                }
                $cmd = ord($buf[$i + 1]);
                if ($cmd === 0xfa) { // SB ... IAC SE subnegotiation
                    $se = strpos($buf, "\xff\xf0", $i + 2);
                    if ($se === false) {
                        break;
                    }
                    $i = $se + 2;
                    continue;
                }
                if ($cmd >= 0xfb && $cmd <= 0xfe) { // WILL/WONT/DO/DONT + option byte
                    if ($i + 2 >= $len) {
                        break;
                    }
                    $i += 3;
                    continue;
                }
                $i += 2; // 2-byte command (incl. IAC IAC → literal 0xFF, dropped as a control byte)
                continue;
            }
            $i++;

            if ($s->swallowLf) {
                $s->swallowLf = false;
                if ($ch === "\n") {
                    continue; // the LF half of a CR-LF Enter
                }
            }
            if ($ch === "\r" || $ch === "\n") {
                if ($ch === "\r") {
                    $s->swallowLf = true;
                }
                $out .= "\r\n";
                $line = $s->lineBuf;
                $s->lineBuf = '';
                $s->requests++;
                $out .= $this->shellLine($line, $s, $host, $cfg, $onRequest);
                if ($s->close || $s->requests >= self::MAX_REQUESTS) {
                    $s->close = true;
                    $s->buffer = '';

                    return $out;
                }
                continue;
            }
            if ($ch === "\x7f" || $ch === "\x08") { // backspace / DEL
                if ($s->lineBuf !== '') {
                    $s->lineBuf = substr($s->lineBuf, 0, -1);
                    if ($s->phase !== 'password') {
                        $out .= "\x08 \x08";
                    }
                }
                continue;
            }
            if ($ch === "\x03") { // Ctrl-C
                $s->lineBuf = '';
                $out .= "^C\r\n" . ($s->authed ? $this->prompt($s, $host) : '');
                continue;
            }
            if ($ch === "\x04") { // Ctrl-D on an empty line ends the session
                if ($s->lineBuf === '' && $s->authed) {
                    $s->close = true;
                    $s->buffer = '';

                    return $out . "logout\r\n";
                }
                continue;
            }
            if ($b < 0x20) {
                continue; // ignore other control bytes
            }
            if (strlen($s->lineBuf) < 4096) {
                $s->lineBuf .= $ch;
                if ($s->phase !== 'password') {
                    $out .= $ch; // local echo, except while a password is being typed
                }
            }
        }

        $s->buffer = substr($buf, $i); // keep any incomplete IAC tail for the next chunk

        return $out;
    }

    /** Run one completed shell line through the state machine and log it. */
    private function shellLine(string $line, ProtocolSession $s, string $host, array $cfg, ?callable $onRequest): string
    {
        $resp = $this->shellLineResponse($line, $s, $host, $cfg);
        if ($onRequest !== null) {
            $onRequest($line, $resp);
        }

        return $resp;
    }

    /**
     * The login -> password -> shell state machine for a completed line. Accept-all login (an
     * optional reject_attempts refuses the first few); then each command runs through FakeShell.
     *
     * @param array<string,mixed> $cfg
     */
    private function shellLineResponse(string $line, ProtocolSession $s, string $host, array $cfg): string
    {
        if (!$s->authed) {
            if ($s->phase !== 'password') {
                $s->user = ($u = trim($line)) !== '' ? $u : 'root';
                $s->phase = 'password';

                return (string) ($cfg['password_prompt'] ?? 'Password: ');
            }
            $s->authTries++;
            if ($s->authTries <= (int) ($cfg['reject_attempts'] ?? 0)) {
                $s->phase = 'login';

                return "\r\nLogin incorrect\r\n"
                    . $this->renderer->render((string) ($this->protocol['banner'] ?? ''), [], $s->seed);
            }
            $s->authed = true;
            $s->phase = 'shell';
            $s->cwd = (string) ($cfg['home'] ?? '/root');

            if (TrollStream::enabled()) {
                // Taunt mode: stream the troll animation forever instead of a shell prompt.
                $s->trolling = true;

                return TrollStream::frame($s->trollFrame++);
            }

            return (string) ($cfg['motd'] ?? "\r\nWelcome.\r\n\r\n") . $this->prompt($s, $host);
        }

        $out = $this->fakeShell()->run($line, $s);

        return $s->close ? $out : $out . $this->prompt($s, $host);
    }

    private function prompt(ProtocolSession $s, string $host): string
    {
        // The prompt host must equal the shell's hostname (uname/hostname/etc), not the protocol config.
        $host = $this->fakeShell()->host();
        $cwd = $s->cwd === '/root' ? '~' : $s->cwd;

        return $s->user . '@' . $host . ':' . $cwd . ($s->user === 'root' ? '# ' : '$ ');
    }

    private function fakeShell(): FakeShell
    {
        return $this->shell ??= new FakeShell($this->identitySeed, $this->secret);
    }

    /**
     * @param array<string,mixed> $cond
     * @return array<int|string,string>|null capture groups on match, null on no match
     */
    private function match(array $cond, string $request): ?array
    {
        if (isset($cond['equals'])) {
            return strcasecmp($request, (string) $cond['equals']) === 0 ? [] : null;
        }
        if (isset($cond['prefix'])) {
            return stripos($request, (string) $cond['prefix']) === 0 ? [] : null;
        }
        if (isset($cond['contains'])) {
            return stripos($request, (string) $cond['contains']) !== false ? [] : null;
        }
        if (isset($cond['regex'])) {
            return preg_match('~' . $cond['regex'] . '~i', $request, $m) === 1 ? $m : null;
        }

        return null;
    }

    /**
     * Render the directive markers in a send spec (string, or a codec spec whose text fields
     * carry directives). Captures come from a regex match; seed is per-attacker.
     *
     * @param string|array<string,mixed> $send
     * @param array<int|string,string>   $caps
     * @return string|array<string,mixed>
     */
    private function renderSend($send, array $caps, int $seed)
    {
        if (!is_array($send)) {
            return $this->renderer->render((string) $send, $caps, $seed);
        }
        $out = [];
        foreach ($send as $k => $v) {
            if (is_string($v)) {
                $out[$k] = $this->renderer->render($v, $caps, $seed);
            } elseif (is_array($v)) {
                $out[$k] = array_map(fn ($x) => $this->renderer->render((string) $x, $caps, $seed), $v);
            } else {
                $out[$k] = $v;
            }
        }

        return $out;
    }

    private static function codecFor(string $framing): Codec
    {
        switch ($framing) {
            case 'resp':
                return new RespCodec();
            case 'raw':
                return new RawCodec();
            case 'line':
            default:
                return new LineCodec();
        }
    }
}
