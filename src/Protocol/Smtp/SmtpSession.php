<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Smtp;

/**
 * Stateful SMTP conversation for one connection. Replaces the bare prefix-matcher that treated
 * every inbound line as a command: after `DATA` a real server collects body lines until a lone
 * `.`, and the old stateless rules answered each body line with "502 command not recognized" —
 * a protocol violation an MTA probe reads as an obvious tell. This engine runs the real
 * greeting -> MAIL -> RCPT -> DATA -> queued state machine, harvests AUTH credentials, and
 * captures the message envelope and body. It NEVER stores or relays real mail (no open relay)
 * and NEVER executes anything — it only produces canned, protocol-correct replies.
 *
 * STARTTLS is deliberately NOT advertised in the EHLO capability list: we answer in plaintext so
 * a scanner's AUTH credentials are harvested in the clear, and we cannot service a real TLS
 * handshake (the client would switch to TLS bytes we'd answer with garbage — itself a tell).
 *
 * Pure and self-contained (no renderer, no I/O): feed() takes one line (CRLF already stripped by
 * the line codec) and returns the bytes to write back. All state lives on this object, so the
 * emulator holds one per connection and the whole machine is unit-testable without a socket.
 */
final class SmtpSession
{
    /** Conversation phases. DATA = collecting body lines until a lone dot. */
    private const P_GREET = 'greet';   // connected, no HELO/EHLO yet
    private const P_READY = 'ready';   // greeted, awaiting MAIL
    private const P_MAIL = 'mail';     // have MAIL FROM, awaiting RCPT
    private const P_RCPT = 'rcpt';     // have >=1 RCPT, awaiting more RCPT or DATA
    private const P_DATA = 'data';     // collecting the message body

    /** AUTH sub-dialogue (a line is a credential token, not a command, while set). */
    private const A_NONE = 'none';
    private const A_LOGIN_USER = 'login_user';
    private const A_LOGIN_PASS = 'login_pass';
    private const A_PLAIN = 'plain';

    // Bounds — a hostile client must not grow memory or loop us. The emulator also caps total
    // requests and raw buffer; these cap what this engine itself retains.
    private const MAX_RCPT = 100;            // recipients per message before 452
    // Message ceiling == the SIZE value advertised in EHLO, so a message under the advertised
    // limit is never rejected (a contradiction a scanner reads as a tell). Only MAX_BODY_KEEP of
    // it is ever retained in memory, so the 10 MB ceiling costs no memory.
    private const MAX_BODY_BYTES = 10240000; // == EHLO "SIZE 10240000"; past it -> 552 + close
    private const MAX_BODY_KEEP = 65536;     // bytes of body actually retained for intel
    private const MAX_FIELD_KEEP = 512;      // cap on a retained address / credential string
    private const MAX_MESSAGES = 10;         // completed messages retained per connection
    private const MAX_AUTH = 50;             // harvested auth attempts retained per connection

    private string $phase = self::P_GREET;
    private string $authStage = self::A_NONE;
    private bool $closed = false;

    private string $helo = '';
    private string $mailFrom = '';
    /** @var string[] */
    private array $rcptTo = [];
    private string $body = '';
    private int $bodyBytes = 0;

    private string $pendingAuthUser = '';

    /** @var array<int,array{user:string,pass:string,mechanism:string}> */
    private array $authAttempts = [];
    /** @var array<int,array{from:string,rcpt:string[],bytes:int,body:string}> */
    private array $messages = [];

    /** One-shot intel lines produced by the last feed(): decoded creds, completed messages. */
    /** @var string[] */
    private array $intel = [];

    private int $msgCounter = 0;

    public function __construct(
        private int $seed = 0,
        private string $host = 'mail.example.com',
        // Per-connection nonce folded into the queue id so two connections from the same source
        // (whose $seed is identical) never produce the same id — no real MTA reuses a queue id.
        // Defaults to '' for deterministic unit tests; the emulator injects a random value.
        private string $nonce = ''
    ) {
    }

    /** True while collecting a DATA body (so the caller need not count body lines as commands). */
    public function inData(): bool
    {
        return $this->phase === self::P_DATA;
    }

    /** Bytes to send the instant the connection opens. */
    public function banner(): string
    {
        return '220 ' . $this->host . ' ESMTP Postfix (Ubuntu)' . "\r\n";
    }

    public function closed(): bool
    {
        return $this->closed;
    }

    /**
     * Feed one inbound line (without its CRLF) and return the reply bytes (may be '').
     * In DATA phase the line is body, not a command; otherwise it is a command or, during an
     * AUTH exchange, a base64 credential token.
     */
    public function feed(string $line): string
    {
        $this->intel = [];

        if ($this->phase === self::P_DATA) {
            return $this->collectData($line);
        }
        if ($this->authStage !== self::A_NONE) {
            return $this->collectAuth($line);
        }

        return $this->command($line);
    }

    /** Return and clear the intel lines produced by the last feed(). */
    /** @return string[] */
    public function drainIntel(): array
    {
        $out = $this->intel;
        $this->intel = [];

        return $out;
    }

    /** @return array<int,array{user:string,pass:string,mechanism:string}> */
    public function authAttempts(): array
    {
        return $this->authAttempts;
    }

    /** @return array<int,array{from:string,rcpt:string[],bytes:int,body:string}> */
    public function messages(): array
    {
        return $this->messages;
    }

    private function command(string $line): string
    {
        $trimmed = rtrim($line, "\r\n");
        if ($trimmed === '') {
            return '500 5.5.2 Error: bad syntax' . "\r\n";
        }

        // Verb is the first token, case-insensitive. The remainder (args) keeps its original case.
        $sp = strpos($trimmed, ' ');
        $verb = strtoupper($sp === false ? $trimmed : substr($trimmed, 0, $sp));
        $args = $sp === false ? '' : trim(substr($trimmed, $sp + 1));

        switch ($verb) {
            case 'HELO':
                if ($args === '') {
                    return '501 Syntax: HELO hostname' . "\r\n";
                }
                $this->helo = $args;
                $this->resetTransaction();
                $this->phase = self::P_READY;

                return '250 ' . $this->host . "\r\n";

            case 'EHLO':
                if ($args === '') {
                    return '501 Syntax: EHLO hostname' . "\r\n";
                }
                $this->helo = $args;
                $this->resetTransaction();
                $this->phase = self::P_READY;

                return $this->ehlo();

            case 'MAIL':
                if ($this->phase === self::P_GREET) {
                    return '503 5.5.1 Error: send HELO/EHLO first' . "\r\n";
                }
                if ($this->phase === self::P_MAIL || $this->phase === self::P_RCPT) {
                    return '503 5.5.1 Error: nested MAIL command' . "\r\n";
                }
                if (stripos($args, 'FROM:') !== 0) {
                    return '501 5.5.4 Syntax: MAIL FROM:<address>' . "\r\n";
                }
                $this->resetTransaction();
                $this->mailFrom = $this->addr(substr($args, 5));
                $this->phase = self::P_MAIL;

                return '250 2.1.0 Ok' . "\r\n";

            case 'RCPT':
                if ($this->phase !== self::P_MAIL && $this->phase !== self::P_RCPT) {
                    return '503 5.5.1 Error: need MAIL command' . "\r\n";
                }
                if (stripos($args, 'TO:') !== 0) {
                    return '501 5.5.4 Syntax: RCPT TO:<address>' . "\r\n";
                }
                if (count($this->rcptTo) >= self::MAX_RCPT) {
                    return '452 4.5.3 Error: too many recipients' . "\r\n";
                }
                $this->rcptTo[] = $this->addr(substr($args, 3));
                $this->phase = self::P_RCPT;

                return '250 2.1.5 Ok' . "\r\n";

            case 'DATA':
                if ($this->phase !== self::P_RCPT) {
                    return '503 5.5.1 Error: need RCPT command' . "\r\n";
                }
                $this->phase = self::P_DATA;
                $this->body = '';
                $this->bodyBytes = 0;

                return '354 End data with <CR><LF>.<CR><LF>' . "\r\n";

            case 'AUTH':
                return $this->beginAuth($args);

            case 'RSET':
                $this->resetTransaction();
                $this->phase = $this->phase === self::P_GREET ? self::P_GREET : self::P_READY;

                return '250 2.0.0 Ok' . "\r\n";

            case 'NOOP':
                return '250 2.0.0 Ok' . "\r\n";

            case 'VRFY':
                return '252 2.0.0 Cannot VRFY user, but will accept message and attempt delivery' . "\r\n";

            case 'EXPN':
                return '502 5.5.1 EXPN command is disabled' . "\r\n";

            case 'HELP':
                return '214 2.0.0 See https://www.postfix.org/' . "\r\n";

            // STARTTLS is intentionally NOT handled here: it is not advertised in EHLO, so a server
            // without TLS answers it as an unknown verb (502 via default). Answering 454 ("try
            // later") would instead confirm the verb exists — a presence tell. Falls through.

            case 'QUIT':
                $this->closed = true;

                return '221 2.0.0 Bye' . "\r\n";

            default:
                return '502 5.5.2 Error: command not recognized' . "\r\n";
        }
    }

    /** Multi-line EHLO reply: every line is `250-` except the final `250 `. STARTTLS omitted (see class doc). */
    private function ehlo(): string
    {
        $caps = [
            'PIPELINING',
            'SIZE 10240000',
            'ETRN',
            'AUTH PLAIN LOGIN',
            'AUTH=PLAIN LOGIN',
            'ENHANCEDSTATUSCODES',
            '8BITMIME',
            'DSN',
        ];
        $out = '250-' . $this->host . "\r\n";
        $last = count($caps) - 1;
        foreach ($caps as $i => $cap) {
            $out .= ($i === $last ? '250 ' : '250-') . $cap . "\r\n";
        }

        return $out;
    }

    /** Strip the `<...>` wrapper and any ESMTP params (SIZE=, BODY=) from a MAIL/RCPT address arg. */
    private function addr(string $raw): string
    {
        $raw = trim($raw);
        if (preg_match('/<([^>]*)>/', $raw, $m) === 1) {
            return $this->capField($m[1]);
        }
        // No angle brackets: take the first whitespace-delimited token (drop ESMTP params).
        $sp = strpos($raw, ' ');

        return $this->capField($sp === false ? $raw : substr($raw, 0, $sp));
    }

    /** Cap a retained address/credential string so a hostile client can't retain unbounded bytes. */
    private function capField(string $s): string
    {
        return strlen($s) > self::MAX_FIELD_KEEP ? substr($s, 0, self::MAX_FIELD_KEEP) : $s;
    }

    /** Begin an AUTH exchange. Supports inline `AUTH PLAIN <b64>`, and staged LOGIN/PLAIN. */
    private function beginAuth(string $args): string
    {
        // Postfix only offers AUTH after EHLO and not inside a mail transaction. Matching that
        // sequencing is a realism win and costs no harvest: a client that intends to authenticate
        // learns AUTH is available only from the EHLO reply, so it EHLOs first anyway.
        if ($this->phase === self::P_GREET) {
            return '503 5.5.1 Error: send HELO/EHLO first' . "\r\n";
        }
        if ($this->phase === self::P_MAIL || $this->phase === self::P_RCPT) {
            return '503 5.5.1 Error: MAIL transaction in progress' . "\r\n";
        }

        $sp = strpos($args, ' ');
        $mech = strtoupper($sp === false ? $args : substr($args, 0, $sp));
        $initial = $sp === false ? '' : trim(substr($args, $sp + 1));

        if ($mech === 'LOGIN') {
            $this->authStage = self::A_LOGIN_USER;

            return '334 VXNlcm5hbWU6' . "\r\n"; // base64("Username:")
        }
        if ($mech === 'PLAIN') {
            if ($initial !== '') {
                return $this->finishPlain($initial);
            }
            $this->authStage = self::A_PLAIN;

            return '334 ' . "\r\n"; // empty challenge; client sends base64(\0user\0pass)
        }

        return '504 5.5.4 Unrecognized authentication type' . "\r\n";
    }

    /** A line arriving mid-AUTH is a base64 credential token, never a command. */
    private function collectAuth(string $line): string
    {
        $token = rtrim($line, "\r\n");

        // RFC 4954: a client may abort the exchange with a single '*'.
        if ($token === '*') {
            $this->authStage = self::A_NONE;
            $this->pendingAuthUser = '';

            return '501 5.5.0 Authentication aborted' . "\r\n";
        }

        switch ($this->authStage) {
            case self::A_LOGIN_USER:
                $this->pendingAuthUser = $this->b64($token);
                $this->authStage = self::A_LOGIN_PASS;

                return '334 UGFzc3dvcmQ6' . "\r\n"; // base64("Password:")

            case self::A_LOGIN_PASS:
                $pass = $this->b64($token);
                $this->authStage = self::A_NONE;
                $this->recordAuth($this->pendingAuthUser, $pass, 'LOGIN');
                $this->pendingAuthUser = '';

                return '535 5.7.8 Error: authentication failed: authentication failure' . "\r\n";

            case self::A_PLAIN:
            default:
                $this->authStage = self::A_NONE;

                return $this->finishPlain($token);
        }
    }

    /** Decode a SASL PLAIN token (authzid\0authcid\0passwd), record it, and reject. */
    private function finishPlain(string $token): string
    {
        $decoded = $this->b64($token);
        $parts = explode("\0", $decoded);
        // authzid may be empty: [authzid, authcid, passwd]; fall back gracefully if malformed.
        $user = $parts[1] ?? ($parts[0] ?? '');
        $pass = $parts[2] ?? '';
        $this->recordAuth($user, $pass, 'PLAIN');

        return '535 5.7.8 Error: authentication failed: authentication failure' . "\r\n";
    }

    private function recordAuth(string $user, string $pass, string $mechanism): void
    {
        $user = $this->capField($user);
        $pass = $this->capField($pass);
        if (count($this->authAttempts) < self::MAX_AUTH) {
            $this->authAttempts[] = ['user' => $user, 'pass' => $pass, 'mechanism' => $mechanism];
        }
        $this->intel[] = 'smtp-auth ' . $mechanism . ' user=' . $this->oneLine($user) . ' pass=' . $this->oneLine($pass);
    }

    /** Collect one body line in DATA phase; a lone `.` ends the message. */
    private function collectData(string $line): string
    {
        $line = rtrim($line, "\r\n");

        if ($line === '.') {
            return $this->finishMessage();
        }

        // RFC 5321 dot-stuffing transparency: a line starting with '.' has one leading dot removed.
        if ($line !== '' && $line[0] === '.') {
            $line = substr($line, 1);
        }

        $this->bodyBytes += strlen($line) + 2; // + CRLF
        if ($this->bodyBytes > self::MAX_BODY_BYTES) {
            // Past the advertised SIZE: refuse and drop the connection. Doing it here (not after the
            // terminating dot) bounds a body that never sends a dot — the caller stops counting body
            // lines as commands, so this is the backstop against an endless no-dot DATA flood.
            $this->resetTransaction();
            $this->phase = self::P_READY;
            $this->closed = true;

            return '552 5.3.4 Error: message too big for system' . "\r\n";
        }
        if (strlen($this->body) < self::MAX_BODY_KEEP) {
            $this->body .= $line . "\r\n";
        }

        return ''; // a server sends nothing until the terminating dot
    }

    private function finishMessage(): string
    {
        $from = $this->mailFrom;
        $rcpt = $this->rcptTo;
        $bytes = $this->bodyBytes;
        $body = $this->body;

        $this->resetTransaction();
        $this->phase = self::P_READY;

        $id = $this->queueId();
        if (count($this->messages) < self::MAX_MESSAGES) {
            $this->messages[] = ['from' => $from, 'rcpt' => $rcpt, 'bytes' => $bytes, 'body' => $body];
        }
        $this->intel[] = 'smtp-mail from=' . $this->oneLine($from)
            . ' to=' . $this->oneLine(implode(',', $rcpt)) . ' bytes=' . $bytes . ' queued=' . $id;

        return '250 2.0.0 Ok: queued as ' . $id . "\r\n";
    }

    private function resetTransaction(): void
    {
        $this->mailFrom = '';
        $this->rcptTo = [];
        $this->body = '';
        $this->bodyBytes = 0;
    }

    /** Postfix-style long queue id. Varies per message (counter) and per connection (nonce), so no
     *  two connections — even from one source IP, whose $seed is identical — ever collide. */
    private function queueId(): string
    {
        $this->msgCounter++;
        $alphabet = '0123456789ABCDFGHJKLMNPQRSTVWXYZ';
        $h = hash('sha256', $this->seed . '|' . $this->nonce . '|smtp-queue|' . $this->msgCounter);
        $out = '4'; // Postfix long queue ids commonly begin with the epoch-base radix digit
        for ($i = 0; $i < 10; $i++) {
            $out .= $alphabet[hexdec($h[$i * 2] . $h[$i * 2 + 1]) % strlen($alphabet)];
        }

        return $out;
    }

    private function b64(string $token): string
    {
        $d = base64_decode(trim($token), true);

        return $d === false ? $token : $d;
    }

    /** Collapse control bytes so a harvested value is one safe log line. */
    private function oneLine(string $s): string
    {
        $s = preg_replace('/[\x00-\x1f\x7f]+/', ' ', $s) ?? '';

        return trim($s);
    }
}
