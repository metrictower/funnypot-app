<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Zero-dependency, single-process TCP server for the low-interaction MSSQL honeypot (port 1433).
 * Speaks just enough of the Tabular Data Stream protocol (MS-TDS) in pure PHP to fingerprint
 * scanners and harvest the SQL Server credentials they offer, on a non-blocking stream_select loop.
 *
 * Deliberately inert: it opens no database, runs no query, and never grants a session. The exchange
 * runs PRELOGIN -> answer advertising ENCRYPT_NOT_SUP -> capture LOGIN7 -> deny with an ERROR token,
 * and stops there.
 *
 * Captured:
 * - the client's offered encryption + version from the PRELOGIN (recon fingerprint of the tool)
 * - the LOGIN7 credential: username and the de-obfuscated password, plus the hostname, application
 *   name, client library name and database the tool announced
 *
 * The TDS password is only obfuscated, not encrypted: each byte is swap-nibbles(b) XOR 0xA5, which
 * this engine reverses to recover the cleartext. Advertising ENCRYPT_NOT_SUP is what makes a
 * standard client send that obfuscated-but-cleartext LOGIN7 rather than wrapping it in TLS.
 *
 * Frame: every TDS message carries an 8-byte header { type(1), status(1), length(2 big-endian,
 * counting the header), spid(2), packetId(1), window(1) }.
 */
final class MssqlServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const INBUF_CAP = 65536; // a PRELOGIN + LOGIN7 exchange is far smaller

    // TDS packet header types (MS-TDS 2.2.3.1.1).
    private const TDS_LOGIN7 = 0x10;   // client LOGIN7 request
    private const TDS_PRELOGIN = 0x12; // client PRELOGIN request
    private const TDS_RESPONSE = 0x04; // server table response (used for our PRELOGIN + login replies)

    private const TDS_HEADER_LEN = 8;
    private const STATUS_EOM = 0x01; // end-of-message

    // PRELOGIN option tokens (MS-TDS 2.2.6.5).
    private const PL_VERSION = 0x00;
    private const PL_ENCRYPTION = 0x01;
    private const PL_INSTOPT = 0x02;
    private const PL_THREADID = 0x03;
    private const PL_MARS = 0x04;
    private const PL_TERMINATOR = 0xFF;

    // PRELOGIN encryption option values (MS-TDS 2.2.6.5). NOT_SUP keeps the client in the clear.
    private const ENCRYPT_OFF = 0x00;
    private const ENCRYPT_ON = 0x01;
    private const ENCRYPT_NOT_SUP = 0x02;
    private const ENCRYPT_REQ = 0x03;

    // TDS response tokens (MS-TDS 2.2.7).
    private const TOKEN_ERROR = 0xAA;
    private const TOKEN_DONE = 0xFD;
    private const DONE_ERROR = 0x0002;

    // Login-failed error number a real SQL Server returns.
    private const ERR_LOGIN_FAILED = 18456;

    // LOGIN7 offset-table field positions (MS-TDS 2.2.6.4). Each entry is a USHORT offset (from the
    // start of the LOGIN7 record) followed by a USHORT length in UTF-16 characters. The fixed part
    // ahead of the table is 36 bytes.
    private const OFF_HOSTNAME = 36;
    private const OFF_USERNAME = 40;
    private const OFF_PASSWORD = 44;
    private const OFF_APPNAME = 48;
    private const OFF_SERVERNAME = 52;
    private const OFF_CLTINTNAME = 60; // client interface / library name
    private const OFF_DATABASE = 68;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private MssqlConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:1433").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-mssql: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-mssql ({$this->config->serverName}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:MssqlSession,ip:string}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['session']->outbuf !== '') {
                    $write[] = $c['sock'];
                }
            }
            $except = [];

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }

            $now = time();

            // Accept new connections and drain readable sockets.
            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $port, $now);
                    continue;
                }

                $id = get_resource_id($r);
                if (!isset($conns[$id])) {
                    continue;
                }

                $session = $conns[$id]['session'];
                $data = @fread($r, self::READ_CHUNK);

                if ($data === false || ($data === '' && feof($r))) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($data === '') {
                    continue;
                }

                $session->lastActiveTime = $now;
                $session->inbuf .= $data;

                // Protect against inbound buffer exhaustion — the exchange is tiny.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Fault isolation: a malformed packet must close only this connection, never escape
                // the loop and crash the listener (degrade, never crash).
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'] ?? '', $e);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($session->close) {
                    // Deliver any queued denial/response best-effort before dropping the socket.
                    if ($session->outbuf !== '') {
                        @fwrite($r, $session->outbuf);
                        $session->outbuf = '';
                    }
                    $this->close($conns, $perIp, $id);
                    continue;
                }
            }

            // Flush outbound buffers.
            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (!isset($conns[$id])) {
                    continue;
                }
                $session = $conns[$id]['session'];
                if ($session->outbuf === '') {
                    continue;
                }

                $written = @fwrite($w, $session->outbuf);
                if ($written === false) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $session->outbuf = substr($session->outbuf, $written);
            }

            // Idle reaping.
            foreach ($conns as $id => $c) {
                if ($now - $c['session']->lastActiveTime > self::IDLE_TIMEOUT) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);

        $name = (string) @stream_socket_get_name($sock, true);
        $ip = ($colon = strrpos($name, ':')) !== false ? substr($name, 0, $colon) : $name;
        $clientPort = ($colon !== false) ? (int) substr($name, $colon + 1) : 0;

        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }

        $id = get_resource_id($sock);
        $session = new MssqlSession($ip, $clientPort, $id);
        // The client speaks first in TDS (PRELOGIN), so nothing is queued on connect.

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "MSSQL connection from {$ip}:{$clientPort}",
        ]);
    }

    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $ip = $conns[$id]['ip'];
        @fclose($conns[$id]['sock']);
        unset($conns[$id]);

        if (isset($perIp[$ip])) {
            $perIp[$ip]--;
            if ($perIp[$ip] <= 0) {
                unset($perIp[$ip]);
            }
        }
    }

    /**
     * Frames the inbound stream into TDS packets by their 8-byte header and dispatches each one.
     * Incomplete trailing bytes are left in inbuf until the rest arrives. Safe to drive directly
     * with raw bytes in tests.
     */
    public function processInbound(MssqlSession $s): void
    {
        while (true) {
            if ($s->state === MssqlSession::STATE_DONE) {
                return;
            }
            if (strlen($s->inbuf) < self::TDS_HEADER_LEN) {
                return; // need a full TDS header first
            }

            $type = ord($s->inbuf[0]);
            $len = (ord($s->inbuf[2]) << 8) | ord($s->inbuf[3]); // big-endian, counts the header

            if ($len < self::TDS_HEADER_LEN || $len > self::INBUF_CAP) {
                $this->logUnknown($s, "bad TDS packet length {$len}");
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < $len) {
                return; // wait for the rest of this packet
            }

            $packet = substr($s->inbuf, 0, $len);
            $s->inbuf = substr($s->inbuf, $len);
            $body = substr($packet, self::TDS_HEADER_LEN);

            $this->dispatch($s, $type, $body);
            if ($s->close || $s->state === MssqlSession::STATE_DONE) {
                return;
            }
        }
    }

    private function dispatch(MssqlSession $s, int $type, string $body): void
    {
        switch ($type) {
            case self::TDS_PRELOGIN:
                $this->handlePrelogin($s, $body);
                break;

            case self::TDS_LOGIN7:
                $this->handleLogin7($s, $body);
                break;

            default:
                // A TLS ClientHello (0x16) from a client that insists on encryption, a SQL batch, or
                // junk — nothing to model. Record it and drop cleanly, never crash.
                $this->logUnknown($s, sprintf('unmodelled TDS packet type 0x%02X', $type));
                $s->close = true;
        }
    }

    /**
     * PRELOGIN: log the client's offered encryption/version, then answer with a PRELOGIN response
     * advertising our version and ENCRYPT_NOT_SUP so the client proceeds unencrypted to LOGIN7.
     */
    private function handlePrelogin(MssqlSession $s, string $body): void
    {
        $parsed = self::parsePrelogin($body);

        $this->logEvent([
            'event' => 'mssql_prelogin',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'MSSQL PRELOGIN client-encryption=%s -> advertised %s, ENCRYPT_NOT_SUP',
                self::encryptionName($parsed['encryption']),
                $this->config->versionString()
            ),
        ]);

        $s->outbuf .= $this->buildPreloginResponse();
        $s->state = MssqlSession::STATE_LOGIN;
    }

    /**
     * Parses the PRELOGIN option-token list for recon. Returns the offered encryption byte (or null)
     * and the list of option tokens the client sent.
     *
     * @return array{encryption:?int,options:list<int>}
     */
    public static function parsePrelogin(string $body): array
    {
        $encryption = null;
        $options = [];

        $p = 0;
        while ($p < strlen($body)) {
            $token = ord($body[$p]);
            if ($token === self::PL_TERMINATOR) {
                break;
            }
            if ($p + 5 > strlen($body)) {
                break; // truncated token entry
            }
            $offset = (ord($body[$p + 1]) << 8) | ord($body[$p + 2]);
            $length = (ord($body[$p + 3]) << 8) | ord($body[$p + 4]);
            $options[] = $token;

            if ($token === self::PL_ENCRYPTION && $length >= 1 && $offset < strlen($body)) {
                $encryption = ord($body[$offset]);
            }
            $p += 5;
        }

        return ['encryption' => $encryption, 'options' => $options];
    }

    /**
     * Builds the PRELOGIN response: an option-token list (VERSION, ENCRYPTION, INSTOPT, THREADID,
     * MARS) followed by its data, wrapped in a server response packet. ENCRYPTION is ENCRYPT_NOT_SUP
     * so a standard client sends its LOGIN7 in the clear.
     */
    public function buildPreloginResponse(): string
    {
        $version = $this->config->versionData(); // 6 bytes

        // Five option-token entries (5 bytes each) + the 1-byte terminator = 26 bytes; the referenced
        // data follows, so the first data offset is 26.
        $entries = [
            [self::PL_VERSION, $version],
            [self::PL_ENCRYPTION, chr(self::ENCRYPT_NOT_SUP)],
            [self::PL_INSTOPT, "\x00"],          // instance validation succeeded
            [self::PL_THREADID, "\x00\x00\x00\x00"],
            [self::PL_MARS, "\x00"],             // MARS off
        ];

        $offset = count($entries) * 5 + 1;
        $tokens = '';
        $data = '';
        foreach ($entries as [$token, $payload]) {
            $tokens .= chr($token) . pack('n', $offset) . pack('n', strlen($payload));
            $data .= $payload;
            $offset += strlen($payload);
        }
        $tokens .= chr(self::PL_TERMINATOR);

        return $this->tdsPacket(self::TDS_RESPONSE, $tokens . $data);
    }

    /**
     * LOGIN7: parse the offset table, de-obfuscate the password, log the captured credential, then
     * deny the logon with an ERROR token. A session is never granted.
     */
    private function handleLogin7(MssqlSession $s, string $body): void
    {
        $s->hostname = self::decodeUtf16le(self::loginField($body, self::OFF_HOSTNAME));
        $s->username = self::decodeUtf16le(self::loginField($body, self::OFF_USERNAME));
        $s->password = self::decodePassword(self::loginField($body, self::OFF_PASSWORD));
        $s->appName = self::decodeUtf16le(self::loginField($body, self::OFF_APPNAME));
        $s->libName = self::decodeUtf16le(self::loginField($body, self::OFF_CLTINTNAME));
        $s->database = self::decodeUtf16le(self::loginField($body, self::OFF_DATABASE));

        $user = self::printable($s->username);

        $this->logEvent([
            'event' => 'mssql_login',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'critical',
            'path' => sprintf(
                'MSSQL login attempt: user=%s host=%s app=%s lib=%s password=%s',
                $user,
                self::printable($s->hostname),
                self::printable($s->appName),
                self::printable($s->libName),
                self::printable($s->password)
            ),
            'user' => $user,
            'password' => self::printable($s->password),
            'hostname' => self::printable($s->hostname),
            'app' => self::printable($s->appName),
            'library' => self::printable($s->libName),
            'database' => self::printable($s->database),
            'body' => sprintf(
                'user=%s password=%s host=%s app=%s lib=%s db=%s',
                $user,
                self::printable($s->password),
                self::printable($s->hostname),
                self::printable($s->appName),
                self::printable($s->libName),
                self::printable($s->database)
            ),
        ]);

        // Deny — a login is never accepted. Queue the ERROR token; the run loop flushes it before
        // the socket is dropped.
        $s->outbuf .= $this->buildLoginError($user);
        $s->state = MssqlSession::STATE_DONE;
        $s->close = true;
    }

    /**
     * Reads one LOGIN7 offset-table string field: a USHORT offset at $tablePos (from the start of the
     * record) and a USHORT length in UTF-16 characters at $tablePos+2. Returns the raw UTF-16LE bytes,
     * or '' if the descriptor points outside the record.
     */
    public static function loginField(string $body, int $tablePos): string
    {
        if ($tablePos + 4 > strlen($body)) {
            return '';
        }
        $offset = self::le16($body, $tablePos);
        $chars = self::le16($body, $tablePos + 2);
        $bytes = $chars * 2;
        if ($chars === 0 || $offset + $bytes > strlen($body)) {
            return '';
        }

        return substr($body, $offset, $bytes);
    }

    /**
     * Reverses the TDS password obfuscation (MS-TDS 2.2.6.4): each byte is XORed with 0xA5 and its
     * nibbles swapped, then the recovered UTF-16LE bytes are decoded to UTF-8. Not encryption —
     * merely a reversible scramble, which is the whole reason the cleartext is recoverable.
     */
    public static function decodePassword(string $raw): string
    {
        $out = '';
        $len = strlen($raw);
        for ($i = 0; $i < $len; $i++) {
            $b = ord($raw[$i]) ^ 0xA5;
            $b = (($b & 0x0F) << 4) | (($b & 0xF0) >> 4);
            $out .= chr($b);
        }

        return self::decodeUtf16le($out);
    }

    // ---- Response builders -------------------------------------------------------------------

    /**
     * Builds a TDS ERROR token (login failed for the given user) followed by a DONE token, wrapped in
     * a server response packet. This is the honeypot's only reply to a login: it never authenticates.
     */
    public function buildLoginError(string $user): string
    {
        $msg = "Login failed for user '{$user}'.";
        $msgU = self::utf16le($msg);
        $serverU = self::utf16le($this->config->serverName);

        // ERROR token data (MS-TDS 2.2.7.10): Number, State, Class, MsgText (US_VARCHAR),
        // ServerName (B_VARCHAR), ProcName (B_VARCHAR), LineNumber (LONG for TDS 7.2+).
        $tokenData = pack('V', self::ERR_LOGIN_FAILED)             // Number
            . chr(1)                                              // State
            . chr(14)                                             // Class (severity)
            . pack('v', self::charLen($msg)) . $msgU              // MsgText US_VARCHAR (char count LE)
            . chr(self::charLen($this->config->serverName)) . $serverU // ServerName B_VARCHAR
            . chr(0)                                              // ProcName B_VARCHAR (empty)
            . pack('V', 1);                                       // LineNumber

        $error = chr(self::TOKEN_ERROR) . pack('v', strlen($tokenData)) . $tokenData;

        // DONE token (MS-TDS 2.2.7.6): Status, CurCmd, DoneRowCount (ULONGLONG for TDS 7.2+).
        $done = chr(self::TOKEN_DONE)
            . pack('v', self::DONE_ERROR)
            . pack('v', 0)
            . pack('P', 0);

        return $this->tdsPacket(self::TDS_RESPONSE, $error . $done);
    }

    /**
     * Wraps a body in the 8-byte TDS packet header (MS-TDS 2.2.3.1): type, status EOM, length
     * (big-endian, counting the header), spid 0, packetId 1, window 0.
     */
    public function tdsPacket(int $type, string $body): string
    {
        $len = strlen($body) + self::TDS_HEADER_LEN;

        return chr($type)
            . chr(self::STATUS_EOM)
            . pack('n', $len)
            . pack('n', 0)   // SPID
            . chr(1)         // PacketID
            . chr(0)         // Window
            . $body;
    }

    // ---- Field / string helpers --------------------------------------------------------------

    public static function encryptionName(?int $value): string
    {
        return match ($value) {
            null => 'none',
            self::ENCRYPT_OFF => 'ENCRYPT_OFF',
            self::ENCRYPT_ON => 'ENCRYPT_ON',
            self::ENCRYPT_NOT_SUP => 'ENCRYPT_NOT_SUP',
            self::ENCRYPT_REQ => 'ENCRYPT_REQ',
            default => sprintf('unknown(0x%02X)', $value),
        };
    }

    /** UTF-16 character count for an ASCII string (persona/message text is ASCII). */
    private static function charLen(string $s): int
    {
        return strlen($s);
    }

    /**
     * Interleaves an ASCII string to UTF-16LE for our own output. Persona / message text is ASCII,
     * so a null-interleave is sufficient and keeps the emulator free of an mbstring dependency.
     */
    private static function utf16le(string $s): string
    {
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $out .= $s[$i] . "\x00";
        }

        return $out;
    }

    /**
     * Decodes UTF-16LE to UTF-8, falling back to a BMP-only decoder when mbstring is unavailable so
     * the engine keeps no hard extension dependency.
     */
    private static function decodeUtf16le(string $b): string
    {
        if ($b === '') {
            return '';
        }
        if (function_exists('mb_convert_encoding')) {
            return (string) @mb_convert_encoding($b, 'UTF-8', 'UTF-16LE');
        }

        $out = '';
        $len = strlen($b) - (strlen($b) % 2);
        for ($i = 0; $i < $len; $i += 2) {
            $cp = ord($b[$i]) | (ord($b[$i + 1]) << 8);
            if ($cp < 0x80) {
                $out .= chr($cp);
            } elseif ($cp < 0x800) {
                $out .= chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
            } else {
                $out .= chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
            }
        }

        return $out;
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(?string $s): string
    {
        if ($s === null) {
            return '';
        }

        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private static function le16(string $b, int $off): int
    {
        return ord($b[$off]) | (ord($b[$off + 1]) << 8);
    }

    private function logUnknown(MssqlSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'mssql_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'MSSQL unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'MSSQL';
        $entry['proto'] = 'mssql';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        ($this->logger)($entry);
    }

    /** Records a per-connection fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => 1433,
                'path' => 'MSSQL internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 1433;
    }
}
