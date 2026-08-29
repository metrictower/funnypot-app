<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Cassandra;

/**
 * Zero-dependency, single-process TCP server for the low-interaction Cassandra honeypot (port 9042).
 * Speaks just enough of the CQL native protocol (v3/v4/v5 legacy framing) in pure PHP to fingerprint
 * scanners and harvest the database credentials they offer, on a non-blocking stream_select loop.
 *
 * Deliberately inert: it opens no keyspace, runs no query, and never grants a session. The exchange
 * runs OPTIONS -> SUPPORTED (optional), STARTUP -> AUTHENTICATE naming PasswordAuthenticator, then
 * captures the AUTH_RESPONSE credential and denies it with an ERROR (bad credentials), and stops
 * there.
 *
 * Captured:
 * - the client's CQL version + driver name/version from the STARTUP options map (recon fingerprint)
 * - the AUTH_RESPONSE credential: the SASL PLAIN token is `\0username\0password`, decoded to cleartext
 *
 * Naming PasswordAuthenticator in the AUTHENTICATE reply is what makes a standard driver send that
 * cleartext credential rather than proceeding straight to READY. The whole auth handshake uses the
 * legacy (unframed) envelope even under protocol v5, so a single 9-byte-header parser captures it.
 *
 * Frame: every CQL message carries a 9-byte header { version(1), flags(1), stream(2 big-endian),
 * opcode(1), length(4 big-endian, body length) } followed by the body. The version byte's high bit
 * marks direction: clear on a request, set on our response.
 */
final class CassandraServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const INBUF_CAP = 65536; // an OPTIONS/STARTUP/AUTH_RESPONSE exchange is far smaller

    private const HEADER_LEN = 9;
    private const DIRECTION_RESPONSE = 0x80; // set in the version byte of a response
    private const FLAG_COMPRESSION = 0x01;   // frame body is compressed (we advertise none)

    // Supported protocol versions. v3+ uses the 9-byte header with a 2-byte stream id; v1/v2 used a
    // different fixed header, so they are out of scope and logged as unknown rather than misframed.
    private const MIN_PROTO = 3;
    private const MAX_PROTO = 5;

    // CQL opcodes (native protocol §2.4).
    private const OP_ERROR = 0x00;
    private const OP_STARTUP = 0x01;
    private const OP_READY = 0x02;
    private const OP_AUTHENTICATE = 0x03;
    private const OP_OPTIONS = 0x05;
    private const OP_SUPPORTED = 0x06;
    private const OP_AUTH_RESPONSE = 0x0F;

    // ERROR body codes (native protocol §9). 0x0100 = bad credentials (authentication error).
    private const ERR_BAD_CREDENTIALS = 0x0100;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private CassandraConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:9042").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-cassandra: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-cassandra ({$this->config->clusterName}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:CassandraSession,ip:string}> $conns */
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
        $session = new CassandraSession($ip, $clientPort, $id);
        // The client speaks first in CQL (OPTIONS or STARTUP), so nothing is queued on connect.

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "Cassandra connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into CQL messages by their 9-byte header and dispatches each one.
     * Incomplete trailing bytes are left in inbuf until the rest arrives. Safe to drive directly with
     * raw bytes in tests.
     */
    public function processInbound(CassandraSession $s): void
    {
        while (true) {
            if ($s->state === CassandraSession::STATE_DONE) {
                return;
            }
            if (strlen($s->inbuf) < self::HEADER_LEN) {
                return; // need a full CQL header first
            }

            $version = ord($s->inbuf[0]);
            // A request must have the direction bit clear; a set bit is a server-direction frame from
            // a client, which is malformed.
            if (($version & self::DIRECTION_RESPONSE) !== 0) {
                $this->logUnknown($s, sprintf('response-direction frame from client (0x%02X)', $version));
                $s->close = true;

                return;
            }
            $proto = $version & 0x7F;
            if ($proto < self::MIN_PROTO || $proto > self::MAX_PROTO) {
                $this->logUnknown($s, "unsupported protocol version {$proto}");
                $s->close = true;

                return;
            }

            $flags = ord($s->inbuf[1]);
            $stream = (ord($s->inbuf[2]) << 8) | ord($s->inbuf[3]); // echoed back verbatim
            $opcode = ord($s->inbuf[4]);
            $length = self::be32($s->inbuf, 5);

            if ($length > self::INBUF_CAP) {
                $this->logUnknown($s, "oversize frame length {$length}");
                $s->close = true;

                return;
            }
            if (strlen($s->inbuf) < self::HEADER_LEN + $length) {
                return; // wait for the rest of this frame
            }

            $body = substr($s->inbuf, self::HEADER_LEN, $length);
            $s->inbuf = substr($s->inbuf, self::HEADER_LEN + $length);

            // We advertise no compression, so a compressed body is unexpected and undecodable here.
            if (($flags & self::FLAG_COMPRESSION) !== 0 && $body !== '') {
                $this->logUnknown($s, 'compressed frame body (compression not advertised)');
                $s->close = true;

                return;
            }

            $this->dispatch($s, $proto, $stream, $opcode, $body);
            if ($s->close || $s->state === CassandraSession::STATE_DONE) {
                return;
            }
        }
    }

    private function dispatch(CassandraSession $s, int $proto, int $stream, int $opcode, string $body): void
    {
        switch ($opcode) {
            case self::OP_OPTIONS:
                $s->outbuf .= $this->buildFrame($proto, $stream, self::OP_SUPPORTED, $this->buildSupportedBody());
                break;

            case self::OP_STARTUP:
                $this->handleStartup($s, $proto, $stream, $body);
                break;

            case self::OP_AUTH_RESPONSE:
                $this->handleAuthResponse($s, $proto, $stream, $body);
                break;

            default:
                // QUERY/PREPARE/REGISTER before auth, a TLS ClientHello, or junk — nothing to model
                // (a real cluster demands auth first). Record it and drop cleanly, never crash.
                $this->logUnknown($s, sprintf('unmodelled opcode 0x%02X', $opcode));
                $s->close = true;
        }
    }

    /**
     * STARTUP: log the client's advertised CQL version + driver, then answer with AUTHENTICATE naming
     * the configured authenticator so the driver sends its credential in an AUTH_RESPONSE.
     */
    private function handleStartup(CassandraSession $s, int $proto, int $stream, string $body): void
    {
        $opts = self::parseStringMap($body);
        // Option keys are case-insensitive in practice; drivers send them upper-case.
        $s->cqlVersion = $opts['CQL_VERSION'] ?? null;
        $s->driverName = $opts['DRIVER_NAME'] ?? null;
        $s->driverVersion = $opts['DRIVER_VERSION'] ?? null;

        $driver = trim(self::printable((string) $s->driverName) . ' ' . self::printable((string) $s->driverVersion));

        $this->logEvent([
            'event' => 'cassandra_startup',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'Cassandra STARTUP cql_version=%s driver=%s -> AUTHENTICATE %s',
                self::printable((string) ($s->cqlVersion ?? '')),
                $driver !== '' ? $driver : '(unnamed)',
                $this->config->authenticator
            ),
            'cql_version' => self::printable((string) ($s->cqlVersion ?? '')),
            'driver' => $driver,
        ]);

        $s->outbuf .= $this->buildFrame($proto, $stream, self::OP_AUTHENTICATE, $this->buildAuthenticateBody());
        $s->state = CassandraSession::STATE_AUTH;
    }

    /**
     * AUTH_RESPONSE: decode the SASL PLAIN token, log the captured credential, then deny it with an
     * ERROR (bad credentials). A session is never granted.
     */
    private function handleAuthResponse(CassandraSession $s, int $proto, int $stream, string $body): void
    {
        $cred = self::parseAuthToken($body);
        $s->username = $cred['username'] ?? null;
        $s->password = $cred['password'] ?? null;

        $user = self::printable((string) ($s->username ?? ''));
        $pass = self::printable((string) ($s->password ?? ''));

        $this->logEvent([
            'event' => 'cassandra_auth',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'critical',
            'path' => sprintf('Cassandra login attempt: user=%s password=%s', $user, $pass),
            'user' => $user,
            'password' => $pass,
            'body' => sprintf('user=%s password=%s', $user, $pass),
        ]);

        // Deny — a login is never accepted. Queue the ERROR; the run loop flushes it before the
        // socket is dropped.
        $s->outbuf .= $this->buildFrame(
            $proto,
            $stream,
            self::OP_ERROR,
            self::buildAuthErrorBody('Username and/or password are incorrect')
        );
        $s->state = CassandraSession::STATE_DONE;
        $s->close = true;
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses a CQL [string map] (a [short] count then that many [string]/[string] pairs). Returns the
     * decoded pairs; a truncated map yields whatever parsed cleanly rather than faulting.
     *
     * @return array<string,string>
     */
    public static function parseStringMap(string $body): array
    {
        $p = 0;
        $count = self::readShort($body, $p);
        if ($count === null) {
            return [];
        }

        $map = [];
        for ($i = 0; $i < $count; $i++) {
            $key = self::readString($body, $p);
            $val = self::readString($body, $p);
            if ($key === null || $val === null) {
                break;
            }
            $map[$key] = $val;
        }

        return $map;
    }

    /**
     * Parses a CQL AUTH_RESPONSE body — a [bytes] value carrying a SASL PLAIN token. The token is
     * `authzid \0 authcid \0 passwd`, so the username is the second field and the password the third.
     * Returns null-ish fields when the token is malformed rather than faulting.
     *
     * @return array{username:?string,password:?string}
     */
    public static function parseAuthToken(string $body): array
    {
        $p = 0;
        $token = self::readBytes($body, $p);
        if ($token === null) {
            return ['username' => null, 'password' => null];
        }

        // SASL PLAIN: split on NUL. A well-formed token has exactly three parts (authzid may be empty).
        $parts = explode("\x00", $token);
        if (count($parts) >= 3) {
            return ['username' => $parts[1], 'password' => $parts[2]];
        }
        if (count($parts) === 2) {
            // Tolerate a token missing the leading authzid separator.
            return ['username' => $parts[0], 'password' => $parts[1]];
        }

        return ['username' => $token, 'password' => null];
    }

    /** Reads a CQL [short] (2-byte big-endian unsigned) at $p, advancing $p. Null if out of range. */
    private static function readShort(string $buf, int &$p): ?int
    {
        if ($p + 2 > strlen($buf)) {
            return null;
        }
        $v = (ord($buf[$p]) << 8) | ord($buf[$p + 1]);
        $p += 2;

        return $v;
    }

    /** Reads a CQL [string] ([short] length + UTF-8 bytes) at $p, advancing $p. Null if out of range. */
    private static function readString(string $buf, int &$p): ?string
    {
        $save = $p;
        $len = self::readShort($buf, $p);
        if ($len === null || $p + $len > strlen($buf)) {
            $p = $save;

            return null;
        }
        $s = substr($buf, $p, $len);
        $p += $len;

        return $s;
    }

    /**
     * Reads a CQL [bytes] ([int] length + that many bytes; a negative length means null) at $p,
     * advancing $p. Null if the length is negative or the value runs past the buffer.
     */
    private static function readBytes(string $buf, int &$p): ?string
    {
        if ($p + 4 > strlen($buf)) {
            return null;
        }
        $len = self::be32($buf, $p);
        // [int] is signed; a negative length encodes a null value.
        if ($len >= 0x80000000) {
            $len -= 0x100000000;
        }
        $p += 4;
        if ($len < 0 || $p + $len > strlen($buf)) {
            return null;
        }
        $s = substr($buf, $p, $len);
        $p += $len;

        return $s;
    }

    private static function be32(string $b, int $off): int
    {
        return (ord($b[$off]) << 24)
            | (ord($b[$off + 1]) << 16)
            | (ord($b[$off + 2]) << 8)
            | ord($b[$off + 3]);
    }

    // ---- Response builders --------------------------------------------------------------------

    /**
     * Wraps a body in the 9-byte CQL header (native protocol §2.2): version with the response
     * direction bit set, flags 0, the echoed stream id, the opcode, and the body length (big-endian).
     */
    public function buildFrame(int $proto, int $stream, int $opcode, string $body): string
    {
        return chr(($proto & 0x7F) | self::DIRECTION_RESPONSE)
            . chr(0x00)                       // flags: no compression, no tracing
            . pack('n', $stream & 0xFFFF)     // echo the client's stream id
            . chr($opcode & 0xFF)
            . pack('N', strlen($body))
            . $body;
    }

    /**
     * The SUPPORTED body: a [string multimap] advertising the CQL version and (deliberately) no
     * compression, so a standard driver proceeds to STARTUP without negotiating a codec we would then
     * have to implement. PROTOCOL_VERSIONS is advertised for a believable identity.
     */
    public function buildSupportedBody(): string
    {
        $entries = [
            'CQL_VERSION' => [$this->config->cqlVersion],
            'COMPRESSION' => [], // none: keeps subsequent frames uncompressed and parseable
            'PROTOCOL_VERSIONS' => ['3/v3', '4/v4', '5/v5'],
        ];

        $out = pack('n', count($entries));
        foreach ($entries as $key => $values) {
            $out .= self::cqlString($key) . self::cqlStringList($values);
        }

        return $out;
    }

    /** The AUTHENTICATE body: a single [string] naming the authenticator class. */
    public function buildAuthenticateBody(): string
    {
        return self::cqlString($this->config->authenticator);
    }

    /**
     * The ERROR body for a failed authentication: [int] error code (bad credentials) + [string]
     * message. This is the honeypot's only reply to a credential: it never authenticates.
     */
    public static function buildAuthErrorBody(string $message): string
    {
        return pack('N', self::ERR_BAD_CREDENTIALS) . self::cqlString($message);
    }

    /** Encodes a CQL [string]: a [short] length prefix then the UTF-8 bytes. */
    private static function cqlString(string $s): string
    {
        return pack('n', strlen($s)) . $s;
    }

    /**
     * Encodes a CQL [string list]: a [short] count then each element as a [string].
     *
     * @param list<string> $values
     */
    private static function cqlStringList(array $values): string
    {
        $out = pack('n', count($values));
        foreach ($values as $v) {
            $out .= self::cqlString($v);
        }

        return $out;
    }

    // ---- Logging ------------------------------------------------------------------------------

    private function logUnknown(CassandraSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'cassandra_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'Cassandra unmodelled input: ' . $detail,
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'CASSANDRA';
        $entry['proto'] = 'cassandra';
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
                'port' => 9042,
                'path' => 'Cassandra internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $s): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $s) ?? '';
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 9042;
    }
}
