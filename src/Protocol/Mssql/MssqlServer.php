<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Mssql;

/**
 * Zero-dependency, single-process TCP server for the MSSQL honeypot (port 1433). Speaks just enough
 * of the Tabular Data Stream protocol (MS-TDS) in pure PHP to fool scanners and clients (sqlcmd,
 * Impacket, Metasploit) on a non-blocking stream_select loop.
 *
 * Two interaction modes, chosen by {@see MssqlConfig::$interaction} (env FUNNYPOT_MSSQL_MODE):
 * - `low`  — PRELOGIN -> capture LOGIN7 credential -> deny with an ERROR token, then close. The
 *            original credential-harvest path.
 * - `high` — PRELOGIN -> accept LOGIN7 (mock-auth, never verified) -> serve a fabricated authenticated
 *            session: recon SELECTs answered with seeded persona result-sets, and the sp_configure ->
 *            xp_cmdshell exploitation chain trapped (full attacker command captured, plausible inert
 *            output returned).
 *
 * INERT in both modes: no database, no query engine, no filesystem, no registry, no outbound network.
 * Attacker commands / UNC paths / OLE progids / connection strings are parsed as text and logged only
 * — never executed, opened, or dialed (no NetNTLM leak-back, no SSRF, no DNS). The classifier
 * ({@see MssqlQueryEngine}) and the token encoders ({@see MssqlTokens}) are pure and unit-tested.
 *
 * The TDS password is only obfuscated, not encrypted: each byte is swap-nibbles(b) XOR 0xA5, which
 * this engine reverses to recover the cleartext. Advertising ENCRYPT_NOT_SUP is what makes a
 * standard client send that obfuscated-but-cleartext LOGIN7 rather than wrapping it in TLS.
 *
 * Frame: every TDS message carries an 8-byte header { type(1), status(1), length(2 big-endian,
 * counting the header), spid(2), packetId(1), window(1) }. A single request message may span several
 * packets; non-final packets clear the STATUS_EOM bit and are reassembled by type before dispatch.
 */
final class MssqlServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms select tick
    private const INBUF_CAP = 65536; // per-packet cap; a batch spanning packets is bounded by SESSION_MSG_CAP

    // Cap on a captured attacker command logged in command/body (full-but-bounded).
    private const CAPTURE_CAP = 4096;

    // TDS packet header types (MS-TDS 2.2.3.1.1).
    private const TDS_SQLBATCH = 0x01;  // client SQL batch request (SESSION mode)
    private const TDS_RPC = 0x03;       // client remote-procedure-call request (SESSION mode)
    private const TDS_RESPONSE = 0x04;  // server token-stream response (PRELOGIN + login + query replies)
    private const TDS_ATTENTION = 0x06; // client attention / cancel
    private const TDS_LOGIN7 = 0x10;    // client LOGIN7 request
    private const TDS_PRELOGIN = 0x12;  // client PRELOGIN request

    private const TDS_HEADER_LEN = 8;
    private const STATUS_EOM = 0x01;    // end-of-message
    private const STATUS_ATTN = 0x20;   // DONE_ATTN — attention/cancel acknowledged (0x02 is DONE_ERROR)

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

    // DONE token status flags (MS-TDS 2.2.7.6).
    private const DONE_FINAL = 0x0000;
    private const DONE_ERROR = 0x0002;
    private const DONE_COUNT = 0x0010; // DoneRowCount is valid

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

    // Well-known RPC ProcIDs (MS-TDS 2.2.6.6) — enough to recognise the sp_executesql path Impacket
    // and other clients use to run a statement without a SQLBATCH.
    private const WELL_KNOWN_PROCS = [
        7 => 'sp_cursorprepare',
        10 => 'sp_executesql',
        11 => 'sp_prepare',
        12 => 'sp_execute',
        13 => 'sp_prepexec',
        14 => 'sp_prepexecrpc',
        15 => 'sp_unprepare',
    ];

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
            $status = ord($s->inbuf[1]);
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
            $eom = ($status & self::STATUS_EOM) !== 0;

            // Reassemble a request message that spans several packets (non-final packets clear EOM):
            // accumulate the body by type until EOM, bounded by SESSION_MSG_CAP.
            if ($s->msgType === null && $eom) {
                $this->dispatch($s, $type, $body);
            } else {
                if ($s->msgType === null) {
                    $s->msgType = $type;
                    $s->msgBuf = '';
                }
                $s->msgBuf .= $body;
                if (strlen($s->msgBuf) > MssqlSession::SESSION_MSG_CAP) {
                    $this->logUnknown($s, 'reassembly buffer over cap');
                    $s->close = true;

                    return;
                }
                if ($eom) {
                    $type = $s->msgType;
                    $body = $s->msgBuf;
                    $s->msgType = null;
                    $s->msgBuf = '';
                    $this->dispatch($s, $type, $body);
                }
            }

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

                return;

            case self::TDS_LOGIN7:
                $this->handleLogin7($s, $body);

                return;
        }

        // In an accepted (high-mode) session, handle batches / RPC / attention.
        if ($s->state === MssqlSession::STATE_SESSION) {
            switch ($type) {
                case self::TDS_SQLBATCH:
                    $this->handleBatch($s, $body);

                    return;

                case self::TDS_RPC:
                    $this->handleRpc($s, $body);

                    return;

                case self::TDS_ATTENTION:
                    // Acknowledge the cancel and stay in session — dropping here would be a tell.
                    $s->outbuf .= $this->tdsPacket(self::TDS_RESPONSE, MssqlTokens::done(self::STATUS_ATTN, 0));

                    return;

                default:
                    // An unusual packet mid-session: log and answer benignly, do NOT drop the session.
                    $this->logUnknown($s, sprintf('unmodelled session packet type 0x%02X', $type));
                    $s->outbuf .= $this->tdsPacket(self::TDS_RESPONSE, MssqlTokens::done(self::DONE_FINAL, 0));

                    return;
            }
        }

        // Pre-session: a TLS ClientHello (0x16) from a client that insists on encryption, or junk —
        // nothing to model. Record it and drop cleanly, never crash.
        $this->logUnknown($s, sprintf('unmodelled TDS packet type 0x%02X', $type));
        $s->close = true;
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

        if ($this->config->interaction !== 'high') {
            // low mode: deny — a login is never accepted. Queue the ERROR token; the run loop flushes
            // it before the socket is dropped.
            $s->outbuf .= $this->buildLoginError($user);
            $s->state = MssqlSession::STATE_DONE;
            $s->close = true;

            return;
        }

        // high mode: accept-any (the lure). Never verify the password — an SSPI/integrated login with
        // an empty password field is accepted too. Advance to an authenticated session and stay open.
        $s->authUser = ($s->username !== null && $s->username !== '') ? $s->username : 'sa';
        $s->currentDb = 'master';
        $s->outbuf .= $this->buildLoginSuccess();
        $s->state = MssqlSession::STATE_SESSION;
    }

    /**
     * The login-success token stream: LOGINACK, the ENVCHANGE records (database, language, packet
     * size), the two INFO messages a real server sends on connect, and a final DONE. This is what
     * makes sqlcmd / Impacket / Metasploit believe they are authenticated.
     */
    public function buildLoginSuccess(): string
    {
        $body = MssqlTokens::loginAck($this->config)
            . MssqlTokens::envChangeLogin('master')
            . MssqlTokens::info(5701, 2, 0, "Changed database context to 'master'.", $this->config->serverName)
            . MssqlTokens::info(5703, 1, 0, 'Changed language setting to us_english.', $this->config->serverName)
            . MssqlTokens::done(self::DONE_FINAL, 0);

        return $this->tdsPacket(self::TDS_RESPONSE, $body);
    }

    /**
     * SQLBATCH (SESSION mode): strip the ALL_HEADERS block, decode the UTF-16LE SQL text, classify it
     * and queue the fabricated token-stream response.
     */
    private function handleBatch(MssqlSession $s, string $body): void
    {
        $sql = self::decodeUtf16le(self::stripAllHeaders($body));
        $this->answerQuery($s, $sql);
    }

    /**
     * RPC (SESSION mode): best-effort. Strip ALL_HEADERS, resolve the proc (US_VARCHAR name or a
     * well-known ProcID). For sp_executesql / sp_prepare / sp_prepexec, pull the first NVARCHAR
     * parameter (the SQL statement) and route it through the same classifier; otherwise log the proc
     * and answer with an empty DONE.
     */
    private function handleRpc(MssqlSession $s, string $body): void
    {
        $rpc = substr($body, self::stripAllHeadersLen($body));

        [$proc, $paramsOff] = self::rpcProcName($rpc);
        $lower = strtolower($proc);

        if (in_array($lower, ['sp_executesql', 'sp_prepare', 'sp_prepexec', 'sp_execute'], true)) {
            $stmt = self::rpcFirstNVarchar($rpc, $paramsOff);
            if ($stmt !== null && $stmt !== '') {
                $this->answerQuery($s, $stmt);

                return;
            }
        }

        $this->logEvent([
            'event' => 'mssql_query',
            'ip' => $s->ip,
            'port' => $s->port,
            'severity' => 'medium',
            'reportable' => true,
            'path' => 'MSSQL RPC: ' . self::printable($proc !== '' ? $proc : 'sp#' . dechex(strlen($rpc))),
        ]);
        $s->outbuf .= $this->tdsPacket(self::TDS_RESPONSE, MssqlTokens::done(self::DONE_FINAL, 0));
    }

    /**
     * Classify a recovered SQL statement, log its intel events, and queue one token-stream response.
     * The classifier is pure and inert; this method only fabricates bytes and log lines.
     */
    private function answerQuery(MssqlSession $s, string $sql): void
    {
        $result = (new MssqlQueryEngine($this->config))->classify($sql, $s);

        if ($result->enableXpCmdshell) {
            $s->xpCmdshellEnabled = true; // intel/story only — nothing is ever executed
        }
        if ($result->newDatabase !== null) {
            $s->currentDb = $result->newDatabase;
        }

        foreach ($result->events as $ev) {
            $entry = [
                'event' => $ev['event'],
                'ip' => $s->ip,
                'port' => $s->port,
                'severity' => $ev['severity'],
                'reportable' => $ev['reportable'],
                'path' => 'MSSQL ' . self::printable(self::cap($ev['summary'], 400)),
            ];
            if (($ev['command'] ?? null) !== null && $ev['command'] !== '') {
                $entry['command'] = self::printable(self::cap($ev['command'], self::CAPTURE_CAP));
                $entry['body'] = $entry['command'];
            }
            if (($ev['proc'] ?? null) !== null) {
                $entry['proc'] = $ev['proc'];
            }
            $this->logEvent($entry);
        }

        $s->outbuf .= $this->tdsPacket(self::TDS_RESPONSE, $this->encodeResult($result));
    }

    /** Encode a query result into a TDS token stream: info messages, result sets, then one DONE. */
    private function encodeResult(MssqlQueryResult $result): string
    {
        $out = '';
        foreach ($result->infoMessages as $m) {
            $out .= MssqlTokens::info($m['number'], $m['state'], $m['class'], $m['text'], $this->config->serverName);
        }

        $hasRows = false;
        $totalRows = 0;
        foreach ($result->resultSets as $rs) {
            $out .= MssqlTokens::colMetadataNVarchar($rs['columns']);
            foreach ($rs['rows'] as $row) {
                $out .= MssqlTokens::row($row);
                $totalRows++;
            }
            $hasRows = true;
        }

        if ($result->returnStatus !== null) {
            $out .= MssqlTokens::returnStatus($result->returnStatus);
        }

        $out .= $hasRows
            ? MssqlTokens::done(self::DONE_COUNT, $totalRows)
            : MssqlTokens::done(self::DONE_FINAL, 0);

        return $out;
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
     * a server response packet. This is low mode's only reply to a login: it never authenticates. The
     * ERROR + DONE encoders are shared with the high-mode path via {@see MssqlTokens}.
     */
    public function buildLoginError(string $user): string
    {
        // ERROR (MS-TDS 2.2.7.10): number 18456, state 1, class 14 (login-failed severity), line 1.
        $error = MssqlTokens::error(self::ERR_LOGIN_FAILED, 1, 14, "Login failed for user '{$user}'.", $this->config->serverName, 1);
        $done = MssqlTokens::done(self::DONE_ERROR, 0);

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

    // ---- ALL_HEADERS / RPC parsing (SESSION mode) --------------------------------------------

    /**
     * The byte length of the ALL_HEADERS block (MS-TDS 2.2.5.2) that prefixes a SQLBATCH/RPC body: a
     * leading DWORD TotalLength (LE) covering the block. Returns 0 (no headers) when the length is
     * absent or implausible, so a batch from a client that omits the block still parses.
     */
    private static function stripAllHeadersLen(string $body): int
    {
        if (strlen($body) < 4) {
            return 0;
        }
        $total = self::le32($body, 0);

        return ($total >= 4 && $total <= strlen($body)) ? $total : 0;
    }

    /** Returns the SQLBATCH body with its ALL_HEADERS block removed. */
    private static function stripAllHeaders(string $body): string
    {
        return substr($body, self::stripAllHeadersLen($body));
    }

    /**
     * Resolves the RPC proc: either an explicit US_VARCHAR name, or the 0xFFFF sentinel followed by a
     * well-known ProcID. Returns [procName, offsetOfParams].
     *
     * @return array{0:string,1:int}
     */
    private static function rpcProcName(string $rpc): array
    {
        if (strlen($rpc) < 2) {
            return ['', strlen($rpc)];
        }
        $nameLen = self::le16($rpc, 0);
        if ($nameLen === 0xFFFF) {
            if (strlen($rpc) < 4) {
                return ['', strlen($rpc)];
            }
            $procId = self::le16($rpc, 2);
            $off = 4 + 2; // ProcID USHORT + OptionFlags USHORT
            return [self::WELL_KNOWN_PROCS[$procId] ?? '', min($off, strlen($rpc))];
        }

        $bytes = $nameLen * 2;
        if (2 + $bytes > strlen($rpc)) {
            return ['', strlen($rpc)];
        }
        $name = self::decodeUtf16le(substr($rpc, 2, $bytes));
        $off = 2 + $bytes + 2; // name + OptionFlags USHORT

        return [$name, min($off, strlen($rpc))];
    }

    /**
     * Extract the first NVARCHAR parameter value from an RPC param block (the statement for
     * sp_executesql). Best-effort: reads the param name (B_VARCHAR), status byte, and an NVARCHAR
     * (0xE7) type; handles both a USHORT-length value and a PLP (MAX) value. Returns null if the first
     * parameter is not an NVARCHAR we can read.
     */
    private static function rpcFirstNVarchar(string $rpc, int $off): ?string
    {
        $len = strlen($rpc);
        if ($off + 1 > $len) {
            return null;
        }
        $nameLen = ord($rpc[$off]);
        $off += 1 + $nameLen * 2; // param name B_VARCHAR
        $off += 1;                // status flags
        if ($off + 1 > $len) {
            return null;
        }
        $type = ord($rpc[$off]);
        $off += 1;
        if ($type !== 0xE7 && $type !== 0xEF) { // NVARCHAR / NCHAR
            return null;
        }
        if ($off + 7 > $len) {
            return null;
        }
        $maxLen = self::le16($rpc, $off);
        $off += 2 + 5; // maxlen USHORT + 5-byte collation

        if ($maxLen === 0xFFFF) {
            // PLP: an 8-byte total length (or unknown sentinel) then DWORD-length chunks until a 0 chunk.
            if ($off + 8 > $len) {
                return null;
            }
            $off += 8;
            $data = '';
            while ($off + 4 <= $len) {
                $chunk = self::le32($rpc, $off);
                $off += 4;
                if ($chunk === 0 || $off + $chunk > $len) {
                    break;
                }
                $data .= substr($rpc, $off, $chunk);
                $off += $chunk;
            }

            return self::decodeUtf16le($data);
        }

        if ($off + 2 > $len) {
            return null;
        }
        $byteLen = self::le16($rpc, $off);
        $off += 2;
        if ($byteLen === 0xFFFF) {
            return null; // NULL value
        }
        $byteLen = min($byteLen, $len - $off);

        return self::decodeUtf16le(substr($rpc, $off, $byteLen));
    }

    /** Truncates a string to a byte cap for log lines. */
    private static function cap(string $s, int $max): string
    {
        return strlen($s) > $max ? substr($s, 0, $max) : $s;
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

    private static function le32(string $b, int $off): int
    {
        return ord($b[$off])
            | (ord($b[$off + 1]) << 8)
            | (ord($b[$off + 2]) << 16)
            | (ord($b[$off + 3]) << 24);
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
        // FP-0247 (Fix A): TCP accept ⇒ source verified by the three-way handshake, so reportable.
        // `??=` so a per-event override (e.g. an explicit false) stays authoritative.
        $entry['reportable'] ??= true;
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
