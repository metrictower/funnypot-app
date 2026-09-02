<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Rtsp;

/**
 * Zero-dependency, single-process TCP server for the low-interaction RTSP honeypot (port 554).
 * Speaks just enough RTSP 1.0 (RFC 2326) in pure PHP, on a non-blocking stream_select event loop, to
 * pose as a network camera / DVR — the prime Mirai and camera-scanner target — and harvest the stream
 * paths and credentials that scanners spray.
 *
 * RTSP is an HTTP-like text protocol: request lines like "DESCRIBE rtsp://host/<path> RTSP/1.0"
 * followed by CSeq and other headers, terminated by a blank line.
 *
 * Deliberately tier-1 and 100% inert: no real video is ever streamed and no client is ever truly
 * authenticated. The value is the intel:
 * - OPTIONS is answered with a plausible Public: method list.
 * - DESCRIBE captures the requested stream path (e.g. /Streaming/Channels/101, /cam/realmonitor,
 *   /h264 — these fingerprint the camera model targeted). With no credential it answers 401 with a
 *   WWW-Authenticate challenge to elicit one; a request that carries an Authorization header has its
 *   credential captured and is then answered with a believable SDP describing an H.264 track (so the
 *   attacker proceeds and reveals more), but nothing is streamed.
 * - SETUP / PLAY / TEARDOWN are answered plausibly (Session, Transport, RTP-Info) but stream nothing.
 * - The client User-Agent is captured throughout.
 */
final class RtspServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536; // an RTSP request is far smaller; guard against buffer exhaustion
    private const MAX_MESSAGES_PER_PASS = 64; // bound pipelined requests processed in one pass

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private RtspConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:554").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-rtsp: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-rtsp listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:RtspSession,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — a real RTSP request is tiny.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Fault isolation: a malformed request must close only this connection, never escape
                // the loop and crash the listener (degrade, never crash).
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'] ?? '', $e);
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($session->close && $session->outbuf === '') {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
            }

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

                // A response was queued for a connection marked done: close once it is fully flushed.
                if ($session->outbuf === '' && $session->close) {
                    $this->close($conns, $perIp, $id);
                }
            }

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
        $session = new RtspSession($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "RTSP connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into RTSP request messages and dispatches each one. Safe to drive
     * directly with raw bytes in tests.
     */
    public function processInbound(RtspSession $s): void
    {
        for ($n = 0; $n < self::MAX_MESSAGES_PER_PASS; $n++) {
            if ($s->close) {
                return;
            }
            if ($s->inbuf === '') {
                return;
            }

            // TCP-interleaved RTP/RTCP data (RFC 2326 §10.12) begins with '$'. A honeypot never carries
            // a media session, so binary framing here is junk / an unexpected stream: record and drop.
            if ($s->inbuf[0] === "\x24") {
                $this->logUnknown($s, 'interleaved binary frame (no media session)');
                $s->close = true;

                return;
            }

            // Find the end of the header block (blank line). Tolerate bare-LF clients alongside CRLF.
            $headerEnd = strpos($s->inbuf, "\r\n\r\n");
            $sepLen = 4;
            if ($headerEnd === false) {
                $lfEnd = strpos($s->inbuf, "\n\n");
                if ($lfEnd === false) {
                    return; // headers not complete yet
                }
                $headerEnd = $lfEnd;
                $sepLen = 2;
            }

            $headerBlock = substr($s->inbuf, 0, $headerEnd);
            $bodyStart = $headerEnd + $sepLen;

            // A request may carry a body (ANNOUNCE / SET_PARAMETER). Wait for the full Content-Length
            // before consuming the message so a split body does not desync the framing.
            $contentLength = self::contentLength($headerBlock);
            if ($contentLength > 0 && strlen($s->inbuf) < $bodyStart + $contentLength) {
                if ($bodyStart + $contentLength > self::INBUF_CAP) {
                    $this->logUnknown($s, 'oversized request body');
                    $s->close = true;

                    return;
                }

                return; // wait for the rest of the body
            }

            $message = substr($s->inbuf, 0, $bodyStart + max(0, $contentLength));
            $s->inbuf = substr($s->inbuf, strlen($message));

            $this->handleRequest($s, $message);
        }
    }

    private function handleRequest(RtspSession $s, string $message): void
    {
        $req = self::parseRequest($message);
        if ($req === null) {
            $this->logUnknown($s, 'malformed RTSP request');
            $s->outbuf .= $this->buildResponse(400, 'Bad Request', 0, []);
            $s->close = true;

            return;
        }

        $cseq = $req['cseq'];

        // Remember the client fingerprint the first time we see it.
        if ($req['userAgent'] !== null && $s->userAgent === null) {
            $s->userAgent = $req['userAgent'];
        }

        switch ($req['method']) {
            case 'OPTIONS':
                $this->handleOptions($s, $req, $cseq);
                break;

            case 'DESCRIBE':
                $this->handleDescribe($s, $req, $cseq);
                break;

            case 'SETUP':
                $this->handleSetup($s, $req, $cseq);
                break;

            case 'PLAY':
            case 'PAUSE':
            case 'RECORD':
                $this->handlePlay($s, $req, $cseq);
                break;

            case 'TEARDOWN':
                $this->handleTeardown($s, $req, $cseq);
                break;

            case 'GET_PARAMETER':
            case 'SET_PARAMETER':
                // Keep-alive / parameter pings: answer 200 so the client stays engaged, capture nothing
                // beyond the path already recorded.
                $s->outbuf .= $this->buildResponse(200, 'OK', $cseq, [
                    'Session' => $s->rtspSessionId,
                ]);
                break;

            default:
                $this->logUnknown($s, 'unmodelled method ' . self::printable($req['method']));
                $s->outbuf .= $this->buildResponse(501, 'Not Implemented', $cseq, []);
        }
    }

    private function handleOptions(RtspSession $s, array $req, int $cseq): void
    {
        if ($req['path'] !== null && $req['path'] !== '*') {
            $s->streamPath = $req['path'];
        }

        $this->logEvent([
            'event' => 'rtsp_options',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'RTSP OPTIONS ' . self::printable($req['uri']),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => 'low',
        ]);

        $s->outbuf .= $this->buildResponse(200, 'OK', $cseq, [
            'Public' => 'OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER',
        ]);
    }

    private function handleDescribe(RtspSession $s, array $req, int $cseq): void
    {
        $s->streamPath = $req['path'];

        $this->logEvent([
            'event' => 'rtsp_describe',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'RTSP DESCRIBE ' . self::printable((string) $req['path']),
            'stream_path' => self::printable((string) $req['path']),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => 'medium',
        ]);

        // A credential rides in an Authorization header: capture it, then hand back a believable SDP so
        // the attacker proceeds (SETUP/PLAY) and reveals more. Accepting any credential is inert — no
        // real stream exists behind it.
        if ($req['authorization'] !== null) {
            $this->captureCredential($s, $req);
            $s->outbuf .= $this->buildSdpResponse($s, $req, $cseq);

            return;
        }

        // No credential and auth is required: challenge to elicit one (the whole point of the emulator).
        if ($this->config->requireAuth) {
            $s->outbuf .= $this->buildUnauthorized($cseq);

            return;
        }

        // Auth disabled by config: answer the description directly.
        $s->outbuf .= $this->buildSdpResponse($s, $req, $cseq);
    }

    private function handleSetup(RtspSession $s, array $req, int $cseq): void
    {
        if ($req['path'] !== null) {
            $s->streamPath = $req['path'];
        }
        if ($s->rtspSessionId === null) {
            $s->rtspSessionId = self::newSessionId();
        }

        // Echo the client transport, filling in plausible server ports. No media is ever sent to them.
        $transport = $req['headers']['transport'] ?? 'RTP/AVP;unicast';
        $transport = self::printable($transport);
        if (stripos($transport, 'server_port') === false && stripos($transport, 'interleaved') === false) {
            $transport .= ';server_port=6970-6971';
        }
        if (stripos($transport, 'ssrc') === false) {
            $transport .= ';ssrc=1A2B3C4D';
        }

        $s->outbuf .= $this->buildResponse(200, 'OK', $cseq, [
            'Session' => $s->rtspSessionId . ';timeout=60',
            'Transport' => $transport,
        ]);
    }

    private function handlePlay(RtspSession $s, array $req, int $cseq): void
    {
        // Answer plausibly but stream nothing: no RTP packets are ever emitted on any transport.
        $rtpInfo = null;
        if ($s->streamPath !== null) {
            $rtpInfo = 'url=rtsp://' . self::hostFromUri($req['uri']) . $s->streamPath
                . '/trackID=1;seq=1;rtptime=0';
        }

        $s->outbuf .= $this->buildResponse(200, 'OK', $cseq, [
            'Session' => $s->rtspSessionId,
            'Range' => 'npt=0.000-',
            'RTP-Info' => $rtpInfo,
        ]);
    }

    private function handleTeardown(RtspSession $s, array $req, int $cseq): void
    {
        $s->outbuf .= $this->buildResponse(200, 'OK', $cseq, [
            'Session' => $s->rtspSessionId,
        ]);
        // The client is done; let the queued response flush, then drop the connection.
        $s->close = true;
    }

    /**
     * Parses and logs the credential from a DESCRIBE (or any) Authorization header. Basic carries the
     * cleartext user:pass; Digest carries the crackable response material and the account name.
     */
    private function captureCredential(RtspSession $s, array $req): void
    {
        $auth = self::parseAuthorization((string) $req['authorization']);
        if ($auth === null) {
            $this->logEvent([
                'event' => 'rtsp_auth',
                'ip' => $s->ip,
                'port' => $s->port,
                'path' => 'RTSP auth (unparsed): ' . self::printable((string) $req['authorization']),
                'stream_path' => self::printable((string) $req['path']),
                'severity' => 'high',
            ]);

            return;
        }

        $body = [];
        foreach ($auth as $k => $v) {
            $body[] = "{$k}={$v}";
        }
        $account = $auth['username'] ?? '';
        $scheme = $auth['scheme'] ?? 'unknown';

        $this->logEvent([
            'event' => 'rtsp_auth',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => "RTSP {$scheme} login attempt: {$account} on " . self::printable((string) $req['path']),
            'body' => implode(' ', $body),
            'stream_path' => self::printable((string) $req['path']),
            'user_agent' => self::printable((string) $s->userAgent),
            'username' => $auth['username'] ?? '',
            'password' => $auth['password'] ?? '',
            'severity' => 'critical',
        ]);
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses an RTSP request message. Returns null on any malformed request line so the caller can log
     * it as an unknown probe rather than faulting.
     *
     * @return array{method:string,uri:string,version:string,path:?string,headers:array<string,string>,cseq:int,userAgent:?string,authorization:?string,body:string}|null
     */
    public static function parseRequest(string $message): ?array
    {
        // Split the request line and header block from the body.
        $sep = strpos($message, "\r\n\r\n");
        $nl = "\r\n";
        if ($sep === false) {
            $sep = strpos($message, "\n\n");
            $nl = "\n";
            if ($sep === false) {
                $sep = strlen($message);
            }
        }
        $head = substr($message, 0, $sep);
        $body = (string) substr($message, $sep + ($nl === "\r\n" ? 4 : 2));

        $lines = preg_split('/\r\n|\n/', $head) ?: [];
        if ($lines === [] || $lines[0] === '') {
            return null;
        }

        // Request line: METHOD SP URI SP RTSP/x.y
        $requestLine = array_shift($lines);
        if (!preg_match('#^([A-Z_]+)\s+(\S+)\s+(RTSP/\d+\.\d+)\s*$#', $requestLine, $m)) {
            return null;
        }
        $method = $m[1];
        $uri = $m[2];
        $version = $m[3];

        $headers = [];
        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon === false) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $value = trim(substr($line, $colon + 1));
            // Last value wins for a repeated header; adequate for the fields we read.
            $headers[$name] = $value;
        }

        $cseqRaw = $headers['cseq'] ?? '0';
        $cseq = (int) preg_replace('/\D+/', '', $cseqRaw);

        return [
            'method' => $method,
            'uri' => $uri,
            'version' => $version,
            'path' => self::pathFromUri($uri),
            'headers' => $headers,
            'cseq' => $cseq,
            'userAgent' => $headers['user-agent'] ?? null,
            'authorization' => $headers['authorization'] ?? null,
            'body' => $body,
        ];
    }

    /** Extracts the stream path from an RTSP URI (strips scheme/host, keeps path + query). */
    public static function pathFromUri(string $uri): ?string
    {
        if ($uri === '*') {
            return '*';
        }
        if (preg_match('#^rtsp[su]?://[^/]+(/.*)?$#i', $uri, $m)) {
            return ($m[1] ?? '') !== '' ? $m[1] : '/';
        }
        // A relative URI (some tools omit the scheme) — use it as the path directly.
        return $uri !== '' ? $uri : null;
    }

    private static function hostFromUri(string $uri): string
    {
        if (preg_match('#^rtsp[su]?://([^/]+)#i', $uri, $m)) {
            return $m[1];
        }

        return '127.0.0.1';
    }

    /**
     * Parses an RTSP/HTTP Authorization header into captured credential fields. Basic yields the
     * cleartext username/password; Digest yields the account name and the crackable response material.
     *
     * @return array<string,string>|null
     */
    public static function parseAuthorization(string $header): ?array
    {
        $header = trim($header);
        if ($header === '') {
            return null;
        }

        $spacePos = strpos($header, ' ');
        $scheme = strtolower($spacePos === false ? $header : substr($header, 0, $spacePos));
        $rest = $spacePos === false ? '' : trim(substr($header, $spacePos + 1));

        if ($scheme === 'basic') {
            $decoded = base64_decode($rest, true);
            if ($decoded === false) {
                return ['scheme' => 'basic', 'raw' => self::printable($rest)];
            }
            $colon = strpos($decoded, ':');
            $user = $colon === false ? $decoded : substr($decoded, 0, $colon);
            $pass = $colon === false ? '' : substr($decoded, $colon + 1);

            return [
                'scheme' => 'basic',
                'username' => self::printable($user),
                'password' => self::printable($pass),
            ];
        }

        if ($scheme === 'digest') {
            $fields = ['scheme' => 'digest'];
            if (preg_match_all('/(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/', $rest, $mm, PREG_SET_ORDER)) {
                foreach ($mm as $pair) {
                    $key = strtolower($pair[1]);
                    $val = $pair[2] !== '' ? $pair[2] : ($pair[3] ?? '');
                    $fields[$key] = self::printable($val);
                }
            }

            return $fields;
        }

        // Some cameras use NTLM or bearer schemes; capture the scheme and the raw material.
        return ['scheme' => self::printable($scheme), 'raw' => self::printable($rest)];
    }

    private static function contentLength(string $headerBlock): int
    {
        if (preg_match('/^content-length\s*:\s*(\d+)/im', $headerBlock, $m)) {
            return (int) $m[1];
        }

        return 0;
    }

    // ---- Response building --------------------------------------------------------------------

    /**
     * Builds an RTSP status response with the given headers. Null-valued headers are omitted. Always
     * carries CSeq, Server and Date so it reads like a real device.
     *
     * @param array<string,?string> $headers
     */
    public function buildResponse(int $code, string $reason, int $cseq, array $headers, string $body = ''): string
    {
        $lines = ["RTSP/1.0 {$code} {$reason}"];
        $lines[] = "CSeq: {$cseq}";
        $lines[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' GMT';
        $lines[] = 'Server: ' . $this->config->serverName;

        foreach ($headers as $name => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $lines[] = "{$name}: {$value}";
        }

        if ($body !== '') {
            $lines[] = 'Content-Length: ' . strlen($body);
        }

        return implode("\r\n", $lines) . "\r\n\r\n" . $body;
    }

    /** A 401 Unauthorized carrying the configured WWW-Authenticate challenge that elicits a credential. */
    private function buildUnauthorized(int $cseq): string
    {
        $lines = ['RTSP/1.0 401 Unauthorized'];
        $lines[] = "CSeq: {$cseq}";
        $lines[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' GMT';
        $lines[] = 'Server: ' . $this->config->serverName;

        $realm = $this->config->realm;
        $scheme = $this->config->authScheme;
        if ($scheme === RtspConfig::AUTH_BASIC || $scheme === RtspConfig::AUTH_BOTH) {
            $lines[] = 'WWW-Authenticate: Basic realm="' . $realm . '"';
        }
        if ($scheme === RtspConfig::AUTH_DIGEST || $scheme === RtspConfig::AUTH_BOTH) {
            $lines[] = 'WWW-Authenticate: Digest realm="' . $realm . '", nonce="' . self::newNonce() . '"';
        }

        return implode("\r\n", $lines) . "\r\n\r\n";
    }

    /**
     * Builds a 200 OK carrying a believable SDP describing a single H.264 video track. This describes a
     * stream that does not exist — no media is ever sent — it only keeps the attacker engaged.
     */
    private function buildSdpResponse(RtspSession $s, array $req, int $cseq): string
    {
        $host = self::hostFromUri($req['uri']);
        $path = $s->streamPath ?? '/';
        $sdp = $this->buildSdp($host);

        $lines = ['RTSP/1.0 200 OK'];
        $lines[] = "CSeq: {$cseq}";
        $lines[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' GMT';
        $lines[] = 'Server: ' . $this->config->serverName;
        $lines[] = 'Content-Type: application/sdp';
        $lines[] = 'Content-Base: rtsp://' . $host . $path . '/';
        $lines[] = 'Content-Length: ' . strlen($sdp);

        return implode("\r\n", $lines) . "\r\n\r\n" . $sdp;
    }

    /** A minimal, plausible SDP for one H.264 track. Cosmetic only — it describes no real media. */
    private function buildSdp(string $host): string
    {
        $lines = [
            'v=0',
            'o=- 0 0 IN IP4 ' . $host,
            's=Media Presentation',
            'e=NONE',
            'c=IN IP4 0.0.0.0',
            'b=AS:5000',
            't=0 0',
            'a=control:*',
            'a=range:npt=0-',
            'm=video 0 RTP/AVP 96',
            'b=AS:5000',
            'a=control:trackID=1',
            'a=rtpmap:96 H264/90000',
            'a=fmtp:96 packetization-mode=1;profile-level-id=4D0028;'
                . 'sprop-parameter-sets=Z00AKp2oHgCJ+WbgICAgQ==,aO48gA==',
        ];

        // SDP lines are CRLF-terminated, each line ending in CRLF (RFC 4566 tolerates both; use CRLF).
        return implode("\r\n", $lines) . "\r\n";
    }

    private static function newSessionId(): string
    {
        // A 8-digit numeric session id like real cameras hand out. Not security-sensitive.
        return (string) random_int(10000000, 99999999);
    }

    private static function newNonce(): string
    {
        return bin2hex(random_bytes(16));
    }

    // ---- Logging ------------------------------------------------------------------------------

    private function logUnknown(RtspSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'rtsp_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'RTSP unmodelled input: ' . $detail,
            'severity' => 'low',
        ]);
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'RTSP';
        $entry['proto'] = 'rtsp';
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
                'port' => 554,
                'path' => 'RTSP internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $str): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $str) ?? '';
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 554;
    }
}
