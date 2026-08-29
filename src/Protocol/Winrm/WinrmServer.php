<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Winrm;

/**
 * Zero-dependency, single-process TCP server for the low-interaction WinRM honeypot (port 5985).
 * WinRM / WS-Management runs over plain HTTP on this port, so the emulator speaks just enough HTTP in
 * pure PHP — a minimal request-line + header parser, bodies framed by Content-Length — on a
 * non-blocking stream_select event loop, to pose as a Windows remote-management endpoint and harvest
 * the credentials brute-forcers spray at it.
 *
 * A minimal HTTP parser is embedded here on purpose: this is HTTP framing on a dedicated port, not a
 * web app, so it never pulls in funnypot-core.
 *
 * Deliberately tier-1 and 100% inert: no command is ever run, no session is ever granted, no client
 * is ever authenticated. The value is the intel:
 * - POST /wsman with no credential is answered 401 with a WWW-Authenticate challenge (Negotiate and
 *   Basic realm="WSMAN") — the challenge is exactly what elicits the credential.
 * - A Basic Authorization header yields the cleartext user:pass.
 * - A Negotiate/NTLM handshake is walked: a type-1 NEGOTIATE draws a type-2 CHALLENGE, and the type-3
 *   AUTHENTICATE the client then sends has its username/domain/workstation and NTLMv2 response
 *   captured. The credential is captured and then always denied.
 * - A GET, or any other path/method, gets a plausible Microsoft-HTTPAPI/2.0 404 so the box reads like
 *   a real HTTP.sys listener.
 */
final class WinrmServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536; // a WinRM request is far smaller; guard against buffer exhaustion
    private const MAX_MESSAGES_PER_PASS = 64; // bound pipelined requests processed in one pass

    // NTLMSSP message types (MS-NLMP 2.2.1).
    private const NTLM_NEGOTIATE = 1;
    private const NTLM_CHALLENGE = 2;
    private const NTLM_AUTHENTICATE = 3;

    // NTLMSSP negotiate flags used when building our type-2 CHALLENGE (MS-NLMP 2.2.2.5).
    private const NTLMSSP_NEGOTIATE_UNICODE = 0x00000001;
    private const NTLMSSP_REQUEST_TARGET = 0x00000004;
    private const NTLMSSP_NEGOTIATE_NTLM = 0x00000200;
    private const NTLMSSP_TARGET_TYPE_SERVER = 0x00020000;
    private const NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private WinrmConfig $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:5985").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-winrm: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-winrm listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:WinrmSession,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — a real WinRM request is tiny.
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
        $session = new WinrmSession($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "WinRM connection from {$ip}:{$clientPort}",
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
     * Frames the inbound stream into HTTP request messages (header block + Content-Length body) and
     * dispatches each one. Safe to drive directly with raw bytes in tests.
     */
    public function processInbound(WinrmSession $s): void
    {
        for ($n = 0; $n < self::MAX_MESSAGES_PER_PASS; $n++) {
            if ($s->close) {
                return;
            }
            if ($s->inbuf === '') {
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

            // A WinRM POST carries a SOAP body. Wait for the full Content-Length before consuming the
            // message so a split body does not desync the framing.
            $contentLength = self::contentLength($headerBlock);
            if ($contentLength > 0 && strlen($s->inbuf) < $bodyStart + $contentLength) {
                if ($bodyStart + $contentLength > self::INBUF_CAP) {
                    $this->logUnknown($s, 'oversized request body');
                    $s->outbuf .= $this->buildResponse(400, 'Bad Request', ['Content-Type' => 'text/html; charset=us-ascii'], '', true);
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

    private function handleRequest(WinrmSession $s, string $message): void
    {
        $req = self::parseRequest($message);
        if ($req === null) {
            $this->logUnknown($s, 'malformed HTTP request');
            $s->outbuf .= $this->buildResponse(400, 'Bad Request', ['Content-Type' => 'text/html; charset=us-ascii'], '', true);
            $s->close = true;

            return;
        }

        // Remember the client fingerprint the first time we see it.
        if ($req['userAgent'] !== null && $s->userAgent === null) {
            $s->userAgent = $req['userAgent'];
        }

        // A credential (or an NTLM handshake step) rides in the Authorization header regardless of the
        // path or method — capture it before anything else.
        if ($req['authorization'] !== null) {
            $this->handleAuthorization($s, $req);

            return;
        }

        // POST /wsman with no credential: challenge to elicit one (the whole point of the emulator).
        if (self::isWsman($req['method'], $req['path'])) {
            $this->logProbe($s, $req, 'unauthenticated /wsman -> 401 challenge', 'medium');
            $s->outbuf .= $this->buildUnauthorized();

            return;
        }

        // A GET, or any other path/method, with no credential: answer like a real HTTP.sys listener.
        $this->logProbe($s, $req, '404 Not Found', 'low');
        $s->outbuf .= $this->build404();
        $s->close = true;
    }

    /**
     * Handles a request carrying an Authorization header. An NTLM type-1 draws a type-2 challenge (to
     * pull out the username-bearing type-3); everything else is a captured credential attempt, logged
     * and then always denied. A credential is never accepted.
     */
    private function handleAuthorization(WinrmSession $s, array $req): void
    {
        $auth = self::parseAuthorization((string) $req['authorization']);
        if ($auth === null) {
            // An empty / unusable Authorization header: treat it like an unauthenticated request.
            $this->logProbe($s, $req, 'empty Authorization -> 401 challenge', 'medium');
            $s->outbuf .= $this->buildUnauthorized();

            return;
        }

        // NTLM handshake start: no username yet. Answer with a type-2 CHALLENGE so the client returns
        // the type-3 AUTHENTICATE that carries the account name. The connection stays open for it.
        if (($auth['ntlmssp_type'] ?? null) === self::NTLM_NEGOTIATE) {
            $this->logProbe($s, $req, 'NTLM NEGOTIATE (type 1) -> challenge issued', 'medium');
            $s->outbuf .= $this->buildNegotiateChallenge();

            return;
        }

        $this->logAuth($s, $req, $auth);

        // Never authenticate: answer 401 again (login failed) with the same challenge.
        $s->outbuf .= $this->buildUnauthorized();
    }

    /**
     * Logs a captured credential attempt: a Basic user:pass, an NTLM type-3 (username/domain/
     * workstation + crackable NT response), or Negotiate/SPNEGO material with no cleartext.
     *
     * @param array<string,mixed> $auth
     */
    private function logAuth(WinrmSession $s, array $req, array $auth): void
    {
        $scheme = (string) ($auth['scheme'] ?? 'unknown');

        $fields = [];
        foreach ($auth as $k => $v) {
            if (is_scalar($v)) {
                $fields[] = $k . '=' . self::printable((string) $v);
            }
        }

        $account = '';
        if (isset($auth['username']) && $auth['username'] !== '') {
            $domain = (string) ($auth['domain'] ?? '');
            $account = ($domain !== '' ? $domain . '\\' : '') . (string) $auth['username'];
        }
        $descr = $account !== '' ? "{$scheme} login attempt: {$account}" : "{$scheme} auth attempt";

        $this->logEvent([
            'event' => 'winrm_auth',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => "WinRM {$descr} on " . self::printable((string) $req['path']),
            'body' => implode(' ', $fields),
            'http_method' => self::printable((string) $req['method']),
            'scheme' => self::printable($scheme),
            'username' => self::printable((string) ($auth['username'] ?? '')),
            'password' => self::printable((string) ($auth['password'] ?? '')),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => 'high',
        ]);
    }

    private function logProbe(WinrmSession $s, array $req, string $detail, string $severity): void
    {
        $this->logEvent([
            'event' => 'winrm_probe',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'WinRM %s %s (%s)',
                self::printable((string) $req['method']),
                self::printable((string) $req['path']),
                $detail
            ),
            'http_method' => self::printable((string) $req['method']),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => $severity,
        ]);
    }

    // ---- Parsing ------------------------------------------------------------------------------

    /**
     * Parses an HTTP request message. Returns null on any malformed request line so the caller can log
     * it as an unknown probe rather than faulting.
     *
     * @return array{method:string,uri:string,version:string,path:string,headers:array<string,string>,userAgent:?string,authorization:?string,body:string}|null
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

        // Request line: METHOD SP request-target SP HTTP/x.y
        $requestLine = array_shift($lines);
        if (!preg_match('#^([A-Z]+)\s+(\S+)\s+HTTP/(\d+\.\d+)\s*$#', $requestLine, $m)) {
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

        return [
            'method' => $method,
            'uri' => $uri,
            'version' => $version,
            'path' => self::pathFromUri($uri),
            'headers' => $headers,
            'userAgent' => $headers['user-agent'] ?? null,
            'authorization' => $headers['authorization'] ?? null,
            'body' => $body,
        ];
    }

    /** Extracts the request path from an HTTP request-target (strips absolute-form scheme/host + query). */
    public static function pathFromUri(string $uri): string
    {
        if ($uri === '*') {
            return '*';
        }
        // absolute-form: some tools send the full URL as the request target.
        if (preg_match('#^https?://[^/]+(/\S*)?$#i', $uri, $m)) {
            $uri = ($m[1] ?? '') !== '' ? $m[1] : '/';
        }
        $q = strpos($uri, '?');
        if ($q !== false) {
            $uri = substr($uri, 0, $q);
        }

        return $uri === '' ? '/' : $uri;
    }

    /** The credential-eliciting endpoint is POST to a /wsman path (case-insensitive). */
    public static function isWsman(string $method, string $path): bool
    {
        return strtoupper($method) === 'POST' && stripos($path, '/wsman') === 0;
    }

    /**
     * Parses an HTTP Authorization header into captured credential fields. Basic yields the cleartext
     * username/password; Negotiate/NTLM yields the NTLMSSP message type and, for a type-3, the account
     * name and the crackable response material.
     *
     * @return array<string,mixed>|null
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

        if ($scheme === 'negotiate' || $scheme === 'ntlm') {
            $token = base64_decode($rest, true);
            if ($token === false || $token === '') {
                return ['scheme' => $scheme, 'raw' => self::printable($rest)];
            }

            // NTLMSSP may be raw or wrapped inside an SPNEGO GSS token, so scan for the signature.
            $ntlm = self::parseNtlm($token);
            if ($ntlm !== null) {
                return array_merge(['scheme' => $scheme], $ntlm);
            }

            // No NTLMSSP: Negotiate wrapping SPNEGO/Kerberos, which we don't model. Record the mechanism.
            $mechanism = ($token !== '' && ord($token[0]) === 0x60) ? 'spnego/kerberos' : 'unknown';

            return ['scheme' => $scheme, 'mechanism' => $mechanism];
        }

        // Some tools use Digest / Bearer schemes against WinRM; capture the scheme and raw material.
        return ['scheme' => self::printable($scheme), 'raw' => self::printable($rest)];
    }

    /**
     * Parses an NTLMSSP message from anywhere inside $buf (raw or SPNEGO-wrapped). Returns the message
     * type and, for a type-3 AUTHENTICATE (MS-NLMP 2.2.1.3), the captured account fields and NT
     * response. Returns null if no NTLMSSP signature is present.
     *
     * @return array{ntlmssp_type:int,domain?:string,username?:string,workstation?:string,nt_response?:string}|null
     */
    public static function parseNtlm(string $buf): ?array
    {
        $sig = "NTLMSSP\x00";
        $base = strpos($buf, $sig);
        if ($base === false) {
            return null;
        }
        $msg = substr($buf, $base);
        if (strlen($msg) < 12) {
            return null;
        }
        $type = self::le32($msg, 8);
        $result = ['ntlmssp_type' => $type];

        if ($type !== self::NTLM_AUTHENTICATE) {
            return $result; // type 1 (or an echoed type 2): no account name to extract
        }

        // AUTHENTICATE payload descriptors { Len(2), MaxLen(2), BufferOffset(4) }: LM@12, NT@20,
        // Domain@28, User@36, Workstation@44. NegotiateFlags@60 (present in a full message).
        $flags = strlen($msg) >= 64 ? self::le32($msg, 60) : 0;
        $unicode = (bool) ($flags & self::NTLMSSP_NEGOTIATE_UNICODE);

        $ntResponse = self::ntlmField($msg, 20);
        $domain = self::ntlmField($msg, 28);
        $username = self::ntlmField($msg, 36);
        $workstation = self::ntlmField($msg, 44);

        $result['domain'] = self::printable($unicode ? self::decodeUtf16le($domain) : $domain);
        $result['username'] = self::printable($unicode ? self::decodeUtf16le($username) : $username);
        $result['workstation'] = self::printable($unicode ? self::decodeUtf16le($workstation) : $workstation);
        $result['nt_response'] = bin2hex($ntResponse);

        return $result;
    }

    /**
     * Reads an NTLMSSP payload field descriptor { Len(2), MaxLen(2), BufferOffset(4) } at $descOff and
     * returns the referenced bytes. Empty string if the descriptor points outside the message.
     */
    private static function ntlmField(string $msg, int $descOff): string
    {
        if ($descOff + 8 > strlen($msg)) {
            return '';
        }
        $len = self::le16($msg, $descOff);
        $offset = self::le32($msg, $descOff + 4);
        if ($len === 0 || $offset + $len > strlen($msg)) {
            return '';
        }

        return substr($msg, $offset, $len);
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
     * Builds an HTTP response with the given headers. Always carries the HTTP.sys Server banner and a
     * Date so it reads like a real WinRM listener; Content-Length is set from the body.
     *
     * @param array<string,?string> $headers
     */
    public function buildResponse(int $code, string $reason, array $headers, string $body = '', bool $close = false): string
    {
        $lines = ["HTTP/1.1 {$code} {$reason}"];
        $lines[] = 'Server: ' . $this->config->serverName;
        $lines[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' GMT';

        foreach ($headers as $name => $value) {
            if ($value === null || $value === '') {
                continue;
            }
            $lines[] = "{$name}: {$value}";
        }

        $lines[] = 'Content-Length: ' . strlen($body);
        $lines[] = 'Connection: ' . ($close ? 'close' : 'Keep-Alive');

        return implode("\r\n", $lines) . "\r\n\r\n" . $body;
    }

    /**
     * A 401 Unauthorized carrying the configured WWW-Authenticate challenges. The connection is kept
     * alive so the client can retry with a credential (Basic) or continue the NTLM handshake.
     */
    private function buildUnauthorized(): string
    {
        $lines = ['HTTP/1.1 401 Unauthorized'];
        $lines[] = 'Server: ' . $this->config->serverName;
        $lines[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' GMT';

        foreach ($this->wwwAuthenticateChallenges() as $challenge) {
            $lines[] = 'WWW-Authenticate: ' . $challenge;
        }

        $lines[] = 'Content-Length: 0';
        $lines[] = 'Connection: Keep-Alive';

        return implode("\r\n", $lines) . "\r\n\r\n";
    }

    /**
     * A 401 carrying our NTLM type-2 CHALLENGE in the Negotiate header. This draws the type-3
     * AUTHENTICATE that carries the username; the connection is kept alive to receive it.
     */
    private function buildNegotiateChallenge(): string
    {
        $token = base64_encode($this->buildNtlmChallenge());

        $lines = ['HTTP/1.1 401 Unauthorized'];
        $lines[] = 'Server: ' . $this->config->serverName;
        $lines[] = 'Date: ' . gmdate('D, d M Y H:i:s') . ' GMT';
        $lines[] = 'WWW-Authenticate: Negotiate ' . $token;
        $lines[] = 'Content-Length: 0';
        $lines[] = 'Connection: Keep-Alive';

        return implode("\r\n", $lines) . "\r\n\r\n";
    }

    /** The WWW-Authenticate challenge lines the 401 offers, per the configured scheme. */
    private function wwwAuthenticateChallenges(): array
    {
        $out = [];
        $scheme = $this->config->authScheme;
        if ($scheme === WinrmConfig::AUTH_NEGOTIATE || $scheme === WinrmConfig::AUTH_BOTH) {
            $out[] = 'Negotiate';
        }
        if ($scheme === WinrmConfig::AUTH_BASIC || $scheme === WinrmConfig::AUTH_BOTH) {
            $out[] = 'Basic realm="' . $this->config->realm . '"';
        }

        return $out;
    }

    /**
     * The plausible Microsoft-HTTPAPI/2.0 404 a real WinRM HTTP.sys listener returns for a GET or an
     * unknown path. Cosmetic only — it exposes nothing and reveals no real resource.
     */
    private function build404(): string
    {
        $body = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\"http://www.w3.org/TR/html4/strict.dtd\">\r\n"
            . "<HTML><HEAD><TITLE>Not Found</TITLE>\r\n"
            . "<META HTTP-EQUIV=\"Content-Type\" Content=\"text/html; charset=us-ascii\"></HEAD>\r\n"
            . "<BODY><h2>Not Found</h2>\r\n"
            . "<hr><p>HTTP Error 404. The requested resource is not found.</p>\r\n"
            . "</BODY></HTML>\r\n";

        return $this->buildResponse(404, 'Not Found', ['Content-Type' => 'text/html; charset=us-ascii'], $body, true);
    }

    /**
     * Builds an NTLMSSP type-2 CHALLENGE message (MS-NLMP 2.2.1.2). Purely cosmetic: it carries a
     * fresh random server challenge and a target-info block naming the persona computer, enough to
     * make a client hand back the type-3 AUTHENTICATE we want to capture. No real key is ever derived.
     */
    public function buildNtlmChallenge(): string
    {
        $target = self::utf16le($this->config->computerName);

        // TargetInfo AV pairs (MS-NLMP 2.2.2.1): NetBIOS domain + computer names, then the EOL pair.
        $targetInfo = self::avPair(0x0002, $target)  // MsvAvNbDomainName
            . self::avPair(0x0001, $target)          // MsvAvNbComputerName
            . self::avPair(0x0000, '');              // MsvAvEOL

        $flags = self::NTLMSSP_NEGOTIATE_UNICODE
            | self::NTLMSSP_REQUEST_TARGET
            | self::NTLMSSP_NEGOTIATE_NTLM
            | self::NTLMSSP_TARGET_TYPE_SERVER
            | self::NTLMSSP_NEGOTIATE_TARGET_INFO;

        // Fixed header (no Version field) is 48 bytes; the payload follows.
        $payloadOffset = 48;
        $targetOffset = $payloadOffset;
        $targetInfoOffset = $payloadOffset + strlen($target);

        return "NTLMSSP\x00"
            . pack('V', self::NTLM_CHALLENGE)
            . pack('v', strlen($target)) . pack('v', strlen($target)) . pack('V', $targetOffset)
            . pack('V', $flags)
            . random_bytes(8)              // ServerChallenge — fresh, never reused for a real key
            . str_repeat("\x00", 8)        // Reserved
            . pack('v', strlen($targetInfo)) . pack('v', strlen($targetInfo)) . pack('V', $targetInfoOffset)
            . $target
            . $targetInfo;
    }

    private static function avPair(int $id, string $value): string
    {
        return pack('v', $id) . pack('v', strlen($value)) . $value;
    }

    // ---- Logging ------------------------------------------------------------------------------

    private function logUnknown(WinrmSession $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'winrm_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'WinRM unmodelled input: ' . $detail,
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
        $entry['method'] = 'WINRM';
        $entry['proto'] = 'winrm';
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
                'port' => 5985,
                'path' => 'WinRM internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    // ---- Byte / string helpers ----------------------------------------------------------------

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

    /**
     * Interleaves an ASCII string to UTF-16LE for our own output (persona names are ASCII), keeping
     * the emulator free of an mbstring dependency.
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
    private static function printable(string $str): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $str) ?? '';
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 5985;
    }
}
