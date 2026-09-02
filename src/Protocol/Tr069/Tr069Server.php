<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Tr069;

/**
 * Zero-dependency, single-process TCP server for the low-interaction TR-069 / CWMP honeypot (7547,
 * alias 7548). CWMP is SOAP 1.1 over plain HTTP, so the emulator speaks just enough HTTP in pure PHP
 * — a minimal request-line + header parser, bodies framed by Content-Length — on a non-blocking
 * stream_select event loop, to pose as a vulnerable broadband gateway (CPE) and harvest the router
 * worms that hammer 7547 across the internet.
 *
 * A minimal HTTP parser is embedded here on purpose: this is HTTP framing on a dedicated port, not a
 * web app, so it never pulls in funnypot-core. The transport mirrors the WinRM emulator class-for-
 * class; duplication of the minimal parser across emulators is intentional (no shared base).
 *
 * The box is the CPE the worm is looking for, never an ACS: it never initiates an Inform. It exposes a
 * plausible connection-request GET (answered 401 Digest / a RomPager landing page) and an exposed
 * TR-064 / CWMP POST endpoint that accepts the worm's RPCs and returns a plausible success SOAP so the
 * worm believes it succeeded and moves on to its download step — after we have captured the payload.
 *
 * 100% inert. The injected command is only ever a string to parse and log; the captured C2 download
 * URL is logged only — never fetched, resolved, or contacted (no exec/eval, no fopen/curl/fsockopen,
 * no DNS). Attacker SOAP is parsed by regex on the raw bytes, never fed to a DOM/SimpleXML parser, so
 * the honeypot itself cannot be turned into an XXE SSRF pivot or hit with billion-laughs. Status is
 * always app-chosen (200/401/400/500), never model-chosen.
 *
 * RomPager/4.07 alongside the other stack banners on the box (Microsoft-HTTPAPI on WinRM, the Oracle
 * TNS listener, ...) is the accepted poly-stack tell: breadth of bait over single-stack coherence.
 */
final class Tr069Server
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const IDLE_TIMEOUT = 120; // seconds
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms
    private const INBUF_CAP = 65536; // a CWMP request is small; multi-NewNTPServer bodies are a few KB
    private const MAX_MESSAGES_PER_PASS = 64; // bound pipelined requests processed in one pass

    // Caps on attacker-supplied strings before they reach the log.
    private const MAX_CMD_LEN = 2048;
    private const MAX_URL_LEN = 512;
    private const MAX_BODY_LOG = 2048;

    // CPU architecture tokens the multi-arch droppers fetch, longest-first so x86_64 beats x86 and
    // arm7 beats arm during matching.
    private const ARCH_TOKENS = [
        'x86_64', 'armv7l', 'armv6l', 'armv5l', 'mips64', 'mipsel', 'powerpc',
        'arm7', 'arm6', 'arm5', 'mpsl', 'mips', 'i686', 'i586', 'i486',
        'x86', 'arm', 'sh4', 'ppc', 'sparc', 'spc', 'm68k', 'arc',
    ];

    private int $boundPort = 7547;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private Tr069Config $config,
        private $logger
    ) {
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:7547").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-cwmp: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        $this->boundPort = $port;
        fwrite(STDERR, "funnypot-cwmp listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:Tr069Session,ip:string}> $conns */
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

                // Guard against inbound buffer exhaustion — a real CWMP request is small.
                if (strlen($session->inbuf) > self::INBUF_CAP) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Fault isolation: a malformed request must close only this connection, never escape
                // the loop and crash the listener (degrade, never crash).
                try {
                    $this->processInbound($session);
                } catch (\Throwable $e) {
                    $this->logFault($conns[$id]['ip'] ?? '', $e, $port);
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
        $session = new Tr069Session($ip, $clientPort, $id);

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "CWMP connection from {$ip}:{$clientPort}",
            'severity' => 'low',
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
    public function processInbound(Tr069Session $s): void
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

            // A CWMP POST carries a SOAP body. Wait for the full Content-Length before consuming the
            // message so a split body does not desync the framing.
            $contentLength = self::contentLength($headerBlock);
            if ($contentLength > 0 && strlen($s->inbuf) < $bodyStart + $contentLength) {
                if ($bodyStart + $contentLength > self::INBUF_CAP) {
                    $this->logUnknown($s, 'oversized request body');
                    $s->outbuf .= $this->build400();
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

    private function handleRequest(Tr069Session $s, string $message): void
    {
        $req = self::parseRequest($message);
        if ($req === null) {
            $this->logUnknown($s, 'malformed HTTP request');
            $s->outbuf .= $this->build400();
            $s->close = true;

            return;
        }

        // Remember the client fingerprint the first time we see it.
        if ($req['userAgent'] !== null && $s->userAgent === null) {
            $s->userAgent = $req['userAgent'];
        }
        if ($req['soapAction'] !== null) {
            $s->soapAction = $req['soapAction'];
        }

        $method = strtoupper((string) $req['method']);

        if ($method === 'POST') {
            $this->handleSoap($s, $req);

            return;
        }

        if ($method === 'GET') {
            // A real CPE serves a RomPager login page on / and challenges the ACS connection-request
            // path with Digest. Both read like a real gateway and grant nothing.
            if ($req['path'] === '/' || $req['path'] === '') {
                $this->logProbe($s, $req, null, 'GET landing page', 'low');
                $s->outbuf .= $this->buildRomPagerPage();
            } else {
                $this->logProbe($s, $req, null, 'connection-request -> 401 Digest', 'low');
                $s->outbuf .= $this->buildDigest401();
            }
            $s->close = true;

            return;
        }

        // Any other method: unmodelled. Answer 400 and close, like a terse embedded HTTP stack.
        $this->logUnknown($s, 'unsupported method ' . self::printable($method));
        $s->outbuf .= $this->build400();
        $s->close = true;
    }

    /**
     * The exploit / RPC surface. Derives the RPC (body element first, SOAPAction fallback), scans every
     * candidate parameter value for a command-injection, and answers with the plausible per-RPC frame
     * (a SOAP Fault in low mode). The exploit is captured regardless of mode; the response only decides
     * whether the worm believes it succeeded.
     *
     * @param array<string,mixed> $req
     */
    private function handleSoap(Tr069Session $s, array $req): void
    {
        $body = (string) $req['body'];
        $rpc = self::extractRpcMethod($body, $s->soapAction);
        $values = self::extractParamValues($body);

        $hit = null;
        foreach ($values as $pv) {
            if (self::detectInjection($pv['value'])) {
                $hit = $pv;
                break;
            }
        }

        if ($hit !== null) {
            $this->logExploit($s, $req, $rpc, $hit, $body);
        } elseif ($rpc === 'Inform') {
            $this->logInform($s, $req, $body);
            $s->outbuf .= $this->buildInformResponse();
            $s->close = true;

            return;
        } elseif ($rpc !== null) {
            $this->logProbe($s, $req, $rpc, self::describeRpc($rpc, $values), 'medium');
        } else {
            // Parseable request but no recognisable RPC (empty / no-Content-Length POST, or an
            // envelope we do not model).
            if (trim($body) === '' || strpos($body, '<') === false) {
                $this->logUnknown($s, 'empty or non-SOAP POST body');
                $s->outbuf .= $this->build400();
                $s->close = true;

                return;
            }
            $this->logProbe($s, $req, null, 'unrecognised SOAP body', 'low');
        }

        $s->outbuf .= $this->buildRpcResponse($rpc);
        $s->close = true;
    }

    // ---- SOAP / CWMP parsing (regex on raw bytes — never a DOM/SimpleXML parser) ----------------

    /**
     * Derives the RPC method name from the first child element of the SOAP Body, falling back to the
     * SOAPAction header (which may be quoted, namespaced with # or :, or absent). Returns null if none.
     */
    public static function extractRpcMethod(string $body, ?string $soapAction = null): ?string
    {
        if (preg_match('~<(?:[\w.\-]+:)?Body\b[^>]*>\s*<(?:([\w.\-]+):)?([A-Za-z][\w.\-]*)~s', $body, $m) === 1) {
            return $m[2];
        }

        if ($soapAction !== null && $soapAction !== '') {
            $a = trim($soapAction, " \t\"'");
            if ($a !== '' && strtolower($a) !== 'null') {
                $sep = max((int) strrpos($a, '#'), (int) strrpos($a, '/'), (int) strrpos($a, ':'));
                $name = $sep > 0 ? substr($a, $sep + 1) : $a;
                $name = trim($name);
                if ($name !== '' && preg_match('~^[A-Za-z][\w.\-]*$~', $name) === 1) {
                    return $name;
                }
            }
        }

        return null;
    }

    /**
     * Extracts every candidate parameter value that could carry a command-injection: TR-064 New*
     * elements, SetParameterValues Name/Value structs, and Download / URL-bearing fields. Regex on the
     * raw bytes only — XML entities are never expanded.
     *
     * @return list<array{name:string,value:string}>
     */
    public static function extractParamValues(string $body): array
    {
        $out = [];

        // TR-064 New* elements (NewNTPServer1..5, NewStatusURL, NewDownloadURL, ...).
        if (preg_match_all('~<(New[\w.\-]*)\b[^>]*>(.*?)</\1>~s', $body, $mm, PREG_SET_ORDER)) {
            foreach ($mm as $m) {
                $out[] = ['name' => $m[1], 'value' => self::stripCdata($m[2])];
            }
        }

        // SetParameterValues ParameterValueStruct: <Name>..</Name><Value>..</Value> pairs.
        if (preg_match_all(
            '~<(?:[\w.\-]+:)?Name>(.*?)</(?:[\w.\-]+:)?Name>\s*<(?:[\w.\-]+:)?Value\b[^>]*>(.*?)</(?:[\w.\-]+:)?Value>~s',
            $body,
            $mm,
            PREG_SET_ORDER
        )) {
            foreach ($mm as $m) {
                $out[] = ['name' => self::stripCdata($m[1]), 'value' => self::stripCdata($m[2])];
            }
        }

        // Download / firmware-fetch fields.
        if (preg_match_all('~<(URL|Username|Password|FileType|CommandKey)\b[^>]*>(.*?)</\1>~s', $body, $mm, PREG_SET_ORDER)) {
            foreach ($mm as $m) {
                $out[] = ['name' => $m[1], 'value' => self::stripCdata($m[2])];
            }
        }

        return $out;
    }

    /** Unwraps a single CDATA section if the whole value is one; otherwise returns the value as-is. */
    private static function stripCdata(string $v): string
    {
        $v = trim($v);
        if (preg_match('~^<!\[CDATA\[(.*)\]\]>$~s', $v, $m) === 1) {
            return $m[1];
        }

        return $v;
    }

    /**
     * A value is an injection if any decoding of it carries a shell metacharacter or a downloader verb.
     * Two-plus passes — raw, URL-decoded, and XML/HTML-entity-decoded (recovers %60 / ${IFS} / &amp;&amp;
     * evasion) — lower-cased. Pure string decoding: no entity is ever expanded against a DTD or network.
     */
    public static function detectInjection(string $value): bool
    {
        foreach (self::decodeSurfaces($value) as $s) {
            if (strpos($s, '`') !== false) {
                return true;
            }
            if (strpos($s, '$(') !== false || strpos($s, '${') !== false) {
                return true;
            }
            if (preg_match('~(?:;|&&|\|\||\|)\s*[\w./]~', $s) === 1) {
                return true;
            }
            if (preg_match('~\b(?:wget|curl|tftp|ftpget|busybox)\b~', $s) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * The decoded surfaces a value is matched against: the raw value, one rawurldecode pass, and an
     * XML/HTML entity decode. All lower-cased.
     *
     * @return list<string>
     */
    private static function decodeSurfaces(string $value): array
    {
        $raw = strtolower($value);
        $url = strtolower(rawurldecode($value));
        $ent = strtolower(html_entity_decode($value, ENT_QUOTES | ENT_HTML5));
        // Entity-then-URL, since worms XML-encode a URL-encoded payload.
        $entUrl = strtolower(rawurldecode(html_entity_decode($value, ENT_QUOTES | ENT_HTML5)));

        return array_values(array_unique([$raw, $url, $ent, $entUrl]));
    }

    /** The most-decoded, human-readable form of a value — used for the captured command string. */
    private static function decodeCommand(string $value): string
    {
        return rawurldecode(html_entity_decode($value, ENT_QUOTES | ENT_HTML5));
    }

    /**
     * Extracts every malware-download target from an injected command: http(s) URLs, and the busybox
     * tftp / ftpget cradles whose host and file operands appear in variable order. Returns one entry
     * per target with a normalised url, the C2 host, and the file name.
     *
     * @return list<array{url:string,host:string,file:string}>
     */
    public static function extractDownloadUrls(string $command): array
    {
        $out = [];
        $lc = $command;

        // http(s):// URLs.
        if (preg_match_all('~\bhttps?://[^\s\'"`;|&()<>]+~i', $lc, $mm)) {
            foreach ($mm[0] as $url) {
                $url = rtrim($url, '.,\\');
                $host = (string) parse_url($url, PHP_URL_HOST);
                $port = parse_url($url, PHP_URL_PORT);
                if ($host !== '' && $port) {
                    $host .= ':' . $port;
                }
                $path = (string) parse_url($url, PHP_URL_PATH);
                $file = $path !== '' ? basename($path) : '';
                $out[] = ['url' => $url, 'host' => $host, 'file' => $file];
            }
        }

        // busybox tftp / ftpget — operand order varies, so classify each token rather than assume a
        // fixed host/file position.
        if (preg_match_all('~\b(tftp|ftpget)\b([^;|&`\n\r]*)~i', $lc, $mm, PREG_SET_ORDER)) {
            foreach ($mm as $m) {
                $verb = strtolower($m[1]);
                $parsed = self::parseTftpLikeArgs($m[2]);
                if ($parsed['host'] === '') {
                    continue;
                }
                $scheme = $verb === 'ftpget' ? 'ftp' : 'tftp';
                $url = $scheme . '://' . $parsed['host'] . ($parsed['file'] !== '' ? '/' . ltrim($parsed['file'], '/') : '');
                $out[] = ['url' => $url, 'host' => $parsed['host'], 'file' => $parsed['file']];
            }
        }

        // Dedupe by url.
        $seen = [];
        $unique = [];
        foreach ($out as $e) {
            if (isset($seen[$e['url']])) {
                continue;
            }
            $seen[$e['url']] = true;
            $unique[] = $e;
        }

        return $unique;
    }

    /**
     * Classifies the operands of a tftp/ftpget invocation into host + remote file, tolerating the many
     * busybox operand orders (`-g -r file host`, `-r file -g host`, `host -c get file`, `-l local -r
     * remote host`, `ftpget host local remote`). Flags with a value (-r/-l/-c) consume the next token;
     * `get`/`put` verbs are skipped; the host is the first bare token that resembles an IP/hostname.
     *
     * @return array{host:string,file:string}
     */
    private static function parseTftpLikeArgs(string $args): array
    {
        $tokens = preg_split('~\s+~', trim($args)) ?: [];
        $host = '';
        $file = '';
        $localFlagFile = '';

        for ($i = 0; $i < count($tokens); $i++) {
            $t = $tokens[$i];
            if ($t === '') {
                continue;
            }
            if ($t[0] === '-') {
                // Combined short flags; -r and -l take the next token as a filename.
                if (strpos($t, 'r') !== false && isset($tokens[$i + 1])) {
                    $file = $file !== '' ? $file : $tokens[++$i];
                } elseif (strpos($t, 'l') !== false && isset($tokens[$i + 1])) {
                    $localFlagFile = $tokens[++$i];
                } elseif (strpos($t, 'c') !== false && isset($tokens[$i + 1]) && in_array(strtolower($tokens[$i + 1]), ['get', 'put'], true)) {
                    // -c get <file>
                    $i++;
                    if (isset($tokens[$i + 1])) {
                        $file = $file !== '' ? $file : $tokens[++$i];
                    }
                }
                continue;
            }
            if (in_array(strtolower($t), ['get', 'put'], true)) {
                if (isset($tokens[$i + 1])) {
                    $file = $file !== '' ? $file : $tokens[++$i];
                }
                continue;
            }
            if ($host === '' && self::looksLikeHost($t)) {
                $host = $t;
                continue;
            }
            // First bare non-host token after the host is a filename candidate (ftpget host file).
            if ($host !== '' && $file === '' && !self::looksLikeHost($t)) {
                $file = $t;
            }
        }

        if ($file === '' && $localFlagFile !== '') {
            $file = $localFlagFile;
        }

        return ['host' => $host, 'file' => $file !== '' ? basename($file) : ''];
    }

    /** A bare token that reads like an IPv4 address or a dotted hostname (not a bare filename). */
    private static function looksLikeHost(string $t): bool
    {
        if (filter_var($t, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        return preg_match('~^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$~', $t) === 1;
    }

    /**
     * The CPU architectures a dropper fetches, inferred from the command / URL tokens. Longest tokens
     * are matched first so x86_64 beats x86 and arm7 beats arm.
     *
     * @return list<string>
     */
    public static function inferArch(string $command): array
    {
        $lc = strtolower($command);
        $found = [];
        foreach (self::ARCH_TOKENS as $tok) {
            if (preg_match('~(?<![a-z0-9])' . preg_quote($tok, '~') . '(?![a-z0-9])~', $lc) === 1) {
                $found[$tok] = true;
            }
        }

        // Collapse an already-more-specific match so we do not list both arm and arm7 for one token.
        $result = array_keys($found);
        $filtered = [];
        foreach ($result as $tok) {
            $covered = false;
            foreach ($result as $other) {
                if ($other !== $tok && strpos($other, $tok) === 0 && strlen($other) > strlen($tok)) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                $filtered[] = $tok;
            }
        }

        return $filtered;
    }

    // ---- HTTP request parsing (shared shape with the sibling emulators) ------------------------

    /**
     * Parses an HTTP request message. Returns null on any malformed request line so the caller can log
     * it as an unknown probe rather than faulting.
     *
     * @return array{method:string,uri:string,version:string,path:string,headers:array<string,string>,userAgent:?string,soapAction:?string,body:string}|null
     */
    public static function parseRequest(string $message): ?array
    {
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
            $headers[$name] = $value; // last value wins; adequate for the fields we read
        }

        return [
            'method' => $method,
            'uri' => $uri,
            'version' => $version,
            'path' => self::pathFromUri($uri),
            'headers' => $headers,
            'userAgent' => $headers['user-agent'] ?? null,
            'soapAction' => $headers['soapaction'] ?? null,
            'body' => $body,
        ];
    }

    /** Extracts the request path from an HTTP request-target (strips absolute-form scheme/host + query). */
    public static function pathFromUri(string $uri): string
    {
        if ($uri === '*') {
            return '*';
        }
        if (preg_match('#^https?://[^/]+(/\S*)?$#i', $uri, $m)) {
            $uri = ($m[1] ?? '') !== '' ? $m[1] : '/';
        }
        $q = strpos($uri, '?');
        if ($q !== false) {
            $uri = substr($uri, 0, $q);
        }

        return $uri === '' ? '/' : $uri;
    }

    private static function contentLength(string $headerBlock): int
    {
        if (preg_match('/^content-length\s*:\s*(\d+)/im', $headerBlock, $m)) {
            return (int) $m[1];
        }

        return 0;
    }

    // ---- Response building ---------------------------------------------------------------------

    /**
     * Builds an HTTP response carrying the CPE Server banner and a Date so it reads like a real
     * embedded HTTP stack; Content-Length is set from the body.
     *
     * @param array<string,?string> $headers
     */
    public function buildResponse(int $code, string $reason, array $headers, string $body = '', bool $close = true): string
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

    /** Picks the plausible per-RPC response frame (or a SOAP Fault in low mode). */
    private function buildRpcResponse(?string $rpc): string
    {
        if ($this->config->mode === Tr069Config::MODE_LOW) {
            return $this->buildFault();
        }

        switch ($rpc) {
            case 'SetNTPServers':
                return $this->buildSetNtpServersResponse();
            case 'SetParameterValues':
                return $this->buildSetParameterValuesResponse();
            case 'GetParameterValues':
            case 'GetParameterNames':
                return $this->buildGetParameterValuesResponse();
            case 'Download':
                return $this->buildDownloadResponse();
            case 'SetProvisioningCode':
                return $this->buildSetProvisioningCodeResponse();
            case 'Reboot':
                return $this->buildSimpleResponse('cwmp', 'RebootResponse');
            case 'FactoryReset':
                return $this->buildSimpleResponse('cwmp', 'FactoryResetResponse');
            case 'Inform':
                return $this->buildInformResponse();
            case null:
                return $this->buildGenericResponse('Response');
            default:
                return $this->buildGenericResponse($rpc . 'Response');
        }
    }

    private function soapResponse(string $inner, string $extraNs = ''): string
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"'
            . ' xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"'
            . ' xmlns:cwmp="urn:dslforum-org:cwmp-1-0"'
            . ' xmlns:u="urn:dslforum-org:service:Time:1"'
            . ($extraNs !== '' ? ' ' . $extraNs : '') . '>' . "\n"
            . '<SOAP-ENV:Header><cwmp:ID SOAP-ENV:mustUnderstand="1">1</cwmp:ID></SOAP-ENV:Header>' . "\n"
            . '<SOAP-ENV:Body>' . $inner . '</SOAP-ENV:Body>' . "\n"
            . '</SOAP-ENV:Envelope>' . "\n";

        return $this->buildResponse(200, 'OK', ['Content-Type' => 'text/xml; charset="utf-8"'], $xml);
    }

    private function buildSetNtpServersResponse(): string
    {
        return $this->soapResponse('<u:SetNTPServersResponse></u:SetNTPServersResponse>');
    }

    private function buildSetParameterValuesResponse(): string
    {
        return $this->soapResponse('<cwmp:SetParameterValuesResponse><Status>0</Status></cwmp:SetParameterValuesResponse>');
    }

    private function buildDownloadResponse(): string
    {
        $inner = '<cwmp:DownloadResponse>'
            . '<Status>1</Status>'
            . '<StartTime>0001-01-01T00:00:00Z</StartTime>'
            . '<CompleteTime>0001-01-01T00:00:00Z</CompleteTime>'
            . '</cwmp:DownloadResponse>';

        return $this->soapResponse($inner);
    }

    private function buildSetProvisioningCodeResponse(): string
    {
        return $this->soapResponse('<u:SetProvisioningCodeResponse></u:SetProvisioningCodeResponse>');
    }

    private function buildSimpleResponse(string $prefix, string $element): string
    {
        return $this->soapResponse("<{$prefix}:{$element}></{$prefix}:{$element}>");
    }

    private function buildGenericResponse(string $element): string
    {
        $element = preg_replace('~[^A-Za-z0-9_]~', '', $element) ?: 'Response';

        return $this->soapResponse("<u:{$element}></u:{$element}>");
    }

    /** A small persona parameter set answered to recon (GetParameterValues) — no real data. */
    private function buildGetParameterValuesResponse(): string
    {
        $params = [
            'InternetGatewayDevice.DeviceInfo.Manufacturer' => 'OUI ' . $this->config->manufacturerOui,
            'InternetGatewayDevice.DeviceInfo.ManufacturerOUI' => $this->config->manufacturerOui,
            'InternetGatewayDevice.DeviceInfo.ModelName' => $this->config->model,
            'InternetGatewayDevice.DeviceInfo.ProductClass' => $this->config->productClass(),
            'InternetGatewayDevice.DeviceInfo.SerialNumber' => $this->config->serialNumber(),
            'InternetGatewayDevice.DeviceInfo.SoftwareVersion' => $this->config->firmware,
            'InternetGatewayDevice.DeviceInfo.HardwareVersion' => '1.0',
        ];

        $structs = '';
        foreach ($params as $name => $value) {
            $structs .= '<ParameterValueStruct>'
                . '<Name>' . self::xmlEscape($name) . '</Name>'
                . '<Value xsi:type="xsd:string">' . self::xmlEscape($value) . '</Value>'
                . '</ParameterValueStruct>';
        }

        $inner = '<cwmp:GetParameterValuesResponse>'
            . '<ParameterList SOAP-ENC:arrayType="cwmp:ParameterValueStruct[' . count($params) . ']">'
            . $structs
            . '</ParameterList>'
            . '</cwmp:GetParameterValuesResponse>';

        return $this->soapResponse($inner, 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"');
    }

    private function buildInformResponse(): string
    {
        return $this->soapResponse('<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>');
    }

    /** A SOAP 1.1 Fault (HTTP 500) that still reads like a real CPE rejecting the RPC (low mode). */
    private function buildFault(): string
    {
        $inner = '<SOAP-ENV:Fault>'
            . '<faultcode>Client</faultcode>'
            . '<faultstring>CWMP fault</faultstring>'
            . '<detail><cwmp:Fault>'
            . '<FaultCode>9003</FaultCode>'
            . '<FaultString>Invalid arguments</FaultString>'
            . '</cwmp:Fault></detail>'
            . '</SOAP-ENV:Fault>';

        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
            . '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"'
            . ' xmlns:cwmp="urn:dslforum-org:cwmp-1-0">' . "\n"
            . '<SOAP-ENV:Body>' . $inner . '</SOAP-ENV:Body>' . "\n"
            . '</SOAP-ENV:Envelope>' . "\n";

        return $this->buildResponse(500, 'Internal Server Error', ['Content-Type' => 'text/xml; charset="utf-8"'], $xml);
    }

    /** The 401 Digest challenge a real CPE answers the ACS connection-request with. Grants nothing. */
    private function buildDigest401(): string
    {
        $nonce = bin2hex(random_bytes(16));
        $opaque = bin2hex(random_bytes(8));
        $challenge = sprintf(
            'Digest realm="%s", qop="auth", nonce="%s", opaque="%s"',
            $this->config->realm,
            $nonce,
            $opaque
        );

        return $this->buildResponse(401, 'Unauthorized', ['WWW-Authenticate' => $challenge], '');
    }

    /** A minimal RomPager-style landing page for a bare GET /. Cosmetic; exposes nothing. */
    private function buildRomPagerPage(): string
    {
        $body = "<html><head><title>Broadband Router</title></head>\r\n"
            . "<body><h2>Broadband Router</h2>\r\n"
            . "<form method=\"post\" action=\"/login.cgi\">\r\n"
            . "<p>Username: <input type=\"text\" name=\"username\"></p>\r\n"
            . "<p>Password: <input type=\"password\" name=\"password\"></p>\r\n"
            . "<p><input type=\"submit\" value=\"Login\"></p>\r\n"
            . "</form></body></html>\r\n";

        return $this->buildResponse(200, 'OK', ['Content-Type' => 'text/html'], $body);
    }

    private function build400(): string
    {
        $body = "<html><head><title>Bad Request</title></head><body><h2>400 Bad Request</h2></body></html>\r\n";

        return $this->buildResponse(400, 'Bad Request', ['Content-Type' => 'text/html'], $body);
    }

    // ---- Logging -------------------------------------------------------------------------------

    /**
     * Records a captured command-injection: the injected shell string, every C2 download URL, the C2
     * host, binary name(s) and CPU arch(es) — all sanitised and length-capped. The command is only
     * ever a string here; nothing is executed and no URL is fetched.
     *
     * @param array<string,mixed>       $req
     * @param array{name:string,value:string} $hit
     */
    private function logExploit(Tr069Session $s, array $req, ?string $rpc, array $hit, string $body): void
    {
        $command = self::decodeCommand($hit['value']);
        $downloads = self::extractDownloadUrls($command);

        $urls = [];
        $hosts = [];
        $files = [];
        foreach ($downloads as $d) {
            $urls[] = $d['url'];
            if ($d['host'] !== '') {
                $hosts[] = $d['host'];
            }
            if ($d['file'] !== '') {
                $files[] = $d['file'];
            }
        }
        // chmod / ./run binary targets, in case they name a binary the URL did not.
        if (preg_match_all('~(?:chmod\s+(?:\+x|[0-7]{3,4})\s+|\./)([\w.\-]+)~i', $command, $bm)) {
            foreach ($bm[1] as $b) {
                $files[] = $b;
            }
        }
        $arch = self::inferArch($command . ' ' . implode(' ', $urls));

        $this->logEvent([
            'event' => 'cwmp_exploit',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'CWMP command injection via %s (%s) on %s',
                self::printable($rpc ?? 'unknown RPC'),
                self::printable($hit['name']),
                self::printable((string) $req['path'])
            ),
            'rpc' => self::printable($rpc ?? ''),
            'param' => self::printable($hit['name']),
            'command' => self::cap(self::printable($command), self::MAX_CMD_LEN),
            'download_url' => self::cap(self::printable(implode(' ', array_values(array_unique($urls)))), self::MAX_URL_LEN),
            'c2_host' => self::printable(implode(' ', array_values(array_unique($hosts)))),
            'binary' => self::printable(implode(' ', array_values(array_unique($files)))),
            'arch' => self::printable(implode(',', $arch)),
            'body' => self::cap(self::printable($body), self::MAX_BODY_LOG),
            'http_method' => self::printable((string) $req['method']),
            'soap_action' => self::printable((string) ($s->soapAction ?? '')),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => 'critical',
        ]);
    }

    /**
     * Records an Inform-shaped body (a scanner posing as a CPE): the claimed device identity + event
     * codes. We answer InformResponse but are never the ACS ourselves.
     *
     * @param array<string,mixed> $req
     */
    private function logInform(Tr069Session $s, array $req, string $body): void
    {
        $oui = self::firstMatch('~<OUI>(.*?)</OUI>~s', $body);
        $productClass = self::firstMatch('~<ProductClass>(.*?)</ProductClass>~s', $body);
        $serial = self::firstMatch('~<SerialNumber>(.*?)</SerialNumber>~s', $body);
        $events = [];
        if (preg_match_all('~<EventCode>(.*?)</EventCode>~s', $body, $mm)) {
            foreach ($mm[1] as $e) {
                $events[] = trim($e);
            }
        }

        $this->logEvent([
            'event' => 'cwmp_inform',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'CWMP Inform on ' . self::printable((string) $req['path']),
            'oui' => self::printable($oui),
            'product_class' => self::printable($productClass),
            'serial' => self::printable($serial),
            'event_codes' => self::printable(implode(',', $events)),
            'http_method' => self::printable((string) $req['method']),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => 'medium',
        ]);
    }

    /**
     * @param array<string,mixed> $req
     */
    private function logProbe(Tr069Session $s, array $req, ?string $rpc, string $detail, string $severity): void
    {
        $rpcLabel = $rpc !== null ? self::printable($rpc) . ' ' : '';

        $this->logEvent([
            'event' => 'cwmp_probe',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => sprintf(
                'CWMP %s %s%s (%s)',
                self::printable((string) $req['method']),
                $rpcLabel,
                self::printable((string) $req['path']),
                $detail
            ),
            'rpc' => self::printable($rpc ?? ''),
            'http_method' => self::printable((string) $req['method']),
            'soap_action' => self::printable((string) ($s->soapAction ?? '')),
            'user_agent' => self::printable((string) $s->userAgent),
            'severity' => $severity,
        ]);
    }

    private function logUnknown(Tr069Session $s, string $detail): void
    {
        $this->logEvent([
            'event' => 'cwmp_unknown',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'CWMP unmodelled input: ' . self::printable($detail),
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
        $entry['method'] = 'CWMP';
        $entry['proto'] = 'cwmp';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        // FP-0247 (Fix A): TCP accept ⇒ source verified by the three-way handshake, so reportable.
        // `??=` so a per-event override (e.g. an explicit false) stays authoritative.
        $entry['reportable'] ??= true;
        ($this->logger)($entry);
    }

    /** Records a per-connection fault to the event stream without ever escaping the run loop. */
    private function logFault(string $ip, \Throwable $e, int $port): void
    {
        try {
            $this->logEvent([
                'event' => 'error',
                'ip' => $ip,
                'port' => $port,
                'path' => 'CWMP internal fault: ' . $e->getMessage(),
                'severity' => 'low',
            ]);
        } catch (\Throwable $ignored) {
            // keeping the listener alive matters more than this one log line
        }
    }

    // ---- Helpers -------------------------------------------------------------------------------

    private static function describeRpc(string $rpc, array $values): string
    {
        return $rpc . ' with ' . count($values) . ' parameter(s), no injection';
    }

    private static function firstMatch(string $pattern, string $subject): string
    {
        if (preg_match($pattern, $subject, $m) === 1) {
            return trim(self::stripCdata($m[1]));
        }

        return '';
    }

    private static function xmlEscape(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }

    /** Replaces control / non-printable bytes so attacker-supplied strings stay log-safe. */
    private static function printable(string $str): string
    {
        return preg_replace('/[^\x20-\x7E]/', '.', $str) ?? '';
    }

    private static function cap(string $s, int $max): string
    {
        return strlen($s) > $max ? substr($s, 0, $max) . '...' : $s;
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 7547;
    }
}
