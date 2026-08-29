<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Sip;

/**
 * Parser and builder for RFC 3261 SIP messages and RFC 4566 SDP descriptors.
 */
final class SipMessage
{
    public bool $isRequest = false;
    public string $method = '';
    public string $uri = '';
    public string $sipVersion = 'SIP/2.0';

    public int $statusCode = 0;
    public string $reasonPhrase = '';

    /** @var array<string, string> Normalized lowercase header key => raw header value */
    public array $headers = [];

    public string $body = '';

    // Parsed SDP metadata (if application/sdp present)
    public ?string $sdpIp = null;
    public ?int $sdpAudioPort = null;
    /** @var list<int> */
    public array $sdpCodecs = [];

    // Compact header alias mapping (RFC 3261 §7.3.3)
    private const COMPACT_HEADERS = [
        'v' => 'via',
        'f' => 'from',
        't' => 'to',
        'i' => 'call-id',
        'm' => 'contact',
        'c' => 'content-type',
        'l' => 'content-length',
        'k' => 'supported',
    ];

    /**
     * Parses a raw SIP datagram or stream buffer into a SipMessage object.
     * Returns null if incomplete or invalid start line.
     */
    public static function parse(string $raw): ?self
    {
        $raw = ltrim($raw, "\r\n ");
        if ($raw === '') {
            return null;
        }

        // Separate headers from body
        $headerEndPos = strpos($raw, "\r\n\r\n");
        $delimiterLen = 4;
        if ($headerEndPos === false) {
            $headerEndPos = strpos($raw, "\n\n");
            $delimiterLen = 2;
            if ($headerEndPos === false) {
                return null; // Incomplete headers
            }
        }

        $headerText = substr($raw, 0, $headerEndPos);
        $body = substr($raw, $headerEndPos + $delimiterLen);

        $lines = preg_split('/\r?\n/', $headerText);
        if (!$lines || empty($lines[0])) {
            return null;
        }

        $msg = new self();
        $startLine = trim($lines[0]);

        if (preg_match('/^([A-Z]+)\s+([^\s]+)\s+(SIP\/2\.0)$/i', $startLine, $m)) {
            $msg->isRequest = true;
            $msg->method = strtoupper($m[1]);
            $msg->uri = $m[2];
            $msg->sipVersion = strtoupper($m[3]);
        } elseif (preg_match('/^(SIP\/2\.0)\s+(\d{3})\s*(.*)$/i', $startLine, $m)) {
            $msg->isRequest = false;
            $msg->sipVersion = strtoupper($m[1]);
            $msg->statusCode = (int) $m[2];
            $msg->reasonPhrase = $m[3];
        } else {
            return null; // Malformed start line
        }

        // Parse headers with line continuation folding (RFC 3261 §7.3.1)
        $currentKey = null;
        for ($i = 1, $len = count($lines); $i < $len; $i++) {
            $line = $lines[$i];
            if ($line === '') {
                continue;
            }

            if (($line[0] === ' ' || $line[0] === "\t") && $currentKey !== null) {
                // Continuation line
                $msg->headers[$currentKey] .= ' ' . trim($line);
                continue;
            }

            $colon = strpos($line, ':');
            if ($colon !== false) {
                $rawKey = trim(substr($line, 0, $colon));
                $val = trim(substr($line, $colon + 1));
                $normKey = strtolower($rawKey);
                if (isset(self::COMPACT_HEADERS[$normKey])) {
                    $normKey = self::COMPACT_HEADERS[$normKey];
                }
                $msg->headers[$normKey] = $val;
                $currentKey = $normKey;
            }
        }

        // Trim body to Content-Length if specified
        $contentLength = (int) ($msg->getHeader('content-length') ?? strlen($body));
        $msg->body = substr($body, 0, $contentLength);

        // Parse SDP if present
        $contentType = strtolower($msg->getHeader('content-type') ?? '');
        if (str_contains($contentType, 'application/sdp') || str_contains($msg->body, 'm=audio')) {
            $msg->parseSdp();
        }

        return $msg;
    }

    public function getHeader(string $name): ?string
    {
        $k = strtolower($name);
        if (isset(self::COMPACT_HEADERS[$k])) {
            $k = self::COMPACT_HEADERS[$k];
        }

        return $this->headers[$k] ?? null;
    }

    public function getCSeq(): ?string
    {
        return $this->getHeader('cseq');
    }

    public function getCallId(): ?string
    {
        return $this->getHeader('call-id');
    }

    public function getFrom(): ?string
    {
        return $this->getHeader('from');
    }

    public function getTo(): ?string
    {
        return $this->getHeader('to');
    }

    public function getVia(): ?string
    {
        return $this->getHeader('via');
    }

    /**
     * Extracts destination dialed telephone number or extension from Request-URI or To header.
     * e.g. "sip:00123456789@192.168.1.100" -> "00123456789"
     */
    public function getDialedNumber(): string
    {
        $target = $this->uri;
        if (preg_match('/sip:([^@;>]+)/i', $target, $m)) {
            return trim($m[1]);
        }

        $to = $this->getHeader('to') ?? '';
        if (preg_match('/sip:([^@;>]+)/i', $to, $m)) {
            return trim($m[1]);
        }

        return 'unknown';
    }

    /**
     * Parses HTTP Digest Auth parameters from Authorization header.
     * @return array<string, string>
     */
    public function getDigestAuth(): array
    {
        $auth = $this->getHeader('authorization') ?? $this->getHeader('proxy-authorization');
        if (!$auth || !preg_match('/^Digest\s+(.*)$/i', $auth, $m)) {
            return [];
        }

        $params = [];
        preg_match_all('/(\w+)=(?:"([^"]+)"|([^\s,]+))/', $m[1], $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $k = strtolower($match[1]);
            $v = $match[2] !== '' ? $match[2] : ($match[3] ?? '');
            $params[$k] = $v;
        }

        return $params;
    }

    /**
     * Parses SDP connection information and audio media ports (RFC 4566).
     */
    private function parseSdp(): void
    {
        $lines = preg_split('/\r?\n/', $this->body);
        if (!$lines) {
            return;
        }

        foreach ($lines as $line) {
            $line = trim($line);
            if (preg_match('/^c=IN IP4 ([0-9.]+)/i', $line, $m)) {
                $this->sdpIp = $m[1];
            } elseif (preg_match('/^m=audio (\d+)\s+RTP\/AVP\s+(.*)$/i', $line, $m)) {
                $this->sdpAudioPort = (int) $m[1];
                $codecs = preg_split('/\s+/', trim($m[2]));
                if ($codecs) {
                    $this->sdpCodecs = array_map('intval', $codecs);
                }
            }
        }
    }

    /**
     * Response Builder: Generates a SIP response string matching this request.
     * @param array<string, string> $extraHeaders
     */
    public function buildResponse(int $code, string $reason, string $toTag = '', array $extraHeaders = [], string $body = '', string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        $res = "SIP/2.0 {$code} {$reason}\r\n";

        // Required headers copied from request
        if ($via = $this->getHeader('via')) {
            $res .= "Via: {$via}\r\n";
        }
        if ($from = $this->getHeader('from')) {
            $res .= "From: {$from}\r\n";
        }

        $to = $this->getHeader('to') ?? '<sip:unknown>';
        if ($toTag !== '' && !str_contains(strtolower($to), 'tag=')) {
            $to .= ';tag=' . $toTag;
        }
        $res .= "To: {$to}\r\n";

        if ($callId = $this->getHeader('call-id')) {
            $res .= "Call-ID: {$callId}\r\n";
        }
        if ($cseq = $this->getHeader('cseq')) {
            $res .= "CSeq: {$cseq}\r\n";
        }

        $res .= "Server: {$userAgent}\r\n";
        $res .= "User-Agent: {$userAgent}\r\n";

        foreach ($extraHeaders as $k => $v) {
            $res .= "{$k}: {$v}\r\n";
        }

        $res .= "Content-Length: " . strlen($body) . "\r\n\r\n";
        $res .= $body;

        return $res;
    }

    public function buildTrying(string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        return $this->buildResponse(100, 'Trying', '', [], '', $userAgent);
    }

    public function buildRinging(string $toTag, string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        return $this->buildResponse(180, 'Ringing', $toTag, [], '', $userAgent);
    }

    public function buildOk(string $toTag, string $contact, string $sdpBody = '', array $extra = [], string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        $headers = array_merge([
            'Contact' => $contact,
            'Allow' => 'INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE',
            'Supported' => 'replaces, timer',
        ], $extra);

        if ($sdpBody !== '') {
            $headers['Content-Type'] = 'application/sdp';
        }

        return $this->buildResponse(200, 'OK', $toTag, $headers, $sdpBody, $userAgent);
    }

    public function buildUnauthorized(string $toTag, string $realm, string $nonce, string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        return $this->buildResponse(401, 'Unauthorized', $toTag, [
            'WWW-Authenticate' => "Digest algorithm=MD5, realm=\"{$realm}\", nonce=\"{$nonce}\"",
        ], '', $userAgent);
    }

    public function buildForbidden(string $toTag, string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        return $this->buildResponse(403, 'Forbidden', $toTag, [], '', $userAgent);
    }

    public function buildBusy(string $toTag, string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        return $this->buildResponse(486, 'Busy Here', $toTag, [], '', $userAgent);
    }

    public function buildRegisteredOk(string $toTag, string $contact = '', int $expires = 3600, string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        $headers = [
            'Expires' => (string) $expires,
            'Allow' => 'INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE',
        ];
        if ($contact !== '') {
            $headers['Contact'] = $contact;
        }

        return $this->buildResponse(200, 'OK', $toTag, $headers, '', $userAgent);
    }

    /**
     * Checks whether an Authorization header matches a candidate password according to RFC 2617.
     */
    public static function verifyDigest(array $auth, string $password, string $method = 'REGISTER'): bool
    {
        $username = $auth['username'] ?? '';
        $realm = $auth['realm'] ?? 'asterisk';
        $nonce = $auth['nonce'] ?? '';
        $uri = $auth['uri'] ?? '';
        $response = $auth['response'] ?? '';

        if ($username === '' || $nonce === '' || $response === '') {
            return false;
        }

        $ha1 = md5("{$username}:{$realm}:{$password}");
        $ha2 = md5("{$method}:{$uri}");

        $qop = $auth['qop'] ?? '';
        if ($qop !== '' && isset($auth['nc'], $auth['cnonce'])) {
            $expected = md5("{$ha1}:{$nonce}:{$auth['nc']}:{$auth['cnonce']}:{$qop}:{$ha2}");
        } else {
            $expected = md5("{$ha1}:{$nonce}:{$ha2}");
        }

        return hash_equals($expected, $response);
    }

    /**
     * Builds RFC 4566 SDP descriptor for 8000 Hz PCMU (G.711u) audio.
     */
    public static function buildSdp(string $mediaIp, int $audioPort, string $sessionId = '1', string $userAgent = 'Asterisk PBX 20.5.0'): string
    {
        return "v=0\r\n"
            . "o=root {$sessionId} {$sessionId} IN IP4 {$mediaIp}\r\n"
            . "s={$userAgent}\r\n"
            . "c=IN IP4 {$mediaIp}\r\n"
            . "t=0 0\r\n"
            . "m=audio {$audioPort} RTP/AVP 0 101\r\n"
            . "a=rtpmap:0 PCMU/8000\r\n"
            . "a=rtpmap:101 telephone-event/8000\r\n"
            . "a=fmtp:101 0-16\r\n"
            . "a=ptime:20\r\n"
            . "a=sendrecv\r\n";
    }
}
