<?php

declare(strict_types=1);

/** Fixed-loopback bounded raw HTTP/FastCGI client, only for the isolated acceptance image. */
final class IngressWire
{
    private int $requests = 0;
    private int $bytes = 0;
    private int $deadline;

    public function __construct()
    {
        $this->deadline = hrtime(true) + 180_000_000_000;
    }

    public function awaitReady(): void
    {
        $until = hrtime(true) + 10_000_000_000;
        do {
            $ready = true;
            foreach ([80, 443, 9001, 8099] as $port) {
                $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $error, 0.1);
                if ($s === false) {
                    $ready = false;
                } else {
                    fclose($s);
                }
            }
            if ($ready) {
                return;
            }
            usleep(50000);
        } while (hrtime(true) < $until);
        throw new RuntimeException('startup-deadline');
    }

    public function http(int $port, string $host, string $method, string $target, int $spaces = 1,
        string $body = '', array $headers = []): array
    {
        $request = $method . str_repeat(' ', $spaces) . $target . " HTTP/1.1\r\nHost: " . $host
            . "\r\nConnection: close\r\nContent-Length: " . strlen($body) . "\r\n";
        foreach ($headers as $key => $value) {
            $request .= $key . ': ' . $value . "\r\n";
        }
        return $this->partial($port, $host, $request . "\r\n" . $body);
    }

    public function partial(int $port, string $host, string $request): array
    {
        [$response, $elapsed] = $this->exchange($port, $host, $request);
        $parsed = self::parseHttp($response);
        $parsed['elapsed_ms'] = $elapsed;
        return $parsed;
    }

    public static function parseHttp(string $response): array
    {
        if ($response === '') {
            return ['status' => 0, 'headers' => [], 'body' => ''];
        }
        $parts = explode("\r\n\r\n", $response, 2);
        if (count($parts) !== 2 || !preg_match('~^HTTP/1\.[01] ([0-9]{3}) ~', $parts[0], $match)) {
            throw new RuntimeException('malformed-http-response');
        }
        $headers = [];
        foreach (array_slice(explode("\r\n", $parts[0]), 1) as $line) {
            if (!str_contains($line, ':')) {
                throw new RuntimeException('malformed-http-header');
            }
            [$key, $value] = explode(':', $line, 2);
            $headers[strtolower($key)][] = trim($value);
        }
        $body = $parts[1];
        if (isset($headers['transfer-encoding']) && ($headers['transfer-encoding'] !== ['chunked'] || isset($headers['content-length']))) {
            throw new RuntimeException('ambiguous-http-framing');
        }
        if (($headers['transfer-encoding'] ?? []) === ['chunked']) {
            $body = self::unchunk($body);
        } elseif (isset($headers['content-length']) &&
            (count($headers['content-length']) !== 1 || !ctype_digit($headers['content-length'][0])
                || (int) $headers['content-length'][0] !== strlen($body))) {
            throw new RuntimeException('truncated-or-extra-http-body');
        }
        return ['status' => (int) $match[1], 'headers' => $headers, 'body' => $body];
    }

    private static function unchunk(string $body): string
    {
        $result = '';
        while (($end = strpos($body, "\r\n")) !== false) {
            $hex = substr($body, 0, $end);
            if ($hex === '' || strlen($hex) > 8 || !ctype_xdigit($hex)) {
                break;
            }
            $size = hexdec($hex);
            $body = substr($body, $end + 2);
            if ($size === 0 && $body === "\r\n") {
                return $result;
            }
            if (strlen($body) < $size + 2 || substr($body, $size, 2) !== "\r\n") {
                break;
            }
            $result .= substr($body, 0, $size);
            $body = substr($body, $size + 2);
        }
        throw new RuntimeException('malformed-or-truncated-chunks');
    }

    public function fastcgi(string $target, string $body, array $extra): array
    {
        $params = ['GATEWAY_INTERFACE' => 'CGI/1.1', 'SERVER_SOFTWARE' => 'ingress-fixture',
            'REQUEST_METHOD' => 'POST', 'REQUEST_URI' => $target, 'SCRIPT_FILENAME' => '/app/demo/index.php',
            'SCRIPT_NAME' => '/index.php', 'SERVER_PROTOCOL' => 'HTTP/1.1', 'SERVER_PORT' => '80',
            'REMOTE_ADDR' => '192.0.2.13', 'HTTP_HOST' => 'public.ingress.invalid',
            'CONTENT_TYPE' => 'text/plain', 'CONTENT_LENGTH' => (string) strlen($body)] + $extra;
        $encoded = '';
        foreach ($params as $key => $value) {
            $encoded .= self::length(strlen($key)) . self::length(strlen($value)) . $key . $value;
        }
        $request = self::record(1, pack('nCxxxxx', 1, 0)) . self::record(4, $encoded)
            . self::record(4, '') . self::record(5, $body) . self::record(5, '');
        [$raw, $elapsed] = $this->exchange(9001, 'public.ingress.invalid', $request);
        $parsed = self::parseFastcgi($raw);
        $parsed['elapsed_ms'] = $elapsed;
        return $parsed;
    }

    public static function parseFastcgi(string $raw): array
    {
        $out = '';
        $ended = false;
        while (strlen($raw) >= 8) {
            $h = unpack('Cversion/Ctype/nid/nsize/Cpadding/Creserved', substr($raw, 0, 8));
            if ($ended || $h['version'] !== 1 || $h['id'] !== 1 || strlen($raw) < 8 + $h['size'] + $h['padding']) {
                throw new RuntimeException('malformed-fastcgi-record');
            }
            $content = substr($raw, 8, $h['size']);
            $raw = substr($raw, 8 + $h['size'] + $h['padding']);
            if ($h['type'] === 6) {
                $out .= $content;
            } elseif ($h['type'] === 7 && $content !== '') {
                throw new RuntimeException('fastcgi-stderr');
            } elseif ($h['type'] === 3) {
                if ($content !== str_repeat("\0", 8)) {
                    throw new RuntimeException('fastcgi-request-error');
                }
                $ended = true;
            }
        }
        if (!$ended || $raw !== '' || !preg_match('/^Status: ([0-9]{3})[^\r]*\r\n/', $out, $match)) {
            throw new RuntimeException('missing-fastcgi-end-or-status');
        }
        return self::parseHttp('HTTP/1.1 ' . $match[1] . " Response\r\n" . substr($out, strlen($match[0])));
    }

    private static function length(int $length): string
    {
        return $length < 128 ? chr($length) : pack('N', $length | 0x80000000);
    }

    private static function record(int $type, string $body): string
    {
        if (strlen($body) > 65535) {
            throw new RuntimeException('fastcgi-input-budget');
        }
        return pack('CCnnCC', 1, $type, 1, strlen($body), 0, 0) . $body;
    }

    private function exchange(int $port, string $host, string $request): array
    {
        if (!in_array($port, [80, 443, 8099, 9001], true) || !in_array($host,
            ['public.ingress.invalid', 'admin.ingress.invalid', 'ingress-probe.invalid'], true)) {
            throw new RuntimeException('off-target-connection');
        }
        $this->bytes += strlen($request);
        if (++$this->requests > 200 || $this->bytes > 8 * 1024 * 1024 || hrtime(true) >= $this->deadline) {
            throw new RuntimeException('global-wire-budget');
        }
        $start = hrtime(true);
        $until = min($this->deadline, $start + 8_000_000_000);
        $context = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false,
            'allow_self_signed' => true, 'peer_name' => $host, 'SNI_enabled' => true]]);
        $socket = @stream_socket_client(($port === 443 ? 'tls' : 'tcp') . '://127.0.0.1:' . $port,
            $errno, $error, 2, STREAM_CLIENT_CONNECT, $context);
        if ($socket === false) {
            throw new RuntimeException('loopback-connect-failed');
        }
        stream_set_blocking($socket, false);
        $written = 0;
        $response = '';
        try {
            while (!feof($socket)) {
                if (hrtime(true) >= $until) {
                    throw new RuntimeException('peer-did-not-close-within-deadline');
                }
                if ($written < strlen($request)) {
                    $n = @fwrite($socket, substr($request, $written, 8192));
                    if ($n !== false) {
                        $written += $n;
                    }
                }
                $chunk = @fread($socket, 8192);
                if ($chunk !== false) {
                    $response .= $chunk;
                    $this->bytes += strlen($chunk);
                }
                if (strlen($response) > 65536 || $this->bytes > 8 * 1024 * 1024) {
                    throw new RuntimeException('response-byte-budget');
                }
                usleep(1000);
            }
            // A parser may close before consuming a gross request. Partial timeout deliberately
            // keeps our write side open; EOF must originate from nginx, never from this client.
            return [$response, (hrtime(true) - $start) / 1e6];
        } finally {
            fclose($socket);
        }
    }
}
