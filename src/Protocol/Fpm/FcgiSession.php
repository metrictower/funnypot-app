<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Fpm;

/**
 * Per-connection FastCGI state machine (FP-0204). Fed inbound bytes, it reassembles records, drives
 * BEGIN_REQUEST -> PARAMS -> STDIN -> request-complete, classifies the request ({@see FcgiThreat}),
 * quarantines any injected PHP, and returns the inert response bytes (FCGI_STDOUT + FCGI_END_REQUEST).
 * Management records (GET_VALUES) are answered with GET_VALUES_RESULT.
 *
 * INERT: the captured STDIN/PARAMS are logged and quarantined (never required, eval'd, or included),
 * the response body is a fixed persona page (no attacker bytes reflected), and the status is always
 * app-chosen. A decode fault throws to the server, which closes only that connection (never a crash).
 *
 * Testable without a socket: feed bytes to {@see receive()}, inspect the returned response and the
 * logger/quarantine callbacks.
 */
final class FcgiSession
{
    /** @var callable(array<string,mixed>):void */
    private $logger;
    /** @var callable(string, array<string,string>):?string|null  (payload, params) => stored path|null */
    private $quarantine;

    /** Incomplete-record buffer ceiling: a single record maxes ~65.8KB, so a buffer past this is hostile. */
    private const INBUF_CAP = 131072;

    private string $inbuf = '';

    /** Active request state. FPM default is non-multiplexed, so we track one request at a time. */
    private ?int $requestId = null;
    private int $role = 0;
    private string $paramsBuf = '';
    private bool $paramsClosed = false;
    private string $stdin = '';
    private int $stdinTotal = 0;
    private bool $stdinClosed = false;
    private bool $completed = false;

    /**
     * @param callable(array<string,mixed>):void $logger
     * @param callable(string, array<string,string>):?string|null $quarantine
     */
    public function __construct(
        private FcgiConfig $config,
        callable $logger,
        ?callable $quarantine = null,
        private string $ip = ''
    ) {
        $this->logger = $logger;
        $this->quarantine = $quarantine;
    }

    /**
     * Feed inbound bytes; return the bytes to write back (possibly ''). Decodes every whole record now
     * buffered and advances the state machine.
     */
    public function receive(string $bytes): string
    {
        $this->inbuf .= $bytes;
        [$records, $consumed] = FastCgiRecord::decode($this->inbuf);
        $this->inbuf = \substr($this->inbuf, $consumed);
        // A record that never completes must not grow the buffer unbounded (throws -> server closes conn).
        if (\strlen($this->inbuf) > self::INBUF_CAP) {
            throw new \RuntimeException('FastCGI: inbound record buffer exceeded cap');
        }

        $out = '';
        foreach ($records as $rec) {
            $out .= $this->onRecord($rec);
        }

        return $out;
    }

    private function onRecord(FastCgiRecord $rec): string
    {
        switch ($rec->type) {
            case FastCgiRecord::TYPE_GET_VALUES:
                return $this->buildGetValuesResult();

            case FastCgiRecord::TYPE_BEGIN_REQUEST:
                // content: role(2 BE), flags(1), reserved(5)
                $this->requestId = $rec->requestId;
                $this->role = \strlen($rec->content) >= 2
                    ? ((\ord($rec->content[0]) << 8) | \ord($rec->content[1]))
                    : FastCgiRecord::ROLE_RESPONDER;
                $this->paramsBuf = '';
                $this->paramsClosed = false;
                $this->stdin = '';
                $this->stdinTotal = 0;
                $this->stdinClosed = false;
                $this->completed = false;

                return '';

            case FastCgiRecord::TYPE_PARAMS:
                if ($rec->content === '') {
                    $this->paramsClosed = true;
                } else {
                    // Bound the PARAMS stream buffer; a flood of PARAMS records can't grow memory.
                    if (\strlen($this->paramsBuf) < $this->config->maxStdin) {
                        $this->paramsBuf .= $rec->content;
                    }
                }

                return $this->maybeComplete();

            case FastCgiRecord::TYPE_STDIN:
                if ($rec->content === '') {
                    $this->stdinClosed = true;
                } else {
                    $this->stdinTotal += \strlen($rec->content);
                    // Keep draining past the cap (stay in-protocol) but stop storing.
                    if (\strlen($this->stdin) < $this->config->maxStdin) {
                        $this->stdin .= \substr($rec->content, 0, $this->config->maxStdin - \strlen($this->stdin));
                    }
                }

                return $this->maybeComplete();

            case FastCgiRecord::TYPE_ABORT_REQUEST:
                $this->completed = true;

                return $this->endRequest();

            default:
                return '';
        }
    }

    /** When PARAMS and STDIN are both closed, classify + respond exactly once. */
    private function maybeComplete(): string
    {
        if ($this->completed || $this->requestId === null) {
            return '';
        }
        // A request with no STDIN stream still completes once PARAMS close (GET-style); treat a closed
        // PARAMS with a closed-or-absent STDIN as complete.
        if (!$this->paramsClosed || !$this->stdinClosed) {
            return '';
        }
        $this->completed = true;

        $params = FastCgiRecord::decodeParams($this->paramsBuf);
        $verdict = FcgiThreat::classify($params, $this->stdin);

        $storedPath = null;
        if ($verdict['critical'] && $this->quarantine !== null && $this->stdin !== '') {
            $storedPath = ($this->quarantine)($this->stdin, $params);
        }

        $entry = [
            'event' => $verdict['class'],
            'ip' => $this->ip,
            'critical' => $verdict['critical'],
            'reasons' => $verdict['reasons'],
            'script' => $params['SCRIPT_FILENAME'] ?? ($params['REQUEST_URI'] ?? ''),
        ];
        if ($this->stdin !== '') {
            $entry['command'] = $this->stdin;
            $entry['body'] = $this->stdin;
        }
        if ($storedPath !== null) {
            $entry['quarantine'] = $storedPath;
        }
        ($this->logger)($entry);

        return $this->respond();
    }

    /** FCGI_STDOUT (CGI headers + inert body) + empty STDOUT (EOF) + FCGI_END_REQUEST, same requestId. */
    private function respond(): string
    {
        $rid = $this->requestId ?? 1;
        $body = "<!DOCTYPE html>\n<html><head><title>200 OK</title></head><body><h1>It works</h1></body></html>\n";
        $headers = "Status: 200 OK\r\n"
            . "Content-Type: text/html; charset=UTF-8\r\n"
            . 'X-Powered-By: ' . $this->config->poweredBy() . "\r\n"
            . "\r\n";

        return FastCgiRecord::encode(FastCgiRecord::TYPE_STDOUT, $rid, $headers . $body)
            . FastCgiRecord::encode(FastCgiRecord::TYPE_STDOUT, $rid, '')
            . $this->endRequest();
    }

    private function endRequest(): string
    {
        $rid = $this->requestId ?? 1;
        // appStatus(4 BE) = 0, protocolStatus(1) = REQUEST_COMPLETE, reserved(3)
        $content = "\x00\x00\x00\x00" . \chr(FastCgiRecord::REQUEST_COMPLETE) . "\x00\x00\x00";

        return FastCgiRecord::encode(FastCgiRecord::TYPE_END_REQUEST, $rid, $content);
    }

    /** Answer a capability probe with plausible non-multiplexing limits (management requestId 0). */
    private function buildGetValuesResult(): string
    {
        $pairs = [
            'FCGI_MAX_CONNS' => '1',
            'FCGI_MAX_REQS' => '1',
            'FCGI_MPXS_CONNS' => '0',
        ];
        $stream = '';
        foreach ($pairs as $name => $value) {
            $stream .= self::encodeLen(\strlen($name)) . self::encodeLen(\strlen($value)) . $name . $value;
        }

        return FastCgiRecord::encode(FastCgiRecord::TYPE_GET_VALUES_RESULT, 0, $stream);
    }

    private static function encodeLen(int $n): string
    {
        if ($n < 128) {
            return \chr($n);
        }

        return \chr((($n >> 24) & 0x7F) | 0x80)
            . \chr(($n >> 16) & 0xFF)
            . \chr(($n >> 8) & 0xFF)
            . \chr($n & 0xFF);
    }
}
