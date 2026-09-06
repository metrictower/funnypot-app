<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Incremental, binary-safe RESP request parser. It pulls one complete command at a time out of a
 * connection's inbound buffer, preserving every argument's exact bytes (embedded NUL / space / CRLF
 * survive). A partial frame is left untouched for the next read; a malformed frame raises a
 * {@see RespProtocolException} carrying the exact Redis 6.2 wire error.
 *
 * All limits are checked BEFORE any allocation: a declared bulk length is validated and bounded
 * before its bytes are copied, the argument count is bounded before the loop, and one command frame
 * may never exceed the frame cap — so a hostile `$999999999` or `*999999999` header costs nothing.
 *
 * Accepts both the RESP command-array form (`*3\r\n$3\r\nSET\r\n...`) and the bounded inline form
 * (`PING\r\n`, with sdssplitargs-style quoting) that nc/telnet clients use.
 */
final class RespParser
{
    public const DEFAULT_MAX_FRAME = 65536; // one complete inbound frame (bytes)
    public const DEFAULT_MAX_ARGV = 128;    // arguments per command

    public function __construct(
        private int $maxFrame = self::DEFAULT_MAX_FRAME,
        private int $maxArgv = self::DEFAULT_MAX_ARGV
    ) {
    }

    /**
     * Consume the next complete command from $buf (by reference). Returns the command, or null when
     * the buffer does not yet hold a complete frame (in which case $buf is left untouched). An empty
     * command (from `*0`/`*-1`/a blank inline line) is returned as a zero-argument RespCommand for
     * the caller to skip, exactly as Redis ignores it.
     *
     * @throws RespProtocolException on a malformed frame
     */
    public function parse(string &$buf): ?RespCommand
    {
        if ($buf === '') {
            return null;
        }

        return $buf[0] === '*' ? $this->parseMultibulk($buf) : $this->parseInline($buf);
    }

    private function parseMultibulk(string &$buf): ?RespCommand
    {
        $crlf = strpos($buf, "\r\n");
        if ($crlf === false) {
            if (strlen($buf) > $this->maxFrame) {
                throw new RespProtocolException('ERR Protocol error: too big mbulk count string');
            }

            return null; // header line incomplete
        }

        $countStr = substr($buf, 1, $crlf - 1);
        if (!self::isDecimal($countStr, true)) {
            throw new RespProtocolException('ERR Protocol error: invalid multibulk length');
        }
        $count = (int) $countStr;
        if ($count <= 0) {
            $buf = substr($buf, $crlf + 2); // *0 / *-1 — an empty request Redis silently ignores

            return new RespCommand([]);
        }
        if ($count > $this->maxArgv) {
            throw new RespProtocolException('ERR Protocol error: invalid multibulk length');
        }

        $cursor = $crlf + 2;
        $len = strlen($buf);
        $args = [];
        for ($i = 0; $i < $count; $i++) {
            if ($cursor >= $len) {
                return null; // need more bytes for the next bulk header
            }
            if ($buf[$cursor] !== '$') {
                throw new RespProtocolException("ERR Protocol error: expected '$', got '" . $buf[$cursor] . "'");
            }
            $hdr = strpos($buf, "\r\n", $cursor);
            if ($hdr === false) {
                if ($len - $cursor > $this->maxFrame) {
                    throw new RespProtocolException('ERR Protocol error: too big bulk count string');
                }

                return null; // bulk header incomplete
            }
            $lenStr = substr($buf, $cursor + 1, $hdr - $cursor - 1);
            if (!self::isDecimal($lenStr, true)) {
                throw new RespProtocolException('ERR Protocol error: invalid bulk length');
            }
            $bulkLen = (int) $lenStr;
            if ($bulkLen < 0 || $bulkLen > $this->maxFrame) {
                throw new RespProtocolException('ERR Protocol error: invalid bulk length');
            }
            $dataStart = $hdr + 2;
            $dataEnd = $dataStart + $bulkLen + 2; // data + trailing CRLF
            if ($dataEnd > $this->maxFrame) {
                throw new RespProtocolException('ERR Protocol error: invalid multibulk length');
            }
            if ($dataEnd > $len) {
                return null; // body + trailing CRLF not fully arrived yet
            }
            $args[] = substr($buf, $dataStart, $bulkLen);
            $cursor = $dataEnd;
        }

        $buf = substr($buf, $cursor);

        return new RespCommand($args);
    }

    private function parseInline(string &$buf): ?RespCommand
    {
        $nl = strpos($buf, "\n");
        if ($nl === false) {
            if (strlen($buf) > $this->maxFrame) {
                throw new RespProtocolException('ERR Protocol error: too big inline request');
            }

            return null; // no line terminator yet
        }
        if ($nl > $this->maxFrame) {
            throw new RespProtocolException('ERR Protocol error: too big inline request');
        }
        $line = substr($buf, 0, $nl);
        $buf = substr($buf, $nl + 1);
        $line = rtrim($line, "\r");
        if ($line === '') {
            return new RespCommand([]); // blank line — Redis ignores it
        }

        $args = self::splitInline($line);
        if ($args === null) {
            throw new RespProtocolException('ERR Protocol error: unbalanced quotes in request');
        }
        if (count($args) > $this->maxArgv) {
            throw new RespProtocolException('ERR Protocol error: invalid multibulk length');
        }

        return new RespCommand($args);
    }

    /** Decimal validation done lexically before any int cast: digits only, optional leading '-'. */
    private static function isDecimal(string $s, bool $allowNegative): bool
    {
        if ($s === '') {
            return false;
        }
        $pattern = $allowNegative ? '/^-?[0-9]+$/' : '/^[0-9]+$/';

        return preg_match($pattern, $s) === 1;
    }

    /**
     * sdssplitargs-style inline tokeniser: whitespace-separated, with double-quoted (backslash
     * escapes, \xHH) and single-quoted ('' escape) tokens. Returns null on unbalanced quotes.
     *
     * @return list<string>|null
     */
    private static function splitInline(string $line): ?array
    {
        $args = [];
        $i = 0;
        $len = strlen($line);
        while (true) {
            while ($i < $len && ($line[$i] === ' ' || $line[$i] === "\t")) {
                $i++;
            }
            if ($i >= $len) {
                break;
            }
            $cur = '';
            $inQuote = false;
            $inSingle = false;
            $done = false;
            while ($i < $len && !$done) {
                $c = $line[$i];
                if ($inQuote) {
                    if ($c === '\\' && $i + 1 < $len) {
                        $n = $line[$i + 1];
                        if ($n === 'x' && $i + 3 < $len && ctype_xdigit($line[$i + 2]) && ctype_xdigit($line[$i + 3])) {
                            $cur .= chr((int) hexdec($line[$i + 2] . $line[$i + 3]));
                            $i += 4;
                            continue;
                        }
                        $cur .= match ($n) {
                            'n' => "\n", 'r' => "\r", 't' => "\t", 'b' => "\x08", 'a' => "\x07",
                            default => $n,
                        };
                        $i += 2;
                        continue;
                    }
                    if ($c === '"') {
                        $i++;
                        $inQuote = false;
                        // a closing quote must be followed by whitespace or end
                        if ($i < $len && $line[$i] !== ' ' && $line[$i] !== "\t") {
                            return null;
                        }
                        $done = true;
                        continue;
                    }
                    $cur .= $c;
                    $i++;
                    continue;
                }
                if ($inSingle) {
                    if ($c === '\\' && $i + 1 < $len && $line[$i + 1] === "'") {
                        $cur .= "'";
                        $i += 2;
                        continue;
                    }
                    if ($c === "'") {
                        $i++;
                        $inSingle = false;
                        if ($i < $len && $line[$i] !== ' ' && $line[$i] !== "\t") {
                            return null;
                        }
                        $done = true;
                        continue;
                    }
                    $cur .= $c;
                    $i++;
                    continue;
                }
                if ($c === ' ' || $c === "\t") {
                    $done = true;
                    continue;
                }
                if ($c === '"') {
                    $inQuote = true;
                    $i++;
                    continue;
                }
                if ($c === "'") {
                    $inSingle = true;
                    $i++;
                    continue;
                }
                $cur .= $c;
                $i++;
            }
            if ($inQuote || $inSingle) {
                return null; // ran off the end still inside a quote
            }
            $args[] = $cur;
        }

        return $args;
    }
}
