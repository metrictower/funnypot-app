<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Fpm;

/**
 * Pure FastCGI (FCGI) record codec — the wire layer of the PHP-FPM honeypot (FP-0204). No I/O, no
 * state: it decodes a byte buffer into records and encodes records back to bytes, so it is fully
 * unit-testable with crafted frames. {@see FcgiSession} drives it; {@see FcgiServer} owns the socket.
 *
 * Frame (FastCGI 1.0 §3.3): every record is an 8-byte header
 *   { version(1), type(1), requestId(2, big-endian), contentLength(2, big-endian),
 *     paddingLength(1), reserved(1) }
 * followed by contentLength content bytes and paddingLength padding bytes. A record is only complete
 * once header + content + padding are all present; the padding MUST be consumed or the stream desyncs.
 *
 * Nothing here executes, opens, or reflects anything — it only shapes bytes.
 */
final class FastCgiRecord
{
    public const VERSION_1 = 1;

    /** Record types (FastCGI 1.0 §8). */
    public const TYPE_BEGIN_REQUEST = 1;
    public const TYPE_ABORT_REQUEST = 2;
    public const TYPE_END_REQUEST = 3;
    public const TYPE_PARAMS = 4;
    public const TYPE_STDIN = 5;
    public const TYPE_STDOUT = 6;
    public const TYPE_STDERR = 7;
    public const TYPE_DATA = 8;
    public const TYPE_GET_VALUES = 9;
    public const TYPE_GET_VALUES_RESULT = 10;

    /** BEGIN_REQUEST roles (§5.1). */
    public const ROLE_RESPONDER = 1;

    /** END_REQUEST protocolStatus (§5.5). */
    public const REQUEST_COMPLETE = 0;

    public const HEADER_LEN = 8;

    /** The 2-byte contentLength field's natural ceiling; used by encode() to reject an oversize record. */
    public const MAX_CONTENT_LEN = 65535;

    public int $version;
    public int $type;
    public int $requestId;
    public string $content;

    public function __construct(int $type, int $requestId, string $content = '', int $version = self::VERSION_1)
    {
        $this->version = $version;
        $this->type = $type;
        $this->requestId = $requestId;
        $this->content = $content;
    }

    /**
     * Decode as many whole records as $buffer holds. Returns the decoded records plus the number of
     * bytes consumed; the caller keeps the unconsumed tail (a record split across TCP reads) for the
     * next pass. A malformed version byte throws so the caller can close that connection — never a
     * silent desync.
     *
     * @return array{0: list<self>, 1: int}
     * @throws \RuntimeException on a protocol-impossible header (bad version)
     */
    public static function decode(string $buffer): array
    {
        $records = [];
        $offset = 0;
        $len = \strlen($buffer);

        while ($len - $offset >= self::HEADER_LEN) {
            $version = \ord($buffer[$offset]);
            $type = \ord($buffer[$offset + 1]);
            $requestId = (\ord($buffer[$offset + 2]) << 8) | \ord($buffer[$offset + 3]);
            $contentLength = (\ord($buffer[$offset + 4]) << 8) | \ord($buffer[$offset + 5]);
            $paddingLength = \ord($buffer[$offset + 6]);
            // reserved byte at +7 ignored

            if ($version !== self::VERSION_1) {
                throw new \RuntimeException('FastCGI: unsupported version ' . $version);
            }

            $recordLen = self::HEADER_LEN + $contentLength + $paddingLength;
            if ($len - $offset < $recordLen) {
                break; // whole record (incl. padding) not yet in the buffer — wait for more
            }

            $content = $contentLength > 0
                ? \substr($buffer, $offset + self::HEADER_LEN, $contentLength)
                : '';
            $records[] = new self($type, $requestId, $content, $version);
            $offset += $recordLen; // skip header + content + padding
        }

        return [$records, $offset];
    }

    /**
     * Encode one record. Content over MAX_CONTENT_LEN must be split by the caller into several records
     * of the same type (the FastCGI stream convention); this encodes a single record only.
     */
    public static function encode(int $type, int $requestId, string $content = ''): string
    {
        $contentLength = \strlen($content);
        if ($contentLength > self::MAX_CONTENT_LEN) {
            throw new \InvalidArgumentException('FastCGI: content exceeds a single record; split first');
        }
        // 8-aligned padding keeps real clients happy; value is arbitrary zero bytes.
        $paddingLength = (8 - ($contentLength % 8)) % 8;

        return \chr(self::VERSION_1)
            . \chr($type)
            . \chr(($requestId >> 8) & 0xFF) . \chr($requestId & 0xFF)
            . \chr(($contentLength >> 8) & 0xFF) . \chr($contentLength & 0xFF)
            . \chr($paddingLength)
            . "\x00"
            . $content
            . \str_repeat("\x00", $paddingLength);
    }

    /**
     * Decode a PARAMS name-value stream (§3.4) into a bounded map. Each pair is
     * { nameLen, valueLen, name, value } where a length is 1 byte if its high bit is clear, else a
     * 4-byte big-endian value with the high bit of the first byte set (and masked off).
     *
     * Bounded on every axis — pair count, per-name, per-value, and aggregate bytes — so a hostile
     * client cannot blow memory. A truncated or over-budget stream stops cleanly at the last whole
     * pair; later keys win (FPM semantics) so a duplicate injected key overrides.
     *
     * @return array<string, string>
     */
    public static function decodeParams(
        string $stream,
        int $maxPairs = 256,
        int $maxNameLen = 1024,
        int $maxValueLen = 65536,
        int $maxTotalBytes = 262144
    ): array {
        $params = [];
        $offset = 0;
        $len = \strlen($stream);
        $consumed = 0;
        $pairs = 0;

        while ($offset < $len && $pairs < $maxPairs && $consumed < $maxTotalBytes) {
            $nameLen = self::readLen($stream, $offset, $len);
            if ($nameLen === null) {
                break;
            }
            $valueLen = self::readLen($stream, $offset, $len);
            if ($valueLen === null) {
                break;
            }
            if ($len - $offset < $nameLen + $valueLen) {
                break; // truncated pair body
            }
            // Reject only this over-limit pair's body but stay aligned: skip past it, keep scanning.
            if ($nameLen > $maxNameLen || $valueLen > $maxValueLen) {
                $offset += $nameLen + $valueLen;
                $consumed += $nameLen + $valueLen;
                $pairs++;
                continue;
            }
            $name = \substr($stream, $offset, $nameLen);
            $offset += $nameLen;
            $value = \substr($stream, $offset, $valueLen);
            $offset += $valueLen;

            $params[$name] = $value;
            $consumed += $nameLen + $valueLen;
            $pairs++;
        }

        return $params;
    }

    /**
     * Read one FastCGI length field, advancing $offset. Returns null when the field (1 or 4 bytes) is
     * not fully present.
     */
    private static function readLen(string $stream, int &$offset, int $len): ?int
    {
        if ($offset >= $len) {
            return null;
        }
        $b0 = \ord($stream[$offset]);
        if (($b0 & 0x80) === 0) {
            $offset += 1;

            return $b0;
        }
        if ($len - $offset < 4) {
            return null;
        }
        $value = (($b0 & 0x7F) << 24)
            | (\ord($stream[$offset + 1]) << 16)
            | (\ord($stream[$offset + 2]) << 8)
            | \ord($stream[$offset + 3]);
        $offset += 4;

        return $value;
    }
}
