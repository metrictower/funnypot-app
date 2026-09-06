<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * A typed, protocol-version-agnostic Redis reply. The command engine builds these from semantic
 * values; {@see RespEncoder} renders them to RESP2 or RESP3 wire bytes. Holding the reply as a tree
 * (rather than a pre-serialised string) is what lets the encoder bound the encoded length before it
 * ever allocates the bytes, and lets one value downgrade correctly per negotiated protocol
 * (RESP3 map/set/verbatim collapse to RESP2 array/bulk exactly as Redis 6.2 does).
 */
final class RespReply
{
    public const SIMPLE = 1;      // +OK
    public const ERROR = 2;       // -ERR ...
    public const INT = 3;         // :123
    public const BULK = 4;        // $len\r\n...  (binary-safe)
    public const NULL_BULK = 5;   // RESP2 $-1 / RESP3 _
    public const ARR = 6;         // *N ...
    public const NULL_ARRAY = 7;  // RESP2 *-1 / RESP3 _
    public const MAP = 8;         // RESP3 %N ...  / RESP2 flattened array
    public const SET = 9;         // RESP3 ~N ...  / RESP2 array
    public const VERBATIM = 10;   // RESP3 =len\r\ntxt:... / RESP2 bulk

    /**
     * @param int                         $type  one of the type constants
     * @param string|int|null             $scalar simple/error/bulk text, or integer value
     * @param list<RespReply>             $items  array/set members
     * @param list<array{0:RespReply,1:RespReply}> $pairs map entries
     * @param string                      $format verbatim 3-char format (e.g. "txt")
     */
    private function __construct(
        public int $type,
        public string|int|null $scalar = null,
        public array $items = [],
        public array $pairs = [],
        public string $format = 'txt'
    ) {
    }

    public static function simple(string $s): self
    {
        return new self(self::SIMPLE, $s);
    }

    public static function error(string $s): self
    {
        return new self(self::ERROR, $s);
    }

    public static function int(int $n): self
    {
        return new self(self::INT, $n);
    }

    public static function bulk(string $s): self
    {
        return new self(self::BULK, $s);
    }

    public static function nullBulk(): self
    {
        return new self(self::NULL_BULK);
    }

    /** @param list<RespReply> $items */
    public static function array(array $items): self
    {
        return new self(self::ARR, null, $items);
    }

    public static function nullArray(): self
    {
        return new self(self::NULL_ARRAY);
    }

    /** @param list<array{0:RespReply,1:RespReply}> $pairs */
    public static function map(array $pairs): self
    {
        return new self(self::MAP, null, [], $pairs);
    }

    /** @param list<RespReply> $items */
    public static function set(array $items): self
    {
        return new self(self::SET, null, $items);
    }

    /** A verbatim string (INFO / CLIENT INFO); $format is the 3-char type such as "txt". */
    public static function verbatim(string $text, string $format = 'txt'): self
    {
        return new self(self::VERBATIM, $text, [], [], substr($format . '   ', 0, 3));
    }

    /** Convenience: a flat array of bulk strings (KEYS / MGET keys / CONFIG GET pairs). */
    public static function bulkList(array $strings): self
    {
        $items = [];
        foreach ($strings as $s) {
            $items[] = self::bulk((string) $s);
        }

        return new self(self::ARR, null, $items);
    }
}
