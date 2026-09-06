<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

/**
 * Serialises a {@see RespReply} tree to RESP2 or RESP3 wire bytes exactly as Redis 6.2 does, and can
 * measure the encoded length WITHOUT building the bytes so a caller can reject an over-large reply
 * before it is ever materialised (a repeated-key MGET whose semantic reply is megabytes must never
 * allocate).
 *
 * RESP3 aggregate types collapse to their RESP2 forms exactly like Redis 6.2: map -> flat array,
 * set -> array, verbatim string -> bulk string, and both null forms -> the versioned null (`_` in
 * RESP3, `$-1`/`*-1` in RESP2).
 */
final class RespEncoder
{
    public const RESP2 = 2;
    public const RESP3 = 3;

    public function encode(RespReply $r, int $version): string
    {
        switch ($r->type) {
            case RespReply::SIMPLE:
                return '+' . $r->scalar . "\r\n";
            case RespReply::ERROR:
                return '-' . $r->scalar . "\r\n";
            case RespReply::INT:
                return ':' . $r->scalar . "\r\n";
            case RespReply::BULK:
                $s = (string) $r->scalar;

                return '$' . strlen($s) . "\r\n" . $s . "\r\n";
            case RespReply::NULL_BULK:
                return $version >= self::RESP3 ? "_\r\n" : "\$-1\r\n";
            case RespReply::NULL_ARRAY:
                return $version >= self::RESP3 ? "_\r\n" : "*-1\r\n";
            case RespReply::ARR:
                $out = '*' . count($r->items) . "\r\n";
                foreach ($r->items as $item) {
                    $out .= $this->encode($item, $version);
                }

                return $out;
            case RespReply::SET:
                $prefix = $version >= self::RESP3 ? '~' : '*';
                $out = $prefix . count($r->items) . "\r\n";
                foreach ($r->items as $item) {
                    $out .= $this->encode($item, $version);
                }

                return $out;
            case RespReply::MAP:
                if ($version >= self::RESP3) {
                    $out = '%' . count($r->pairs) . "\r\n";
                    foreach ($r->pairs as [$k, $v]) {
                        $out .= $this->encode($k, $version) . $this->encode($v, $version);
                    }

                    return $out;
                }
                $out = '*' . (count($r->pairs) * 2) . "\r\n";
                foreach ($r->pairs as [$k, $v]) {
                    $out .= $this->encode($k, $version) . $this->encode($v, $version);
                }

                return $out;
            case RespReply::VERBATIM:
                $text = (string) $r->scalar;
                if ($version >= self::RESP3) {
                    $body = $r->format . ':' . $text;

                    return '=' . strlen($body) . "\r\n" . $body . "\r\n";
                }

                return '$' . strlen($text) . "\r\n" . $text . "\r\n";
        }

        return "\$-1\r\n";
    }

    /**
     * The exact number of bytes {@see encode()} would produce, but abandoned early once it passes
     * $cap — the returned value is then simply "greater than $cap" (never the true, possibly huge,
     * total). Nothing is concatenated; this walks the tree adding lengths only.
     */
    public function encodedLength(RespReply $r, int $version, int $cap): int
    {
        $total = 0;
        $this->measure($r, $version, $cap, $total);

        return $total;
    }

    private function measure(RespReply $r, int $version, int $cap, int &$total): void
    {
        if ($total > $cap) {
            return; // already over budget — stop walking
        }
        switch ($r->type) {
            case RespReply::SIMPLE:
            case RespReply::ERROR:
                $total += 1 + strlen((string) $r->scalar) + 2;

                return;
            case RespReply::INT:
                $total += 1 + strlen((string) $r->scalar) + 2;

                return;
            case RespReply::BULK:
                $len = strlen((string) $r->scalar);
                $total += 1 + strlen((string) $len) + 2 + $len + 2;

                return;
            case RespReply::NULL_BULK:
            case RespReply::NULL_ARRAY:
                $total += $version >= self::RESP3 ? 3 : 5;

                return;
            case RespReply::ARR:
            case RespReply::SET:
                $total += 1 + strlen((string) count($r->items)) + 2;
                foreach ($r->items as $item) {
                    if ($total > $cap) {
                        return;
                    }
                    $this->measure($item, $version, $cap, $total);
                }

                return;
            case RespReply::MAP:
                $count = $version >= self::RESP3 ? count($r->pairs) : count($r->pairs) * 2;
                $total += 1 + strlen((string) $count) + 2;
                foreach ($r->pairs as [$k, $v]) {
                    if ($total > $cap) {
                        return;
                    }
                    $this->measure($k, $version, $cap, $total);
                    $this->measure($v, $version, $cap, $total);
                }

                return;
            case RespReply::VERBATIM:
                $text = (string) $r->scalar;
                if ($version >= self::RESP3) {
                    $len = 4 + strlen($text); // "txt:" prefix + data

                    $total += 1 + strlen((string) $len) + 2 + $len + 2;

                    return;
                }
                $total += 1 + strlen((string) strlen($text)) + 2 + strlen($text) + 2;

                return;
        }
    }
}
