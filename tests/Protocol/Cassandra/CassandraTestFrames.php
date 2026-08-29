<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Cassandra;

/**
 * Byte builders for the Cassandra tests: CQL native-protocol framing, a STARTUP options map, an
 * OPTIONS request, and an AUTH_RESPONSE carrying the SASL PLAIN credential token a real driver sends.
 * Kept minimal — just enough structure for the honeypot's parsers to exercise every field it reads.
 */
trait CassandraTestFrames
{
    /** Wraps a body in the 9-byte CQL header (version, flags, stream big-endian, opcode, length). */
    private static function cqlFrame(int $proto, int $flags, int $stream, int $opcode, string $body): string
    {
        return chr($proto & 0x7F) // request direction: high bit clear
            . chr($flags & 0xFF)
            . pack('n', $stream & 0xFFFF)
            . chr($opcode & 0xFF)
            . pack('N', strlen($body))
            . $body;
    }

    /** Encodes a CQL [string]: [short] length + UTF-8 bytes. */
    private static function cqlStr(string $s): string
    {
        return pack('n', strlen($s)) . $s;
    }

    /**
     * Encodes a CQL [string map]: [short] count + count [string]/[string] pairs.
     *
     * @param array<string,string> $map
     */
    private static function cqlStringMap(array $map): string
    {
        $out = pack('n', count($map));
        foreach ($map as $k => $v) {
            $out .= self::cqlStr((string) $k) . self::cqlStr((string) $v);
        }

        return $out;
    }

    /** Encodes a CQL [bytes]: [int] length + bytes. */
    private static function cqlBytes(string $b): string
    {
        return pack('N', strlen($b)) . $b;
    }

    /** A CQL OPTIONS request (empty body). */
    private static function optionsRequest(int $proto = 4, int $stream = 1): string
    {
        return self::cqlFrame($proto, 0x00, $stream, 0x05, '');
    }

    /**
     * A CQL STARTUP request whose options map carries the CQL version and (optionally) the driver.
     *
     * @param array<string,string> $options
     */
    private static function startupRequest(array $options = ['CQL_VERSION' => '3.0.0'], int $proto = 4, int $stream = 1): string
    {
        return self::cqlFrame($proto, 0x00, $stream, 0x01, self::cqlStringMap($options));
    }

    /**
     * A CQL AUTH_RESPONSE carrying a SASL PLAIN token `\0username\0password`, wrapped in [bytes], the
     * way a driver answering PasswordAuthenticator does.
     */
    private static function authResponse(string $user, string $password, int $proto = 4, int $stream = 1): string
    {
        $token = "\x00" . $user . "\x00" . $password;

        return self::cqlFrame($proto, 0x00, $stream, 0x0F, self::cqlBytes($token));
    }

    /** Strips the 9-byte CQL header, returning the frame body. */
    private static function frameBody(string $frame): string
    {
        return substr($frame, 9);
    }

    private static function frameVersion(string $frame): int
    {
        return ord($frame[0]);
    }

    private static function frameStream(string $frame): int
    {
        return (ord($frame[2]) << 8) | ord($frame[3]);
    }

    private static function frameOpcode(string $frame): int
    {
        return ord($frame[4]);
    }

    /** Reads a CQL [string] at $p, advancing $p (test-side mirror for asserting response bodies). */
    private static function readCqlString(string $buf, int &$p): string
    {
        $len = (ord($buf[$p]) << 8) | ord($buf[$p + 1]);
        $p += 2;
        $s = substr($buf, $p, $len);
        $p += $len;

        return $s;
    }
}
