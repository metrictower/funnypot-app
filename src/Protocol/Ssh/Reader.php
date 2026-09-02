<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Ssh;

/**
 * Cursor reader for the SSH wire types written by {@see Buf}. Every accessor is bounds-checked
 * against the buffer so a truncated or malicious packet raises instead of reading past the end —
 * the transport treats any exception as a protocol error and drops the connection.
 */
final class Reader
{
    private int $p = 0;
    private int $len;

    public function __construct(private string $b)
    {
        $this->len = strlen($b);
    }

    public function byte(): int
    {
        if ($this->p + 1 > $this->len) {
            throw new \RuntimeException('ssh: short read (byte)');
        }

        return ord($this->b[$this->p++]);
    }

    public function bool(): bool
    {
        return $this->byte() !== 0;
    }

    public function uint32(): int
    {
        if ($this->p + 4 > $this->len) {
            throw new \RuntimeException('ssh: short read (uint32)');
        }
        /** @var array{1:int} $u */
        $u = unpack('N', substr($this->b, $this->p, 4));
        $this->p += 4;

        return $u[1];
    }

    public function string(): string
    {
        $n = $this->uint32();
        if ($n < 0 || $this->p + $n > $this->len) {
            throw new \RuntimeException('ssh: short read (string)');
        }
        $s = substr($this->b, $this->p, $n);
        $this->p += $n;

        return $s;
    }

    /** @return string[] */
    public function nameList(): array
    {
        $s = $this->string();

        return $s === '' ? [] : explode(',', $s);
    }

    /**
     * Read an mpint (RFC 4251 §5) and return its unsigned big-endian magnitude. A zero value is the
     * empty string; a negative value (top bit of the first byte set, i.e. no 0x00 sign byte) is
     * rejected — sshd's BN_is_negative check — so a peer public value is always a positive integer.
     */
    public function mpint(): string
    {
        $s = $this->string();
        if ($s === '') {
            return '';
        }
        if (ord($s[0]) & 0x80) {
            throw new \RuntimeException('ssh: negative mpint');
        }

        return ltrim($s, "\x00");
    }
}
