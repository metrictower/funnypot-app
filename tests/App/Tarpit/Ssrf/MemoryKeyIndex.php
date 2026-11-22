<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\KeyIndexView;

/** An in-memory key index for the pure network tests: facts are added directly, completeness is a flag. */
final class MemoryKeyIndex implements KeyIndexView
{
    /** @var array<string,true> */
    public array $hashes = [];

    public function __construct(public bool $complete = true, private string $key = 'test-keyidx')
    {
    }

    public function add(string $kind, string $value): void
    {
        $this->hashes[$this->hashOf($kind, $value)] = true;
    }

    public function contains(string $kind, string $value): bool
    {
        return isset($this->hashes[$this->hashOf($kind, $value)]);
    }

    public function hashOf(string $kind, string $value): string
    {
        return substr(hash_hmac('sha256', $kind . "\0" . $value, $this->key), 0, 24);
    }

    public function containsHash(string $hashHex): bool
    {
        return isset($this->hashes[$hashHex]);
    }

    public function complete(): bool
    {
        return $this->complete;
    }
}
