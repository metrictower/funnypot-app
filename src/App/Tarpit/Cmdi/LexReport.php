<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Cmdi;

/** What {@see ShellLexer} learned about one command line. Plain values only. */
final class LexReport
{
    /**
     * @param list<string>                      $families        syntax features present (quotes, pipes, ...)
     * @param array<string,list<string>>        $familyTokens    the closed-set tokens seen per family
     * @param array{id:string,token:string}|null $trueDefect     the real parse error, if the line has one
     * @param list<string>                      $argv            the words of a simple command
     * @param list<list<string>|null>           $segments        each simple command's literal words, or null
     * @param list<string>                      $redirectTargets literal redirection targets
     */
    public function __construct(
        public readonly array $families,
        public readonly array $familyTokens,
        public readonly ?array $trueDefect,
        public readonly bool $simple,
        public readonly array $argv,
        public readonly array $segments,
        public readonly array $redirectTargets,
        public readonly string $shapeKey,
        public readonly int $classCount,
        public readonly int $steps,
        public readonly int $length,
    ) {
    }

    public function has(string $family): bool
    {
        return in_array($family, $this->families, true);
    }

    /** True when the line holds no command at all (blank or comment only). */
    public function isEmpty(): bool
    {
        return $this->trueDefect === null && $this->segments === [];
    }
}
