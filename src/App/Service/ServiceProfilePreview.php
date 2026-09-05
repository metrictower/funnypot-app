<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

/**
 * The pure result of a resolution attempt: either a resolved profile (ok) or a set of stable error
 * reason codes, always with any soft warnings and any missing-companion / pending detail. It never
 * writes and never throws for a resolution rejection — the admin surface renders it and apply refuses
 * a non-ok preview.
 */
final class ServiceProfilePreview
{
    /**
     * @param list<array{code:string,ids?:list<string>,detail?:string}> $errors
     * @param list<array{code:string,ids?:list<string>,detail?:string}> $warnings
     */
    private function __construct(
        public readonly bool $ok,
        public readonly ?ResolvedServiceProfile $resolved,
        public readonly array $errors,
        public readonly array $warnings,
    ) {
    }

    /**
     * @param list<array{code:string,ids?:list<string>,detail?:string}> $warnings
     */
    public static function resolved(ResolvedServiceProfile $resolved, array $warnings): self
    {
        return new self(true, $resolved, [], $warnings);
    }

    /**
     * @param list<array{code:string,ids?:list<string>,detail?:string}> $errors
     * @param list<array{code:string,ids?:list<string>,detail?:string}> $warnings
     */
    public static function rejected(array $errors, array $warnings = []): self
    {
        return new self(false, null, $errors, $warnings);
    }

    /** @return list<string> */
    public function errorCodes(): array
    {
        return array_values(array_map(static fn (array $e): string => $e['code'], $this->errors));
    }

    public function hasError(string $code): bool
    {
        return in_array($code, $this->errorCodes(), true);
    }

    /** @return array<string,mixed> the admin/preview payload (no ranking key, no private path) */
    public function toArray(): array
    {
        return [
            'ok' => $this->ok,
            'errors' => $this->errors,
            'warnings' => $this->warnings,
            'resolved' => $this->resolved?->toArray(),
        ];
    }
}
