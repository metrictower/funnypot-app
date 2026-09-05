<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * Any failure of install-identity preparation or of a runtime bundle read. Carries a stable public
 * code and a remedy class only: the message never includes secret bytes, an absolute path or the
 * source location, because the front controller logs it and a log line is one hop from an
 * attacker-visible surface. Bootstrap ALWAYS fails closed on this exception — no listener binds, the
 * web tier serves its plain 404 — never an ephemeral fallback identity.
 */
final class IdentityBootstrapException extends \RuntimeException
{
    /** Remedy classes — what the operator has to do, never where the file is. */
    public const REMEDY_CONFIG = 'config';        // an explicit input is missing/malformed/changed
    public const REMEDY_STORAGE = 'storage';      // the persisted state is unsafe/unwritable/corrupt
    public const REMEDY_RUNTIME = 'runtime';      // the process/runtime lacks a capability or privilege
    public const REMEDY_TLS = 'tls';              // a selected certificate/key pair is unusable
    public const REMEDY_ACCOUNTS = 'accounts';    // a reserved OS principal conflicts

    private function __construct(private string $errorCode, private string $remedy, string $message)
    {
        parent::__construct($message);
    }

    public static function withCode(string $code, string $remedy): self
    {
        return new self($code, $remedy, 'identity bootstrap failed: ' . $code . ' (' . $remedy . ')');
    }

    /** Stable, secret-free code (e.g. `master-malformed`). */
    public function errorCode(): string
    {
        return $this->errorCode;
    }

    public function remedy(): string
    {
        return $this->remedy;
    }
}
