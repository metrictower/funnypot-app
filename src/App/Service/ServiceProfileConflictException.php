<?php

declare(strict_types=1);

namespace Funnypot\App\Service;

use RuntimeException;

/**
 * A CAS/reconcile conflict: the caller's expected revision or preview hash no longer matches, or a
 * reconciliation is in flight. Carries the HTTP status the admin surface returns (409) and a stable
 * reason code, and guarantees no bytes/revision/audit changed.
 */
final class ServiceProfileConflictException extends RuntimeException
{
    public function __construct(public readonly string $reason, public readonly int $httpStatus = 409)
    {
        parent::__construct($reason);
    }
}
