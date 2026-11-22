<?php

declare(strict_types=1);

// expect: extends: PDO
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

final class OwnPdo extends \PDO
{
}
