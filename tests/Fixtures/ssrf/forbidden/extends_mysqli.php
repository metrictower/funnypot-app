<?php

declare(strict_types=1);

// expect: extends: mysqli
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

final class OwnMysqli extends \mysqli
{
}
