<?php

declare(strict_types=1);

// expect: anonymous_class
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_anonymous_class(): void
{
    $o = new class () extends \SoapClient { public function __construct() {} };
}
