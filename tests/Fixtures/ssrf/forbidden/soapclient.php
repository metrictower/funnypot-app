<?php

declare(strict_types=1);

// expect: new: SoapClient
// Never autoloaded or executed: a positive control for the SSRF namespace allowlist.

namespace Funnypot\Tests\Fixtures\Ssrf\Forbidden;

function f_soapclient(): void
{
    new \SoapClient(null, ["location" => "http://x.invalid/", "uri" => "u"]);
}
