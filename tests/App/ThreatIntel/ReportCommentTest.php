<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\ThreatIntel;

use Funnypot\App\ThreatIntel\ReportComment;
use PHPUnit\Framework\TestCase;

/**
 * Public-report comment sanitisation (FP-0247, Fix H). AbuseIPDB comments are public, so the
 * attacker-controlled detail must never republish a victim's credentials, PII, exploit blobs, control
 * bytes, or an injected third-party hostname.
 */
final class ReportCommentTest extends TestCase
{
    public function test_control_bytes_stripped(): void
    {
        $c = ReportComment::build('prefix', "line1\r\n\x00\x1b[31mred\x07 tail");
        self::assertStringNotContainsString("\x00", $c);
        self::assertStringNotContainsString("\x1b", $c);
        self::assertStringNotContainsString("\x07", $c);
        self::assertMatchesRegularExpression('/^[\x20-\x7E]*$/', $c);   // printable ASCII only
    }

    public function test_credential_params_redacted(): void
    {
        $c = ReportComment::build('web', 'GET /login?user=bob&password=hunter2&token=abc123&x=ok');
        self::assertStringNotContainsString('hunter2', $c);
        self::assertStringNotContainsString('abc123', $c);
        self::assertStringContainsString('[redacted]', $c);
        self::assertStringContainsString('x=ok', $c);   // non-secret param survives
    }

    public function test_more_credential_keys_redacted(): void
    {
        foreach (['apikey=SECRETVAL', 'api_key=SECRETVAL', 'secret=SECRETVAL', 'authorization=SECRETVAL', 'pwd=SECRETVAL'] as $pair) {
            $c = ReportComment::build('p', 'GET /x?' . $pair);
            self::assertStringNotContainsString('SECRETVAL', $c, "key not redacted: {$pair}");
        }
    }

    /**
     * FP-0247 (opus #5): compound / `_`-joined credential param names — `\b` fails on these, so they
     * were previously republished verbatim. The name need only CONTAIN a credential token now.
     */
    public function test_compound_credential_keys_redacted(): void
    {
        $compound = [
            'access_token=SECRETVAL',
            'refresh_token=SECRETVAL',
            'client_secret=SECRETVAL',
            'session_id=SECRETVAL',
            'sessionid=SECRETVAL',
            'x_api_key=SECRETVAL',
            'user_password=SECRETVAL',
            'X-Auth-Token=SECRETVAL',
        ];
        foreach ($compound as $pair) {
            $c = ReportComment::build('web', 'GET /oauth/callback?' . $pair . '&keep=ok');
            self::assertStringNotContainsString('SECRETVAL', $c, "compound key not redacted: {$pair}");
            self::assertStringContainsString('[redacted]', $c, "no redaction marker for: {$pair}");
            self::assertStringContainsString('keep=ok', $c, 'non-secret param must survive');
        }
    }

    public function test_gemini_dialect_api_key_redacted(): void
    {
        // FP-0247 (fable #3b): a Gemini-dialect AI-API request carries the Google API key in the query
        // string; the AI honeypot path now routes through build(), so the key must be redacted.
        $c = ReportComment::build('ai_api_recon', '/v1beta/models/gemini-pro:generateContent?key=AIzaSyD-EXAMPLE-KEY-1234567890');
        self::assertStringNotContainsString('AIzaSyD-EXAMPLE-KEY-1234567890', $c);
        self::assertStringContainsString('[redacted]', $c);
        self::assertStringContainsString('gemini-pro', $c);   // the useful model detail survives
    }

    public function test_protocol_relative_host_stripped_but_path_kept(): void
    {
        // nginx forwards `GET //host/path` verbatim; the protocol-relative authority carries no scheme,
        // so it must be stripped separately or it names a third-party host in the public report.
        $c = ReportComment::build('funnypot web honeypot, port 80: GET', '//victim.example/admin?a=1');
        self::assertStringNotContainsString('victim.example', $c);
        self::assertStringContainsString('/admin?a=1', $c);
    }

    public function test_protocol_relative_host_after_method_token_stripped(): void
    {
        $c = ReportComment::build('p', 'GET //evil.test:8443/wp-login.php');
        self::assertStringNotContainsString('evil.test', $c);
        self::assertStringContainsString('/wp-login.php', $c);
        self::assertStringContainsString('GET', $c);
    }

    public function test_emails_redacted(): void
    {
        $c = ReportComment::build('smtp', 'MAIL FROM victim.person@company.example harvested');
        self::assertStringNotContainsString('victim.person@company.example', $c);
        self::assertStringContainsString('[email]', $c);
    }

    public function test_long_blobs_collapsed(): void
    {
        $blob = str_repeat('QUJDZGVmMTIzNA', 6);   // > 48 base64-ish chars
        $c = ReportComment::build('web', 'POST /upload body=' . $blob);
        self::assertStringNotContainsString($blob, $c);
        self::assertStringContainsString('[blob]', $c);
    }

    public function test_host_header_never_appears_in_web_comment(): void
    {
        // Exactly what HoneypotController::maybeReport() now passes: an absolute-URI request line whose
        // path carries a third-party host. Even with the Host header dropped, the scheme://host in the
        // request target must not reach the public report.
        $c = ReportComment::build('funnypot web honeypot, port 80: [sqli] GET', 'http://victim.example/wp-login.php?a=1');
        self::assertStringNotContainsString('victim.example', $c);
        self::assertStringNotContainsString('http://', $c);
        self::assertStringContainsString('/wp-login.php', $c);   // the useful path detail survives
    }

    public function test_scheme_host_stripped_but_path_kept(): void
    {
        $c = ReportComment::build('p', 'GET https://evil.test:8443/a/b?q=1');
        self::assertStringNotContainsString('evil.test', $c);
        self::assertStringContainsString('/a/b?q=1', $c);
        self::assertStringContainsString('GET', $c);
    }

    public function test_truncated_to_max(): void
    {
        $c = ReportComment::build('p', str_repeat('a', 500), 100);
        self::assertLessThanOrEqual(100, strlen($c));
    }

    public function test_trusted_prefix_preserved(): void
    {
        $c = ReportComment::build('funnypot SSH honeypot, port 22: login', 'root:toor');
        self::assertStringStartsWith('funnypot SSH honeypot, port 22: login', $c);
    }
}
