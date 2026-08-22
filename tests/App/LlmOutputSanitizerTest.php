<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmOutputSanitizer;
use PHPUnit\Framework\TestCase;

/**
 * The sanitizer treats model output as hostile: a clean HTML body passes, every dangerous or
 * malformed shape returns null (which the responder turns into the plain 404).
 */
final class LlmOutputSanitizerTest extends TestCase
{
    private LlmOutputSanitizer $s;

    protected function setUp(): void
    {
        $this->s = new LlmOutputSanitizer();
    }

    public function test_clean_html_passes(): void
    {
        $html = '<!doctype html><html><head><title>Sign in</title></head><body>'
            . '<h1>Sign in</h1><form method="post" action="/login"><input name="user">'
            . '<input name="pass" type="password"><button>Log in</button></form></body></html>';
        self::assertSame($html, $this->s->sanitize($html));
    }

    public function test_trims_but_keeps_body(): void
    {
        $html = "  <html><body><p>ok, this is a plausible enough page body</p></body></html>  ";
        self::assertSame(trim($html), $this->s->sanitize($html));
    }

    /**
     * @dataProvider rejected
     */
    public function test_rejects(string $label, string $raw): void
    {
        self::assertNull($this->s->sanitize($raw), $label);
    }

    /** @return array<int,array{0:string,1:string}> */
    public static function rejected(): array
    {
        $pad = str_repeat('x', 60);   // enough length so short-circuit isn't the size rule

        return [
            ['too short', '<p>hi</p>'],
            ['preamble / not markup', "Sure! Here is the HTML:\n<html><body>$pad</body></html>"],
            ['markdown fence', "```html\n<html><body>$pad</body></html>\n```"],
            ['script tag', "<html><body><script>alert(1)</script>$pad</body></html>"],
            ['iframe', "<html><body><iframe src=\"/x\"></iframe>$pad</body></html>"],
            ['link tag', "<html><head><link rel=stylesheet href=\"x.css\">$pad</head></html>"],
            ['style block', "<html><head><style>body{color:red}</style>$pad</head></html>"],
            ['meta refresh', "<html><head><meta http-equiv=\"refresh\" content=\"0\">$pad</head></html>"],
            ['meta refresh extra spaces', "<html><head><meta   http-equiv=\"refresh\" content=\"0\">$pad</head></html>"],
            ['meta refresh tab sep', "<html><head><meta\thttp-equiv=\"refresh\" content=\"0\">$pad</head></html>"],
            ['event handler', "<html><body><img src=x onerror=\"alert(1)\">$pad</body></html>"],
            ['event handler slash sep', "<html><body><div/onload=\"alert(1)\">$pad</div></body></html>"],
            ['javascript href', "<html><body><a href=\"javascript:alert(document.domain)\">go</a>$pad</body></html>"],
            ['vbscript href', "<html><body><a href=\"vbscript:msgbox(1)\">go</a>$pad</body></html>"],
            ['data uri action', "<html><body><form action=\"data:text/html;base64,PHg+\">$pad</form></body></html>"],
            ['absolute href', "<html><body><a href=\"https://evil.example/x\">go</a>$pad</body></html>"],
            ['protocol-relative src', "<html><body><img src=\"//evil.example/x.png\">$pad</body></html>"],
            ['css url external', "<html><body><div style=\"background:url(http://evil/x)\">$pad</div></body></html>"],
            ['php tag', "<html><body><?php system('id'); ?>$pad</body></html>"],
            ['eval', "<html><body>text eval(atob('x')) more $pad</body></html>"],
            ['base64_decode', "<html><body>base64_decode('...') $pad here</body></html>"],
            ['private key', "<html><body>-----BEGIN RSA PRIVATE KEY----- $pad</body></html>"],
            ['path traversal', "<html><body><a href=\"../../etc/passwd\">x</a>$pad</body></html>"],
            ['control bytes', "<html><body>\x07\x00 bad bytes $pad</body></html>"],
            ['invalid utf-8', "<html><body>\xff\xfe not utf8 $pad</body></html>"],
            ['self-disclosure honeypot', "<html><body><p>This is a fake web server for defensive security-research honeypots. $pad</p></body></html>"],
            ['self-disclosure as an ai', "<html><body><p>As an AI, I generated this placeholder page for you. $pad</p></body></html>"],
            // GALAH paraphrase leaks that slip the leading-80 refusal check and the original list
            ['self-disclosure pretending', "<html><body><p>I can assure you this is a 100% real server, not an AI pretending to be one. $pad</p></body></html>"],
            ['self-disclosure simulated', "<html><body><p>This is a simulated response from a fake server application. $pad</p></body></html>"],
            ['self-disclosure decoy', "<html><body><p>Welcome to the decoy environment. $pad</p></body></html>"],
        ];
    }

    public function test_api_server_status_page_passes_unchanged(): void
    {
        // Over-rejection guard: a legit status page names "server"/"web server" (bare words), which
        // are deliberately NOT disclosure markers — only the compounds are. It must pass unchanged.
        $pad = str_repeat('x', 60);
        $html = "<html><body><h1>API Server Status</h1><p>The web server is running normally. $pad</p></body></html>";
        self::assertSame($html, $this->s->sanitize($html));
    }

    public function test_disclosure_rejected_for_any_kind(): void
    {
        // The leak surfaces mid-body, past the 80-char refusal window, so it must be caught regardless
        // of content kind — a probe like /are-you-a-honeypot must never elicit the model's own framing.
        $body = "APP_ENV=production\nNOTE=this file is served by a honeypot for security research\nDB=appdb";
        self::assertNull($this->s->sanitize($body, 'text'));
    }

    public function test_rejects_oversize(): void
    {
        $huge = '<html><body>' . str_repeat('a', 9000) . '</body></html>';
        self::assertNull($this->s->sanitize($huge, 'html', 8192));
    }

    // --- non-HTML kinds: each must accept a plausible body of its type and reject weaponised shapes ---

    public function test_json_valid_passes_and_bad_values_rejected(): void
    {
        $ok = '{"users":[{"id":1042,"name":"a.reyes","role":"admin","token":"tok_9f3ac21e"}],"total":1}';
        self::assertSame($ok, $this->s->sanitize($ok, 'json'));
        self::assertNull($this->s->sanitize('not json at all, just a sentence padded out to length', 'json'));
        self::assertNull($this->s->sanitize('{"x":"<script>alert(1)</script> padded out to the min length"}', 'json'));
        self::assertNull($this->s->sanitize('{"cb":"https://evil.example/beacon and some padding to pass length"}', 'json'));
    }

    public function test_css_valid_passes_and_active_content_rejected(): void
    {
        $ok = '.app-header{background:#1b1e21;color:#fff;padding:12px}.btn{border-radius:4px;padding:6px}';
        self::assertSame($ok, $this->s->sanitize($ok, 'css'));
        foreach ([
            '@import' => '@import url("//evil/x.css");.a{color:red;padding:2px enough length here}',
            'expression' => '.a{width:expression(alert(1));color:red; padding to reach the min length x}',
            'external url' => '.a{background:url(http://evil/x.png);color:red; padding to reach min length}',
            'markup breakout' => '.a{color:red}</style><script>1</script> padding to reach the min length',
        ] as $label => $bad) {
            self::assertNull($this->s->sanitize($bad, 'css'), $label);
        }
    }

    public function test_js_data_object_passes_and_runtime_rejected(): void
    {
        $ok = 'var APP_CONFIG={"version":"2.3.1","apiBase":"/api/v1","debug":false,"buildId":"a1f9c3"};';
        self::assertSame($ok, $this->s->sanitize($ok, 'js'));
        foreach ([
            'document' => 'var x=1; document.cookie="a=b"; var padding_to_reach_the_min_length=2;',
            'fetch' => 'var x=1; fetch("/y"); var padding_to_reach_the_minimum_length_here=2;',
            'window' => 'var x=window.location; var more_padding_to_reach_the_min_length_here=2;',
            'template literal' => 'var x=`hi ${1}`; var padding_to_reach_the_minimum_length_here=2;',
            'unicode escape' => 'var x="\\u0065\\u0076al"; var padding_to_reach_min_length_here_ok=2;',
            'markup' => 'var x=1;</script><b>hi</b> padding to reach the minimum length here ok',
        ] as $label => $bad) {
            self::assertNull($this->s->sanitize($bad, 'js'), $label);
        }
    }

    public function test_xml_wellformed_passes_and_xxe_rejected(): void
    {
        $ok = '<?xml version="1.0" encoding="UTF-8"?><services><service name="auth" enabled="true"/></services>';
        self::assertSame($ok, $this->s->sanitize($ok, 'xml'));
        self::assertNull($this->s->sanitize('<a><b>unclosed tags here, padded out to the minimum length</a>', 'xml'));
        self::assertNull($this->s->sanitize('<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', 'xml'));
    }

    public function test_text_plain_passes_and_markup_rejected(): void
    {
        $ok = "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_USER=appuser\nDB_PASS=changeme_9f3ac2";
        self::assertSame($ok, $this->s->sanitize($ok, 'text'));
        self::assertNull($this->s->sanitize("<html>this is not plaintext, padded out to the min length</html>", 'text'));
        self::assertNull($this->s->sanitize("Sorry, I cannot help with that request. Here is nothing useful.", 'text'));
    }

    public function test_json_rejects_active_html_in_values(): void
    {
        $s = new LlmOutputSanitizer();
        $bads = [
            '{"a":"<iframe src=/x>padding to reach the min length band here now"}',
            '{"a":"<img x onerror=alert(1)> padding to reach the minimum length band"}',
            '{"a":"<style>body{} padding to reach the minimum length band here now ok"}',
        ];
        foreach ($bads as $b) {
            self::assertNull($s->sanitize($b, 'json'), "should reject: {$b}");
        }
    }

    public function test_sanitize_to_array_returns_decoded_and_rejects_active_values(): void
    {
        $s = new LlmOutputSanitizer();
        $ok = $s->sanitizeToArray('{"app_name":"Portal","heading":"Users","nav_items":["Home","Users"]}');
        self::assertIsArray($ok);
        self::assertSame('Portal', $ok['app_name']);
        self::assertNull($s->sanitizeToArray('{"heading":"<img x onerror=alert(1)> padding padding padding here"}'));
        self::assertNull($s->sanitizeToArray('not json at all but long enough to clear the size band easily'));
    }

    public function test_page_body_ok_allows_trusted_chrome_but_blocks_disclosure_and_script(): void
    {
        $s = new LlmOutputSanitizer();
        $good = '<!doctype html><html><head><style>.a{color:#111}</style></head><body>'
            . '<h1>Users</h1><a href="/admin">Home</a></body></html>';
        self::assertTrue($s->pageBodyOk($good));                                   // <style> + relative href OK
        self::assertFalse($s->pageBodyOk($good . '<script>x()</script>'));         // active content
        self::assertFalse($s->pageBodyOk('<html><body>this is a honeypot page</body></html>')); // disclosure
        self::assertFalse($s->pageBodyOk('<html><body><td>honey</td><td>pot</td></body></html>')); // split disclosure
    }
}
