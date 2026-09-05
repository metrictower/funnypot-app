<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Render\Fake\FakeSecrets;
use Funnypot\Core\Support\VisualPersona;
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
            // FP-0112 review #1: parity with resources/app-fingerprint-denylist.php's own_vocabulary —
            // the runtime LLM path had none of these until this fix.
            ['self-disclosure funnypot', "<html><body><p>This box is actually a funnypot deployment. $pad</p></body></html>"],
            ['self-disclosure bait', "<html><body><p>Everything on this page is bait for scanners. $pad</p></body></html>"],
            ['self-disclosure lure', "<html><body><p>This form is a lure planted for crawlers. $pad</p></body></html>"],
            ['self-disclosure tarpit', "<html><body><p>You have wandered into a tarpit, friend. $pad</p></body></html>"],
            ['self-disclosure metrictower', "<html><body><p>Reported upstream to metrictower. $pad</p></body></html>"],
            ['self-disclosure troll', "<html><body><p>We troll attackers with fake data here. $pad</p></body></html>"],
            ['self-disclosure sabotage', "<html><body><p>Consider this content data sabotage. $pad</p></body></html>"],
            ['self-disclosure deception', "<html><body><p>This whole site runs on deception. $pad</p></body></html>"],
            // Suffix/inflected variants (FP-0112 review #4's tightened forms) must be caught here too.
            ['self-disclosure baited', "<html><body><p>Every field on this page was baited. $pad</p></body></html>"],
            ['self-disclosure tarpitting', "<html><body><p>The engine is tarpitting your scanner now. $pad</p></body></html>"],
            ['self-disclosure deceptive', "<html><body><p>This response is deliberately deceptive. $pad</p></body></html>"],
        ];
    }

    /**
     * FP-0112 review #1: parity guard. Every own_vocabulary stem this project's denylist declares
     * (minus honeypot/decoy, already covered above by the stricter substring entries) must trip the
     * sanitizer on ITS OWN — i.e. with none of the surrounding META_DISCLOSURE phrases present — so a
     * future denylist addition can never silently ship without the runtime LLM gate picking it up too.
     */
    public function test_every_denylist_own_vocabulary_stem_is_blocked_on_its_own(): void
    {
        $d = require dirname(__DIR__, 2) . '/resources/app-fingerprint-denylist.php';
        $stems = array_values((array) ($d['own_vocabulary'] ?? []));
        self::assertNotEmpty($stems, 'own_vocabulary must be non-empty for this parity check to mean anything');

        $pad = str_repeat('x', 60);
        foreach ($stems as $stem) {
            // Reduce a regex-shaped stem (e.g. `honeypot(?:s|ted)?`, `decept(?:ion|ive)`) to one
            // concrete literal word the pattern actually matches, so it can be dropped into real prose.
            // An OPTIONAL group (trailing `?`) is dropped entirely (the bare stem already matches); a
            // MANDATORY group (no trailing `?`, e.g. decept's `(?:ion|ive)`) keeps its first alternative
            // instead, since the bare stem alone would NOT satisfy that pattern.
            $literal = preg_replace_callback('/\(\?:([^)]*)\)(\??)/', static function (array $m): string {
                return $m[2] === '?' ? '' : explode('|', $m[1])[0];
            }, $stem);
            self::assertNotSame('', $literal, "could not derive a literal example from stem '{$stem}'");

            $html = "<html><body><p>a plain sentence mentioning {$literal} in passing. {$pad}</p></body></html>";
            self::assertNull(
                $this->s->sanitize($html),
                "own_vocabulary stem '{$stem}' (literal '{$literal}') must be blocked by the runtime sanitizer"
            );
        }
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

    // --- entity-encoded tells: a browser renders the tell, a raw strpos never sees it ---

    /**
     * @param bool $disclosure true for a self-disclosure tell (scanned by the assembled-page pass too);
     *                         false for an exploit shape, which only the raw-output prelude owns
     * @dataProvider entityEncodedTells
     */
    public function test_entity_encoded_tell_is_rejected_in_every_arm(string $label, string $encoded, bool $disclosure): void
    {
        $pad = str_repeat('x', 60);
        self::assertNull($this->s->sanitize("<html><body><p>{$encoded} {$pad}</p></body></html>", 'html'), "html: $label");
        self::assertNull($this->s->sanitize("APP_ENV=production\nNOTE={$encoded}\n{$pad}", 'text'), "text: $label");
        self::assertNull($this->s->sanitize('{"note":"' . $encoded . '","pad":"' . $pad . '"}', 'json'), "json: $label");
        self::assertNull($this->s->sanitizeToArray('{"note":"' . $encoded . '","pad":"' . $pad . '"}'), "slots: $label");
        if ($disclosure) {
            self::assertFalse($this->s->pageBodyOk("<html><body><p>{$encoded}</p></body></html>"), "pageBodyOk: $label");
            self::assertFalse($this->s->pageBodyOk("<html><body><p>{$encoded}</p></body></html>", true), "trusted chrome: $label");
        }
    }

    /** @return array<string,array{0:string,1:string,2:bool}> */
    public static function entityEncodedTells(): array
    {
        return [
            'decimal entity' => ['decimal', '&#104;oneypot', true],
            'hex entity' => ['hex', '&#x68;oneypot', true],
            'mixed-entity hyphen' => ['hyphen', 'security&#45;research', true],
            'entity + no-break spaces' => ['nbsp', 'as&#32;an&nbsp;ai', true],
            'own vocabulary' => ['own-vocab', 'this is a &#102;unnypot', true],
            'exploit list' => ['exploit', '&#101;val(document.cookie)', false],
        ];
    }

    public function test_split_across_cells_plus_entities_is_rejected(): void
    {
        self::assertFalse($this->s->pageBodyOk('<html><body><table><tr><td>&#104;oney</td><td>pot</td></tr></table></body></html>'));
        self::assertFalse($this->s->pageBodyOk('<html><body><td>tar</td><td>&#112;it</td> maze</body></html>'));
    }

    public function test_legitimate_entities_still_pass(): void
    {
        $pad = str_repeat('x', 60);
        $html = "<html><body><h1>Terms &amp; Conditions</h1><p>Use &lt;draft&gt; &quot;v2&quot; &copy; 2024 {$pad}</p></body></html>";
        self::assertSame($html, $this->s->sanitize($html));
        self::assertTrue($this->s->pageBodyOk($html));
    }

    // --- real-secret canaries: the deploy's own values have no legitimate presence in any body ---

    public function test_canary_value_is_rejected_raw_and_encoded_in_both_arms(): void
    {
        $s = new LlmOutputSanitizer(['s3cretVALUE123']);
        $pad = str_repeat('x', 60);
        self::assertNull($s->sanitize("<html><body><p>key=s3cretVALUE123 {$pad}</p></body></html>"));
        self::assertNull($s->sanitize("<html><body><p>key=&#115;3cretVALUE123 {$pad}</p></body></html>"));
        self::assertNull($s->sanitize("KEY=S3CRETvalue123\n{$pad}", 'text'));                 // case-insensitive
        self::assertNull($s->sanitizeToArray('{"heading":"s3cretVALUE123","pad":"' . $pad . '"}'));
        self::assertFalse($s->pageBodyOk('<html><body><td>s3cretVALUE123</td></body></html>'));
        self::assertFalse($s->pageBodyOk('<html><body><td>s3cretVALUE123</td></body></html>', true)); // trusted chrome too
        self::assertFalse($s->pageBodyOk('<html><body><td>&#115;3cretVALUE123</td></body></html>'));
        // Same sanitizer, a body without the value: unchanged behaviour.
        $ok = "<html><body><p>key=tok_7c1d20b4 {$pad}</p></body></html>";
        self::assertSame($ok, $s->sanitize($ok));
        self::assertTrue($s->pageBodyOk($ok));
    }

    public function test_short_and_empty_canaries_are_dropped(): void
    {
        // A short/common value would reject most bodies; the empties an unset knob yields must be inert.
        $s = new LlmOutputSanitizer(['', 'admin', 'pass1']);
        $pad = str_repeat('x', 60);
        $html = "<html><body><p>admin pass1 {$pad}</p></body></html>";
        self::assertSame($html, $s->sanitize($html));
    }

    // --- live-key shapes: rejected on RAW model output, accepted on assembled pages (our own bait) ---

    /** @return array<string,array{0:string}> shapes built by concatenation so no key literal sits in the repo */
    public static function liveKeyShapes(): array
    {
        return [
            'aws access key' => ['AKIA' . str_repeat('Q7', 8)],
            'stripe live' => ['sk_live_' . str_repeat('a1', 8)],
            'github pat' => ['ghp_' . str_repeat('b2', 12)],
            'slack bot' => ['xoxb-1234-abcd'],
            'jwt pair' => ['eyJ' . str_repeat('c', 24) . '.eyJ' . str_repeat('d', 24) . '.sig'],
        ];
    }

    /** @dataProvider liveKeyShapes */
    public function test_live_key_shape_rejected_on_raw_output_only(string $key): void
    {
        $pad = str_repeat('x', 60);
        self::assertNull($this->s->sanitize("<html><body><p>{$key} {$pad}</p></body></html>"), 'html');
        self::assertNull($this->s->sanitize("AWS_KEY={$key}\n{$pad}", 'text'), 'text');
        self::assertNull($this->s->sanitizeToArray('{"heading":"' . $key . '","pad":"' . $pad . '"}'), 'slots');
        $encoded = '&#' . ord($key[0]) . ';' . substr($key, 1);
        self::assertNull($this->s->sanitize("<html><body><p>{$encoded} {$pad}</p></body></html>"), 'entity-encoded');
        // The assembled-page pass carries our OWN bait of exactly these shapes — it must pass.
        self::assertTrue($this->s->pageBodyOk("<html><body><td>{$key}</td></body></html>"));
        self::assertTrue($this->s->pageBodyOk("<html><body><td>{$key}</td></body></html>", true));
    }

    public function test_assembled_panel_bait_keys_pass_page_body_ok(): void
    {
        // The real collision that scopes the shape scan: the persona AWS key and FakeSecrets values
        // are rendered into panel/slot pages by trusted chrome.
        $persona = VisualPersona::fromSeed(4242);
        $fs = FakeSecrets::fromSeed(4242);
        self::assertMatchesRegularExpression('/^AKIA[0-9A-Z]{16}$/', $persona->awsKey());
        $cells = '<td>' . $persona->awsKey() . '</td>';
        foreach ($fs->keys() as $k) {
            $cells .= '<td>' . $k['fullInert'] . '</td>';
        }
        foreach ($fs->envVars() as [$name, $value]) {
            $cells .= '<td>' . $name . '=' . $value . '</td>';
        }
        $body = '<html><body><table><tr>' . $cells . '</tr></table></body></html>';
        self::assertTrue($this->s->pageBodyOk($body, true));
        self::assertTrue($this->s->pageBodyOk($body));
    }

    public function test_exempted_persona_fake_values_pass_the_shape_scan_on_raw_output(): void
    {
        $persona = VisualPersona::fromSeed(4242);
        $stripe = '';
        foreach (FakeSecrets::fromSeed(4242)->envVars() as [$name, $value]) {
            if ($name === 'STRIPE_SECRET_KEY') {
                $stripe = $value;
            }
        }
        self::assertStringStartsWith('sk_live_', $stripe);
        $pad = str_repeat('x', 60);
        $body = "AWS_ACCESS_KEY_ID={$persona->awsKey()}\nSTRIPE_SECRET_KEY={$stripe}\n{$pad}";

        $exempting = new LlmOutputSanitizer([], [$persona->awsKey(), $stripe]);
        self::assertSame($body, $exempting->sanitize($body, 'text'));
        // A different key of the same shape is still rejected by the exempting sanitizer …
        self::assertNull($exempting->sanitize('AWS_ACCESS_KEY_ID=AKIA' . str_repeat('Z9', 8) . "\n{$pad}", 'text'));
        // … and without the exemption the persona value itself is (it is shape-indistinguishable from real).
        self::assertNull($this->s->sanitize($body, 'text'));
    }

    public function test_tok_style_bait_passes_everywhere(): void
    {
        $pad = str_repeat('x', 60);
        $html = "<html><body><td>tok_7c1d20b4</td><td>changeme_7c1d20</td><td>{$pad}</td></body></html>";
        self::assertSame($html, $this->s->sanitize($html));
        self::assertTrue($this->s->pageBodyOk($html));
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
        // FP-0112 review #1: pageBodyOk() is the whole-assembled-page pass (used by LlmFakeResponder's
        // panel emulator) and must carry the same own_vocabulary parity as sanitize()/prelude().
        self::assertFalse($s->pageBodyOk('<html><body>welcome to the funnypot control room</body></html>'));
        self::assertFalse($s->pageBodyOk('<html><body>you have entered the tarpit maze</body></html>'));
        self::assertFalse($s->pageBodyOk('<html><body><td>tar</td><td>pit</td> maze entry</body></html>')); // split
        // But a legitimate compound containing a stem as a SUBSTRING (not a whole token) must still pass
        // — pageBodyOk must not regress into the false-positive shape own_vocabulary is built to avoid.
        self::assertTrue($s->pageBodyOk('<html><body><h1>UsersController</h1><p>a graceful failure handler</p></body></html>'));
    }
}
