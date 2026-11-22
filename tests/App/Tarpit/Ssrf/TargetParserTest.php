<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Ssrf;

use Funnypot\App\Tarpit\Ssrf\TargetParser;
use PHPUnit\Framework\TestCase;

final class TargetParserTest extends TestCase
{
    public function test_only_http_and_https_are_accepted(): void
    {
        $refused = ['file:///etc/passwd', 'gopher://x/_', 'ftp://x/a', 'dict://x:11211/', 'ldap://x/', 'javascript:alert(1)', 'data:text/plain,x',
            'mailto:a@b.example', '//x.example/', 'http:/x.example/', 'tftp://x/a'];
        foreach ($refused as $u) {
            [$t, $err] = TargetParser::check($u);
            self::assertNull($t, $u);
            self::assertContains($err, ['scheme', 'syntax'], $u);
        }
        self::assertCount(11, $refused);
        self::assertSame('http', TargetParser::parse('HTTP://a.example/')?->scheme);
        self::assertSame(443, TargetParser::parse('https://a.example/')?->port);
    }

    /** @return array<string,array{0:string,1:list<string>}> */
    public static function spellings(): array
    {
        return [
            'loopback' => ['127.0.0.1', ['127.0.0.1', '2130706433', '0x7f000001', '0X7F000001', '017700000001', '127.1', '127.0.1', '0x7f.0.0.1',
                '0177.0.0.1', '0x7f.1', '127.000.000.001', '127.0.0.1.', '0x7f.0x0.0x0.0x1',
                '00000000000177.0.0.1', '0x0000000000007f.1', '127.0.00000000000000000.1', '0' . str_repeat('0', 40) . '17700000001']],
            'metadata' => ['169.254.169.254', ['169.254.169.254', '2852039166', '0xa9fea9fe', '025177524776', '169.254.43518', '0xa9.0xfe.0xa9.0xfe',
                '0251.0376.0251.0376', '169.16689662', '0xa9.16689662', '0251.254.169.254', '169.0376.0251.0376', '169.254.0xa9fe']],
            'source' => ['10.213.87.2', ['10.213.87.2', '181753602', '0x0ad55702', '01265253402', '10.213.22274', '10.13981442', '0xa.0xd5.0x57.0x2',
                '012.0325.0127.02', '10.0325.87.2', '0xa.213.87.2', '10.213.0x57.2', '10.213.87.02']],
            'zero' => ['0.0.0.0', ['0', '0x0', '0.0', '0.0.0.0', '00', '0x00000000']],
        ];
    }

    public function test_every_ipv4_spelling_canonicalises(): void
    {
        foreach (self::spellings() as $case => [$canonical, $list]) {
            if ($case !== 'zero') {
                self::assertGreaterThanOrEqual(12, count($list), $case);
            }
            foreach ($list as $s) {
                $t = TargetParser::parse('http://' . $s . ':8080/x');
                self::assertNotNull($t, $s);
                self::assertSame('ipv4', $t->kind, $s);
                self::assertSame($canonical, $t->host, $s);
            }
        }
        foreach (['1.2.3.999', '0x1g.1.1.1', '08.1.1.1', '256.1.1.1', '1.2.3.4.5', '4294967296', '99999999999', '0x1ffffffff', '0400000000000',
            '1.' . str_repeat('0', 64)] as $bad) {
            self::assertSame('host', TargetParser::check('http://' . $bad . '/')[1], $bad);
        }
        self::assertSame('name', TargetParser::parse('http://127.0.0.1.nip.io/')?->kind, 'a name whose last label is not a number');
    }

    public function test_userinfo_and_fragment_confusion_follow_curl(): void
    {
        $t = TargetParser::parse('http://127.0.0.1:80@listener.tld/');
        self::assertSame('listener.tld', $t?->host);
        self::assertSame('127.0.0.1', $t?->user);
        self::assertSame('80', $t?->pass);
        self::assertSame('listener.tld', TargetParser::parse('http://listener.tld#@127.0.0.1/')?->host);
        self::assertSame('listener.tld', TargetParser::parse('http://a@b@listener.tld/')?->host, 'the host follows the last @');
        self::assertSame('charset', TargetParser::check('http://listener.tld\\@127.0.0.1/')[1], 'a backslash is refused');
        self::assertSame('charset', TargetParser::check("http://a.example/ x")[1]);
        self::assertSame('/', TargetParser::parse('http://a.example')?->path);
        self::assertSame('q=1', TargetParser::parse('http://a.example/p?q=1#f')?->query);
    }

    public function test_ipv6_literals_and_zone_ids(): void
    {
        self::assertSame('[::1]', TargetParser::parse('http://[::1]:6379/')?->host);
        self::assertSame(6379, TargetParser::parse('http://[::1]:6379/')?->port);
        self::assertSame('[::ffff:127.0.0.1]', TargetParser::parse('http://[::ffff:127.0.0.1]/')?->host);
        self::assertSame('[fe80::1]', TargetParser::parse('http://[fe80::1%25eth0]/')?->host);
        self::assertSame('[fd00:ec2::254]', TargetParser::parse('http://[FD00:EC2::254]/')?->host);
        self::assertSame('ipv6', TargetParser::parse('http://[::]/')?->kind);
        foreach (['http://[::1/', 'http://[zz::1]/', 'http://[127.0.0.1]/', 'http://[::1]x/', 'http://[fe80::1%25]/'] as $bad) {
            self::assertNull(TargetParser::parse($bad), $bad);
        }
        self::assertSame('charset', TargetParser::check('http://a.example/[x]')[1], 'brackets only in the host');
    }

    public function test_percent_encoded_control_bytes_are_refused(): void
    {
        foreach (['%0a', '%0D', '%00', '%7f', '%1b'] as $c) {
            self::assertSame('control', TargetParser::check('http://a.example/x' . $c . 'y')[1], $c);
        }
        self::assertSame('syntax', TargetParser::check('http://a.example/%zz')[1]);
        self::assertNotNull(TargetParser::parse('http://a.example/%20x'));
        self::assertSame('length', TargetParser::check('http://a.example/' . str_repeat('a', 500))[1]);
        self::assertSame('port', TargetParser::check('http://a.example:70000/')[1]);
        self::assertSame('port', TargetParser::check('http://a.example:0/')[1]);
    }

    public function test_parse_is_linear(): void
    {
        mt_srand(816);
        $alphabet = 'abc019.:/?#@%[]xX-_';
        $checked = 0;
        for ($i = 0; $i < 3000; $i++) {
            $len = mt_rand(1, 500);
            $u = 'http://';
            for ($j = 0; $j < $len; $j++) {
                $u .= $alphabet[mt_rand(0, strlen($alphabet) - 1)];
            }
            $steps = 0;
            TargetParser::check($u, $steps);
            self::assertLessThanOrEqual(4 * strlen($u), $steps, $u);
            $checked++;
        }
        $steps = 0;
        TargetParser::check('http://' . str_repeat('1.', 120) . '1/', $steps);
        self::assertGreaterThan(0, $steps);
        self::assertSame(3000, $checked);
    }

    public function test_masking_hides_userinfo_and_presign_values(): void
    {
        $key = 'AK' . 'IAQ3EGRMPLX7CANARY1';
        $u = 'http://' . $key . ':s3cr3tCANARY@sts.eu-west-2.internal/?Action=GetCallerIdentity&X-Amz-Credential=' . $key
            . '%2F20261122%2Feu-west-2%2Fsts%2Faws4_request&X-Amz-Signature=deadbeefCANARY&x-amz-security-token=tokCANARY&a=1#frag';
        $m = TargetParser::mask($u);
        self::assertStringNotContainsString('CANARY', $m);
        self::assertSame('http://***@sts.eu-west-2.internal/?Action=GetCallerIdentity&X-Amz-Credential=***&X-Amz-Signature=***&x-amz-security-token=***&a=1#frag', $m);
        self::assertSame('http://a.example/p', TargetParser::mask('http://a.example/p'));
    }

    public function test_masking_covers_every_pair_and_the_sigv2_names(): void
    {
        $u = 'http://172.16.0.5/?' . str_repeat('a&', 65) . 'X-Amz-Signature=SIGCANARY999999&AWSAccessKeyId=AKCANARY&SecurityToken=TOKCANARY';
        $m = TargetParser::mask($u);
        self::assertStringNotContainsString('CANARY', $m, 'a credential after the 64th pair is masked too');
        self::assertStringEndsWith('X-Amz-Signature=***&AWSAccessKeyId=***&SecurityToken=***', $m);
        $pairs = TargetParser::queryPairs(substr($u, strpos($u, '?') + 1));
        self::assertSame('SIGCANARY999999', $pairs['x-amz-signature'], 'reading sees every pair');
    }

    public function test_an_accepted_url_still_parses_once_masked(): void
    {
        $long = 'http://a@172.16.0.5/' . str_repeat('p', 512 - strlen('http://a@172.16.0.5/'));
        self::assertSame(512, strlen($long));
        self::assertNotNull(TargetParser::parse($long), 'the raw URL is within the limit');
        self::assertNull(TargetParser::parse(TargetParser::mask($long)), 'masking lengthened it past the limit');
        self::assertSame('url_invalid', \Funnypot\App\Tarpit\Ssrf\SsrfForms::url($long, true)[1], 'so it is refused at save, never stored broken');
        mt_srand(8162);
        for ($i = 0; $i < 2000; $i++) {
            $u = 'http://' . (mt_rand(0, 1) ? str_repeat('u', mt_rand(1, 3)) . ':' . str_repeat('p', mt_rand(0, 3)) . '@' : '') . '172.16.0.' . mt_rand(1, 250) . '/'
                . str_repeat('x', mt_rand(0, 420)) . '?a=1&signature=' . str_repeat('s', mt_rand(0, 4)) . '&x-amz-credential=' . str_repeat('c', mt_rand(0, 3));
            if (\Funnypot\App\Tarpit\Ssrf\SsrfForms::url($u, true)[1] === null) {
                self::assertNotNull(TargetParser::parse(TargetParser::mask($u)), "accepted, so its masked form parses: {$u}");
            }
        }
    }
}
