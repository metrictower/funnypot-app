<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit\Mint;

use Funnypot\App\Tarpit\Mint\MintForms;
use Funnypot\App\Tarpit\Mint\MintRequest;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

final class MintFormsTest extends TestCase
{
    private static function never(): \Closure
    {
        return static fn (string $x): bool => false;
    }

    public function test_join_rules_alone_and_all_at_once(): void
    {
        self::assertSame([], MintForms::join('artex1', 'a@example.com', 'Passw0rd!x', 'Passw0rd!x', self::never(), self::never()));
        self::assertSame(['username' => 'username_invalid'], MintForms::join('a', 'a@example.com', 'Passw0rd!x', 'Passw0rd!x', self::never(), self::never()));
        self::assertSame(['username' => 'username_taken'], MintForms::join('jdoe', 'a@example.com', 'Passw0rd!x', 'Passw0rd!x', static fn (string $u): bool => $u === 'jdoe', self::never()));
        self::assertSame(['email' => 'email_taken'], MintForms::join('artex1', 'a@example.com', 'Passw0rd!x', 'Passw0rd!x', self::never(), static fn (): bool => true));
        self::assertSame(['password_confirmation' => 'password_mismatch'], MintForms::join('artex1', 'a@example.com', 'Passw0rd!x', 'other-one', self::never(), self::never()));
        self::assertSame(
            ['username' => 'username_invalid', 'email' => 'email_invalid', 'password' => 'password_length'],
            MintForms::join('<x>', 'not-an-email', 'short', 'short', self::never(), self::never()),
            'every failure of the stage at once'
        );
        self::assertSame(['password' => 'password_length'], MintForms::join('artex1', 'a@example.com', str_repeat('a', 73), str_repeat('a', 73), self::never(), self::never()));
        foreach (["a\0b", 'ab<', "a\u{e9}b", 'a b', '-ab'] as $bad) {
            self::assertArrayHasKey('username', MintForms::join($bad, 'a@example.com', 'Passw0rd!x', 'Passw0rd!x', self::never(), self::never()), $bad);
        }
        foreach (['a@b', 'a"b@x.com', "a@x.com\n", 'a@x.c', str_repeat('a', 65) . '@x.com'] as $bad) {
            self::assertArrayHasKey('email', MintForms::join('artex1', $bad, 'Passw0rd!x', 'Passw0rd!x', self::never(), self::never()), $bad);
        }
    }

    public function test_token_field_stage(): void
    {
        self::assertSame([], MintForms::token('ci token', '30', ['read:user'], self::never()));
        self::assertSame(['note' => 'note_blank'], MintForms::token('   ', '30', ['read:user'], self::never()));
        self::assertSame(['note' => 'note_long'], MintForms::token(str_repeat('a', 101), '30', ['read:user'], self::never()));
        self::assertSame(['note' => 'note_taken'], MintForms::token('dup', '30', ['read:user'], static fn (): bool => true));
        self::assertSame(['scopes' => 'scopes_none'], MintForms::token('n', '30', [], self::never()));
        self::assertSame(['scopes' => 'scopes_none'], MintForms::token('n', '30', null, self::never()), 'a non-list scopes field counts as none');
        self::assertSame(['scopes' => 'scopes_unknown'], MintForms::token('n', '30', ['read:user', 'repo'], self::never()));
        self::assertSame(['expiration' => 'expiration_none'], MintForms::token('n', 'none', ['read:user'], self::never()));
        self::assertSame(['expiration' => 'expiration_bad'], MintForms::token('n', '365', ['read:user'], self::never()));
        foreach (['<script>', "a\"b", "a'b", 'a&b', "a\0b", "caf\u{e9}"] as $bad) {
            self::assertSame(['note' => 'note_charset'], MintForms::token($bad, '30', ['read:user'], self::never()), $bad);
        }
        self::assertCount(3, MintForms::token(null, null, null, self::never()));
    }

    public function test_app_rules_and_callback_forms(): void
    {
        self::assertSame([], MintForms::app('my-app', 'https://app.example.com', 'https://app.example.com/cb', '', self::never()));
        foreach (MintForms::CALLBACK_FORMS as $kind => $form) {
            foreach ($form['examples'] as $cb) {
                self::assertTrue(MintForms::validCallback($cb), "{$kind}: {$cb}");
            }
        }
        foreach (MintForms::REFUSED_CALLBACKS as $cb) {
            self::assertFalse(MintForms::validCallback($cb), $cb);
            self::assertSame(['callback_url' => 'callback_invalid'], MintForms::app('a', 'https://a.example.com', $cb, '', self::never()), 'the ordinary invalid-callback error');
        }
        foreach (['http://evil.example/cb', 'javascript:alert(1)', 'https://a.example.com/"x', 'ftp://a.example.com/', 'https://a.example.com/#x', 'https://' . str_repeat('a', 200) . '.com', '//evil.example/cb', 'http://127.0.0.2/cb', 'http://localhost.evil.example/cb'] as $bad) {
            self::assertFalse(MintForms::validCallback($bad), $bad);
        }
        self::assertSame(['description' => 'description_charset'], MintForms::app('a', 'https://a.example.com', 'https://a.example.com/cb', '<b>', self::never()));
        self::assertSame(['description' => 'description_long'], MintForms::app('a', 'https://a.example.com', 'https://a.example.com/cb', str_repeat('a', 201), self::never()));
        self::assertSame(['name' => 'app_name_taken'], MintForms::app('a', 'https://a.example.com', 'https://a.example.com/cb', '', static fn (): bool => true));
        self::assertCount(3, MintForms::app(null, null, null, null, self::never()));
    }

    public function test_type_confusion_reads_as_missing_without_a_warning(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            if ((error_reporting() & $no) === 0) {
                return true;
            }
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            $match = ['route' => 'tokens', 'methods' => ['GET', 'POST'], 'params' => [], 'api' => false, 'pattern' => false];
            $body = 'note%5B%5D=x&scopes=read%3Auser&scopes2%5Ba%5D%5Bb%5D=c&csrf_token%5B%5D=y&expiration%5Bx%5D=30';
            $r = MintRequest::parse(new RequestContext('POST', '/settings/tokens', '', ['Content-Type' => 'application/x-www-form-urlencoded'], $body), $match, '1.2.3.4');
            self::assertNull($r->str('note'));
            self::assertNull($r->strList('scopes'), 'a scalar where a list is expected');
            self::assertNull($r->strList('scopes2'), 'a nested map is not a list of strings');
            self::assertNull($r->str('csrf_token'));
            self::assertNull($r->str('expiration'));
            self::assertCount(3, MintForms::token($r->str('note'), $r->str('expiration'), $r->strList('scopes'), self::never()));

            $json = MintRequest::parse(new RequestContext('POST', '/api/v2/user', '', ['Content-Type' => 'application/json'], '[1,2,3]'), $match, '1.2.3.4');
            self::assertTrue($json->badJson, 'a JSON array where an object is expected');
            $deep = MintRequest::parse(new RequestContext('POST', '/api/v2/user', '', ['Content-Type' => 'application/json'], '{"a":{"b":{"c":{"d":1}}}}'), $match, '1.2.3.4');
            self::assertTrue($deep->badJson, 'deeper than four levels');
            $many = MintRequest::parse(new RequestContext('POST', '/settings/tokens', str_repeat('q=1&', 3000), ['Content-Type' => 'application/x-www-form-urlencoded'], str_repeat('a=1&', 4000)), $match, '1.2.3.4');
            self::assertFalse($many->tooLarge);
            self::assertLessThanOrEqual(MintRequest::MAX_PAIRS, count($many->body));
            $big = MintRequest::parse(new RequestContext('POST', '/settings/tokens', '', [], str_repeat('a', MintRequest::MAX_BODY + 1)), $match, '1.2.3.4');
            self::assertTrue($big->tooLarge);
            $list = MintRequest::parse(new RequestContext('POST', '/settings/tokens', '', [], http_build_query(['scopes' => array_fill(0, 40, 'read:user')])), $match, '1.2.3.4');
            self::assertNull($list->strList('scopes'), 'more than 32 scopes is not a list we read');
        } finally {
            restore_error_handler();
        }
    }

    public function test_profile_rules(): void
    {
        self::assertSame([], MintForms::profile('Ar Tex', 'build/ci owner: team@example.com, v2.0-rc_1 +1=ok'));
        self::assertSame(['name' => 'name_charset', 'bio' => 'bio_long'], MintForms::profile('<x>', str_repeat('a', 161)));
        self::assertSame([], MintForms::profile(null, null));
    }
}
