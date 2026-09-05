<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use PHPUnit\Framework\TestCase;

/**
 * scripts/deploy.sh and scripts/letsencrypt.sh with docker/ssh stubbed: the identity preflight runs
 * the built image on the real data volume with --network none and no port, BEFORE the public
 * container is removed/replaced, under `set -e`; the master is never placed in argv; and an
 * injection-shaped Let's Encrypt domain is rejected before any ssh process exists.
 */
final class DeployPreflightTest extends TestCase
{
    private string $tmp = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open') || !is_executable('/bin/bash')) {
            self::markTestSkipped('needs proc_open and bash');
        }
        $this->tmp = sys_get_temp_dir() . '/fp_deploy_' . bin2hex(random_bytes(5));
        mkdir($this->tmp . '/repo/scripts/lib', 0755, true);
        mkdir($this->tmp . '/bin', 0755);
        mkdir($this->tmp . '/out', 0755);
        $root = dirname(__DIR__, 3);
        // A copy, so the real scripts/deploy.env (gitignored, operator secrets) is never sourced.
        copy($root . '/scripts/deploy.sh', $this->tmp . '/repo/scripts/deploy.sh');
        copy($root . '/scripts/letsencrypt.sh', $this->tmp . '/repo/scripts/letsencrypt.sh');
        copy($root . '/scripts/lib/dns-name.sh', $this->tmp . '/repo/scripts/lib/dns-name.sh');
        $this->stub('docker', "#!/bin/sh\necho \"docker \$*\" >> \"\$FP_OUT/docker.log\"\nexit 0\n");
        // Only the two invocations that PIPE data (the `bash -s` heredoc and the image ship stream)
        // may read stdin: the (re)start ssh has none, and reading an inherited stdin there would
        // block forever under a parallel runner whose worker stdin never closes.
        $this->stub('ssh', <<<'SH'
#!/bin/sh
n=$(ls "$FP_OUT" | grep -c '^ssh\..*\.argv' || true)
i=$((n + 1))
printf '%s\n' "$@" > "$FP_OUT/ssh.$i.argv"
case "$*" in
  *"bash -s"*) cat > "$FP_OUT/ssh.$i.stdin" ;;
  *"docker load"*) cat > /dev/null ;;
  *) : ;;
esac
exit 0
SH);
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '' && is_dir($this->tmp)) {
            exec('rm -rf ' . escapeshellarg($this->tmp));
        }
    }

    private function stub(string $name, string $body): void
    {
        file_put_contents($this->tmp . '/bin/' . $name, $body);
        chmod($this->tmp . '/bin/' . $name, 0755);
    }

    /**
     * @param array<string,string> $env
     * @return array{0:int,1:string,2:string}
     */
    private function runScript(string $script, array $env): array
    {
        $env += [
            'PATH' => $this->tmp . '/bin:/usr/bin:/bin',
            'FP_OUT' => $this->tmp . '/out',
            'HOME' => $this->tmp,
            'FUNNYPOT_HOST' => 'honeypot.example.test',
            'FUNNYPOT_KEY' => '/dev/null',
            'FUNNYPOT_CANARY' => '0',
            'FUNNYPOT_LLM_ON' => '0',
            'FUNNYPOT_ALLOW_DIRTY' => '1',
        ];
        $pipes = [];
        // stdin closed: no stub may ever wait on the runner's input.
        $p = proc_open(['/bin/bash', $this->tmp . '/repo/scripts/' . $script], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->tmp, $env);
        self::assertIsResource($p);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        return [proc_close($p), $out, $err];
    }

    private function remoteScript(): string
    {
        // ssh #1 installs docker, #2 is the image ship pipeline, the LAST one (re)starts the
        // container with the remote script as its final argv element.
        $files = glob($this->tmp . '/out/ssh.*.argv') ?: [];
        self::assertNotEmpty($files, 'ssh was invoked');
        natsort($files);
        $argv = (string) file_get_contents((string) end($files));
        $pos = strpos($argv, 'set -e');
        self::assertNotFalse($pos, 'remote script found in the last ssh invocation');

        return substr($argv, $pos);
    }

    public function test_preflight_precedes_replacement_with_no_network_no_ports_and_the_same_mounts(): void
    {
        [$rc, , $err] = $this->runScript('deploy.sh', ['LE_DOMAIN' => 'admin.example.com', 'FUNNYPOT_INSTALL_SECRET_FILE' => '/etc/funnypot/install.secret']);
        self::assertSame(0, $rc, $err);
        $remote = $this->remoteScript();

        $preflight = strpos($remote, 'identity:prepare');
        $remove = strpos($remote, 'docker rm -f funnypot');
        $public = strpos($remote, 'docker run -d --name funnypot');
        self::assertNotFalse($preflight);
        self::assertNotFalse($remove);
        self::assertNotFalse($public);
        self::assertLessThan($remove, $preflight, 'preflight BEFORE the public container is removed');
        self::assertLessThan($public, $remove);
        self::assertStringStartsWith('set -e', $remote, 'a failing preflight stops the remote script');

        $preflightCmd = substr($remote, (int) strrpos(substr($remote, 0, $preflight), 'docker run'), $preflight - (int) strrpos(substr($remote, 0, $preflight), 'docker run') + strlen('identity:prepare'));
        self::assertStringContainsString('--rm --network none', $preflightCmd);
        self::assertStringContainsString('--entrypoint php funnypot /app/bin/funnypot identity:prepare', $preflightCmd, 'exact entrypoint/argv separation');
        self::assertDoesNotMatchRegularExpression('/\s-p\s/', $preflightCmd, 'no port flag in the preflight');
        self::assertStringContainsString('-v "$DATA_DIR":/app/demo/storage', $preflightCmd, 'the REAL data volume');
        self::assertStringContainsString('-v /etc/letsencrypt:/etc/letsencrypt:ro', $preflightCmd);
        self::assertStringContainsString("-e FUNNYPOT_LE_DOMAIN='admin.example.com'", $preflightCmd, 'the same TLS selection inputs as the public run');
        self::assertStringContainsString('-v /etc/funnypot/install.secret:/run/secrets/funnypot-install-secret:ro -e FUNNYPOT_INSTALL_SECRET_FILE=/run/secrets/funnypot-install-secret', $preflightCmd, 'the protected file mount, not the value');

        $publicCmd = substr($remote, $public);
        self::assertStringContainsString('-v "$DATA_DIR":/app/demo/storage', $publicCmd);
        self::assertStringContainsString('-v /etc/funnypot/install.secret:/run/secrets/funnypot-install-secret:ro', $publicCmd);
        self::assertStringContainsString("-e FUNNYPOT_LE_DOMAIN='admin.example.com'", $publicCmd);
        self::assertStringNotContainsString('FUNNYPOT_INSTALL_SECRET=', $remote, 'the raw master is never in a remote command');
        $localLog = (string) file_get_contents($this->tmp . '/out/docker.log');
        self::assertStringNotContainsString('FUNNYPOT_INSTALL_SECRET=', $localLog);
    }

    public function test_injection_shaped_domain_is_rejected_before_any_ssh(): void
    {
        foreach (["admin.example.com'; touch /tmp/pwned; '", "admin.example.com\nlisten 80;", 'Admin.Example.com', '*.example.com'] as $bad) {
            [$rc, , $err] = $this->runScript('deploy.sh', ['LE_DOMAIN' => $bad]);
            self::assertSame(1, $rc);
            self::assertStringContainsString('LE_DOMAIN is not a valid lowercase DNS name', $err);
            self::assertStringNotContainsString('pwned', $err, 'the rejected value is never echoed');
            self::assertSame([], glob($this->tmp . '/out/ssh.*') ?: [], 'no ssh process was started');
            self::assertFileDoesNotExist($this->tmp . '/out/docker.log', 'rejected before the build');

            [$rc, , $err] = $this->runScript('letsencrypt.sh', ['LE_DOMAIN' => $bad, 'LE_EMAIL' => 'ops@example.com']);
            self::assertSame(1, $rc);
            self::assertStringContainsString('LE_DOMAIN is not a valid lowercase DNS name', $err);
            self::assertSame([], glob($this->tmp . '/out/ssh.*') ?: []);
        }
        [$rc, , $err] = $this->runScript('deploy.sh', ['FUNNYPOT_INSTALL_SECRET_FILE' => '/etc/x; rm -rf /']);
        self::assertSame(1, $rc);
        self::assertStringContainsString('FUNNYPOT_INSTALL_SECRET_FILE must be an absolute path', $err);
        self::assertSame([], glob($this->tmp . '/out/ssh.*') ?: []);
    }

    public function test_shell_grammar_matches_the_php_grammar(): void
    {
        $lib = dirname(__DIR__, 3) . '/scripts/lib/dns-name.sh';
        foreach (['admin.example.com' => true, 'a' => true, 'sub-1.example.co.uk' => true, 'Admin.example.com' => false, '-a.example' => false, 'a..b' => false, 'a/b' => false, 'a,b' => false, str_repeat('a', 64) . '.x' => false, "ok.example\nlisten 80;" => false, "ok.example\r" => false] as $name => $valid) {
            $rc = 1;
            exec('sh -c ' . escapeshellarg(". {$lib}; funnypot_dns_name_valid " . escapeshellarg($name)), $o, $rc);
            self::assertSame($valid, $rc === 0, "shell grammar for '{$name}'");
            self::assertSame($valid, \Funnypot\App\Tls\DnsName::isValid($name), "php grammar for '{$name}'");
        }
    }
}
