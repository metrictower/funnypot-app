<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Ops;

use Funnypot\App\Ops\PortDrift;
use Funnypot\App\Ops\PortManifest;
use PHPUnit\Framework\TestCase;

/**
 * The drift gate: the committed nginx.conf, entrypoint.sh, Dockerfile, deploy.sh (run in its
 * print-only mode) and docker-compose.yml all agree with demo/ports.json; and each kind of drift or
 * ownership collision is reported as one exact line against a fixture manifest.
 */
final class PortDriftTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    public function test_committed_config_has_no_drift_against_the_manifest(): void
    {
        if (!function_exists('proc_open') || !is_executable('/bin/bash')) {
            self::markTestSkipped('needs proc_open and bash for the deploy script dry-run');
        }
        $m = PortManifest::fromFile(self::root() . '/demo/ports.json');
        $surfaces = self::productionSurfaces();
        $surfaces['deploy'] = PortDrift::deployPrintedFlags(self::root() . '/scripts/deploy.sh');
        foreach (array_keys($m->optInPublishes('deploy')) as $env) {
            $surfaces['deploy_opt_in'][$env] = PortDrift::deployPrintedFlags(self::root() . '/scripts/deploy.sh', [$env => '1']);
        }
        self::assertSame([], PortDrift::check($m, $surfaces));
        self::assertStringNotContainsString('-p 22:2222', $surfaces['deploy'], 'port 22 is opt-in');
        self::assertStringContainsString('-p 22:2222', $surfaces['deploy_opt_in']['FUNNYPOT_SSH_ON_22']);
    }

    public function test_deploy_print_mode_touches_nothing(): void
    {
        if (!function_exists('proc_open') || !is_executable('/bin/bash')) {
            self::markTestSkipped('needs proc_open and bash');
        }
        // A copy in an empty dir with a poisoned deploy.env beside it: print mode must not source
        // it, must not need a host/key/docker, and must not run docker or ssh.
        $tmp = sys_get_temp_dir() . '/fp_ports_' . bin2hex(random_bytes(4));
        mkdir($tmp . '/scripts/lib', 0755, true);
        mkdir($tmp . '/bin', 0755);
        copy(self::root() . '/scripts/deploy.sh', $tmp . '/scripts/deploy.sh');
        copy(self::root() . '/scripts/lib/dns-name.sh', $tmp . '/scripts/lib/dns-name.sh');
        file_put_contents($tmp . '/scripts/deploy.env', "echo POISONED >&2\nexit 99\n");
        foreach (['docker', 'ssh'] as $bin) {
            file_put_contents($tmp . '/bin/' . $bin, "#!/bin/sh\necho \"{$bin} $*\" >> \"{$tmp}/calls\"\nexit 0\n");
            chmod($tmp . '/bin/' . $bin, 0755);
        }
        try {
            $out = PortDrift::deployPrintedFlags($tmp . '/scripts/deploy.sh', ['PATH' => $tmp . '/bin:/usr/bin:/bin']);
            self::assertStringContainsString('-p 80:80', $out);
            self::assertStringContainsString('-p 5060:5060/udp', $out);
            self::assertFileDoesNotExist($tmp . '/calls', 'no docker/ssh was invoked');
        } finally {
            exec('rm -rf ' . escapeshellarg($tmp));
        }
    }

    /** @return array{nginx:string, entrypoint:string, dockerfile:string, compose:string, deploy:string, deploy_opt_in:array<string,string>} */
    private static function productionSurfaces(): array
    {
        return [
            'nginx' => (string) file_get_contents(self::root() . '/demo/nginx.conf'),
            'entrypoint' => (string) file_get_contents(self::root() . '/demo/entrypoint.sh'),
            'dockerfile' => (string) file_get_contents(self::root() . '/demo/Dockerfile'),
            'compose' => (string) file_get_contents(self::root() . '/demo/docker-compose.yml'),
            'deploy' => '',
            'deploy_opt_in' => [],
        ];
    }

    // ---- fixtures ------------------------------------------------------------------------------

    /** @return array{nginx:string, entrypoint:string, dockerfile:string, compose:string, deploy:string, deploy_opt_in:array<string,string>} */
    private static function cleanSurfaces(): array
    {
        return [
            'nginx' => "server {\n    listen 80 default_server;\n    listen 8080;\n}\nserver {\n    listen 443 ssl default_server;\n}\n",
            'entrypoint' => "spawn() { :; }\n    spawn adb         0.0.0.0:5555\n    spawn vnc 0.0.0.0:5900\n    spawn snmp 0.0.0.0:161  # udp\n",
            'dockerfile' => "FROM x\nEXPOSE 80 8080\nEXPOSE 443\nEXPOSE 5555 5900 10000/udp\nEXPOSE 161/udp\n",
            'compose' => "services:\n  funnypot:\n    ports:\n      - \"80:80\"\n      - \"443:443\"\n      - \"8080:8080\"\n    environment:\n      X: y\n",
            'deploy' => '-p 80:80 -p 443:443 -p 5555:5555 -p 5900:5900 -p 8080:8080 -p 161:161/udp -p 10000:10000/udp -p 5800:5900',
            'deploy_opt_in' => [],
        ];
    }

    private static function fixture(): PortManifest
    {
        return PortManifest::fromArray(PortManifestTest::minimalDoc());
    }

    public function test_clean_fixture_has_no_drift(): void
    {
        self::assertSame([], PortDrift::check(self::fixture(), self::cleanSurfaces()));
    }

    /**
     * @dataProvider drifts
     * @param callable(array<string,mixed>): array<string,mixed> $mutate
     */
    public function test_each_drift_is_one_exact_line(callable $mutate, string $expected): void
    {
        $problems = PortDrift::check(self::fixture(), $mutate(self::cleanSurfaces()));
        self::assertContains($expected, $problems, implode("\n", $problems));
    }

    /** @return iterable<string, array{0: callable, 1: string}> */
    public static function drifts(): iterable
    {
        yield 'extra nginx listen' => [static function (array $s): array { $s['nginx'] = str_replace('listen 8080;', "listen 8080;\n    listen 8888;", $s['nginx']); return $s; }, 'demo/nginx.conf: extra listen 8888'];
        yield 'missing nginx listen' => [static function (array $s): array { $s['nginx'] = str_replace("    listen 8080;\n", '', $s['nginx']); return $s; }, 'demo/nginx.conf: missing listen 8080'];
        yield 'nginx lost ssl' => [static function (array $s): array { $s['nginx'] = str_replace('listen 443 ssl default_server;', 'listen 443 default_server;', $s['nginx']); return $s; }, 'demo/nginx.conf: extra listen 443'];
        yield 'duplicate nginx listen' => [static function (array $s): array { $s['nginx'] .= "server {\n    listen 8080;\n}\n"; return $s; }, 'demo/nginx.conf: duplicate listen 8080 (x2)'];
        yield 'nginx and listener race for a port' => [static function (array $s): array { $s['nginx'] = str_replace('listen 8080;', "listen 8080;\n    listen 5555;", $s['nginx']); return $s; }, 'collision: tcp/5555 is listened by nginx and bound by listener process adb'];
        yield 'nginx and an undeclared spawn race for a port' => [static function (array $s): array {
            $s['nginx'] = str_replace('listen 8080;', "listen 8080;\n    listen 5556;", $s['nginx']);
            $s['entrypoint'] .= "    spawn newthing 0.0.0.0:5556\n";

            return $s;
        }, "collision: tcp/5556 is listened by nginx and bound by undeclared spawn 'newthing 0.0.0.0:5556'"];
        yield 'missing spawn' => [static function (array $s): array { $s['entrypoint'] = str_replace("    spawn adb         0.0.0.0:5555\n", '', $s['entrypoint']); return $s; }, 'demo/entrypoint.sh: missing spawn adb 0.0.0.0:5555'];
        yield 'extra spawn' => [static function (array $s): array { $s['entrypoint'] .= "    spawn ldap 0.0.0.0:389\n"; return $s; }, 'demo/entrypoint.sh: extra spawn ldap 0.0.0.0:389'];
        yield 'duplicate EXPOSE' => [static function (array $s): array { $s['dockerfile'] .= "EXPOSE 5555\n"; return $s; }, 'demo/Dockerfile: duplicate EXPOSE 5555 (x2)'];
        yield 'EXPOSE lists a forward alias' => [static function (array $s): array { $s['dockerfile'] .= "EXPOSE 5800\n"; return $s; }, 'demo/Dockerfile: extra EXPOSE 5800'];
        yield 'EXPOSE missing udp' => [static function (array $s): array { $s['dockerfile'] = str_replace("EXPOSE 161/udp\n", '', $s['dockerfile']); return $s; }, 'demo/Dockerfile: missing EXPOSE 161/udp'];
        yield 'compose extra port' => [static function (array $s): array { $s['compose'] = str_replace('- "8080:8080"', "- \"8080:8080\"\n      - \"9999:9999\"", $s['compose']); return $s; }, 'demo/docker-compose.yml: extra port 9999:9999'];
        yield 'compose missing port' => [static function (array $s): array { $s['compose'] = str_replace("      - \"8080:8080\"\n", '', $s['compose']); return $s; }, 'demo/docker-compose.yml: missing port 8080:8080'];
        yield 'deploy missing publish' => [static function (array $s): array { $s['deploy'] = str_replace(' -p 5555:5555', '', $s['deploy']); return $s; }, 'scripts/deploy.sh: missing publish 5555:5555'];
        yield 'deploy missing forward' => [static function (array $s): array { $s['deploy'] = str_replace(' -p 5800:5900', '', $s['deploy']); return $s; }, 'scripts/deploy.sh: missing publish 5800:5900'];
        yield 'deploy extra publish' => [static function (array $s): array { $s['deploy'] .= ' -p 22:2222'; return $s; }, 'scripts/deploy.sh: extra publish 22:2222'];
        yield 'deploy udp published as tcp' => [static function (array $s): array { $s['deploy'] = str_replace('-p 161:161/udp', '-p 161:161', $s['deploy']); return $s; }, 'scripts/deploy.sh: missing publish 161:161/udp'];
    }

    public function test_opt_in_publish_must_be_absent_by_default_and_present_when_armed(): void
    {
        $doc = PortManifestTest::minimalDoc();
        $doc['endpoints'][] = PortManifestTest::ep('ssh-alias-22', 'listener', 'tcp', 5900, ['host_port' => 22, 'service_id' => 'vnc', 'process_id' => 'vnc', 'forward_target_endpoint_id' => 'vnc-5900', 'deploy_opt_in' => 'FUNNYPOT_X_ON_22', 'runtime_toggleable' => true]);
        $m = PortManifest::fromJson(PortManifest::fromArray($doc)->canonicalJson());
        self::assertSame([], $m->validate());

        $s = self::cleanSurfaces();
        $s['deploy_opt_in'] = ['FUNNYPOT_X_ON_22' => $s['deploy'] . ' -p 22:5900'];
        self::assertSame([], PortDrift::check($m, $s));

        $leak = $s;
        $leak['deploy'] .= ' -p 22:5900';
        self::assertContains('scripts/deploy.sh: opt-in publish 22:5900 (FUNNYPOT_X_ON_22) is published by default', PortDrift::check($m, $leak));

        $inert = $s;
        $inert['deploy_opt_in'] = ['FUNNYPOT_X_ON_22' => $s['deploy']];
        self::assertContains('scripts/deploy.sh: missing publish 22:5900 with FUNNYPOT_X_ON_22=1', PortDrift::check($m, $inert));

        $missing = $s;
        $missing['deploy_opt_in'] = [];
        self::assertContains('scripts/deploy.sh: no printed flags for opt-in FUNNYPOT_X_ON_22=1', PortDrift::check($m, $missing));
    }

    public function test_parsers_read_the_real_syntaxes(): void
    {
        self::assertSame(['80', '443 ssl', '8443 ssl'], PortDrift::nginxListens("listen 80 default_server;\n# listen 81;\nlisten 443 ssl default_server;\n  listen 8443 ssl; # x\n"));
        self::assertSame(['redis 0.0.0.0:6379', 'cwmp 0.0.0.0:7548'], PortDrift::entrypointSpawns("    spawn redis       0.0.0.0:6379\n    spawn() { :; }\n    spawn cwmp        0.0.0.0:7548 # second\n"));
        self::assertSame(['80', '161/udp', '443'], PortDrift::dockerfileExposes("EXPOSE 80  161/udp\n# EXPOSE 9\nEXPOSE 443/tcp\n"));
        self::assertSame(['80:80', '5060:5060/udp'], PortDrift::composePublishes("services:\n  a:\n    ports:\n      # - \"1:1\"\n      - \"80:80\"\n      - 5060:5060/udp\n    volumes:\n      - \"9:9\"\n  b:\n    x:\n      - \"7:7\"\n"));
        self::assertSame(['80:80', '161:161/udp', '5061:5060'], PortDrift::publishFlags('-p 80:80/tcp -p 161:161/udp -p 5061:5060 -px 1:1'));
    }
}
