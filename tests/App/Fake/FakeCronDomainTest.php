<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Fake;

use Funnypot\App\Render\Fake\FakeCron;
use PHPUnit\Framework\TestCase;

/**
 * One host = one domain: the cron heartbeat must not invent a second public FQDN alongside the host's
 * persona domain. When a persona domain is supplied it renders there; standalone it hits an internal
 * RFC1918 service host — never a second registrable domain an attacker could pivot on.
 */
final class FakeCronDomainTest extends TestCase
{
    /** The heartbeat command line for a seed/domain, or '' if none is present in the slice. */
    private function heartbeat(FakeCron $cron): string
    {
        foreach ($cron->cronJobs() as $r) {
            if (strpos($r['command'], '/heartbeat/') !== false) {
                return $r['command'];
            }
        }
        return '';
    }

    public function test_persona_domain_is_used_verbatim(): void
    {
        $cmd = $this->heartbeat(FakeCron::fromSeed(4242, 'acme.example'));
        self::assertNotSame('', $cmd, 'heartbeat present in the first-8 anchors');
        self::assertStringContainsString('https://api.acme.example/', $cmd);
        // No invented second domain sneaks in beside the persona one.
        self::assertStringNotContainsString('.io/', $cmd);
    }

    public function test_standalone_heartbeat_hits_an_internal_rfc1918_host(): void
    {
        $cmd = $this->heartbeat(FakeCron::fromSeed(4242));
        self::assertNotSame('', $cmd);
        // No public FQDN: the endpoint is an RFC1918 10.x service host.
        self::assertMatchesRegularExpression('#https://10\.0\.5\.\d{1,3}/#', $cmd);
        self::assertDoesNotMatchRegularExpression('#https://[a-z0-9.-]+\.(io|com|net|co)/#', $cmd);
    }

    public function test_no_second_public_domain_across_seeds(): void
    {
        // Every command a persona-domain cron table renders must reference no host outside the persona
        // domain (RFC1918 peers and bucket/rclone/borg storage names are not FQDNs and are allowed).
        for ($seed = 0; $seed < 8; $seed++) {
            $cron = FakeCron::fromSeed($seed, 'acme.example');
            foreach ($cron->cronJobs() as $r) {
                if (preg_match_all('#https?://([a-z0-9.-]+)#i', $r['command'], $m)) {
                    foreach ($m[1] as $host) {
                        $isPersona = ($host === 'acme.example' || substr($host, -strlen('.acme.example')) === '.acme.example');
                        $isPrivate = (strpos($host, '10.') === 0);
                        self::assertTrue($isPersona || $isPrivate, "seed $seed host $host is persona or RFC1918");
                    }
                }
            }
        }
    }

    public function test_still_deterministic_per_seed(): void
    {
        self::assertSame(
            FakeCron::fromSeed(4242, 'acme.example')->cronJobs(),
            FakeCron::fromSeed(4242, 'acme.example')->cronJobs()
        );
        self::assertSame(FakeCron::fromSeed(9)->cronJobs(), FakeCron::fromSeed(9)->cronJobs());
    }
}
