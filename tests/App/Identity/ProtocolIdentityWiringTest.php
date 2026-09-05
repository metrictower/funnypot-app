<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\SipIdentity;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Protocol\Ipmi\IpmiConfig;
use Funnypot\Protocol\Mssql\MssqlConfig;
use Funnypot\Protocol\Sip\SipConfig;
use Funnypot\Protocol\Smb\SmbConfig;
use PHPUnit\Framework\TestCase;

/**
 * The protocol tiers receive the install persona through injected identity, never from a persona
 * variable or a fleet literal: same install ⇒ same handshake identity, fresh install ⇒ different,
 * and every explicit service-specific override still wins.
 */
final class ProtocolIdentityWiringTest extends TestCase
{
    protected function tearDown(): void
    {
        foreach (['FUNNYPOT_SIP_EXTENSION_MODE', 'FUNNYPOT_SMB_GUID_SEED', 'FUNNYPOT_SMB_DOMAIN', 'FUNNYPOT_MSSQL_SEED', 'FUNNYPOT_IPMI_GUID', 'FUNNYPOT_PERSONA_SEED'] as $k) {
            putenv($k);
        }
    }

    public function test_sip_takes_seed_and_domain_from_the_injected_identity_only(): void
    {
        putenv('FUNNYPOT_PERSONA_SEED=ignored-by-sip');
        $id = SipIdentity::fromPersonaMaterial('install-persona-a');
        $cfg = SipConfig::fromEnv($id);
        self::assertSame(PersonaIdentity::seedFromMaterial('install-persona-a'), $cfg->personaSeed);
        self::assertNotSame(0, $cfg->personaSeed, 'never seed zero');
        self::assertSame('', $cfg->personaDomain, 'pattern mode carries no domain');

        putenv('FUNNYPOT_SIP_EXTENSION_MODE=org');
        $org = SipConfig::fromEnv($id);
        self::assertSame(VisualPersona::fromSeed($cfg->personaSeed)->domain(), $org->personaDomain, 'org mode: the SAME domain the office panels render');
        self::assertSame($cfg->personaSeed, SipConfig::fromEnv(SipIdentity::fromPersonaMaterial('install-persona-a'))->personaSeed, 'restart-stable');
        self::assertNotSame($cfg->personaSeed, SipConfig::fromEnv(SipIdentity::fromPersonaMaterial('install-persona-b'))->personaSeed, 'fresh install varies');
        self::assertNotSame(PersonaIdentity::seedFromMaterial('funnypot'), $cfg->personaSeed, 'never the retired fleet literal');
    }

    public function test_smb_guid_follows_the_install_persona_unless_overridden(): void
    {
        $a = SmbConfig::fromEnv('install-persona-a');
        self::assertSame(16, strlen($a->serverGuid()));
        self::assertSame($a->serverGuid(), SmbConfig::fromEnv('install-persona-a')->serverGuid(), 'restart-stable');
        self::assertNotSame($a->serverGuid(), SmbConfig::fromEnv('install-persona-b')->serverGuid(), 'fresh install varies');
        self::assertNotSame((new SmbConfig())->serverGuid(), $a->serverGuid(), 'never the domain\\computer fleet default');

        putenv('FUNNYPOT_SMB_DOMAIN=OTHERDOM');
        self::assertSame($a->serverGuid(), SmbConfig::fromEnv('install-persona-a')->serverGuid(), 'a cosmetic domain change does not move the GUID');
        putenv('FUNNYPOT_SMB_GUID_SEED=operator-guid-seed');
        $o = SmbConfig::fromEnv('install-persona-a');
        self::assertSame('operator-guid-seed', $o->serverGuidSeed, 'the explicit service override wins');
        self::assertNotSame($a->serverGuid(), $o->serverGuid());
    }

    public function test_mssql_seed_follows_the_install_persona_unless_overridden(): void
    {
        $a = MssqlConfig::fromEnv('install-persona-a');
        self::assertSame('install-persona-a', $a->personaSeed);
        self::assertSame($a->databases, MssqlConfig::fromEnv('install-persona-a')->databases);
        self::assertNotSame($a->databases, MssqlConfig::fromEnv('install-persona-b')->databases);
        putenv('FUNNYPOT_MSSQL_SEED=operator-seed');
        self::assertSame('operator-seed', MssqlConfig::fromEnv('install-persona-a')->personaSeed);
    }

    public function test_ipmi_guid_follows_the_install_persona_unless_overridden(): void
    {
        $a = IpmiConfig::fromEnv('install-persona-a');
        self::assertSame(16, strlen($a->guid));
        self::assertSame($a->guid, IpmiConfig::fromEnv('install-persona-a')->guid);
        self::assertNotSame($a->guid, IpmiConfig::fromEnv('install-persona-b')->guid);
        self::assertNotSame((new IpmiConfig())->guid, $a->guid, 'never the fleet-wide default GUID');
        putenv('FUNNYPOT_IPMI_GUID=ffeeddccbbaa99887766554433221100');
        self::assertSame(hex2bin('ffeeddccbbaa99887766554433221100'), IpmiConfig::fromEnv('install-persona-a')->guid);
    }
}
