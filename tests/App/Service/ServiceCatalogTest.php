<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Ops\PortManifest;
use Funnypot\App\Service\ServiceCatalog;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ServiceCatalogTest extends TestCase
{
    public function testProductionCatalogJoinsCleanly(): void
    {
        $c = ServiceCatalog::fromPackage();
        self::assertNotSame([], $c->services());
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $c->catalogHash());
    }

    public function testEveryListenerAndMediaEndpointHasExactlyOneOwner(): void
    {
        $manifest = PortManifest::fromFile(dirname(__DIR__, 3) . '/demo/ports.json');
        $c = ServiceCatalog::fromPackage();
        $owned = [];
        foreach ($c->services() as $desc) {
            foreach ($desc->endpoints as $ep) {
                self::assertArrayNotHasKey($ep->endpointId, $owned, "double-owned {$ep->endpointId}");
                $owned[$ep->endpointId] = $desc->id;
            }
        }
        foreach ($manifest->endpoints() as $row) {
            if (in_array($row['owner_kind'], ['listener', 'media-capability'], true)) {
                self::assertArrayHasKey($row['endpoint_id'], $owned, "unowned {$row['endpoint_id']}");
            }
        }
    }

    public function testProcessUnitsSumToTheCeiling(): void
    {
        $c = ServiceCatalog::fromPackage();
        $sum = 0;
        foreach ($c->services() as $desc) {
            $sum += $desc->processUnits;
        }
        // 39 listener services (cwmp = 2 processes) = 40 child processes; web-alias + rtp add 0.
        self::assertSame(40, $sum);
        self::assertSame(40, $c->processCeiling());
    }

    public function testEveryBundleResolvesToKnownServices(): void
    {
        $c = ServiceCatalog::fromPackage();
        self::assertNotSame([], $c->bundles());
        foreach ($c->bundles() as $b) {
            self::assertTrue($c->isBaseFamily($b->baseFamily));
            foreach ($b->required as $r) {
                self::assertNotNull($c->descriptor($r));
            }
        }
    }

    public function testRtpIsAMediaCapabilityRidingSipAndNotSelectable(): void
    {
        $c = ServiceCatalog::fromPackage();
        $rtp = $c->descriptor('rtp');
        self::assertNotNull($rtp);
        self::assertFalse($rtp->selectable);
        self::assertSame('sip', $rtp->mediaOf);
        self::assertSame('return-routable-media-v1', $rtp->udpClass);
        self::assertSame($rtp, $c->mediaFor('sip'));
    }

    public function testWindowsBusinessBundleDoesNotImplyFullAd(): void
    {
        $c = ServiceCatalog::fromPackage();
        $b = $c->bundle('windows-business');
        self::assertNotNull($b);
        self::assertSame(['smb', 'rdp'], $b->required);
        self::assertNotContains('kerberos', $b->required);
        self::assertNotContains('ldap', $b->required);
    }

    public function testOtBundlesAreDistinct(): void
    {
        $c = ServiceCatalog::fromPackage();
        self::assertSame(['modbus'], $c->bundle('ot-modbus-plc')->required);
        self::assertSame(['s7comm'], $c->bundle('ot-siemens-plc')->required);
        self::assertSame(['bacnet'], $c->bundle('ot-building-controller')->required);
        self::assertSame(['ethernet-ip'], $c->bundle('ot-ethernet-ip')->required);
    }

    public function testOrphanSemanticEndpointFailsClosed(): void
    {
        $manifest = PortManifest::fromFile(dirname(__DIR__, 3) . '/demo/ports.json');
        $this->expectException(RuntimeException::class);
        ServiceCatalog::fromSources($manifest, [
            'schema' => ServiceCatalog::SCHEMA,
            'base_families' => ['neutral'],
            'process_ceiling' => 1,
            'probe_ids' => ['tcp-connect-v1'],
            'udp_classes' => [],
            'services' => ['ghost' => ['label' => 'x', 'families' => ['neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'endpoint_ids' => ['does-not-exist']]],
            'bundles' => [],
            'conflict_groups' => [],
        ]);
    }

    public function testRawPortKeyInDescriptorFailsClosed(): void
    {
        $manifest = PortManifest::fromFile(dirname(__DIR__, 3) . '/demo/ports.json');
        $this->expectException(RuntimeException::class);
        ServiceCatalog::fromSources($manifest, [
            'schema' => ServiceCatalog::SCHEMA,
            'base_families' => ['neutral'],
            'process_ceiling' => 1,
            'probe_ids' => ['tcp-connect-v1'],
            'udp_classes' => [],
            'services' => ['ssh' => ['label' => 'x', 'families' => ['neutral'], 'process_units' => 1, 'probe_id' => 'tcp-connect-v1', 'port' => 22, 'endpoint_ids' => ['ssh-2222']]],
            'bundles' => [],
            'conflict_groups' => [],
        ]);
    }
}
