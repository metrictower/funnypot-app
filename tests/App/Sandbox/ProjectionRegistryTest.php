<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Sandbox;

use Funnypot\App\Sandbox\Projection\ProjectionDestinationOwner;
use Funnypot\App\Sandbox\Projection\ProjectionEntryRegistry;
use Funnypot\App\Sandbox\Projection\RestartConsumer;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class ProjectionRegistryTest extends TestCase
{
    public function testFoundationRegistryIsTheExactNineRows(): void
    {
        $registry = ProjectionEntryRegistry::v1();
        $records = $registry->records();
        self::assertCount(9, $records);
        self::assertSame([
            'web-http-identity', 'protocol-shell-identity', 'protocol-sip-identity', 'protocol-redis-identity',
            'edge-main-tls-certificate', 'edge-main-tls-private-key', 'edge-admin-tls-certificate',
            'edge-admin-tls-private-key', 'post-exploit-state-identity',
        ], array_column($records, 'entry_id'));
        self::assertNotContains('upload-sample', array_column($records, 'destination_owner'));
        foreach ($records as $record) {
            self::assertSame('exactly-one', $record['link_count_policy']);
            self::assertContains('direct-nofollow/v1', $record['attestation_ids']);
            self::assertSame(0500, $record['directory_mode']);
            self::assertStringStartsWith('views/' . $record['destination_owner'] . '/', $record['destination_path']);
        }
        self::assertSame('9d1788e41d0f5dc1bfd9e8b0e7f845bec28f5fb7860b0aed796c53bda44b9b48', $registry->registryHash());
    }

    public function testOwnerAndRestartVocabulariesAreSeparateExactEightValueEnums(): void
    {
        $ids = ['prepare', 'edge', 'web', 'protocols', 'worker', 'egress', 'post-exploit-state', 'upload-sample'];
        self::assertSame($ids, array_column(ProjectionDestinationOwner::cases(), 'value'));
        self::assertSame($ids, array_column(RestartConsumer::cases(), 'value'));
        self::assertSame([10005, 10005], ProjectionDestinationOwner::POST_EXPLOIT_STATE->ownership());
        self::assertSame([10006, 10006], ProjectionDestinationOwner::UPLOAD_SAMPLE->ownership());
    }

    public function testRegistryHasNoPublicMutationOrCallableRegistrationApi(): void
    {
        $methods = array_map(static fn ($m): string => $m->getName(), (new ReflectionClass(ProjectionEntryRegistry::class))->getMethods(\ReflectionMethod::IS_PUBLIC));
        self::assertSame(['__construct', 'v1', 'entry', 'entries', 'records', 'registryHash'], $methods);
        self::assertNotContains('register', $methods);
        self::assertNotContains('add', $methods);
    }
}
