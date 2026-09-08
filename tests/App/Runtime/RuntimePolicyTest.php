<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Runtime;

use Funnypot\App\Runtime\RuntimePolicy;
use Funnypot\App\Runtime\RuntimePolicyException;
use PHPUnit\Framework\TestCase;

final class RuntimePolicyTest extends TestCase
{
    private const ROLES = [
        ['role_id' => 'prepare', 'uid' => 0, 'gid' => 0, 'supplemental_gids' => [], 'long_lived' => false],
        ['role_id' => 'edge', 'uid' => 10001, 'gid' => 10001, 'supplemental_gids' => [], 'long_lived' => true],
        ['role_id' => 'web', 'uid' => 10007, 'gid' => 10007, 'supplemental_gids' => [10000], 'long_lived' => true],
        ['role_id' => 'protocols', 'uid' => 10002, 'gid' => 10002, 'supplemental_gids' => [10000], 'long_lived' => true],
        ['role_id' => 'worker', 'uid' => 10003, 'gid' => 10003, 'supplemental_gids' => [10000], 'long_lived' => true],
        ['role_id' => 'egress', 'uid' => 10004, 'gid' => 10004, 'supplemental_gids' => [], 'long_lived' => true],
    ];

    public function testPackagePolicyIsTheExactSixRoleIdentityLifecycleAuthority(): void
    {
        $policy = RuntimePolicy::fromPackage();
        self::assertSame(['schema' => RuntimePolicy::SCHEMA, 'roles' => self::ROLES], $policy->toArray());
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $policy->policyHash());
        self::assertNull($policy->role('post-exploit-state'));
        self::assertNull($policy->role('upload-sample'));
    }

    /** @dataProvider invalidResources */
    public function testClosedParserRejectsMissingDuplicateUnknownAndTopologyFields(array $doc): void
    {
        $this->expectException(RuntimePolicyException::class);
        RuntimePolicy::fromArray($doc);
    }

    public static function invalidResources(): iterable
    {
        $base = ['schema' => RuntimePolicy::SCHEMA, 'roles' => self::ROLES];
        $missing = $base;
        array_pop($missing['roles']);
        yield 'missing role' => [$missing];
        $duplicate = $base;
        $duplicate['roles'][5] = $duplicate['roles'][4];
        yield 'duplicate role' => [$duplicate];
        foreach (['command', 'view', 'mount', 'network', 'resource', 'image', 'compose', 'docker', 'seccomp', 'deployment'] as $field) {
            $extra = $base;
            $extra['roles'][0][$field] = 'forbidden';
            yield "forbidden {$field}" => [$extra];
        }
        $owner = $base;
        $owner['roles'][5]['uid'] = 10003;
        $owner['roles'][5]['gid'] = 10003;
        yield 'duplicate numeric owner' => [$owner];
        $tuple = $base;
        $tuple['roles'][2]['uid'] = 12345;
        yield 'changed fixed tuple' => [$tuple];
        $lifecycle = $base;
        $lifecycle['roles'][1]['long_lived'] = false;
        yield 'changed lifecycle' => [$lifecycle];
        $groups = $base;
        $groups['roles'][5]['supplemental_gids'] = [10000];
        yield 'changed supplemental groups' => [$groups];
    }
}
