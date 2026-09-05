<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Service;

use Funnypot\App\Service\ServiceProfileConflictException;
use Funnypot\App\Service\ServiceProfileStore;
use PHPUnit\Framework\TestCase;

final class ServiceProfileStoreTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-sps-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0770, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->dir)) {
            exec('rm -rf ' . escapeshellarg($this->dir));
        }
    }

    private function store(): ServiceProfileStore
    {
        return new ServiceProfileStore($this->dir . '/service-profile.sqlite');
    }

    /** @return array{input_json:string,resolved_json:string,preview_hash:string,desired_hash:string,catalog_hash:string,published_hash:string} */
    private static function fields(string $tag): array
    {
        return [
            'input_json' => '{"mode":"named","bundle_id":"' . $tag . '"}',
            'resolved_json' => '{"r":"' . $tag . '"}',
            'preview_hash' => hash('sha256', 'preview-' . $tag),
            'desired_hash' => hash('sha256', 'desired-' . $tag),
            'catalog_hash' => str_repeat('c', 64),
            'published_hash' => str_repeat('p', 64),
        ];
    }

    public function testInitializeIfEmptyCommitsRevisionOneThenIsANoOp(): void
    {
        $s = $this->store();
        self::assertTrue($s->isEmpty());
        self::assertSame(1, $s->initializeIfEmpty(self::fields('linux-web'), 'system'));
        self::assertSame(1, $s->currentRevision());
        self::assertSame(1, $s->initializeIfEmpty(self::fields('windows-business'), 'system'));
        self::assertSame('{"mode":"named","bundle_id":"linux-web"}', $s->snapshot()['input_json']);
    }

    public function testApplyCasAdvancesTheRevision(): void
    {
        $s = $this->store();
        $s->initializeIfEmpty(self::fields('linux-web'), 'system');
        $f = self::fields('windows-business');
        $rev = $s->applyCas(1, $f['preview_hash'], static fn () => $f, 'op', '10.0.0.1');
        self::assertSame(2, $rev);
        self::assertSame(2, $s->currentRevision());
    }

    public function testStaleRevisionLosesAndChangesNothing(): void
    {
        $a = $this->store();
        $a->initializeIfEmpty(self::fields('linux-web'), 'system');
        $b = new ServiceProfileStore($this->dir . '/service-profile.sqlite');
        $f2 = self::fields('windows-business');
        self::assertSame(2, $a->applyCas(1, $f2['preview_hash'], static fn () => $f2, 'opA', '1.1.1.1'));

        $before = $b->snapshot();
        $auditBefore = count($b->audits());
        $f3 = self::fields('voip-pbx');
        try {
            $b->applyCas(1, $f3['preview_hash'], static fn () => $f3, 'opB', '2.2.2.2'); // still thinks rev is 1
            self::fail('expected conflict');
        } catch (ServiceProfileConflictException $e) {
            self::assertSame('stale-revision', $e->reason);
        }
        self::assertSame($before, $b->snapshot());
        self::assertCount($auditBefore, $b->audits());
    }

    public function testChangedPreviewHashIsRejected(): void
    {
        $s = $this->store();
        $s->initializeIfEmpty(self::fields('linux-web'), 'system');
        $f = self::fields('windows-business');
        $this->expectException(ServiceProfileConflictException::class);
        // operator expected an old preview hash but the fresh re-resolve produced a different one
        $s->applyCas(1, hash('sha256', 'stale-preview'), static fn () => $f, 'op', '3.3.3.3');
    }

    public function testInFlightReconciliationRejectsApply(): void
    {
        $s = $this->store();
        $s->initializeIfEmpty(self::fields('linux-web'), 'system');
        $lease = $s->claimForReconcile(1);
        self::assertSame(1, $s->inFlightRevision());
        $f = self::fields('windows-business');
        try {
            $s->applyCas(1, $f['preview_hash'], static fn () => $f, 'op', '4.4.4.4');
            self::fail('expected reconciling conflict');
        } catch (ServiceProfileConflictException $e) {
            self::assertSame('reconciling', $e->reason);
        }
        // a wrong lease cannot clear it; the real lease can.
        try {
            $s->finishReconcile('wrong-token');
            self::fail('expected lease-invalid');
        } catch (ServiceProfileConflictException $e) {
            self::assertSame('lease-invalid', $e->reason);
        }
        $s->finishReconcile($lease);
        self::assertNull($s->inFlightRevision());
    }

    public function testRollbackClaimedAppendsOnlyWhenTheFailedRevisionIsStillCurrent(): void
    {
        $s = $this->store();
        $s->initializeIfEmpty(self::fields('linux-web'), 'system');
        $f2 = self::fields('windows-business');
        $s->applyCas(1, $f2['preview_hash'], static fn () => $f2, 'op', '1.1.1.1'); // now rev 2
        $lease = $s->claimForReconcile(2);
        $lkg = self::fields('linux-web');
        $rev = $s->rollbackClaimed($lease, 2, static fn () => $lkg, 'health-failed');
        self::assertSame(3, $rev);
        self::assertSame('rollback', $s->audits()[0]['result']);
        self::assertNull($s->inFlightRevision());
    }

    public function testRollbackNeverOverwritesANewerOperatorRevision(): void
    {
        $s = $this->store();
        $s->initializeIfEmpty(self::fields('linux-web'), 'system');
        $lease = $s->claimForReconcile(1);
        // operator has NOT written a newer revision; simulate the failed revision no longer current by
        // rolling back against a mismatched failedRevision.
        $lkg = self::fields('linux-web');
        $rev = $s->rollbackClaimed($lease, 99, static fn () => $lkg, 'health-failed');
        self::assertSame(1, $rev); // unchanged; lease cleared
        self::assertNull($s->inFlightRevision());
    }
}
