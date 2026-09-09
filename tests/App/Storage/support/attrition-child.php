<?php

declare(strict_types=1);

// FP-0272 concurrency worker: one bounded store action against a shared attrition.sqlite, driven by
// AttritionStoreConcurrencyTest. It prints one JSON fact line and exits. Deterministic inputs (fixed
// key/peer/route/clock) so every worker targets the SAME journey/job/generation.

use Funnypot\App\Storage\SqliteAttritionStore;
use Funnypot\App\Tarpit\Attrition\AttritionLimits;
use Funnypot\App\Tarpit\Attrition\AttritionStateCost;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use Funnypot\App\Tarpit\Attrition\JobCandidate;
use Funnypot\App\Tarpit\Attrition\ManifestCommit;

require dirname(__DIR__, 4) . '/vendor/autoload.php';

$dbPath = (string) ($argv[1] ?? '');
$action = (string) ($argv[2] ?? '');
$now = 1757000000;

$codec = new AttritionTokenCodec(str_repeat("\x5a", 32));
$store = new SqliteAttritionStore($dbPath, new AttritionLimits(21600, 32, 64, 50000, 64), static fn (): int => $now);

$entry = $codec->issueEntry('/admin/audit-archive/page-000002', '203.0.113.9', $now, 21600);
$eh = $codec->verifyExpectedKind($entry, 'e', $now);
$jobTok = $codec->deriveJob($eh);
$jh = $codec->verifyExpectedKind($jobTok, 'j', $now);
$m0 = $codec->deriveFirstManifest($jh);
$mh = $codec->verifyExpectedKind($m0, 'm', $now);
$jobId = $codec->storedId($jobTok, 'j');

switch ($action) {
    case 'create':
        $r = $store->createJob(new JobCandidate(
            $codec->journeyId($eh),
            $codec->storedId($entry, 'e'),
            $jobId,
            $codec->storedId($m0, 'm'),
            SqliteAttritionStore::JOB_REVISION,
            $eh->expiresAt,
        ), $now);
        echo json_encode(['job' => $r?->jobId]);
        break;
    case 'poll':
        $r = $store->advancePoll($jobId, $now);
        echo json_encode(['poll' => $r?->poll]);
        break;
    case 'commit0':
        $art0 = $codec->deriveArtifact($mh, 0);
        $m1 = $codec->deriveNextManifest($mh, 1);
        $r = $store->commitManifest(new ManifestCommit(
            $codec->journeyId($mh),
            $jobId,
            $codec->generationId($mh, 0),
            0,
            $codec->storedId($m0, 'm'),
            $codec->storedId($art0, 'a'),
            $codec->storedId($m1, 'm'),
            SqliteAttritionStore::RENDERER_REVISION,
            $mh->expiresAt,
            AttritionStateCost::GENERATION,
        ), $now);
        echo json_encode(['gen' => $r?->generation]);
        break;
    default:
        fwrite(STDERR, "unknown action {$action}\n");
        exit(2);
}
exit(0);
