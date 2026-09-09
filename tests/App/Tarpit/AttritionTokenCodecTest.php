<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tarpit;

use Funnypot\App\Tarpit\Attrition\AttritionHandle;
use Funnypot\App\Tarpit\Attrition\AttritionTokenCodec;
use PHPUnit\Framework\TestCase;

/**
 * FP-0272 §5 — the handle codec. Exact 117-byte canonical grammar, kind separation, full MAC, the bounded
 * time window, opaque peer partitioning, deterministic child derivations, and separated stored-id domains.
 */
final class AttritionTokenCodecTest extends TestCase
{
    private const KEY_A = 'attrition-codec-test-key-A-32byte';   // 33 bytes -> trimmed below
    private const ROUTE = '/admin/audit-archive/page-000002';
    private const NOW = 1757000000;

    private function codec(string $seed = self::KEY_A): AttritionTokenCodec
    {
        return new AttritionTokenCodec(substr(hash('sha256', $seed, true), 0, 32));
    }

    private function entry(?AttritionTokenCodec $codec = null, string $peer = '203.0.113.9', int $now = self::NOW): string
    {
        $codec ??= $this->codec();
        $t = $codec->issueEntry(self::ROUTE, $peer, $now, 21600);
        self::assertNotNull($t);

        return $t;
    }

    public function test_token_is_exactly_117_bytes_and_matches_the_canonical_grammar(): void
    {
        $t = $this->entry();
        self::assertSame(117, strlen($t));
        self::assertMatchesRegularExpression(
            '/\Aat1\.(e|j|m|a)\.([1-9][0-9]{9})\.([1-9][0-9]{9})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})\z/',
            $t
        );
    }

    public function test_pinned_vector_is_stable(): void
    {
        // A change here is a token-domain break: it invalidates every live handle and must be a deliberate v2.
        $t = $this->entry(null, '203.0.113.9', self::NOW);
        self::assertSame('at1.e.1756999800.1757021400.Evyc1sZkxxkuys3iJCsKqg.ivwkhTCTV0DalRgJ4j-66A.I2xjuwvc4ILKerFC-NQFZlRJXWGhKGC5J3U6ADcBUw8', $t);
    }

    public function test_verify_returns_a_typed_handle_with_16_16_32_byte_fields(): void
    {
        $codec = $this->codec();
        $t = $this->entry($codec);
        $h = $codec->verifyExpectedKind($t, AttritionHandle::KIND_ENTRY, self::NOW);
        self::assertInstanceOf(AttritionHandle::class, $h);
        self::assertSame('e', $h->kind);
        self::assertSame(16, strlen($h->subject));
        self::assertSame(16, strlen($h->nonce));
        self::assertSame(1756999800, $h->issuedAt);
        self::assertSame(1756999800 + 21600, $h->expiresAt);
    }

    public function test_debug_dump_hides_the_private_bytes(): void
    {
        $h = $this->codec()->verifyExpectedKind($this->entry(), 'e', self::NOW);
        $dump = print_r($h->__debugInfo(), true);
        self::assertStringNotContainsString($h->subject, $dump);
        self::assertStringNotContainsString($h->nonce, $dump);
    }

    public function test_stable_within_the_issue_bucket_and_shifts_across_buckets(): void
    {
        $codec = $this->codec();
        self::assertSame($codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW, 21600), $codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW + 100, 21600));
        self::assertNotSame($codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW, 21600), $codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW + 900, 21600));
    }

    public function test_ipv4_mapped_ipv6_folds_to_ipv4_but_real_ipv6_and_other_peers_differ(): void
    {
        $codec = $this->codec();
        $v4 = $codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW, 21600);
        $mapped = $codec->issueEntry(self::ROUTE, '::ffff:203.0.113.9', self::NOW, 21600);
        self::assertSame($v4, $mapped, 'IPv4-mapped IPv6 must fold to the equivalent IPv4 subject');

        $v6 = $codec->issueEntry(self::ROUTE, '2001:db8::1', self::NOW, 21600);
        self::assertNotSame($v4, $v6);
        self::assertNotSame($v4, $codec->issueEntry(self::ROUTE, '203.0.113.10', self::NOW, 21600));
    }

    public function test_invalid_peer_or_route_variance_behaves(): void
    {
        $codec = $this->codec();
        self::assertNull($codec->issueEntry(self::ROUTE, 'not-an-ip', self::NOW, 21600));
        self::assertNull($codec->issueEntry(self::ROUTE, '', self::NOW, 21600));
        // Same peer, a different route -> a different token (route partitions the entry nonce).
        self::assertNotSame($codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW, 21600), $codec->issueEntry('/admin/audit-archive/page-000003', '203.0.113.9', self::NOW, 21600));
    }

    public function test_child_handles_inherit_subject_and_expiry_and_verify(): void
    {
        $codec = $this->codec();
        $e = $codec->verifyExpectedKind($this->entry($codec), 'e', self::NOW);
        $jobTok = $codec->deriveJob($e);
        $job = $codec->verifyExpectedKind($jobTok, 'j', self::NOW);
        self::assertNotNull($job);
        self::assertSame($e->subject, $job->subject, 'a child inherits the entry subject');
        self::assertSame($e->issuedAt, $job->issuedAt);
        self::assertSame($e->expiresAt, $job->expiresAt, 'following the journey never extends the lifetime');
        self::assertNotSame($e->nonce, $job->nonce);

        $m0 = $codec->verifyExpectedKind($codec->deriveFirstManifest($job), 'm', self::NOW);
        self::assertNotNull($m0);
        $a0 = $codec->verifyExpectedKind($codec->deriveArtifact($m0, 0), 'a', self::NOW);
        self::assertNotNull($a0);
        $m1 = $codec->verifyExpectedKind($codec->deriveNextManifest($m0, 1), 'm', self::NOW);
        self::assertNotNull($m1);
        self::assertNotSame($m0->nonce, $m1->nonce);
        self::assertNotSame($codec->deriveArtifact($m0, 0), $codec->deriveArtifact($m1, 1));
    }

    public function test_child_derivation_is_deterministic_and_bearer_continues_after_ip_change(): void
    {
        $codec = $this->codec();
        $e = $codec->verifyExpectedKind($this->entry($codec), 'e', self::NOW);
        self::assertSame($codec->deriveJob($e), $codec->deriveJob($e), 'deterministic');
        // A bearer's child token verifies regardless of the caller's current IP — verification never
        // compares the peer; the token carries only the opaque subject.
        $jobTok = $codec->deriveJob($e);
        self::assertNotNull($codec->verifyExpectedKind($jobTok, 'j', self::NOW + 5000));
    }

    public function test_wrong_kind_is_rejected(): void
    {
        $codec = $this->codec();
        $t = $this->entry($codec);
        foreach (['j', 'm', 'a'] as $k) {
            self::assertNull($codec->verifyExpectedKind($t, $k, self::NOW), "kind {$k} must not verify an entry token");
        }
    }

    public function test_every_byte_matters(): void
    {
        $codec = $this->codec();
        $t = $this->entry($codec);
        for ($i = 0; $i < strlen($t); $i++) {
            $c = $t[$i];
            $repl = $c === 'A' ? 'B' : 'A';
            if ($c === '.') {
                continue; // a separator flip is caught by the grammar; tested via length/grammar elsewhere
            }
            $mutated = substr($t, 0, $i) . $repl . substr($t, $i + 1);
            if ($mutated === $t) {
                continue;
            }
            self::assertNull($codec->verifyExpectedKind($mutated, 'e', self::NOW), "mutation at {$i} must be rejected");
        }
    }

    public function test_time_window_and_lifetime_bounds(): void
    {
        $codec = $this->codec();
        $t = $codec->issueEntry(self::ROUTE, '203.0.113.9', self::NOW, 21600);
        $issued = self::NOW - (self::NOW % 900);
        $expires = $issued + 21600;
        // expired
        self::assertNull($codec->verifyExpectedKind($t, 'e', $expires));
        self::assertNull($codec->verifyExpectedKind($t, 'e', $expires + 1));
        // valid up to the last second
        self::assertNotNull($codec->verifyExpectedKind($t, 'e', $expires - 1));
        // issued-in-the-future beyond skew (issued is bucket start, so only a now far in the past trips it)
        self::assertNull($codec->verifyExpectedKind($t, 'e', $issued - AttritionTokenCodec::CLOCK_SKEW_S - 1));
    }

    public function test_alternate_encoding_and_padding_are_rejected(): void
    {
        $codec = $this->codec();
        $t = $this->entry($codec);
        // A trailing '=' breaks both the length and the grammar.
        self::assertNull($codec->verifyExpectedKind($t . '=', 'e', self::NOW));
        // Non-url base64 alphabet is not in [A-Za-z0-9_-] — inject into a mac position (the last char).
        self::assertNull($codec->verifyExpectedKind(substr($t, 0, -1) . '/', 'e', self::NOW));
        self::assertNull($codec->verifyExpectedKind(substr($t, 0, -1) . '+', 'e', self::NOW));
        // Wrong length.
        self::assertNull($codec->verifyExpectedKind(substr($t, 0, 116), 'e', self::NOW));
    }

    public function test_cross_install_key_does_not_verify(): void
    {
        $a = $this->codec('key-a');
        $b = $this->codec('key-b');
        $t = $a->issueEntry(self::ROUTE, '203.0.113.9', self::NOW, 21600);
        self::assertNotNull($a->verifyExpectedKind($t, 'e', self::NOW));
        self::assertNull($b->verifyExpectedKind($t, 'e', self::NOW), 'a different install key must reject the token');
    }

    public function test_stored_ids_are_32_hex_and_domain_separated(): void
    {
        $codec = $this->codec();
        $e = $codec->verifyExpectedKind($this->entry($codec), 'e', self::NOW);
        $entryTok = $this->entry($codec);
        $jobTok = $codec->deriveJob($e);

        $journeyId = $codec->journeyId($e);
        $entryId = $codec->storedId($entryTok, 'e');
        $jobId = $codec->storedId($jobTok, 'j');
        $genId = $codec->generationId($e, 0);
        foreach ([$journeyId, $entryId, $jobId, $genId] as $id) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $id);
        }
        // The same token under different kind domains yields different stored ids.
        self::assertNotSame($codec->storedId($entryTok, 'e'), $codec->storedId($entryTok, 'j'));
        self::assertCount(4, array_unique([$journeyId, $entryId, $jobId, $genId]));
        // Deterministic.
        self::assertSame($journeyId, $codec->journeyId($e));
        self::assertSame($genId, $codec->generationId($e, 0));
        self::assertNotSame($genId, $codec->generationId($e, 1));
    }

    public function test_generation_id_is_job_unique_within_one_journey(): void
    {
        // Two canonical pages from the SAME peer within one 15-minute bucket share subject + issued_at
        // (one journey) but are two distinct jobs. Their generation-0 manifest handles must yield
        // DIFFERENT generation ids, or the second job's generation commit collides on the PRIMARY KEY.
        $codec = $this->codec();
        $a = $codec->verifyExpectedKind($codec->issueEntry('/admin/audit-archive/page-000002', '203.0.113.9', self::NOW, 21600), 'e', self::NOW);
        $b = $codec->verifyExpectedKind($codec->issueEntry('/admin/audit-archive/page-000003', '203.0.113.9', self::NOW, 21600), 'e', self::NOW);
        self::assertSame($a->subject, $b->subject, 'same peer + bucket => same subject (one journey)');
        self::assertSame($codec->journeyId($a), $codec->journeyId($b), 'both jobs live in one journey');

        $mA = $codec->verifyExpectedKind($codec->deriveFirstManifest($codec->verifyExpectedKind($codec->deriveJob($a), 'j', self::NOW)), 'm', self::NOW);
        $mB = $codec->verifyExpectedKind($codec->deriveFirstManifest($codec->verifyExpectedKind($codec->deriveJob($b), 'j', self::NOW)), 'm', self::NOW);
        self::assertNotSame($codec->generationId($mA, 0), $codec->generationId($mB, 0), 'generation-0 id must differ per job');
    }
}
