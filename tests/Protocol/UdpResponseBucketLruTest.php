<?php

declare(strict_types=1);

namespace Funnypot\Protocol {
    /**
     * Controlled clock for the LRU tests below. The trait's unqualified `microtime(true)` resolves to
     * this namespace, so defining it here lets a test pin exact call times. It falls through to the real
     * clock whenever no test has engaged fake time, so the shim is inert for every other suite that
     * composes the bucket trait in the same worker process.
     */
    function microtime($asFloat = true)
    {
        $fake = \Funnypot\Tests\Protocol\UdpBucketClock::$now;

        return $fake ?? \microtime($asFloat);
    }
}

namespace Funnypot\Tests\Protocol {
    use Funnypot\Protocol\Sip\SipConfig;
    use Funnypot\Protocol\Sip\SipServer;
    use Funnypot\Protocol\UdpResponseBucket;
    use PHPUnit\Framework\TestCase;

    /** Fake-time holder for the trait clock shim above; null = use the real clock. */
    final class UdpBucketClock
    {
        public static ?float $now = null;
    }

    /**
     * Small-capacity composing fixture over the real trait, so eviction can be forced with a handful of
     * sources instead of the production 4096. Constants mirror production except for the tiny IP cap.
     */
    final class SmallUdpBucketFixture
    {
        use UdpResponseBucket;

        private const UDP_RESP_BURST = 20.0;
        private const UDP_RESP_RATE = 10.0;
        private const UDP_BUCKET_MAX_IPS = 3;
        private const UDP_RESP_SEED = 2.0;

        public function allow(string $ip): bool
        {
            return $this->udpResponseAllowed($ip);
        }

        public function ensure(string $ip, float $now): void
        {
            $this->udpResponseBucketEnsure($ip, $now);
        }

        public function has(string $ip): bool
        {
            return isset($this->udpResponseBuckets[$ip]);
        }

        public function lastAt(string $ip): ?float
        {
            return $this->udpResponseBuckets[$ip]['last'] ?? null;
        }

        public function lastGrantedAt(string $ip): ?float
        {
            return $this->udpResponseBuckets[$ip]['last_granted_at'] ?? null;
        }

        public function setCredit(string $ip, float $credit): void
        {
            $this->udpResponseBuckets[$ip]['credit'] = $credit;
        }

        public function creditOf(string $ip): ?float
        {
            return $this->udpResponseBuckets[$ip]['credit'] ?? null;
        }
    }

    /**
     * FP-0306 — the UDP response bucket splits its single timestamp into an accrual anchor (`last`,
     * advances every call) and an LRU eviction key (`last_granted_at`, advances only after a granted
     * reply). This proves a source that is only ever refused cannot pin its map slot ahead of a source
     * that is genuinely being served, without changing the reflection-safety bound (seed/refill/debit
     * are untouched — covered by UdpReflectionInvariantTest / SipEgressBudgetTest / SipTelemetryTest).
     */
    final class UdpResponseBucketLruTest extends TestCase
    {
        protected function tearDown(): void
        {
            UdpBucketClock::$now = null;
        }

        /** Seed 2.0 still grants exactly the first two immediate calls and refuses the third. */
        public function test_seed_grants_two_then_refuses_third(): void
        {
            $bucket = new SmallUdpBucketFixture();

            self::assertTrue($bucket->allow('203.0.113.1'), 'first immediate call granted');
            self::assertTrue($bucket->allow('203.0.113.1'), 'second immediate call granted (seed=2.0)');
            self::assertFalse($bucket->allow('203.0.113.1'), 'third immediate call refused');
        }

        /** A refused call advances the accrual anchor but never the LRU key. */
        public function test_refusal_advances_last_but_not_last_granted_at(): void
        {
            $bucket = new SmallUdpBucketFixture();
            $ip = '203.0.113.2';

            $bucket->allow($ip);
            $bucket->allow($ip);
            $grantTime = $bucket->lastGrantedAt($ip);
            self::assertNotNull($grantTime);
            self::assertGreaterThan(0.0, $grantTime, 'a granted call sets the LRU key');

            self::assertFalse($bucket->allow($ip), 'bucket drained -> refused');
            self::assertGreaterThanOrEqual($grantTime, $bucket->lastAt($ip), 'refusal advances the accrual anchor');
            self::assertSame($grantTime, $bucket->lastGrantedAt($ip), 'refusal leaves the LRU key at the last grant');
        }

        /**
         * Repeated refusals must not re-count the same elapsed interval and grant early. Ten refused
         * calls at one fixed instant accrue nothing beyond the first; the naive "skip the `last` write on
         * refusal" fix would keep re-adding the interval and grant mid-burst.
         *
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_refused_calls_do_not_double_count_elapsed(): void
        {
            $bucket = new SmallUdpBucketFixture();
            $ip = '203.0.113.3';

            UdpBucketClock::$now = 1000.0;
            $bucket->allow($ip);
            $bucket->allow($ip); // seed drained at t=1000.0

            // 0.05s of real elapsed time buys 0.5 tokens (<1); ten calls at the SAME instant add nothing more.
            UdpBucketClock::$now = 1000.05;
            for ($i = 0; $i < 10; $i++) {
                self::assertFalse($bucket->allow($ip), "rapid refusal #{$i} must not grant early");
            }
            self::assertSame(1000.05, $bucket->lastAt($ip), 'accrual anchor tracks the fixed instant');
            self::assertSame(1000.0, $bucket->lastGrantedAt($ip), 'LRU key still the last grant');

            // Only genuine elapsed time refills: 0.15s past the anchor buys >=1 token.
            UdpBucketClock::$now = 1000.2;
            self::assertTrue($bucket->allow($ip), 'grants only after real elapsed time');
        }

        /**
         * A drained source last granted BEFORE an active source, then kept warm with refused touches, is
         * still evicted first; the active source survives, and the drained source returns only at the
         * depleted seed. Under the old single-`last` key the refused touches would evict the active
         * source instead.
         *
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_refused_touches_do_not_protect_drained_source_from_eviction(): void
        {
            $bucket = new SmallUdpBucketFixture();
            $attacker = '198.51.100.10';
            $legit = '198.51.100.20';

            // Sub-token time deltas (<0.1s total at rate 10/s) keep the attacker genuinely drained across
            // every touch: only refill would grant, and no window here accrues a whole token.
            UdpBucketClock::$now = 1.000;
            $bucket->allow($attacker); // grant, last_granted_at=1.000
            $bucket->allow($attacker); // grant, last_granted_at=1.000
            self::assertFalse($bucket->allow($attacker), 'attacker drained');

            UdpBucketClock::$now = 1.001;
            self::assertTrue($bucket->allow($legit), 'legit source granted just after the attacker');

            // Attacker keeps its entry warm with refused calls; the LRU key must stay at 1.000.
            UdpBucketClock::$now = 1.002;
            self::assertFalse($bucket->allow($attacker));
            UdpBucketClock::$now = 1.003;
            self::assertFalse($bucket->allow($attacker));
            self::assertSame(1.000, $bucket->lastGrantedAt($attacker), 'refused touches never refresh the LRU key');
            self::assertSame(1.003, $bucket->lastAt($attacker), 'refused touches do advance the accrual anchor');

            // Two fresh sources fill the cap (=3) and force one eviction: the attacker (oldest grant) goes.
            UdpBucketClock::$now = 1.004;
            $bucket->allow('203.0.113.41');
            UdpBucketClock::$now = 1.005;
            $bucket->allow('203.0.113.42');

            self::assertFalse($bucket->has($attacker), 'drained attacker evicted despite the warm-up touches');
            self::assertTrue($bucket->has($legit), 'active legitimate source survives');

            // Re-admission hands back only the depleted seed, never a fresh full burst.
            UdpBucketClock::$now = 1.006;
            self::assertTrue($bucket->allow($attacker), 're-admitted attacker gets its first seed packet');
            self::assertTrue($bucket->allow($attacker), 're-admitted attacker gets its second seed packet (seed=2.0)');
            self::assertFalse($bucket->allow($attacker), 're-admission is only the depleted seed, not a burst');
        }

        /**
         * A never-granted entry (e.g. SIP's credit-only source) sits at last_granted_at=0.0 and is the
         * first eviction candidate, ahead of any source that has been served — and the trait never
         * disturbs SIP's extra `credit` field while doing so.
         */
        public function test_never_granted_entry_is_first_eviction_candidate(): void
        {
            $bucket = new SmallUdpBucketFixture();
            $creditOnly = '198.51.100.30';
            $served = '198.51.100.31';

            // Ensure-only, then attach a credit field: this is the shape SIP's creditUdpIngress() leaves.
            $bucket->ensure($creditOnly, \microtime(true));
            $bucket->setCredit($creditOnly, 4096.0);
            self::assertSame(0.0, $bucket->lastGrantedAt($creditOnly), 'never-granted entry keeps LRU key 0.0');

            self::assertTrue($bucket->allow($served), 'other source is served');
            self::assertGreaterThan(0.0, $bucket->lastGrantedAt($served));

            // Fill the cap and force an eviction; the credit-only source is the one that goes.
            $bucket->allow('203.0.113.51');
            $bucket->allow('203.0.113.52');

            self::assertFalse($bucket->has($creditOnly), 'never-granted credit-only source evicted first');
            self::assertTrue($bucket->has($served), 'served source retained');
        }

        /**
         * On the real SIP server the trait must never touch the `credit` byte-budget field across a
         * granted or refused reply, and a creditUdpIngress()-only source (never granted) must sit at LRU
         * key 0.0 — the first eviction candidate — while a granted source does not.
         */
        public function test_sip_credit_field_survives_and_credit_only_source_ranks_first_for_eviction(): void
        {
            $server = new SipServer(new SipConfig(bind: '127.0.0.1:0', rtpPort: 0), null);
            $server->bind();

            $credit = new \ReflectionMethod($server, 'creditUdpIngress');
            $credit->setAccessible(true);
            $allow = new \ReflectionMethod($server, 'udpResponseAllowed');
            $allow->setAccessible(true);
            $map = new \ReflectionProperty($server, 'udpResponseBuckets');
            $map->setAccessible(true);

            $entry = static fn (string $ip): array => $map->getValue($server)[$ip] ?? [];

            // Credit-only source: earns byte credit but is never granted a reply.
            $creditOnly = '198.51.100.60';
            $credit->invoke($server, $creditOnly, 1000);
            self::assertGreaterThan(0.0, $entry($creditOnly)['credit'], 'ingress earns byte credit');
            self::assertSame(0.0, $entry($creditOnly)['last_granted_at'], 'credit-only source never advances the LRU key');

            // A granted+credited source keeps its credit untouched by the trait across grant and refusal.
            $served = '198.51.100.61';
            $credit->invoke($server, $served, 1000);
            $before = $entry($served)['credit'];
            self::assertTrue($allow->invoke($server, $served), 'first reply granted');
            self::assertTrue($allow->invoke($server, $served), 'second reply granted (seed=2.0)');
            self::assertFalse($allow->invoke($server, $served), 'third reply refused (bucket drained)');
            self::assertSame($before, $entry($served)['credit'], 'trait never debits or clears SIP credit');
            self::assertGreaterThan(0.0, $entry($served)['last_granted_at'], 'served source advanced the LRU key');

            // The credit-only source is the first eviction candidate relative to the served one.
            self::assertLessThan(
                $entry($served)['last_granted_at'],
                $entry($creditOnly)['last_granted_at'],
                'never-granted credit-only source ranks ahead of a served source for eviction'
            );
        }

        /** The trait stays composed by exactly the seven current UDP listeners — no silent new user. */
        public function test_trait_is_composed_by_exactly_the_seven_udp_servers(): void
        {
            $expected = ['BacnetServer', 'CoapServer', 'IpmiServer', 'NtpServer', 'SipServer', 'SnmpServer', 'StunServer'];

            $found = [];
            $dir = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(__DIR__ . '/../../src/Protocol', \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($dir as $file) {
                if ($file->getExtension() !== 'php') {
                    continue;
                }
                if (str_contains((string) file_get_contents($file->getPathname()), 'use UdpResponseBucket;')) {
                    $found[] = $file->getBasename('.php');
                }
            }
            sort($found);

            self::assertSame($expected, $found, 'the UDP response bucket trait must stay used by exactly these seven servers');
        }
    }
}
