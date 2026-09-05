<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityKeyDeriver;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

/**
 * The closed KDF surface: pinned vectors per named domain, pairwise inequality, exact 32-byte
 * outputs, no derive-by-label method, and a commitment that is never the private proof output.
 */
final class IdentityKeyDeriverTest extends TestCase
{
    /** A fixed master (bytes 0x00..0x1f) and the base64url of every named output for it. */
    private const VECTOR_MASTER_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

    private const NAMED = [
        'coreRenderSalt', 'shellFilesystemKey', 'consoleSessionMacKey', 'dockerRegistryTokenKey',
        'engagementAnalyticsKey', 'engagementExperimentKey', 'serviceProfileKey',
        'redisTelemetryFingerprintKey', 'postExploitStateKey',
    ];

    private function vectorDeriver(): IdentityKeyDeriver
    {
        return IdentityKeyDeriver::fromMaster((string) hex2bin(self::VECTOR_MASTER_HEX));
    }

    public function test_every_named_output_is_exactly_32_bytes_and_pairwise_distinct(): void
    {
        $d = $this->vectorDeriver();
        $outputs = [];
        foreach (self::NAMED as $m) {
            $v = $d->{$m}();
            self::assertSame(IdentityKeyDeriver::KEY_BYTES, strlen($v), "{$m} must be 32 bytes");
            $outputs[$m] = $v;
        }
        // persona material is public/printable but its underlying bytes must also be distinct
        $outputs['personaMaterial'] = IdentityKeyDeriver::decodeKey(substr($d->personaMaterial(), strlen(IdentityKeyDeriver::PERSONA_PREFIX)));
        self::assertCount(count($outputs), array_unique(array_values($outputs)), 'no two domains may share an output');
        self::assertCount(count(IdentityKeyDeriver::DOMAINS), array_unique(IdentityKeyDeriver::DOMAINS), 'info strings are unique');
        self::assertSame(count(self::NAMED) + 2, count(IdentityKeyDeriver::DOMAINS), 'named methods + persona + proof cover every info string');
    }

    public function test_outputs_are_hkdf_sha256_of_the_named_info_under_the_fixed_salt(): void
    {
        // Independently recomputed: HKDF-SHA256(master, salt, info) — so the deriver cannot silently
        // drift to a different construction or salt.
        $d = $this->vectorDeriver();
        $master = (string) hex2bin(self::VECTOR_MASTER_HEX);
        $expect = static fn (string $info): string => hash_hkdf('sha256', $master, 32, $info, IdentityKeyDeriver::SALT);
        self::assertSame($expect('core-render-salt/v1'), $d->coreRenderSalt());
        self::assertSame($expect('shell-filesystem/v1'), $d->shellFilesystemKey());
        self::assertSame($expect('console-session-mac/v1'), $d->consoleSessionMacKey());
        self::assertSame($expect('docker-registry-token/v1'), $d->dockerRegistryTokenKey());
        self::assertSame($expect('engagement-analytics/v1'), $d->engagementAnalyticsKey());
        self::assertSame($expect('engagement-experiment/v1'), $d->engagementExperimentKey());
        self::assertSame($expect('service-profile/v1'), $d->serviceProfileKey());
        self::assertSame($expect('redis-telemetry/v1'), $d->redisTelemetryFingerprintKey());
        self::assertSame($expect('post-exploit-state/v1'), $d->postExploitStateKey());
        self::assertSame(IdentityKeyDeriver::PERSONA_PREFIX . IdentityKeyDeriver::encodeKey($expect('persona-material/v1')), $d->personaMaterial());
        // The commitment is a one-way SHA-256 over the private proof output, never the output itself.
        $proof = $expect('runtime-keyset-proof/v1');
        self::assertSame(IdentityKeyDeriver::COMMITMENT_PREFIX . hash('sha256', "funnypot/keyset-commitment/v1\0" . $proof), $d->keysetCommitment());
        self::assertNotSame($proof, $d->keysetCommitment());
        self::assertNotSame(bin2hex($proof), substr($d->keysetCommitment(), strlen(IdentityKeyDeriver::COMMITMENT_PREFIX)));
    }

    public function test_pinned_vectors(): void
    {
        $d = $this->vectorDeriver();
        // Pinned once for master 0x00..0x1f; a change here is a KDF-domain break that re-identifies
        // every install (persona, filesystem, sessions, tokens) and must be a deliberate v2.
        self::assertSame('fpi1_' . 'uE8ZMzlqROWV3AQgORHiSRKqYqldELNC7zllUQVeBJA', $d->personaMaterial());
        self::assertSame('fpkc1_' . '91fb722063b420cda9acf2f11f45e2b0653bff62c905a0b1a6625917744c0407', $d->keysetCommitment());
        self::assertSame('3c12bcd23664eb3298d2bb84d592bfa7b8ebbfbe88de0f6904ca3e55a0835ef9', bin2hex($d->coreRenderSalt()));
        self::assertSame('b319fa5d095225ed156e73f90da01eec2b6d5d91e918ff3af95a9cb052a5be64', bin2hex($d->shellFilesystemKey()));
        self::assertSame('52cd0dd4195f9ac7cdac4557c5d39abb2aed6cb0f576427cf5b94b9c47ec1230', bin2hex($d->consoleSessionMacKey()));
        self::assertSame('405a1d89a7b703efdffc1891355c65d635efa79a46d93072b2c11584b3333793', bin2hex($d->dockerRegistryTokenKey()));
        self::assertSame('b413b226dc0b73647d1b99e085da1fa844b2b26f02f8d6e39652452646c60b8f', bin2hex($d->engagementAnalyticsKey()));
        self::assertSame('6def1fae9bbb56bc01ab80fa88b55144698decbcee7b5c9a874f4e14c419670c', bin2hex($d->engagementExperimentKey()));
        self::assertSame('c1383cb1966d127965a7a1fa2b8dc3f5bead832773fcb64a4cc609eb830346bb', bin2hex($d->serviceProfileKey()));
        self::assertSame('4dba5d60996195ceb3bd78b04366bcf8c42ec3c365080e15b36d8eab1ad48878', bin2hex($d->redisTelemetryFingerprintKey()));
        self::assertSame('304d022333b863b8d63cfb6b043b4dbc21c323f0f4f7928f857eb9621e95ee95', bin2hex($d->postExploitStateKey()));
        self::assertSame('fpph1_' . 'c5b906a8c87e9125c06409a9c69784b14ee0e62578ea0759f9b59b7c4a989fe6', IdentityKeyDeriver::publicPersonaHash('httptest'));
        self::assertMatchesRegularExpression('/^fpkc1_[0-9a-f]{64}$/', $d->keysetCommitment());
        self::assertMatchesRegularExpression('/^fpi1_[A-Za-z0-9_-]{43}$/', $d->personaMaterial());
    }

    public function test_persona_material_and_public_hash_are_stable_and_prefixed(): void
    {
        $a = IdentityTestSupport::deriver('a');
        self::assertSame($a->personaMaterial(), IdentityTestSupport::deriver('a')->personaMaterial());
        self::assertNotSame($a->personaMaterial(), IdentityTestSupport::deriver('b')->personaMaterial());
        self::assertStringStartsWith('fpph1_', IdentityKeyDeriver::publicPersonaHash($a->personaMaterial()));
        self::assertSame(IdentityKeyDeriver::publicPersonaHash('x'), IdentityKeyDeriver::publicPersonaHash('x'));
        self::assertNotSame(IdentityKeyDeriver::publicPersonaHash('x'), IdentityKeyDeriver::publicPersonaHash('y'));
    }

    public function test_same_persona_override_with_two_masters_keeps_visible_identity_but_changes_every_key(): void
    {
        $a = IdentityTestSupport::deriver('a');
        $b = IdentityTestSupport::deriver('b');
        self::assertSame(IdentityKeyDeriver::publicPersonaHash('httptest'), IdentityKeyDeriver::publicPersonaHash('httptest'));
        self::assertNotSame($a->keysetCommitment(), $b->keysetCommitment());
        foreach (self::NAMED as $m) {
            self::assertNotSame($a->{$m}(), $b->{$m}(), "{$m} must differ across masters");
        }
    }

    public function test_surface_is_closed_no_public_method_takes_a_label(): void
    {
        $rc = new ReflectionClass(IdentityKeyDeriver::class);
        foreach ($rc->getMethods(ReflectionMethod::IS_PUBLIC) as $m) {
            if ($m->isStatic()) {
                continue; // fromMaster / encode / decode / publicPersonaHash take data, not a derivation label
            }
            self::assertSame(0, $m->getNumberOfParameters(), "{$m->getName()} must not accept a caller-chosen derivation label");
        }
        self::assertFalse($rc->hasMethod('derive') && $rc->getMethod('derive')->isPublic(), 'no public derive()');
        self::assertFalse($rc->isInstantiable(), 'construction only via fromMaster()');
    }

    public function test_master_validation(): void
    {
        try {
            IdentityKeyDeriver::fromMaster(str_repeat("\0", 32));
            self::fail('all-zero accepted');
        } catch (IdentityBootstrapException $e) {
            self::assertSame('master-all-zero', $e->errorCode());
        }
        try {
            IdentityKeyDeriver::fromMaster(random_bytes(31));
            self::fail('short accepted');
        } catch (IdentityBootstrapException $e) {
            self::assertSame('master-length', $e->errorCode());
        }
        self::assertInstanceOf(IdentityKeyDeriver::class, IdentityKeyDeriver::fromMaster(str_repeat("\0", 31) . "\x01"));
    }

    public function test_key_encoding_is_strict_base64url(): void
    {
        $k = random_bytes(32);
        self::assertSame($k, IdentityKeyDeriver::decodeKey(IdentityKeyDeriver::encodeKey($k)));
        foreach (['', 'short', IdentityKeyDeriver::encodeKey($k) . '=', str_replace('-', '+', IdentityKeyDeriver::encodeKey(str_repeat("\xfb", 32)))] as $bad) {
            try {
                IdentityKeyDeriver::decodeKey($bad);
                self::fail('malformed key accepted');
            } catch (IdentityBootstrapException $e) {
                self::assertSame('bundle-key-malformed', $e->errorCode());
            }
        }
    }
}
