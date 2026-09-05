<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Tls;

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityInputs;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\InstallSecretStore;
use Funnypot\App\Identity\SourceOpenAttestation;
use Funnypot\App\Tls\DecoyCertificateManager;
use Funnypot\App\Tls\DnsName;
use Funnypot\App\Tls\TlsSelection;
use PHPUnit\Framework\TestCase;

/**
 * TLS selection: explicit > legacy > generated, operator pairs served byte-identical and never
 * regenerated, the generated pair persisted with provenance and regenerated (same subject, new key)
 * only when provably ours, the Let's Encrypt chain accepted in exactly one shape, and every
 * hostname validated before it can reach OpenSSL, a path or nginx.
 */
final class DecoyCertificateManagerTest extends TestCase
{
    private string $base = '';
    private string $storage = '';
    private string $legacy = '';
    private string $le = '';

    protected function setUp(): void
    {
        $this->base = (string) realpath(sys_get_temp_dir()) . '/fp_tls_' . bin2hex(random_bytes(5));
        $this->storage = $this->base . '/storage';
        $this->legacy = $this->base . '/legacy';
        $this->le = $this->base . '/le';
        mkdir($this->base, 0755);
        mkdir($this->storage, 0777);
        mkdir($this->legacy, 0755);
        mkdir($this->le, 0755);
        (new InstallSecretStore($this->paths(), new IdentityFileOps()))->ensurePrivateDirectories();
    }

    protected function tearDown(): void
    {
        if ($this->base !== '' && is_dir($this->base)) {
            exec('chmod -R u+rwX ' . escapeshellarg($this->base) . ' && rm -rf ' . escapeshellarg($this->base));
        }
    }

    private function paths(): IdentityPaths
    {
        return IdentityPaths::forStorage($this->storage, $this->base . '/runtime');
    }

    private function manager(IdentityInputs $inputs): DecoyCertificateManager
    {
        return new DecoyCertificateManager($this->paths(), new IdentityFileOps(), $inputs, $this->legacy, $this->le);
    }

    private function expectCode(string $code, callable $fn): void
    {
        try {
            $fn();
        } catch (IdentityBootstrapException $e) {
            self::assertSame($code, $e->errorCode());
            self::assertStringNotContainsString($this->base, $e->getMessage());

            return;
        }
        self::fail("expected {$code}");
    }

    /** @return array{0:string,1:string} [certPem, keyPem] */
    private static function makePair(string $cn): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => $cn], $key, ['digest_alg' => 'sha256']);
        $x = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256'], random_int(1, PHP_INT_MAX >> 2));
        openssl_x509_export($x, $cert);
        openssl_pkey_export($key, $pem);

        return [$cert, $pem];
    }

    private function closeSel(TlsSelection $s): void
    {
        foreach ([$s->cert, $s->key, $s->adminCert, $s->adminKey] as $o) {
            if ($o !== null && is_resource($o->handle)) {
                fclose($o->handle);
            }
        }
    }

    // --- generated -----------------------------------------------------------------------------------

    public function test_generates_persists_and_reuses_a_marked_pair_with_persona_subject(): void
    {
        $sel = $this->manager(new IdentityInputs())->select('persona-host.example', null);
        self::assertSame(TlsSelection::GENERATED, $sel->selection);
        self::assertSame('persona-host.example', $sel->hostname);
        $parsed = openssl_x509_parse($sel->cert->bytes);
        self::assertSame('persona-host.example', $parsed['subject']['CN']);
        self::assertStringContainsString('DNS:persona-host.example', $parsed['extensions']['subjectAltName']);
        self::assertTrue(openssl_x509_check_private_key($sel->cert->bytes, $sel->key->bytes));
        self::assertSame(SourceOpenAttestation::DIRECT_NOFOLLOW, $sel->cert->attestation->id);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $sel->fingerprintSha256);

        clearstatcache();
        self::assertSame(0700, (int) lstat($this->paths()->tlsDir())['mode'] & 0777);
        self::assertSame(0600, (int) lstat($this->paths()->tlsKeyPath())['mode'] & 0777);
        $prov = json_decode((string) file_get_contents($this->paths()->tlsProvenancePath()), true);
        self::assertSame(DecoyCertificateManager::PROVENANCE_SCHEMA, $prov['schema']);
        self::assertSame($sel->fingerprintSha256, $prov['fingerprint_sha256']);
        self::assertStringNotContainsString('PRIVATE KEY', (string) file_get_contents($this->paths()->tlsProvenancePath()));
        $this->closeSel($sel);

        // Restart: the same pair, same fingerprint.
        $again = $this->manager(new IdentityInputs())->select('persona-host.example', $sel->manifestRecord());
        self::assertSame($sel->fingerprintSha256, $again->fingerprintSha256);
        self::assertSame($sel->cert->bytes, $again->cert->bytes);
        $this->closeSel($again);
    }

    public function test_deleting_a_marked_pair_regenerates_same_subject_with_a_new_random_key(): void
    {
        $first = $this->manager(new IdentityInputs())->select('persona-host.example', null);
        $this->closeSel($first);
        unlink($this->paths()->tlsCertPath());
        unlink($this->paths()->tlsKeyPath());
        unlink($this->paths()->tlsProvenancePath());

        $second = $this->manager(new IdentityInputs())->select('persona-host.example', $first->manifestRecord());
        self::assertSame('persona-host.example', openssl_x509_parse($second->cert->bytes)['subject']['CN']);
        self::assertSame(openssl_x509_parse($first->cert->bytes)['extensions']['subjectAltName'], openssl_x509_parse($second->cert->bytes)['extensions']['subjectAltName']);
        self::assertNotSame($first->fingerprintSha256, $second->fingerprintSha256, 'a fresh random key ⇒ a new fingerprint');
        self::assertNotSame($first->key->bytes, $second->key->bytes);
        $this->closeSel($second);
    }

    public function test_unmarked_file_in_the_generated_slot_is_refused_and_untouched(): void
    {
        [$cert, $key] = self::makePair('foreign.example');
        mkdir($this->paths()->tlsDir(), 0700);
        file_put_contents($this->paths()->tlsCertPath(), $cert);
        file_put_contents($this->paths()->tlsKeyPath(), $key);
        chmod($this->paths()->tlsCertPath(), 0600);
        chmod($this->paths()->tlsKeyPath(), 0600);
        $this->expectCode('tls-generated-unmarked', fn () => $this->manager(new IdentityInputs())->select('persona-host.example', null));
        self::assertSame($cert, file_get_contents($this->paths()->tlsCertPath()), 'never overwritten');
        self::assertFileDoesNotExist($this->paths()->tlsProvenancePath(), 'never marked as ours');
    }

    public function test_cn_and_public_dns_overrides_shape_subject_and_san(): void
    {
        $sel = $this->manager(new IdentityInputs(cn: 'ops.example.com', publicDns: 'pub.example.net'))->select('persona-host.example', null);
        $p = openssl_x509_parse($sel->cert->bytes);
        self::assertSame('ops.example.com', $p['subject']['CN']);
        self::assertStringContainsString('DNS:ops.example.com', $p['extensions']['subjectAltName']);
        self::assertStringContainsString('DNS:pub.example.net', $p['extensions']['subjectAltName']);
        $this->closeSel($sel);
    }

    /** @dataProvider badNames */
    public function test_injection_shaped_hostnames_fail_before_openssl_or_paths(string $bad): void
    {
        $this->expectCode('tls-hostname-invalid', fn () => $this->manager(new IdentityInputs(cn: $bad))->select('persona-host.example', null));
        self::assertFileDoesNotExist($this->paths()->tlsCertPath(), 'nothing generated');
        $this->expectCode('tls-public-dns-invalid', fn () => $this->manager(new IdentityInputs(publicDns: $bad))->select('persona-host.example', null));
        $this->expectCode('tls-letsencrypt-domain-invalid', fn () => $this->manager(new IdentityInputs(leDomain: $bad))->select('persona-host.example', null));
        self::assertFalse(DnsName::isValid($bad));
    }

    /** @return array<string,array{0:string}> */
    public static function badNames(): array
    {
        return [
            'newline' => ["a.example\nlisten 80;"],
            'slash' => ['../../etc/passwd'],
            'comma' => ['a.example,DNS:evil'],
            'wildcard' => ['*.example.com'],
            'space' => ['a.example b'],
            'uppercase' => ['Admin.Example.com'],
            'equals' => ['a=b.example'],
            'quote' => ["a'.example"],
            'leading hyphen' => ['-a.example'],
            'too long label' => [str_repeat('a', 64) . '.example'],
            'too long' => [implode('.', array_fill(0, 30, 'abcdefghij')) . '.example'],
            'empty label' => ['a..example'],
        ];
    }

    // --- explicit ------------------------------------------------------------------------------------

    public function test_explicit_pair_is_selected_byte_identical_and_never_regenerated(): void
    {
        [$cert, $key] = self::makePair('operator.example');
        $c = $this->base . '/op.crt';
        $k = $this->base . '/op.key';
        file_put_contents($c, $cert);
        file_put_contents($k, $key);
        chmod($k, 0600);
        $sel = $this->manager(new IdentityInputs(tlsCertFile: $c, tlsKeyFile: $k))->select('persona-host.example', null);
        self::assertSame(TlsSelection::EXPLICIT, $sel->selection);
        self::assertSame($cert, $sel->cert->bytes);
        self::assertSame($key, $sel->key->bytes);
        self::assertSame($c, $sel->certPath);
        self::assertFileDoesNotExist($this->paths()->tlsCertPath(), 'no generated pair while an operator pair is selected');
        $this->closeSel($sel);
        self::assertSame($cert, file_get_contents($c));
        self::assertSame($key, file_get_contents($k));

        // Prior manifest pinned this fingerprint: the same pair is fine, a changed one is not.
        $same = $this->manager(new IdentityInputs(tlsCertFile: $c, tlsKeyFile: $k))->select('persona-host.example', $sel->manifestRecord());
        $this->closeSel($same);
        [$cert2, $key2] = self::makePair('operator.example');
        file_put_contents($c, $cert2);
        file_put_contents($k, $key2);
        $this->expectCode('tls-selection-changed', fn () => $this->manager(new IdentityInputs(tlsCertFile: $c, tlsKeyFile: $k))->select('persona-host.example', $sel->manifestRecord()));
        // ...and an operator pair must not silently stop being served.
        $this->expectCode('tls-selection-changed', fn () => $this->manager(new IdentityInputs())->select('persona-host.example', $sel->manifestRecord()));
    }

    public function test_half_mismatched_or_symlinked_explicit_pairs_fail(): void
    {
        [$cert, $key] = self::makePair('operator.example');
        [, $otherKey] = self::makePair('operator.example');
        $c = $this->base . '/op.crt';
        $k = $this->base . '/op.key';
        file_put_contents($c, $cert);
        file_put_contents($k, $otherKey);
        chmod($k, 0600);
        $this->expectCode('tls-explicit-incomplete', fn () => $this->manager(new IdentityInputs(tlsCertFile: $c))->select('h.example', null));
        $this->expectCode('tls-explicit-pair-invalid', fn () => $this->manager(new IdentityInputs(tlsCertFile: $c, tlsKeyFile: $k))->select('h.example', null));
        file_put_contents($k, $key);
        symlink($k, $this->base . '/op-link.key');
        $this->expectCode('tls-explicit-path', fn () => $this->manager(new IdentityInputs(tlsCertFile: $c, tlsKeyFile: $this->base . '/op-link.key'))->select('h.example', null));
        chmod($k, 0666);
        $this->expectCode('tls-explicit-unsafe', fn () => $this->manager(new IdentityInputs(tlsCertFile: $c, tlsKeyFile: $k))->select('h.example', null));
    }

    // --- legacy --------------------------------------------------------------------------------------

    public function test_legacy_pair_is_selected_byte_identical_and_a_half_pair_fails(): void
    {
        [$cert, $key] = self::makePair('legacy.example');
        file_put_contents($this->legacy . '/funnypot.crt', $cert);
        $this->expectCode('tls-legacy-incomplete', fn () => $this->manager(new IdentityInputs())->select('h.example', null));
        file_put_contents($this->legacy . '/funnypot.key', $key);
        chmod($this->legacy . '/funnypot.key', 0600);
        $sel = $this->manager(new IdentityInputs())->select('h.example', null);
        self::assertSame(TlsSelection::LEGACY, $sel->selection);
        self::assertSame($cert, $sel->cert->bytes);
        self::assertSame($this->legacy . '/funnypot.crt', $sel->certPath);
        self::assertFileDoesNotExist($this->paths()->tlsCertPath());
        $this->closeSel($sel);
        self::assertSame($cert, file_get_contents($this->legacy . '/funnypot.crt'));
        self::assertSame($key, file_get_contents($this->legacy . '/funnypot.key'));
    }

    // --- Let's Encrypt -------------------------------------------------------------------------------

    private function makeLe(string $domain, int $certRev = 1, ?int $keyRev = null, ?string $certTarget = null): array
    {
        $keyRev ??= $certRev;
        [$cert, $key] = self::makePair($domain);
        mkdir($this->le . '/live/' . $domain, 0755, true);
        mkdir($this->le . '/archive/' . $domain, 0755, true);
        file_put_contents($this->le . '/archive/' . $domain . '/fullchain' . $certRev . '.pem', $cert);
        file_put_contents($this->le . '/archive/' . $domain . '/privkey' . $keyRev . '.pem', $key);
        chmod($this->le . '/archive/' . $domain . '/privkey' . $keyRev . '.pem', 0600);
        symlink($certTarget ?? '../../archive/' . $domain . '/fullchain' . $certRev . '.pem', $this->le . '/live/' . $domain . '/fullchain.pem');
        symlink('../../archive/' . $domain . '/privkey' . $keyRev . '.pem', $this->le . '/live/' . $domain . '/privkey.pem');

        return [$cert, $key];
    }

    public function test_letsencrypt_pair_accepted_only_in_the_exact_live_to_archive_shape(): void
    {
        $absent = $this->manager(new IdentityInputs(leDomain: 'admin.example.com'))->select('h.example', null);
        self::assertFalse($absent->hasAdminPair(), 'first boot before issuance: a valid absent pair');
        self::assertContains(DecoyCertificateManager::WARN_LETSENCRYPT_ABSENT, $absent->warnings);
        $this->closeSel($absent);

        [$cert, $key] = $this->makeLe('admin.example.com', 3);
        $sel = $this->manager(new IdentityInputs(leDomain: 'admin.example.com'))->select('h.example', null);
        self::assertTrue($sel->hasAdminPair());
        self::assertSame('admin.example.com', $sel->adminDomain);
        self::assertSame($cert, $sel->adminCert->bytes);
        self::assertSame($key, $sel->adminKey->bytes);
        self::assertSame(SourceOpenAttestation::LETSENCRYPT_MANAGED_CHAIN, $sel->adminCert->attestation->id);
        self::assertSame(strtolower((string) openssl_x509_fingerprint($cert, 'sha256')), $sel->adminFingerprintSha256);
        $this->closeSel($sel);
        self::assertSame($cert, file_get_contents($this->le . '/archive/admin.example.com/fullchain3.pem'), 'byte-identical');
    }

    public function test_letsencrypt_wrong_shapes_fail(): void
    {
        $this->makeLe('mismatch.example.com', 1, 2);
        $this->expectCode('tls-letsencrypt-revision-mismatch', fn () => $this->manager(new IdentityInputs(leDomain: 'mismatch.example.com'))->select('h.example', null));

        $this->makeLe('abs.example.com', 1, 1, $this->le . '/archive/abs.example.com/fullchain1.pem');
        $this->expectCode('tls-letsencrypt-link-shape', fn () => $this->manager(new IdentityInputs(leDomain: 'abs.example.com'))->select('h.example', null));

        $this->makeLe('cross.example.com', 1, 1, '../../archive/other.example.com/fullchain1.pem');
        $this->expectCode('tls-letsencrypt-link-shape', fn () => $this->manager(new IdentityInputs(leDomain: 'cross.example.com'))->select('h.example', null));

        $this->makeLe('nested.example.com', 1, 1, '../../archive/nested.example.com/sub/fullchain1.pem');
        $this->expectCode('tls-letsencrypt-link-shape', fn () => $this->manager(new IdentityInputs(leDomain: 'nested.example.com'))->select('h.example', null));

        // A regular file where the managed link must be is not the managed shape either.
        [$cert] = self::makePair('plain.example.com');
        mkdir($this->le . '/live/plain.example.com', 0755, true);
        mkdir($this->le . '/archive/plain.example.com', 0755, true);
        file_put_contents($this->le . '/live/plain.example.com/fullchain.pem', $cert);
        file_put_contents($this->le . '/live/plain.example.com/privkey.pem', 'x');
        $this->expectCode('tls-letsencrypt-link-shape', fn () => $this->manager(new IdentityInputs(leDomain: 'plain.example.com'))->select('h.example', null));
    }
}
