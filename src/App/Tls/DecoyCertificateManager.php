<?php

declare(strict_types=1);

namespace Funnypot\App\Tls;

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityInputs;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\OpenedSource;
use Funnypot\App\Identity\SourceOpener;

/**
 * Selects, verifies and (only for its own marked pair) generates the certificate nginx serves.
 * Precedence is fixed: an explicit FUNNYPOT_TLS_CERT_FILE + FUNNYPOT_TLS_KEY_FILE pair, else a complete
 * unmarked legacy /etc/nginx/funnypot.{crt,key} pair, else the provenance-marked generated pair under
 * the private persistent identity directory. The first two are served byte-identical and never
 * copied, marked, overwritten or regenerated; a half pair, an unreadable key, a mismatched pair or a
 * previously selected operator pair whose fingerprint changed fails before nginx starts.
 *
 * Generated material: the subject CN and DNS SAN come from FUNNYPOT_CN, else the persona hostname,
 * plus FUNNYPOT_PUBLIC_DNS — each passed through {@see DnsName} before touching OpenSSL — and the key
 * is fresh CSPRNG asymmetric material, never KDF output. A sidecar records schema, hostname, public
 * fingerprint and time (never the key) so a marked pair can be safely regenerated after deletion
 * with the same subject/SAN and a new random key. The optional Let's Encrypt admin pair is the single
 * managed-symlink exception and is validated by the exact live→archive chain rule.
 */
final class DecoyCertificateManager
{
    public const PROVENANCE_SCHEMA = 'funnypot-tls-provenance/v1';
    public const DEFAULT_LEGACY_DIR = '/etc/nginx';
    public const DEFAULT_LETSENCRYPT_ROOT = '/etc/letsencrypt';
    public const MAX_PEM_BYTES = 65536;
    public const DAYS_VALID = 3650;

    public const WARN_LETSENCRYPT_ABSENT = 'tls-letsencrypt-absent';
    public const WARN_GENERATED_REGENERATED = 'tls-generated-regenerated';

    private SourceOpener $opener;

    /** @var list<string> */
    private array $warnings = [];

    public function __construct(
        private IdentityPaths $paths,
        private IdentityFileOps $ops,
        private IdentityInputs $inputs,
        private string $legacyDir = self::DEFAULT_LEGACY_DIR,
        private string $letsEncryptRoot = self::DEFAULT_LETSENCRYPT_ROOT,
    ) {
        $this->opener = new SourceOpener($ops);
    }

    /**
     * @param array<string,mixed>|null $prior the previous manifest's tls record, if any
     */
    public function select(string $personaHostname, ?array $prior): TlsSelection
    {
        $this->warnings = [];
        // Every hostname input is validated up front, before any file is generated or path formed.
        $hostname = DnsName::validate($this->inputs->cn ?? $personaHostname, 'tls-hostname-invalid');
        $publicDns = $this->inputs->publicDns !== null ? DnsName::validate($this->inputs->publicDns, 'tls-public-dns-invalid') : null;
        $leDomain = $this->inputs->leDomain !== null ? DnsName::validate($this->inputs->leDomain, 'tls-letsencrypt-domain-invalid') : null;

        [$selection, $certPath, $keyPath, $cert, $key] = $this->selectMain($hostname, $publicDns);
        $fingerprint = $this->fingerprint($cert->bytes, 'tls-' . $selection);

        // An operator pair that was served before must still be the pair served now.
        if (is_array($prior) && in_array($prior['selection'] ?? null, [TlsSelection::EXPLICIT, TlsSelection::LEGACY], true)) {
            if (($prior['selection'] ?? null) !== $selection || ($prior['fingerprint_sha256'] ?? null) !== $fingerprint) {
                $this->closeAll([$cert, $key]);
                throw IdentityBootstrapException::withCode('tls-selection-changed', IdentityBootstrapException::REMEDY_TLS);
            }
        }

        [$adminDomain, $adminFp, $adminCert, $adminKey] = $this->selectAdmin($leDomain);

        return new TlsSelection(
            $selection,
            $hostname,
            $certPath,
            $keyPath,
            $fingerprint,
            $cert,
            $key,
            $adminDomain,
            $adminFp,
            $adminCert,
            $adminKey,
            $this->warnings,
        );
    }

    /** @return array{0:string,1:string,2:string,3:OpenedSource,4:OpenedSource} */
    private function selectMain(string $hostname, ?string $publicDns): array
    {
        $explicitCert = $this->inputs->tlsCertFile;
        $explicitKey = $this->inputs->tlsKeyFile;
        if ($explicitCert !== null || $explicitKey !== null) {
            if ($explicitCert === null || $explicitKey === null) {
                throw IdentityBootstrapException::withCode('tls-explicit-incomplete', IdentityBootstrapException::REMEDY_TLS);
            }
            $cert = $this->opener->openCanonicalPath($explicitCert, 'tls-explicit', self::MAX_PEM_BYTES, SourceOpener::MODE_NO_GO_WRITE);
            $key = $this->opener->openCanonicalPath($explicitKey, 'tls-explicit', self::MAX_PEM_BYTES, SourceOpener::MODE_NO_GO_WRITE);
            $this->requirePair($cert, $key, 'tls-explicit');

            return [TlsSelection::EXPLICIT, $explicitCert, $explicitKey, $cert, $key];
        }

        $legacyCert = rtrim($this->legacyDir, '/') . '/funnypot.crt';
        $legacyKey = rtrim($this->legacyDir, '/') . '/funnypot.key';
        $hasCert = $this->ops->lstat($legacyCert) !== false;
        $hasKey = $this->ops->lstat($legacyKey) !== false;
        if ($hasCert || $hasKey) {
            if (!$hasCert || !$hasKey) {
                throw IdentityBootstrapException::withCode('tls-legacy-incomplete', IdentityBootstrapException::REMEDY_TLS);
            }
            $cert = $this->opener->openCanonicalPath($legacyCert, 'tls-legacy', self::MAX_PEM_BYTES, SourceOpener::MODE_NO_GO_WRITE);
            $key = $this->opener->openCanonicalPath($legacyKey, 'tls-legacy', self::MAX_PEM_BYTES, SourceOpener::MODE_NO_GO_WRITE);
            $this->requirePair($cert, $key, 'tls-legacy');

            return [TlsSelection::LEGACY, $legacyCert, $legacyKey, $cert, $key];
        }

        [$cert, $key] = $this->ensureGenerated($hostname, $publicDns);

        return [TlsSelection::GENERATED, $this->paths->tlsCertPath(), $this->paths->tlsKeyPath(), $cert, $key];
    }

    /** @return array{0:OpenedSource,1:OpenedSource} */
    private function ensureGenerated(string $hostname, ?string $publicDns): array
    {
        $dir = $this->paths->tlsDir();
        $st = $this->ops->lstat($dir);
        if ($st === false) {
            if (!$this->ops->mkdir($dir, 0700) || !$this->ops->chmod($dir, 0700)) {
                throw IdentityBootstrapException::withCode('tls-dir-create', IdentityBootstrapException::REMEDY_STORAGE);
            }
        }
        $this->opener->requireDirectory($dir, 'tls-dir', SourceOpener::MODE_PRIVATE);

        $san = $publicDns !== null && $publicDns !== $hostname ? [$hostname, $publicDns] : [$hostname];
        $hasCert = $this->ops->lstat($this->paths->tlsCertPath()) !== false;
        $hasKey = $this->ops->lstat($this->paths->tlsKeyPath()) !== false;
        $hasProvenance = $this->ops->lstat($this->paths->tlsProvenancePath()) !== false;

        if (($hasCert || $hasKey) && !$hasProvenance) {
            // Something is in OUR slot without our marker: never overwrite what we cannot prove we made.
            throw IdentityBootstrapException::withCode('tls-generated-unmarked', IdentityBootstrapException::REMEDY_TLS);
        }
        if ($hasProvenance && $hasCert && $hasKey) {
            [$cert, $key] = $this->openGenerated();
            $prov = $this->readProvenance();
            $fp = $this->fingerprint($cert->bytes, 'tls-generated');
            if (($prov['fingerprint_sha256'] ?? null) !== $fp || ($prov['hostname'] ?? null) !== $hostname || ($prov['san'] ?? null) !== $san) {
                // A marked pair whose subject policy moved (operator changed FUNNYPOT_CN) or whose
                // sidecar disagrees is regenerated: it is provably ours, and a stale CN is a tell.
                $this->closeAll([$cert, $key]);
                $this->warnings[] = self::WARN_GENERATED_REGENERATED;
                $this->generate($hostname, $san);

                [$cert, $key] = $this->openGenerated();
            }
            $this->requirePair($cert, $key, 'tls-generated');

            return [$cert, $key];
        }
        if ($hasProvenance) {
            $this->warnings[] = self::WARN_GENERATED_REGENERATED;
        }
        $this->generate($hostname, $san);
        [$cert, $key] = $this->openGenerated();
        $this->requirePair($cert, $key, 'tls-generated');

        return [$cert, $key];
    }

    /** @return array{0:OpenedSource,1:OpenedSource} */
    private function openGenerated(): array
    {
        $anchor = $this->paths->storageRoot();
        $base = ['.funnypot', 'identity', 'tls'];
        $cert = $this->opener->openDirect($anchor, [...$base, 'cert.pem'], 'tls-generated', self::MAX_PEM_BYTES, SourceOpener::MODE_PRIVATE, SourceOpener::MODE_PRIVATE);
        $key = $this->opener->openDirect($anchor, [...$base, 'key.pem'], 'tls-generated', self::MAX_PEM_BYTES, SourceOpener::MODE_PRIVATE, SourceOpener::MODE_PRIVATE);

        return [$cert, $key];
    }

    /** @return array<string,mixed> */
    private function readProvenance(): array
    {
        $src = $this->opener->openDirect($this->paths->storageRoot(), ['.funnypot', 'identity', 'tls', 'provenance.json'], 'tls-provenance', 4096, SourceOpener::MODE_PRIVATE, SourceOpener::MODE_PRIVATE);
        $this->ops->close($src->handle);
        $doc = json_decode($src->bytes, true, 4);
        if (!is_array($doc) || ($doc['schema'] ?? null) !== self::PROVENANCE_SCHEMA) {
            throw IdentityBootstrapException::withCode('tls-provenance-malformed', IdentityBootstrapException::REMEDY_TLS);
        }

        return $doc;
    }

    /**
     * Fresh RSA-2048 key + self-signed certificate through the OpenSSL API (no shell). The subject and
     * SAN are already-validated DNS names, so the temporary config they are written into cannot gain a
     * directive. Files land via O_EXCL 0600 temps + rename inside the 0700 tls dir; the sidecar is
     * written last so a crash mid-way leaves an unmarked-but-incomplete slot that the next run refuses
     * rather than serves.
     *
     * @param list<string> $san
     */
    private function generate(string $hostname, array $san): void
    {
        foreach ([$hostname, ...$san] as $n) {
            DnsName::validate($n, 'tls-hostname-invalid');
        }
        $conf = $this->paths->tlsDir() . '/openssl.cnf.tmp.' . $this->ops->randomHex(6);
        $confText = "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = {$hostname}\n[v3]\n"
            . 'subjectAltName = ' . implode(',', array_map(static fn (string $n): string => 'DNS:' . $n, $san)) . "\n"
            . "basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n";
        $this->writePrivate($conf, $confText, 'tls-generate');
        try {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'config' => $conf]);
            $csr = $key !== false ? openssl_csr_new(['commonName' => $hostname], $key, ['digest_alg' => 'sha256', 'config' => $conf, 'req_extensions' => 'v3']) : false;
            $x509 = $csr !== false ? openssl_csr_sign($csr, null, $key, self::DAYS_VALID, ['digest_alg' => 'sha256', 'config' => $conf, 'x509_extensions' => 'v3'], random_int(1, PHP_INT_MAX >> 2)) : false;
            $certPem = '';
            $keyPem = '';
            if ($x509 === false || !openssl_x509_export($x509, $certPem) || !openssl_pkey_export($key, $keyPem, null, ['config' => $conf])) {
                throw IdentityBootstrapException::withCode('tls-generate', IdentityBootstrapException::REMEDY_RUNTIME);
            }
        } finally {
            $this->ops->unlink($conf);
        }
        $parsed = openssl_x509_parse($certPem);
        if (!is_array($parsed) || ($parsed['subject']['CN'] ?? null) !== $hostname) {
            throw IdentityBootstrapException::withCode('tls-generate', IdentityBootstrapException::REMEDY_RUNTIME);
        }

        $this->ops->unlink($this->paths->tlsProvenancePath()); // unmark first: an interrupted rewrite must never look complete
        $this->writePrivate($this->paths->tlsKeyPath(), $keyPem, 'tls-generate');
        $this->writePrivate($this->paths->tlsCertPath(), $certPem, 'tls-generate');
        $prov = [
            'schema' => self::PROVENANCE_SCHEMA,
            'hostname' => $hostname,
            'san' => $san,
            'fingerprint_sha256' => $this->fingerprint($certPem, 'tls-generate'),
            'generated_at' => $this->ops->time(),
        ];
        $this->writePrivate($this->paths->tlsProvenancePath(), json_encode($prov, JSON_UNESCAPED_SLASHES) . "\n", 'tls-generate');
    }

    /** O_EXCL 0600 temp in the same directory, full write + fsync, rename into place, directory fsync. */
    private function writePrivate(string $path, string $bytes, string $code): void
    {
        $tmp = $path . '.tmp.' . $this->ops->randomHex(6);
        $h = $this->ops->openExclusive($tmp);
        if ($h === false) {
            throw IdentityBootstrapException::withCode($code . '-write', IdentityBootstrapException::REMEDY_STORAGE);
        }
        try {
            if ($this->ops->write($h, $bytes) !== strlen($bytes) || !$this->ops->flush($h) || !$this->ops->fsync($h)) {
                throw IdentityBootstrapException::withCode($code . '-write', IdentityBootstrapException::REMEDY_STORAGE);
            }
        } catch (\Throwable $e) {
            $this->ops->close($h);
            $this->ops->unlink($tmp);
            throw $e;
        }
        $this->ops->close($h);
        if (!$this->ops->rename($tmp, $path)) {
            $this->ops->unlink($tmp);
            throw IdentityBootstrapException::withCode($code . '-write', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $d = $this->ops->openDir(dirname($path));
        if ($d !== false) {
            $this->ops->fsync($d);
            $this->ops->close($d);
        }
    }

    /** @param string|null $domain already validated @return array{0:?string,1:?string,2:?OpenedSource,3:?OpenedSource} */
    private function selectAdmin(?string $domain): array
    {
        if ($domain === null) {
            return [null, null, null, null];
        }
        $live = rtrim($this->letsEncryptRoot, '/') . '/live/' . $domain;
        if ($this->ops->lstat($live) === false) {
            // First boot before scripts/letsencrypt.sh has issued anything: a valid absent pair.
            $this->warnings[] = self::WARN_LETSENCRYPT_ABSENT;

            return [$domain, null, null, null];
        }
        [$cert, $key] = $this->opener->openLetsEncryptPair($this->letsEncryptRoot, $domain, self::MAX_PEM_BYTES);
        $this->requirePair($cert, $key, 'tls-letsencrypt');

        return [$domain, $this->fingerprint($cert->bytes, 'tls-letsencrypt'), $cert, $key];
    }

    private function requirePair(OpenedSource $cert, OpenedSource $key, string $code): void
    {
        $ok = @openssl_x509_read($cert->bytes) !== false
            && @openssl_pkey_get_private($key->bytes) !== false
            && @openssl_x509_check_private_key($cert->bytes, $key->bytes);
        while (openssl_error_string() !== false) {
            // drain the thread-local error queue so a rejected pair cannot leak into a later message
        }
        if (!$ok) {
            $this->closeAll([$cert, $key]);
            throw IdentityBootstrapException::withCode($code . '-pair-invalid', IdentityBootstrapException::REMEDY_TLS);
        }
    }

    private function fingerprint(string $certPem, string $code): string
    {
        $fp = @openssl_x509_fingerprint($certPem, 'sha256');
        while (openssl_error_string() !== false) {
        }
        if (!is_string($fp) || $fp === '') {
            throw IdentityBootstrapException::withCode($code . '-pair-invalid', IdentityBootstrapException::REMEDY_TLS);
        }

        return strtolower($fp);
    }

    /** @param list<OpenedSource> $sources */
    private function closeAll(array $sources): void
    {
        foreach ($sources as $s) {
            $this->ops->close($s->handle);
        }
    }
}
