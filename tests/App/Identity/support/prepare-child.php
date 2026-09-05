<?php

declare(strict_types=1);

/**
 * One concurrent preparer, spawned N times by InstallSecretConcurrencyTest against ONE shared storage
 * root. Runs the real IdentityPreparer (legacy/LE lookups isolated beneath the root) and prints the
 * facts the parent compares across all children: public identity hash, keyset commitment, master
 * inode/link count and the TLS fingerprint. Exits non-zero on any bootstrap failure.
 *
 *   php prepare-child.php <storage-dir> <runtime-dir>
 */

require dirname(__DIR__, 4) . '/vendor/autoload.php';

use Funnypot\App\Identity\IdentityBootstrapException;
use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityInputs;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\IdentityPreparer;
use Funnypot\App\Tls\DecoyCertificateManager;

$storage = (string) ($argv[1] ?? '');
$runtime = (string) ($argv[2] ?? '');
if ($storage === '' || $runtime === '') {
    fwrite(STDERR, "usage: prepare-child.php <storage> <runtime>\n");
    exit(2);
}
$paths = IdentityPaths::forStorage($storage, $runtime);
$inputs = new IdentityInputs();
$ops = new IdentityFileOps();
try {
    $result = (new IdentityPreparer($paths, $inputs, $ops, new DecoyCertificateManager($paths, $ops, $inputs, $storage . '/no-legacy-nginx', $storage . '/no-letsencrypt')))->prepare();
} catch (IdentityBootstrapException $e) {
    fwrite(STDERR, 'child failed: ' . $e->errorCode() . "\n");
    exit(1);
}
clearstatcache();
$st = lstat($paths->masterPath());
echo json_encode([
    'hash' => $result->publicPersonaHash,
    'commitment' => $result->keysetCommitment,
    'ino' => $st['ino'] ?? null,
    'nlink' => $st['nlink'] ?? null,
    'mode' => sprintf('%o', ($st['mode'] ?? 0) & 0777),
    'tls' => $result->tls->fingerprintSha256,
    'source' => $result->sourceClass,
]), "\n";
$result->close();
exit(0);
