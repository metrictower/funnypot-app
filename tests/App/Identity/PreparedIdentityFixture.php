<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Identity;

use Funnypot\App\Identity\IdentityFileOps;
use Funnypot\App\Identity\IdentityInputs;
use Funnypot\App\Identity\IdentityPaths;
use Funnypot\App\Identity\IdentityPreparationResult;
use Funnypot\App\Identity\IdentityPreparer;
use Funnypot\App\Tls\DecoyCertificateManager;

/**
 * Runs the REAL identity preparation against an isolated data directory so a php -S child of
 * demo/index.php (or demo/listen.php) boots exactly as the container does: it finds its scoped
 * bundle under the runtime root and never sees a persona/master variable. The master enters as a
 * constructor-injected canonical value (the production explicit-env input) — there is no test-mode
 * bypass in production code — and the legacy/Let's Encrypt lookups are pointed at empty directories
 * beneath the data dir so a developer's real /etc/nginx or /etc/letsencrypt can never leak in.
 */
final class PreparedIdentityFixture
{
    /**
     * @param string $dataDir the isolated data dir that FUNNYPOT_DB also lives in (the storage root)
     * @return array{runtimeDir:string,result:IdentityPreparationResult}
     */
    public static function prepare(string $dataDir, string $persona = IdentityTestSupport::PERSONA, string $tag = 'a', ?IdentityInputs $inputs = null): array
    {
        $dataDir = (string) realpath($dataDir);
        $runtime = $dataDir . '/runtime';
        @mkdir($dataDir . '/no-legacy-nginx', 0700);
        @mkdir($dataDir . '/no-letsencrypt', 0700);
        $paths = IdentityPaths::forStorage($dataDir, $runtime);
        $inputs ??= new IdentityInputs(secretEnv: IdentityTestSupport::canonicalMaster($tag), personaSeed: $persona);
        $ops = new IdentityFileOps();
        $preparer = new IdentityPreparer(
            $paths,
            $inputs,
            $ops,
            new DecoyCertificateManager($paths, $ops, $inputs, $dataDir . '/no-legacy-nginx', $dataDir . '/no-letsencrypt'),
        );
        $result = $preparer->prepare();

        return ['runtimeDir' => $runtime, 'result' => $result];
    }

    /**
     * The child environment additions: only the runtime-root path. Deliberately NO persona or master
     * variable — the child reads its bundle, exactly as php-fpm does after the entrypoint's unset.
     *
     * @return array<string,string>
     */
    public static function childEnv(string $runtimeDir): array
    {
        return [IdentityPaths::RUNTIME_ENV => $runtimeDir];
    }
}
