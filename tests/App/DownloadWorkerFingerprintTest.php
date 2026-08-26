<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use PHPUnit\Framework\TestCase;

/**
 * Fingerprint guard for the download service worker. `DownloadRouter` serves `src/App/Download/sw.js`
 * to the client VERBATIM, so its bytes are attacker-visible on a single unauthenticated GET
 * (/__dl/sw.js). Three commits in a row shipped that file carrying the words "honeypot", "funnypot",
 * "bait", "decoy" etc. in its comments — a one-request unmasking — because NO test ever read the real
 * file (FingerprintSafetyTest scans skin HTML + LLM exemplars; DownloadRouterTest stubs the worker with
 * "/* sw *​/"). This reads the actual shipped bytes and fails if any self-identifying term reappears.
 */
final class DownloadWorkerFingerprintTest extends TestCase
{
    private const SW_PATH = __DIR__ . '/../../src/App/Download/sw.js';

    /** Terms that would reveal the box is a honeypot / this project. Word-boundary matched so ordinary
     *  code like "conTROLLer" is not a false positive. */
    private const TELLS = [
        'honeypot', 'funnypot', 'metrictower', 'bait', 'decoy', 'lure',
        'attacker', 'scanner', 'tarpit', 'malformed', 'skull', 'troll', 'sabotage', 'deception',
    ];

    public function test_worker_file_exists_and_is_the_served_artifact(): void
    {
        self::assertFileExists(self::SW_PATH);
        $src = (string) file_get_contents(self::SW_PATH);
        // Sanity: it really is the worker (so a rename can't make this test vacuously pass).
        self::assertStringContainsString("addEventListener('fetch'", $src);
    }

    public function test_worker_carries_no_self_identifying_terms(): void
    {
        $src = strtolower((string) file_get_contents(self::SW_PATH));
        foreach (self::TELLS as $term) {
            self::assertDoesNotMatchRegularExpression(
                '/\b' . preg_quote($term, '/') . '\b/',
                $src,
                "download worker (served verbatim at /__dl/sw.js) contains the self-identifying term '{$term}' "
                . '— an unauthenticated GET would unmask the honeypot'
            );
        }
    }
}
