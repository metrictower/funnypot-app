<?php

declare(strict_types=1);

namespace Funnypot\App\Config;

/**
 * An id that changes whenever the deployed code changes, app-only deploys included. The SSRF decoy's
 * served-key index versions on it, so new generator code rebuilds the index instead of leaving keys it
 * no longer knows answered as invalid.
 *
 * The image bakes one at build time: `build-id` at the app root holds a sha256 over every file of src/,
 * resources/ and composer's installed-package map. Without it (a source checkout, a test run), the id is
 * a hash over the generator sources that decide which keys and hosts are served, plus composer's map.
 * Only local files under the app root are read.
 */
final class BuildStamp
{
    /** The sources whose code decides what keys and hosts the app serves. */
    public const GENERATOR_FILES = [
        'src/App/Tarpit/ConfigDump.php', 'src/App/Tarpit/InertSecret.php', 'src/App/Tarpit/LogRabbitHole.php', 'src/App/Tarpit/HostileFormat.php',
        'src/App/Render/Fake/FakeSecrets.php', 'src/App/Render/Fake/Fleet.php', 'src/App/Render/Fake/ServerProfile.php', 'src/Shell/Host/HostIdentity.php',
        'src/Shell/Fs/FakeFilesystem.php', 'src/Shell/Fs/PinnedNodes.php', 'src/Shell/Fs/Draw.php',
        'src/App/Tarpit/Ssrf/KeyIndexBuilder.php', 'src/App/Tarpit/Ssrf/ServedKeys.php', 'vendor/composer/installed.php',
    ];

    public static function value(string $appRoot): string
    {
        $baked = $appRoot . '/build-id';
        if (is_file($baked)) {
            $id = trim((string) file_get_contents($baked));
            if (preg_match('/\A[0-9a-f]{64}\z/', $id) === 1) {
                return 'image:' . $id;
            }
        }
        $h = hash_init('sha256');
        foreach (self::GENERATOR_FILES as $file) {
            $path = $appRoot . '/' . $file;
            hash_update($h, $file . "\0" . (is_file($path) ? (string) hash_file('sha256', $path) : 'missing') . "\n");
        }

        return 'src:' . hash_final($h);
    }
}
