<?php

declare(strict_types=1);

namespace Funnypot\App\Render;

/**
 * Cache-busting tag for LLM page artifacts. Derived from the grammar, every Render class's
 * mtime+size (recursively, so subdirectories like Skins/ count too), the prompt-builder source, the
 * vendored core chrome classes (Support\Chrome\* + Support\VisualPersona, now that they live in
 * funnypot-core rather than under $srcDir), and the prompt version — so a skin edit, prompt edit,
 * core chrome edit, or grammar change can never serve a fake built for the old shape out of the
 * response cache.
 */
final class ArtifactVersion
{
    public static function current(string $resourcesDir, string $srcDir, string $promptVersion): string
    {
        $grammar = @file_get_contents(rtrim($resourcesDir, '/') . '/page-slots.gbnf');

        $files = self::phpFiles(rtrim($srcDir, '/'));
        // $srcDir is .../src/App/Render; the prompt builder lives at its sibling .../src/App/Llm.
        $promptBuilder = dirname(rtrim($srcDir, '/')) . '/Llm/LlmPromptBuilder.php';
        if (is_file($promptBuilder)) {
            $files[] = $promptBuilder;
        }

        // The Skin/PageSlots/GenericSkin/etc. classes moved out of $srcDir into the vendored core
        // package; hash their vendored copies too so a core chrome change still busts the cache.
        $appRoot = dirname(rtrim($srcDir, '/'), 3);
        $coreChromeDir = $appRoot . '/vendor/metrictower/funnypot-core/src/Support/Chrome';
        $files = array_merge($files, self::phpFiles($coreChromeDir));
        $visualPersona = $appRoot . '/vendor/metrictower/funnypot-core/src/Support/VisualPersona.php';
        if (is_file($visualPersona)) {
            $files[] = $visualPersona;
        }

        sort($files);

        $fingerprint = '';
        foreach ($files as $file) {
            $fingerprint .= filemtime($file) . '.' . filesize($file);
        }

        $hash = hash('sha256', ($grammar === false ? '' : $grammar) . $fingerprint . $promptVersion);

        return 'a' . substr($hash, 0, 11);
    }

    /** @return list<string> */
    private static function phpFiles(string $dir): array
    {
        if (!is_dir($dir)) {
            return [];
        }
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );
        $files = [];
        foreach ($iterator as $file) {
            if ($file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        return $files;
    }
}
