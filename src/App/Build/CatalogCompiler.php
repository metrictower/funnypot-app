<?php

declare(strict_types=1);

namespace Funnypot\App\Build;

use Symfony\Component\Yaml\Yaml;

/**
 * Derives the emulation catalog (see {@see \Funnypot\App\Emulation\EmulationCatalog}) from the templates
 * on disk — attack rules, product/route decoys, protocol services — plus the compiled nuclei
 * corpus as one group entry. Build-time only (needs symfony/yaml); the output is pure data.
 *
 * This is the auto-registration mechanism: every emulation the engine ships is discovered here, so
 * the operator's on/off list is always the full, current set. Templates may declare `title`,
 * `category`, `cve` and `default` to control how they appear; anything omitted is derived (title
 * humanized from the id, category from tags, cve from a `cve-…` tag, default = on).
 */
final class CatalogCompiler
{
    /** Tags that name an emulation category, most-specific first. */
    private const CATEGORY_TAGS = [
        'rce', 'deserialization', 'ssti', 'sqli', 'xxe', 'ssrf', 'lfi', 'traversal',
        'redirect', 'xss', 'injection', 'disclosure', 'auth', 'default-login', 'exposure',
    ];

    /**
     * @param string      $appRoot    the app repo root (holds templates/protocol + the nuclei corpus)
     * @param string|null $engineRoot funnypot-core root (holds templates/attack + templates/route +
     *                                the compiled manifest). Null means it is the same root, as in a
     *                                mono-repo or a test fixture.
     * @return array<string,array<string,mixed>> id => catalog entry
     */
    public function compile(string $appRoot, ?string $engineRoot = null): array
    {
        $appRoot = rtrim($appRoot, '/');
        $engineRoot = rtrim($engineRoot ?? $appRoot, '/');
        $entries = [];

        foreach ($this->scan($engineRoot . '/templates/attack', 'id') as [$doc, $rel]) {
            $entry = $this->entry($doc, 'attack', $rel, (string) ($doc['id'] ?? ''));
            if ($entry !== null) {
                $entries[$entry['id']] = $entry;
            }
        }
        // CoreRuleSet-derived attack classes live in a separate generated dir; they broaden the same
        // per-class emulation, so they belong in the catalog as their own toggleable entries.
        foreach ($this->scan($engineRoot . '/templates/attack-crs', 'id') as [$doc, $rel]) {
            $entry = $this->entry($doc, 'attack', $rel, (string) ($doc['id'] ?? ''));
            if ($entry !== null) {
                $entries[$entry['id']] = $entry;
            }
        }
        foreach ($this->scan($engineRoot . '/templates/route', 'id') as [$doc, $rel]) {
            $entry = $this->entry($doc, 'route', $rel, (string) ($doc['id'] ?? ''), 'info');
            if ($entry !== null) {
                $entries[$entry['id']] = $entry;
            }
        }
        foreach ($this->scan($appRoot . '/templates/protocol', 'protocol') as [$doc, $rel]) {
            $proto = (string) ($doc['protocol'] ?? '');
            if ($proto === '') {
                continue;
            }
            $entry = $this->entry($doc, 'service', $rel, 'service-' . $proto, 'medium');
            if ($entry !== null) {
                $entry['ports'] = array_values(array_map('intval', (array) ($doc['listen'] ?? [])));
                $entry['title'] = (string) ($doc['title'] ?? strtoupper($proto));
                $entries[$entry['id']] = $entry;
            }
        }

        $entries['nuclei-reflection'] = $this->corpusEntry($engineRoot);

        uasort($entries, static function (array $a, array $b): int {
            return [$a['kind'], $a['id']] <=> [$b['kind'], $b['id']];
        });

        return $entries;
    }

    /**
     * @param array<string,mixed> $doc
     * @return array<string,mixed>|null
     */
    private function entry(array $doc, string $kind, string $source, string $id, string $defaultSeverity = 'high'): ?array
    {
        if ($id === '') {
            return null;
        }
        $tags = array_map('strval', (array) ($doc['tags'] ?? []));

        return [
            'id' => $id,
            'kind' => $kind,
            'title' => (string) ($doc['title'] ?? $this->humanize($id)),
            'category' => (string) ($doc['category'] ?? $this->category($tags, $kind)),
            'cve' => strtoupper((string) ($doc['cve'] ?? $this->cveFromTags($tags))),
            'severity' => (string) ($doc['severity'] ?? $defaultSeverity),
            'default' => (bool) ($doc['default'] ?? true),
            'ports' => [],
            'source' => $source,
        ];
    }

    /** @return array<string,mixed> */
    private function corpusEntry(string $root): array
    {
        $count = 0;
        $manifest = $root . '/resources/compiled/manifest.json';
        if (is_file($manifest)) {
            $m = json_decode((string) file_get_contents($manifest), true);
            $count = is_array($m) ? (int) ($m['templates_indexed'] ?? 0) : 0;
        }

        return [
            'id' => 'nuclei-reflection',
            'kind' => 'corpus',
            'title' => 'Nuclei detection reflection',
            'category' => 'reflection',
            'cve' => '',
            'severity' => 'varies',
            'default' => true,
            'ports' => [],
            'source' => 'resources/compiled/nuclei-index.full.php',
            'count' => $count,
        ];
    }

    /**
     * Parse every YAML in a dir that has the required key.
     *
     * @return array<int,array{0:array<string,mixed>,1:string}> [doc, relative-path]
     */
    private function scan(string $dir, string $requiredKey): array
    {
        if (!is_dir($dir)) {
            return [];
        }
        $files = glob(rtrim($dir, '/') . '/*.yaml') ?: [];
        sort($files);

        $out = [];
        $rootLen = strlen(dirname($dir, 2)) + 1;
        foreach ($files as $file) {
            $doc = Yaml::parseFile($file);
            if (is_array($doc) && isset($doc[$requiredKey])) {
                $out[] = [$doc, substr($file, $rootLen)];
            }
        }

        return $out;
    }

    /** @param string[] $tags */
    private function category(array $tags, string $kind): string
    {
        foreach (self::CATEGORY_TAGS as $cat) {
            if (in_array($cat, $tags, true)) {
                return $cat;
            }
        }

        return $kind === 'service' ? 'service' : ($kind === 'route' ? 'exposure' : 'other');
    }

    /** @param string[] $tags */
    private function cveFromTags(array $tags): string
    {
        foreach ($tags as $tag) {
            if (preg_match('/^cve-\d{4}-\d{4,}$/i', $tag) === 1) {
                return $tag;
            }
        }

        return '';
    }

    private function humanize(string $id): string
    {
        $s = preg_replace('/^(attack|route|service)-/', '', $id) ?? $id;
        $s = str_replace('-', ' ', $s);

        return ucwords($s);
    }
}
