<?php

declare(strict_types=1);

namespace Funnypot\App\ThreatIntel;

use Funnypot\Core\RequestContext;

/**
 * Names the SCANNER behind an HTTP probe from the fixed canary tokens it emits — the HTTP-tier analog
 * of the SIP tier's SipServer::classifyTool(). Passive and advisory: it reads the request only, emits
 * nothing, and its label is attached to the LOG entry after the response has already gone out. It never
 * influences detection, the served decoy, latency, routing/persona, tarpit, or the report class.
 *
 * High-precision, not high-recall: a false tool label is worse than none, so the pack carries only
 * strong, rarely-benign tells and no tell firing means no attribution (null), unlike the SIP tier which
 * sees only probe traffic and emits 'unknown' on a miss. Distinct from AttackClassifier, which names the
 * attack CLASS (sqli/xss/…); this names the TOOL.
 *
 * Matching is bounded by construction: literal stripos for needles, an anchored+bounded extractor for a
 * version, and a linear fixed-slice scan for tplmap's numeric SSTI fences — no arbitrary-gap regex, no
 * attacker-sized backtracking. Request surfaces are decoded once (raw + rawurldecode, a second pass only
 * if an encoded octet survived) and lowercased, reusing AttackClassifier's decode discipline so an
 * encoded token still matches.
 */
final class ScannerAttributor
{
    private const PARAMS_CAP = 65536;
    private const TARGET_CAP = 16384;
    private const PATH_CAP = 4096;
    private const UA_CAP = 512;
    private const HEADER_CAP = 1024;
    private const VERSION_CAP = 32;

    private const SURFACES = ['ua', 'path', 'params', 'target', 'header'];

    /** @var list<array<string,mixed>> the validated fingerprint pack (most-specific first). */
    private array $pack;

    /** @param list<array<string,mixed>>|null $pack injected for tests; otherwise the app resource pack. */
    public function __construct(?array $pack = null)
    {
        $pack ??= require dirname(__DIR__, 3) . '/resources/scanner-fingerprints.php';
        $this->pack = self::validatePack($pack);
    }

    /**
     * The tool behind the request, or null when no tell fires (the honest empty default). The first
     * matching row wins; surfaces are built at most once and reused across rows.
     */
    public function attribute(RequestContext $r): ?Attribution
    {
        $params = null;
        $target = null;
        $path = null;
        $ua = null;
        $headers = null;

        foreach ($this->pack as $row) {
            $hay = null;
            switch ($row['surface']) {
                case 'params':
                    $hay = $params ??= self::decodeSurface($r->query . "\n" . (string) ($r->rawBody ?? ''), self::PARAMS_CAP);
                    break;
                case 'target':
                    $hay = $target ??= self::decodeSurface($r->path . '?' . $r->query, self::TARGET_CAP);
                    break;
                case 'path':
                    $hay = $path ??= self::decodeSurface($r->path, self::PATH_CAP);
                    break;
                case 'ua':
                    $hay = $ua ??= strtolower(substr((string) ($r->headers['User-Agent'] ?? ''), 0, self::UA_CAP));
                    break;
                case 'header':
                    $headers ??= self::lowerHeaderMap($r->headers);
                    $val = $headers[strtolower((string) $row['header'])] ?? null;
                    if ($val === null) {
                        continue 2;
                    }
                    $hay = strtolower(substr($val, 0, self::HEADER_CAP));
                    break;
            }

            if (isset($row['matcher'])) {
                $matched = self::fencePair($hay, (int) $row['matcher']['max_gap'], (int) $row['matcher']['max_starts'])['matched'];
            } else {
                $needle = (string) $row['needle'];
                $matched = $needle === '' ? true : (stripos($hay, $needle) !== false);
            }
            if (!$matched) {
                continue;
            }

            $version = isset($row['version']) ? self::extractVersion($hay, $row['version']) : null;

            return new Attribution((string) $row['tool'], (string) $row['confidence'], $version);
        }

        return null;
    }

    /** Raw + URL-decoded (and a second pass if an encoded octet survived), lowercased. The input is
     *  capped before decoding, so the working surface is bounded to a small constant multiple of $cap. */
    private static function decodeSurface(string $raw, int $cap): string
    {
        $raw = substr($raw, 0, $cap);
        $once = rawurldecode($raw);
        $surface = $raw . "\n" . $once;
        if (preg_match('~%[0-9A-Fa-f]{2}~', $once) === 1) {
            $surface .= "\n" . rawurldecode($once);
        }

        return strtolower($surface);
    }

    /** @param array<string,string> $headers @return array<string,string> keyed by lowercased name. */
    private static function lowerHeaderMap(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $out[strtolower($name)] = $value;
        }

        return $out;
    }

    /** @param array{re:string,group:int} $spec */
    private static function extractVersion(string $hay, array $spec): ?string
    {
        if (preg_match($spec['re'], $hay, $m) === 1 && isset($m[$spec['group']]) && $m[$spec['group']] !== '') {
            $v = $m[$spec['group']];

            return strlen($v) <= self::VERSION_CAP ? $v : null;
        }

        return null;
    }

    /**
     * tplmap's numeric SSTI fences: {{<10 digits>}}payload{{<10 digits>}}. Linear and bounded — scan for
     * a `{{` start, validate the fixed 14-byte candidate with a fully-anchored regex, then look for a
     * second valid fence whose start is within $maxGap bytes of the first fence's end. At most $maxStarts
     * candidate `{{` positions are inspected in total; beyond that it gives up (no match) rather than
     * scan an attacker-sized surface. No `.*`, unbounded lookaround, or backtracking window.
     *
     * @return array{matched:bool,starts:int} starts = candidate positions inspected (a tested bound).
     */
    public static function fencePair(string $hay, int $maxGap, int $maxStarts): array
    {
        $fence = '~\A\{\{\d{10}\}\}\z~D';
        $starts = 0;
        $from = 0;

        while (($p = strpos($hay, '{{', $from)) !== false) {
            if ($starts >= $maxStarts) {
                return ['matched' => false, 'starts' => $starts];
            }
            $starts++;
            if (preg_match($fence, substr($hay, $p, 14)) === 1) {
                $secondFrom = $p + 14;
                $q = $secondFrom;
                while (($q = strpos($hay, '{{', $q)) !== false && ($q - $secondFrom) <= $maxGap) {
                    if ($starts >= $maxStarts) {
                        return ['matched' => false, 'starts' => $starts];
                    }
                    $starts++;
                    if (preg_match($fence, substr($hay, $q, 14)) === 1) {
                        return ['matched' => true, 'starts' => $starts];
                    }
                    $q += 2;
                }
            }
            $from = $p + 2;
        }

        return ['matched' => false, 'starts' => $starts];
    }

    /**
     * Reject a malformed or unbounded pack at load time, so a bad row is a fatal misconfiguration rather
     * than a silent dead rule or a ReDoS foothold. Enforces the closed vocabularies, the surface/matcher
     * shapes, the tplmap gap ceiling, and — for a version extractor — that the regex is fully anchored and
     * carries no unbounded quantifier or gap.
     *
     * @param array<int|string,mixed> $pack
     * @return list<array<string,mixed>>
     */
    public static function validatePack(array $pack): array
    {
        $out = [];
        foreach ($pack as $i => $row) {
            if (!is_array($row)) {
                throw new \InvalidArgumentException("scanner-fingerprints row {$i} is not an array");
            }
            $surface = $row['surface'] ?? null;
            if (!is_string($surface) || !in_array($surface, self::SURFACES, true)) {
                throw new \InvalidArgumentException("scanner-fingerprints row {$i}: bad surface");
            }
            if (!isset($row['tool']) || !is_string($row['tool']) || preg_match('~\A[a-z0-9][a-z0-9-]{0,31}\z~', $row['tool']) !== 1) {
                throw new \InvalidArgumentException("scanner-fingerprints row {$i}: tool must be a short lowercase closed-vocab label");
            }
            if (($row['confidence'] ?? null) !== 'high' && ($row['confidence'] ?? null) !== 'medium') {
                throw new \InvalidArgumentException("scanner-fingerprints row {$i}: confidence must be high|medium");
            }

            $hasMatcher = isset($row['matcher']);
            $hasNeedle = array_key_exists('needle', $row);
            if ($hasMatcher === $hasNeedle) {
                throw new \InvalidArgumentException("scanner-fingerprints row {$i}: exactly one of needle|matcher required");
            }

            if ($surface === 'header') {
                if (!isset($row['header']) || !is_string($row['header']) || $row['header'] === '') {
                    throw new \InvalidArgumentException("scanner-fingerprints row {$i}: header surface needs a header name");
                }
            }

            if ($hasNeedle) {
                if (!is_string($row['needle'])) {
                    throw new \InvalidArgumentException("scanner-fingerprints row {$i}: needle must be a string");
                }
                // An empty needle (presence-only) is allowed for a header surface only.
                if ($row['needle'] === '' && $surface !== 'header') {
                    throw new \InvalidArgumentException("scanner-fingerprints row {$i}: empty needle only valid for a header surface");
                }
            }

            if ($hasMatcher) {
                $m = $row['matcher'];
                if (!is_array($m) || ($m['kind'] ?? null) !== 'fence_pair') {
                    throw new \InvalidArgumentException("scanner-fingerprints row {$i}: unknown matcher kind");
                }
                $gap = $m['max_gap'] ?? null;
                $mstarts = $m['max_starts'] ?? null;
                if (!is_int($gap) || $gap < 1 || $gap > 256) {
                    throw new \InvalidArgumentException("scanner-fingerprints row {$i}: matcher max_gap must be 1..256");
                }
                if (!is_int($mstarts) || $mstarts < 1 || $mstarts > 1024) {
                    throw new \InvalidArgumentException("scanner-fingerprints row {$i}: matcher max_starts must be 1..1024");
                }
            }

            if (isset($row['version'])) {
                self::validateVersionSpec($row['version'], (int) $i);
            }

            $out[] = $row;
        }

        return $out;
    }

    /** @param mixed $spec */
    private static function validateVersionSpec($spec, int $i): void
    {
        if (!is_array($spec) || !isset($spec['re']) || !is_string($spec['re']) || !isset($spec['group']) || !is_int($spec['group']) || $spec['group'] < 1) {
            throw new \InvalidArgumentException("scanner-fingerprints row {$i}: version needs {re:string, group:int>=1}");
        }
        $re = $spec['re'];
        // Fully anchored, and free of unbounded constructs, so the extractor honours the ReDoS budget.
        if (strpos($re, '\A') === false || strpos($re, '\z') === false) {
            throw new \InvalidArgumentException("scanner-fingerprints row {$i}: version regex must be anchored (\\A … \\z)");
        }
        foreach (['.*', '.+'] as $bad) {
            if (strpos($re, $bad) !== false) {
                throw new \InvalidArgumentException("scanner-fingerprints row {$i}: version regex has an unbounded quantifier");
            }
        }
        if (preg_match('~\{\d+,\}~', $re) === 1) {
            throw new \InvalidArgumentException("scanner-fingerprints row {$i}: version regex has an open-ended {n,} quantifier");
        }
        if (@preg_match($re, '') === false) {
            throw new \InvalidArgumentException("scanner-fingerprints row {$i}: version regex does not compile");
        }
    }

    /** Every distinct tool label the pack can emit — for the fingerprint-safety label scan. @return list<string> */
    public function toolLabels(): array
    {
        $labels = [];
        foreach ($this->pack as $row) {
            $labels[(string) $row['tool']] = true;
        }

        return array_keys($labels);
    }
}
