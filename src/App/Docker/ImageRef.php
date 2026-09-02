<?php

declare(strict_types=1);

namespace Funnypot\App\Docker;

/**
 * Pure, INERT parser for a Docker image reference (`alpine`, `postgres:15.4`,
 * `evil.example:5000/x/miner@sha256:…`). It only ever splits and normalises a string — it never
 * resolves, contacts, or otherwise touches a registry, a network, or the filesystem. Used to decide
 * image locality (is this a tag the fake daemon already "has"?) and to render the "No such image"
 * message + the pull stream coherently.
 *
 * Normalisation follows docker's own rules: the first `/`-separated segment is treated as a registry
 * only when it contains a `.` or `:` or is exactly `localhost`; otherwise the ref is a Docker Hub
 * ("docker.io") ref and a single-segment repo is prefixed with `library/`. A missing tag defaults to
 * `latest` (unless a digest pins it). Everything is bounded: a ref longer than 255 bytes or carrying a
 * character outside docker's own ref charset is marked invalid (the raw form is still returned for
 * logging, never used as a path or host).
 */
final class ImageRef
{
    /** docker's own reference length ceiling. */
    private const MAX_LEN = 255;

    /**
     * @return array{registry:string,repo:string,tag:string,digest:string,canonical:string,display:string,valid:bool}
     */
    public static function parse(string $ref): array
    {
        $raw = substr($ref, 0, self::MAX_LEN);
        $invalid = [
            'registry' => '', 'repo' => '', 'tag' => '', 'digest' => '',
            'canonical' => '', 'display' => $raw, 'valid' => false,
        ];

        if ($ref === '' || strlen($ref) > self::MAX_LEN) {
            return $invalid;
        }
        // docker's ref charset: alnum plus these separators. Anything else (whitespace, shell
        // metacharacters, control bytes) is not a ref — log it raw, never treat it as a name/host.
        if (preg_match('#^[A-Za-z0-9._:/@\-]+$#', $ref) !== 1) {
            return $invalid;
        }

        $digest = '';
        $name = $ref;
        $at = strpos($name, '@');
        if ($at !== false) {
            $digest = substr($name, $at + 1);
            $name = substr($name, 0, $at);
            // A digest must look like algo:hex; a malformed one makes the whole ref invalid.
            if (preg_match('#^[a-z0-9]+:[0-9a-fA-F]{16,}$#', $digest) !== 1) {
                return $invalid;
            }
        }
        if ($name === '') {
            return $invalid;
        }

        // Split off a registry (first segment iff it looks like a host[:port]).
        $registry = 'docker.io';
        $remainder = $name;
        $slash = strpos($name, '/');
        if ($slash !== false) {
            $first = substr($name, 0, $slash);
            if (strpos($first, '.') !== false || strpos($first, ':') !== false || $first === 'localhost') {
                $registry = $first;
                $remainder = substr($name, $slash + 1);
            }
        }

        // Split off a tag on the LAST path component only (so a registry:port is not mistaken for one).
        $tag = '';
        $lastSlash = strrpos($remainder, '/');
        $repoHead = $lastSlash === false ? '' : substr($remainder, 0, $lastSlash + 1);
        $repoTail = $lastSlash === false ? $remainder : substr($remainder, $lastSlash + 1);
        $colon = strpos($repoTail, ':');
        if ($colon !== false) {
            $tag = substr($repoTail, $colon + 1);
            $repoTail = substr($repoTail, 0, $colon);
        }
        $repo = $repoHead . $repoTail;
        if ($repo === '') {
            return $invalid;
        }

        // Docker Hub single-segment repos get the implicit `library/` namespace.
        if ($registry === 'docker.io' && strpos($repo, '/') === false) {
            $repo = 'library/' . $repo;
        }
        if ($tag === '' && $digest === '') {
            $tag = 'latest';
        }

        $canonical = $registry . '/' . $repo . ($tag !== '' ? ':' . $tag : '') . ($digest !== '' ? '@' . $digest : '');

        return [
            'registry' => $registry,
            'repo' => $repo,
            'tag' => $tag,
            'digest' => $digest,
            'canonical' => $canonical,
            'display' => self::display($ref, $registry, $repo, $tag, $digest),
            'valid' => true,
        ];
    }

    /** True when the ref's canonical form is one the fake daemon already holds (fleet tag or pulled). */
    public static function isLocal(string $ref, array $localCanonicals, array $pulledCanonicals): bool
    {
        $p = self::parse($ref);
        if (!$p['valid']) {
            return false;
        }

        return in_array($p['canonical'], $localCanonicals, true)
            || in_array($p['canonical'], $pulledCanonicals, true);
    }

    /**
     * The short, human form docker echoes back (e.g. `alpine:latest`, not the fully-qualified
     * `docker.io/library/alpine:latest`). Keeps the registry when it is not Docker Hub, and drops the
     * implicit `library/` namespace for Hub refs.
     */
    private static function display(string $ref, string $registry, string $repo, string $tag, string $digest): string
    {
        $shortRepo = $repo;
        if ($registry === 'docker.io' && strpos($repo, 'library/') === 0) {
            $shortRepo = substr($repo, strlen('library/'));
        }
        $prefix = $registry === 'docker.io' ? '' : $registry . '/';
        $out = $prefix . $shortRepo;
        if ($tag !== '') {
            $out .= ':' . $tag;
        }
        if ($digest !== '') {
            $out .= '@' . $digest;
        }

        return substr($out, 0, self::MAX_LEN);
    }
}
