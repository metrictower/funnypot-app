<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * Opens identity/TLS source files by the {@see SourceOpenAttestation} rules. Every open starts from a
 * trusted, already-canonical anchor and walks the named components beneath it with lstat; a symlink
 * anywhere, a group/other-writable directory, an unexpected owner, a non-regular final or a link
 * count other than one fails closed with a stable code. Accepted owners are root and the effective
 * uid — never a literal 0 alone, so the same code runs as root in the container and unprivileged
 * everywhere else.
 */
final class SourceOpener
{
    /** Group/other WRITE forbidden (shared-readable trees such as identity-http and /etc). */
    public const MODE_NO_GO_WRITE = 0022;
    /** Any group/other access forbidden (the private persistent/runtime trees). */
    public const MODE_PRIVATE = 0077;

    private const S_IFMT = 0170000;
    private const S_IFDIR = 0040000;
    private const S_IFREG = 0100000;
    private const S_IFLNK = 0120000;

    public function __construct(private IdentityFileOps $ops)
    {
    }

    /** @return list<int> */
    public function acceptedOwners(): array
    {
        return array_values(array_unique([0, $this->ops->euid()]));
    }

    /**
     * Validate every directory component beneath $anchor and the final regular file, then open +
     * fstat + read + fstat. The anchor is a TRUSTED root (the operator's storage mount, `/`, the
     * parent of the runtime root) and is only required to be a directory: the legacy storage mount is
     * 0777 by design, so the owner/mode rules apply to the components beneath it, which this code (or
     * the operator, for an explicit source) created.
     *
     * @param list<string> $components path segments beneath the anchor; the last is the file
     * @param int          $dirModeMask forbidden mode bits on directories (MODE_PRIVATE|MODE_NO_GO_WRITE)
     * @param int          $fileModeMask forbidden mode bits on the final file
     */
    public function openDirect(string $anchor, array $components, string $code, int $maxBytes, int $dirModeMask, int $fileModeMask): OpenedSource
    {
        if ($components === []) {
            throw IdentityBootstrapException::withCode($code . '-path', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $ast = $this->ops->lstat($anchor === '' ? '/' : $anchor);
        if ($ast === false || ((int) $ast['mode'] & self::S_IFMT) !== self::S_IFDIR) {
            throw IdentityBootstrapException::withCode($code . '-missing', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $path = rtrim($anchor, '/');
        $last = count($components) - 1;
        foreach ($components as $i => $c) {
            if ($c === '' || $c === '.' || $c === '..' || str_contains($c, '/')) {
                throw IdentityBootstrapException::withCode($code . '-path', IdentityBootstrapException::REMEDY_STORAGE);
            }
            $path .= '/' . $c;
            if ($i < $last) {
                $this->requireDirectory($path, $code, $dirModeMask);
            }
        }

        return $this->openFinal($path, $code, $maxBytes, $fileModeMask, SourceOpenAttestation::DIRECT_NOFOLLOW);
    }

    /**
     * An operator-supplied absolute path (explicit TLS pair, explicit secret file): it must already be
     * canonical — `realpath()` returns it unchanged — so a symlinked operator path is refused rather
     * than resolved, and then every component from `/` down is validated by the direct rule.
     */
    public function openCanonicalPath(string $path, string $code, int $maxBytes, int $fileModeMask): OpenedSource
    {
        if ($path === '' || $path[0] !== '/' || $this->ops->realpath($path) !== $path) {
            throw IdentityBootstrapException::withCode($code . '-path', IdentityBootstrapException::REMEDY_CONFIG);
        }

        return $this->openDirect('/', explode('/', ltrim($path, '/')), $code, $maxBytes, self::MODE_NO_GO_WRITE, $fileModeMask);
    }

    /**
     * The sole symlink-following exception: certbot's live pair. Only the two final names may be
     * links, each to exactly `../../archive/<same domain>/<fullchain|privkey><same revision>.pem`;
     * everything else on both paths is validated as a real directory and the archive finals are
     * opened by the direct rule. Absolute, nested, cross-domain, mismatched-revision or otherwise
     * shaped targets fail.
     *
     * @return array{0:OpenedSource,1:OpenedSource} [fullchain, privkey]
     */
    public function openLetsEncryptPair(string $leRoot, string $domain, int $maxBytes): array
    {
        $code = 'tls-letsencrypt';
        $this->requireDirectory($leRoot, $code, self::MODE_NO_GO_WRITE);
        $live = rtrim($leRoot, '/') . '/live';
        $archive = rtrim($leRoot, '/') . '/archive';
        $this->requireDirectory($live, $code, self::MODE_NO_GO_WRITE);
        $this->requireDirectory($live . '/' . $domain, $code, self::MODE_NO_GO_WRITE);
        $this->requireDirectory($archive, $code, self::MODE_NO_GO_WRITE);
        $this->requireDirectory($archive . '/' . $domain, $code, self::MODE_NO_GO_WRITE);

        $revisions = [];
        $targets = [];
        foreach (['fullchain', 'privkey'] as $name) {
            $link = $live . '/' . $domain . '/' . $name . '.pem';
            $st = $this->ops->lstat($link);
            if ($st === false || ((int) $st['mode'] & self::S_IFMT) !== self::S_IFLNK) {
                throw IdentityBootstrapException::withCode($code . '-link-shape', IdentityBootstrapException::REMEDY_TLS);
            }
            $target = $this->ops->readlink($link);
            if (!is_string($target)
                || preg_match('#^\.\./\.\./archive/([^/]+)/(fullchain|privkey)([1-9][0-9]{0,8})\.pem$#', $target, $m) !== 1
                || $m[1] !== $domain
                || $m[2] !== $name) {
                throw IdentityBootstrapException::withCode($code . '-link-shape', IdentityBootstrapException::REMEDY_TLS);
            }
            $revisions[$name] = (int) $m[3];
            $targets[$name] = $name . $m[3] . '.pem';
        }
        if ($revisions['fullchain'] !== $revisions['privkey']) {
            throw IdentityBootstrapException::withCode($code . '-revision-mismatch', IdentityBootstrapException::REMEDY_TLS);
        }
        $out = [];
        foreach (['fullchain', 'privkey'] as $name) {
            $final = $archive . '/' . $domain . '/' . $targets[$name];
            // Archive certs are commonly 0644 and the key 0600; the reader rule is "no group/other
            // write", the same rule every other shared-readable source gets.
            $out[] = $this->openFinal($final, $code, $maxBytes, self::MODE_NO_GO_WRITE, SourceOpenAttestation::LETSENCRYPT_MANAGED_CHAIN);
        }

        return [$out[0], $out[1]];
    }

    /** A real directory (not a symlink) with an accepted owner and none of the forbidden mode bits. */
    public function requireDirectory(string $path, string $code, int $modeMask): void
    {
        $st = $this->ops->lstat($path);
        if ($st === false) {
            throw IdentityBootstrapException::withCode($code . '-missing', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $mode = (int) $st['mode'];
        if (($mode & self::S_IFMT) !== self::S_IFDIR
            || !in_array((int) $st['uid'], $this->acceptedOwners(), true)
            || ($mode & $modeMask) !== 0) {
            throw IdentityBootstrapException::withCode($code . '-component-unsafe', IdentityBootstrapException::REMEDY_STORAGE);
        }
    }

    private function openFinal(string $path, string $code, int $maxBytes, int $fileModeMask, string $attestationId): OpenedSource
    {
        $st = $this->ops->lstat($path);
        if ($st === false) {
            throw IdentityBootstrapException::withCode($code . '-missing', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $mode = (int) $st['mode'];
        if (($mode & self::S_IFMT) !== self::S_IFREG
            || !in_array((int) $st['uid'], $this->acceptedOwners(), true)
            || ($mode & $fileModeMask) !== 0) {
            throw IdentityBootstrapException::withCode($code . '-unsafe', IdentityBootstrapException::REMEDY_STORAGE);
        }
        if ((int) $st['nlink'] !== 1) {
            throw IdentityBootstrapException::withCode($code . '-link-count', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $attestation = SourceOpenAttestation::fromStat($attestationId, $st);

        $h = $this->ops->openRead($path);
        if ($h === false) {
            throw IdentityBootstrapException::withCode($code . '-open', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $fst = $this->ops->fstat($h);
        if ($fst === false || !$attestation->matches($fst)) {
            $this->ops->close($h);
            throw IdentityBootstrapException::withCode($code . '-changed', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $bytes = $this->ops->readAll($h, $maxBytes + 1);
        if ($bytes === false || strlen($bytes) > $maxBytes) {
            $this->ops->close($h);
            throw IdentityBootstrapException::withCode($code . '-read', IdentityBootstrapException::REMEDY_STORAGE);
        }
        $fst2 = $this->ops->fstat($h);
        if ($fst2 === false || !$attestation->matches($fst2) || (int) $fst2['size'] !== strlen($bytes)) {
            $this->ops->close($h);
            throw IdentityBootstrapException::withCode($code . '-changed', IdentityBootstrapException::REMEDY_STORAGE);
        }

        return new OpenedSource($h, $bytes, $attestation);
    }
}
