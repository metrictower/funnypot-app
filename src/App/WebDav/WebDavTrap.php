<?php

declare(strict_types=1);

namespace Funnypot\App\WebDav;

use Funnypot\App\Storage\WriteCaptureStore;
use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Shell\Fs\FakeFilesystem;
use Throwable;

/**
 * FP-0200 (core slice): an RFC-4918-shaped WebDAV honeypot mounted at /webdav/. A client or scanner can
 * OPTIONS it (advertises DAV: 1,2), PROPFIND to browse (a canned root + the source's own dropped files),
 * PUT to drop a file, GET it back, DELETE/MKCOL. It reuses the FP-0467 WriteCaptureStore for writes (body
 * captured to the bounded ledger, never raw disk) and the shared multistatus builder for listings, so it
 * never creates a second upload store. Subsequent webshell execution against a dropped .php is served by
 * the FP-0149 exec-failure path on the normal GET surface.
 *
 * SCOPE (core slice): OPTIONS/PROPFIND/PUT/GET/HEAD/DELETE/MKCOL. LOCK/UNLOCK/MOVE/COPY return a minimal
 * 200/201 so a client does not hard-fail, but full lock/move/copy semantics are a focused follow-up. INERT:
 * nothing executes, the body-drop is bounded + fail-open, the source scope is opaque (no raw IP). Only the
 * /webdav/ mount is claimed; any other path returns null so the normal pipeline is unaffected.
 */
final class WebDavTrap
{
    private const MOUNT = '/webdav';

    public function __construct(private WriteCaptureStore $store, private ?FakeFilesystem $fs = null)
    {
    }

    public function scopeFor(string $clientIp): string
    {
        // Same scope formula as WriteCaptureTrap so a WebDAV-dropped file and an HTTP-dropped file share
        // one capture ledger for this source.
        return hash('sha256', 'fp0467|' . $clientIp);
    }

    public function claims(RequestContext $context): bool
    {
        $p = '/' . ltrim($context->path, '/');

        return $p === self::MOUNT || strncmp($p, self::MOUNT . '/', strlen(self::MOUNT) + 1) === 0;
    }

    public function handle(RequestContext $context, string $clientIp): ?SynthesizedResponse
    {
        if (!$this->claims($context)) {
            return null;
        }
        $scope = $this->scopeFor($clientIp);
        $path = $this->canon($context->path);

        switch (strtoupper($context->method)) {
            case 'OPTIONS':
                return $this->options();
            case 'PROPFIND':
                return $this->propfind($context, $scope, $path);
            case 'PUT':
                return $this->put($context, $scope, $path);
            case 'GET':
            case 'HEAD':
                return $this->get($context, $scope, $path, strtoupper($context->method) === 'HEAD');
            case 'DELETE':
                return $this->simple(204, '');
            case 'MKCOL':
                return $this->simple(201, '');
            case 'LOCK':
                return $this->lock($path);
            case 'UNLOCK':
                return $this->simple(204, '');
            case 'MOVE':
                return $this->move($context, $scope, $path, true);
            case 'COPY':
                return $this->move($context, $scope, $path, false);
            case 'PROPPATCH':
                return $this->proppatch($path);
            default:
                return null; // let the normal pipeline answer non-WebDAV verbs
        }
    }

    private function options(): SynthesizedResponse
    {
        return new SynthesizedResponse(200, [
            'Allow' => 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY, LOCK, UNLOCK',
            'DAV' => '1, 2',
            'MS-Author-Via' => 'DAV',
            'Content-Length' => '0',
        ], '', Detection::none());
    }

    private function propfind(RequestContext $context, string $scope, string $path): SynthesizedResponse
    {
        $depth = strtolower(trim((string) ($context->headers['Depth'] ?? '1')));
        $resources = [];
        // the requested collection itself
        $resources[] = $this->dir($path === '' ? self::MOUNT . '/' : $this->hrefDir($path));
        if ($depth !== '0') {
            // Children of the requested path in the deterministic fake filesystem (/webdav maps to the FS
            // root), so a mounted share shows a plausible, consistent Linux tree.
            foreach ($this->fsChildren($path) as $r) {
                $resources[] = $r;
            }
            // the source's own dropped files (so a PUT then PROPFIND shows it)
            foreach ($this->store->listForScope($scope) as $f) {
                if (strncmp($f['path'], self::MOUNT . '/', strlen(self::MOUNT) + 1) === 0
                    && $this->canon(dirname($f['path'])) === ($path === '' ? self::MOUNT : $path)) {
                    $resources[] = $this->file($f['path'], $f['size'], $f['content_type'], $f['captured_at']);
                }
            }
        }

        return new SynthesizedResponse(207, ['Content-Type' => 'application/xml; charset=utf-8'],
            WebDavMultistatus::build($resources), Detection::none());
    }

    /**
     * Fake-FS children of a WebDAV path, as multistatus descriptors. /webdav -> FS "/". Fail-closed to a
     * small canned root when there is no FS or the path isn't a directory.
     *
     * @return list<array{href:string,collection:bool,size:int,contentType:string,mtime:int,displayname:string}>
     */
    private function fsChildren(string $davPath): array
    {
        if ($this->fs === null) {
            // canned fallback (no FS wired)
            return [
                $this->dir(self::MOUNT . '/backup/'),
                $this->file(self::MOUNT . '/readme.txt', 128, 'text/plain', 1_700_000_000),
            ];
        }
        $fsPath = $this->fsPathFor($davPath);
        try {
            $nodes = $this->fs->list($fsPath);
        } catch (Throwable $e) {
            return [];
        }
        $base = $davPath === '' ? self::MOUNT : $davPath;
        $out = [];
        foreach ($nodes as $node) {
            $href = $base . '/' . $node->name;
            if ($node->isDir()) {
                $out[] = $this->dir($href . '/');
            } else {
                $out[] = $this->file($href, $node->size, $this->typeFor($node->name), $node->mtime);
            }
        }

        return $out;
    }

    /** /webdav -> "/", /webdav/etc -> "/etc". */
    private function fsPathFor(string $davPath): string
    {
        $rest = substr($this->canon($davPath), strlen(self::MOUNT));

        return $rest === '' ? '/' : $rest;
    }

    private function put(RequestContext $context, string $scope, string $path): SynthesizedResponse
    {
        $body = (string) ($context->rawBody ?? '');
        $this->store->capture($scope, $path, $body, $this->typeFor($path));

        return $this->simple(201, '');
    }

    private function get(RequestContext $context, string $scope, string $path, bool $head): SynthesizedResponse
    {
        // A dropped file for this source wins (freshest); else fall back to the deterministic fake FS.
        $hit = $this->store->verify($scope, $path);
        if ($hit !== null) {
            return new SynthesizedResponse(200, ['Content-Type' => $hit['content_type']],
                $head ? '' : $hit['content'], Detection::none());
        }
        if ($this->fs !== null) {
            try {
                $body = $this->fs->read($this->fsPathFor($path));

                return new SynthesizedResponse(200, ['Content-Type' => $this->typeFor($path)],
                    $head ? '' : $body, Detection::none());
            } catch (Throwable $e) {
                // not a readable file in the fake FS -> 404 below
            }
        }

        return $this->simple(404, "Not Found\n");
    }

    private function lock(string $path): SynthesizedResponse
    {
        $token = 'opaquelocktoken:' . bin2hex(random_bytes(16));
        $xml = '<?xml version="1.0" encoding="utf-8"?>' . "\n"
            . '<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>'
            . '<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>'
            . '<D:depth>0</D:depth><D:timeout>Second-3600</D:timeout>'
            . '<D:locktoken><D:href>' . htmlspecialchars($token, ENT_XML1, 'UTF-8') . '</D:href></D:locktoken>'
            . '</D:activelock></D:lockdiscovery></D:prop>';

        return new SynthesizedResponse(200, [
            'Content-Type' => 'application/xml; charset=utf-8',
            'Lock-Token' => '<' . $token . '>',
        ], $xml, Detection::none());
    }

    /** MOVE (deleteSrc=true) / COPY (false) a captured file to the Destination, operating on the store. */
    private function move(RequestContext $context, string $scope, string $src, bool $deleteSrc): SynthesizedResponse
    {
        $dest = $this->destPath($context);
        if ($dest === null) {
            return $this->simple(400, "Bad Request\n");
        }
        $hit = $this->store->verify($scope, $src);
        if ($hit === null) {
            return $this->simple(404, "Not Found\n");
        }
        $existed = $this->store->verify($scope, $dest) !== null;
        $this->store->capture($scope, $dest, $hit['content'], $hit['content_type']);
        if ($deleteSrc) {
            $this->store->remove($scope, $src);
        }

        return $this->simple($existed ? 204 : 201, '');
    }

    /** PROPPATCH: pretend every requested property was set (207, all 200 OK). */
    private function proppatch(string $path): SynthesizedResponse
    {
        $href = htmlspecialchars($path, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $xml = '<?xml version="1.0" encoding="utf-8"?>' . "\n"
            . '<D:multistatus xmlns:D="DAV:"><D:response><D:href>' . $href . '</D:href>'
            . '<D:propstat><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>' . "\n";

        return new SynthesizedResponse(207, ['Content-Type' => 'application/xml; charset=utf-8'], $xml, Detection::none());
    }

    /** The WebDAV Destination header as a canonical path (scheme/host stripped), or null if absent/invalid. */
    private function destPath(RequestContext $context): ?string
    {
        $d = trim((string) ($context->headers['Destination'] ?? ''));
        if ($d === '') {
            return null;
        }
        $d = (string) preg_replace('~^[a-z][a-z0-9+.\-]*://[^/]+~i', '', $d);
        $d = rawurldecode($d);
        if ($d === '' || $d[0] !== '/') {
            return null;
        }
        $p = $this->canon($d);

        return $this->claimsPath($p) ? $p : null;
    }

    private function claimsPath(string $p): bool
    {
        return $p === self::MOUNT || strncmp($p, self::MOUNT . '/', strlen(self::MOUNT) + 1) === 0;
    }

    private function simple(int $status, string $body): SynthesizedResponse
    {
        return new SynthesizedResponse($status, ['Content-Type' => 'text/plain; charset=utf-8'], $body, Detection::none());
    }

    /** @return array{href:string,collection:bool,size:int,contentType:string,mtime:int,displayname:string} */
    private function dir(string $href): array
    {
        $name = trim(basename(rtrim($href, '/'))) ?: 'webdav';

        return ['href' => $href, 'collection' => true, 'size' => 0, 'contentType' => '', 'mtime' => 1_700_000_000, 'displayname' => $name];
    }

    /** @return array{href:string,collection:bool,size:int,contentType:string,mtime:int,displayname:string} */
    private function file(string $href, int $size, string $type, int $mtime): array
    {
        return ['href' => $href, 'collection' => false, 'size' => $size, 'contentType' => $type ?: 'application/octet-stream', 'mtime' => $mtime, 'displayname' => basename($href)];
    }

    private function hrefDir(string $path): string
    {
        return rtrim($path, '/') . '/';
    }

    private function canon(string $path): string
    {
        $out = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($out);
                continue;
            }
            $out[] = $seg;
        }

        return '/' . implode('/', $out);
    }

    private function typeFor(string $path): string
    {
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        $map = ['txt' => 'text/plain', 'html' => 'text/html', 'htm' => 'text/html', 'php' => 'text/html',
            'xml' => 'text/xml', 'json' => 'application/json', 'js' => 'application/javascript', 'css' => 'text/css'];

        return ($map[$ext] ?? 'application/octet-stream') . (isset($map[$ext]) ? '; charset=utf-8' : '');
    }
}
