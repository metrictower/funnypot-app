<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The child-side reader of ONE scoped runtime bundle. A web worker or listener validates only its
 * own self-contained bundle — the runtime root, its parent directory and the file, by the direct
 * no-follow rule with the reader ownership rule (owner root or the effective uid, no group/other
 * write) — and never opens the persistent manifest or another process's bundle. The envelope is
 * checked for schema and bundle name; the typed DTO then checks the payload shape.
 */
final class IdentityBundleReader
{
    public const SCHEMA = 'funnypot-identity-bundle/v1';
    public const MAX_BYTES = 65536;

    private IdentityFileOps $ops;

    public function __construct(private IdentityPaths $paths, ?IdentityFileOps $ops = null)
    {
        $this->ops = $ops ?? new IdentityFileOps();
    }

    /**
     * @return array{envelope:array<string,mixed>,payload:array<string,mixed>}
     */
    public function read(string $bundle): array
    {
        [$dir, $file] = match ($bundle) {
            HttpIdentity::BUNDLE => ['identity-http', IdentityPaths::HTTP_BUNDLE],
            ShellIdentity::BUNDLE => ['identity-private', IdentityPaths::SHELL_BUNDLE],
            SipIdentity::BUNDLE => ['identity-private', IdentityPaths::SIP_BUNDLE],
            RedisIdentity::BUNDLE => ['identity-private', IdentityPaths::REDIS_BUNDLE],
            PostExploitIdentity::BUNDLE => ['identity-private', IdentityPaths::POST_EXPLOIT_BUNDLE],
            default => throw IdentityBootstrapException::withCode('bundle-unknown', IdentityBootstrapException::REMEDY_RUNTIME),
        };
        $root = $this->paths->runtimeRoot();
        $opener = new SourceOpener($this->ops);
        $src = $opener->openDirect(
            dirname($root),
            [basename($root), $dir, $file],
            'bundle',
            self::MAX_BYTES,
            SourceOpener::MODE_NO_GO_WRITE,
            SourceOpener::MODE_NO_GO_WRITE,
        );
        $this->ops->close($src->handle);

        return self::decode($src->bytes, $bundle);
    }

    /**
     * Parse + envelope-check bundle bytes. Shared with the producer's root-read/compare pass.
     *
     * @return array{envelope:array<string,mixed>,payload:array<string,mixed>}
     */
    public static function decode(string $bytes, string $bundle): array
    {
        $doc = json_decode($bytes, true, 8);
        if (!is_array($doc) || !is_array($doc['envelope'] ?? null) || !is_array($doc['payload'] ?? null)) {
            throw IdentityBootstrapException::withCode('bundle-malformed', IdentityBootstrapException::REMEDY_RUNTIME);
        }
        $env = $doc['envelope'];
        foreach (['schema', 'bundle', 'source', 'public_persona_hash', 'keyset_commitment'] as $k) {
            if (!is_string($env[$k] ?? null) || $env[$k] === '') {
                throw IdentityBootstrapException::withCode('bundle-envelope-malformed', IdentityBootstrapException::REMEDY_RUNTIME);
            }
        }
        if ($env['schema'] !== self::SCHEMA) {
            throw IdentityBootstrapException::withCode('bundle-schema', IdentityBootstrapException::REMEDY_RUNTIME);
        }
        if ($env['bundle'] !== $bundle) {
            throw IdentityBootstrapException::withCode('bundle-name', IdentityBootstrapException::REMEDY_RUNTIME);
        }

        return ['envelope' => $env, 'payload' => $doc['payload']];
    }

    /**
     * Require exactly $keys (no more, no fewer) as non-empty strings.
     *
     * @param array<string,mixed> $payload
     * @param list<string>        $keys
     * @return array<string,string>
     */
    public static function requireExactly(array $payload, array $keys): array
    {
        $have = array_keys($payload);
        sort($have);
        $want = $keys;
        sort($want);
        if ($have !== $want) {
            throw IdentityBootstrapException::withCode('bundle-payload-malformed', IdentityBootstrapException::REMEDY_RUNTIME);
        }
        $out = [];
        foreach ($keys as $k) {
            if (!is_string($payload[$k]) || $payload[$k] === '') {
                throw IdentityBootstrapException::withCode('bundle-payload-malformed', IdentityBootstrapException::REMEDY_RUNTIME);
            }
            $out[$k] = $payload[$k];
        }

        return $out;
    }
}
