<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

final class SandboxPaths
{
    public const ROOT_ENV = 'FUNNYPOT_SANDBOX_ROOT';
    public const PRODUCTION_ROOT = '/run/funnypot-sandbox';
    public const LOCK_FILE = '.publication.lock';
    public const EPHEMERAL_DIR = '.ephemeral';
    public const GENERATIONS_DIR = 'generations';
    public const CURRENT_FILE = 'current.json';
    public const PREVIOUS_FILE = 'previous.json';
    public const PROJECTION_FILE = 'projection.json';
    public const MANIFEST_FILE = 'manifest.json';

    private function __construct(private string $root)
    {
    }

    /** Constructor-style injection for trusted in-process tests. */
    public static function forRoot(string $root): self
    {
        return new self(self::validAbsolute($root));
    }

    /** The override is validate-only; the production default is create-or-validated by prepareRoot(). */
    public static function fromEnvironment(?callable $env = null, ?SandboxFileOps $ops = null): self
    {
        $env ??= static fn (string $key) => getenv($key);
        $ops ??= new SandboxFileOps();
        $override = $env(self::ROOT_ENV);
        $path = is_string($override) && $override !== '' ? self::validAbsolute($override) : self::PRODUCTION_ROOT;
        if (is_string($override) && $override !== '') {
            self::validateRoot($path, $ops);
        }

        return new self($path);
    }

    public function prepareRoot(SandboxFileOps $ops): void
    {
        $st = $ops->lstat($this->root);
        if ($st === false) {
            if ($this->root !== self::PRODUCTION_ROOT) {
                throw new SandboxProjectionException('sandbox-root-invalid');
            }
            $ops->mkdir($this->root, 0700);
        }
        self::validateRoot($this->root, $ops);
        foreach ([$this->generations(), $this->ephemeral()] as $dir) {
            $st = $ops->lstat($dir);
            if ($st === false) { $ops->mkdir($dir, 0700); }
            self::validateDirectory($dir, $ops, 0700);
        }
    }

    /** Read-only boundary validation for status/startup consumers; creates no object. */
    public function validateExisting(SandboxFileOps $ops): bool
    {
        if ($ops->lstat($this->root) === false) { return false; }
        self::validateRoot($this->root, $ops);
        self::validateDirectory($this->generations(), $ops, 0700);
        return true;
    }

    private static function validAbsolute(string $path): string
    {
        $path = rtrim($path, '/');
        if ($path === '' || $path[0] !== '/' || in_array('..', explode('/', $path), true)) {
            throw new SandboxProjectionException('sandbox-root-invalid');
        }

        return $path;
    }

    private static function validateRoot(string $root, SandboxFileOps $ops): void
    {
        self::validateDirectory($root, $ops, 0700);
    }

    private static function validateDirectory(string $path, SandboxFileOps $ops, int $mode): void
    {
        $st = $ops->lstat($path);
        if (!is_array($st) || (((int) $st['mode']) & 0170000) !== 0040000 || (int) $st['uid'] !== $ops->euid()
            || (((int) $st['mode']) & 0777) !== $mode) {
            throw new SandboxProjectionException('sandbox-root-invalid');
        }
    }

    public function root(): string { return $this->root; }
    public function lock(): string { return $this->root . '/' . self::LOCK_FILE; }
    public function ephemeral(): string { return $this->root . '/' . self::EPHEMERAL_DIR; }
    public function generations(): string { return $this->root . '/' . self::GENERATIONS_DIR; }
    public function current(): string { return $this->root . '/' . self::CURRENT_FILE; }
    public function previous(): string { return $this->root . '/' . self::PREVIOUS_FILE; }
    public function candidate(string $id): string { return $this->generations() . '/.candidate-' . self::id($id); }
    public function generation(string $id): string { return $this->generations() . '/' . self::id($id); }
    public function projection(string $id): string { return $this->generation($id) . '/' . self::PROJECTION_FILE; }
    public function manifest(string $id): string { return $this->generation($id) . '/' . self::MANIFEST_FILE; }

    private static function id(string $id): string
    {
        if (preg_match('/^[0-9a-f]{32}$/', $id) !== 1) {
            throw new SandboxProjectionException('generation-id-invalid');
        }

        return $id;
    }
}
