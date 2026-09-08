<?php

declare(strict_types=1);

namespace Funnypot\Tests\Fixtures;

use Funnypot\App\Sandbox\Projection\SandboxFileOps;

final class SandboxPublisherFixtureOps extends SandboxFileOps
{
    private bool $held = false;

    public function __construct(private int $holdMs = 0, private string $marker = '', private string $crash = '')
    {
    }

    public function flock($h, int $op): bool
    {
        $ok = parent::flock($h, $op);
        if ($ok && !$this->held && ($op & LOCK_EX) === LOCK_EX) {
            $this->held = true;
            if ($this->marker !== '') { file_put_contents($this->marker, "held\n"); }
            if ($this->holdMs > 0) { usleep($this->holdMs * 1000); }
        }
        return $ok;
    }

    public function rename(string $from, string $to): bool
    {
        $candidate = str_contains($from, '/.candidate-');
        $current = str_ends_with($to, '/current.json');
        if ($candidate && $this->crash === 'before-candidate-rename') { exit(75); }
        $ok = parent::rename($from, $to);
        if ($ok && $candidate && $this->crash === 'after-candidate-rename') { exit(75); }
        if ($ok && $current && $this->crash === 'after-current-rename') { exit(75); }
        return $ok;
    }
}
