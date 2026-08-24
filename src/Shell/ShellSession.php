<?php

declare(strict_types=1);

namespace Funnypot\Shell;

use Funnypot\Shell\Fs\Overlay;

/**
 * Mutable per-connection shell state the interpreter reads and writes: identity, cwd, environment,
 * typed-command history, last exit status, the session filesystem overlay, and the peer address (so
 * `netstat` can show the attacker's own connection). Transport-agnostic — the SSH/telnet adapter and
 * the web terminal each build one of these; the interpreter never touches a socket.
 */
final class ShellSession
{
    /** @var string[] commands typed this session, for `history` */
    public array $history = [];
    public int $lastExit = 0;
    public bool $close = false;
    public Overlay $overlay;

    /** @param array<string,string> $env */
    public function __construct(
        public string $host,
        public string $user = 'root',
        public int $uid = 0,
        public int $gid = 0,
        public string $cwd = '/root',
        public string $peerIp = '10.0.0.5',
        public array $env = []
    ) {
        $this->overlay = new Overlay();
        if ($this->env === []) {
            $this->env = [
                'USER' => $this->user,
                'HOME' => $this->user === 'root' ? '/root' : '/home/' . $this->user,
                'SHELL' => '/bin/bash',
                'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'PWD' => $this->cwd,
                'TERM' => 'xterm-256color',
                'LANG' => 'en_US.UTF-8',
            ];
        }
    }

    public function isRoot(): bool
    {
        return $this->uid === 0;
    }
}
