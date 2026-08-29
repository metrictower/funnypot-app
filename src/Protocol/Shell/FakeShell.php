<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Shell;

use Funnypot\Protocol\ProtocolSession;
use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Host\HostFacts;
use Funnypot\Shell\ShellInterpreter;
use Funnypot\Shell\ShellSession;

/**
 * Telnet/SSH adapter over the shared, procedurally-generated fake shell (ShellInterpreter +
 * FakeFilesystem + HostFacts). Preserves the run($line, ProtocolSession) contract the listeners use:
 * builds a ShellSession from the connection's ProtocolSession, runs the interpreter, carries the
 * overlay/cwd/history/exit-status back onto the session (this adapter is shared across connections, so
 * per-connection state lives on the session), and converts \n -> \r\n bounded for the wire. It is a
 * lookup/dispatch layer, never an interpreter of attacker code: no exec/eval, no real filesystem, no
 * outbound socket — wget/curl return canned text and the URL is only logged by the listener.
 */
final class FakeShell
{
    private const MAX_OUTPUT = 8192;

    private ShellInterpreter $interp;
    private HostFacts $facts;

    public function __construct(?int $identitySeed = null, ?string $secret = null, string $role = 'ops')
    {
        $seed = $identitySeed ?? 0;
        $hostSeedBytes = Draw::seed(($secret ?? '') . "\0" . $seed . "\0" . $role);
        $this->facts = new HostFacts($seed);
        $this->interp = new ShellInterpreter(
            new FakeFilesystem($hostSeedBytes, $role, $seed),
            $this->facts,
            self::MAX_OUTPUT
        );
    }

    /** The shell host identity — the prompt uses this so it matches uname / hostname / /etc/hostname. */
    public function host(): string
    {
        return $this->facts->hostname();
    }

    /**
     * Run one line. $interactive is the terminal/PTY path (telnet, `ssh host` with a pty), where a
     * real tty maps every \n to \r\n; a non-PTY exec (`ssh host cmd`) writes raw \n, so callers on
     * that path pass false. Converting there would be a tell — real openssh exec never CRLF-cooks.
     */
    public function run(string $line, ProtocolSession $s, bool $interactive = true): string
    {
        $user = $s->user !== '' ? $s->user : 'root';
        $uid = $user === 'root' ? 0 : 1000;
        $ss = new ShellSession(
            $this->facts->hostname(),
            $user,
            $uid,
            $uid,
            $s->cwd !== '' ? $s->cwd : '/root',
            $s->peerIp !== '' ? $s->peerIp : '10.0.0.1'
        );
        // carry this connection's accumulated shell state in
        if ($s->fsOverlay !== null) {
            $ss->overlay = $s->fsOverlay;
        }
        if ($s->shellEnv !== []) {
            $ss->env = $s->shellEnv;
        }
        $ss->history = $s->shellHistory;
        $ss->lastExit = $s->lastExit;

        $out = $this->interp->run($line, $ss);

        // carry it back out onto the session for the next command
        $s->cwd = $ss->cwd;
        $s->fsOverlay = $ss->overlay;
        $s->shellEnv = $ss->env;
        $s->shellHistory = $ss->history;
        $s->lastExit = $ss->lastExit;
        if ($ss->close) {
            $s->close = true;
        }

        if ($interactive) {
            $out = str_replace("\n", "\r\n", $out);
        }

        return strlen($out) > self::MAX_OUTPUT ? substr($out, 0, self::MAX_OUTPUT) : $out;
    }
}
