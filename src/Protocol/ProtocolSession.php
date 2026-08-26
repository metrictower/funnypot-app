<?php

declare(strict_types=1);

namespace Funnypot\Protocol;

use Funnypot\Shell\Fs\Overlay;

/**
 * Per-connection state for the protocol engine: the inbound byte buffer, a request counter,
 * the per-attacker seed (so {{fake.*}} values are stable-but-distinct per source), and a
 * close flag the listener honours. All bounds are enforced against this by the emulator.
 */
final class ProtocolSession
{
    public string $buffer = '';
    public int $requests = 0;
    public bool $close = false;

    // Shell state (used only by protocols with a `shell` block): login -> password -> shell.
    public string $phase = 'login';
    public string $user = '';
    public string $cwd = '/root';
    public bool $authed = false;
    public int $authTries = 0;

    // Fake-filesystem shell state, carried across commands for this ONE connection (the emulator is
    // shared across connections, so this per-connection state must live here, not on the FakeShell).
    public ?Overlay $fsOverlay = null;
    public int $lastExit = 0;
    /** @var array<string,string> */
    public array $shellEnv = [];
    /** @var string[] */
    public array $shellHistory = [];
    /** The peer's IP, set by the listener, so `netstat`/`w` can show the attacker's own connection. */
    public string $peerIp = '';

    // Interactive line editing for the telnet-style shell: the in-progress line, and a flag to
    // swallow the LF of a CR-LF pair so one Enter is one line whether the client sends \r, \r\n or \n.
    public string $lineBuf = '';
    public bool $swallowLf = false;

    // Taunt mode: once logged in, the session streams the troll animation and ignores input.
    public bool $trolling = false;
    public int $trollFrame = 0;

    /** Malformed style: an OSC-52 clipboard value read back from the client, awaiting an intel log. */
    public ?string $clipboardCapture = null;

    public function __construct(public int $seed = 0)
    {
    }
}
