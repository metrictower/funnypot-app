<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Vnc;

/**
 * Tracks the RFB 3.8 protocol state, buffers, negotiated encodings, and timers
 * for one active VNC connection.
 */
final class VncSession
{
    public const STATE_WAIT_VERSION = 0;
    public const STATE_WAIT_SECURITY = 1;
    public const STATE_WAIT_CLIENT_INIT = 2;
    public const STATE_ACTIVE = 3;

    public int $state = self::STATE_WAIT_VERSION;
    public string $inbuf = '';
    public string $outbuf = '';

    public string $clientVersion = '';
    public bool $isRfb38 = true;
    public int $securityType = 1; // 1 = None
    public int $sharedFlag = 1;

    /** @var int[] Encodings requested by the client via SetEncodings */
    public array $encodings = [];
    public bool $supportsCursor = false;
    public bool $supportsDesktopSize = false;
    public bool $supportsExtendedDesktopSize = false;

    public bool $sentFirstUpdate = false;
    public bool $sentCursor = false;
    public bool $sentChaosResize = false;
    public bool $taunting = false;

    // Recon telemetry: log the first framebuffer request once (proves the bot saw the screen).
    public bool $loggedFbRequest = false;

    // Two-phase taunt: a click shows a fake "Reverse VNC connection?" dialog first; the real
    // storm (resize/animation/beeps) only starts after tauntPopupSec.
    public bool $clicked = false;
    public bool $popupShown = false;
    public float $clickTime = 0.0;

    // Dodging popup: -1 means "not placed yet" (centre on first paint). The dialog jumps away
    // when the pointer approaches so it can never be clicked.
    public int $popupX = -1;
    public int $popupY = -1;
    public float $lastPopupMoveTime = 0.0;

    // Malformed farewell: a burst of invalid RFB sent once, just before the taunt drops the client.
    public bool $sentFarewell = false;

    public float $connectTime;
    public float $lastBeepTime = 0.0;
    public float $lastClipboardTime = 0.0;
    public float $lastAnimationTime = 0.0;
    public float $tauntStartTime = 0.0;
    public int $animationFrame = 0;
    public int $lastActiveTime;

    public ?string $cachedFramebuffer = null;
    public bool $close = false;

    public function __construct(
        public readonly string $ip,
        public readonly int $port,
        public readonly int $id
    ) {
        $this->connectTime = microtime(true);
        $this->lastActiveTime = time();
    }
}
