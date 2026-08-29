<?php

declare(strict_types=1);

namespace Funnypot\Protocol\Vnc;

/**
 * Zero-dependency, single-process TCP server for the visual VNC honeypot.
 * Speaks RFB 3.8 in pure PHP using a non-blocking stream_select event loop.
 *
 * Implements:
 * - Visual deception themes (FBI warning with dynamic IP stamp, Windows 95 BSOD, TempleOS, custom images)
 * - Clipboard hijacking (ServerCutText, message type 3)
 * - Periodic system beeps (Bell, message type 2)
 * - Troll face mouse cursor (Cursor pseudo-encoding -239)
 * - Massive resolution manipulation / window thrashing (DesktopSize -223, ExtendedDesktopSize -308
 *   with a fake multi-monitor layout), then a bounded-duration drop of the connection
 * - Telemetry capture: logs keystrokes (KeyEvent), mouse clicks (PointerEvent), and client cut text
 */
final class VncServer
{
    private const MAX_CONNS = 128;
    private const PER_IP_CONNS = 10;
    private const READ_CHUNK = 8192;
    private const TICK_INTERVAL_US = 200000; // 200ms tick for smooth beeps and timers

    // Legacy DesktopSize pseudo-encoding: resizes the client window to a single new size.
    public const ENC_DESKTOP_SIZE = -223;

    // Backpressure: a client that stops draining (e.g. a resize-bombed viewer) would otherwise let
    // outbuf grow until the PHP memory limit kills the listener. Drop it past the hard cap; the
    // soft cap gates the (rate-limited) popup repaints. Keeps the process alive under 128M.
    private const OUTBUF_SOFT_CAP = 6291456;  // 6 MiB
    private const OUTBUF_HARD_CAP = 25165824; // 24 MiB — client is not reading; disconnect

    private VncThemeRenderer $renderer;

    /**
     * @param callable(array<string,mixed>):void $logger
     */
    public function __construct(
        private VncConfig $config,
        private $logger
    ) {
        $this->renderer = new VncThemeRenderer($this->config);
    }

    /**
     * Bind and serve forever on the given address (e.g. "0.0.0.0:5900").
     */
    public function run(string $bind): void
    {
        $server = @stream_socket_server("tcp://{$bind}", $errno, $errstr);
        if ($server === false) {
            fwrite(STDERR, "funnypot-vnc: cannot bind {$bind}: {$errstr}\n");

            return;
        }
        stream_set_blocking($server, false);
        $port = self::portOf($bind);
        fwrite(STDERR, "funnypot-vnc ({$this->config->style}) listening on {$bind}\n");

        /** @var array<int,array{sock:resource,session:VncSession,ip:string}> $conns */
        $conns = [];
        $perIp = [];

        while (true) {
            $read = [$server];
            $write = [];
            foreach ($conns as $c) {
                $read[] = $c['sock'];
                if ($c['session']->outbuf !== '') {
                    $write[] = $c['sock'];
                }
            }
            $except = [];

            if (@stream_select($read, $write, $except, 0, self::TICK_INTERVAL_US) === false) {
                continue;
            }

            $now = time();
            $nowFloat = microtime(true);

            // Accept new connections
            foreach ($read as $r) {
                if ($r === $server) {
                    $this->accept($server, $conns, $perIp, $port, $now);
                    continue;
                }

                $id = get_resource_id($r);
                if (!isset($conns[$id])) {
                    continue;
                }

                $session = $conns[$id]['session'];
                $data = @fread($r, self::READ_CHUNK);

                if ($data === false || ($data === '' && feof($r))) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                if ($data === '') {
                    continue;
                }

                $session->lastActiveTime = $now;
                $session->inbuf .= $data;

                // Protect against inbound buffer exhaustion
                if (strlen($session->inbuf) > 65536) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                $this->processInbound($session);
                if ($session->close) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
            }

            // Flush outbound buffers
            foreach ($write as $w) {
                $id = get_resource_id($w);
                if (!isset($conns[$id])) {
                    continue;
                }
                $session = $conns[$id]['session'];
                if ($session->outbuf === '') {
                    continue;
                }

                $written = @fwrite($w, $session->outbuf);
                if ($written === false) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }
                $session->outbuf = substr($session->outbuf, $written);
            }

            // Periodic timers: system beeps and clipboard refresh
            foreach ($conns as $id => $c) {
                $session = $c['session'];
                if ($session->state !== VncSession::STATE_ACTIVE) {
                    continue;
                }

                // Periodic system beep (Bell) — in taunt mode, only beep once clicked/taunting!
                $shouldBeep = ($this->config->style === 'taunt') ? $session->taunting : $this->config->beep;
                if ($shouldBeep && $this->config->beep && ($nowFloat - $session->lastBeepTime >= $this->config->beepInterval)) {
                    $session->outbuf .= "\x02"; // Bell message
                    $session->lastBeepTime = $nowFloat;
                }

                // Periodic clipboard injection
                if ($this->config->clipboardInterval > 0 && ($nowFloat - $session->lastClipboardTime >= $this->config->clipboardInterval)) {
                    $session->outbuf .= self::buildServerCutText($this->renderClipboardText($session));
                    $session->lastClipboardTime = $nowFloat;
                }

                // A client that stopped reading during the strobe storm must not buffer forever —
                // that is what exhausted the PHP memory limit and killed the listener. Drop it.
                if ($this->outbufOverflowed($session)) {
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Two-phase taunt: the click showed the popup; start the slideshow after the delay.
                $this->maybeBeginTauntStorm($session, $nowFloat);

                // Taunt slideshow: advance through the scripted frames on their timers. When the last
                // frame's time is up, spray the malformed farewell and drop the connection.
                if ($this->advanceTauntSlideshow($session, $nowFloat) === 'finished') {
                    // Parting shot: spray invalid RFB, best-effort flushed straight to the socket
                    // (close() would otherwise discard the queued outbuf), then drop the client.
                    if ($this->config->malformedExit && !$session->sentFarewell) {
                        $session->sentFarewell = true;
                        @fwrite($c['sock'], $session->outbuf . self::buildGarbageFarewell());
                        $session->outbuf = '';
                    }
                    $this->logEvent([
                        'proto' => 'vnc',
                        'event' => 'taunt_disconnect',
                        'ip' => $session->ip,
                        'port' => $session->port,
                        'path' => 'VNC taunt slideshow finished - dropping connection',
                    ]);
                    $this->close($conns, $perIp, $id);
                    continue;
                }

                // Idle timeout: keep a silently-lurking client (watching to see if the box is in use)
                // connected for the full VNC-specific window before dropping it.
                if ($now - $session->lastActiveTime > $this->config->idleTimeoutSec) {
                    $this->close($conns, $perIp, $id);
                }
            }
        }
    }

    private function accept($server, array &$conns, array &$perIp, int $port, int $now): void
    {
        $sock = @stream_socket_accept($server, 0);
        if ($sock === false) {
            return;
        }
        stream_set_blocking($sock, false);

        $name = (string) @stream_socket_get_name($sock, true);
        $ip = ($colon = strrpos($name, ':')) !== false ? substr($name, 0, $colon) : $name;
        $clientPort = ($colon !== false) ? (int) substr($name, $colon + 1) : 0;

        if (count($conns) >= self::MAX_CONNS || ($perIp[$ip] ?? 0) >= self::PER_IP_CONNS) {
            @fclose($sock);

            return;
        }

        $id = get_resource_id($sock);
        $session = new VncSession($ip, $clientPort, $id);

        // RFB 3.8 Step 1: Server sends protocol version greeting immediately
        $session->outbuf .= "RFB 003.008\n";

        $conns[$id] = ['sock' => $sock, 'session' => $session, 'ip' => $ip];
        $perIp[$ip] = ($perIp[$ip] ?? 0) + 1;

        $this->logEvent([
            'proto' => 'vnc',
            'event' => 'connect',
            'ip' => $ip,
            'port' => $port,
            'path' => "VNC connection from {$ip}:{$clientPort}",
        ]);
    }

    private function close(array &$conns, array &$perIp, int $id): void
    {
        if (!isset($conns[$id])) {
            return;
        }
        $ip = $conns[$id]['ip'];
        @fclose($conns[$id]['sock']);
        unset($conns[$id]);

        if (isset($perIp[$ip])) {
            $perIp[$ip]--;
            if ($perIp[$ip] <= 0) {
                unset($perIp[$ip]);
            }
        }
    }

    /**
     * Processes inbound bytes according to the current RFB state.
     */
    public function processInbound(VncSession $s): void
    {
        switch ($s->state) {
            case VncSession::STATE_WAIT_VERSION:
                $this->handleVersion($s);
                break;

            case VncSession::STATE_WAIT_SECURITY:
                $this->handleSecuritySelect($s);
                break;

            case VncSession::STATE_WAIT_CLIENT_INIT:
                $this->handleClientInit($s);
                break;

            case VncSession::STATE_ACTIVE:
                $this->handleActiveMessages($s);
                break;
        }
    }

    /**
     * RFB Step 1: Version exchange.
     */
    private function handleVersion(VncSession $s): void
    {
        if (strlen($s->inbuf) < 12) {
            return;
        }

        $line = substr($s->inbuf, 0, 12);
        $s->inbuf = substr($s->inbuf, 12);
        $s->clientVersion = trim($line);

        // Expected format: "RFB 003.008\n"
        if (!preg_match('/^RFB (\d{3})\.(\d{3})\n$/', $line, $m)) {
            $s->close = true;

            return;
        }

        $major = (int) $m[1];
        $minor = (int) $m[2];

        if ($major < 3 || ($major === 3 && $minor < 7)) {
            $s->close = true; // Pre-3.7 protocol is unsupported

            return;
        }

        $s->isRfb38 = ($major > 3 || ($major === 3 && $minor >= 8));

        // Recon: the client-claimed RFB version fingerprints the tool even if it disconnects next.
        $this->logEvent([
            'proto' => 'vnc',
            'event' => 'version',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => "VNC client speaks {$s->clientVersion}",
        ]);

        // Offer Security Types:
        // Type 1 = None (no authentication needed)
        // Type 2 = VNC Authentication
        if ($this->config->authMode === 'harvest') {
            // Offer Type 2 to harvest passwords
            $s->outbuf .= "\x01\x02";
        } else {
            // Default: Offer Type 1 (None)
            $s->outbuf .= "\x01\x01";
        }

        $s->state = VncSession::STATE_WAIT_SECURITY;
    }

    /**
     * RFB Step 2: Security type selection.
     */
    private function handleSecuritySelect(VncSession $s): void
    {
        if (strlen($s->inbuf) < 1) {
            return;
        }

        $chosenType = ord($s->inbuf[0]);
        $s->inbuf = substr($s->inbuf, 1);
        $s->securityType = $chosenType;

        // Recon: which auth the client accepted (None vs VNC-Auth) plus its RFB version.
        $typeName = $chosenType === 1 ? 'None' : ($chosenType === 2 ? 'VNC-Auth' : 'type-' . $chosenType);
        $this->logEvent([
            'proto' => 'vnc',
            'event' => 'auth_select',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => "VNC security chosen: {$typeName} ({$s->clientVersion})",
        ]);

        if ($chosenType === 1) {
            // Type 1: None
            if ($s->isRfb38) {
                // RFB 3.8 sends SecurityResult (0 = OK)
                $s->outbuf .= "\x00\x00\x00\x00";
            }
            $s->state = VncSession::STATE_WAIT_CLIENT_INIT;
        } elseif ($chosenType === 2) {
            // Type 2: VncAuth challenge
            $challenge = random_bytes(16);
            $s->outbuf .= $challenge;
            // Wait for 16-byte response in active/auth handler
            $s->state = VncSession::STATE_WAIT_CLIENT_INIT;
        } else {
            // Unsupported security type requested
            if ($s->isRfb38) {
                $reason = "Unsupported security type";
                $s->outbuf .= "\x00\x00\x00\x01" . pack('N', strlen($reason)) . $reason;
            }
            $s->close = true;
        }
    }

    /**
     * RFB Step 3: ClientInit.
     */
    private function handleClientInit(VncSession $s): void
    {
        if (strlen($s->inbuf) < 1) {
            return;
        }

        $s->sharedFlag = ord($s->inbuf[0]);
        $s->inbuf = substr($s->inbuf, 1);

        // ServerInit response:
        // width (2), height (2)
        // PixelFormat (16 bytes): 32bpp, 24 depth, 0 big-endian, 1 true-color, rmax 255, gmax 255, bmax 255,
        // rshift 16, gshift 8, bshift 0, padding (3)
        // name_length (4), name (string)
        $w = $this->config->width;
        $h = $this->config->height;
        $name = $this->config->serverName;

        $pixelFormat = pack(
            'CCCCnnnCCCC3',
            32,   // bits-per-pixel
            24,   // depth
            0,    // big-endian (0 = Little Endian)
            1,    // true-colour
            255,  // red-max
            255,  // green-max
            255,  // blue-max
            16,   // red-shift
            8,    // green-shift
            0,    // blue-shift
            0, 0, 0 // padding
        );

        $serverInit = pack('nn', $w, $h) . $pixelFormat . pack('N', strlen($name)) . $name;
        $s->outbuf .= $serverInit;

        // Immediate Deception: Overwrite the client clipboard on connect!
        $clipText = $this->renderClipboardText($s);
        $s->outbuf .= self::buildServerCutText($clipText);
        $s->lastClipboardTime = microtime(true);

        // Initial audio beep if enabled
        if ($this->config->beep) {
            $s->outbuf .= "\x02";
            $s->lastBeepTime = microtime(true);
        }

        $s->state = VncSession::STATE_ACTIVE;

        $this->logEvent([
            'proto' => 'vnc',
            'event' => 'handshake_complete',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => "VNC handshake complete ({$w}x{$h}, client: {$s->clientVersion})",
        ]);
    }

    /**
     * RFB Step 4: Active session message dispatcher.
     */
    private function handleActiveMessages(VncSession $s): void
    {
        while ($s->inbuf !== '') {
            $msgType = ord($s->inbuf[0]);

            switch ($msgType) {
                case 0: // SetPixelFormat (20 bytes total)
                    if (strlen($s->inbuf) < 20) {
                        return;
                    }
                    $s->inbuf = substr($s->inbuf, 20);
                    break;

                case 2: // SetEncodings (4 + count * 4 bytes)
                    if (strlen($s->inbuf) < 4) {
                        return;
                    }
                    $count = unpack('n', substr($s->inbuf, 2, 2))[1];
                    $totalLen = 4 + ($count * 4);
                    if (strlen($s->inbuf) < $totalLen) {
                        return;
                    }

                    $s->encodings = [];
                    for ($i = 0; $i < $count; $i++) {
                        $enc = unpack('N', substr($s->inbuf, 4 + ($i * 4), 4))[1];
                        // Convert unsigned uint32 to signed int32
                        if ($enc >= 0x80000000) {
                            $enc -= 0x100000000;
                        }
                        $s->encodings[] = $enc;
                        if ($enc === VncCursor::ENCODING_CURSOR) { // -239
                            $s->supportsCursor = true;
                        }
                        if ($enc === self::ENC_DESKTOP_SIZE) { // -223
                            $s->supportsDesktopSize = true;
                        }
                    }
                    $s->inbuf = substr($s->inbuf, $totalLen);

                    // Recon: the ordered encoding list fingerprints the client library/tool.
                    $names = [];
                    foreach (array_slice($s->encodings, 0, 24) as $enc) {
                        $names[] = self::encodingName($enc) . '(' . $enc . ')';
                    }
                    $summary = implode(', ', $names);
                    if (count($s->encodings) > 24) {
                        $summary .= ', +' . (count($s->encodings) - 24) . ' more';
                    }
                    $this->logEvent([
                        'proto' => 'vnc',
                        'event' => 'encodings',
                        'ip' => $s->ip,
                        'port' => $s->port,
                        'path' => "VNC SetEncodings [{$count}]: {$summary}",
                    ]);
                    break;

                case 3: // FramebufferUpdateRequest (10 bytes total)
                    if (strlen($s->inbuf) < 10) {
                        return;
                    }
                    $hdr = unpack('Ctype/Cincremental/nx/ny/nw/nh', substr($s->inbuf, 0, 10));
                    $s->inbuf = substr($s->inbuf, 10);

                    // Recon: the first framebuffer request proves the bot actually pulled the screen.
                    if (!$s->loggedFbRequest) {
                        $s->loggedFbRequest = true;
                        $this->logEvent([
                            'proto' => 'vnc',
                            'event' => 'screen_viewed',
                            'ip' => $s->ip,
                            'port' => $s->port,
                            'path' => sprintf(
                                'VNC framebuffer requested - attacker saw the screen (%dx%d, incremental=%d)',
                                $hdr['w'],
                                $hdr['h'],
                                $hdr['incremental']
                            ),
                        ]);
                    }

                    // Send the fake desktop screenshot!
                    $this->sendFramebufferUpdate($s, (bool) $hdr['incremental']);
                    break;

                case 4: // KeyEvent (8 bytes total)
                    if (strlen($s->inbuf) < 8) {
                        return;
                    }
                    $keyHdr = unpack('Ctype/Cdown/x2/Nkeysym', substr($s->inbuf, 0, 8));
                    $s->inbuf = substr($s->inbuf, 8);

                    if ($keyHdr['down'] === 1) {
                        $keysym = $keyHdr['keysym'];
                        $char = ($keysym >= 32 && $keysym <= 126) ? chr($keysym) : sprintf('0x%04X', $keysym);
                        $this->logEvent([
                            'proto' => 'vnc',
                            'event' => 'key',
                            'ip' => $s->ip,
                            'port' => $s->port,
                            'path' => "VNC key down: {$char}",
                        ]);
                        $this->triggerActionTrap($s, "key {$char}");
                    }
                    break;

                case 5: // PointerEvent (6 bytes total)
                    if (strlen($s->inbuf) < 6) {
                        return;
                    }
                    $ptrHdr = unpack('Ctype/Cbutton/nx/ny', substr($s->inbuf, 0, 6));
                    $s->inbuf = substr($s->inbuf, 6);

                    // Dodging popup: while the fake dialog is up (after the first click, before the
                    // storm), any pointer movement toward it makes it jump away — it is unclickable.
                    if ($this->config->style === 'taunt' && $this->config->dodgePopup
                        && $s->clicked && !$s->taunting
                        && $this->cursorNearPopup($s, $ptrHdr['x'], $ptrHdr['y'])) {
                        $this->relocatePopup($s, $ptrHdr['x'], $ptrHdr['y']);
                    }

                    // Log when user clicks (button > 0)
                    if ($ptrHdr['button'] > 0) {
                        $this->logEvent([
                            'proto' => 'vnc',
                            'event' => 'click',
                            'ip' => $s->ip,
                            'port' => $s->port,
                            'path' => sprintf('VNC mouse click: btn=%d at (%d, %d)', $ptrHdr['button'], $ptrHdr['x'], $ptrHdr['y']),
                        ]);
                        $this->triggerActionTrap($s, sprintf('click btn=%d at (%d, %d)', $ptrHdr['button'], $ptrHdr['x'], $ptrHdr['y']));
                    }
                    break;

                case 6: // ClientCutText (8 + len bytes)
                    if (strlen($s->inbuf) < 8) {
                        return;
                    }
                    $cutHdr = unpack('Ctype/x3/Nlen', substr($s->inbuf, 0, 8));
                    $textLen = $cutHdr['len'];
                    if ($textLen > 65536) {
                        $s->close = true;

                        return;
                    }
                    if (strlen($s->inbuf) < 8 + $textLen) {
                        return;
                    }
                    $copiedText = substr($s->inbuf, 8, $textLen);
                    $s->inbuf = substr($s->inbuf, 8 + $textLen);

                    $this->logEvent([
                        'proto' => 'vnc',
                        'event' => 'client_clipboard',
                        'ip' => $s->ip,
                        'port' => $s->port,
                        'path' => 'VNC client clipboard: ' . substr($copiedText, 0, 200),
                        'body' => $copiedText,
                    ]);
                    break;

                default:
                    // Unknown message type: cannot determine frame length, so close. Log it first —
                    // a bot probing for a TightVNC/UltraVNC extension (file transfer, chat) shows up here.
                    $this->logEvent([
                        'proto' => 'vnc',
                        'event' => 'unknown_msg',
                        'ip' => $s->ip,
                        'port' => $s->port,
                        'path' => sprintf('VNC unknown message type %d (extension probe?)', $msgType),
                    ]);
                    $s->close = true;

                    return;
            }
        }
    }

    /**
     * Sends the visual FramebufferUpdate packet including any pseudo-rectangles
     * (Cursor and DesktopSize chaos resize).
     */
    public function sendFramebufferUpdate(VncSession $s, bool $incremental): void
    {
        // Don't re-transmit identical full screen data repeatedly if already sent on incremental requests
        if ($incremental && $s->sentFirstUpdate) {
            return;
        }

        if ($s->cachedFramebuffer === null) {
            // The realistic desktop; the taunt slideshow pushes its own frames directly.
            $s->cachedFramebuffer = $this->renderer->renderBgra($s->ip, $s->port, null);
        }

        $rectangles = [];

        // 1. Chaos Desktop Resize (-223) on initial connect (only if chaosResizeOnAction is false)
        if ($this->config->chaosResize && !$this->config->chaosResizeOnAction && $s->supportsDesktopSize && !$s->sentChaosResize) {
            $s->sentChaosResize = true;
            // DesktopSize pseudo-rectangle header: x=0, y=0, width, height, encoding = -223
            $rectangles[] = pack('n4N', 0, 0, $this->config->massiveWidth, $this->config->massiveHeight, -223);
        }

        // 2. Custom Mouse Cursor (-239)
        // Clients that negotiate the Cursor pseudo-encoding hide their own pointer and wait for
        // ours, so send one on connect or the attacker sees no cursor at all. Taunt keeps the
        // realistic arrow until the first click, then triggerActionTrap swaps in the skull.
        if ($s->supportsCursor && !$s->sentCursor && $this->config->cursor !== 'none') {
            $s->sentCursor = true;
            $connectCursor = ($this->config->style === 'taunt') ? 'normal' : $this->config->cursor;
            $cursorRect = VncCursor::buildRectangle($connectCursor);
            if ($cursorRect !== '') {
                $rectangles[] = $cursorRect;
            }
        }

        // 3. Fake Desktop Framebuffer (Raw Encoding 0)
        $w = $this->config->width;
        $h = $this->config->height;
        $mainRect = pack('n4N', 0, 0, $w, $h, 0) . $s->cachedFramebuffer;
        $rectangles[] = $mainRect;

        // FramebufferUpdate header: type (0), padding (0), number of rectangles (uint16_be)
        $msgHeader = "\x00\x00" . pack('n', count($rectangles));
        $s->outbuf .= $msgHeader . implode('', $rectangles);

        $s->sentFirstUpdate = true;
    }

    /**
     * The scripted taunt slideshow: on the first interaction the dialog shows, then these frames
     * play in order, then the malformed farewell drops the client.
     *
     * @return list<array{kind:string,path?:string,w?:int,h?:int,dur:float}>
     */
    private function tauntSteps(): array
    {
        $dir = dirname(__DIR__, 3) . '/demo/assets/';

        return [
            ['kind' => 'error', 'w' => 340, 'h' => 180, 'dur' => 1.0],
            ['kind' => 'image', 'path' => $dir . 'ah-ah-ah.jpg', 'dur' => 0.5],
            ['kind' => 'reversing', 'w' => 200, 'h' => 200, 'dur' => 1.0],
            ['kind' => 'image', 'path' => $dir . 'evil-troll.png', 'dur' => 1.0],
            ['kind' => 'installed', 'w' => 200, 'h' => 200, 'dur' => 1.5],
        ];
    }

    /**
     * Renders one taunt slide: resize the client window to the frame's size, then paint it.
     */
    private function pushTauntStep(VncSession $s, int $i): void
    {
        $steps = $this->tauntSteps();
        if (!isset($steps[$i])) {
            return;
        }
        $step = $steps[$i];

        if ($step['kind'] === 'image') {
            [$w, $h, $bgra] = $this->renderer->renderStormImageBgra($step['path']);
        } else {
            $w = $step['w'];
            $h = $step['h'];
            $bgra = match ($step['kind']) {
                'error' => $this->renderer->renderVncErrorBgra($w, $h),
                'installed' => $this->renderer->renderInstalledTextBgra($w, $h),
                default => $this->renderer->renderReversingTextBgra($w, $h),
            };
        }

        // Snap the client window to this frame's size (clients that negotiated DesktopSize).
        if ($s->supportsDesktopSize) {
            $s->outbuf .= "\x00\x00\x00\x01" . pack('n4N', 0, 0, $w, $h, self::ENC_DESKTOP_SIZE);
        }
        $s->outbuf .= "\x00\x00\x00\x01" . pack('n4N', 0, 0, $w, $h, 0) . $bgra;
    }

    /**
     * Advances the taunt slideshow when the current frame's time is up.
     * Returns 'waiting' (not taunting or frame still showing), 'advanced' (moved to the next
     * frame), or 'finished' (last frame's time is up — the caller drops the client).
     */
    public function advanceTauntSlideshow(VncSession $s, float $now): string
    {
        if (!$s->taunting) {
            return 'waiting';
        }
        $steps = $this->tauntSteps();
        $dur = $steps[$s->tauntStep]['dur'] ?? 0.0;
        if (($now - $s->tauntStepStart) < $dur) {
            return 'waiting';
        }

        $next = $s->tauntStep + 1;
        if ($next >= count($steps)) {
            return 'finished';
        }

        $s->tauntStep = $next;
        $s->tauntStepStart = $now;
        $this->pushTauntStep($s, $next);

        return 'advanced';
    }

    /**
     * Whether another animation frame may be queued. False when the client is not draining and
     * outbuf has reached the soft cap — queueing more would grow the buffer without bound.
     */
    public function canQueueFrame(VncSession $s): bool
    {
        return strlen($s->outbuf) < self::OUTBUF_SOFT_CAP;
    }

    /**
     * A client that has let outbuf pass the hard cap is not reading at all; drop it.
     */
    public function outbufOverflowed(VncSession $s): bool
    {
        return strlen($s->outbuf) >= self::OUTBUF_HARD_CAP;
    }

    /**
     * Phase 1 of the taunt: push the fake "Reverse VNC connection?" dialog over the desktop at
     * the session's current dialog position (centred on first paint).
     */
    public function pushPopupFrame(VncSession $s): void
    {
        $w = $this->config->width;
        $h = $this->config->height;
        if ($s->popupX < 0 || $s->popupY < 0) {
            $s->popupX = (int) (($w - VncThemeRenderer::POPUP_W) / 2);
            $s->popupY = (int) (($h - VncThemeRenderer::POPUP_H) / 2);
        }
        $bgra = $this->renderer->renderPopupBgra($s->ip, $s->port, $w, $h, $s->popupX, $s->popupY);
        $mainRect = pack('n4N', 0, 0, $w, $h, 0) . $bgra;
        $s->outbuf .= "\x00\x00\x00\x01" . $mainRect;
    }

    /**
     * True when the pointer is within a margin of the current dialog rectangle.
     */
    public function cursorNearPopup(VncSession $s, int $x, int $y): bool
    {
        if ($s->popupX < 0 || $s->popupY < 0) {
            return false;
        }
        $margin = 60;
        return $x >= $s->popupX - $margin
            && $x <= $s->popupX + VncThemeRenderer::POPUP_W + $margin
            && $y >= $s->popupY - $margin
            && $y <= $s->popupY + VncThemeRenderer::POPUP_H + $margin;
    }

    // How far the dialog slides away from the pointer on each dodge. A gentle nudge, not a teleport.
    private const POPUP_DODGE_STEP = 220;

    /**
     * Slides the dialog a short step directly away from the pointer, clamped so it always stays
     * fully on screen. If an edge blocks the away-direction, it mirrors to the opposite side so it
     * can never be cornered. Throttled and backpressure-aware (each move repaints the framebuffer).
     * Returns true if it moved.
     */
    public function relocatePopup(VncSession $s, int $cursorX, int $cursorY): bool
    {
        $now = microtime(true);
        if (($now - $s->lastPopupMoveTime) < 0.15 || !$this->canQueueFrame($s)) {
            return false;
        }

        $pw = VncThemeRenderer::POPUP_W;
        $ph = VncThemeRenderer::POPUP_H;
        $margin = 20;
        $minX = $margin;
        $maxX = max($margin, $this->config->width - $pw - $margin);
        $minY = $margin;
        $maxY = max($margin, $this->config->height - $ph - $margin);

        // Direction from the pointer to the dialog centre; default to down-right if it sits dead centre.
        $dx = (float) (($s->popupX + $pw / 2) - $cursorX);
        $dy = (float) (($s->popupY + $ph / 2) - $cursorY);
        $len = sqrt(($dx * $dx) + ($dy * $dy));
        if ($len == 0.0) {
            $dx = 1.0;
            $dy = 1.0;
            $len = sqrt(2.0);
        }

        $newX = (int) round($s->popupX + ($dx / $len) * self::POPUP_DODGE_STEP);
        $newY = (int) round($s->popupY + ($dy / $len) * self::POPUP_DODGE_STEP);
        $newX = max($minX, min($maxX, $newX));
        $newY = max($minY, min($maxY, $newY));

        // If clamping pinned it against an edge (the pointer is crowding it there), mirror across
        // that axis to the opposite side so the dialog keeps its distance.
        if ($newX === $s->popupX) {
            $newX = max($minX, min($maxX, $minX + $maxX - $s->popupX));
        }
        if ($newY === $s->popupY) {
            $newY = max($minY, min($maxY, $minY + $maxY - $s->popupY));
        }

        if ($newX === $s->popupX && $newY === $s->popupY) {
            return false;
        }

        $s->popupX = $newX;
        $s->popupY = $newY;
        $s->lastPopupMoveTime = $now;
        $this->pushPopupFrame($s);

        return true;
    }

    /**
     * Human-readable name for an RFB encoding number, for fingerprinting a client from its
     * SetEncodings list. Unknown values come back as enc(N).
     */
    public static function encodingName(int $enc): string
    {
        static $map = [
            0 => 'Raw', 1 => 'CopyRect', 2 => 'RRE', 4 => 'CoRRE', 5 => 'Hextile',
            6 => 'zlib', 7 => 'Tight', 8 => 'zlibhex', 15 => 'TRLE', 16 => 'ZRLE', 17 => 'ZYWRLE',
            -223 => 'DesktopSize', -224 => 'LastRect', -239 => 'Cursor', -240 => 'XCursor',
            -257 => 'PointerPos', -258 => 'ExtKeyEvent', -259 => 'KeyboardLED',
            -307 => 'DesktopName', -308 => 'ExtDesktopSize', -309 => 'xvp',
            -312 => 'Fence', -313 => 'ContinuousUpdates', -314 => 'CursorWithAlpha',
            -412 => 'JPEGFineGrained',
        ];
        if (isset($map[$enc])) {
            return $map[$enc];
        }
        if ($enc >= -32 && $enc <= -23) {
            return 'TightJPEGQuality';
        }
        if ($enc >= -256 && $enc <= -247) {
            return 'TightCompressLevel';
        }

        return 'enc(' . $enc . ')';
    }

    /**
     * A short burst of deliberately invalid RFB: a bogus version banner mid-stream, a
     * FramebufferUpdate rectangle with an unknown encoding and truncated pixels, a ServerCutText
     * that lies about its length, and unknown server->client message types. Only ever sent to an
     * attacker whose client is about to be dropped — it can confuse their viewer, never ours.
     */
    public static function buildGarbageFarewell(): string
    {
        $out = '';
        // 1. Fake version banner injected mid-session (protocol desync).
        $out .= "RFB 999.999\n";
        // 2. FramebufferUpdate: 1 rect, invalid encoding, far fewer pixels than 64x64 declares.
        $out .= "\x00\x00" . pack('n', 1);
        $out .= pack('n4N', 0, 0, 64, 64, 0x41414141);
        $out .= str_repeat("\xDE\xAD\xBE\xEF", 8);
        // 3. ServerCutText claiming a 4 GiB payload it never sends.
        $out .= "\x03\x00\x00\x00" . pack('N', 0xFFFFFFFF);
        // 4. Unknown / invalid server->client message types.
        $out .= "\xFF\xFE\xFD\xAA\x55";
        // 5. Bounded high-entropy filler.
        $out .= str_repeat("\x13\x37\xC0\xDE", 64);

        return $out;
    }

    /**
     * Starts the real taunt storm once the popup has been shown for tauntPopupSec.
     * Returns true if it started on this call.
     */
    public function maybeBeginTauntStorm(VncSession $s, float $now): bool
    {
        if (!$s->clicked || $s->taunting || $this->config->style !== 'taunt') {
            return false;
        }
        if (($now - $s->clickTime) < $this->config->tauntPopupSec) {
            return false;
        }

        $this->beginTauntStorm($s, $now);

        return true;
    }

    /**
     * Phase 2: start the scripted slideshow — skull cursor, beeps, and the first frame. Subsequent
     * frames and the final malformed drop are driven by advanceTauntSlideshow from the tick loop.
     */
    private function beginTauntStorm(VncSession $s, float $now): void
    {
        $s->taunting = true;
        $s->tauntStartTime = $now;
        $s->tauntStep = 0;
        $s->tauntStepStart = $now;

        // Show the first slide.
        $this->pushTauntStep($s, 0);

        // Morph cursor to the skull.
        if ($s->supportsCursor) {
            $skullRect = VncCursor::buildRectangle('skull');
            if ($skullRect !== '') {
                $s->outbuf .= "\x00\x00\x00\x01" . $skullRect;
            }
        }

        // Start beeping.
        if ($this->config->beep) {
            $s->outbuf .= "\x02";
            $s->lastBeepTime = $now;
        }

        $this->logEvent([
            'proto' => 'vnc',
            'event' => 'trap_triggered',
            'ip' => $s->ip,
            'port' => $s->port,
            'path' => 'Taunt slideshow started',
        ]);
    }

    /**
     * Handles user interaction trap (click or keypress).
     * In taunt mode the first interaction shows the fake "Reverse VNC connection?" dialog; the
     * real storm (resize/animation/beeps) begins later via maybeBeginTauntStorm.
     * In realistic mode: preserves the realistic desktop.
     */
    public function triggerActionTrap(VncSession $s, string $action): void
    {
        if ($this->config->style === 'taunt') {
            if (!$s->clicked) {
                $s->clicked = true;
                $s->clickTime = microtime(true);

                // Phase 1: pop the fake dialog over the desktop. The clipboard was already
                // hijacked on connect; nothing resizes or beeps yet.
                $this->pushPopupFrame($s);
                $s->popupShown = true;

                $this->logEvent([
                    'proto' => 'vnc',
                    'event' => 'popup_shown',
                    'ip' => $s->ip,
                    'port' => $s->port,
                    'path' => "Reverse-VNC-connection dialog shown by {$action}",
                ]);
            }
        } elseif ($this->config->chaosResize && $this->config->chaosResizeOnAction && $s->supportsDesktopSize && !$s->sentChaosResize) {
            $s->sentChaosResize = true;

            // FramebufferUpdate with 1 rectangle: DesktopSize (-223)
            $rect = pack('n4N', 0, 0, $this->config->massiveWidth, $this->config->massiveHeight, -223);
            $s->outbuf .= "\x00\x00\x00\x01" . $rect;

            $this->logEvent([
                'proto' => 'vnc',
                'event' => 'trap_triggered',
                'ip' => $s->ip,
                'port' => $s->port,
                'path' => "Chaos massive resize ({$this->config->massiveWidth}x{$this->config->massiveHeight}) triggered by {$action}",
            ]);
        }
    }

    /**
     * Packs ServerCutText message (Type 3).
     */
    public static function buildServerCutText(string $text): string
    {
        // message-type (1) = 3
        // padding (3) = 0
        // length (4) = uint32_be
        // text bytes
        return "\x03\x00\x00\x00" . pack('N', strlen($text)) . $text;
    }

    private function renderClipboardText(VncSession $s): string
    {
        return str_replace(
            ['{ip}', '{port}', '{time}'],
            [$s->ip, (string) $s->port, gmdate('Y-m-d H:i:s T')],
            $this->config->clipboard
        );
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function logEvent(array $entry): void
    {
        $entry['ts'] = gmdate('c');
        $entry['severity'] = $entry['severity'] ?? 'medium';
        $entry['method'] = 'VNC';
        $entry['proto'] = 'vnc';
        $entry['matched'] = 1;
        $entry['served'] = 1;
        ($this->logger)($entry);
    }

    private static function portOf(string $bind): int
    {
        $colon = strrpos($bind, ':');

        return $colon !== false ? (int) substr($bind, $colon + 1) : 5900;
    }
}
