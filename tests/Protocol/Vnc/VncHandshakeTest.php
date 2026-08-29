<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Vnc;

use Funnypot\Protocol\Vnc\VncConfig;
use Funnypot\Protocol\Vnc\VncServer;
use Funnypot\Protocol\Vnc\VncSession;
use PHPUnit\Framework\TestCase;

final class VncHandshakeTest extends TestCase
{
    public function test_full_handshake_and_framebuffer_update(): void
    {
        $events = [];
        $logger = static function (array $e) use (&$events): void {
            $events[] = $e;
        };

        $config = new VncConfig(
            style: 'realistic',
            width: 400,
            height: 300,
            clipboard: 'TEST CLIPBOARD INJECTION: {ip}',
            beep: true,
            cursor: 'troll',
            chaosResize: true,
            chaosResizeOnAction: false,
            massiveWidth: 8192,
            massiveHeight: 8192,
            serverName: 'Test VNC Desktop'
        );

        $server = new VncServer($config, $logger);
        $session = new VncSession('192.0.2.42', 54321, 1);

        // --- Step 1: Version Exchange ---
        // Client sends its version
        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);

        self::assertSame(VncSession::STATE_WAIT_SECURITY, $session->state);
        self::assertSame("RFB 003.008", $session->clientVersion);
        self::assertTrue($session->isRfb38);

        // Server offers 1 security type: Type 1 (None) -> "\x01\x01"
        self::assertSame("\x01\x01", $session->outbuf);
        $session->outbuf = '';

        // --- Step 2: Security Selection ---
        // Client selects Type 1 (None)
        $session->inbuf .= "\x01";
        $server->processInbound($session);

        self::assertSame(VncSession::STATE_WAIT_CLIENT_INIT, $session->state);
        // RFB 3.8 sends SecurityResult 0 (OK) -> "\x00\x00\x00\x00"
        self::assertSame("\x00\x00\x00\x00", $session->outbuf);
        $session->outbuf = '';

        // --- Step 3: ClientInit ---
        // Client sends shared-flag = 1
        $session->inbuf .= "\x01";
        $server->processInbound($session);

        self::assertSame(VncSession::STATE_ACTIVE, $session->state);

        // ServerInit check:
        // Width (2 bytes), Height (2 bytes) = 400, 300
        $out = $session->outbuf;
        $session->outbuf = '';

        $w = unpack('n', substr($out, 0, 2))[1];
        $h = unpack('n', substr($out, 2, 2))[1];
        self::assertSame(400, $w);
        self::assertSame(300, $h);

        // Check desktop name inside ServerInit
        self::assertStringContainsString('Test VNC Desktop', $out);

        // Check clipboard injection (ServerCutText, message type 3)
        self::assertStringContainsString('TEST CLIPBOARD INJECTION: 192.0.2.42', $out);

        // Check initial beep (\x02)
        self::assertStringContainsString("\x02", $out);

        // --- Step 4: SetEncodings ---
        // Client requests Raw (0), DesktopSize (-223), Cursor (-239)
        // SetEncodings packet: type (2) + pad (1) + count (2 bytes) + 3*4 bytes
        $encPacket = "\x02\x00" . pack('n', 3) . pack('NNN', 0, -223, -239);
        $session->inbuf .= $encPacket;
        $server->processInbound($session);

        self::assertTrue($session->supportsDesktopSize);
        self::assertTrue($session->supportsCursor);

        // --- Step 5: FramebufferUpdateRequest ---
        // Request update: type (3) + incremental (0) + x(0), y(0), w(400), h(300)
        $reqPacket = "\x03\x00" . pack('nnnn', 0, 0, 400, 300);
        $session->inbuf .= $reqPacket;
        $server->processInbound($session);

        $fbOut = $session->outbuf;
        $session->outbuf = '';

        // FramebufferUpdate packet check:
        // Type 0, pad 0, number of rects (2 bytes)
        self::assertSame("\x00\x00", substr($fbOut, 0, 2));
        $rectCount = unpack('n', substr($fbOut, 2, 2))[1];
        // Rectangles: Chaos DesktopSize (-223) + Troll Cursor (-239) + Main Framebuffer (0) = 3 rectangles
        self::assertSame(3, $rectCount);

        // --- Step 6: Telemetry Events (Key, Click, Clipboard) ---
        // Attacker sends KeyEvent: key down 'A' (ASCII 65 = 0x41)
        // type (4) + down (1) + pad (2) + keysym (4)
        $keyPacket = "\x04\x01\x00\x00" . pack('N', 65);
        $session->inbuf .= $keyPacket;
        $server->processInbound($session);

        // Attacker sends PointerEvent: click button 1 at (150, 220)
        // type (5) + button (1) + x (2) + y (2)
        $clickPacket = "\x05\x01" . pack('nn', 150, 220);
        $session->inbuf .= $clickPacket;
        $server->processInbound($session);

        // Attacker sends ClientCutText: copied "secret_exploit"
        $copiedText = "secret_exploit";
        $cutPacket = "\x06\x00\x00\x00" . pack('N', strlen($copiedText)) . $copiedText;
        $session->inbuf .= $cutPacket;
        $server->processInbound($session);

        // Verify events logged
        $eventTypes = array_column($events, 'event');
        self::assertContains('key', $eventTypes);
        self::assertContains('click', $eventTypes);
        self::assertContains('client_clipboard', $eventTypes);

        $clipboardEvent = array_values(array_filter($events, fn ($e) => $e['event'] === 'client_clipboard'))[0];
        self::assertSame('secret_exploit', $clipboardEvent['body']);
    }

    public function test_unsupported_version_disconnects(): void
    {
        $server = new VncServer(new VncConfig(), static fn () => null);
        $session = new VncSession('127.0.0.1', 5900, 1);

        $session->inbuf .= "RFB 003.003\n"; // RFB 3.3 unsupported
        $server->processInbound($session);

        self::assertTrue($session->close);
    }

    public function test_malformed_version_disconnects(): void
    {
        $server = new VncServer(new VncConfig(), static fn () => null);
        $session = new VncSession('127.0.0.1', 5900, 1);

        $session->inbuf .= "NOT_AN_RFB_VERSION\n";
        $server->processInbound($session);

        self::assertTrue($session->close);
    }

    public function test_unsupported_security_type_disconnects(): void
    {
        $server = new VncServer(new VncConfig(), static fn () => null);
        $session = new VncSession('127.0.0.1', 5900, 1);

        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->outbuf = '';

        // Client chooses unsupported security type (e.g. 99)
        $session->inbuf .= "\x63";
        $server->processInbound($session);

        self::assertTrue($session->close);
        self::assertStringContainsString("Unsupported security type", $session->outbuf);
    }

    public function test_chaos_resize_triggered_on_user_interaction(): void
    {
        $events = [];
        $logger = static function (array $e) use (&$events): void {
            $events[] = $e;
        };

        // chaosResize = true, chaosResizeOnAction = true (realistic-mode chaos, not the taunt)
        $config = new VncConfig(
            style: 'realistic',
            width: 800,
            height: 600,
            cursor: 'none',
            chaosResize: true,
            chaosResizeOnAction: true,
            massiveWidth: 16000,
            massiveHeight: 9000
        );

        $server = new VncServer($config, $logger);
        $session = new VncSession('10.0.0.99', 44444, 2);

        // Handshake to active
        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01"; // None
        $server->processInbound($session);
        $session->inbuf .= "\x01"; // ClientInit
        $server->processInbound($session);
        $session->outbuf = ''; // Clear serverInit/clipboard

        // Set encodings with DesktopSize (-223)
        $session->inbuf .= "\x02\x00" . pack('n', 2) . pack('NN', 0, -223);
        $server->processInbound($session);
        self::assertTrue($session->supportsDesktopSize);

        // Initial FramebufferUpdateRequest -> Server sends NORMAL screen size (800x600), NOT massive
        $session->inbuf .= "\x03\x00" . pack('nnnn', 0, 0, 800, 600);
        $server->processInbound($session);

        $fbOut = $session->outbuf;
        $session->outbuf = '';

        // Expect 1 rectangle (the standard 800x600 framebuffer), NOT massive DesktopSize yet
        $rectCount = unpack('n', substr($fbOut, 2, 2))[1];
        self::assertSame(1, $rectCount);
        self::assertFalse($session->sentChaosResize);

        // NOW: The user clicks the mouse! (button 1 at x=100, y=100)
        $session->inbuf .= "\x05\x01" . pack('nn', 100, 100);
        $server->processInbound($session);

        $trapOut = $session->outbuf;
        $session->outbuf = '';

        // Verify sentChaosResize is now true
        self::assertTrue($session->sentChaosResize);

        // Verify FramebufferUpdate with DesktopSize (-223) was emitted immediately
        self::assertSame("\x00\x00", substr($trapOut, 0, 2));
        $updateRectCount = unpack('n', substr($trapOut, 2, 2))[1];
        self::assertSame(1, $updateRectCount);

        $rectHeader = unpack('nx/ny/nw/nh/Nenc', substr($trapOut, 4, 12));
        self::assertSame(16000, $rectHeader['w']);
        self::assertSame(9000, $rectHeader['h']);

        $enc = $rectHeader['enc'];
        if ($enc >= 0x80000000) {
            $enc -= 0x100000000;
        }
        self::assertSame(-223, $enc);

        // Verify trap event was logged
        $eventTypes = array_column($events, 'event');
        self::assertContains('trap_triggered', $eventTypes);
        self::assertContains('click', $eventTypes);
    }

    public function test_taunt_slideshow_starts_with_first_slide_after_popup(): void
    {
        $config = new VncConfig(style: 'taunt', width: 800, height: 600);
        $server = new VncServer($config, static fn () => null);
        $session = new VncSession('10.0.0.1', 55555, 3);

        // Handshake to active
        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01"; // None
        $server->processInbound($session);
        $session->inbuf .= "\x01"; // ClientInit
        $server->processInbound($session);
        $session->outbuf = '';

        // Advertise DesktopSize (-223) + Cursor (-239)
        $session->inbuf .= "\x02\x00" . pack('n', 2) . pack('NN', -223, -239);
        $server->processInbound($session);
        $session->outbuf = '';

        // Click shows the popup first; discard it, then start the slideshow.
        $session->inbuf .= "\x05\x01" . pack('nn', 50, 50);
        $server->processInbound($session);
        self::assertTrue($session->clicked);
        self::assertFalse($session->taunting);
        $session->outbuf = '';

        self::assertTrue($server->maybeBeginTauntStorm($session, $session->clickTime + 3.0));
        self::assertTrue($session->taunting);
        self::assertSame(0, $session->tauntStep);

        // Frame 0 is the "VNC has stopped working" error box (340x180): a DesktopSize (-223) resize.
        $rect0 = unpack('nx/ny/nw/nh/Nenc', substr($session->outbuf, 4, 12));
        $enc = $rect0['enc'] >= 0x80000000 ? $rect0['enc'] - 0x100000000 : $rect0['enc'];
        self::assertSame(-223, $enc);
        self::assertSame(340, $rect0['w']);
        self::assertSame(180, $rect0['h']);

        // The skull cursor (-239) is pushed once the slideshow starts.
        self::assertStringContainsString(pack('N', -239 & 0xFFFFFFFF), $session->outbuf);
    }

    public function test_taunt_shows_realistic_cursor_on_connect_then_skull_on_click(): void
    {
        // In taunt mode the attacker must still see a normal pointer until they interact;
        // the skull only appears once the trap springs.
        $config = new VncConfig(style: 'taunt', width: 400, height: 300, cursor: 'normal');
        $server = new VncServer($config, static fn () => null);
        $session = new VncSession('10.0.0.9', 55560, 6);

        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->outbuf = '';

        // Advertise Raw + Cursor
        $session->inbuf .= "\x02\x00" . pack('n', 2) . pack('NN', 0, -239);
        $server->processInbound($session);
        $session->outbuf = '';

        // FramebufferUpdateRequest -> a Cursor (-239) rect must be present before any click.
        $session->inbuf .= "\x03\x00" . pack('nnnn', 0, 0, 400, 300);
        $server->processInbound($session);
        self::assertFalse($session->taunting);
        self::assertStringContainsString(pack('N', -239 & 0xFFFFFFFF), $session->outbuf);
        $session->outbuf = '';

        // Click -> popup only; the pointer stays a normal arrow (no skull yet).
        $session->inbuf .= "\x05\x01" . pack('nn', 10, 10);
        $server->processInbound($session);
        self::assertTrue($session->clicked);
        self::assertFalse($session->taunting);
        $session->outbuf = '';

        // Storm begins after the popup delay -> skull cursor (-239) is pushed.
        self::assertTrue($server->maybeBeginTauntStorm($session, $session->clickTime + 3.0));
        self::assertTrue($session->taunting);
        self::assertStringContainsString(pack('N', -239 & 0xFFFFFFFF), $session->outbuf);
    }

    public function test_click_shows_popup_then_storm_after_delay(): void
    {
        $config = new VncConfig(style: 'taunt', width: 400, height: 300, tauntPopupSec: 2.0);
        $server = new VncServer($config, static fn () => null);
        $session = new VncSession('10.0.0.11', 55561, 7);

        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->outbuf = '';

        // Click -> popup shown, storm NOT started.
        $session->inbuf .= "\x05\x01" . pack('nn', 10, 10);
        $server->processInbound($session);
        self::assertTrue($session->clicked);
        self::assertTrue($session->popupShown);
        self::assertFalse($session->taunting);

        // Still within the popup window -> storm holds off.
        self::assertFalse($server->maybeBeginTauntStorm($session, $session->clickTime + 1.0));
        self::assertFalse($session->taunting);

        // After the popup delay -> storm starts and the auto-drop clock starts here.
        self::assertTrue($server->maybeBeginTauntStorm($session, $session->clickTime + 2.1));
        self::assertTrue($session->taunting);
        self::assertSame($session->tauntStartTime, $session->clickTime + 2.1);
    }

    public function test_popup_dodges_when_pointer_approaches(): void
    {
        $config = new VncConfig(style: 'taunt', width: 1024, height: 768, cursor: 'normal', dodgePopup: true);
        $server = new VncServer($config, static fn () => null);
        $session = new VncSession('10.0.0.12', 55562, 8);

        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->outbuf = '';

        // Click -> popup shown, centred.
        $session->inbuf .= "\x05\x01" . pack('nn', 512, 384);
        $server->processInbound($session);
        self::assertTrue($session->clicked);
        $centreX = $session->popupX;
        $centreY = $session->popupY;
        self::assertGreaterThanOrEqual(0, $centreX);
        $session->outbuf = '';

        // Move the pointer over the dialog (button up) -> it must jump to a new position.
        $session->inbuf .= "\x05\x00" . pack('nn', $centreX + 180, $centreY + 75);
        $server->processInbound($session);

        self::assertTrue($session->popupX !== $centreX || $session->popupY !== $centreY, 'popup should dodge the cursor');
        self::assertNotEmpty($session->outbuf, 'dodging repaints the framebuffer');
    }

    public function test_taunt_slideshow_resizes_to_the_small_text_frame(): void
    {
        $config = new VncConfig(style: 'taunt', width: 800, height: 600);
        $server = new VncServer($config, static fn () => null);
        $session = new VncSession('10.0.0.3', 55557, 5);

        $session->inbuf .= "RFB 003.008\n";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->inbuf .= "\x01";
        $server->processInbound($session);
        $session->outbuf = '';
        $session->inbuf .= "\x02\x00" . pack('n', 1) . pack('N', -223); // DesktopSize
        $server->processInbound($session);
        $session->outbuf = '';

        // Start the slideshow (frame 0 error), advance past ah-ah-ah (frame 1) to the 200x200
        // "Reversing VNC connection" panel (frame 2).
        $session->clicked = true;
        $session->clickTime = 10.0;
        self::assertTrue($server->maybeBeginTauntStorm($session, 12.1));
        self::assertSame('advanced', $server->advanceTauntSlideshow($session, 13.2)); // -> frame 1 (ah-ah-ah)
        $session->outbuf = '';
        self::assertSame('advanced', $server->advanceTauntSlideshow($session, 13.8)); // -> frame 2 (reversing)
        self::assertSame(2, $session->tauntStep);

        // First rect of frame 2 is a DesktopSize (-223) resize to 200x200.
        $rect = unpack('nx/ny/nw/nh/Nenc', substr($session->outbuf, 4, 12));
        $enc = $rect['enc'] >= 0x80000000 ? $rect['enc'] - 0x100000000 : $rect['enc'];
        self::assertSame(-223, $enc);
        self::assertSame(200, $rect['w']);
        self::assertSame(200, $rect['h']);
    }
}
