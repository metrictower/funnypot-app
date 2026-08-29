<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Vnc;

use Funnypot\Protocol\Vnc\VncConfig;
use Funnypot\Protocol\Vnc\VncCursor;
use Funnypot\Protocol\Vnc\VncServer;
use Funnypot\Protocol\Vnc\VncSession;
use Funnypot\Protocol\Vnc\VncThemeRenderer;
use PHPUnit\Framework\TestCase;

final class VncDeceptionFeaturesTest extends TestCase
{
    public function test_troll_cursor_structure(): void
    {
        $rect = VncCursor::buildRectangle('troll');
        self::assertNotEmpty($rect);

        // Header: pack('n4N', hotX, hotY, width, height, -239)
        // hotX (2), hotY (2), width (2), height (2), encoding (4) = 12 bytes
        $hdr = substr($rect, 0, 12);
        $fields = unpack('nhotx/nhoty/nw/nh/Nenc', $hdr);

        self::assertSame(16, $fields['hotx']);
        self::assertSame(16, $fields['hoty']);
        self::assertSame(32, $fields['w']);
        self::assertSame(32, $fields['h']);

        // Convert unsigned uint32 to signed int32
        $enc = $fields['enc'];
        if ($enc >= 0x80000000) {
            $enc -= 0x100000000;
        }
        self::assertSame(VncCursor::ENCODING_CURSOR, $enc);

        // Payload: 32*32*4 bytes pixel data (4096 bytes) + (32/8)*32 mask bytes (128 bytes) = 4224 bytes
        $payloadLen = strlen($rect) - 12;
        self::assertSame(4096 + 128, $payloadLen);
    }

    public function test_skull_cursor_structure(): void
    {
        $rect = VncCursor::buildRectangle('skull');
        self::assertNotEmpty($rect);

        $hdr = substr($rect, 0, 12);
        $fields = unpack('nhotx/nhoty/nw/nh/Nenc', $hdr);

        self::assertSame(16, $fields['hotx']);
        self::assertSame(14, $fields['hoty']);
        self::assertSame(32, $fields['w']);
        self::assertSame(32, $fields['h']);

        $enc = $fields['enc'];
        if ($enc >= 0x80000000) {
            $enc -= 0x100000000;
        }
        self::assertSame(VncCursor::ENCODING_CURSOR, $enc);

        $payloadLen = strlen($rect) - 12;
        self::assertSame(4096 + 128, $payloadLen);
    }

    public function test_invisible_cursor(): void
    {
        $rect = VncCursor::buildRectangle('invisible');
        self::assertNotEmpty($rect);

        $fields = unpack('nhotx/nhoty/nw/nh/Nenc', substr($rect, 0, 12));
        self::assertSame(1, $fields['w']);
        self::assertSame(1, $fields['h']);
    }

    public function test_none_cursor_returns_empty(): void
    {
        // 'none' means send no cursor at all. 'normal' now renders a realistic arrow so the
        // attacker actually sees a pointer (clients that negotiate -239 hide their local one).
        self::assertSame('', VncCursor::buildRectangle('none'));
        self::assertNotEmpty(VncCursor::buildRectangle('normal'));
    }

    public function test_arrow_cursor_structure(): void
    {
        $rect = VncCursor::buildRectangle('normal');
        self::assertNotEmpty($rect);

        $fields = unpack('nhotx/nhoty/nw/nh/Nenc', substr($rect, 0, 12));
        $enc = $fields['enc'] >= 0x80000000 ? $fields['enc'] - 0x100000000 : $fields['enc'];
        self::assertSame(VncCursor::ENCODING_CURSOR, $enc);
        self::assertGreaterThan(0, $fields['w']);
        self::assertGreaterThan(0, $fields['h']);
        // Arrow hotspot is the tip, at the top-left.
        self::assertLessThanOrEqual(2, $fields['hotx']);
        self::assertLessThanOrEqual(2, $fields['hoty']);
    }

    public function test_build_server_cut_text(): void
    {
        $msg = VncServer::buildServerCutText('ACCESS DENIED');
        // Type (1 byte) = 3
        self::assertSame("\x03", $msg[0]);
        // Padding = 3 zero bytes
        self::assertSame("\x00\x00\x00", substr($msg, 1, 3));
        // Length = uint32_be(13)
        self::assertSame(13, unpack('N', substr($msg, 4, 4))[1]);
        // Content
        self::assertSame('ACCESS DENIED', substr($msg, 8));
    }

    public function test_vnc_config_from_env(): void
    {
        putenv('FUNNYPOT_STYLE=taunt');
        putenv('FUNNYPOT_VNC_WIDTH=1024');
        putenv('FUNNYPOT_VNC_HEIGHT=768');
        putenv('FUNNYPOT_VNC_CLIPBOARD=HA_HA_HA');
        putenv('FUNNYPOT_VNC_BEEP=false');
        putenv('FUNNYPOT_VNC_CHAOS_RESIZE=true');
        putenv('FUNNYPOT_VNC_MASSIVE_WIDTH=16000');
        putenv('FUNNYPOT_VNC_MASSIVE_HEIGHT=9000');

        $cfg = VncConfig::fromEnv();

        self::assertSame('taunt', $cfg->style);
        self::assertSame(1024, $cfg->width);
        self::assertSame(768, $cfg->height);
        self::assertSame('HA_HA_HA', $cfg->clipboard);
        self::assertFalse($cfg->beep);
        self::assertTrue($cfg->chaosResize);
        self::assertSame(16000, $cfg->massiveWidth);
        self::assertSame(9000, $cfg->massiveHeight);

        // Reset env
        putenv('FUNNYPOT_STYLE');
        putenv('FUNNYPOT_VNC_WIDTH');
        putenv('FUNNYPOT_VNC_HEIGHT');
        putenv('FUNNYPOT_VNC_CLIPBOARD');
        putenv('FUNNYPOT_VNC_BEEP');
        putenv('FUNNYPOT_VNC_CHAOS_RESIZE');
        putenv('FUNNYPOT_VNC_MASSIVE_WIDTH');
        putenv('FUNNYPOT_VNC_MASSIVE_HEIGHT');
    }

    /**
     * The service-specific style must beat the global one: the Docker image always sets
     * FUNNYPOT_STYLE (default realistic), so if the global wins, FUNNYPOT_VNC_STYLE can
     * never enable taunt for VNC alone.
     */
    public function test_vnc_style_overrides_global_style(): void
    {
        putenv('FUNNYPOT_STYLE=realistic');
        putenv('FUNNYPOT_VNC_STYLE=taunt');

        $cfg = VncConfig::fromEnv();
        self::assertSame('taunt', $cfg->style);

        putenv('FUNNYPOT_STYLE');
        putenv('FUNNYPOT_VNC_STYLE');
    }

    public function test_global_style_applies_when_no_vnc_style(): void
    {
        putenv('FUNNYPOT_STYLE=taunt');
        putenv('FUNNYPOT_VNC_STYLE');

        $cfg = VncConfig::fromEnv();
        self::assertSame('taunt', $cfg->style);

        putenv('FUNNYPOT_STYLE');
    }

    public function test_taskbar_clock_overlay_draws_text(): void
    {
        $w = 1536;
        $h = 1024;
        $im = imagecreatetruecolor($w, $h);
        imagefilledrectangle($im, 0, 0, $w - 1, $h - 1, imagecolorallocate($im, 0, 0, 0));

        VncThemeRenderer::drawTaskbarClock($im, $w, $h, 1000000000);

        // The clock region should now hold bright text pixels.
        $bright = false;
        for ($y = (int) ($h * 0.930); $y < (int) ($h * 0.966) && !$bright; $y++) {
            for ($x = (int) ($w * 0.915); $x < (int) ($w * 0.961); $x++) {
                if ((imagecolorat($im, $x, $y) & 0xFF) > 200) {
                    $bright = true;
                    break;
                }
            }
        }
        imagedestroy($im);

        self::assertTrue($bright, 'taskbar clock overlay must render visible text');
    }

    public function test_server_name_matches_staking_persona(): void
    {
        // The bundled eth.png is a fake ETH staking wallet, so the RFB desktop name
        // presents the matching persona rather than a generic OS name.
        putenv('FUNNYPOT_VNC_IMAGE=' . dirname(__DIR__, 3) . '/demo/assets/eth.png');
        putenv('FUNNYPOT_VNC_NAME');

        $cfg = VncConfig::fromEnv();
        self::assertNotNull($cfg->image);
        self::assertSame('ETH staking SRV02', $cfg->serverName);

        putenv('FUNNYPOT_VNC_IMAGE');
    }

    public function test_extended_desktop_size_reports_six_absurd_monitors(): void
    {
        $rect = VncServer::buildExtendedDesktopSize(VncServer::absurdScreens());

        // Pseudo-rectangle header: reason, result, framebuffer w/h, encoding.
        $hdr = unpack('nreason/nresult/nw/nh/Nenc', substr($rect, 0, 12));
        $enc = $hdr['enc'] >= 0x80000000 ? $hdr['enc'] - 0x100000000 : $hdr['enc'];
        self::assertSame(-308, $enc, 'encoding must be ExtendedDesktopSize');
        // Bounding box of the six scattered monitors.
        self::assertSame(8192, $hdr['w']);
        self::assertSame(7880, $hdr['h']);

        // Payload: number-of-screens (1) + 3 padding, then 16 bytes per screen.
        self::assertSame(6, ord($rect[12]));
        self::assertSame(12 + 4 + (6 * 16), strlen($rect));
    }

    public function test_taunt_auto_expires_after_duration(): void
    {
        $config = new VncConfig(style: 'taunt', tauntDurationSec: 10.0);
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('203.0.113.9', 5900, 1);
        $s->taunting = true;
        $s->tauntStartTime = 100.0;

        self::assertFalse($server->tauntExpired($s, 105.0));
        self::assertTrue($server->tauntExpired($s, 110.5));
    }

    public function test_taunt_never_expires_when_not_taunting(): void
    {
        $config = new VncConfig(style: 'taunt', tauntDurationSec: 10.0);
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('203.0.113.9', 5900, 1);
        $s->tauntStartTime = 100.0;

        self::assertFalse($server->tauntExpired($s, 999.0));
    }

    public function test_backpressure_stops_queueing_frames_when_outbuf_backs_up(): void
    {
        $config = new VncConfig(style: 'taunt');
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('203.0.113.9', 5900, 1);

        self::assertTrue($server->canQueueFrame($s));
        self::assertFalse($server->outbufOverflowed($s));

        // Simulate a client that has stopped reading: outbuf fills up.
        $s->outbuf = str_repeat('x', 7 * 1024 * 1024);
        self::assertFalse($server->canQueueFrame($s), 'must stop queueing past the soft cap');

        $s->outbuf = str_repeat('x', 30 * 1024 * 1024);
        self::assertTrue($server->outbufOverflowed($s), 'must flag overflow past the hard cap');
    }

    public function test_animation_frame_output_stays_bounded(): void
    {
        // The massive strobe frame must never paint a massive framebuffer — it announces a huge
        // desktop but paints a capped image. One frame must be well under the memory-limit danger zone.
        $config = new VncConfig(style: 'taunt', strobeResize: true, massiveWidth: 8192, massiveHeight: 8192);
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('203.0.113.9', 5900, 1);
        $s->supportsDesktopSize = true;
        $s->taunting = true;
        $s->animationFrame = 0; // even => massive announce

        $server->pushAnimationFrame($s);
        self::assertLessThan(6 * 1024 * 1024, strlen($s->outbuf));
    }

    public function test_cursor_near_popup_detection(): void
    {
        $config = new VncConfig(style: 'taunt', width: 1024, height: 768);
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('1.2.3.4', 5900, 1);
        $s->popupX = 300;
        $s->popupY = 200;

        self::assertTrue($server->cursorNearPopup($s, 350, 250));   // inside the dialog
        self::assertTrue($server->cursorNearPopup($s, 270, 200));   // within the margin
        self::assertFalse($server->cursorNearPopup($s, 5, 5));      // far away

        // Before the dialog is placed there is nothing to be near.
        $fresh = new VncSession('1.2.3.4', 5900, 2);
        self::assertFalse($server->cursorNearPopup($fresh, 350, 250));
    }

    public function test_relocate_popup_moves_away_but_stays_on_screen(): void
    {
        $w = 1024;
        $h = 768;
        $config = new VncConfig(style: 'taunt', width: $w, height: $h);
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('1.2.3.4', 5900, 1);
        $s->clicked = true;
        $s->popupX = 332; // centred
        $s->popupY = 309;

        $cursorX = $s->popupX + 180;
        $cursorY = $s->popupY + 75;

        self::assertTrue($server->relocatePopup($s, $cursorX, $cursorY));

        // It moved...
        self::assertTrue($s->popupX !== 332 || $s->popupY !== 309);
        // ...but the whole dialog is still on screen.
        self::assertGreaterThanOrEqual(0, $s->popupX);
        self::assertGreaterThanOrEqual(0, $s->popupY);
        self::assertLessThanOrEqual($w, $s->popupX + 360);
        self::assertLessThanOrEqual($h, $s->popupY + 150);
        self::assertNotEmpty($s->outbuf, 'a relocate repaints the framebuffer');
    }

    public function test_relocate_never_pushes_dialog_off_screen_at_an_edge(): void
    {
        $w = 1024;
        $h = 768;
        $config = new VncConfig(style: 'taunt', width: $w, height: $h);
        $server = new VncServer($config, static fn () => null);
        $s = new VncSession('1.2.3.4', 5900, 1);
        $s->clicked = true;
        // Dialog already jammed into the top-left; cursor pushes further into the corner.
        $s->popupX = 20;
        $s->popupY = 20;

        self::assertTrue($server->relocatePopup($s, 0, 0));

        self::assertGreaterThanOrEqual(0, $s->popupX);
        self::assertGreaterThanOrEqual(0, $s->popupY);
        self::assertLessThanOrEqual($w, $s->popupX + 360);
        self::assertLessThanOrEqual($h, $s->popupY + 150);
    }

    public function test_garbage_farewell_is_invalid_and_bounded(): void
    {
        $g = VncServer::buildGarbageFarewell();

        self::assertNotEmpty($g);
        self::assertLessThan(16384, strlen($g));
        // Fake version banner mid-stream.
        self::assertStringContainsString('RFB 999.999', $g);
        // Unknown server->client message types (>= 4 are all invalid).
        self::assertStringContainsString("\xFF\xFE\xFD", $g);
        // A rectangle with a bogus encoding.
        self::assertStringContainsString(pack('N', 0x41414141), $g);
        // A ServerCutText that lies about its length.
        self::assertStringContainsString("\x03\x00\x00\x00" . pack('N', 0xFFFFFFFF), $g);
    }
}
