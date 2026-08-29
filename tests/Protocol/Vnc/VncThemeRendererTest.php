<?php

declare(strict_types=1);

namespace Funnypot\Tests\Protocol\Vnc;

use Funnypot\Protocol\Vnc\VncConfig;
use Funnypot\Protocol\Vnc\VncThemeRenderer;
use PHPUnit\Framework\TestCase;

final class VncThemeRendererTest extends TestCase
{
    public function test_render_win95_theme(): void
    {
        $cfg = new VncConfig(width: 800, height: 600);
        $renderer = new VncThemeRenderer($cfg);

        $bgra = $renderer->renderBgra('198.51.100.22', 5900);
        // Byte length must exactly equal width * height * 4
        self::assertSame(800 * 600 * 4, strlen($bgra));
    }

    public function test_render_troll_taunt_alternating_frames(): void
    {
        $cfg = new VncConfig(style: 'taunt', width: 800, height: 600);
        $renderer = new VncThemeRenderer($cfg);

        // Frame 0: Red Giant Trollface
        $frame0 = $renderer->renderBgra('10.0.0.1', 5900, 0);
        self::assertSame(800 * 600 * 4, strlen($frame0));

        // Frame 1: Black Skull ASCII
        $frame1 = $renderer->renderBgra('10.0.0.1', 5900, 1);
        self::assertSame(800 * 600 * 4, strlen($frame1));

        // Ensure the two frames are visually distinct
        self::assertNotSame($frame0, $frame1);
    }
}
