<?php

declare(strict_types=1);

namespace Funnypot\Tests\Shell\Fs;

use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;
use Funnypot\Shell\Fs\Overlay;
use PHPUnit\Framework\TestCase;

final class OverlayTest extends TestCase
{
    private function base(): FakeFilesystem
    {
        return new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer');
    }

    public function test_overlay_reflects_writes_without_perturbing_siblings(): void
    {
        $base = $this->base();
        $siblingsBefore = $base->list('/tmp');                 // full Node objects
        $fs = $base->withOverlay((new Overlay())->withFile('/tmp/pwned.sh', "#!/bin/sh\n"));

        self::assertTrue($fs->exists('/tmp/pwned.sh'));
        self::assertSame("#!/bin/sh\n", $fs->read('/tmp/pwned.sh'));

        // siblings unchanged in name AND all fields AND order; the new entry is appended last.
        $after = $fs->list('/tmp');
        $afterSansNew = array_values(array_filter($after, fn ($n) => $n->name !== 'pwned.sh'));
        self::assertEquals($siblingsBefore, $afterSansNew);
        self::assertSame('pwned.sh', end($after)->name);
    }

    public function test_overlay_does_not_perturb_other_directories(): void
    {
        $base = $this->base();
        $other = $base->list('/usr/lib');
        $fs = $base->withOverlay((new Overlay())->withFile('/tmp/x', 'y'));
        self::assertEquals($other, $fs->list('/usr/lib')); // a mutation under /tmp can't change /usr/lib
    }

    public function test_remove_tombstones(): void
    {
        $base = $this->base();
        $victim = $base->list('/var')[0]->name;
        $fs = $base->withOverlay((new Overlay())->withRemoved('/var/' . $victim));
        self::assertFalse($fs->exists('/var/' . $victim));
        self::assertFalse($fs->isValidChild('/var', $victim));
    }

    public function test_overlay_round_trips_through_array(): void
    {
        $o = (new Overlay())->withFile('/tmp/a', 'aa')->withDir('/tmp/d')->withRemoved('/var/log');
        $r = Overlay::fromArray($o->toArray());
        self::assertSame('aa', $r->fileBytes('/tmp/a'));
        self::assertTrue($r->isRemoved('/var/log'));
    }
}
