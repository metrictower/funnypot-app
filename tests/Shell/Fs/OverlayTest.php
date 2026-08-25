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
        return new FakeFilesystem(Draw::seed("s\0h\0dev"), 'developer', 7);
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

    public function test_child_under_removed_dir_is_unreachable(): void
    {
        // rm -rf /tmp/d then a child under it must NOT resolve (ancestor validation, not a bare lookup).
        $fs = $this->base()->withOverlay(
            (new Overlay())->withDir('/tmp/d')->withFile('/tmp/d/f', 'x')->withRemoved('/tmp/d')
        );
        self::assertFalse($fs->exists('/tmp/d'));
        self::assertFalse($fs->exists('/tmp/d/f'));
    }

    public function test_read_under_removed_pinned_dir_throws(): void
    {
        // rm -rf /etc ; cat /etc/passwd must fail — a pinned file under a tombstoned ancestor is gone.
        $fs = $this->base()->withOverlay((new Overlay())->withRemoved('/etc'));
        $this->expectException(\Funnypot\Shell\Fs\PathNotFound::class);
        $fs->read('/etc/passwd');
    }

    public function test_overlay_file_size_matches_and_siblings_read_unchanged(): void
    {
        $base = $this->base();
        $before = $base->read('/etc/passwd'); // pinned sibling, guaranteed present

        $fs = $base->withOverlay((new Overlay())->withFile('/etc/injected.php', '<?php echo 1;'));
        self::assertSame(strlen('<?php echo 1;'), $fs->stat('/etc/injected.php')->size);
        self::assertSame('<?php echo 1;', $fs->read('/etc/injected.php'));
        self::assertSame($before, $fs->read('/etc/passwd')); // sibling bytes unchanged
    }

    public function test_overlay_round_trips_through_array(): void
    {
        $o = (new Overlay())->withFile('/tmp/a', 'aa')->withDir('/tmp/d')->withRemoved('/var/log');
        $r = Overlay::fromArray($o->toArray());
        self::assertSame('aa', $r->fileBytes('/tmp/a'));
        self::assertTrue($r->isRemoved('/var/log'));
    }

    public function test_overlay_refuses_growth_past_the_byte_ceiling(): void
    {
        // Bound the persisted per-session diff: past ~256 KiB, a net-growth write is a no-op (ENOSPC).
        $o = new Overlay();
        $blob = str_repeat('x', 4096);
        for ($i = 0; $i < 200; $i++) {                 // 200 * 4 KiB ~= 800 KiB attempted
            $o = $o->withFile('/tmp/f' . $i, $blob);
        }
        $bytes = strlen((string) json_encode($o->toArray()));
        self::assertLessThan(300000, $bytes);          // capped well under the attempted 800 KiB

        // Overwriting an existing key (no net growth) is still allowed even at the ceiling.
        $existing = null;
        foreach ($o->toArray()['files'] as $path => $_) {
            $existing = (string) $path;
            break;
        }
        self::assertNotNull($existing);
        $o2 = $o->withFile($existing, 'small');
        self::assertSame('small', $o2->fileBytes($existing));
    }
}
