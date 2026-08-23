<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\App\Render\VisualPersona;

/** Backups: downloadable archive lures. Each filename keeps its archive extension so the link routes
 *  to the decoy-archive handler (migrated from AdminLteSkin::backupsCard). */
final class BackupsSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $sp = ServerProfile::fromSeed($persona->seed());
        $rows = [];
        foreach ($sp->backups() as $b) {
            $rows[] = ['file' => $b['name'], 'cells' => [$b['size'], $b['age'], 'Download']];
        }
        // Downloads route to $navBase/backups/<file> so the mount-rooted path reaches the decoy handler.
        $table = $this->downloadTableHtml(['File', 'Size', 'Created', ''], $rows, $navBase, '/backups', ' class="alte-table"', 'alte-dl');
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Backups'))
            . $this->card('Backups', $table, 'Keep last 7 · retain 30 days');
    }
}
