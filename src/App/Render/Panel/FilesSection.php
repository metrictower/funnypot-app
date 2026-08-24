<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FakeFiles;
use Funnypot\Support\VisualPersona;

/** File manager: per-directory listings; only downloadable files link (keeping their extension so they
 *  route to the decoy-archive handler), dirs and text lures stay plain (migrated from
 *  AdminLteSkin::filesCard). */
final class FilesSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $ff = FakeFiles::fromSeed($persona->seed());
        $out = $this->breadcrumbHtml($this->baseCrumbs($navBase, 'File Manager'));
        foreach ($ff->dirs() as $dir) {
            $rows = '';
            foreach ($ff->listing($dir) as $f) {
                $name = $f['name'];
                $label = $f['isDir'] ? $this->esc($name . '/') : $this->esc($name);
                // Only downloadable files become links (they keep their extension -> decoy-archive handler);
                // dirs and text lures render as plain text.
                if ($f['isDownload'] && preg_match('/^[A-Za-z0-9._-]+$/', $name) === 1 && strpos($name, '..') === false) {
                    $label = '<a class="fp-dl" href="' . $this->esc($navBase . '/files/download/' . $name) . '">' . $this->esc($name) . '</a>';
                }
                $rows .= '<tr><td>' . $label . '</td><td>' . $this->esc($f['size']) . '</td><td>' . $this->esc($f['modified'])
                    . '</td><td>' . $this->esc($f['perms']) . '</td><td>' . $this->esc($f['owner']) . '</td></tr>';
            }
            $table = '<table class="alte-table alte-mono"><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Perms</th><th>Owner</th></tr></thead><tbody>'
                . $rows . '</tbody></table>';
            $out .= $this->card($dir, $table, 'file manager');
        }
        return $out;
    }
}
