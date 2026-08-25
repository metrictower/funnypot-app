<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FakeSecrets;
use Funnypot\Core\Support\VisualPersona;

/** API Keys + .env: masked, inert secret lures (migrated from AdminLteSkin::keysCard). */
final class KeysSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $fs = FakeSecrets::fromSeed($persona->seed());
        $rows = [];
        foreach ($fs->keys() as $k) {
            $rows[] = [$k['label'], $k['masked'], $k['created'], $k['lastUsed']];
        }
        $keys = $this->tableHtml(['Name', 'Key', 'Created', 'Last used'], $rows, ' class="alte-table"');
        $env = $this->kvTableHtml($fs->envVars(), ' class="alte-kv"');
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'API Keys'))
            . $this->card('API Keys', $keys, 'Reveal to copy')
            . $this->card('.env', $env, 'application environment');
    }
}
