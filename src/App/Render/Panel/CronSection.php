<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FakeCron;
use Funnypot\Support\VisualPersona;

/** Scheduled tasks: the seeded crontab (migrated from AdminLteSkin::cronCard). */
final class CronSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $rows = [];
        foreach (FakeCron::fromSeed($persona->seed())->cronJobs() as $c) {
            $rows[] = [$c['schedule'], $c['user'], $c['command']];
        }
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Scheduled Tasks'))
            . $this->card('Scheduled Tasks', $this->tableHtml(['Schedule', 'User', 'Command'], $rows, ' class="alte-table alte-mono"'), 'crontab');
    }
}
