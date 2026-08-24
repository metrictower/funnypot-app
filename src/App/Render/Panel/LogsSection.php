<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FakeLog;
use Funnypot\Support\VisualPersona;

/** Logs: long, deterministic auth.log + access.log scroll-backs (migrated from AdminLteSkin::logsCard). */
final class LogsSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $log = FakeLog::fromSeed($persona->seed());
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Logs'))
            . $this->card('auth.log', $this->preScrollHtml($log->authLog(400), 'alte-log'), '/var/log/auth.log')
            . $this->card('access.log', $this->preScrollHtml($log->accessLog(200), 'alte-log'), '/var/log/nginx/access.log');
    }
}
