<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\FakeLog;
use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\Core\Support\VisualPersona;

/** Logs: long, deterministic auth.log + access.log scroll-backs (migrated from AdminLteSkin::logsCard). */
final class LogsSection extends AbstractPanelSection
{
    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $seed = $persona->seed();
        $log = FakeLog::fromSeed($seed);
        // The auth-log path must match the OS this seed already picked (RHEL-family logs to
        // /var/log/secure, Debian-family to /var/log/auth.log) — a path/OS mismatch is a tell.
        $authPath = ServerProfile::fromSeed($seed)->authLogPath();
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Logs'))
            . $this->card('auth.log', $this->preScrollHtml($log->authLog(400), 'alte-log'), $authPath)
            . $this->card('access.log', $this->preScrollHtml($log->accessLog(200), 'alte-log'), '/var/log/nginx/access.log');
    }
}
