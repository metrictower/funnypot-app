<?php
declare(strict_types=1);
namespace Funnypot\App\Render\Panel;

use Funnypot\App\Render\Fake\ServerProfile;
use Funnypot\App\Render\VisualPersona;

/**
 * Databases: a phpMyAdmin-style Browse illusion, and the home of the users loot after the T1 de-tell.
 *
 * The password_hash column NO LONGER rides on the dashboard landing. It lives one drill-down deep, on
 * the `users` table Browse page — reached from the Databases landing (`/<mount>/databases`) or the
 * legacy `/<mount>/users` slug. The landing itself shows only a schema/table catalogue (names, engines,
 * row counts, sizes) with no secrets, which is where "a real admin tool shows that convention correctly."
 */
final class DatabasesSection extends AbstractPanelSection
{
    /** appdb schema catalogue: table => [engine, rowSalt]. `users` is the loot table. */
    private const TABLES = [
        'users' => 'InnoDB',
        'roles' => 'InnoDB',
        'sessions' => 'InnoDB',
        'api_tokens' => 'InnoDB',
        'orders' => 'InnoDB',
        'invoices' => 'InnoDB',
        'audit_log' => 'InnoDB',
        'migrations' => 'InnoDB',
    ];

    public function render(array $route, VisualPersona $persona, string $navBase): string
    {
        $seed = $persona->seed();
        $sp = ServerProfile::fromSeed($seed);

        // `/mount/users` (module=users) and `/mount/databases/users` (section=users) both land on loot.
        $table = $route['module'] === 'users' ? 'users' : $route['section'];

        if ($table === '') {
            return $this->landing($seed, $navBase);
        }
        if ($table === 'users') {
            return $this->usersBrowse($sp, $persona, $navBase);
        }
        return $this->genericBrowse($seed, $table, $navBase);
    }

    /** Schema catalogue — no secrets, just the table list a DB admin tool opens on. */
    private function landing(int $seed, string $navBase): string
    {
        $rowsHtml = '';
        foreach (self::TABLES as $name => $engine) {
            $count = $this->rowCount($seed, $name);
            $size = $this->tableSize($seed, $name);
            $browse = '<a class="alte-dl" href="' . $this->esc($navBase . '/databases/' . $name) . '">Browse</a>';
            $rowsHtml .= '<tr><td>' . $this->esc($name) . '</td><td>' . $this->esc($engine) . '</td><td>'
                . $this->esc(number_format($count)) . '</td><td>' . $this->esc($size) . '</td><td>' . $browse . '</td></tr>';
        }
        $table = '<table class="alte-table"><thead><tr><th>Table</th><th>Engine</th><th>Rows</th><th>Size</th><th></th></tr></thead><tbody>'
            . $rowsHtml . '</tbody></table>';
        return $this->breadcrumbHtml($this->baseCrumbs($navBase, 'Databases'))
            . $this->card('appdb', $table, count(self::TABLES) . ' tables · utf8mb4');
    }

    /** The users table Browse: the loot with the password_hash column — one drill-down deep, never the
     *  landing (T1). Emails use the persona domain so the loot stays coherent with the host identity. */
    private function usersBrowse(ServerProfile $sp, VisualPersona $persona, string $navBase): string
    {
        $rows = $sp->lootUsers($persona->domain());
        $total = $sp->lootRowCount('users');
        $table = $this->tableHtml(['id', 'username', 'email', 'role', 'password_hash'], $rows, ' class="alte-table"');
        $table .= '<div class="alte-pager">Showing 1&ndash;' . count($rows) . ' of ' . number_format($total) . ' rows</div>';
        $crumbs = [['Corevance', $navBase], ['Databases', $navBase . '/databases'], ['appdb.users', '']];
        return $this->breadcrumbHtml($crumbs) . $this->card('users', $table, 'appdb · InnoDB');
    }

    /** Any other table: a small, benign seeded Browse so a drill-down never dead-ends in a 404 (a 404
     *  inside a deep panel is a tell). No secrets — id + a couple of generic columns. */
    private function genericBrowse(int $seed, string $table, string $navBase): string
    {
        $total = $this->rowCount($seed, $table);
        $rows = [];
        $show = $total < 25 ? $total : 25;
        for ($i = 0; $i < $show; $i++) {
            $id = (string) (1 + $i);
            $created = $this->daysAgo($seed, $table . '|' . $i);
            $rows[] = [$id, 'row-' . sprintf('%06d', $this->rowRef($seed, $table . '|' . $i)), $created];
        }
        $html = $this->tableHtml(['id', 'ref', 'created'], $rows, ' class="alte-table"');
        $html .= '<div class="alte-pager">Showing 1&ndash;' . $show . ' of ' . number_format($total) . ' rows</div>';
        $crumbs = [['Corevance', $navBase], ['Databases', $navBase . '/databases'], ['appdb.' . $table, '']];
        return $this->breadcrumbHtml($crumbs) . $this->card($table, $html, 'appdb · InnoDB');
    }

    // --- deterministic seeded scalars (no time()/rand(); frozen per seed) ---

    private function h(int $seed, string $salt): int
    {
        return (int) hexdec(substr(hash('sha256', $seed . '|dbsec|' . $salt), 0, 13));
    }

    private function rowCount(int $seed, string $table): int
    {
        if ($table === 'migrations') {
            return 60 + ($this->h($seed, 'rc|migrations') % 80);
        }
        if ($table === 'audit_log') {
            return 50000 + ($this->h($seed, 'rc|audit') % 400000);
        }
        return 500 + ($this->h($seed, 'rc|' . $table) % 90000);
    }

    private function tableSize(int $seed, string $table): string
    {
        $mb = 1 + ($this->h($seed, 'sz|' . $table) % 2400);
        if ($mb < 1024) {
            return $mb . ' MB';
        }
        return number_format($mb / 1024, 1) . ' GB';
    }

    private function rowRef(int $seed, string $salt): int
    {
        return $this->h($seed, 'ref|' . $salt) % 1000000;
    }

    private function daysAgo(int $seed, string $salt): string
    {
        $d = $this->h($seed, 'age|' . $salt) % 900;
        return $d . ' d ago';
    }
}
