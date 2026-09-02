<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Docker;

use PHPUnit\Framework\TestCase;

/**
 * The paramount invariant for a container decoy (AC3): the Docker seam NEVER executes a command, spawns
 * a process, opens a socket/network connection, resolves a host, pulls from a real registry, writes to a
 * real docker socket, or touches the host filesystem. This is a STRUCTURAL guarantee — a static scan of
 * every `src/App/Docker/*.php` source for call-shaped process/network/FS primitives and for a
 * docker-socket path used as anything but a matched signal string.
 *
 * The scan is deliberately anchored (per the plan-review addendum) so it is neither vacuous nor
 * self-contradictory: `EscapeIntent.php` legitimately CONTAINS the literal `/var/run/docker.sock` for
 * the bind-docker-sock signal, so the socket-path token is allowed there (and only there) while every
 * call-shaped primitive is banned everywhere. A positive-control fixture proves the regexes bite.
 */
final class DockerNeverExecutesTest extends TestCase
{
    /** Process / command execution — anchored so `->execute(`, `execId(`, `'exec-create'` don't trip. */
    private const EXEC_RE = '/(?<![\w>:$])(?:exec|shell_exec|system|passthru|proc_open|popen)\s*\(/';

    /** A backtick anywhere in the source is a shell-exec operator. */
    private const BACKTICK_RE = '/\x60/';

    /** Filesystem / network / deserialisation primitives (call-shaped), banned everywhere in the seam. */
    private const IO_RES = [
        '/\b(?:file_get_contents|fopen|readfile|fsockopen|pfsockopen|stream_socket_client|stream_socket_server|stream_context_create|socket_create|socket_connect|gethostbynamel|gethostbyname|dns_get_record|checkdnsrr|eval|unserialize|mkdir|rmdir|unlink|symlink|link|chmod|chown|rename|touch)\s*\(/',
        '/(?<![\w>])file\s*\(/',
        '/\bcurl_\w+\s*\(/',
        '/\b(?:include|require)(?:_once)?\s*[\(\'"]/',
    ];

    /** A `unix://` scheme is only ever used to OPEN a socket — never legitimate in the seam. */
    private const UNIX_SCHEME_RE = '#unix://#';

    /** Docker-socket path literals — allowed ONLY in EscapeIntent.php (the bind-docker-sock signal). */
    private const SOCKET_PATH_RE = '#/(?:var/)?run/(?:docker\.sock|containerd/containerd\.sock)#';

    /** @return array<string,array{0:string}> file basename => [path] */
    public static function dockerSources(): array
    {
        $dir = dirname(__DIR__, 3) . '/src/App/Docker';
        $out = [];
        foreach ((array) glob($dir . '/*.php') as $path) {
            $out[basename((string) $path)] = [(string) $path];
        }
        self::assertArrayHasKeyStatic('DockerApiResponder.php', $out);

        return $out;
    }

    private static function assertArrayHasKeyStatic(string $key, array $arr): void
    {
        if (!array_key_exists($key, $arr)) {
            throw new \RuntimeException('expected Docker sources to include ' . $key);
        }
    }

    /**
     * PHP CODE only: comments blanked and string-literal CONTENTS blanked, so a backtick or a
     * primitive name that appears in a docblock or a matched signal string is not a false positive,
     * while a real call (`proc_open($x)`) or a real backtick operator survives to be caught.
     */
    private static function codeOnly(string $src): string
    {
        $out = '';
        foreach (token_get_all($src) as $tok) {
            if (is_array($tok)) {
                if (in_array($tok[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    $out .= ' ';
                    continue;
                }
                if ($tok[0] === T_CONSTANT_ENCAPSED_STRING || $tok[0] === T_ENCAPSED_AND_WHITESPACE) {
                    $out .= "''";   // keep a token here, drop the literal contents
                    continue;
                }
                $out .= $tok[1];
                continue;
            }
            $out .= $tok;   // single-char token, incl. the backtick shell-exec operator
        }

        return $out;
    }

    /** @dataProvider dockerSources */
    public function test_source_has_no_process_or_network_primitive(string $path): void
    {
        $raw = (string) file_get_contents($path);
        $code = self::codeOnly($raw);
        $base = basename($path);

        self::assertSame(0, preg_match(self::EXEC_RE, $code), "process-exec primitive in {$base}");
        self::assertSame(0, preg_match(self::BACKTICK_RE, $code), "backtick shell-exec in {$base}");
        foreach (self::IO_RES as $re) {
            self::assertSame(0, preg_match($re, $code), "I/O primitive ({$re}) in {$base}");
        }
        // The socket path / unix:// checks run on RAW source so the signal-string rule is enforced.
        self::assertSame(0, preg_match(self::UNIX_SCHEME_RE, $raw), "unix:// socket scheme in {$base}");
        if ($base !== 'EscapeIntent.php') {
            self::assertSame(0, preg_match(self::SOCKET_PATH_RE, $raw), "a docker-socket path in {$base} (only EscapeIntent may hold it, as a signal string)");
        }
    }

    /** The EscapeIntent socket literals are matched as strings only, never adjacent to an open/connect. */
    public function test_escape_intent_socket_literal_is_a_signal_not_a_connection(): void
    {
        $raw = (string) file_get_contents(dirname(__DIR__, 3) . '/src/App/Docker/EscapeIntent.php');
        $code = self::codeOnly($raw);
        self::assertSame(1, preg_match(self::SOCKET_PATH_RE, $raw), 'EscapeIntent should carry the sock literal for the signal');
        // ...but no call-shaped opener anywhere in its code.
        self::assertSame(0, preg_match(self::EXEC_RE, $code));
        foreach (self::IO_RES as $re) {
            self::assertSame(0, preg_match($re, $code));
        }
    }

    /** Positive control: the regex set is NOT vacuous — it matches a fixture that really executes. */
    public function test_the_scan_is_non_vacuous(): void
    {
        $bad = "<?php proc_open('id', [], \$p); \$x = `whoami`; fsockopen('evil.example', 2375);";
        $hit = preg_match(self::EXEC_RE, $bad) === 1
            || preg_match(self::BACKTICK_RE, $bad) === 1;
        foreach (self::IO_RES as $re) {
            $hit = $hit || preg_match($re, $bad) === 1;
        }
        self::assertTrue($hit, 'an empty/broken regex must not pass a genuinely executing fixture');

        // And each family bites its own primitive.
        self::assertSame(1, preg_match(self::EXEC_RE, '<?php system("id");'));
        self::assertSame(1, preg_match(self::UNIX_SCHEME_RE, 'fsockopen("unix:///var/run/docker.sock")'));
    }

    /** The demo/index.php Docker wiring block references no socket path or unix:// scheme. */
    public function test_index_php_docker_block_touches_no_socket(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 3) . '/demo/index.php');
        $start = strpos($src, 'Fake Docker Engine API decoy');
        self::assertNotFalse($start);
        $block = substr($src, $start, 900);
        self::assertSame(0, preg_match(self::SOCKET_PATH_RE, $block));
        self::assertSame(0, preg_match(self::UNIX_SCHEME_RE, $block));
        self::assertStringContainsString('docker.sqlite', $block, 'the only I/O is the app\'s own bounded SQLite');
    }
}
