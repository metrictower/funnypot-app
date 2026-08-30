<?php

declare(strict_types=1);

namespace Funnypot\Tests\App;

use PHPUnit\Framework\TestCase;

/**
 * Runtime boot smoke for the front controller. FrontControllerImportsTest proves every `use` import
 * resolves, but not that the controller actually BOOTS a request end to end — a constructor that
 * throws, a missing runtime file, or a service wiring fault still ships green (nothing in the unit
 * suite or the Docker build ever executes demo/index.php) and then dark-500s or leaks a stack trace on
 * the first real request. That is the same failure class as the namespace-migration outage, one layer
 * deeper than the static import check.
 *
 * This starts demo/index.php under the PHP built-in server against a fully isolated temp data dir (no
 * LLM sidecar, no external reporters, no touch of demo/storage) and asserts a synthetic scanner probe
 * comes back with a plausible status and a body free of any PHP fault or absolute-path leak — mirroring
 * the "only ever upgrade a 404, never escape as a 5xx" invariant for the whole app, not just the LLM.
 */
final class FrontControllerBootSmokeTest extends TestCase
{
    private const READY_TIMEOUT = 8.0;

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open disabled — cannot spawn the built-in server');
        }
        if (PHP_BINARY === '' || !is_executable(PHP_BINARY)) {
            self::markTestSkipped('no usable PHP CLI binary to run the built-in server');
        }
    }

    /** @dataProvider probes */
    public function test_front_controller_boots_without_leaking_a_fault(string $probe, bool $mustBeServed): void
    {
        $root = dirname(__DIR__, 2);
        $index = $root . '/demo/index.php';
        self::assertFileExists($index);

        $data = $this->tempDir('fpboot_data');
        // An EMPTY docroot means no request maps to a static file, so every path is dispatched through
        // the router (the real front controller) exactly as nginx + php-fpm route it in prod.
        $docroot = $this->tempDir('fpboot_doc');

        // fromEnv() honours these, so all persistence lands in the temp dir; disable the sidecar and
        // give a fixed persona so the boot makes no network calls and is deterministic.
        $env = [
            'PATH' => getenv('PATH') !== false ? (string) getenv('PATH') : '/usr/bin:/bin',
            'FUNNYPOT_DB' => $data . '/funnypot.sqlite',
            'FUNNYPOT_LOG' => $data . '/hits.log',
            'FUNNYPOT_GEO_DB' => $data . '/geo.csv',
            'FUNNYPOT_VULNS' => $data . '/vulns.json',
            'FUNNYPOT_LLM' => '0',
            'FUNNYPOT_PERSONA_SEED' => 'bootsmoke',
        ];
        // proc_open replaces the whole environment, so carry through the ini-locating vars if the parent
        // uses them — else the child PHP could load a different extension set and false-fail the boot.
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR'] as $iniVar) {
            $v = getenv($iniVar);
            if ($v !== false && $v !== '') {
                $env[$iniVar] = $v;
            }
        }

        [$proc, $pipes, $port] = $this->startServer($index, $docroot, $env);

        try {
            self::assertTrue($this->waitForReady('127.0.0.1', $port, self::READY_TIMEOUT), 'built-in server never became ready');

            [$status, $headers, $body] = $this->httpGet('127.0.0.1', $port, $probe);

            self::assertNotSame(0, $status, "front controller did not answer '{$probe}' (boot crash?)");
            self::assertLessThan(
                500,
                $status,
                "front controller returned {$status} for '{$probe}' — a boot fault escaped as a 5xx (itself a honeypot tell)"
            );

            // An attack probe MUST come back as a genuinely SERVED fake. Non-404 alone is too weak: a
            // fallback that emits a bare 200 on a mid-dispatch fault would pass it while every real
            // request is broken. The engine stamps X-Request-Id on every fake it builds and NOT on an
            // unserved/dark 404, so its presence is a positive witness that the engine classified and
            // served — distinguishing a live engine from a quiet dark-404 or a generic fallback.
            if ($mustBeServed) {
                self::assertNotSame(
                    404,
                    $status,
                    "attack probe '{$probe}' returned 404 — the deception engine is dark (booted but not serving fakes)"
                );
                self::assertArrayHasKey(
                    'x-request-id',
                    $headers,
                    "attack probe '{$probe}' answered {$status} without the engine's X-Request-Id — not a real served fake (dark engine or generic fallback)"
                );
            }

            // A leaked PHP fault or absolute source path is both an info leak and a decisive tell.
            $tells = ['Fatal error', 'Uncaught', 'Stack trace', 'Parse error', 'Call to undefined', $root];
            foreach ($tells as $tell) {
                self::assertStringNotContainsStringIgnoringCase(
                    $tell,
                    $body,
                    "response to '{$probe}' leaked a PHP fault / path fragment: '{$tell}'"
                );
            }
        } finally {
            $this->stopServer($proc, $pipes);
        }
    }

    /**
     * A bare hit (any plausible status) and an attack probe (must be SERVED, not dark-404'd). Both must
     * boot without a 5xx or a leaked fault.
     *
     * @return array<string,array{0:string,1:bool}>
     */
    public static function probes(): array
    {
        return [
            'root' => ['/', false],
            'lfi scan' => ['/index.php?page=../../../../etc/passwd', true],
        ];
    }

    // --- built-in server lifecycle -----------------------------------------------------------------

    /**
     * @param array<string,string> $env
     * @return array{0:resource,1:array<int,resource>,2:int}
     */
    private function startServer(string $index, string $docroot, array $env): array
    {
        // Try a few free ports: a port can be taken between probe-and-bind, so retry rather than flake.
        $lastErr = '';
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $port = $this->freePort();
            $cmd = [PHP_BINARY, '-d', 'display_errors=0', '-S', "127.0.0.1:{$port}", '-t', $docroot, $index];
            $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $pipes = [];
            $proc = @proc_open($cmd, $descriptors, $pipes, $docroot, $env);
            if (is_resource($proc)) {
                foreach ($pipes as $p) {
                    stream_set_blocking($p, false);
                }
                if ($this->waitForReady('127.0.0.1', $port, self::READY_TIMEOUT)) {
                    return [$proc, $pipes, $port];
                }
                // Did not come up on this port — tear down and try another.
                $lastErr = (string) stream_get_contents($pipes[2]);
                $this->stopServer($proc, $pipes);
            }
        }
        self::fail('could not start the PHP built-in server after 5 attempts' . ($lastErr !== '' ? ": {$lastErr}" : ''));
    }

    /**
     * @param resource $proc
     * @param array<int,resource> $pipes
     */
    private function stopServer($proc, array $pipes): void
    {
        foreach ($pipes as $p) {
            if (is_resource($p)) {
                @fclose($p);
            }
        }
        if (is_resource($proc)) {
            @proc_terminate($proc); // SIGTERM
            // Reap so the child does not linger as a zombie past the test.
            $running = true;
            for ($i = 0; $i < 20; $i++) {
                $st = @proc_get_status($proc);
                if (!is_array($st) || $st['running'] !== true) {
                    $running = false;
                    break;
                }
                usleep(50000);
            }
            // proc_close blocks until the child exits, so a php -S that ignored SIGTERM would wedge the
            // whole (paratest) worker here. Escalate to SIGKILL first so teardown always fails fast.
            if ($running) {
                @proc_terminate($proc, 9); // SIGKILL
            }
            @proc_close($proc);
        }
    }

    private function freePort(): int
    {
        $sock = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($sock === false) {
            self::markTestSkipped("cannot open a local socket to pick a free port: {$errstr}");
        }
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        $port = (int) substr($name, strrpos($name, ':') + 1);
        self::assertGreaterThan(0, $port, 'failed to resolve a free port');

        return $port;
    }

    private function waitForReady(string $host, int $port, float $timeout): bool
    {
        $deadline = microtime(true) + $timeout;
        while (microtime(true) < $deadline) {
            $fp = @fsockopen($host, $port, $errno, $errstr, 0.25);
            if (is_resource($fp)) {
                fclose($fp);

                return true;
            }
            usleep(100000);
        }

        return false;
    }

    /**
     * Minimal raw HTTP/1.0 GET (no keep-alive, so the server closes and we read to EOF).
     *
     * @return array{0:int,1:array<string,string>,2:string} [status, headers (lowercased keys), body]
     *                                                        status 0 == no answer
     */
    private function httpGet(string $host, int $port, string $path): array
    {
        $fp = @fsockopen($host, $port, $errno, $errstr, self::READY_TIMEOUT);
        if (!is_resource($fp)) {
            return [0, [], ''];
        }
        stream_set_timeout($fp, (int) self::READY_TIMEOUT);
        fwrite($fp, "GET {$path} HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n");

        $raw = '';
        while (!feof($fp)) {
            $chunk = fread($fp, 8192);
            if ($chunk === false) {
                break;
            }
            $raw .= $chunk;
            $meta = stream_get_meta_data($fp);
            if ($meta['timed_out']) {
                break;
            }
        }
        fclose($fp);

        $split = strpos($raw, "\r\n\r\n");
        $head = $split === false ? $raw : substr($raw, 0, $split);
        $body = $split === false ? '' : substr($raw, $split + 4);

        $status = 0;
        $headers = [];
        $lines = preg_split('/\r\n/', $head) ?: [];
        foreach ($lines as $i => $line) {
            if ($i === 0) {
                if (preg_match('#^HTTP/\d\.\d\s+(\d{3})#', $line, $m) === 1) {
                    $status = (int) $m[1];
                }
                continue;
            }
            $c = strpos($line, ':');
            if ($c !== false) {
                $headers[strtolower(trim(substr($line, 0, $c)))] = trim(substr($line, $c + 1));
            }
        }

        return [$status, $headers, $body];
    }

    // --- temp dirs ---------------------------------------------------------------------------------

    /** @var string[] */
    private array $tmpDirs = [];

    private function tempDir(string $prefix): string
    {
        $dir = sys_get_temp_dir() . '/' . $prefix . '_' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0777, true) && !is_dir($dir)) {
            self::markTestSkipped("cannot create temp dir {$dir}");
        }
        $this->tmpDirs[] = $dir;

        return $dir;
    }

    protected function tearDown(): void
    {
        foreach ($this->tmpDirs as $dir) {
            $this->rmrf($dir);
        }
        $this->tmpDirs = [];
    }

    private function rmrf(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            is_dir($path) ? $this->rmrf($path) : @unlink($path);
        }
        @rmdir($dir);
    }
}
