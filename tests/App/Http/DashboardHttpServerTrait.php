<?php

declare(strict_types=1);

namespace Funnypot\Tests\App\Http;

/**
 * Shared PHP-built-in-server lifecycle for tests that need to observe REAL HTTP response headers off
 * demo/index.php (FP-0250 §4.1/§4.4). Under the phpunit CLI SAPI, header()/http_response_code() are
 * no-ops for introspection purposes (headers_list() stays empty — DashboardController.php's admin()
 * docblock notes the same CLI limitation for http_response_code()), so a CSP/Referrer-Policy/nonce
 * assertion has to go over the wire. This mirrors FrontControllerBootSmokeTest's proven boot-a-real-
 * server idiom (same isolated-temp-dir env, same free-port retry, same SIGTERM-then-SIGKILL teardown),
 * generalised to arbitrary method/headers/body/cookies so a test can log in and then inspect the
 * authed shell's real response.
 */
trait DashboardHttpServerTrait
{
    private const READY_TIMEOUT = 8.0;

    /** @var string[] */
    private array $httpTmpDirs = [];

    /**
     * @param array<string,string> $env
     * @return array{0:resource,1:array<int,resource>,2:int}
     */
    private function startDashboardServer(string $index, string $docroot, array $env): array
    {
        $lastErr = '';
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $port = $this->freeDashboardPort();
            $cmd = [PHP_BINARY, '-d', 'display_errors=0', '-S', "127.0.0.1:{$port}", '-t', $docroot, $index];
            $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $pipes = [];
            $proc = @proc_open($cmd, $descriptors, $pipes, $docroot, $env);
            if (is_resource($proc)) {
                foreach ($pipes as $p) {
                    stream_set_blocking($p, false);
                }
                if ($this->waitForDashboardReady('127.0.0.1', $port, self::READY_TIMEOUT)) {
                    return [$proc, $pipes, $port];
                }
                $lastErr = (string) stream_get_contents($pipes[2]);
                $this->stopDashboardServer($proc, $pipes);
            }
        }
        self::fail('could not start the PHP built-in server after 5 attempts' . ($lastErr !== '' ? ": {$lastErr}" : ''));
    }

    /**
     * @param resource $proc
     * @param array<int,resource> $pipes
     */
    private function stopDashboardServer($proc, array $pipes): void
    {
        foreach ($pipes as $p) {
            if (is_resource($p)) {
                @fclose($p);
            }
        }
        if (is_resource($proc)) {
            @proc_terminate($proc);
            $running = true;
            for ($i = 0; $i < 20; $i++) {
                $st = @proc_get_status($proc);
                if (!is_array($st) || $st['running'] !== true) {
                    $running = false;
                    break;
                }
                usleep(50000);
            }
            if ($running) {
                @proc_terminate($proc, 9);
            }
            @proc_close($proc);
        }
    }

    private function freeDashboardPort(): int
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

    private function waitForDashboardReady(string $host, int $port, float $timeout): bool
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
     * Raw HTTP/1.0 request (no keep-alive, so the server closes and we read to EOF).
     *
     * @param array<string,string> $headers extra request headers (e.g. Cookie, Content-Type)
     * @return array{0:int,1:array<string,string>,2:string,3:list<string>} [status, headers (lowercased
     *         keys, LAST value wins), body, every raw Set-Cookie line (there is normally only one)]
     */
    private function dashboardHttpRequest(
        string $host,
        int $port,
        string $method,
        string $path,
        array $headers = [],
        string $body = ''
    ): array {
        $fp = @fsockopen($host, $port, $errno, $errstr, self::READY_TIMEOUT);
        if (!is_resource($fp)) {
            return [0, [], '', []];
        }
        stream_set_timeout($fp, (int) self::READY_TIMEOUT);
        $reqHeaders = array_merge(['Host' => '127.0.0.1', 'User-Agent' => 'curl/8.0', 'Connection' => 'close'], $headers);
        if ($body !== '' && !isset($reqHeaders['Content-Length'])) {
            $reqHeaders['Content-Length'] = (string) strlen($body);
        }
        $lines = "{$method} {$path} HTTP/1.0\r\n";
        foreach ($reqHeaders as $k => $v) {
            $lines .= "{$k}: {$v}\r\n";
        }
        $lines .= "\r\n{$body}";
        fwrite($fp, $lines);

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
        $respBody = $split === false ? '' : substr($raw, $split + 4);

        $status = 0;
        $respHeaders = [];
        $setCookies = [];
        $headLines = preg_split('/\r\n/', $head) ?: [];
        foreach ($headLines as $i => $line) {
            if ($i === 0) {
                if (preg_match('#^HTTP/\d\.\d\s+(\d{3})#', $line, $m) === 1) {
                    $status = (int) $m[1];
                }
                continue;
            }
            $c = strpos($line, ':');
            if ($c !== false) {
                $name = strtolower(trim(substr($line, 0, $c)));
                $val = trim(substr($line, $c + 1));
                $respHeaders[$name] = $val;
                if ($name === 'set-cookie') {
                    $setCookies[] = $val;
                }
            }
        }

        return [$status, $respHeaders, $respBody, $setCookies];
    }

    private function dashboardTempDir(string $prefix): string
    {
        $dir = sys_get_temp_dir() . '/' . $prefix . '_' . bin2hex(random_bytes(6));
        if (!@mkdir($dir, 0777, true) && !is_dir($dir)) {
            self::markTestSkipped("cannot create temp dir {$dir}");
        }
        $this->httpTmpDirs[] = $dir;

        return $dir;
    }

    private function dashboardRmrf(string $dir): void
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
            is_dir($path) ? $this->dashboardRmrf($path) : @unlink($path);
        }
        @rmdir($dir);
    }

    private function dashboardCleanupTmpDirs(): void
    {
        foreach ($this->httpTmpDirs as $dir) {
            $this->dashboardRmrf($dir);
        }
        $this->httpTmpDirs = [];
    }

    /**
     * The env demo/index.php needs to boot in full isolation (mirrors FrontControllerBootSmokeTest):
     * every persisted path under a fresh temp dir, the LLM sidecar off, a fixed persona so nothing
     * makes a network call. $extra overrides/adds vars (e.g. FUNNYPOT_MODE, FUNNYPOT_ADMIN_PASSWORD).
     *
     * @param array<string,string> $extra
     * @return array<string,string>
     */
    private function dashboardBootEnv(string $data, array $extra = []): array
    {
        $env = [
            'PATH' => getenv('PATH') !== false ? (string) getenv('PATH') : '/usr/bin:/bin',
            'FUNNYPOT_DB' => $data . '/funnypot.sqlite',
            'FUNNYPOT_LOG' => $data . '/hits.log',
            'FUNNYPOT_GEO_DB' => $data . '/geo.csv',
            'FUNNYPOT_VULNS' => $data . '/vulns.json',
            'FUNNYPOT_LLM' => '0',
            'FUNNYPOT_PERSONA_SEED' => 'httptest',
        ];
        foreach (['PHPRC', 'PHP_INI_SCAN_DIR'] as $iniVar) {
            $v = getenv($iniVar);
            if ($v !== false && $v !== '') {
                $env[$iniVar] = $v;
            }
        }

        return array_merge($env, $extra);
    }
}
